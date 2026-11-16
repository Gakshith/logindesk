//! Gmail over its REST API, with an access token minted from the user's refresh token.
//!
//! `search`: `users/me/messages?q=from:<site> newer_than:15m&maxResults=5`, then
//! `messages/{id}?format=raw`. Each message must arrive after `since` and pass Gmail's own
//! `Authentication-Results` (DKIM or DMARC aligned with the site), so a spoofed `From` is dropped
//! before the parser sees it.
//!
//! Errors: `invalid_grant` (revoked or expired refresh token), `invalid_client`, or a 401 right
//! after a fresh token → `NotConnected`; 5xx / timeout → `Transient`; anything else → `Internal`.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, UNIX_EPOCH};

use logindesk_core::limits::{OTP_LOOKBACK, OTP_MAX_MESSAGES};
use logindesk_core::{Secret, SecretString};
use serde_json::Value;
use zeroize::Zeroizing;

use crate::auth::dkim_aligned;
use crate::http::{agent, map_err, read_json_any};
use crate::mime::decode_b64;
use crate::{MailError, MailQuery, MailSource, RawMessage};

/// Gmail's REST API.
pub const GMAIL_API_BASE: &str = "https://gmail.googleapis.com";
/// Google's OAuth token endpoint.
pub const GOOGLE_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
/// The authserv-id Gmail writes in `Authentication-Results`.
pub const GMAIL_AUTHSERV: &str = "mx.google.com";

/// The user's own OAuth client plus the refresh token from `logindesk connect gmail`.
/// Shared by every source the daemon builds, so one access token serves many logins.
pub struct GmailAuth {
    /// Desktop OAuth client id (not secret).
    pub client_id: String,
    client_secret: SecretString,
    refresh_token: SecretString,
    access: Mutex<Option<(SecretString, Instant)>>,
}

impl std::fmt::Debug for GmailAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GmailAuth")
            .field("client_id", &self.client_id)
            .finish_non_exhaustive()
    }
}

impl GmailAuth {
    /// From the values `connect gmail` stored in the vault.
    pub fn new(
        client_id: String,
        client_secret: SecretString,
        refresh_token: SecretString,
    ) -> Self {
        Self {
            client_id,
            client_secret,
            refresh_token,
            access: Mutex::new(None),
        }
    }
}

/// Gmail as a mailbox.
#[derive(Debug, Clone)]
pub struct GmailRestSource {
    /// `https://gmail.googleapis.com`, or a loopback mock in tests.
    pub api_base: String,
    /// `https://oauth2.googleapis.com/token`, or a loopback fake in tests.
    pub token_url: String,
    /// Credentials.
    pub auth: Arc<GmailAuth>,
}

impl GmailRestSource {
    /// The real Google endpoints.
    pub fn new(auth: Arc<GmailAuth>) -> Self {
        Self {
            api_base: GMAIL_API_BASE.into(),
            token_url: GOOGLE_TOKEN_URL.into(),
            auth,
        }
    }
}

/// https anywhere, plain http only on loopback (test mocks).
pub(crate) fn endpoint_ok(u: &str) -> Result<String, MailError> {
    let url = url::Url::parse(u).map_err(|_| MailError::Internal)?;
    let loopback = match url.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        Some(url::Host::Domain(d)) => d == "localhost" || d.ends_with(".localhost"),
        None => false,
    };
    match url.scheme() {
        "https" => Ok(u.trim_end_matches('/').to_string()),
        "http" if loopback => Ok(u.trim_end_matches('/').to_string()),
        _ => Err(MailError::Internal),
    }
}

/// A token-endpoint call: `Ok(json)` on 200, else the mapped error.
pub(crate) fn token_call(url: &str, form: &[(&str, &str)]) -> Result<Value, MailError> {
    let url = endpoint_ok(url)?;
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(15)))
        .http_status_as_error(false)
        .max_redirects(0)
        .build()
        .new_agent();
    let mut resp = agent
        .post(&url)
        .send_form(form.iter().copied())
        .map_err(|e| map_err(&e))?;
    let status = resp.status().as_u16();
    let body = read_json_any(&mut resp).unwrap_or(Value::Null);
    if status == 200 {
        return Ok(body);
    }
    let err = body.get("error").and_then(Value::as_str).unwrap_or("");
    Err(match (status, err) {
        (_, "invalid_grant" | "invalid_client" | "unauthorized_client") => MailError::NotConnected,
        (s, _) if s >= 500 => MailError::Transient,
        _ => MailError::Internal,
    })
}

enum Fail {
    Unauthorized,
    Mail(MailError),
}

impl From<MailError> for Fail {
    fn from(e: MailError) -> Self {
        Self::Mail(e)
    }
}

impl GmailRestSource {
    /// A cached access token, or a fresh one from the refresh token.
    fn access_token(&self, fresh: bool) -> Result<Zeroizing<String>, MailError> {
        let mut cache = self.auth.access.lock().map_err(|_| MailError::Internal)?;
        if !fresh
            && let Some((tok, until)) = cache.as_ref()
            && Instant::now() < *until
        {
            return Ok(Zeroizing::new(tok.expose().clone()));
        }
        *cache = None;
        let v = token_call(
            &self.token_url,
            &[
                ("client_id", self.auth.client_id.as_str()),
                ("client_secret", self.auth.client_secret.expose().as_str()),
                ("refresh_token", self.auth.refresh_token.expose().as_str()),
                ("grant_type", "refresh_token"),
            ],
        )?;
        let tok = v
            .get("access_token")
            .and_then(Value::as_str)
            .filter(|t| !t.is_empty())
            .ok_or(MailError::Internal)?;
        let ttl = v.get("expires_in").and_then(Value::as_u64).unwrap_or(3600);
        let until = Instant::now() + Duration::from_secs(ttl.saturating_sub(60));
        let out = Zeroizing::new(tok.to_string());
        *cache = Some((SecretString::new(tok.to_string()), until));
        Ok(out)
    }

    fn get(&self, agent: &ureq::Agent, url: &str, token: &str) -> Result<Value, Fail> {
        let bearer = Zeroizing::new(format!("Bearer {token}"));
        match agent
            .get(url)
            .header("Authorization", bearer.as_str())
            .call()
        {
            Ok(mut r) => Ok(read_json_any(&mut r)?),
            Err(ureq::Error::StatusCode(401)) => Err(Fail::Unauthorized),
            Err(e) => Err(Fail::Mail(map_err(&e))),
        }
    }

    fn search_with(&self, token: &str, q: &MailQuery) -> Result<Vec<RawMessage>, Fail> {
        let base = endpoint_ok(&self.api_base)?;
        let agent = agent();
        let minutes = OTP_LOOKBACK.as_secs().div_ceil(60);
        let query = format!("from:{} newer_than:{minutes}m", q.site);
        let enc: String = url::form_urlencoded::byte_serialize(query.as_bytes()).collect();
        let list = self.get(
            &agent,
            &format!("{base}/gmail/v1/users/me/messages?q={enc}&maxResults={OTP_MAX_MESSAGES}"),
            token,
        )?;
        let ids: Vec<String> = list
            .get("messages")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|m| m.get("id")?.as_str())
                    .filter(|id| !id.is_empty() && id.bytes().all(|b| b.is_ascii_alphanumeric()))
                    .take(OTP_MAX_MESSAGES)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            let m = self.get(
                &agent,
                &format!("{base}/gmail/v1/users/me/messages/{id}?format=raw"),
                token,
            )?;
            let Some(ms) = m
                .get("internalDate")
                .and_then(Value::as_str)
                .and_then(|s| s.parse::<u64>().ok())
            else {
                continue;
            };
            let received = UNIX_EPOCH + Duration::from_millis(ms);
            if received < q.since {
                continue;
            }
            let Some(raw) = m.get("raw").and_then(Value::as_str) else {
                continue;
            };
            let bytes = decode_b64(raw.as_bytes());
            if !dkim_aligned(&bytes, &q.site, Some(GMAIL_AUTHSERV)) {
                continue;
            }
            out.push(RawMessage {
                id,
                received,
                bytes: Secret::new(bytes),
            });
        }
        out.sort_by_key(|m| std::cmp::Reverse(m.received));
        Ok(out)
    }
}

impl MailSource for GmailRestSource {
    fn search(&self, q: &MailQuery) -> Result<Vec<RawMessage>, MailError> {
        let token = self.access_token(false)?;
        match self.search_with(&token, q) {
            Ok(v) => Ok(v),
            Err(Fail::Mail(e)) => Err(e),
            // A cached token may have been revoked: mint one more, once.
            Err(Fail::Unauthorized) => {
                let token = self.access_token(true)?;
                match self.search_with(&token, q) {
                    Ok(v) => Ok(v),
                    Err(Fail::Mail(e)) => Err(e),
                    Err(Fail::Unauthorized) => Err(MailError::NotConnected),
                }
            }
        }
    }
}
