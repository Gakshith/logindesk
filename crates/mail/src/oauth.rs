//! OAuth 2 for an installed app (RFC 8252): loopback redirect on `127.0.0.1:<random port>` +
//! PKCE S256 (RFC 7636). Used by `logindesk connect gmail`; scope `gmail.readonly` only.
//!
//! Flow: [`Loopback::bind`] → open [`Loopback::auth_url`] in the browser →
//! [`Loopback::wait_for_code`] → [`exchange_code`] returns the refresh token.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::time::{Duration, Instant};

use logindesk_core::SecretString;
use serde_json::Value;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::MailError;
use crate::gmail::token_call;

/// Google's consent page.
pub const GOOGLE_AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
/// Read-only Gmail: list and read messages, nothing else.
pub const GMAIL_READONLY_SCOPE: &str = "https://www.googleapis.com/auth/gmail.readonly";

/// Why consent did not produce a refresh token. Never carries a secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OAuthError {
    /// Google redirected back with `error=<code>` (e.g. `access_denied`).
    Denied(String),
    /// The redirect's `state` did not match (a stray or forged request).
    StateMismatch,
    /// Nobody came back to the loopback port in time.
    Timeout,
    /// The token endpoint answered, but without a refresh token.
    NoRefreshToken,
    /// The token endpoint refused (`invalid_grant`, wrong client secret, ...).
    Rejected,
    /// Network or server trouble; try again.
    Unavailable,
    /// The local listener failed.
    Io(std::io::ErrorKind),
}

impl std::fmt::Display for OAuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Denied(c) => write!(f, "Google refused the consent ({c})"),
            Self::StateMismatch => f.write_str("the browser came back with the wrong state"),
            Self::Timeout => f.write_str("no answer from the browser in time"),
            Self::NoRefreshToken => f.write_str("Google returned no refresh token"),
            Self::Rejected => {
                f.write_str("Google rejected the code (check the client id and secret)")
            }
            Self::Unavailable => f.write_str("could not reach Google's token endpoint"),
            Self::Io(k) => write!(f, "local listener failed ({k})"),
        }
    }
}

impl std::error::Error for OAuthError {}

fn random_bytes<const N: usize>() -> Result<[u8; N], OAuthError> {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).map_err(|_| OAuthError::Io(std::io::ErrorKind::Other))?;
    Ok(b)
}

/// Base64url without padding.
pub fn b64url(input: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |acc, (i, &b)| acc | u32::from(b) << (16 - 8 * i));
        for i in 0..=chunk.len() {
            out.push(char::from(A[((n >> (18 - 6 * i)) & 63) as usize]));
        }
    }
    out
}

/// PKCE verifier (secret) and its S256 challenge.
#[derive(Debug)]
pub struct Pkce {
    /// Sent only to the token endpoint.
    pub verifier: SecretString,
    /// Sent in the consent URL.
    pub challenge: String,
}

impl Pkce {
    /// 32 random bytes → 43-char verifier.
    pub fn new() -> Result<Self, OAuthError> {
        let raw = Zeroizing::new(random_bytes::<32>()?);
        Ok(Self::from_verifier(SecretString::new(b64url(raw.as_ref()))))
    }

    /// For tests (RFC 7636 appendix B vector).
    pub fn from_verifier(verifier: SecretString) -> Self {
        let challenge = b64url(&Sha256::digest(verifier.expose().as_bytes()));
        Self {
            verifier,
            challenge,
        }
    }
}

/// The local redirect target.
#[derive(Debug)]
pub struct Loopback {
    listener: TcpListener,
    /// `http://127.0.0.1:<port>`
    pub redirect_uri: String,
    state: String,
}

fn enc(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

impl Loopback {
    /// Listen on `127.0.0.1` at a port the OS picks.
    pub fn bind() -> Result<Self, OAuthError> {
        let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| OAuthError::Io(e.kind()))?;
        let port = listener
            .local_addr()
            .map_err(|e| OAuthError::Io(e.kind()))?
            .port();
        Ok(Self {
            listener,
            redirect_uri: format!("http://127.0.0.1:{port}"),
            state: b64url(&random_bytes::<16>()?),
        })
    }

    /// The consent URL to open in the browser.
    pub fn auth_url(&self, auth_endpoint: &str, client_id: &str, pkce: &Pkce) -> String {
        format!(
            "{auth_endpoint}?client_id={}&redirect_uri={}&response_type=code&scope={}&code_challenge={}&code_challenge_method=S256&state={}&access_type=offline&prompt=consent",
            enc(client_id),
            enc(&self.redirect_uri),
            enc(GMAIL_READONLY_SCOPE),
            pkce.challenge,
            self.state
        )
    }

    /// Wait for the browser's redirect and return the authorization code.
    /// Requests without `code`/`error` (a favicon fetch) are answered 404 and ignored.
    pub fn wait_for_code(&self, limit: Duration) -> Result<SecretString, OAuthError> {
        let deadline = Instant::now() + limit;
        self.listener
            .set_nonblocking(true)
            .map_err(|e| OAuthError::Io(e.kind()))?;
        loop {
            let (stream, _) = match self.listener.accept() {
                Ok(c) => c,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() > deadline {
                        return Err(OAuthError::Timeout);
                    }
                    std::thread::sleep(Duration::from_millis(100));
                    continue;
                }
                Err(e) => return Err(OAuthError::Io(e.kind())),
            };
            let _ = stream.set_nonblocking(false);
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
            let mut reader = BufReader::new(&stream);
            let mut line = Zeroizing::new(String::new());
            if reader.read_line(&mut line).is_err() {
                continue;
            }
            let target = line.split_whitespace().nth(1).unwrap_or("");
            let query = target.split_once('?').map_or("", |(_, q)| q);
            let (mut code, mut state, mut error) = (None, None, None);
            for (k, v) in url::form_urlencoded::parse(query.as_bytes()) {
                match k.as_ref() {
                    "code" => code = Some(SecretString::new(v.into_owned())),
                    "state" => state = Some(v.into_owned()),
                    "error" => error = Some(v.into_owned()),
                    _ => {}
                }
            }
            let mut w = &stream;
            if code.is_none() && error.is_none() {
                let _ = w.write_all(
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
                continue;
            }
            let reply = |w: &mut &std::net::TcpStream, msg: &str| {
                let body = format!(
                    "<!doctype html><meta charset=utf-8><title>logindesk</title><p>{msg}</p>"
                );
                let _ = write!(
                    w,
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            };
            if state.as_deref() != Some(self.state.as_str()) {
                reply(
                    &mut w,
                    "This sign-in link is not the one logindesk started. Close this tab.",
                );
                return Err(OAuthError::StateMismatch);
            }
            if let Some(e) = error {
                reply(&mut w, "Consent was not given. You can close this tab.");
                // Google's error codes are short ASCII words; keep only that.
                let e: String = e
                    .chars()
                    .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .take(40)
                    .collect();
                return Err(OAuthError::Denied(e));
            }
            reply(
                &mut w,
                "logindesk is connected to Gmail. You can close this tab.",
            );
            return code.ok_or(OAuthError::Timeout);
        }
    }
}

/// Trade the authorization code for a refresh token.
pub fn exchange_code(
    token_url: &str,
    client_id: &str,
    client_secret: &SecretString,
    code: &SecretString,
    pkce: &Pkce,
    redirect_uri: &str,
) -> Result<SecretString, OAuthError> {
    let v = token_call(
        token_url,
        &[
            ("client_id", client_id),
            ("client_secret", client_secret.expose()),
            ("code", code.expose()),
            ("code_verifier", pkce.verifier.expose()),
            ("redirect_uri", redirect_uri),
            ("grant_type", "authorization_code"),
        ],
    )
    .map_err(|e| match e {
        MailError::NotConnected | MailError::Internal => OAuthError::Rejected,
        MailError::Transient => OAuthError::Unavailable,
    })?;
    v.get("refresh_token")
        .and_then(Value::as_str)
        .filter(|t| !t.is_empty())
        .map(|t| SecretString::new(t.to_string()))
        .ok_or(OAuthError::NoRefreshToken)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64url_and_pkce_vector() {
        assert_eq!(b64url(b""), "");
        assert_eq!(b64url(b"f"), "Zg");
        assert_eq!(b64url(b"fo"), "Zm8");
        assert_eq!(b64url(b"foo"), "Zm9v");
        assert_eq!(b64url(&[0xfb, 0xff]), "-_8");
        // RFC 7636 appendix B.
        let p = Pkce::from_verifier(SecretString::new(
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".into(),
        ));
        assert_eq!(p.challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
        let fresh = Pkce::new().expect("rng");
        assert_eq!(fresh.verifier.expose().len(), 43);
    }
}
