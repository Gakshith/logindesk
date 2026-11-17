//! A Gmail-REST-shaped mock: `GET /gmail/v1/users/me/messages` (list) and
//! `GET /gmail/v1/users/me/messages/{id}` (get, `format=full|metadata|minimal|raw`).
//!
//! It serves two fixed fixtures plus every mail the fake site sent:
//! - [`ALIGNED_ID`]: from `no-reply@example.com`; DKIM `d=example.com`, SPF and DMARC pass.
//! - [`SPOOFED_ID`]: claims `From: no-reply@example.com` but is DKIM-signed by `evil-mailer.test`
//!   and the envelope sender is there too, so DMARC fails. Phase 8 must reject its code.
//!
//! Headers follow Gmail's shape (`Authentication-Results` from `mx.google.com`, folded with CRLF + spaces).
//! Bodies are base64url without padding; decoders should accept padded input too.
//! Requests need `Authorization: Bearer <Fixtures::gmail_token>`, otherwise 401 like the real API.

use std::collections::HashMap;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use base64::Engine;
use serde_json::{Value, json};

use crate::site::{Mail, Shared, rfc2822_date};

/// Message id of the aligned (genuine) fixture.
pub const ALIGNED_ID: &str = "18f3c2a9d41b7e05";
/// Message id of the spoofed fixture.
pub const SPOOFED_ID: &str = "18f3c2b17a0e9c33";
/// The code in the aligned fixture.
pub const ALIGNED_CODE: &str = "482913";
/// The code in the spoofed fixture.
pub const SPOOFED_CODE: &str = "135790";

/// One message as the mock stores it.
#[derive(Debug, Clone)]
pub struct GmailMessage {
    /// 16-hex-digit id.
    pub id: String,
    /// Thread id (same as id: one message per thread).
    pub thread_id: String,
    /// Receive time, Unix milliseconds.
    pub internal_date_ms: u64,
    /// Headers in order.
    pub headers: Vec<(String, String)>,
    /// Plain-text body.
    pub body: String,
}

impl GmailMessage {
    fn header(&self, name: &str) -> &str {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
            .unwrap_or("")
    }

    fn raw(&self) -> String {
        let mut s: String = self
            .headers
            .iter()
            .map(|(n, v)| format!("{n}: {v}\r\n"))
            .collect();
        s.push_str("\r\n");
        s.push_str(&self.body.replace('\n', "\r\n"));
        s
    }

    fn snippet(&self) -> String {
        let flat: String = self.body.split_whitespace().collect::<Vec<_>>().join(" ");
        let cut: String = flat.chars().take(100).collect();
        cut.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('\'', "&#39;")
            .replace('"', "&quot;")
    }

    fn to_json(&self, format: &str) -> Value {
        let b64 = |s: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(s.as_bytes());
        let mut v = json!({
            "id": self.id,
            "threadId": self.thread_id,
            "labelIds": ["UNREAD", "CATEGORY_UPDATES", "INBOX"],
            "snippet": self.snippet(),
            "sizeEstimate": self.raw().len(),
            "historyId": "4821137",
            "internalDate": self.internal_date_ms.to_string(),
        });
        let headers: Vec<Value> = self
            .headers
            .iter()
            .map(|(n, val)| json!({"name": n, "value": val}))
            .collect();
        match format {
            "minimal" => {}
            "raw" => v["raw"] = json!(b64(&self.raw())),
            "metadata" => v["payload"] = json!({"mimeType": "text/plain", "headers": headers}),
            _ => {
                v["payload"] = json!({
                    "partId": "",
                    "mimeType": "text/plain",
                    "filename": "",
                    "headers": headers,
                    "body": {"size": self.body.len(), "data": b64(&self.body)},
                })
            }
        }
        v
    }
}

fn h(n: &str, v: &str) -> (String, String) {
    (n.to_string(), v.to_string())
}

/// Gmail folds long `Authentication-Results` values onto continuation lines.
fn fold(parts: &[&str]) -> String {
    parts.join("\r\n       ")
}

/// The aligned and the spoofed fixture, received 2 and 1 minutes before `now_secs`.
pub fn fixture_messages(to: &str, now_secs: u64) -> Vec<GmailMessage> {
    let t_aligned = now_secs.saturating_sub(120);
    let t_spoofed = now_secs.saturating_sub(60);
    let aligned = GmailMessage {
        id: ALIGNED_ID.into(),
        thread_id: ALIGNED_ID.into(),
        internal_date_ms: t_aligned * 1000,
        headers: vec![
            h("Delivered-To", to),
            h(
                "Received",
                &format!(
                    "by 2002:a05:6a10:8f12:b0:5c1:1a2b:3c4d with SMTP id x18csp1234567pxb;\r\n        {}",
                    rfc2822_date(t_aligned)
                ),
            ),
            h(
                "Authentication-Results",
                &fold(&[
                    "mx.google.com;",
                    "dkim=pass header.i=@example.com header.s=s2026 header.b=Qk7tW2pA;",
                    "spf=pass (google.com: domain of no-reply@example.com designates 192.0.2.10 as permitted sender) smtp.mailfrom=no-reply@example.com;",
                    "dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=example.com",
                ]),
            ),
            h("Return-Path", "<no-reply@example.com>"),
            h(
                "DKIM-Signature",
                "v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=s2026;\r\n        h=from:to:subject:date:message-id; bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=;\r\n        b=Qk7tW2pAfixtureNotARealSignature",
            ),
            h("From", "Example <no-reply@example.com>"),
            h("To", to),
            h("Subject", "Your Example verification code"),
            h("Date", &rfc2822_date(t_aligned)),
            h("Message-ID", "<aligned.fixture@example.com>"),
            h("MIME-Version", "1.0"),
            h("Content-Type", "text/plain; charset=\"UTF-8\""),
        ],
        body: format!(
            "Your Example verification code is {ALIGNED_CODE}.\nIt expires in 10 minutes.\n"
        ),
    };
    let spoofed = GmailMessage {
        id: SPOOFED_ID.into(),
        thread_id: SPOOFED_ID.into(),
        internal_date_ms: t_spoofed * 1000,
        headers: vec![
            h("Delivered-To", to),
            h(
                "Received",
                &format!(
                    "by 2002:a05:6a10:8f12:b0:5c1:1a2b:3c4d with SMTP id y22csp7654321pxb;\r\n        {}",
                    rfc2822_date(t_spoofed)
                ),
            ),
            h(
                "Authentication-Results",
                &fold(&[
                    "mx.google.com;",
                    "dkim=pass header.i=@evil-mailer.test header.s=k1 header.b=Zr4Lm9Xc;",
                    "spf=pass (google.com: domain of bounce@evil-mailer.test designates 198.51.100.7 as permitted sender) smtp.mailfrom=bounce@evil-mailer.test;",
                    "dmarc=fail (p=REJECT sp=REJECT dis=QUARANTINE) header.from=example.com",
                ]),
            ),
            h("Return-Path", "<bounce@evil-mailer.test>"),
            h(
                "DKIM-Signature",
                "v=1; a=rsa-sha256; c=relaxed/relaxed; d=evil-mailer.test; s=k1;\r\n        h=from:to:subject:date:message-id; bh=frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY=;\r\n        b=Zr4Lm9XcfixtureNotARealSignature",
            ),
            h("From", "Example <no-reply@example.com>"),
            h("To", to),
            h("Subject", "Your Example verification code"),
            h("Date", &rfc2822_date(t_spoofed)),
            h("Message-ID", "<spoofed.fixture@evil-mailer.test>"),
            h("MIME-Version", "1.0"),
            h("Content-Type", "text/plain; charset=\"UTF-8\""),
        ],
        body: format!(
            "Your Example verification code is {SPOOFED_CODE}.\nIt expires in 10 minutes.\n"
        ),
    };
    vec![aligned, spoofed]
}

/// A mail the fake site sent, as Gmail would show it (aligned for the site's own domain).
pub fn from_site_mail(index: usize, m: &Mail) -> GmailMessage {
    let id = format!("19{:014x}", index + 1);
    let domain = m
        .from_addr
        .rsplit('@')
        .next()
        .unwrap_or("example.localhost")
        .to_string();
    GmailMessage {
        id: id.clone(),
        thread_id: id,
        internal_date_ms: m.sent_at * 1000,
        headers: vec![
            h("Delivered-To", &m.to),
            h(
                "Authentication-Results",
                &fold(&[
                    "mx.google.com;",
                    &format!("dkim=pass header.i=@{domain} header.s=tb header.b=TbFixture;"),
                    &format!(
                        "spf=pass (google.com: domain of {} designates 127.0.0.1 as permitted sender) smtp.mailfrom={};",
                        m.from_addr, m.from_addr
                    ),
                    &format!("dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from={domain}"),
                ]),
            ),
            h("Return-Path", &format!("<{}>", m.from_addr)),
            h(
                "DKIM-Signature",
                &format!(
                    "v=1; a=rsa-sha256; c=relaxed/relaxed; d={domain}; s=tb; b=TbFixtureNotARealSignature"
                ),
            ),
            h("From", &format!("Example <{}>", m.from_addr)),
            h("To", &m.to),
            h("Subject", &m.subject),
            h("Date", &rfc2822_date(m.sent_at)),
            h("Message-ID", &format!("<{}>", m.message_id)),
            h("MIME-Version", "1.0"),
            h("Content-Type", "text/plain; charset=\"UTF-8\""),
        ],
        body: m.body.clone(),
    }
}

/// All messages the mock serves, newest first (like Gmail).
pub fn all_messages(site: &crate::site::Site) -> Vec<GmailMessage> {
    let mut v = fixture_messages(&site.fx.user_email, crate::site::now());
    v.extend(
        site.outbox()
            .iter()
            .enumerate()
            .map(|(i, m)| from_site_mail(i, m)),
    );
    v.sort_by(|a, b| {
        b.internal_date_ms
            .cmp(&a.internal_date_ms)
            .then(b.id.cmp(&a.id))
    });
    v
}

/// Routes, merged into the main site router.
pub fn router() -> Router<Shared> {
    Router::new()
        .route("/gmail/v1/users/me/messages", get(list))
        .route("/gmail/v1/users/me/messages/{id}", get(get_one))
}

fn google_error(status: StatusCode, message: &str, reason: &str, status_name: &str) -> Response {
    let body = json!({"error": {
        "code": status.as_u16(),
        "message": message,
        "errors": [{"message": message, "domain": "global", "reason": reason}],
        "status": status_name,
    }});
    (status, Json(body)).into_response()
}

fn authorized(site: &crate::site::Site, headers: &HeaderMap) -> bool {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .is_some_and(|t| t == site.fx.gmail_token)
}

fn unauthorized() -> Response {
    google_error(
        StatusCode::UNAUTHORIZED,
        "Request had invalid authentication credentials. Expected OAuth 2 access token, login cookie or other valid authentication credential.",
        "authError",
        "UNAUTHENTICATED",
    )
}

/// A tiny subset of Gmail's `q` syntax: `from:`, `subject:`, `newer_than:Nd|Nh|Nm`, other words match subject or body.
fn matches(m: &GmailMessage, q: &str, now_ms: u64) -> bool {
    q.split_whitespace().all(|tok| {
        if let Some(v) = tok.strip_prefix("from:") {
            m.header("From").to_lowercase().contains(&v.to_lowercase())
        } else if let Some(v) = tok.strip_prefix("subject:") {
            m.header("Subject")
                .to_lowercase()
                .contains(&v.to_lowercase())
        } else if let Some(v) = tok.strip_prefix("newer_than:") {
            let (n, unit) = v.split_at(v.len().saturating_sub(1));
            let n: u64 = n.parse().unwrap_or(0);
            let secs = match unit {
                "d" => n * 86_400,
                "h" => n * 3_600,
                "m" => n * 60,
                _ => 0,
            };
            m.internal_date_ms + secs * 1000 >= now_ms
        } else {
            let t = tok.to_lowercase();
            m.header("Subject").to_lowercase().contains(&t) || m.body.to_lowercase().contains(&t)
        }
    })
}

async fn list(
    State(site): State<Shared>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    if !authorized(&site, &headers) {
        return unauthorized();
    }
    let query = q.get("q").map(String::as_str).unwrap_or("");
    let max: usize = q
        .get("maxResults")
        .and_then(|v| v.parse().ok())
        .unwrap_or(100)
        .clamp(1, 500);
    let now_ms = crate::site::now() * 1000;
    let hits: Vec<Value> = all_messages(&site)
        .into_iter()
        .filter(|m| matches(m, query, now_ms))
        .take(max)
        .map(|m| json!({"id": m.id, "threadId": m.thread_id}))
        .collect();
    // Like Gmail, an empty result has no "messages" key.
    let body = if hits.is_empty() {
        json!({"resultSizeEstimate": 0})
    } else {
        json!({"messages": hits, "resultSizeEstimate": hits.len()})
    };
    Json(body).into_response()
}

async fn get_one(
    State(site): State<Shared>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    if !authorized(&site, &headers) {
        return unauthorized();
    }
    let format = q.get("format").map(String::as_str).unwrap_or("full");
    match all_messages(&site).into_iter().find(|m| m.id == id) {
        Some(m) => Json(m.to_json(format)).into_response(),
        None => google_error(
            StatusCode::NOT_FOUND,
            "Requested entity was not found.",
            "notFound",
            "NOT_FOUND",
        ),
    }
}
