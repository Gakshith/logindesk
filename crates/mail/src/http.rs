//! HTTP mail sources on loopback: Mailpit's REST API and the fake site's outbox hook.
//! Plain http only (no TLS feature), and only to a loopback host.

use std::io::ErrorKind;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use logindesk_core::Secret;
use logindesk_core::limits::OTP_MAX_MESSAGES;
use logindesk_policy::registrable_domain;
use serde_json::Value;

use crate::mime::{MAX_MESSAGE_BYTES, from_domain};
use crate::time::{format_rfc2822, parse_rfc3339};
use crate::{MailError, MailQuery, RawMessage};

/// One request may take this long before it counts as `Transient`.
const TIMEOUT: Duration = Duration::from_secs(10);
/// A message list larger than this is refused.
const MAX_LIST_BYTES: u64 = 4 * 1024 * 1024;

pub(crate) fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(TIMEOUT))
        .http_status_as_error(true)
        .max_redirects(0)
        .build()
        .new_agent()
}

/// `base_url` must be `http://` to a loopback host; the trailing `/` is dropped.
fn loopback_base(base_url: &str) -> Result<String, MailError> {
    let u = url::Url::parse(base_url).map_err(|_| MailError::Internal)?;
    let loopback = match u.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        Some(url::Host::Domain(d)) => d == "localhost" || d.ends_with(".localhost"),
        None => false,
    };
    if u.scheme() != "http" || !loopback {
        return Err(MailError::Internal);
    }
    Ok(base_url.trim_end_matches('/').to_string())
}

/// The contract mapping: refused connection → `NotConnected`, 5xx / timeout / dropped
/// connection → `Transient`, anything else → `Internal`. Never carries a message.
pub fn map_err(e: &ureq::Error) -> MailError {
    match e {
        ureq::Error::ConnectionFailed => MailError::NotConnected,
        ureq::Error::Io(io) => match io.kind() {
            ErrorKind::ConnectionRefused | ErrorKind::NotConnected => MailError::NotConnected,
            ErrorKind::TimedOut
            | ErrorKind::WouldBlock
            | ErrorKind::ConnectionReset
            | ErrorKind::ConnectionAborted
            | ErrorKind::BrokenPipe
            | ErrorKind::UnexpectedEof
            | ErrorKind::Interrupted => MailError::Transient,
            _ => MailError::Internal,
        },
        ureq::Error::Timeout(_) => MailError::Transient,
        ureq::Error::StatusCode(c) if *c >= 500 => MailError::Transient,
        _ => MailError::Internal,
    }
}

/// Read a JSON body of any status (size-capped).
pub(crate) fn read_json_any(
    resp: &mut ureq::http::Response<ureq::Body>,
) -> Result<Value, MailError> {
    let bytes = resp
        .body_mut()
        .with_config()
        .limit(MAX_LIST_BYTES)
        .read_to_vec()
        .map_err(|e| map_err(&e))?;
    serde_json::from_slice(&bytes).map_err(|_| MailError::Internal)
}

fn get_json(agent: &ureq::Agent, url: &str) -> Result<Value, MailError> {
    let mut resp = agent.get(url).call().map_err(|e| map_err(&e))?;
    let bytes = resp
        .body_mut()
        .with_config()
        .limit(MAX_LIST_BYTES)
        .read_to_vec()
        .map_err(|e| map_err(&e))?;
    serde_json::from_slice(&bytes).map_err(|_| MailError::Internal)
}

fn on_site(addr: &str, site: &str) -> bool {
    from_domain(addr)
        .and_then(|d| registrable_domain(&d))
        .is_some_and(|d| d == site)
}

/// Mailpit ids are short UUID-like tokens; anything else is not put in a URL path.
fn safe_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// `GET /api/v1/messages`, filter, then `GET /api/v1/message/{ID}/raw` for each.
pub fn mailpit_search(base_url: &str, q: &MailQuery) -> Result<Vec<RawMessage>, MailError> {
    let base = loopback_base(base_url)?;
    let agent = agent();
    let list = get_json(&agent, &format!("{base}/api/v1/messages?limit=50"))?;
    let msgs = list
        .get("messages")
        .and_then(Value::as_array)
        .ok_or(MailError::Internal)?;
    let mut picked: Vec<(String, SystemTime)> = msgs
        .iter()
        .filter_map(|m| {
            let id = m.get("ID")?.as_str()?;
            let from = m.get("From")?.get("Address")?.as_str()?;
            let created = parse_rfc3339(m.get("Created")?.as_str()?)?;
            (safe_id(id) && on_site(from, &q.site) && created >= q.since)
                .then(|| (id.to_string(), created))
        })
        .collect();
    picked.sort_by_key(|p| std::cmp::Reverse(p.1));
    picked.truncate(OTP_MAX_MESSAGES);

    let mut out = Vec::with_capacity(picked.len());
    for (id, received) in picked {
        let mut resp = agent
            .get(&format!("{base}/api/v1/message/{id}/raw"))
            .call()
            .map_err(|e| map_err(&e))?;
        let bytes = match resp
            .body_mut()
            .with_config()
            .limit(MAX_MESSAGE_BYTES as u64)
            .read_to_vec()
        {
            Ok(b) => b,
            // An oversized message is skipped, not fatal.
            Err(ureq::Error::BodyExceedsLimit(_)) => continue,
            Err(e) => return Err(map_err(&e)),
        };
        out.push(RawMessage {
            id,
            received,
            bytes: Secret::new(bytes),
        });
    }
    Ok(out)
}

/// One header value on one line.
fn one_line(s: &str) -> String {
    s.replace(['\r', '\n'], " ")
}

/// `GET {base}/_testbed/outbox`, then a synthesized RFC 5322 message per entry.
pub fn outbox_search(base_url: &str, q: &MailQuery) -> Result<Vec<RawMessage>, MailError> {
    let base = loopback_base(base_url)?;
    let list = get_json(&agent(), &format!("{base}/_testbed/outbox"))?;
    let arr = list.as_array().ok_or(MailError::Internal)?;
    // The outbox has whole-second times: a mail sent in the same second as `since` counts.
    let since_secs = q
        .since
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let mut picked: Vec<(usize, u64, &Value)> = arr
        .iter()
        .enumerate()
        .filter_map(|(i, m)| {
            let from = m.get("from_addr")?.as_str()?;
            let sent = m.get("sent_at")?.as_u64()?;
            (on_site(from, &q.site) && sent >= since_secs).then_some((i, sent, m))
        })
        .collect();
    // Newest first; the outbox is append-only, so a later index is newer within one second.
    picked.sort_by_key(|p| std::cmp::Reverse((p.1, p.0)));
    picked.truncate(OTP_MAX_MESSAGES);

    let mut out = Vec::with_capacity(picked.len());
    for (_, sent, m) in picked {
        let field = |k: &str| m.get(k).and_then(Value::as_str).unwrap_or("");
        let id = field("message_id").to_string();
        if id.is_empty() {
            continue;
        }
        let raw = format!(
            "From: <{}>\r\nTo: <{}>\r\nSubject: {}\r\nDate: {}\r\nMessage-ID: <{}>\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=\"UTF-8\"\r\nContent-Transfer-Encoding: 8bit\r\n\r\n{}",
            one_line(field("from_addr")),
            one_line(field("to")),
            one_line(field("subject")),
            format_rfc2822(sent),
            one_line(&id),
            field("body").replace("\r\n", "\n").replace('\n', "\r\n"),
        );
        out.push(RawMessage {
            id,
            received: UNIX_EPOCH + Duration::from_secs(sent),
            bytes: Secret::new(raw.into_bytes()),
        });
    }
    Ok(out)
}
