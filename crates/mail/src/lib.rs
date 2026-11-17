//! logindesk-mail: mail sources and the one-time-code parser (contract §7).
//!
//! The parser never calls a model, never follows a link, never logs a body.
//! The daemon owns polling; a source performs one search per call.
//!
//! FROZEN API (docs/contract.md §7). Parser rules and source details: docs/mail.md.
#![forbid(unsafe_code)]

mod auth;
mod gmail;
mod http;
mod imap;
mod mime;
pub mod oauth;
mod otp;
mod time;

pub use gmail::{GMAIL_API_BASE, GOOGLE_TOKEN_URL, GmailAuth, GmailRestSource};
pub use imap::{ImapAuth, ImapSource};

#[cfg(test)]
mod tests;

use std::collections::HashSet;
use std::time::SystemTime;

use logindesk_core::{Secret, SecretString};

/// What to look for.
#[derive(Debug, Clone)]
pub struct MailQuery {
    /// Registrable domain of the site that sent the code.
    pub site: String,
    /// Ignore mail received before this.
    pub since: SystemTime,
}

/// One raw RFC 5322 message.
#[derive(Debug)]
pub struct RawMessage {
    /// Source-specific id.
    pub id: String,
    /// When it arrived.
    pub received: SystemTime,
    /// Full message bytes.
    pub bytes: Secret<Vec<u8>>,
}

/// Source errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailError {
    /// No mailbox / bad credentials → `Status::EmailNotConnected`.
    NotConnected,
    /// Try again next poll.
    Transient,
    /// Anything else.
    Internal,
}

/// A mailbox.
pub trait MailSource: Send + Sync {
    /// At most `OTP_MAX_MESSAGES` messages from `q.site`, newest first, received after `q.since`.
    fn search(&self, q: &MailQuery) -> Result<Vec<RawMessage>, MailError>;
}

/// What the parser found.
#[derive(Debug)]
pub enum OtpOutcome {
    /// A numeric / short alphanumeric code.
    Code(SecretString),
    /// An https link on the site's registrable domain.
    Link(SecretString),
    /// More than one plausible code → `NeedsUser { AmbiguousOtp }`.
    Ambiguous,
    /// Nothing yet.
    NotFound,
}

/// Codes already used (by message id), so a code is never submitted twice.
#[derive(Debug, Default)]
pub struct UsedCodes(HashSet<String>);

impl UsedCodes {
    /// Was this message id used?
    pub fn contains(&self, id: &str) -> bool {
        self.0.contains(id)
    }
    /// Mark a message id used.
    pub fn insert(&mut self, id: &str) {
        self.0.insert(id.to_string());
    }
}

/// Pick the code from the newest unused message whose From domain is on `q.site`.
///
/// A message counts only if it is not in `used`, arrived at or after `q.since`, and has exactly
/// one `From` address whose registrable domain is `q.site`. Only the newest such message is
/// read (ties broken by its `Date` header). Its id is marked used when a code or link is
/// returned. Rules in docs/mail.md.
pub fn extract_otp(msgs: &[RawMessage], q: &MailQuery, used: &mut UsedCodes) -> OtpOutcome {
    let site = q.site.trim().to_ascii_lowercase();
    let mut newest: Option<(&RawMessage, mime::Parsed)> = None;
    for m in msgs {
        if used.contains(&m.id) || m.received < q.since {
            continue;
        }
        let p = mime::parse(m.bytes.expose());
        let on_site = p
            .from_domain
            .as_deref()
            .and_then(logindesk_policy::registrable_domain)
            .is_some_and(|d| d == site);
        if !on_site {
            continue;
        }
        let newer = match &newest {
            None => true,
            Some((n, np)) => (m.received, p.date) > (n.received, np.date),
        };
        if newer {
            newest = Some((m, p));
        }
    }
    let Some((m, p)) = newest else {
        return OtpOutcome::NotFound;
    };
    match otp::find(&p, &site) {
        otp::Found::Code(c) => {
            used.insert(&m.id);
            OtpOutcome::Code(SecretString::new(c.to_string()))
        }
        otp::Found::Link(l) => {
            used.insert(&m.id);
            OtpOutcome::Link(SecretString::new(l.to_string()))
        }
        otp::Found::Ambiguous => OtpOutcome::Ambiguous,
        otp::Found::Nothing => OtpOutcome::NotFound,
    }
}

/// Mailpit's HTTP API as a mailbox (the test bed's IMAP stand-in).
#[derive(Debug, Clone)]
pub struct MailpitSource {
    /// e.g. `http://127.0.0.1:8025`
    pub base_url: String,
}

impl MailSource for MailpitSource {
    fn search(&self, q: &MailQuery) -> Result<Vec<RawMessage>, MailError> {
        http::mailpit_search(&self.base_url, q)
    }
}

/// The fake site's `GET /_testbed/outbox` as a mailbox, so an end-to-end run needs no Docker.
/// Each outbox entry becomes a synthesized RFC 5322 message, parsed like any other.
#[derive(Debug, Clone)]
pub struct OutboxSource {
    /// e.g. `http://127.0.0.1:41234` (the fake site's main listener)
    pub base_url: String,
}

impl MailSource for OutboxSource {
    fn search(&self, q: &MailQuery) -> Result<Vec<RawMessage>, MailError> {
        http::outbox_search(&self.base_url, q)
    }
}
