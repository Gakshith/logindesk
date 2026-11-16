//! logindesk-mail: mail sources and the one-time-code parser (contract §7).
//!
//! The parser never calls a model, never follows a link, never logs a body.
//! The daemon owns polling; a source performs one search per call.
//!
//! FROZEN API (docs/contract.md §7). Bodies marked LANE-MAIL are stubs.
#![forbid(unsafe_code)]

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
pub fn extract_otp(msgs: &[RawMessage], q: &MailQuery, used: &mut UsedCodes) -> OtpOutcome {
    let _ = (msgs, q, used);
    OtpOutcome::NotFound // LANE-MAIL
}

/// Mailpit's HTTP API as a mailbox (the test bed's IMAP stand-in).
#[derive(Debug, Clone)]
pub struct MailpitSource {
    /// e.g. `http://127.0.0.1:8025`
    pub base_url: String,
}

impl MailSource for MailpitSource {
    fn search(&self, q: &MailQuery) -> Result<Vec<RawMessage>, MailError> {
        let _ = q;
        Err(MailError::Internal) // LANE-MAIL
    }
}
