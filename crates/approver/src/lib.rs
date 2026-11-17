//! logindesk-approver: ask the human, and the single-use token a "yes" becomes (contract §5).
//!
//! Rule from spike 1: only a fresh `LAContext` whose reply is `success == true` with no
//! error counts as approval. Everything else is Denied / TimedOut / Unavailable.

use std::fmt;
use std::time::{Duration, Instant};

use logindesk_core::ids::RequestId;
use logindesk_core::limits::APPROVAL_TOKEN_TTL;

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::MacApprover;

/// What the agent wants to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Pair a new MCP client.
    Pair,
    /// Log in with a stored account.
    Login,
    /// Create an account.
    Signup,
    /// Submit a form.
    Submit,
    /// Store a secret the page shows.
    CaptureSecret,
}

impl Action {
    /// Lowercase verb for prompts and the audit log.
    pub fn verb(self) -> &'static str {
        match self {
            Self::Pair => "pair",
            Self::Login => "log in",
            Self::Signup => "sign up",
            Self::Submit => "submit",
            Self::CaptureSecret => "capture a secret",
        }
    }
}

/// One question for the user.
#[derive(Debug, Clone)]
pub struct ApprovalRequest {
    /// Id.
    pub request_id: RequestId,
    /// As the client declared it; shown "(unverified)".
    pub client_name: String,
    /// What.
    pub action: Action,
    /// Registrable domain.
    pub site: String,
    /// Signup: field labels to be shared.
    pub shares: Vec<String>,
}

impl ApprovalRequest {
    /// The sentence shown in the system sheet.
    pub fn prompt_text(&self) -> String {
        format!(
            "let the agent \"{}\" (unverified) {} on {}. Typing your Mac password approves",
            self.client_name,
            self.action.verb(),
            self.site
        )
    }
}

/// The answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalOutcome {
    /// Yes.
    Approved,
    /// No, or any error.
    Denied,
    /// Nobody answered in time.
    TimedOut,
    /// No way to ask (no GUI, unsupported OS).
    Unavailable,
}

/// Asks the user.
pub trait Approver: Send + Sync {
    /// Blocks until the user answers or `limit` passes. Never panics.
    fn approve(&self, req: &ApprovalRequest, limit: Duration) -> ApprovalOutcome;
}

/// Why a token was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenError {
    /// Older than [`APPROVAL_TOKEN_TTL`].
    Expired,
    /// Minted for another action or site.
    Mismatch,
}

/// Proof that this one action on this one site was approved.
/// No `Clone`, no `Copy`, no serde: it is consumed by value where it is used.
pub struct ApprovalToken {
    request_id: RequestId,
    action: Action,
    site: String,
    issued_at: Instant,
    standing: bool,
}

impl fmt::Debug for ApprovalToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApprovalToken")
            .field("request_id", &self.request_id)
            .field("action", &self.action)
            .field("site", &self.site)
            .field("standing", &self.standing)
            .finish_non_exhaustive()
    }
}

impl ApprovalToken {
    /// A token for an approved request; `None` for any other outcome.
    pub fn from_outcome(req: &ApprovalRequest, outcome: ApprovalOutcome) -> Option<Self> {
        (outcome == ApprovalOutcome::Approved).then(|| Self::new(req, false))
    }

    /// A token from a standing grant the user set in a terminal (`logindesk grant`).
    pub fn from_standing_grant(req: &ApprovalRequest) -> Self {
        Self::new(req, true)
    }

    fn new(req: &ApprovalRequest, standing: bool) -> Self {
        Self {
            request_id: req.request_id,
            action: req.action,
            site: req.site.clone(),
            issued_at: Instant::now(),
            standing,
        }
    }

    /// The request this token answers (the daemon records it as spent).
    pub fn request_id(&self) -> RequestId {
        self.request_id
    }

    /// True when it came from a standing grant rather than a live prompt.
    pub fn is_standing(&self) -> bool {
        self.standing
    }

    /// Consume the token for `action` on `site`.
    pub fn spend(self, action: Action, site: &str) -> Result<RequestId, TokenError> {
        if self.issued_at.elapsed() > APPROVAL_TOKEN_TTL {
            return Err(TokenError::Expired);
        }
        if self.action != action || self.site != site {
            return Err(TokenError::Mismatch);
        }
        Ok(self.request_id)
    }
}

/// Always `Unavailable`: for platforms with no approval UI.
#[derive(Debug, Default)]
pub struct NoApprover;

impl Approver for NoApprover {
    fn approve(&self, _req: &ApprovalRequest, _limit: Duration) -> ApprovalOutcome {
        ApprovalOutcome::Unavailable
    }
}

/// Test double that answers from a fixed outcome. Only with the `test-doubles` feature.
#[cfg(any(test, feature = "test-doubles"))]
#[derive(Debug)]
pub struct Scripted(pub ApprovalOutcome);

#[cfg(any(test, feature = "test-doubles"))]
impl Approver for Scripted {
    fn approve(&self, _req: &ApprovalRequest, _limit: Duration) -> ApprovalOutcome {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req() -> ApprovalRequest {
        ApprovalRequest {
            request_id: RequestId::random(),
            client_name: "claude-code".into(),
            action: Action::Login,
            site: "example.com".into(),
            shares: vec![],
        }
    }

    #[test]
    fn only_approved_mints() {
        let r = req();
        for o in [
            ApprovalOutcome::Denied,
            ApprovalOutcome::TimedOut,
            ApprovalOutcome::Unavailable,
        ] {
            assert!(ApprovalToken::from_outcome(&r, o).is_none());
        }
        let t = ApprovalToken::from_outcome(
            &r,
            Scripted(ApprovalOutcome::Approved).approve(&r, Duration::ZERO),
        )
        .unwrap();
        assert_eq!(t.spend(Action::Login, "example.com"), Ok(r.request_id));
    }

    #[test]
    fn mismatch_refused() {
        let r = req();
        assert_eq!(
            ApprovalToken::from_standing_grant(&r).spend(Action::Login, "evil.com"),
            Err(TokenError::Mismatch)
        );
        assert_eq!(
            ApprovalToken::from_standing_grant(&r).spend(Action::Signup, "example.com"),
            Err(TokenError::Mismatch)
        );
    }

    #[test]
    fn prompt_says_password_approves() {
        assert!(
            req()
                .prompt_text()
                .contains("Typing your Mac password approves")
        );
    }
}
