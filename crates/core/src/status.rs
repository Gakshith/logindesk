//! The only shape a tool result or daemon reply takes (contract §2).
//! Every enum is closed. `wire()` gives the snake_case tag.

use crate::ids::{AccountId, Handle, SessionId};

/// Outcome of a broker operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    /// Signed in; the session stays open in the broker.
    LoggedIn {
        /// Session to act in.
        session_id: SessionId,
    },
    /// Account created and signed in.
    Created {
        /// New record.
        account_id: AccountId,
        /// Session to act in.
        session_id: SessionId,
        /// Email the account was created with.
        email_used: String,
    },
    /// Done.
    Ok,
    /// Waiting on the user; call `wait` with the handle.
    AwaitingApproval {
        /// Handle to wait on.
        handle: Handle,
    },
    /// The user said no.
    Denied,
    /// The vault is locked; the user must unlock it.
    VaultLocked,
    /// No mailbox is connected, but the site emailed a code.
    EmailNotConnected,
    /// A human has to do something the broker will not.
    NeedsUser {
        /// What.
        reason: NeedsUserReason,
    },
    /// It did not work.
    Failed {
        /// Why.
        reason: FailReason,
    },
}

/// Why a human is needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NeedsUserReason {
    /// A CAPTCHA.
    Captcha,
    /// An SMS code.
    Sms,
    /// Some other second factor.
    SecondFactorOther,
    /// A page the broker does not understand.
    UnknownPage,
    /// More than one plausible emailed code.
    AmbiguousOtp,
}

/// Why it failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailReason {
    /// The site rejected the stored credentials.
    CredentialsRejected,
    /// No stored account for this site.
    NoAccount,
    /// More than one account; name one.
    AccountAmbiguous,
    /// The login form could not be mapped.
    FieldMappingFailed,
    /// The page or form is not on the account's site.
    FenceBlocked,
    /// The site did not load.
    SiteUnreachable,
    /// Out of time.
    Timeout,
    /// Too many requests.
    RateLimited,
    /// The client is not paired.
    NotPaired,
    /// No grant for this site and action.
    GrantDenied,
    /// Unknown or closed session.
    SessionNotFound,
    /// Something inside the broker broke (details in the audit log).
    Internal,
}

/// Fixed message for [`Status::EmailNotConnected`].
pub const EMAIL_NOT_CONNECTED_MSG: &str =
    "Run `logindesk connect gmail` (or `connect imap`) in a terminal, then retry.";

impl Status {
    /// snake_case wire tag.
    pub fn wire(&self) -> &'static str {
        match self {
            Self::LoggedIn { .. } => "logged_in",
            Self::Created { .. } => "created",
            Self::Ok => "ok",
            Self::AwaitingApproval { .. } => "awaiting_approval",
            Self::Denied => "denied",
            Self::VaultLocked => "vault_locked",
            Self::EmailNotConnected => "email_not_connected",
            Self::NeedsUser { .. } => "needs_user",
            Self::Failed { .. } => "failed",
        }
    }
}

impl NeedsUserReason {
    /// snake_case wire tag.
    pub fn wire(self) -> &'static str {
        match self {
            Self::Captcha => "captcha",
            Self::Sms => "sms",
            Self::SecondFactorOther => "second_factor_other",
            Self::UnknownPage => "unknown_page",
            Self::AmbiguousOtp => "ambiguous_otp",
        }
    }
    /// Parse a wire tag.
    pub fn from_wire(s: &str) -> Option<Self> {
        [
            Self::Captcha,
            Self::Sms,
            Self::SecondFactorOther,
            Self::UnknownPage,
            Self::AmbiguousOtp,
        ]
        .into_iter()
        .find(|r| r.wire() == s)
    }
}

impl FailReason {
    const ALL: [Self; 12] = [
        Self::CredentialsRejected,
        Self::NoAccount,
        Self::AccountAmbiguous,
        Self::FieldMappingFailed,
        Self::FenceBlocked,
        Self::SiteUnreachable,
        Self::Timeout,
        Self::RateLimited,
        Self::NotPaired,
        Self::GrantDenied,
        Self::SessionNotFound,
        Self::Internal,
    ];
    /// snake_case wire tag.
    pub fn wire(self) -> &'static str {
        match self {
            Self::CredentialsRejected => "credentials_rejected",
            Self::NoAccount => "no_account",
            Self::AccountAmbiguous => "account_ambiguous",
            Self::FieldMappingFailed => "field_mapping_failed",
            Self::FenceBlocked => "fence_blocked",
            Self::SiteUnreachable => "site_unreachable",
            Self::Timeout => "timeout",
            Self::RateLimited => "rate_limited",
            Self::NotPaired => "not_paired",
            Self::GrantDenied => "grant_denied",
            Self::SessionNotFound => "session_not_found",
            Self::Internal => "internal",
        }
    }
    /// Parse a wire tag.
    pub fn from_wire(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|r| r.wire() == s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_round_trip() {
        for r in FailReason::ALL {
            assert_eq!(FailReason::from_wire(r.wire()), Some(r));
        }
        assert_eq!(
            NeedsUserReason::from_wire("captcha"),
            Some(NeedsUserReason::Captcha)
        );
        assert_eq!(Status::VaultLocked.wire(), "vault_locked");
    }
}
