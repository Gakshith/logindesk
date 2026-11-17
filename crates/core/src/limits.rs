//! Every timeout in one place (contract §4). Crates import these; none hard-codes its own.

use std::time::Duration;

/// How long a tool call blocks waiting for an approval before returning a handle.
pub const APPROVAL_IN_CALL: Duration = Duration::from_secs(40);
/// Longest an approval stays open.
pub const APPROVAL_WAIT_MAX: Duration = Duration::from_secs(10 * 60);
/// An approval token is refused after this.
pub const APPROVAL_TOKEN_TTL: Duration = Duration::from_secs(60);
/// Longest a flow waits for an emailed code.
pub const OTP_WAIT_MAX: Duration = Duration::from_secs(3 * 60);
/// Mail poll interval while a flow waits for a code.
pub const OTP_POLL_EVERY: Duration = Duration::from_secs(3);
/// Most messages read per poll.
pub const OTP_MAX_MESSAGES: usize = 5;
/// Ignore mail older than this.
pub const OTP_LOOKBACK: Duration = Duration::from_secs(15 * 60);
/// Page load limit.
pub const PAGE_LOAD_MAX: Duration = Duration::from_secs(30);
/// Snapshot limit.
pub const SNAPSHOT_MAX: Duration = Duration::from_secs(5);
/// Idle browser sessions close after this.
pub const SESSION_IDLE_CLOSE: Duration = Duration::from_secs(30 * 60);
