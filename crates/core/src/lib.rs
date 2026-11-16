//! logindesk-core: types shared by every logindesk crate (see docs/contract.md).
//!
//! [`Secret`] is the wrapper every password, OTP, token and key travels in.
//! [`status`], [`ids`] and [`limits`] are the frozen cross-crate contract.
#![forbid(unsafe_code)]

pub mod ids;
pub mod limits;
mod secret;
pub mod status;

pub use secret::{REDACTED, Secret, SecretString};
