//! logindesk-core: types shared by every logindesk crate.
//!
//! The one piece with real logic so far is [`Secret`], the wrapper every
//! password, OTP, token and key travels in.
#![forbid(unsafe_code)]

mod secret;

pub use secret::{REDACTED, Secret, SecretString};
