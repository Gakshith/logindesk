//! logindesk test bed. Test-only; never a dependency of `crates/*`.
//!
//! - [`site`]: the fake website (axum) with every page Phase 7–9 need, plus a second "other origin" listener.
//! - [`gmail_mock`]: a Gmail-REST-shaped mock (`users.messages.list` / `get`) with aligned and spoofed senders.
//! - [`mailpit`] + [`smtp`]: the site's mail goes to a Mailpit container (Docker, image pinned by digest).
//! - [`canary`]: the leak harness. Plants high-entropy markers and finds them in any captured channel, in any encoding.
//! - [`hostile`]: the hostile MCP client's attack list (real attacks land in Phase 6).
//!
//! Everything binds `127.0.0.1` on runtime-chosen ports. Nothing here is reachable off-host.

#![forbid(unsafe_code)]

pub mod canary;
pub mod fixtures;
pub mod gmail_mock;
pub mod hostile;
pub mod mailpit;
pub mod site;
pub mod smtp;
pub mod totp;
