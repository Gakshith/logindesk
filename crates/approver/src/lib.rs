//! logindesk-approver: skeleton. Real logic lands in Phase 4.
//!
//! macOS-only code lives behind `cfg(target_os = "macos")` so the crate
//! still builds on other platforms (CI runs it on Linux).
#![forbid(unsafe_code)]

#[cfg(target_os = "macos")]
mod macos;

#[cfg(not(target_os = "macos"))]
mod unsupported;
