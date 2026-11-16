//! logindesk-daemon: the broker.
//!
//! Unlocks the vault once and holds the keys (like ssh-agent) so an agent can
//! log in on its own: `login(site)` → grant check (auto / ask / deny) → sealed
//! browser fills the password itself → emailed code read and filled → a
//! status comes back. No secret ever crosses the socket.
//!
//! - [`proto`] — frames and the request/reply shapes (docs/socket.md).
//! - [`server`] — the Unix socket, client token, threads.
//! - [`broker`] — the login flow and sessions.
//! - [`audit`] — hash-chained JSONL log.
//! - [`browser`] — the browser trait (real: `logindesk_executor::Session`).
//! - [`mailcfg`] — `mail.json`.
#![forbid(unsafe_code)]

pub mod audit;
pub mod broker;
pub mod browser;
pub mod identity;
pub mod mailcfg;
pub mod password;
pub mod proto;
pub mod server;

use std::sync::Arc;

use logindesk_vault::{Keys, Vault, hardening};

pub use broker::{Broker, Config, Deps};
pub use server::Server;

/// Process hardening. Failures are warnings: the daemon still runs, with
/// less protection.
pub fn harden() {
    if let Err(e) = hardening::disable_core_dumps() {
        eprintln!("logindesk: warning: could not disable core dumps: {e}");
    }
    if let Err(e) = hardening::deny_debugger_attach() {
        eprintln!("logindesk: warning: could not block debugger attach: {e}");
    }
}

/// The platform's approver: Touch ID / Mac password on macOS, none elsewhere.
pub fn system_approver() -> Box<dyn logindesk_approver::Approver> {
    #[cfg(target_os = "macos")]
    {
        Box::new(logindesk_approver::MacApprover)
    }
    #[cfg(not(target_os = "macos"))]
    {
        Box::new(logindesk_approver::NoApprover)
    }
}

/// Production deps: system approver, sealed Chrome, `mail.json`.
pub fn default_deps(cfg: &Config) -> Deps {
    Deps {
        approver: system_approver(),
        launcher: Box::new(browser::ChromeLauncher),
        mail: Box::new(mailcfg::FileMail(
            cfg.data_dir.clone(),
            mailcfg::MailCreds::default(),
        )),
    }
}

/// Bind the socket and serve until the process exits.
pub fn run(cfg: Config, vault: Vault, keys: Keys) -> std::io::Result<()> {
    harden();
    let server = Server::bind(&cfg.data_dir)?;
    let mut deps = default_deps(&cfg);
    // Gmail / IMAP secrets: read once, now, while the keys are in hand.
    deps.mail = Box::new(mailcfg::FileMail(
        cfg.data_dir.clone(),
        mailcfg::MailCreds::from_vault(&vault, &keys),
    ));
    let broker = Arc::new(Broker::new(cfg, deps, vault, keys)?);
    eprintln!(
        "logindesk daemon: listening on {} (vault unlocked; Ctrl-C to stop)",
        server.socket().display()
    );
    server.serve(broker)
}
