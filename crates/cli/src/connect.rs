//! `logindesk connect gmail|imap|status` and `logindesk disconnect`: a real mailbox for emailed
//! one-time codes. Secrets (refresh token, client secret, app password) go into the vault as
//! `mail` records; `mail.json` holds only the kind and a URL. The daemon reads both at start.

use std::io::BufRead;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, SystemTime};

use clap::{Subcommand, ValueEnum};
use logindesk_daemon::mailcfg::{
    GMAIL_RECORD_SITE, IMAP_RECORD_SITE, MailConfig, MailCreds, MailKind, NOTE_CLIENT_SECRET,
    NOTE_REFRESH,
};
use logindesk_mail::oauth::{GOOGLE_AUTH_URL, Loopback, Pkce, exchange_code};
use logindesk_mail::{GOOGLE_TOKEN_URL, MailError, MailQuery};
use logindesk_vault::{Keys, Vault};

use crate::prompt::Prompter;

type Res = Result<(), Box<dyn std::error::Error>>;

/// How long the browser consent may take.
const CONSENT_WAIT: Duration = Duration::from_secs(300);

#[derive(Debug, Subcommand)]
pub enum ConnectCmd {
    /// Gmail through Google's API, read-only. Prints the Google Cloud steps, then opens consent.
    /// Asks for: the vault password, the OAuth client ID (unless --client-id), the client secret.
    Gmail {
        /// Your Desktop-app OAuth client ID (`...apps.googleusercontent.com`).
        #[arg(long)]
        client_id: Option<String>,
        /// Print the consent URL instead of opening the browser.
        #[arg(long)]
        no_browser: bool,
    },
    /// Any IMAP mailbox over TLS with an app password (asked for, never an argument).
    Imap {
        /// Known host settings.
        #[arg(long, value_enum)]
        preset: Option<Preset>,
        /// IMAP host (overrides --preset).
        #[arg(long)]
        host: Option<String>,
        /// IMAP TLS port.
        #[arg(long, default_value_t = 993)]
        port: u16,
        /// Login name, usually your email address.
        #[arg(long)]
        user: String,
    },
    /// Show the connected mailbox (never shows secrets).
    Status {
        /// Also unlock the vault and test the connection with one search.
        #[arg(long)]
        check: bool,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Preset {
    /// imap.gmail.com (needs 2-Step Verification and an app password).
    Gmail,
    /// imap.mail.me.com (appleid.apple.com → app-specific password).
    Icloud,
    /// outlook.office365.com (Microsoft may require OAuth instead of app passwords).
    Outlook,
}

impl Preset {
    fn host(self) -> &'static str {
        match self {
            Self::Gmail => "imap.gmail.com",
            Self::Icloud => "imap.mail.me.com",
            Self::Outlook => "outlook.office365.com",
        }
    }
}

const GMAIL_STEPS: &str = "\
Connect Gmail (read-only). One-time setup in Google Cloud, about 5 minutes:
  1. https://console.cloud.google.com → create a project (any name).
  2. APIs & Services → Library → \"Gmail API\" → Enable.
  3. OAuth consent screen → External → fill the app name and your email.
     Publishing status: Testing. Test users: add your own Gmail address.
  4. Credentials → Create credentials → OAuth client ID → Application type: Desktop app.
  5. Copy the client ID and client secret; paste them below.
logindesk asks only for gmail.readonly and keeps the token in your vault.
";

pub fn run(vault: &Path, dir: &Path, cmd: ConnectCmd, prompt: &mut Prompter) -> Res {
    std::fs::create_dir_all(dir)?;
    match cmd {
        ConnectCmd::Gmail {
            client_id,
            no_browser,
        } => gmail(vault, dir, client_id, no_browser, prompt),
        ConnectCmd::Imap {
            preset,
            host,
            port,
            user,
        } => {
            let host = host
                .or(preset.map(|p| p.host().to_string()))
                .ok_or("give --host or --preset")?;
            imap(vault, dir, &host, port, &user, prompt)
        }
        ConnectCmd::Status { check } => status(vault, dir, check, prompt),
    }
}

/// A non-secret line from stdin (works with --password-stdin too).
fn read_line(label: &str) -> std::io::Result<String> {
    eprint!("{label}");
    let mut s = String::new();
    if std::io::stdin().lock().read_line(&mut s)? == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "stdin closed",
        ));
    }
    Ok(s.trim().to_string())
}

fn gmail(
    vault_path: &Path,
    dir: &Path,
    client_id: Option<String>,
    no_browser: bool,
    prompt: &mut Prompter,
) -> Res {
    eprint!("{GMAIL_STEPS}");
    let mut vault = Vault::open(vault_path)?;
    let keys = crate::unlock(&vault, prompt)?;
    let client_id = match client_id {
        Some(c) => c,
        None => read_line("OAuth client ID: ")?,
    };
    if client_id.is_empty() || client_id.contains(char::is_whitespace) {
        return Err("the client ID looks wrong".into());
    }
    let secret = prompt.secret("OAuth client secret: ")?;
    if secret.expose().is_empty() {
        return Err("the client secret must not be empty".into());
    }

    let pkce = Pkce::new()?;
    let lb = Loopback::bind()?;
    let url = lb.auth_url(GOOGLE_AUTH_URL, &client_id, &pkce);
    eprintln!("\nApprove access in your browser. If it does not open, visit:\n{url}\n");
    if !no_browser {
        let _ = Command::new("open").arg(&url).status();
    }
    eprintln!("Waiting up to 5 minutes for Google to send you back...");
    let code = lb.wait_for_code(CONSENT_WAIT)?;
    let refresh = exchange_code(
        GOOGLE_TOKEN_URL,
        &client_id,
        &secret,
        &code,
        &pkce,
        &lb.redirect_uri,
    )?;

    // One mailbox at a time: drop whatever `connect` stored before.
    MailCreds::remove_from_vault(&mut vault, &keys)?;
    vault.add(
        &keys,
        MailCreds::record(GMAIL_RECORD_SITE, &client_id, NOTE_REFRESH, refresh),
    )?;
    vault.add(
        &keys,
        MailCreds::record(GMAIL_RECORD_SITE, &client_id, NOTE_CLIENT_SECRET, secret),
    )?;
    MailConfig {
        kind: MailKind::Gmail,
        url: String::new(),
    }
    .save(dir)?;
    finish(&mut vault, &keys, dir, "Gmail (read-only)")
}

fn imap(
    vault_path: &Path,
    dir: &Path,
    host: &str,
    port: u16,
    user: &str,
    prompt: &mut Prompter,
) -> Res {
    let mut url = url::Url::parse(&format!("imaps://{host}:{port}"))
        .map_err(|_| format!("{host:?} is not a host name"))?;
    url.set_username(user)
        .map_err(|()| "the user name cannot be used in a URL")?;
    let mut vault = Vault::open(vault_path)?;
    let keys = crate::unlock(&vault, prompt)?;
    let pw = prompt.secret(&format!("App password for {user} on {host}: "))?;
    if pw.expose().is_empty() {
        return Err("the app password must not be empty".into());
    }
    MailCreds::remove_from_vault(&mut vault, &keys)?;
    vault.add(&keys, MailCreds::record(IMAP_RECORD_SITE, user, host, pw))?;
    MailConfig {
        kind: MailKind::Imap,
        url: url.to_string(),
    }
    .save(dir)?;
    finish(&mut vault, &keys, dir, &format!("IMAP {host}"))
}

/// Test the stored connection; undo it if the mailbox refuses the credentials.
fn finish(vault: &mut Vault, keys: &Keys, dir: &Path, what: &str) -> Res {
    eprintln!("Testing the connection...");
    match check(vault, keys, dir) {
        Ok(()) => {
            eprintln!(
                "{what} connected. Restart `logindesk daemon` so it picks up the new mailbox."
            );
            Ok(())
        }
        Err(MailError::NotConnected) => {
            MailCreds::remove_from_vault(vault, keys)?;
            MailConfig::remove(dir)?;
            Err("the mailbox refused the credentials; nothing was kept".into())
        }
        Err(MailError::Transient) => {
            eprintln!(
                "{what} saved, but the mailbox did not answer just now. Run `logindesk connect status --check` later."
            );
            Ok(())
        }
        Err(MailError::Internal) => {
            eprintln!(
                "{what} saved, but the test search got an unexpected reply. Run `logindesk connect status --check` later."
            );
            Ok(())
        }
    }
}

/// One harmless search (a domain that never sends mail).
fn check(vault: &Vault, keys: &Keys, dir: &Path) -> Result<(), MailError> {
    let cfg = MailConfig::load(dir)
        .ok()
        .flatten()
        .ok_or(MailError::NotConnected)?;
    let src = cfg
        .source(&MailCreds::from_vault(vault, keys))
        .ok_or(MailError::NotConnected)?;
    let q = MailQuery {
        site: "example.invalid".into(),
        since: SystemTime::now() - Duration::from_secs(60),
    };
    src.search(&q).map(|_| ())
}

fn status(vault_path: &Path, dir: &Path, check_it: bool, prompt: &mut Prompter) -> Res {
    let Some(cfg) = MailConfig::load(dir)? else {
        eprintln!(
            "No mailbox connected. Run `logindesk connect gmail` or `logindesk connect imap`."
        );
        return Ok(());
    };
    let what = match cfg.kind {
        MailKind::Gmail => "Gmail (REST, read-only OAuth)".to_string(),
        MailKind::Imap => format!("IMAP {}", cfg.url),
        MailKind::Mailpit => format!("Mailpit {}", cfg.url),
        MailKind::Outbox => format!("test-bed outbox {}", cfg.url),
    };
    eprintln!("Mailbox: {what}");
    if !check_it {
        return Ok(());
    }
    let vault = Vault::open(vault_path)?;
    let keys = crate::unlock(&vault, prompt)?;
    match check(&vault, &keys, dir) {
        Ok(()) => eprintln!("Check: OK, a test search succeeded."),
        Err(MailError::NotConnected) => {
            return Err("check failed: not connected (credentials missing, revoked or refused). Run `logindesk connect` again.".into());
        }
        Err(MailError::Transient) => return Err("check failed: the mailbox did not answer".into()),
        Err(MailError::Internal) => return Err("check failed: unexpected reply".into()),
    }
    Ok(())
}

/// Delete the mailbox secrets from the vault and remove `mail.json`.
pub fn disconnect(vault_path: &Path, dir: &Path, prompt: &mut Prompter) -> Res {
    let mut vault = Vault::open(vault_path)?;
    let keys = crate::unlock(&vault, prompt)?;
    let n = MailCreds::remove_from_vault(&mut vault, &keys)?;
    MailConfig::remove(dir)?;
    eprintln!(
        "Disconnected: removed {n} mailbox secret(s) and mail.json. Restart `logindesk daemon` to drop them from memory."
    );
    eprintln!(
        "For Gmail, also revoke access at https://myaccount.google.com/permissions if you no longer use it."
    );
    Ok(())
}
