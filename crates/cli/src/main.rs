//! The `logindesk` binary.
//!
//! Output rule: data (ids, listings) goes to stdout; everything meant for a
//! human (prompts, progress, warnings, errors) goes to stderr or the TTY.
//! No command ever prints a secret, except the explicit plaintext export,
//! which writes to a file, never to a stream.
#![forbid(unsafe_code)]

mod paths;
mod prompt;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand};
use logindesk_daemon::Config;
use logindesk_daemon::identity::Identity;
use logindesk_daemon::mailcfg::{MailConfig, MailKind};
use logindesk_daemon::server;
use logindesk_policy::{Grants, Tier, site_of};
use logindesk_vault::{Error, KdfParams, Keys, NewRecord, RecordId, RecordKind, Vault, hardening};
use serde_json::json;

use crate::prompt::Prompter;

/// Minimum vault password length for `setup`.
const MIN_PASSWORD_CHARS: usize = 12;

#[derive(Debug, Parser)]
#[command(
    name = "logindesk",
    version,
    about = "Log in and sign up for websites on your behalf, without the agent ever seeing a secret."
)]
struct Cli {
    /// Vault file. Default: the logindesk folder in your OS data directory.
    #[arg(long, env = "LOGINDESK_VAULT", global = true)]
    vault: Option<PathBuf>,
    /// Read the vault password (and any secret) from stdin, one per line,
    /// instead of prompting on the terminal. For scripts and tests.
    #[arg(long, global = true)]
    password_stdin: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Create a new encrypted vault.
    Setup {
        /// Argon2id memory in KiB (advanced; never below the OWASP minimum).
        #[arg(long, hide = true)]
        kdf_memory_kib: Option<u32>,
        /// Argon2id iterations (advanced; never below the OWASP minimum).
        #[arg(long, hide = true)]
        kdf_iterations: Option<u32>,
    },
    /// Check the vault password and report how long an unlock takes.
    Unlock,
    /// Tell the running daemon to drop its vault keys.
    Lock,
    /// Manage vault records.
    #[command(subcommand)]
    Vault(VaultCmd),
    /// Run the broker: unlock once, then serve agents on a local socket until stopped.
    Daemon {
        /// Show the browser window (also `LOGINDESK_HEADFUL=1`).
        #[arg(long)]
        headful: bool,
        /// Drop the vault keys after this many minutes with no request.
        #[arg(long, value_name = "MIN")]
        lock_after: Option<u64>,
    },
    /// Serve MCP on stdin/stdout (for an agent's MCP config). Needs a running daemon.
    Mcp,
    /// Per-site login grants: auto (no prompt), ask (Touch ID each time), deny.
    #[command(subcommand)]
    Grant(GrantCmd),
    /// Where the daemon reads emailed one-time codes.
    #[command(subcommand)]
    Mail(MailCmd),
    /// Log in to a site through the daemon (as client "cli") and print the reply.
    Login {
        /// Host or URL.
        site: String,
        /// Username or account id, when the site has more than one account.
        #[arg(long)]
        account: Option<String>,
    },
    /// Create an account on a site through the daemon (as client "cli") and print the reply.
    Signup {
        /// Host or URL.
        site: String,
        /// The signup page, when not https://<site>/signup.
        #[arg(long)]
        url: Option<String>,
    },
    /// Who signups are made as (stored beside the vault; not secret).
    #[command(subcommand)]
    Identity(IdentityCmd),
}

#[derive(Debug, Subcommand)]
enum IdentityCmd {
    /// Set the signup email (plus-addressed per site) and optional full name.
    Set {
        /// e.g. you@gmail.com
        #[arg(long)]
        email: String,
        /// Full name for forms that ask for one.
        #[arg(long)]
        name: Option<String>,
    },
    /// Show the identity.
    Show,
}

#[derive(Debug, Clone, Copy, Default, clap::ValueEnum)]
enum ActionArg {
    #[default]
    Login,
    Signup,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum TierArg {
    Auto,
    Ask,
    Deny,
}

impl From<TierArg> for Tier {
    fn from(t: TierArg) -> Self {
        match t {
            TierArg::Auto => Self::Auto,
            TierArg::Ask => Self::Ask,
            TierArg::Deny => Self::Deny,
        }
    }
}

#[derive(Debug, Subcommand)]
enum GrantCmd {
    /// Set the login tier for a site.
    Add {
        /// Host or URL; stored as its registrable domain.
        site: String,
        /// auto: the agent acts with no prompt. ask: Touch ID each time. deny: never.
        #[arg(long, value_enum)]
        tier: TierArg,
        /// Which action the grant is for.
        #[arg(long, value_enum, default_value = "login")]
        action: ActionArg,
    },
    /// List grants.
    List,
    /// Remove a site's grant (it falls back to ask).
    Remove {
        /// Host or URL.
        site: String,
        /// Which action's grant to remove.
        #[arg(long, value_enum, default_value = "login")]
        action: ActionArg,
    },
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum MailKindArg {
    Mailpit,
    Outbox,
}

#[derive(Debug, Subcommand)]
enum MailCmd {
    /// Read codes from a local mailbox API.
    Set {
        /// mailpit or outbox.
        #[arg(value_enum)]
        kind: MailKindArg,
        /// Base URL, e.g. http://127.0.0.1:8025
        url: String,
    },
    /// Stop reading mail (sites that email a code return email_not_connected).
    Off,
}

#[derive(Debug, Subcommand)]
enum VaultCmd {
    /// Add a record. The secret is prompted for, never passed as an argument.
    Add {
        /// Site, e.g. example.com.
        #[arg(long)]
        site: String,
        /// Username or email.
        #[arg(long, default_value = "")]
        username: String,
        /// login, api-key, mail or note.
        #[arg(long, default_value = "login")]
        kind: RecordKind,
        /// Non-secret notes.
        #[arg(long, default_value = "")]
        notes: String,
    },
    /// List records (never shows secrets).
    List,
    /// Show one record's metadata (never shows the secret).
    ShowMetadata {
        /// Record id from `vault list`.
        id: RecordId,
    },
    /// Export the vault. Default: an encrypted copy (same password).
    Export {
        /// Output file. Must not exist; created with mode 0600.
        #[arg(long)]
        out: PathBuf,
        /// Write a PLAINTEXT CSV with every secret. Asks for the vault
        /// password again.
        #[arg(long)]
        plaintext: bool,
    },
    /// Import logins from a CSV export (Chrome, Firefox, Safari, Bitwarden, 1Password).
    Import {
        /// The CSV file.
        #[arg(long)]
        csv: PathBuf,
    },
}

fn main() -> ExitCode {
    harden();
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Process hardening before any secret is read. Failures are reported, not
/// fatal: logindesk still works, with less protection.
fn harden() {
    if let Err(e) = hardening::disable_core_dumps() {
        eprintln!("warning: could not disable core dumps: {e}");
    }
    if let Err(e) = hardening::deny_debugger_attach() {
        eprintln!("warning: could not block debugger attach: {e}");
    }
}

fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let path = match cli.vault {
        Some(p) => p,
        None => paths::default_vault_path()?,
    };
    let mut prompt = Prompter::new(cli.password_stdin);
    match cli.cmd {
        Cmd::Setup {
            kdf_memory_kib,
            kdf_iterations,
        } => {
            let d = KdfParams::DEFAULT;
            let params = KdfParams {
                m_kib: kdf_memory_kib.unwrap_or(d.m_kib),
                t: kdf_iterations.unwrap_or(d.t),
                p: d.p,
            };
            setup(&path, params, &mut prompt)
        }
        Cmd::Unlock => {
            let vault = Vault::open(&path)?;
            let t = Instant::now();
            let keys = unlock(&vault, &mut prompt)?;
            eprintln!(
                "Password OK. Unlock took {:.2} s (Argon2id m={} MiB, t={}, p={}).{}",
                t.elapsed().as_secs_f64(),
                vault.kdf_params().m_kib / 1024,
                vault.kdf_params().t,
                vault.kdf_params().p,
                mlock_note(&keys)
            );
            eprintln!(
                "This command locks the vault again as it exits; `logindesk daemon` keeps it unlocked for agents."
            );
            Ok(())
        }
        Cmd::Lock => {
            let dir = data_dir(&path);
            if !server::socket_path(&dir)?.exists() {
                eprintln!(
                    "Nothing to lock: no daemon is running, so the vault is never left unlocked between commands."
                );
                return Ok(());
            }
            let r = logindesk_mcp::client::call(&dir, "cli", json!({"op": "lock"}));
            if r["status"] == "ok" {
                eprintln!("The daemon dropped its vault keys. Restart it to unlock again.");
                Ok(())
            } else if r == logindesk_mcp::client::daemon_down() {
                eprintln!(
                    "Nothing to lock: no daemon is running, so the vault is never left unlocked between commands."
                );
                Ok(())
            } else {
                Err(format!("the daemon refused: {r}").into())
            }
        }
        Cmd::Vault(cmd) => vault_cmd(&path, cmd, &mut prompt),
        Cmd::Daemon {
            headful,
            lock_after,
        } => {
            let vault = Vault::open(&path)?;
            let keys = unlock(&vault, &mut prompt)?;
            let mut cfg = Config::for_vault(&path);
            cfg.headless = !(headful || std::env::var("LOGINDESK_HEADFUL").is_ok_and(|v| v == "1"));
            cfg.chrome = std::env::var_os("LOGINDESK_CHROME").map(PathBuf::from);
            cfg.lock_after = lock_after.map(|m| Duration::from_secs(m.saturating_mul(60)));
            Ok(logindesk_daemon::run(cfg, vault, keys)?)
        }
        Cmd::Mcp => Ok(logindesk_mcp::run(data_dir(&path))?),
        Cmd::Grant(cmd) => grant_cmd(&path, cmd),
        Cmd::Mail(cmd) => mail_cmd(&data_dir(&path), cmd),
        Cmd::Login { site, account } => {
            let mut op = json!({"op": "login", "site": site});
            if let Some(a) = account {
                op["account"] = a.into();
            }
            client_flow(&data_dir(&path), op, "logged_in")
        }
        Cmd::Signup { site, url } => {
            let mut op = json!({"op": "signup", "site": site});
            if let Some(u) = url {
                op["url"] = u.into();
            }
            client_flow(&data_dir(&path), op, "created")
        }
        Cmd::Identity(cmd) => identity_cmd(&data_dir(&path), cmd),
    }
}

/// Send `op`, follow `awaiting_approval` with `wait` until the flow ends, print the reply.
fn client_flow(
    dir: &Path,
    op: serde_json::Value,
    done: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut r = logindesk_mcp::client::call(dir, "cli", op);
    while r["status"] == "awaiting_approval" {
        eprintln!("Waiting for you to approve the prompt...");
        let h = r["handle"].clone();
        r = logindesk_mcp::client::call(dir, "cli", json!({"op": "wait", "handle": h}));
    }
    writeln!(std::io::stdout().lock(), "{r}")?;
    if r["status"] == done {
        Ok(())
    } else {
        Err(format!("did not complete ({})", r["status"]).into())
    }
}

fn identity_cmd(dir: &Path, cmd: IdentityCmd) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::create_dir_all(dir)?;
    match cmd {
        IdentityCmd::Set { email, name } => {
            Identity { email, name }.save(dir)?;
            eprintln!("Signups will use this identity (email plus-addressed per site).");
        }
        IdentityCmd::Show => match Identity::load(dir)? {
            Some(i) => {
                let mut out = std::io::stdout().lock();
                writeln!(out, "email: {}", i.email)?;
                writeln!(out, "name:  {}", i.name.unwrap_or_default())?;
            }
            None => {
                return Err("no identity: run `logindesk identity set --email <you@...>`".into());
            }
        },
    }
    Ok(())
}

/// Socket, token, audit, profiles and mail.json live beside the vault.
fn data_dir(vault: &Path) -> PathBuf {
    Config::for_vault(vault).data_dir
}

fn domain(site: &str) -> Result<String, Box<dyn std::error::Error>> {
    site_of(site).ok_or_else(|| format!("{site:?} is not a website host or URL").into())
}

fn grant_cmd(vault: &Path, cmd: GrantCmd) -> Result<(), Box<dyn std::error::Error>> {
    let gpath = Grants::path_beside(vault);
    if let Some(dir) = gpath.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut g = Grants::load(&gpath)?;
    match cmd {
        GrantCmd::Add { site, tier, action } => {
            let d = domain(&site)?;
            let tier = Tier::from(tier);
            let (map, verb) = match action {
                ActionArg::Login => (&mut g.login, "log in"),
                ActionArg::Signup => (&mut g.signup, "sign up"),
            };
            map.insert(d.clone(), tier);
            g.save(&gpath)?;
            let what = match tier {
                Tier::Auto => format!("agents may {verb} with no prompt"),
                Tier::Ask => format!("each {verb} asks for Touch ID / your Mac password"),
                Tier::Deny => format!("agents may never {verb}"),
            };
            eprintln!("{d}: {what}.");
        }
        GrantCmd::List => {
            let mut out = std::io::stdout().lock();
            let t = |tier: &Tier| match tier {
                Tier::Auto => "auto",
                Tier::Ask => "ask",
                Tier::Deny => "deny",
            };
            for (site, tier) in &g.login {
                writeln!(out, "{site:<40}  login   {}", t(tier))?;
            }
            for (site, tier) in &g.signup {
                writeln!(out, "{site:<40}  signup  {}", t(tier))?;
            }
            eprintln!(
                "{} grant(s). Sites without one ask each time.",
                g.login.len() + g.signup.len()
            );
        }
        GrantCmd::Remove { site, action } => {
            let d = domain(&site)?;
            let map = match action {
                ActionArg::Login => &mut g.login,
                ActionArg::Signup => &mut g.signup,
            };
            if map.remove(&d).is_none() {
                return Err(format!("no grant for {d}").into());
            }
            g.save(&gpath)?;
            eprintln!("{d}: grant removed; it will ask each time.");
        }
    }
    Ok(())
}

fn mail_cmd(dir: &Path, cmd: MailCmd) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::create_dir_all(dir)?;
    match cmd {
        MailCmd::Set { kind, url } => {
            let u = url::Url::parse(&url).map_err(|_| format!("{url:?} is not a URL"))?;
            if u.scheme() != "http" && u.scheme() != "https" {
                return Err("the mail URL must be http or https".into());
            }
            let kind = match kind {
                MailKindArg::Mailpit => MailKind::Mailpit,
                MailKindArg::Outbox => MailKind::Outbox,
            };
            MailConfig { kind, url }.save(dir)?;
            eprintln!("Emailed codes will be read from {u}.");
        }
        MailCmd::Off => {
            MailConfig::remove(dir)?;
            eprintln!("Mail off: sites that email a code will return email_not_connected.");
        }
    }
    Ok(())
}

fn mlock_note(keys: &Keys) -> &'static str {
    if keys.is_memory_locked() {
        ""
    } else {
        " Warning: key memory could not be locked in RAM (mlock)."
    }
}

fn setup(
    path: &Path,
    params: KdfParams,
    prompt: &mut Prompter,
) -> Result<(), Box<dyn std::error::Error>> {
    if path.exists() {
        return Err(Box::new(Error::AlreadyExists));
    }
    eprintln!("Creating a vault at {}", path.display());
    eprintln!(
        "Choose a vault password of at least {MIN_PASSWORD_CHARS} characters. It cannot be recovered if lost."
    );
    let pw = prompt.secret("New vault password: ")?;
    if pw.expose().chars().count() < MIN_PASSWORD_CHARS {
        return Err(
            format!("the vault password must be at least {MIN_PASSWORD_CHARS} characters").into(),
        );
    }
    let again = prompt.secret("Repeat the vault password: ")?;
    if pw.expose() != again.expose() {
        return Err("the passwords do not match".into());
    }
    let t = Instant::now();
    let (_vault, keys) = Vault::create(path, &pw, params)?;
    eprintln!(
        "Vault created. Key derivation took {:.2} s (Argon2id m={} MiB, t={}, p={}).{}",
        t.elapsed().as_secs_f64(),
        params.m_kib / 1024,
        params.t,
        params.p,
        mlock_note(&keys)
    );
    Ok(())
}

fn unlock(vault: &Vault, prompt: &mut Prompter) -> Result<Keys, Box<dyn std::error::Error>> {
    let pw = prompt.secret("Vault password: ")?;
    Ok(vault.unlock(&pw)?)
}

fn vault_cmd(
    path: &Path,
    cmd: VaultCmd,
    prompt: &mut Prompter,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut vault = Vault::open(path)?;
    let keys = unlock(&vault, prompt)?;
    let mut out = std::io::stdout().lock();
    match cmd {
        VaultCmd::Add {
            site,
            username,
            kind,
            notes,
        } => {
            let secret = prompt.secret(&format!("Secret for {site}: "))?;
            if secret.expose().is_empty() {
                return Err("the secret must not be empty".into());
            }
            let id = vault.add(
                &keys,
                NewRecord {
                    kind,
                    site,
                    username,
                    secret,
                    created_by: "cli".into(),
                    notes,
                },
            )?;
            writeln!(out, "{id}")?;
        }
        VaultCmd::List => {
            let mut list = vault.list(&keys)?;
            list.sort_by(|a, b| {
                (a.site.as_str(), a.username.as_str()).cmp(&(b.site.as_str(), b.username.as_str()))
            });
            writeln!(
                out,
                "{:<32}  {:<7}  {:<10}  {:<30}  USERNAME",
                "ID", "KIND", "UPDATED", "SITE"
            )?;
            for m in &list {
                writeln!(
                    out,
                    "{}  {:<7}  {}  {:<30}  {}",
                    m.id,
                    m.kind.name(),
                    paths::date(m.updated_at),
                    m.site,
                    m.username
                )?;
            }
            eprintln!("{} record(s).", list.len());
        }
        VaultCmd::ShowMetadata { id } => {
            let r = vault.get(&keys, id)?;
            let m = &r.meta;
            writeln!(out, "id:         {}", m.id)?;
            writeln!(out, "kind:       {}", m.kind)?;
            writeln!(out, "site:       {}", m.site)?;
            writeln!(out, "username:   {}", m.username)?;
            writeln!(out, "secret:     {}", r.secret)?; // prints [REDACTED]
            writeln!(out, "version:    {}", m.version)?;
            writeln!(out, "created by: {}", m.created_by)?;
            writeln!(out, "created:    {}", paths::date(m.created_at))?;
            writeln!(out, "updated:    {}", paths::date(m.updated_at))?;
            writeln!(out, "notes:      {}", m.notes)?;
        }
        VaultCmd::Export {
            out: file,
            plaintext: false,
        } => {
            let n = vault.records(&keys)?.len(); // verify everything before copying
            vault.export_encrypted(&file)?;
            eprintln!(
                "Wrote an encrypted copy of {n} record(s) to {} (mode 0600, same password).",
                file.display()
            );
        }
        VaultCmd::Export {
            out: file,
            plaintext: true,
        } => {
            if file.exists() {
                return Err(Box::new(Error::AlreadyExists));
            }
            eprintln!(
                "WARNING: a plaintext export writes EVERY password in the clear to {}.",
                file.display()
            );
            eprintln!(
                "Anyone or any program that can read that file gets them all. Delete it as soon as you are done."
            );
            let again =
                prompt.secret("Re-enter the vault password to confirm the PLAINTEXT export: ")?;
            match vault.unlock(&again) {
                Ok(confirm) => drop(confirm),
                Err(Error::WrongPassword) => {
                    return Err("wrong password; nothing was exported".into());
                }
                Err(e) => return Err(Box::new(e)),
            }
            let records = vault.records(&keys)?;
            logindesk_vault::write_plaintext_csv(&file, &records)?;
            eprintln!(
                "Wrote {} record(s) in PLAINTEXT to {} (mode 0600).",
                records.len(),
                file.display()
            );
        }
        VaultCmd::Import { csv } => {
            let rows = logindesk_vault::parse_import_csv(std::fs::File::open(&csv)?)?;
            let n = rows.len();
            for row in rows {
                vault.add(
                    &keys,
                    NewRecord {
                        kind: RecordKind::Login,
                        site: row.site,
                        username: row.username,
                        secret: row.secret,
                        created_by: "import:csv".into(),
                        notes: row.notes,
                    },
                )?;
            }
            eprintln!(
                "Imported {n} login(s). The CSV still holds them in plaintext: delete {} now.",
                csv.display()
            );
        }
    }
    Ok(())
}
