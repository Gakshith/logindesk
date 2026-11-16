//! `logindesk doctor`: one line per check, ✓ or ✗ with a one-line fix.
//! Never shows the Touch ID sheet unless `--popup` is passed. Never prints a secret.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, SystemTime};

use logindesk_approver::{Action, ApprovalOutcome, ApprovalRequest};
use logindesk_core::ids::RequestId;
use logindesk_daemon::mailcfg::MailConfig;
use logindesk_policy::Grants;
use serde_json::{Value, json};

use crate::install::{self, Client};

/// How long `logindesk mcp` gets to answer `initialize`.
const MCP_REPLY: Duration = Duration::from_secs(10);

/// One check's result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mark {
    /// Passed.
    Ok,
    /// Failed: needs the fix.
    Fail,
    /// Not set up / not run; informational.
    Skip,
}

/// One line of the report.
#[derive(Debug, Clone)]
pub struct Check {
    /// Pass, fail or skip.
    pub mark: Mark,
    /// What was checked and what was found.
    pub what: String,
    /// One-line fix (shown when not passing).
    pub fix: String,
}

fn ok(what: impl Into<String>) -> Check {
    Check {
        mark: Mark::Ok,
        what: what.into(),
        fix: String::new(),
    }
}

fn fail(what: impl Into<String>, fix: impl Into<String>) -> Check {
    Check {
        mark: Mark::Fail,
        what: what.into(),
        fix: fix.into(),
    }
}

fn skip(what: impl Into<String>, fix: impl Into<String>) -> Check {
    Check {
        mark: Mark::Skip,
        what: what.into(),
        fix: fix.into(),
    }
}

/// Inputs.
#[derive(Debug)]
pub struct Opts {
    /// Vault file.
    pub vault: PathBuf,
    /// Data dir beside the vault (socket, token, mail.json).
    pub data_dir: PathBuf,
    /// Home dir (client configs).
    pub home: Option<PathBuf>,
    /// Show the Touch ID sheet.
    pub popup: bool,
}

/// Run every check.
pub fn run(o: &Opts) -> Vec<Check> {
    let mut v = vec![
        chrome(),
        browser_smoke(),
        vault(&o.vault),
        daemon(&o.data_dir),
        grants(&o.vault),
    ];
    v.push(mail(&o.data_dir));
    match &o.home {
        Some(h) => v.extend(clients(h)),
        None => v.push(skip("client configs: HOME is not set", "set HOME")),
    }
    v.push(stdout_clean(&o.vault));
    v.push(popup(o.popup));
    v
}

/// Print the report to stderr (human output). Returns true when nothing failed.
pub fn report(checks: &[Check]) -> bool {
    let mut e = std::io::stderr().lock();
    for c in checks {
        let m = match c.mark {
            Mark::Ok => "✓",
            Mark::Fail => "✗",
            Mark::Skip => "–",
        };
        let _ = writeln!(e, "{m} {}", c.what);
        if c.mark != Mark::Ok && !c.fix.is_empty() {
            let _ = writeln!(e, "    fix: {}", c.fix);
        }
    }
    let failed = checks.iter().filter(|c| c.mark == Mark::Fail).count();
    if failed == 0 {
        let _ = writeln!(e, "All checks passed.");
    } else {
        let _ = writeln!(e, "{failed} check(s) failed.");
    }
    failed == 0
}

/// Same lookup order as the executor.
fn find_chrome() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("LOGINDESK_CHROME").filter(|p| !p.is_empty()) {
        let p = PathBuf::from(p);
        return p.is_file().then_some(p);
    }
    let fixed = [
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Chromium.app/Contents/MacOS/Chromium",
    ];
    if let Some(p) = fixed.iter().map(Path::new).find(|p| p.is_file()) {
        return Some(p.to_path_buf());
    }
    let path = std::env::var_os("PATH")?;
    ["google-chrome", "chromium"].iter().find_map(|b| {
        std::env::split_paths(&path)
            .map(|d| d.join(b))
            .find(|p| p.is_file())
    })
}

fn chrome() -> Check {
    match find_chrome() {
        Some(p) => ok(format!("Chrome: {}", p.display())),
        None => fail(
            "Chrome: not found",
            "install Google Chrome, or set LOGINDESK_CHROME=/path/to/chrome",
        ),
    }
}

/// The test page: a login form built by JS after `load`, like a real SPA.
const SMOKE_PAGE: &str = r#"<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>logindesk doctor</title></head><body><h1>logindesk doctor</h1><div id="app"></div>
<script>setTimeout(function () { document.getElementById('app').innerHTML =
'<form method="post" action="/never"><label for="u">Email</label> <input id="u" type="email" autocomplete="username">' +
'<label for="p">Password</label> <input id="p" type="password" autocomplete="current-password">' +
'<button type="submit">Sign in</button></form>'; }, 300);</script></body></html>"#;

/// Serve [`SMOKE_PAGE`] on 127.0.0.1 until `stop` is set. Returns the port.
fn serve_smoke_page(
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> std::io::Result<(u16, std::thread::JoinHandle<()>)> {
    use std::io::Read;
    use std::sync::atomic::Ordering;
    let l = std::net::TcpListener::bind("127.0.0.1:0")?;
    l.set_nonblocking(true)?;
    let port = l.local_addr()?.port();
    let h = std::thread::spawn(move || {
        while !stop.load(Ordering::Relaxed) {
            match l.accept() {
                Ok((mut c, _)) => {
                    let _ = c.set_nonblocking(false);
                    let _ = c.set_read_timeout(Some(Duration::from_secs(2)));
                    let mut buf = [0u8; 4096];
                    let _ = c.read(&mut buf);
                    let get_root = buf.starts_with(b"GET / ");
                    let (status, body) = if get_root {
                        ("200 OK", SMOKE_PAGE)
                    } else {
                        ("404 Not Found", "")
                    };
                    let _ = write!(
                        c,
                        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                }
                Err(_) => std::thread::sleep(Duration::from_millis(20)),
            }
        }
    });
    Ok((port, h))
}

/// Launch the sealed browser headless on a throwaway profile, open a local test login
/// page, and map + fill it with dummy values (never submitted, no secret).
fn browser_smoke() -> Check {
    use logindesk_executor::{BrowserConfig, ExecError, FormKind, Session};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    const SITE: &str = "doctor.localhost";
    if find_chrome().is_none() {
        return skip(
            "sealed browser: not tested (no Chrome)",
            "install Google Chrome",
        );
    }
    let stop = Arc::new(AtomicBool::new(false));
    let (port, server) = match serve_smoke_page(stop.clone()) {
        Ok(x) => x,
        Err(e) => {
            return fail(
                format!("sealed browser: cannot serve the local test page ({e})"),
                "check that 127.0.0.1 is reachable",
            );
        }
    };
    let profile = std::env::temp_dir().join(format!("logindesk-doctor-{}", std::process::id()));
    let result = (|| {
        let mut s = Session::launch(&BrowserConfig {
            chrome: None,
            profile_dir: profile.clone(),
            headless: true,
        })?;
        s.navigate(&format!("http://{SITE}:{port}/"))?;
        s.rehearse(SITE, FormKind::Login)
    })();
    stop.store(true, Ordering::Relaxed);
    let _ = server.join();
    let _ = std::fs::remove_dir_all(&profile);
    let fix = "run `logindesk doctor` again; if it repeats, report the reason shown";
    match result {
        Ok(shape) if shape.passwords == 1 => {
            ok("sealed browser: launches headless, maps and fills a test login form")
        }
        Ok(_) => fail(
            "sealed browser: mapped the test form without its password field",
            fix,
        ),
        Err(ExecError::Mapping(m)) => fail(
            format!("sealed browser: could not map the test form ({})", m.wire()),
            fix,
        ),
        Err(e) => fail(format!("sealed browser: {e}"), fix),
    }
}

fn vault(path: &Path) -> Check {
    if !path.exists() {
        return fail(
            format!("vault: none at {}", path.display()),
            "run `logindesk setup` (or pass --vault / set LOGINDESK_VAULT)",
        );
    }
    match logindesk_vault::Vault::open(path) {
        Ok(_) => ok(format!("vault: {}", path.display())),
        Err(e) => fail(
            format!("vault: {} does not open ({e})", path.display()),
            "check the path; restore from an encrypted export if it is damaged",
        ),
    }
}

fn mode(p: &Path) -> Option<u32> {
    std::fs::symlink_metadata(p)
        .ok()
        .map(|m| m.permissions().mode() & 0o777)
}

fn daemon(dir: &Path) -> Check {
    let sock = match logindesk_core::paths::socket_path(dir) {
        Ok(s) => s,
        Err(e) => {
            return fail(
                format!("daemon: socket path unusable ({e})"),
                "remove the stale /tmp/logindesk-* directory and restart `logindesk daemon`",
            );
        }
    };
    let is_sock = std::fs::symlink_metadata(&sock).is_ok_and(|m| m.file_type().is_socket());
    if !is_sock {
        return fail(
            "daemon: not running",
            "run `logindesk daemon` in a terminal",
        );
    }
    let sock_mode = mode(&sock);
    let dir_mode = sock.parent().and_then(mode);
    if sock_mode != Some(0o600) || dir_mode.is_none_or(|m| m & 0o077 != 0) {
        return fail(
            format!(
                "daemon: socket permissions {:o} (dir {:o}), want 600 (dir 700)",
                sock_mode.unwrap_or(0),
                dir_mode.unwrap_or(0)
            ),
            "stop the daemon, `chmod 700` its data dir, and start it again",
        );
    }
    let r = logindesk_mcp::client::call(dir, "doctor", json!({"op": "ping"}));
    if r["status"] == "ok" {
        ok(format!(
            "daemon: answers ping (socket 600, dir 700) at {}",
            sock.display()
        ))
    } else {
        fail(
            format!("daemon: socket exists but ping got {}", r["status"]),
            "restart `logindesk daemon` (a stale socket or token)",
        )
    }
}

fn grants(vault: &Path) -> Check {
    let p = Grants::path_beside(vault);
    match Grants::load(&p) {
        Ok(g) => ok(format!(
            "grants: {} site(s) ({})",
            g.login.len(),
            p.display()
        )),
        Err(e) => fail(
            format!("grants: {} does not parse ({e})", p.display()),
            "fix the JSON, or delete the file and re-add grants with `logindesk grant add`",
        ),
    }
}

fn mail(dir: &Path) -> Check {
    let cfg = match MailConfig::load(dir) {
        Ok(Some(c)) => c,
        Ok(None) => {
            return skip(
                "mail: not set (sites that email a code return email_not_connected)",
                "`logindesk mail set mailpit http://127.0.0.1:8025` (or `outbox <url>`)",
            );
        }
        Err(e) => {
            return fail(
                format!("mail: {} is invalid ({e})", MailConfig::path(dir).display()),
                "`logindesk mail off`, then `logindesk mail set ...` again",
            );
        }
    };
    // Doctor never asks for the vault password, so it cannot load Gmail/IMAP
    // credentials; those are checked by `logindesk connect status`.
    if matches!(
        cfg.kind,
        logindesk_daemon::mailcfg::MailKind::Gmail | logindesk_daemon::mailcfg::MailKind::Imap
    ) {
        return ok(format!(
            "mail: {:?} configured (live check: `logindesk connect status`)",
            cfg.kind
        ));
    }
    let creds = logindesk_daemon::mailcfg::MailCreds::default();
    let Some(src) = cfg.source(&creds) else {
        return fail(
            "mail: no source for this config",
            "`logindesk mail set ...` again",
        );
    };
    let q = logindesk_mail::MailQuery {
        site: "doctor.invalid".into(),
        since: SystemTime::now(),
    };
    match src.search(&q) {
        Ok(_) => ok(format!("mail: {:?} at {} answers", cfg.kind, cfg.url)),
        Err(e) => fail(
            format!(
                "mail: {:?} at {} does not answer ({e:?})",
                cfg.kind, cfg.url
            ),
            "start the mailbox, or point `logindesk mail set` at the right URL",
        ),
    }
}

fn clients(home: &Path) -> Vec<Check> {
    let mut out = Vec::new();
    for c in Client::ALL {
        match install::installed_command(c, home) {
            Ok(None) => {}
            Ok(Some(cmd)) if Path::new(&cmd).is_file() => {
                out.push(ok(format!("{}: points to {cmd}", c.label())));
            }
            Ok(Some(cmd)) => out.push(fail(
                format!("{}: points to {cmd}, which does not exist", c.label()),
                format!("`logindesk install --client {}`", client_arg(c)),
            )),
            Err(e) => out.push(fail(
                format!(
                    "{}: {} does not parse ({e})",
                    c.label(),
                    c.config_path(home).display()
                ),
                "fix the file, then `logindesk install` again",
            )),
        }
    }
    if out.is_empty() {
        out.push(skip(
            "clients: logindesk is not in any client config",
            "`logindesk install --client claude-code` (or claude-desktop, cursor, vscode, codex, gemini)",
        ));
    }
    out
}

fn client_arg(c: Client) -> String {
    clap::ValueEnum::to_possible_value(&c)
        .map(|v| v.get_name().to_string())
        .unwrap_or_default()
}

/// Spawn `logindesk mcp`, send `initialize`, and check every stdout line is JSON-RPC.
fn stdout_clean(vault: &Path) -> Check {
    let fix = "something prints to stdout in mcp mode; report it (logs must go to stderr)";
    let exe = match std::env::current_exe() {
        Ok(e) => e,
        Err(e) => return fail(format!("stdout: cannot find own binary ({e})"), fix),
    };
    let child = Command::new(exe)
        .arg("--vault")
        .arg(vault)
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn();
    let mut child = match child {
        Ok(c) => c,
        Err(e) => return fail(format!("stdout: cannot start `logindesk mcp` ({e})"), fix),
    };
    let init = json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "logindesk-doctor", "version": env!("CARGO_PKG_VERSION")}
        }
    });
    // Keep stdin open until we have the reply: closing it ends the server.
    let mut stdin = child.stdin.take();
    if let Some(s) = stdin.as_mut() {
        let _ = writeln!(s, "{init}");
    }
    let (tx, rx) = mpsc::channel();
    if let Some(out) = child.stdout.take() {
        std::thread::spawn(move || {
            for line in BufReader::new(out).lines() {
                let Ok(l) = line else { break };
                if tx.send(l).is_err() {
                    break;
                }
            }
        });
    }
    let verdict = loop {
        match rx.recv_timeout(MCP_REPLY) {
            Ok(l) => match serde_json::from_str::<Value>(&l) {
                Ok(v) if v["jsonrpc"] == "2.0" => {
                    if v["id"] == 1 {
                        break ok("stdout: `logindesk mcp` answers initialize with JSON-RPC only");
                    }
                }
                _ => break fail("stdout: `logindesk mcp` printed a non-JSON-RPC line", fix),
            },
            Err(mpsc::RecvTimeoutError::Timeout) => {
                break fail(
                    "stdout: `logindesk mcp` did not answer initialize in 10 s",
                    "run `logindesk mcp` by hand and look at its stderr",
                );
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                break fail(
                    "stdout: `logindesk mcp` exited without answering initialize",
                    "run `logindesk mcp` by hand and look at its stderr",
                );
            }
        }
    };
    drop(stdin);
    let _ = child.kill();
    let _ = child.wait();
    verdict
}

/// `logindesk doctor`. Fails (exit 1) when any check fails.
pub fn cmd(vault: &Path, data_dir: &Path, popup: bool) -> Result<(), Box<dyn std::error::Error>> {
    let o = Opts {
        vault: vault.to_path_buf(),
        data_dir: data_dir.to_path_buf(),
        home: std::env::var_os("HOME")
            .filter(|h| !h.is_empty())
            .map(PathBuf::from),
        popup,
    };
    if report(&run(&o)) {
        Ok(())
    } else {
        Err("doctor found problems (see the fixes above)".into())
    }
}

fn popup(show: bool) -> Check {
    if !show {
        return skip(
            "approval popup: not tested",
            "`logindesk doctor --popup` shows the Touch ID sheet once",
        );
    }
    let req = ApprovalRequest {
        request_id: RequestId::random(),
        client_name: "logindesk doctor".into(),
        action: Action::Pair,
        site: "doctor test".into(),
        shares: vec![],
    };
    let outcome =
        logindesk_daemon::system_approver().approve(&req, logindesk_core::limits::APPROVAL_IN_CALL);
    match outcome {
        ApprovalOutcome::Approved => ok("approval popup: shown and approved"),
        ApprovalOutcome::Denied => fail(
            "approval popup: shown, denied",
            "run again and approve with Touch ID or your Mac password",
        ),
        ApprovalOutcome::TimedOut => fail(
            "approval popup: nobody answered in 40 s",
            "run again and answer the sheet",
        ),
        ApprovalOutcome::Unavailable => fail(
            "approval popup: unavailable (no GUI session or unsupported OS)",
            "run doctor from a logged-in macOS desktop session",
        ),
    }
}
