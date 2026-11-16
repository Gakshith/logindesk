//! `logindesk install|uninstall|doctor` against a temp HOME. Never touches the real
//! user's client configs: HOME is a temp dir and PATH holds no real `claude`.
#![allow(clippy::unwrap_used)] // test code: a panic is a test failure

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};

use serde_json::{Value, json};

struct Home(PathBuf);
impl Home {
    fn new(tag: &str) -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        let p = std::env::temp_dir().join(format!(
            "logindesk-install-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Self(p.canonicalize().unwrap())
    }
    fn path(&self, rel: &str) -> PathBuf {
        self.0.join(rel)
    }
    fn write(&self, rel: &str, text: &str) {
        let p = self.path(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, text).unwrap();
    }
    fn backups(&self, rel: &str) -> usize {
        let p = self.path(rel);
        let name = format!("{}.bak-", p.file_name().unwrap().to_string_lossy());
        std::fs::read_dir(p.parent().unwrap())
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(&name)
            })
            .count()
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Run the binary with HOME = `home` and a PATH that has no real `claude`.
fn ld(home: &Home, path: &str, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_logindesk"))
        .args(args)
        .env_clear()
        .env("HOME", &home.0)
        .env("PATH", path)
        .output()
        .unwrap()
}

const SAFE_PATH: &str = "/usr/bin:/bin";

fn exe() -> String {
    Path::new(env!("CARGO_BIN_EXE_logindesk"))
        .canonicalize()
        .unwrap()
        .display()
        .to_string()
}

fn json_at(home: &Home, rel: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(home.path(rel)).unwrap()).unwrap()
}

/// One JSON client: install twice, dry-run, uninstall; the other entry and keys survive.
fn json_client(client: &str, rel: &str, key: &str, typed: bool) {
    let h = Home::new(client);
    h.write(
        rel,
        &json!({"theme": "dark", key: {"other": {"command": "/bin/other", "args": []}}})
            .to_string(),
    );

    // Dry run: prints a diff, writes nothing.
    let before = std::fs::read_to_string(h.path(rel)).unwrap();
    let o = ld(&h, SAFE_PATH, &["install", "--client", client, "--dry-run"]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let diff = String::from_utf8_lossy(&o.stdout);
    assert!(diff.contains("+") && diff.contains(&exe()), "{diff}");
    assert_eq!(std::fs::read_to_string(h.path(rel)).unwrap(), before);
    assert_eq!(h.backups(rel), 0);

    // Install: backup made, our entry has the absolute binary path, others kept.
    let o = ld(&h, SAFE_PATH, &["install", "--client", client]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert_eq!(h.backups(rel), 1);
    let v = json_at(&h, rel);
    assert_eq!(v["theme"], "dark");
    assert_eq!(v[key]["other"]["command"], "/bin/other");
    assert_eq!(v[key]["logindesk"]["command"], exe());
    assert_eq!(v[key]["logindesk"]["args"], json!(["mcp"]));
    assert_eq!(v[key]["logindesk"]["type"] == "stdio", typed);

    // Idempotent: nothing written, no new backup.
    let o = ld(&h, SAFE_PATH, &["install", "--client", client]);
    assert!(String::from_utf8_lossy(&o.stderr).contains("already up to date"));
    assert_eq!(h.backups(rel), 1);

    // Uninstall: only our entry goes.
    let o = ld(&h, SAFE_PATH, &["uninstall", "--client", client]);
    assert!(o.status.success());
    assert_eq!(h.backups(rel), 2);
    let v = json_at(&h, rel);
    assert!(v[key].get("logindesk").is_none());
    assert_eq!(v[key]["other"]["command"], "/bin/other");
    assert_eq!(v["theme"], "dark");
    let o = ld(&h, SAFE_PATH, &["uninstall", "--client", client]);
    assert!(String::from_utf8_lossy(&o.stderr).contains("is not in"));
    assert_eq!(h.backups(rel), 2);
}

#[test]
fn claude_desktop() {
    let rel = if cfg!(target_os = "macos") {
        "Library/Application Support/Claude/claude_desktop_config.json"
    } else {
        ".config/Claude/claude_desktop_config.json"
    };
    json_client("claude-desktop", rel, "mcpServers", false);
}

#[test]
fn cursor() {
    json_client("cursor", ".cursor/mcp.json", "mcpServers", false);
}

#[test]
fn vscode() {
    let rel = if cfg!(target_os = "macos") {
        "Library/Application Support/Code/User/mcp.json"
    } else {
        ".config/Code/User/mcp.json"
    };
    json_client("vscode", rel, "servers", true);
}

#[test]
fn gemini() {
    json_client("gemini", ".gemini/settings.json", "mcpServers", false);
}

#[test]
fn claude_code_file_fallback() {
    // No `claude` on PATH: the user-scope entry goes straight into ~/.claude.json.
    json_client("claude-code", ".claude.json", "mcpServers", true);
}

#[test]
fn new_file_and_vault_env() {
    let h = Home::new("fresh");
    let vault = h.path("v/vault.sqlite");
    let o = ld(
        &h,
        SAFE_PATH,
        &[
            "--vault",
            vault.to_str().unwrap(),
            "install",
            "--client",
            "cursor",
        ],
    );
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert_eq!(h.backups(".cursor/mcp.json"), 0, "nothing to back up");
    let v = json_at(&h, ".cursor/mcp.json");
    assert_eq!(
        v["mcpServers"]["logindesk"]["env"]["LOGINDESK_VAULT"],
        vault.display().to_string()
    );
}

#[test]
fn refuses_to_clobber_bad_json() {
    let h = Home::new("bad");
    h.write(".cursor/mcp.json", "{ not json");
    let o = ld(&h, SAFE_PATH, &["install", "--client", "cursor"]);
    assert!(!o.status.success());
    assert_eq!(
        std::fs::read_to_string(h.path(".cursor/mcp.json")).unwrap(),
        "{ not json"
    );
}

#[test]
fn codex_toml() {
    let h = Home::new("codex");
    let rel = ".codex/config.toml";
    let user = "# my settings\nmodel = \"o3\"\n\n[mcp_servers.other]\ncommand = \"/bin/other\"\nargs = [\"x\"]\n\n[history]\npersistence = \"none\"\n";
    h.write(rel, user);
    let o = ld(&h, SAFE_PATH, &["install", "--client", "codex"]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert_eq!(h.backups(rel), 1);
    let t = std::fs::read_to_string(h.path(rel)).unwrap();
    assert!(
        t.starts_with(user.trim_end()),
        "user text kept byte for byte:\n{t}"
    );
    assert!(t.contains(&format!(
        "[mcp_servers.logindesk]\ncommand = \"{}\"\nargs = [\"mcp\"]\n",
        exe()
    )));
    let o = ld(&h, SAFE_PATH, &["install", "--client", "codex"]);
    assert!(String::from_utf8_lossy(&o.stderr).contains("already up to date"));
    assert_eq!(h.backups(rel), 1);
    let o = ld(&h, SAFE_PATH, &["uninstall", "--client", "codex"]);
    assert!(o.status.success());
    let t = std::fs::read_to_string(h.path(rel)).unwrap();
    assert!(!t.contains("logindesk"));
    assert_eq!(t.trim_end(), user.trim_end());
}

#[test]
fn claude_code_uses_the_claude_cli_when_present() {
    let h = Home::new("ccli");
    // A stand-in `claude` that logs its arguments.
    let bin = h.path("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let log = h.path("claude.log");
    let script = bin.join("claude");
    std::fs::write(
        &script,
        format!("#!/bin/sh\necho \"$@\" >> '{}'\n", log.display()),
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    h.write(".claude.json", "{\"numStartups\": 1}");
    let path = format!("{}:{SAFE_PATH}", bin.display());

    let o = ld(
        &h,
        &path,
        &["install", "--client", "claude-code", "--dry-run"],
    );
    assert!(o.status.success());
    assert!(String::from_utf8_lossy(&o.stdout).contains("mcp add --scope user logindesk -- "));
    assert!(!log.exists(), "dry run ran claude");

    let o = ld(&h, &path, &["install", "--client", "claude-code"]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert_eq!(h.backups(".claude.json"), 1);
    let calls = std::fs::read_to_string(&log).unwrap();
    assert!(calls.contains("mcp remove --scope user logindesk"));
    assert!(calls.contains(&format!("mcp add --scope user logindesk -- {} mcp", exe())));
}

#[test]
fn doctor_with_missing_vault_reports_and_does_not_panic() {
    let h = Home::new("doctor");
    let vault = h.path("nope/vault.sqlite");
    let o = ld(
        &h,
        SAFE_PATH,
        &["--vault", vault.to_str().unwrap(), "doctor"],
    );
    let err = String::from_utf8_lossy(&o.stderr);
    eprintln!("{err}");
    assert!(!o.status.success());
    assert!(!err.contains("panicked"), "{err}");
    assert!(err.contains("✗ vault: none at"), "{err}");
    assert!(err.contains("fix: run `logindesk setup`"), "{err}");
    assert!(err.contains("✗ daemon: not running"), "{err}");
    assert!(err.contains("– approval popup: not tested"), "{err}");
    assert!(err.contains("stdout:"), "{err}");
    // With Chrome installed, the sealed browser maps the local test page.
    assert!(
        err.contains("✓ sealed browser: launches headless, maps and fills a test login form")
            || err.contains("– sealed browser: not tested (no Chrome)"),
        "{err}"
    );
    assert!(o.stdout.is_empty(), "doctor wrote to stdout");
}

#[test]
fn doctor_flags_a_client_pointing_at_a_missing_binary() {
    let h = Home::new("doctor-client");
    h.write(
        ".cursor/mcp.json",
        r#"{"mcpServers":{"logindesk":{"command":"/gone/logindesk","args":["mcp"]}}}"#,
    );
    let vault = h.path("vault.sqlite");
    let o = ld(
        &h,
        SAFE_PATH,
        &["--vault", vault.to_str().unwrap(), "doctor"],
    );
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(
        err.contains("✗ Cursor: points to /gone/logindesk, which does not exist"),
        "{err}"
    );
    assert!(err.contains("logindesk install --client cursor"), "{err}");
}
