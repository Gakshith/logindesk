//! The `daemon`, `mcp`, `grant`, `mail`, `login` and `lock` commands, as
//! processes. No test here opens a browser or a Touch ID prompt: logins use a
//! `deny` grant or an unknown site, so they stop before either.
#![allow(clippy::unwrap_used)] // test code: a panic is a test failure

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

const PW: &str = "correct horse battery";
const SECRET: &str = "CANARY-daemon-pw-4be1";

struct Tmp(PathBuf);
impl Tmp {
    fn new() -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        // Short: a Unix socket path is limited to 104 bytes on macOS.
        let p = std::env::temp_dir().join(format!(
            "ldc{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
    fn vault(&self) -> PathBuf {
        self.0.join("vault.sqlite")
    }
}
impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Out {
    ok: bool,
    stdout: String,
    stderr: String,
}

fn cmd(vault: &Path, args: &[&str]) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_logindesk"));
    c.arg("--vault")
        .arg(vault)
        .arg("--password-stdin")
        .args(args)
        .env_remove("LOGINDESK_VAULT")
        .env_remove("LOGINDESK_HEADFUL");
    c
}

fn run(vault: &Path, args: &[&str], stdin_lines: &[&str]) -> Out {
    let mut child = cmd(vault, args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    {
        let mut stdin = child.stdin.take().unwrap();
        for l in stdin_lines {
            writeln!(stdin, "{l}").unwrap();
        }
    }
    let o = child.wait_with_output().unwrap();
    Out {
        ok: o.status.success(),
        stdout: String::from_utf8_lossy(&o.stdout).into(),
        stderr: String::from_utf8_lossy(&o.stderr).into(),
    }
}

fn setup_with_account(t: &Tmp) {
    let o = run(
        &t.vault(),
        &[
            "setup",
            "--kdf-memory-kib",
            "19456",
            "--kdf-iterations",
            "2",
        ],
        &[PW, PW],
    );
    assert!(o.ok, "{}", o.stderr);
    let o = run(
        &t.vault(),
        &[
            "vault",
            "add",
            "--site",
            "https://www.example.com/login",
            "--username",
            "alice",
        ],
        &[PW, SECRET],
    );
    assert!(o.ok, "{}", o.stderr);
}

/// Kills the daemon when the test ends, pass or fail.
struct Daemon(Child);
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn start_daemon(t: &Tmp) -> Daemon {
    let mut child = cmd(&t.vault(), &["daemon"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    writeln!(child.stdin.take().unwrap(), "{PW}").unwrap();
    let d = Daemon(child);
    let sock = t.0.join("daemon.sock");
    let token = t.0.join("client.token");
    let start = Instant::now();
    while !(sock.exists() && token.exists()) {
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "daemon did not start"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    d
}

fn reply(o: &Out) -> Value {
    serde_json::from_str(o.stdout.trim()).unwrap_or_else(|_| panic!("not JSON: {}", o.stdout))
}

#[test]
fn grants_and_mail_config() {
    let t = Tmp::new();
    let v = t.vault();
    assert!(
        run(
            &v,
            &[
                "grant",
                "add",
                "https://www.example.com/x",
                "--tier",
                "auto"
            ],
            &[]
        )
        .ok
    );
    assert!(run(&v, &["grant", "add", "other.org", "--tier", "deny"], &[]).ok);
    let o = run(&v, &["grant", "list"], &[]);
    assert!(o.ok);
    assert!(
        o.stdout.contains("example.com") && o.stdout.contains("auto"),
        "{}",
        o.stdout
    );
    assert!(o.stdout.contains("other.org") && o.stdout.contains("deny"));
    assert!(run(&v, &["grant", "remove", "other.org"], &[]).ok);
    assert!(!run(&v, &["grant", "remove", "other.org"], &[]).ok);
    assert!(!run(&v, &["grant", "add", "not a site", "--tier", "auto"], &[]).ok);
    assert!(!run(&v, &["grant", "add", "x.com", "--tier", "maybe"], &[]).ok);
    let g = std::fs::read_to_string(t.0.join("grants.json")).unwrap();
    assert!(
        g.contains("\"example.com\": \"auto\"") && !g.contains("other.org"),
        "{g}"
    );

    let signup_grant = [
        "grant",
        "add",
        "example.com",
        "--tier",
        "auto",
        "--action",
        "signup",
    ];
    assert!(run(&v, &signup_grant, &[]).ok);
    let o = run(&v, &["grant", "list"], &[]);
    assert!(o.stdout.contains("signup  auto"), "{}", o.stdout);
    let g = std::fs::read_to_string(t.0.join("grants.json")).unwrap();
    assert!(g.contains("\"signup\""), "{g}");
    assert!(
        run(
            &v,
            &["grant", "remove", "example.com", "--action", "signup"],
            &[]
        )
        .ok
    );

    assert!(!run(&v, &["identity", "show"], &[]).ok);
    assert!(!run(&v, &["identity", "set", "--email", "not-an-email"], &[]).ok);
    let set = [
        "identity",
        "set",
        "--email",
        "you@mail.test",
        "--name",
        "Ann",
    ];
    assert!(run(&v, &set, &[]).ok);
    let o = run(&v, &["identity", "show"], &[]);
    assert!(
        o.ok && o.stdout.contains("you@mail.test") && o.stdout.contains("Ann"),
        "{}",
        o.stdout
    );

    assert!(
        run(
            &v,
            &["mail", "set", "mailpit", "http://127.0.0.1:8025"],
            &[]
        )
        .ok
    );
    let m = std::fs::read_to_string(t.0.join("mail.json")).unwrap();
    assert!(m.contains("mailpit") && m.contains("127.0.0.1:8025"), "{m}");
    assert!(!run(&v, &["mail", "set", "mailpit", "ftp://x"], &[]).ok);
    assert!(run(&v, &["mail", "off"], &[]).ok);
    assert!(!t.0.join("mail.json").exists());
}

#[test]
fn login_without_daemon_says_how_to_start_it() {
    let t = Tmp::new();
    let o = run(&t.vault(), &["login", "example.com"], &[]);
    assert!(!o.ok);
    let r = reply(&o);
    assert_eq!(r["status"], "failed");
    assert_eq!(r["reason"], "internal");
    assert!(r["message"].as_str().unwrap().contains("logindesk daemon"));
}

/// A line-oriented MCP stdio client.
struct Mcp {
    child: Child,
    lines: mpsc::Receiver<String>,
    raw: Vec<String>,
}

impl Mcp {
    fn start(vault: &Path) -> Self {
        let mut child = cmd(vault, &["mcp"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let out = child.stdout.take().unwrap();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for l in BufReader::new(out).lines().map_while(Result::ok) {
                if tx.send(l).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            lines: rx,
            raw: Vec::new(),
        }
    }
    fn send(&mut self, v: Value) {
        let stdin = self.child.stdin.as_mut().unwrap();
        writeln!(stdin, "{v}").unwrap();
        stdin.flush().unwrap();
    }
    fn wait_id(&mut self, id: u64) -> Value {
        loop {
            let l = self.lines.recv_timeout(Duration::from_secs(20)).unwrap();
            self.raw.push(l.clone());
            let v: Value =
                serde_json::from_str(&l).unwrap_or_else(|_| panic!("stdout is not MCP: {l}"));
            if v["id"] == id {
                return v;
            }
        }
    }
    fn call(&mut self, id: u64, name: &str, args: Value) -> Value {
        self.send(json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":name,"arguments":args}}));
        let r = self.wait_id(id);
        let text = r["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or_else(|| panic!("{r}"));
        serde_json::from_str(text).unwrap()
    }
}

impl Drop for Mcp {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn daemon_serves_cli_and_mcp_and_never_leaks() {
    let t = Tmp::new();
    setup_with_account(&t);
    let v = t.vault();
    assert!(run(&v, &["grant", "add", "example.com", "--tier", "deny"], &[]).ok);
    let _d = start_daemon(&t);

    // CLI client: the grant is enforced by the daemon.
    let o = run(&v, &["login", "example.com"], &[]);
    let r = reply(&o);
    assert_eq!(
        (r["status"].as_str(), r["reason"].as_str()),
        (Some("failed"), Some("grant_denied"))
    );
    let o = run(&v, &["login", "nowhere.test"], &[]);
    assert_eq!(reply(&o)["reason"], "no_account");

    // MCP: tools listed, accounts listed without secrets, sessions fenced by id.
    let mut m = Mcp::start(&v);
    m.send(
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
        "protocolVersion":"2025-03-26","capabilities":{},
        "clientInfo":{"name":"test-agent","version":"0"}}}),
    );
    let init = m.wait_id(1);
    assert!(init["result"]["serverInfo"].is_object(), "{init}");
    m.send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}));
    m.send(json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}));
    let tools = m.wait_id(2);
    let mut names: Vec<String> = tools["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_string())
        .collect();
    names.sort();
    assert_eq!(
        names,
        [
            "click",
            "close_session",
            "fill_secret",
            "list_accounts",
            "login",
            "navigate",
            "open",
            "press_enter",
            "signup",
            "snapshot",
            "type",
            "wait"
        ]
    );
    // The new tools steer the agent: snapshot first, type only non-secrets,
    // fill_secret for passwords/codes/email, never ask the user for a secret.
    let desc = |name: &str| {
        tools["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["name"] == name)
            .unwrap()["description"]
            .as_str()
            .unwrap()
            .replace('\n', " ")
    };
    let ty = desc("type");
    assert!(
        ty.contains("snapshot") && ty.contains("fill_secret") && ty.contains("Never ask the user"),
        "{ty}"
    );
    let fs = desc("fill_secret");
    assert!(
        fs.contains("snapshot") && fs.contains("new_password") && fs.contains("never ask the user"),
        "{fs}"
    );
    assert!(desc("login").contains("field_mapping_failed"));
    assert!(desc("signup").contains("fill_secret"));
    let schema = tools["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"] == "fill_secret")
        .unwrap()["inputSchema"]
        .to_string();
    for k in ["password", "new_password", "email", "code"] {
        assert!(schema.contains(&format!("\"{k}\"")), "{schema}");
    }
    for t in tools["result"]["tools"].as_array().unwrap() {
        let d = t["description"].as_str().unwrap().replace('\n', " ");
        assert!(
            d.contains("Secrets are filled by the broker and never returned"),
            "{d}"
        );
    }

    let accts = m.call(3, "list_accounts", json!({}));
    assert_eq!(accts["status"], "ok");
    assert_eq!(accts["data"]["accounts"][0]["username"], "alice");
    assert_eq!(accts["data"]["accounts"][0]["site"], "example.com");
    let r = m.call(4, "login", json!({"site":"example.com"}));
    assert_eq!(r["reason"], "grant_denied");
    let r = m.call(5, "snapshot", json!({"session_id":"0".repeat(32)}));
    assert_eq!(r["reason"], "session_not_found");
    let r = m.call(6, "click", json!({"session_id":"x","ref":3}));
    assert_eq!(r["reason"], "session_not_found");
    // Signup on a blocklisted site is refused before any browser; wait on a bad handle.
    let r = m.call(7, "signup", json!({"site":"paypal.com"}));
    assert_eq!(r["reason"], "grant_denied");
    let r = m.call(8, "wait", json!({"handle":"0".repeat(32)}));
    assert_eq!(r["reason"], "session_not_found");
    for l in &m.raw {
        assert!(!l.contains(SECRET), "MCP output leaked the secret: {l}");
    }
    drop(m);

    // The audit log names the MCP client and holds no secret.
    let audit = std::fs::read_to_string(t.0.join("audit.jsonl")).unwrap();
    assert!(audit.contains("\"client\":\"test-agent\""), "{audit}");
    assert!(audit.contains("\"client\":\"cli\""));
    assert!(!audit.contains(SECRET));

    // lock: the daemon drops its keys; logins then say vault_locked.
    let o = run(&v, &["lock"], &[]);
    assert!(o.ok, "{}", o.stderr);
    assert!(o.stderr.contains("dropped its vault keys"), "{}", o.stderr);
    assert_eq!(
        reply(&run(&v, &["login", "example.com"], &[]))["status"],
        "vault_locked"
    );
}

/// The 2026-07-28 MCP lifecycle sends no `initialize`: `clientInfo` travels in each
/// request's `_meta`. The agent's name must still reach the audit log.
#[test]
fn per_request_client_info_names_the_agent_in_the_audit() {
    let t = Tmp::new();
    setup_with_account(&t);
    let v = t.vault();
    assert!(run(&v, &["grant", "add", "example.com", "--tier", "deny"], &[]).ok);
    let _d = start_daemon(&t);
    let mut m = Mcp::start(&v);
    let meta = json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {},
        "io.modelcontextprotocol/clientInfo": {"name": "claude-code", "version": "2.1"}
    });
    m.send(
        json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
        "name":"login","arguments":{"site":"example.com"},"_meta": meta}}),
    );
    let r = m.wait_id(1);
    let text = r["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("{r}"));
    let reply: Value = serde_json::from_str(text).unwrap();
    assert_eq!(reply["reason"], "grant_denied");
    drop(m);
    let audit = std::fs::read_to_string(t.0.join("audit.jsonl")).unwrap();
    assert!(
        audit.contains(r#""client":"claude-code","op":"login""#),
        "{audit}"
    );
    assert!(!audit.contains("unknown-mcp-client"), "{audit}");
}
