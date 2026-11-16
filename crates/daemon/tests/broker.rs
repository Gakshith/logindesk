//! Broker and socket tests with a fake browser, a scripted approver and a fake
//! mailbox. The real Chrome end to end runs after the lanes merge.
#![allow(clippy::unwrap_used)] // test code: a panic is a test failure

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use logindesk_approver::{
    Action, ApprovalOutcome, ApprovalRequest, ApprovalToken, Approver, Scripted,
};
use logindesk_core::SecretString;
use logindesk_daemon::audit;
use logindesk_daemon::browser::{Browser, Launcher};
use logindesk_daemon::mailcfg::MailProvider;
use logindesk_daemon::proto::{MAX_FRAME, Op, Reply, Request, read_frame, write_frame};
use logindesk_daemon::server::{self, Server};
use logindesk_daemon::{Broker, Config, Deps};
use logindesk_executor::{BrowserConfig, ExecError, PageState, Snapshot};
use logindesk_mail::{MailError, MailQuery, MailSource, RawMessage};
use logindesk_policy::{Grants, Tier};
use logindesk_vault::{KdfParams, NewRecord, RecordKind, Vault};

const PW: &str = "correct horse battery";
/// Planted in the vault; must never appear in a reply or the audit log.
const MARKER: &str = "CANARY-pw-9d41e7b2c0";

// ---------- fakes ----------

#[derive(Debug, Default)]
struct Calls {
    launches: usize,
    closes: usize,
    navigations: Vec<String>,
    fills: Vec<(String, String)>,
    profile_dirs: Vec<PathBuf>,
}

#[derive(Debug)]
struct Script {
    after_fill: Result<PageState, ExecError>,
    calls: Mutex<Calls>,
}

struct FakeBrowser {
    script: Arc<Script>,
    url: String,
}

impl Browser for FakeBrowser {
    fn navigate(&mut self, url: &str) -> Result<(), ExecError> {
        self.script
            .calls
            .lock()
            .unwrap()
            .navigations
            .push(url.into());
        self.url = url.into();
        Ok(())
    }
    fn current_url(&mut self) -> Result<String, ExecError> {
        Ok(self.url.clone())
    }
    fn snapshot(&mut self) -> Result<Snapshot, ExecError> {
        Ok(Snapshot {
            url: self.url.clone(),
            title: "Dashboard".into(),
            lines: vec![
                "[11] link \"Settings\"".into(),
                "[12] textbox \"Password\" (filled)".into(),
            ],
        })
    }
    fn click(&mut self, node_ref: u64) -> Result<(), ExecError> {
        if node_ref == 11 {
            self.url = format!("{}#settings", self.url);
            Ok(())
        } else {
            Err(ExecError::Mapping)
        }
    }
    fn page_state(&mut self) -> Result<PageState, ExecError> {
        Ok(PageState::LoggedIn)
    }
    fn fill_login(
        &mut self,
        site: &str,
        username: &str,
        password: &SecretString,
        token: ApprovalToken,
    ) -> Result<PageState, ExecError> {
        // Same rule as the real executor: no valid token, no fill.
        token
            .spend(Action::Login, site)
            .map_err(|_| ExecError::Token)?;
        assert_eq!(
            password.expose(),
            MARKER,
            "the vault password reaches the fill"
        );
        self.script
            .calls
            .lock()
            .unwrap()
            .fills
            .push((site.into(), username.into()));
        self.script.after_fill
    }
    fn fill_otp(&mut self, _site: &str, _code: &SecretString) -> Result<PageState, ExecError> {
        Ok(PageState::LoggedIn)
    }
    fn close(self: Box<Self>) {
        self.script.calls.lock().unwrap().closes += 1;
    }
}

struct FakeLauncher(Arc<Script>);

impl Launcher for FakeLauncher {
    fn launch(&self, cfg: &BrowserConfig) -> Result<Box<dyn Browser>, ExecError> {
        let mut c = self.0.calls.lock().unwrap();
        c.launches += 1;
        c.profile_dirs.push(cfg.profile_dir.clone());
        Ok(Box::new(FakeBrowser {
            script: Arc::clone(&self.0),
            url: String::new(),
        }))
    }
}

/// Counts prompts, answers from a script.
struct Counting {
    inner: Scripted,
    asked: Arc<AtomicUsize>,
}

impl Approver for Counting {
    fn approve(&self, req: &ApprovalRequest, limit: Duration) -> ApprovalOutcome {
        self.asked.fetch_add(1, Ordering::SeqCst);
        self.inner.approve(req, limit)
    }
}

#[derive(Clone, Copy)]
enum MailMode {
    None,
    NotConnected,
    Empty,
}

struct FakeMailbox(MailMode);

impl MailSource for FakeMailbox {
    fn search(&self, _q: &MailQuery) -> Result<Vec<RawMessage>, MailError> {
        match self.0 {
            MailMode::NotConnected => Err(MailError::NotConnected),
            _ => Ok(Vec::new()),
        }
    }
}

struct FakeMail(MailMode);

impl MailProvider for FakeMail {
    fn current(&self) -> Option<Arc<dyn MailSource>> {
        match self.0 {
            MailMode::None => None,
            m => Some(Arc::new(FakeMailbox(m))),
        }
    }
}

// ---------- harness ----------

struct Tmp(PathBuf);
impl Tmp {
    fn new() -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        // Short: a Unix socket path is limited to 104 bytes on macOS.
        let p = std::env::temp_dir().join(format!(
            "ldd{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
}
impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct H {
    tmp: Tmp,
    broker: Arc<Broker>,
    script: Arc<Script>,
    asked: Arc<AtomicUsize>,
}

struct Opts {
    approve: ApprovalOutcome,
    after_fill: Result<PageState, ExecError>,
    mail: MailMode,
    accounts: &'static [(&'static str, &'static str)],
    grants: &'static [(&'static str, Tier)],
    lock_after: Option<Duration>,
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            approve: ApprovalOutcome::Approved,
            after_fill: Ok(PageState::LoggedIn),
            mail: MailMode::None,
            accounts: &[("example.com", "alice@example.com")],
            grants: &[("example.com", Tier::Auto)],
            lock_after: None,
        }
    }
}

fn vault_with(dir: &Path, accounts: &[(&str, &str)]) -> (Vault, logindesk_vault::Keys) {
    let path = dir.join("vault.sqlite");
    let (mut v, k) = Vault::create(&path, &SecretString::new(PW.into()), KdfParams::MIN).unwrap();
    for (site, user) in accounts {
        v.add(
            &k,
            NewRecord {
                kind: RecordKind::Login,
                site: (*site).into(),
                username: (*user).into(),
                secret: SecretString::new(MARKER.into()),
                created_by: "test".into(),
                notes: String::new(),
            },
        )
        .unwrap();
    }
    // An API key on the same site must never count as a login account.
    v.add(
        &k,
        NewRecord {
            kind: RecordKind::ApiKey,
            site: "example.com".into(),
            username: "api".into(),
            secret: SecretString::new(MARKER.into()),
            created_by: "test".into(),
            notes: String::new(),
        },
    )
    .unwrap();
    (v, k)
}

fn harness(o: Opts) -> H {
    let tmp = Tmp::new();
    let (vault, keys) = vault_with(&tmp.0, o.accounts);
    let mut cfg = Config::for_vault(&tmp.0.join("vault.sqlite"));
    cfg.otp_poll_every = Duration::from_millis(10);
    cfg.otp_wait_max = Duration::from_millis(60);
    cfg.lock_after = o.lock_after;
    let mut g = Grants::default();
    for (s, t) in o.grants {
        g.login.insert((*s).into(), *t);
    }
    g.save(&cfg.grants_path).unwrap();
    let script = Arc::new(Script {
        after_fill: o.after_fill,
        calls: Mutex::new(Calls::default()),
    });
    let asked = Arc::new(AtomicUsize::new(0));
    let deps = Deps {
        approver: Box::new(Counting {
            inner: Scripted(o.approve),
            asked: Arc::clone(&asked),
        }),
        launcher: Box::new(FakeLauncher(Arc::clone(&script))),
        mail: Box::new(FakeMail(o.mail)),
    };
    let broker = Arc::new(Broker::new(cfg, deps, vault, keys).unwrap());
    H {
        tmp,
        broker,
        script,
        asked,
    }
}

fn req(op: Op) -> Request {
    Request {
        token: String::new(),
        client_name: "test-agent".into(),
        op,
    }
}

fn login(h: &H, site: &str, account: Option<&str>) -> Reply {
    h.broker.handle(&req(Op::Login {
        site: site.into(),
        account: account.map(Into::into),
    }))
}

fn tag(r: &Reply) -> String {
    match &r.reason {
        Some(x) => format!("{}/{x}", r.status),
        None => r.status.clone(),
    }
}

// ---------- tests ----------

#[test]
fn auto_grant_logs_in_with_no_prompt() {
    let h = harness(Opts::default());
    let r = login(&h, "https://www.example.com/", None);
    assert_eq!(tag(&r), "logged_in");
    assert_eq!(h.asked.load(Ordering::SeqCst), 0, "auto must not prompt");
    let sid = r.session_id.clone().unwrap();
    assert_eq!(sid.len(), 32);
    assert!(r.account_id.is_some());
    let c = h.script.calls.lock().unwrap();
    assert_eq!(
        c.fills,
        vec![("example.com".into(), "alice@example.com".into())]
    );
    assert_eq!(c.navigations, vec!["https://example.com/login".to_string()]);
    assert_eq!(
        c.profile_dirs,
        vec![h.tmp.0.join("profiles").join("example.com")]
    );
    drop(c);
    assert_eq!(h.broker.session_count(), 1);
}

#[test]
fn ask_tier_prompts_and_maps_every_outcome() {
    for (outcome, want) in [
        (ApprovalOutcome::Approved, "logged_in"),
        (ApprovalOutcome::Denied, "denied"),
        (ApprovalOutcome::Unavailable, "denied"),
        (ApprovalOutcome::TimedOut, "failed/timeout"),
    ] {
        let h = harness(Opts {
            approve: outcome,
            grants: &[],
            ..Opts::default()
        });
        let r = login(&h, "example.com", None);
        assert_eq!(tag(&r), want, "{outcome:?}");
        assert_eq!(h.asked.load(Ordering::SeqCst), 1);
        if want != "logged_in" {
            let c = h.script.calls.lock().unwrap();
            assert_eq!(c.launches, 0, "no browser before a yes");
            assert!(c.fills.is_empty());
        }
    }
}

#[test]
fn deny_tier_refuses_without_prompt_or_browser() {
    let h = harness(Opts {
        grants: &[("example.com", Tier::Deny)],
        ..Opts::default()
    });
    assert_eq!(tag(&login(&h, "example.com", None)), "failed/grant_denied");
    assert_eq!(h.asked.load(Ordering::SeqCst), 0);
    assert_eq!(h.script.calls.lock().unwrap().launches, 0);
}

#[test]
fn grants_are_reread_every_request() {
    let h = harness(Opts::default());
    assert_eq!(tag(&login(&h, "example.com", None)), "logged_in");
    let mut g = Grants::default();
    g.login.insert("example.com".into(), Tier::Deny);
    g.save(&h.broker.config().grants_path).unwrap();
    assert_eq!(tag(&login(&h, "example.com", None)), "failed/grant_denied");
}

#[test]
fn no_account_and_ambiguous() {
    let h = harness(Opts {
        accounts: &[
            ("example.com", "alice@example.com"),
            ("https://login.example.com/signin", "bob@example.com"),
        ],
        grants: &[("example.com", Tier::Auto), ("other.org", Tier::Auto)],
        ..Opts::default()
    });
    assert_eq!(tag(&login(&h, "other.org", None)), "failed/no_account");
    assert_eq!(tag(&login(&h, "not a site", None)), "failed/no_account");
    assert_eq!(
        tag(&login(&h, "example.com", None)),
        "failed/account_ambiguous"
    );
    assert_eq!(
        tag(&login(&h, "example.com", Some("nobody@example.com"))),
        "failed/no_account"
    );
    let r = login(&h, "example.com", Some("bob@example.com"));
    assert_eq!(tag(&r), "logged_in");
    // The record's URL is where the login starts.
    assert_eq!(
        h.script.calls.lock().unwrap().navigations,
        vec!["https://login.example.com/signin".to_string()]
    );
    // Selecting by account id works too.
    let list = h.broker.handle(&req(Op::ListAccounts {
        site: Some("example.com".into()),
    }));
    let accts = list.data.unwrap()["accounts"].as_array().unwrap().clone();
    assert_eq!(accts.len(), 2, "api keys are not accounts");
    let id = accts[0]["account_id"].as_str().unwrap().to_string();
    assert_eq!(tag(&login(&h, "example.com", Some(&id))), "logged_in");
}

#[test]
fn page_states_map_to_statuses() {
    for (after, want, keeps) in [
        (
            Ok(PageState::Rejected),
            "failed/credentials_rejected",
            false,
        ),
        (
            Ok(PageState::LoginForm),
            "failed/credentials_rejected",
            false,
        ),
        (Ok(PageState::Captcha), "needs_user/captcha", true),
        (Ok(PageState::Unknown), "needs_user/unknown_page", true),
        (Err(ExecError::Fence), "failed/fence_blocked", false),
        (
            Err(ExecError::Unreachable),
            "failed/site_unreachable",
            false,
        ),
        (
            Err(ExecError::Mapping),
            "failed/field_mapping_failed",
            false,
        ),
        (Err(ExecError::Browser("x")), "failed/internal", false),
    ] {
        let h = harness(Opts {
            after_fill: after,
            ..Opts::default()
        });
        let r = login(&h, "example.com", None);
        assert_eq!(tag(&r), want);
        assert_eq!(h.broker.session_count(), usize::from(keeps), "{want}");
        assert_eq!(r.session_id.is_some(), keeps);
        if !keeps {
            assert_eq!(h.script.calls.lock().unwrap().closes, 1);
        }
    }
}

#[test]
fn otp_without_mailbox_and_timeouts() {
    let cases = [
        (MailMode::None, "email_not_connected"),
        (MailMode::NotConnected, "email_not_connected"),
        (MailMode::Empty, "failed/timeout"),
    ];
    for (mail, want) in cases {
        let h = harness(Opts {
            after_fill: Ok(PageState::NeedsOtp),
            mail,
            ..Opts::default()
        });
        let t = Instant::now();
        let r = login(&h, "example.com", None);
        assert_eq!(tag(&r), want);
        assert!(t.elapsed() < Duration::from_secs(5));
        if want == "email_not_connected" {
            assert!(r.message.unwrap().contains("logindesk connect"));
        }
    }
}

#[test]
fn second_login_replaces_the_sites_session() {
    let h = harness(Opts::default());
    let a = login(&h, "example.com", None).session_id.unwrap();
    let b = login(&h, "example.com", None).session_id.unwrap();
    assert_ne!(a, b);
    assert_eq!(h.broker.session_count(), 1);
    assert_eq!(h.script.calls.lock().unwrap().closes, 1);
    let r = h.broker.handle(&req(Op::Snapshot { session_id: a }));
    assert_eq!(tag(&r), "failed/session_not_found");
}

#[test]
fn session_ops_and_navigate_fence() {
    let h = harness(Opts::default());
    let sid = login(&h, "example.com", None).session_id.unwrap();

    let snap = h.broker.handle(&req(Op::Snapshot {
        session_id: sid.clone(),
    }));
    assert_eq!(tag(&snap), "ok");
    let d = snap.data.unwrap();
    assert_eq!(d["lines"][1], "[12] textbox \"Password\" (filled)");

    let before = h.script.calls.lock().unwrap().navigations.len();
    for bad in [
        "https://evil.com/",
        "https://example.com.evil.com/",
        "file:///etc/passwd",
        "javascript:alert(1)",
        "not a url",
    ] {
        let r = h.broker.handle(&req(Op::Navigate {
            session_id: sid.clone(),
            url: bad.into(),
        }));
        assert_eq!(tag(&r), "failed/fence_blocked", "{bad}");
    }
    assert_eq!(
        h.script.calls.lock().unwrap().navigations.len(),
        before,
        "a fenced URL never reaches the browser"
    );
    let r = h.broker.handle(&req(Op::Navigate {
        session_id: sid.clone(),
        url: "https://app.example.com/settings".into(),
    }));
    assert_eq!(tag(&r), "ok");
    assert_eq!(r.data.unwrap()["url"], "https://app.example.com/settings");

    let r = h.broker.handle(&req(Op::Click {
        session_id: sid.clone(),
        node_ref: 11,
    }));
    assert_eq!(tag(&r), "ok");
    let r = h.broker.handle(&req(Op::Click {
        session_id: sid.clone(),
        node_ref: 99,
    }));
    assert_eq!(tag(&r), "failed/field_mapping_failed");

    for bad in ["nope", &"0".repeat(32)] {
        let r = h.broker.handle(&req(Op::Snapshot {
            session_id: bad.into(),
        }));
        assert_eq!(tag(&r), "failed/session_not_found");
    }
    let r = h.broker.handle(&req(Op::CloseSession {
        session_id: sid.clone(),
    }));
    assert_eq!(tag(&r), "ok");
    assert_eq!(h.broker.session_count(), 0);
    let r = h.broker.handle(&req(Op::CloseSession { session_id: sid }));
    assert_eq!(tag(&r), "failed/session_not_found");
}

#[test]
fn lock_wipes_keys() {
    let h = harness(Opts::default());
    assert_eq!(tag(&h.broker.handle(&req(Op::Lock))), "ok");
    assert!(!h.broker.is_unlocked());
    assert_eq!(tag(&login(&h, "example.com", None)), "vault_locked");
    let r = h.broker.handle(&req(Op::ListAccounts { site: None }));
    assert_eq!(tag(&r), "vault_locked");
}

#[test]
fn idle_sessions_close_and_lock_after_applies() {
    let h = harness(Opts {
        lock_after: Some(Duration::from_secs(60)),
        ..Opts::default()
    });
    login(&h, "example.com", None);
    h.broker.tick(Instant::now());
    assert_eq!(h.broker.session_count(), 1);
    assert!(h.broker.is_unlocked());
    let later = Instant::now() + h.broker.config().idle_close + Duration::from_secs(1);
    h.broker.tick(later);
    assert_eq!(h.broker.session_count(), 0);
    assert_eq!(h.script.calls.lock().unwrap().closes, 1);
    assert!(!h.broker.is_unlocked(), "lock_after wiped the keys");
}

#[test]
fn bad_token_is_not_paired() {
    let h = harness(Opts::default());
    let good = "a".repeat(32);
    let body = |t: &str| format!(r#"{{"token":"{t}","client_name":"x","op":"ping"}}"#);
    let ok = server::answer(body(&good).as_bytes(), &h.broker, &good);
    assert_eq!(tag(&ok), "ok");
    for t in ["", "b", &"b".repeat(32), &good.to_uppercase()] {
        let r = server::answer(body(t).as_bytes(), &h.broker, &good);
        assert_eq!(tag(&r), "failed/not_paired", "token {t:?}");
    }
    let r = server::answer(
        br#"{"client_name":"x","op":"login","site":"example.com"}"#,
        &h.broker,
        &good,
    );
    assert_eq!(tag(&r), "failed/not_paired");
    assert_eq!(h.script.calls.lock().unwrap().launches, 0);
    let r = server::answer(b"not json", &h.broker, &good);
    assert_eq!(tag(&r), "failed/internal");
}

#[test]
fn audit_chain_records_requests_and_verifies() {
    let h = harness(Opts::default());
    login(&h, "example.com", None);
    login(&h, "other.org", None);
    h.broker.handle(&req(Op::Ping));
    let p = h.tmp.0.join("audit.jsonl");
    let (n, _) = audit::verify(&p).unwrap();
    assert_eq!(n, 3);
    let text = std::fs::read_to_string(&p).unwrap();
    assert!(text.contains(r#""op":"login","site":"example.com","status":"logged_in""#));
    assert!(text.contains(r#""reason":"no_account""#));
    let edited = text.replacen("logged_in", "denied", 1);
    std::fs::write(&p, edited).unwrap();
    assert_eq!(audit::verify(&p), Err(audit::VerifyError::Broken(1)));
}

/// Every 8-char window of the marker, so a partial leak is caught too.
fn assert_no_marker(what: &str, bytes: &[u8]) {
    let hay = String::from_utf8_lossy(bytes);
    let m = MARKER.as_bytes();
    for w in m.windows(8) {
        let w = std::str::from_utf8(w).unwrap();
        assert!(!hay.contains(w), "{what} leaked {w:?}: {hay}");
    }
}

#[test]
fn no_frame_or_audit_line_contains_the_planted_password() {
    let tmp_h = harness(Opts {
        accounts: &[
            ("example.com", "alice@example.com"),
            ("example.org", "a@example.org"),
            ("example.org", "b@example.org"),
        ],
        grants: &[("example.com", Tier::Auto), ("example.org", Tier::Auto)],
        ..Opts::default()
    });
    let h = &tmp_h;
    let token = "c".repeat(32);
    let mut frames: Vec<Vec<u8>> = Vec::new();
    let mut send = |v: serde_json::Value| {
        let mut v = v;
        v["client_name"] = "canary".into();
        if v.get("token").is_none() {
            v["token"] = token.clone().into();
        }
        let r = server::answer(&serde_json::to_vec(&v).unwrap(), &h.broker, &token);
        let b = r.to_bytes();
        frames.push(b);
        r
    };
    use serde_json::json;
    let r = send(json!({"op":"login","site":"example.com"}));
    let sid = r.session_id.unwrap();
    send(json!({"op":"login","site":"example.org"}));
    send(json!({"op":"login","site":"example.org","account":"b@example.org"}));
    send(json!({"op":"login","site":"nowhere.net"}));
    send(json!({"op":"list_accounts"}));
    send(json!({"op":"list_accounts","site":"example.com"}));
    send(json!({"op":"snapshot","session_id":sid}));
    send(json!({"op":"navigate","session_id":sid,"url":"https://example.com/a"}));
    send(json!({"op":"navigate","session_id":sid,"url":"https://evil.com/"}));
    send(json!({"op":"click","session_id":sid,"ref":11}));
    send(json!({"op":"close_session","session_id":sid}));
    send(json!({"op":"ping"}));
    send(json!({"op":"bogus"}));
    send(json!({"op":"ping","token":"wrong"}));
    send(json!({"op":"lock"}));
    send(json!({"op":"login","site":"example.com"}));
    assert_eq!(frames.len(), 16);
    for f in &frames {
        assert_no_marker("reply frame", f);
    }
    let audit = std::fs::read(h.tmp.0.join("audit.jsonl")).unwrap();
    assert_no_marker("audit log", &audit);
    assert_eq!(audit::verify(&h.tmp.0.join("audit.jsonl")).unwrap().0, 16);
    // The grants and mail files never hold one either.
    assert_no_marker(
        "grants",
        &std::fs::read(h.tmp.0.join("grants.json")).unwrap(),
    );
}

// ---------- the real socket ----------

fn call(sock: &Path, body: &[u8]) -> Reply {
    let mut s = UnixStream::connect(sock).unwrap();
    write_frame(&mut s, body).unwrap();
    serde_json::from_slice(&read_frame(&mut s).unwrap().unwrap()).unwrap()
}

#[test]
fn socket_permissions_token_and_frame_limit() {
    let h = harness(Opts::default());
    let dir = h.tmp.0.clone();
    let server = Server::bind(&dir).unwrap();
    let sock = server.socket().to_path_buf();
    let b = Arc::clone(&h.broker);
    std::thread::spawn(move || server.serve(b));

    let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&dir), 0o700);
    assert_eq!(mode(&sock), 0o600);
    let tok_path = server::token_path(&dir);
    assert_eq!(mode(&tok_path), 0o600);
    let token = std::fs::read_to_string(&tok_path).unwrap();
    assert_eq!(token.len(), 32);

    // A second daemon on the same dir refuses to start.
    assert!(Server::bind(&dir).is_err());

    let ping = |t: &str| format!(r#"{{"token":"{t}","client_name":"t","op":"ping"}}"#);
    assert_eq!(tag(&call(&sock, ping(&token).as_bytes())), "ok");
    assert_eq!(
        tag(&call(&sock, ping("nope").as_bytes())),
        "failed/not_paired"
    );

    // Several requests on one connection.
    let mut s = UnixStream::connect(&sock).unwrap();
    for _ in 0..3 {
        write_frame(&mut s, ping(&token).as_bytes()).unwrap();
        let r: Reply = serde_json::from_slice(&read_frame(&mut s).unwrap().unwrap()).unwrap();
        assert_eq!(r.status, "ok");
    }
    drop(s);

    // Oversize length prefix: one failed/internal reply, then the connection closes.
    let mut s = UnixStream::connect(&sock).unwrap();
    s.write_all(&((MAX_FRAME as u32) + 1).to_be_bytes())
        .unwrap();
    let r: Reply = serde_json::from_slice(&read_frame(&mut s).unwrap().unwrap()).unwrap();
    assert_eq!(tag(&r), "failed/internal");
    assert_eq!(r.message.as_deref(), Some("frame too large"));
    let mut rest = Vec::new();
    s.read_to_end(&mut rest).unwrap();
    assert!(rest.is_empty());

    // Exactly MAX_FRAME is accepted (and refused only as bad JSON).
    let mut s = UnixStream::connect(&sock).unwrap();
    write_frame(&mut s, &vec![b' '; MAX_FRAME]).unwrap();
    let r: Reply = serde_json::from_slice(&read_frame(&mut s).unwrap().unwrap()).unwrap();
    assert_eq!(tag(&r), "failed/internal");
    assert_eq!(r.message.as_deref(), Some("request is not JSON"));
}
