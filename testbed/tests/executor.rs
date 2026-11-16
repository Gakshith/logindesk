//! The sealed browser against the fake site: real headless Chrome over the CDP pipe.
//! Every case skips (with a note on stderr) when no Chrome/Chromium is installed.

use std::io::{Read, Write};
use std::net::TcpStream;

use axum::Router;
use axum::response::Html;
use axum::routing::get;
use logindesk_approver::{Action, ApprovalRequest, ApprovalToken};
use logindesk_core::SecretString;
use logindesk_core::ids::RequestId;
use logindesk_executor::{BrowserConfig, ExecError, PageState, Session};
use testbed::fixtures::Fixtures;
use testbed::site::{self, MailSink, Running};

const SITE: &str = "example.localhost";

/// Field order matters for Drop: the browser closes before the profile dir goes.
struct Env {
    s: Session,
    run: Running,
    fx: Fixtures,
    rt: tokio::runtime::Runtime,
    _profile: tempfile::TempDir,
}

impl Env {
    fn base(&self) -> String {
        self.run.site.base()
    }
}

fn env() -> Option<Env> {
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    let fx = Fixtures::random();
    let run = rt
        .block_on(site::start(fx.clone(), MailSink::LogOnly, 0))
        .expect("site");
    let profile = tempfile::tempdir().expect("profile dir");
    let cfg = BrowserConfig {
        chrome: None,
        profile_dir: profile.path().to_path_buf(),
        headless: true,
    };
    match Session::launch(&cfg) {
        Ok(s) => Some(Env {
            s,
            run,
            fx,
            rt,
            _profile: profile,
        }),
        Err(ExecError::NoChrome) => {
            eprintln!("SKIP: no Chrome/Chromium found (set LOGINDESK_CHROME)");
            None
        }
        Err(e) => panic!("launch: {e}"),
    }
}

fn token(site: &str) -> ApprovalToken {
    ApprovalToken::from_standing_grant(&ApprovalRequest {
        request_id: RequestId::random(),
        client_name: "executor-test".into(),
        action: Action::Login,
        site: site.into(),
        shares: vec![],
    })
}

fn login(e: &mut Env, user: &str, pw: &str) -> Result<PageState, ExecError> {
    let url = format!("{}/login", e.base());
    e.s.navigate(&url).expect("navigate");
    e.s.fill_login(SITE, user, &SecretString::new(pw.to_string()), token(SITE))
}

/// `GET /_testbed/outbox` over plain HTTP; the 6-digit code from the newest mail.
fn outbox_code(e: &Env) -> String {
    let addr = e.run.main_addr;
    let mut c = TcpStream::connect(addr).expect("connect");
    write!(
        c,
        "GET /_testbed/outbox HTTP/1.1\r\nHost: {SITE}:{}\r\nConnection: close\r\n\r\n",
        addr.port()
    )
    .expect("write");
    let mut raw = String::new();
    c.read_to_string(&mut raw).expect("read");
    let body = raw.split_once("\r\n\r\n").expect("http body").1;
    let mails: serde_json::Value = serde_json::from_str(body).expect("outbox json");
    let text = mails
        .as_array()
        .and_then(|a| a.last())
        .and_then(|m| m["body"].as_str())
        .expect("a mail")
        .to_string();
    text.split(|c: char| !c.is_ascii_digit())
        .find(|w| w.len() == 6)
        .expect("6-digit code")
        .to_string()
}

#[test]
fn password_login_logs_in_and_snapshot_has_no_password() {
    let Some(mut e) = env() else { return };
    let (user, pw) = (e.fx.user_email.clone(), e.fx.user_password.clone());
    assert_eq!(login(&mut e, &user, &pw), Ok(PageState::LoggedIn));
    assert!(e.s.current_url().expect("url").ends_with("/account"));
    let snap = e.s.snapshot().expect("snapshot");
    let all = snap.lines.join("\n");
    eprintln!("snapshot after login ({}):\n{all}", snap.title);
    assert_eq!(snap.title, "Your account");
    assert!(all.contains("Signed in as"), "{all}");
    assert!(!all.contains(&pw), "password leaked into snapshot");
    assert!(e.run.site.collected().is_empty());
}

#[test]
fn wrong_password_is_rejected() {
    let Some(mut e) = env() else { return };
    let user = e.fx.user_email.clone();
    assert_eq!(
        login(&mut e, &user, "not-the-password"),
        Ok(PageState::Rejected)
    );
}

#[test]
fn emailed_code_completes_login() {
    let Some(mut e) = env() else { return };
    let (user, pw) = (e.fx.otp_user_email.clone(), e.fx.user_password.clone());
    assert_eq!(login(&mut e, &user, &pw), Ok(PageState::NeedsOtp));
    assert_eq!(e.s.page_state(), Ok(PageState::NeedsOtp));
    let code = outbox_code(&e);
    assert_eq!(
        e.s.fill_otp(SITE, &SecretString::new(code)),
        Ok(PageState::LoggedIn)
    );
}

#[test]
fn wrong_code_is_rejected() {
    let Some(mut e) = env() else { return };
    let (user, pw) = (e.fx.otp_user_email.clone(), e.fx.user_password.clone());
    assert_eq!(login(&mut e, &user, &pw), Ok(PageState::NeedsOtp));
    let real = outbox_code(&e);
    let wrong = if real == "000000" { "111111" } else { "000000" };
    assert_eq!(
        e.s.fill_otp(SITE, &SecretString::new(wrong.into())),
        Ok(PageState::Rejected)
    );
}

#[test]
fn lookalike_host_is_fenced() {
    let Some(mut e) = env() else { return };
    let port = e.run.main_addr.port();
    e.s.navigate(&format!("http://{}:{port}/login", site::LOOKALIKE_HOST))
        .expect("navigate");
    assert_eq!(e.s.page_state(), Ok(PageState::LoginForm));
    let (user, pw) = (e.fx.user_email.clone(), e.fx.user_password.clone());
    let r =
        e.s.fill_login(SITE, &user, &SecretString::new(pw.clone()), token(SITE));
    assert_eq!(r, Err(ExecError::Fence));
    // A code is fenced the same way.
    assert_eq!(
        e.s.fill_otp(SITE, &SecretString::new("123456".into())),
        Err(ExecError::Fence)
    );
    assert!(e.run.site.collected().is_empty(), "something was posted");
}

#[test]
fn cross_origin_form_is_fenced() {
    let Some(mut e) = env() else { return };
    let url = format!("{}/cross-origin", e.base());
    e.s.navigate(&url).expect("navigate");
    let (user, pw) = (e.fx.user_email.clone(), e.fx.user_password.clone());
    let r =
        e.s.fill_login(SITE, &user, &SecretString::new(pw), token(SITE));
    assert_eq!(r, Err(ExecError::Fence));
    assert!(e.run.site.collected().is_empty(), "something was posted");
}

#[test]
fn token_for_another_site_is_refused() {
    let Some(mut e) = env() else { return };
    let url = format!("{}/login", e.base());
    e.s.navigate(&url).expect("navigate");
    let (user, pw) = (e.fx.user_email.clone(), e.fx.user_password.clone());
    let r = e.s.fill_login(
        SITE,
        &user,
        &SecretString::new(pw),
        token("other.localhost"),
    );
    assert_eq!(r, Err(ExecError::Token));
    assert_eq!(e.s.page_state(), Ok(PageState::LoginForm));
}

#[test]
fn iframe_only_login_is_a_mapping_failure() {
    let Some(mut e) = env() else { return };
    let url = format!("{}/iframe-login", e.base());
    e.s.navigate(&url).expect("navigate");
    let (user, pw) = (e.fx.user_email.clone(), e.fx.user_password.clone());
    let r =
        e.s.fill_login(SITE, &user, &SecretString::new(pw), token(SITE));
    assert_eq!(r, Err(ExecError::Mapping));
}

#[test]
fn unreachable_site() {
    let Some(mut e) = env() else { return };
    // Bind then drop a listener: nothing is serving on that port now.
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .expect("free port")
        .port();
    assert_eq!(
        e.s.navigate(&format!("http://{SITE}:{port}/")),
        Err(ExecError::Unreachable)
    );
}

/// A same-site page whose form never submits: the fields stay filled for the snapshot.
#[test]
fn filled_form_snapshot_shows_filled_not_values() {
    let Some(mut e) = env() else { return };
    let app = Router::new().route(
        "/",
        get(|| async {
            Html(
                r#"<!doctype html><title>Stay</title><h1>Stay</h1>
<form action="/nowhere" onsubmit="return false">
<label for="u">Email</label> <input id="u" type="email" autocomplete="username">
<label for="p">Password</label> <input id="p" type="password">
<label for="q">Note</label> <input id="q" type="text">
<button>Sign in</button></form>"#,
            )
        }),
    );
    let port = e.rt.block_on(async {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = l.local_addr().expect("addr").port();
        tokio::spawn(async move {
            let _ = axum::serve(l, app).await;
        });
        port
    });
    e.s.navigate(&format!("http://{SITE}:{port}/"))
        .expect("navigate");
    let (user, pw) = (e.fx.user_email.clone(), e.fx.user_password.clone());
    let r =
        e.s.fill_login(SITE, &user, &SecretString::new(pw.clone()), token(SITE));
    assert_eq!(r, Ok(PageState::LoginForm));
    let snap = e.s.snapshot().expect("snapshot");
    let all = snap.lines.join("\n");
    eprintln!("snapshot of filled form:\n{all}");
    assert!(!all.contains(&pw), "password value in snapshot");
    assert!(!all.contains(&user), "username value in snapshot");
    assert!(
        snap.lines
            .iter()
            .any(|l| l.contains("textbox \"Email\" (filled)")),
        "{all}"
    );
    assert!(
        snap.lines
            .iter()
            .any(|l| l.contains("\"Password\" (filled)")),
        "{all}"
    );
    assert!(
        snap.lines
            .iter()
            .any(|l| l.contains("textbox \"Note\" (empty)")),
        "{all}"
    );
}

#[test]
fn click_follows_a_link() {
    let Some(mut e) = env() else { return };
    let url = format!("{}/", e.base());
    e.s.navigate(&url).expect("navigate");
    let snap = e.s.snapshot().expect("snapshot");
    let line = snap
        .lines
        .iter()
        .find(|l| l.contains("link \"Login\""))
        .expect("Login link");
    let r: u64 = line[1..line.find(']').expect("ref")]
        .parse()
        .expect("ref number");
    e.s.click(r).expect("click");
    assert!(e.s.current_url().expect("url").ends_with("/login"));
    assert_eq!(e.s.page_state(), Ok(PageState::LoginForm));
}
