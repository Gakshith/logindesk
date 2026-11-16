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
use logindesk_executor::{
    BrowserConfig, ExecError, FormKind, MapFail, PageState, SecretField, Session, Snapshot,
};
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
    assert_eq!(r, Err(ExecError::Mapping(MapFail::NoForm)));
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
            .any(|l| l.contains("textbox \"Email\" (email, filled)")),
        "{all}"
    );
    assert!(
        snap.lines
            .iter()
            .any(|l| l.contains("\"Password\" (password, filled)")),
        "{all}"
    );
    assert!(
        snap.lines
            .iter()
            .any(|l| l.contains("textbox \"Note\" (text, empty)")),
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

// ---------- real-site shapes (fix round: every real page was field_mapping_failed) ----------

fn signup_token(site: &str) -> ApprovalToken {
    ApprovalToken::from_standing_grant(&ApprovalRequest {
        request_id: RequestId::random(),
        client_name: "executor-test".into(),
        action: Action::Signup,
        site: site.into(),
        shares: vec![],
    })
}

fn login_at(e: &mut Env, path: &str, user: &str, pw: &str) -> Result<PageState, ExecError> {
    let url = format!("{}{path}", e.base());
    e.s.navigate(&url).expect("navigate");
    e.s.fill_login(SITE, user, &SecretString::new(pw.to_string()), token(SITE))
}

/// The form is built by JS 2 s after `load` (what broke on real SPA pages).
#[test]
fn form_rendered_after_load_is_waited_for() {
    let Some(mut e) = env() else { return };
    let (user, pw) = (e.fx.user_email.clone(), e.fx.user_password.clone());
    assert_eq!(
        login_at(&mut e, "/login-late", &user, &pw),
        Ok(PageState::LoggedIn)
    );
}

/// No form until "Sign in" is clicked; the off-site "Sign in with Google" is skipped.
#[test]
fn sign_in_button_opens_the_form() {
    let Some(mut e) = env() else { return };
    let (user, pw) = (e.fx.user_email.clone(), e.fx.user_password.clone());
    assert_eq!(
        login_at(&mut e, "/login-js", &user, &pw),
        Ok(PageState::LoggedIn)
    );
    assert!(e.s.current_url().expect("url").ends_with("/account"));
}

#[test]
fn two_step_login() {
    let Some(mut e) = env() else { return };
    let (user, pw) = (e.fx.user_email.clone(), e.fx.user_password.clone());
    assert_eq!(
        login_at(&mut e, "/login-two-step", &user, &pw),
        Ok(PageState::LoggedIn)
    );
}

#[test]
fn two_step_unknown_account_is_rejected() {
    let Some(mut e) = env() else { return };
    let pw = e.fx.user_password.clone();
    assert_eq!(
        login_at(&mut e, "/login-two-step", "nobody@example.localhost", &pw),
        Ok(PageState::Rejected)
    );
}

/// The password page of a two-step login posts to another origin: fenced, nothing sent.
#[test]
fn two_step_password_page_is_fenced() {
    let Some(mut e) = env() else { return };
    let (user, pw) = (e.fx.user_email.clone(), e.fx.user_password.clone());
    assert_eq!(
        login_at(&mut e, "/login-two-step?evil=1", &user, &pw),
        Err(ExecError::Fence)
    );
    assert!(e.run.site.collected().is_empty(), "the password was posted");
}

/// Late-rendered signup with new + confirm password and an off-screen honeypot:
/// rehearse maps it, fills the two visible passwords, leaves the honeypot empty.
#[test]
fn signup_rehearsal_skips_the_honeypot() {
    let Some(mut e) = env() else { return };
    let url = format!("{}/signup-late", e.base());
    e.s.navigate(&url).expect("navigate");
    let shape = e.s.rehearse(SITE, FormKind::Signup).expect("rehearse");
    assert_eq!(shape.passwords, 2);
    assert!(!shape.two_step);
    let snap = e.s.snapshot().expect("snapshot");
    let all = snap.lines.join("\n");
    eprintln!("signup rehearsal snapshot:\n{all}");
    assert!(all.contains("textbox \"Email\" (email, filled)"), "{all}");
    assert!(all.contains("\"Password\" (password, filled)"), "{all}");
    assert!(
        all.contains("\"Confirm password\" (password, filled)"),
        "{all}"
    );
    assert!(
        all.contains("\"Leave this empty\" (password, empty)"),
        "{all}"
    );
    assert!(!all.contains("rehearsal"), "a value leaked: {all}");
    assert!(
        e.s.current_url().expect("url").ends_with("/signup-late"),
        "submitted"
    );
}

#[test]
fn late_signup_form_signs_up() {
    let Some(mut e) = env() else { return };
    let url = format!("{}/signup-late", e.base());
    e.s.navigate(&url).expect("navigate");
    let r = e.s.fill_signup(
        SITE,
        "new-user@example.localhost",
        "New User",
        &SecretString::new("Fresh-password-123".into()),
        signup_token(SITE),
    );
    assert!(
        matches!(r, Ok(PageState::NeedsOtp | PageState::VerifyEmail)),
        "{r:?}"
    );
}

#[test]
fn page_without_a_form_says_why() {
    let Some(mut e) = env() else { return };
    // A page with no form and no "Sign in" button at all.
    let url = format!("{}/_testbed/outbox", e.base());
    e.s.navigate(&url).expect("navigate");
    let (user, pw) = (e.fx.user_email.clone(), e.fx.user_password.clone());
    let r =
        e.s.fill_login(SITE, &user, &SecretString::new(pw), token(SITE));
    assert_eq!(r, Err(ExecError::Mapping(MapFail::NoForm)));
}

// ---------- agent-driven forms (contract §12): the agent types, the broker fills secrets ----------

/// The ref of the first snapshot line containing `needle`.
fn ref_of(snap: &Snapshot, needle: &str) -> u64 {
    let l = snap
        .lines
        .iter()
        .find(|l| l.contains(needle))
        .unwrap_or_else(|| panic!("no line with {needle:?} in:\n{}", snap.lines.join("\n")));
    l[1..l.find(']').expect("ref")].parse().expect("ref number")
}

fn secret(s: &str) -> SecretString {
    SecretString::new(s.to_string())
}

#[test]
fn agent_drives_an_unpredictable_signup() {
    let Some(mut e) = env() else { return };
    let url = format!("{}/signup-wild", e.base());
    e.s.navigate(&url).expect("navigate");
    let snap = e.s.snapshot().expect("snapshot");
    let all = snap.lines.join("\n");
    eprintln!("signup-wild snapshot:\n{all}");
    // Kinds tell the agent which ref takes which secret.
    assert!(
        all.contains("textbox \"First name\" (text, empty)"),
        "{all}"
    );
    assert!(all.contains("textbox \"Email\" (email, empty)"), "{all}");
    assert!(
        all.contains("textbox \"Password\" (password, empty)"),
        "{all}"
    );
    assert!(
        all.contains("textbox \"Confirm password\" (password, empty)"),
        "{all}"
    );
    assert!(
        all.contains("combobox \"Country\" (select: \"Choose…\"; options: \"Choose…\" | \"India\" | \"United States\" | \"Germany\")"),
        "{all}"
    );
    assert!(
        all.contains("checkbox \"I agree to the terms\" (unchecked)"),
        "{all}"
    );

    let first = ref_of(&snap, "textbox \"First name\"");
    let phone = ref_of(&snap, "textbox \"Phone\"");
    let country = ref_of(&snap, "combobox \"Country\"");
    let email = ref_of(&snap, "textbox \"Email\"");
    let pw = ref_of(&snap, "textbox \"Password\"");
    let pw2 = ref_of(&snap, "textbox \"Confirm password\"");
    let terms = ref_of(&snap, "checkbox \"I agree to the terms\"");

    // The agent types the non-secret fields; a select takes a label or a value.
    e.s.type_text(SITE, first, "Ada").expect("first name");
    e.s.type_text(SITE, phone, "5550100").expect("phone");
    e.s.type_text(SITE, country, "united states")
        .expect("select by label");
    e.s.type_text(SITE, country, "de").expect("select by value");
    assert_eq!(
        e.s.type_text(SITE, country, "Atlantis"),
        Err(ExecError::Refused)
    );

    // The agent can never type into a secret field, even text it made up.
    assert_eq!(e.s.type_text(SITE, pw, "guess"), Err(ExecError::Refused));
    assert_eq!(e.s.type_text(SITE, terms, "x"), Err(ExecError::Refused));

    // The broker's secrets go only into fields of the right kind.
    let (addr, password) = ("ada+example@example.localhost", "Wild-signup-pass-123");
    assert_eq!(
        e.s.fill_at(SITE, first, SecretField::Password, &secret(password)),
        Err(ExecError::Refused)
    );
    assert_eq!(
        e.s.fill_at(SITE, pw, SecretField::Email, &secret(addr)),
        Err(ExecError::Refused)
    );
    assert_eq!(
        e.s.fill_at(SITE, pw, SecretField::Code, &secret("123456")),
        Err(ExecError::Refused)
    );
    e.s.fill_at(SITE, email, SecretField::Email, &secret(addr))
        .expect("email");
    e.s.fill_at(SITE, pw, SecretField::Password, &secret(password))
        .expect("password");
    e.s.fill_at(SITE, pw2, SecretField::Password, &secret(password))
        .expect("confirm");
    e.s.click(terms).expect("tick terms");

    // Filled, but no value is visible to the agent.
    let snap = e.s.snapshot().expect("snapshot");
    let all = snap.lines.join("\n");
    eprintln!("filled snapshot:\n{all}");
    for v in ["Ada", "5550100", addr, password] {
        assert!(!all.contains(v), "{v:?} leaked:\n{all}");
    }
    assert!(
        all.contains("textbox \"First name\" (text, filled)"),
        "{all}"
    );
    assert!(
        all.contains("textbox \"Password\" (password, filled)"),
        "{all}"
    );
    assert!(
        all.contains("combobox \"Country\" (select: \"Germany\""),
        "{all}"
    );
    assert!(all.contains("(checked)"), "{all}");

    // Submit; the site saw exactly what was typed and filled.
    e.s.press_enter_at(SITE, pw2).expect("submit");
    let snap = e.s.snapshot().expect("snapshot");
    let all = snap.lines.join("\n");
    assert!(
        all.contains(&format!(
            "first=Ada; phone=5550100; country=de; email={addr}; terms=on; password_len={}; passwords_match=yes",
            password.len()
        )),
        "{all}"
    );

    // The code page: the agent cannot type into it, the broker can fill it.
    assert!(
        all.contains("textbox \"Verification code\" (code, empty)"),
        "{all}"
    );
    let code = ref_of(&snap, "textbox \"Verification code\"");
    assert_eq!(e.s.type_text(SITE, code, "123456"), Err(ExecError::Refused));
    assert_eq!(
        e.s.fill_at(SITE, code, SecretField::Password, &secret("123456")),
        Err(ExecError::Refused)
    );
    e.s.fill_at(SITE, code, SecretField::Code, &secret("123456"))
        .expect("code");
    e.s.press_enter_at(SITE, code).expect("submit code");
    let all = e.s.snapshot().expect("snapshot").lines.join("\n");
    assert!(all.contains("Code received: 6 digits"), "{all}");
    assert!(e.run.site.collected().is_empty());
}

/// The form posts off-site: every agent call on its fields is fenced; nothing is sent.
#[test]
fn agent_calls_are_fenced_by_the_form_action() {
    let Some(mut e) = env() else { return };
    let url = format!("{}/signup-wild?evil=1", e.base());
    e.s.navigate(&url).expect("navigate");
    let snap = e.s.snapshot().expect("snapshot");
    let first = ref_of(&snap, "textbox \"First name\"");
    let pw = ref_of(&snap, "textbox \"Password\"");
    assert_eq!(e.s.type_text(SITE, first, "Ada"), Err(ExecError::Fence));
    assert_eq!(
        e.s.fill_at(
            SITE,
            pw,
            SecretField::Password,
            &secret("Wild-signup-pass-123")
        ),
        Err(ExecError::Fence)
    );
    assert_eq!(e.s.press_enter_at(SITE, pw), Err(ExecError::Fence));
    // And a session for another site gets nothing here at all.
    assert_eq!(
        e.s.type_text("other.localhost", first, "Ada"),
        Err(ExecError::Fence)
    );
    assert!(e.run.site.collected().is_empty(), "something was posted");
    let all = e.s.snapshot().expect("snapshot").lines.join("\n");
    assert!(
        all.contains("(password, empty)") && !all.contains("(password, filled)"),
        "{all}"
    );
}
