//! The mail lane end to end: the fake site emails a code, a `MailSource` finds it and
//! `extract_otp` returns exactly that code. Outbox always; Mailpit when Docker is up (not in CI).

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use logindesk_mail::{
    MailQuery, MailSource, MailpitSource, OtpOutcome, OutboxSource, UsedCodes, extract_otp,
};
use logindesk_policy::registrable_domain;
use testbed::fixtures::{Fixtures, SITE_DOMAIN};
use testbed::mailpit::{Mailpit, docker_available};
use testbed::site::{self, MailSink, Running};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// One HTTP/1.0 request over a plain socket; returns the whole response.
async fn http(running: &Running, method: &str, path: &str, form: &str) -> String {
    let mut c = tokio::net::TcpStream::connect(running.main_addr)
        .await
        .expect("connect");
    let req = format!(
        "{method} {path} HTTP/1.0\r\nHost: {SITE_DOMAIN}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{form}",
        form.len()
    );
    c.write_all(req.as_bytes()).await.expect("write");
    let mut resp = String::new();
    c.read_to_string(&mut resp).await.expect("read");
    resp
}

/// Log in as the OTP user so the site emails a code. Returns the code, read from the outbox JSON.
async fn trigger_otp(running: &Running, fx: &Fixtures) -> String {
    let form = format!(
        "email={}&password={}",
        fx.otp_user_email.replace('@', "%40"),
        fx.user_password
    );
    let resp = http(running, "POST", "/login", &form).await;
    assert!(
        resp.contains(" 303 "),
        "login did not redirect to the OTP page"
    );
    let outbox = http(running, "GET", "/_testbed/outbox", "").await;
    let json = outbox.split_once("\r\n\r\n").expect("body").1;
    let mails: serde_json::Value = serde_json::from_str(json).expect("outbox json");
    let body = mails
        .as_array()
        .and_then(|a| a.last())
        .and_then(|m| m.get("body"))
        .and_then(|b| b.as_str())
        .expect("outbox entry");
    body.split(|c: char| !c.is_ascii_digit())
        .find(|w| w.len() == 6)
        .expect("six-digit code in the outbox")
        .to_string()
}

fn query() -> MailQuery {
    MailQuery {
        site: registrable_domain(SITE_DOMAIN).expect("site"),
        since: SystemTime::now() - Duration::from_secs(5),
    }
}

/// Poll `src` like the daemon would, until a code appears (5 s max).
async fn poll_code(src: Arc<dyn MailSource>, q: MailQuery, used: &mut UsedCodes) -> OtpOutcome {
    for _ in 0..50 {
        let (s, qq) = (src.clone(), q.clone());
        let msgs = tokio::task::spawn_blocking(move || s.search(&qq))
            .await
            .expect("join")
            .expect("search");
        let o = extract_otp(&msgs, &q, used);
        if !matches!(o, OtpOutcome::NotFound) {
            return o;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    OtpOutcome::NotFound
}

fn assert_code(o: &OtpOutcome, want: &str) {
    match o {
        OtpOutcome::Code(c) => assert!(c.expose() == want, "extracted code differs from sent"),
        other => panic!("expected a code, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn outbox_source_returns_the_emailed_code() {
    let fx = Fixtures::random();
    let running = site::start(fx.clone(), MailSink::LogOnly, 0)
        .await
        .expect("site");
    let q = query();
    let sent = trigger_otp(&running, &fx).await;

    let src: Arc<dyn MailSource> = Arc::new(OutboxSource {
        base_url: format!("http://{}", running.main_addr),
    });
    let mut used = UsedCodes::default();
    assert_code(&poll_code(src.clone(), q.clone(), &mut used).await, &sent);

    // The same message is never handed out twice.
    let msgs = tokio::task::spawn_blocking({
        let (s, qq) = (src.clone(), q.clone());
        move || s.search(&qq)
    })
    .await
    .expect("join")
    .expect("search");
    assert!(matches!(
        extract_otp(&msgs, &q, &mut used),
        OtpOutcome::NotFound
    ));

    // A second login sends a fresh code; the newest one wins.
    let second = trigger_otp(&running, &fx).await;
    assert_code(&poll_code(src, q, &mut used).await, &second);
}

#[tokio::test(flavor = "multi_thread")]
async fn mailpit_source_returns_the_emailed_code() {
    if std::env::var_os("CI").is_some() || !docker_available() {
        eprintln!("SKIP mailpit_source_returns_the_emailed_code: Docker not available or in CI");
        return;
    }
    let mp = tokio::task::spawn_blocking(Mailpit::start)
        .await
        .expect("join")
        .expect("mailpit starts");
    let fx = Fixtures::random();
    let running = site::start(fx.clone(), MailSink::Smtp(mp.smtp), 0)
        .await
        .expect("site");
    let q = query();
    let sent = trigger_otp(&running, &fx).await;

    let src: Arc<dyn MailSource> = Arc::new(MailpitSource {
        base_url: format!("http://{}", mp.http),
    });
    let mut used = UsedCodes::default();
    assert_code(&poll_code(src, q, &mut used).await, &sent);
    eprintln!("mailpit_source_returns_the_emailed_code: Mailpit path verified");
    drop(mp);
}
