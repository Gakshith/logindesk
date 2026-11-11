//! The fake site delivers its mail to a real Mailpit container.
//! Skipped (passes with a SKIP line) when `CI` is set or Docker is not available.

use testbed::fixtures::Fixtures;
use testbed::mailpit::{Mailpit, docker_available};
use testbed::site::{self, MailSink};

#[tokio::test(flavor = "multi_thread")]
async fn site_mail_reaches_mailpit() {
    if std::env::var_os("CI").is_some() || !docker_available() {
        eprintln!("SKIP site_mail_reaches_mailpit: Docker not available or running in CI");
        return;
    }
    let mp = std::sync::Arc::new(
        tokio::task::spawn_blocking(Mailpit::start)
            .await
            .expect("join")
            .expect("mailpit starts"),
    );
    let fx = Fixtures::random();
    let (otp_user, pw) = (fx.otp_user_email.clone(), fx.user_password.clone());
    let running = site::start(fx, MailSink::Smtp(mp.smtp), 0)
        .await
        .expect("site");
    // Trigger an OTP mail over a real socket.
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let body = format!("email={}&password={}", otp_user.replace('@', "%40"), pw);
    let mut c = tokio::net::TcpStream::connect(running.main_addr)
        .await
        .expect("connect");
    let req = format!(
        "POST /login HTTP/1.0\r\nHost: example.localhost\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    c.write_all(req.as_bytes()).await.expect("write");
    let mut resp = String::new();
    c.read_to_string(&mut resp).await.expect("read");
    assert!(resp.contains("303"), "{resp}");

    let sent = running.site.outbox().pop().expect("outbox");
    let mut found = false;
    for _ in 0..50 {
        let m = mp.clone();
        let text = tokio::task::spawn_blocking(move || m.api_get("/api/v1/messages"))
            .await
            .expect("join")
            .unwrap_or_default();
        if text.contains(&sent.subject) && text.contains(&otp_user) {
            found = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(found, "Mailpit did not receive the OTP mail");
    drop(mp);
}
