//! `cargo run -p testbed` starts the fake site and Mailpit (when Docker is available).
//!
//! ```text
//! testbed                 site + Mailpit if Docker answers, otherwise site only (mail kept in /_testbed/outbox)
//! testbed --mailpit       site + Mailpit; fail if Docker is unavailable
//! testbed --no-mailpit    site only
//! testbed hostile         print the hostile-client attack list
//! ```
//! Ports are chosen at runtime (set `TESTBED_PORT` to fix the main one) and printed on stderr.
//! Everything listens on 127.0.0.1 only.

#![forbid(unsafe_code)]

use testbed::fixtures::Fixtures;
use testbed::mailpit::{self, Mailpit};
use testbed::site::{self, MailSink};

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("hostile") {
        testbed::hostile::print_plan();
        return std::process::ExitCode::SUCCESS;
    }
    let want = if args.iter().any(|a| a == "--no-mailpit") {
        Some(false)
    } else if args.iter().any(|a| a == "--mailpit") {
        Some(true)
    } else {
        None
    };

    let mailpit = match want {
        Some(false) => None,
        _ if !mailpit::docker_available() => {
            if want == Some(true) {
                eprintln!("[testbed] --mailpit given but Docker is not available");
                return std::process::ExitCode::FAILURE;
            }
            eprintln!("[testbed] Docker not available: starting the site without Mailpit");
            None
        }
        _ => match Mailpit::start() {
            Ok(m) => Some(m),
            Err(e) => {
                eprintln!("[testbed] Mailpit failed to start: {e}");
                return std::process::ExitCode::FAILURE;
            }
        },
    };
    let sink = mailpit
        .as_ref()
        .map_or(MailSink::LogOnly, |m| MailSink::Smtp(m.smtp));
    let port: u16 = std::env::var("TESTBED_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(0);
    let fx = Fixtures::random();
    let running = match site::start(fx, sink, port).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[testbed] could not bind the site: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    let s = &running.site;
    eprintln!("[testbed] site        {}/", s.base());
    eprintln!(
        "[testbed] lookalike   http://{}:{}/login",
        site::LOOKALIKE_HOST,
        running.main_addr.port()
    );
    eprintln!("[testbed] other origin {}/", s.other_base());
    eprintln!(
        "[testbed] gmail mock  {}/gmail/v1/users/me/messages  (Authorization: Bearer {})",
        s.base(),
        s.fx.gmail_token
    );
    eprintln!(
        "[testbed] accounts    {} and {} (needs email code), password {}",
        s.fx.user_email, s.fx.otp_user_email, s.fx.user_password
    );
    match &mailpit {
        Some(m) => eprintln!(
            "[testbed] mailpit     smtp {}  ui http://{}/  ({})",
            m.smtp,
            m.http,
            mailpit::IMAGE
        ),
        None => eprintln!(
            "[testbed] mailpit     off; mail is kept at {}/_testbed/outbox",
            s.base()
        ),
    }
    eprintln!("[testbed] Ctrl-C or SIGTERM to stop");
    wait_for_shutdown().await;
    eprintln!("[testbed] stopping");
    drop(mailpit);
    std::process::ExitCode::SUCCESS
}

/// Ctrl-C, SIGTERM or SIGHUP. (SIGKILL cannot be caught: the next start removes that container.)
async fn wait_for_shutdown() {
    use tokio::signal::unix::{SignalKind, signal};
    let (Ok(mut term), Ok(mut hup)) = (
        signal(SignalKind::terminate()),
        signal(SignalKind::hangup()),
    ) else {
        let _ = tokio::signal::ctrl_c().await;
        return;
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
        _ = hup.recv() => {}
    }
}
