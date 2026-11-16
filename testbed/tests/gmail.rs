//! Gmail REST source against the test bed's Gmail mock, plus the OAuth loopback (PKCE) exchange,
//! with a tiny fake Google token endpoint. No real Google call is made.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use logindesk_core::SecretString;
use logindesk_mail::oauth::{Loopback, OAuthError, Pkce, exchange_code};
use logindesk_mail::{
    GmailAuth, GmailRestSource, MailError, MailQuery, MailSource, OtpOutcome, UsedCodes,
    extract_otp,
};
use testbed::fixtures::Fixtures;
use testbed::gmail_mock::{ALIGNED_CODE, SPOOFED_CODE};
use testbed::site::{self, MailSink, Running};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

type Form = HashMap<String, String>;
type Seen = Arc<Mutex<Vec<Form>>>;

/// A fake token endpoint: every POST's form is recorded, `answer` picks (status, json).
fn fake_token_endpoint(answer: impl Fn(&Form) -> (u16, String) + Send + 'static) -> (String, Seen) {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let url = format!("http://{}/token", l.local_addr().expect("addr"));
    let seen: Seen = Arc::default();
    let rec = seen.clone();
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(s) = s else { return };
            let mut r = BufReader::new(s.try_clone().expect("clone"));
            let mut len = 0usize;
            loop {
                let mut line = String::new();
                if r.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                    break;
                }
                if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    len = v.trim().parse().unwrap_or(0);
                }
            }
            let mut body = vec![0u8; len];
            let _ = r.read_exact(&mut body);
            let form: Form = url::form_urlencoded::parse(&body).into_owned().collect();
            let (status, json) = answer(&form);
            rec.lock().expect("lock").push(form);
            let mut w = s;
            let _ = write!(
                w,
                "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{json}",
                json.len()
            );
        }
    });
    (url, seen)
}

fn auth() -> Arc<GmailAuth> {
    Arc::new(GmailAuth::new(
        "cid.apps.googleusercontent.com".into(),
        SecretString::new("client-secret-x".into()),
        SecretString::new("1//refresh-x".into()),
    ))
}

fn query(site: &str) -> MailQuery {
    MailQuery {
        site: site.into(),
        since: SystemTime::now() - Duration::from_secs(600),
    }
}

async fn search(
    src: &GmailRestSource,
    q: &MailQuery,
) -> Result<Vec<logindesk_mail::RawMessage>, MailError> {
    let (s, q) = (src.clone(), q.clone());
    tokio::task::spawn_blocking(move || s.search(&q))
        .await
        .expect("join")
}

async fn trigger_otp(running: &Running, fx: &Fixtures) -> String {
    let form = format!(
        "email={}&password={}",
        fx.otp_user_email.replace('@', "%40"),
        fx.user_password
    );
    let mut c = tokio::net::TcpStream::connect(running.main_addr)
        .await
        .expect("connect");
    let req = format!(
        "POST /login HTTP/1.0\r\nHost: example.localhost\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{form}",
        form.len()
    );
    c.write_all(req.as_bytes()).await.expect("write");
    let mut resp = String::new();
    c.read_to_string(&mut resp).await.expect("read");
    assert!(resp.contains(" 303 "), "login did not redirect");
    let body = running.site.outbox().pop().expect("outbox").body;
    body.split(|c: char| !c.is_ascii_digit())
        .find(|w| w.len() == 6)
        .expect("code")
        .to_string()
}

fn code_of(o: &OtpOutcome) -> String {
    match o {
        OtpOutcome::Code(c) => c.expose().clone(),
        other => panic!("expected a code, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn gmail_source_reads_the_mock_and_drops_the_spoof() {
    let fx = Fixtures::random();
    let running = site::start(fx.clone(), MailSink::LogOnly, 0)
        .await
        .expect("site");
    let tok = fx.gmail_token.clone();
    let (token_url, seen) = fake_token_endpoint(move |f| {
        if f.get("grant_type").map(String::as_str) == Some("refresh_token")
            && f.get("refresh_token").map(String::as_str) == Some("1//refresh-x")
        {
            (
                200,
                format!(r#"{{"access_token":"{tok}","expires_in":3599,"token_type":"Bearer"}}"#),
            )
        } else {
            (400, r#"{"error":"invalid_grant"}"#.into())
        }
    });
    let src = GmailRestSource {
        api_base: format!("http://{}", running.main_addr),
        token_url,
        auth: auth(),
    };

    // example.com: the aligned fixture is kept, the newer DKIM-spoofed one is dropped.
    let q = query("example.com");
    let msgs = search(&src, &q).await.expect("search");
    assert_eq!(msgs.len(), 1, "the spoofed message must be filtered out");
    let code = code_of(&extract_otp(&msgs, &q, &mut UsedCodes::default()));
    assert_eq!(code, ALIGNED_CODE);
    assert_ne!(code, SPOOFED_CODE);

    // The fake site's own OTP mail, as Gmail would show it.
    let sent = trigger_otp(&running, &fx).await;
    let q = query("example.localhost");
    let msgs = search(&src, &q).await.expect("search");
    assert_eq!(
        code_of(&extract_otp(&msgs, &q, &mut UsedCodes::default())),
        sent
    );

    // One refresh served all three searches (the access token is cached).
    assert_eq!(seen.lock().expect("lock").len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_token_and_revoked_grant_are_not_connected() {
    let fx = Fixtures::random();
    let running = site::start(fx, MailSink::LogOnly, 0).await.expect("site");
    let api = format!("http://{}", running.main_addr);

    // Google hands out a token the API refuses: one retry with a fresh token, then NotConnected.
    let (token_url, seen) = fake_token_endpoint(|_| {
        (
            200,
            r#"{"access_token":"ya29.wrong","expires_in":3599}"#.into(),
        )
    });
    let src = GmailRestSource {
        api_base: api.clone(),
        token_url,
        auth: auth(),
    };
    assert_eq!(
        search(&src, &query("example.com")).await.err(),
        Some(MailError::NotConnected)
    );
    assert_eq!(seen.lock().expect("lock").len(), 2, "exactly one retry");

    // The user revoked access: the refresh token is dead.
    let (token_url, _) = fake_token_endpoint(|_| {
        (
            400,
            r#"{"error":"invalid_grant","error_description":"Token has been expired or revoked."}"#
                .into(),
        )
    });
    let src = GmailRestSource {
        api_base: api.clone(),
        token_url,
        auth: auth(),
    };
    assert_eq!(
        search(&src, &query("example.com")).await.err(),
        Some(MailError::NotConnected)
    );

    // Google's token endpoint is down: try again later.
    let (token_url, _) = fake_token_endpoint(|_| (503, "{}".into()));
    let src = GmailRestSource {
        api_base: api,
        token_url,
        auth: auth(),
    };
    assert_eq!(
        search(&src, &query("example.com")).await.err(),
        Some(MailError::Transient)
    );
}

/// What a browser does after consent: GET the redirect URI (after a stray favicon request).
fn browser_returns(redirect_uri: String, query: String) -> std::thread::JoinHandle<String> {
    std::thread::spawn(move || {
        let hostport = redirect_uri.trim_start_matches("http://").to_string();
        let get = |path: &str| {
            let mut s = std::net::TcpStream::connect(&hostport).expect("connect");
            write!(s, "GET {path} HTTP/1.1\r\nHost: {hostport}\r\n\r\n").expect("write");
            let mut out = String::new();
            let _ = s.read_to_string(&mut out);
            out
        };
        let fav = get("/favicon.ico");
        assert!(fav.starts_with("HTTP/1.1 404"));
        get(&format!("/?{query}"))
    })
}

fn param(url: &str, name: &str) -> String {
    let q = url.split_once('?').expect("query").1;
    url::form_urlencoded::parse(q.as_bytes())
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.into_owned())
        .expect("param")
}

#[test]
fn oauth_loopback_pkce_exchange() {
    let pkce = Pkce::new().expect("pkce");
    let lb = Loopback::bind().expect("bind");
    let url = lb.auth_url(
        "https://accounts.example.test/auth",
        "cid.apps.googleusercontent.com",
        &pkce,
    );
    assert_eq!(
        param(&url, "scope"),
        "https://www.googleapis.com/auth/gmail.readonly"
    );
    assert_eq!(param(&url, "code_challenge_method"), "S256");
    assert_eq!(param(&url, "redirect_uri"), lb.redirect_uri);
    assert!(lb.redirect_uri.starts_with("http://127.0.0.1:"));
    let challenge = param(&url, "code_challenge");
    let state = param(&url, "state");

    let browser = browser_returns(
        lb.redirect_uri.clone(),
        format!("state={state}&code=4%2Fauth-code&scope=x"),
    );
    let code = lb.wait_for_code(Duration::from_secs(10)).expect("code");
    assert!(browser.join().expect("join").contains("connected to Gmail"));

    let (token_url, seen) = fake_token_endpoint(move |f| {
        let verifier = f.get("code_verifier").cloned().unwrap_or_default();
        let ok = f.get("grant_type").map(String::as_str) == Some("authorization_code")
            && f.get("code").map(String::as_str) == Some("4/auth-code")
            && Pkce::from_verifier(SecretString::new(verifier)).challenge == challenge;
        if ok {
            (
                200,
                r#"{"access_token":"ya29.a","refresh_token":"1//new-refresh","expires_in":3599}"#
                    .into(),
            )
        } else {
            (400, r#"{"error":"invalid_grant"}"#.into())
        }
    });
    let secret = SecretString::new("client-secret-x".into());
    let refresh = exchange_code(
        &token_url,
        "cid.apps.googleusercontent.com",
        &secret,
        &code,
        &pkce,
        &lb.redirect_uri,
    )
    .expect("exchange");
    assert!(refresh.expose() == "1//new-refresh");
    let forms = seen.lock().expect("lock");
    assert_eq!(forms[0].get("redirect_uri"), Some(&lb.redirect_uri));

    // A wrong verifier (someone else's code) is rejected.
    drop(forms);
    let other = Pkce::new().expect("pkce");
    assert_eq!(
        exchange_code(&token_url, "cid", &secret, &code, &other, &lb.redirect_uri).err(),
        Some(OAuthError::Rejected)
    );
}

#[test]
fn oauth_loopback_rejects_wrong_state_and_reports_denial() {
    let pkce = Pkce::new().expect("pkce");
    let lb = Loopback::bind().expect("bind");
    let _ = lb.auth_url("https://accounts.example.test/auth", "cid", &pkce);
    let b = browser_returns(lb.redirect_uri.clone(), "state=forged&code=x".into());
    assert_eq!(
        lb.wait_for_code(Duration::from_secs(10)).err(),
        Some(OAuthError::StateMismatch)
    );
    let _ = b.join();

    let lb = Loopback::bind().expect("bind");
    let state = param(&lb.auth_url("https://a.test/auth", "cid", &pkce), "state");
    let b = browser_returns(
        lb.redirect_uri.clone(),
        format!("state={state}&error=access_denied"),
    );
    assert_eq!(
        lb.wait_for_code(Duration::from_secs(10)).err(),
        Some(OAuthError::Denied("access_denied".into()))
    );
    let _ = b.join();

    let lb = Loopback::bind().expect("bind");
    assert_eq!(
        lb.wait_for_code(Duration::from_millis(300)).err(),
        Some(OAuthError::Timeout)
    );
}
