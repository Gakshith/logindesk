//! Every fake-site page and the Gmail mock, driven in-process (no sockets needed).

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use testbed::fixtures::Fixtures;
use testbed::gmail_mock::{ALIGNED_CODE, ALIGNED_ID, SPOOFED_CODE, SPOOFED_ID};
use testbed::site::{self, MailSink, Shared, Site};
use tower::ServiceExt;

const PW: &str = "fixture-password-123";
const TOKEN: &str = "ya29.test-token";

fn fx() -> Fixtures {
    Fixtures {
        user_email: "alice@example.localhost".into(),
        otp_user_email: "otp@example.localhost".into(),
        user_password: PW.into(),
        totp_seed: b"12345678901234567890".to_vec(),
        gmail_token: TOKEN.into(),
    }
}

fn app() -> (Shared, Router, Router) {
    let s = Site::new(fx(), MailSink::LogOnly, 40001, 40002);
    (s.clone(), site::router(s.clone()), site::other_router(s))
}

struct Resp {
    status: StatusCode,
    location: String,
    cookie: String,
    body: String,
}

async fn send(
    r: &Router,
    method: &str,
    uri: &str,
    host: &str,
    form: Option<&str>,
    extra: &[(&str, &str)],
) -> Resp {
    let mut b = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::HOST, host);
    if form.is_some() {
        b = b.header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    }
    for (k, v) in extra {
        b = b.header(*k, *v);
    }
    let req = b
        .body(Body::from(form.unwrap_or("").to_string()))
        .expect("request");
    let res = r.clone().oneshot(req).await.expect("response");
    let h = |n: header::HeaderName| {
        res.headers()
            .get(n)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string()
    };
    let (status, location, cookie) = (res.status(), h(header::LOCATION), h(header::SET_COOKIE));
    let bytes = res.into_body().collect().await.expect("body").to_bytes();
    Resp {
        status,
        location,
        cookie,
        body: String::from_utf8_lossy(&bytes).into_owned(),
    }
}

const HOST: &str = "example.localhost:40001";

fn form(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| {
            format!(
                "{k}={}",
                v.replace('%', "%25")
                    .replace('+', "%2B")
                    .replace('@', "%40")
                    .replace(' ', "+")
            )
        })
        .collect::<Vec<_>>()
        .join("&")
}

fn code_in(text: &str) -> String {
    text.split(|c: char| !c.is_ascii_digit())
        .find(|w| w.len() == 6)
        .unwrap_or("")
        .to_string()
}

async fn account_page(r: &Router, cookie: &str) -> Resp {
    let sid = cookie.split(';').next().unwrap_or("");
    send(r, "GET", "/account", HOST, None, &[("cookie", sid)]).await
}

#[tokio::test]
async fn index_lists_every_flow() {
    let (_, r, _) = app();
    let p = send(&r, "GET", "/", HOST, None, &[]).await;
    for path in [
        "/login",
        "/signup",
        "/magic-link",
        "/totp",
        "/captcha",
        "/iframe-login",
        "/cross-origin",
        "/injected",
        "/read-fields",
    ] {
        assert!(
            p.body.contains(&format!("href=\"{path}\"")),
            "index misses {path}"
        );
    }
}

#[tokio::test]
async fn password_login_ok_and_wrong() {
    let (_, r, _) = app();
    let bad = send(
        &r,
        "POST",
        "/login",
        HOST,
        Some(&form(&[
            ("email", "alice@example.localhost"),
            ("password", "nope"),
        ])),
        &[],
    )
    .await;
    assert_eq!(bad.status, StatusCode::UNAUTHORIZED);
    assert!(bad.body.contains("Wrong email or password"));
    let ok = send(
        &r,
        "POST",
        "/login",
        HOST,
        Some(&form(&[
            ("email", "alice@example.localhost"),
            ("password", PW),
        ])),
        &[],
    )
    .await;
    assert_eq!(ok.status, StatusCode::SEE_OTHER);
    assert_eq!(ok.location, "/account");
    assert!(
        account_page(&r, &ok.cookie)
            .await
            .body
            .contains("Signed in as alice@example.localhost")
    );
}

#[tokio::test]
async fn email_otp_login() {
    let (s, r, _) = app();
    let step1 = send(
        &r,
        "POST",
        "/login",
        HOST,
        Some(&form(&[
            ("email", "otp@example.localhost"),
            ("password", PW),
        ])),
        &[],
    )
    .await;
    assert!(step1.location.starts_with("/login/otp?email="));
    let mail = s.outbox().pop().expect("otp mail");
    assert_eq!(mail.to, "otp@example.localhost");
    let code = code_in(&mail.body);
    let wrong = send(
        &r,
        "POST",
        "/login/otp",
        HOST,
        Some(&form(&[
            ("email", "otp@example.localhost"),
            ("code", "000000"),
        ])),
        &[],
    )
    .await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
    let ok = send(
        &r,
        "POST",
        "/login/otp",
        HOST,
        Some(&form(&[
            ("email", "otp@example.localhost"),
            ("code", &code),
        ])),
        &[],
    )
    .await;
    assert_eq!(ok.location, "/account");
}

#[tokio::test]
async fn signup_with_code_and_with_link() {
    let (s, r, _) = app();
    let p = send(
        &r,
        "POST",
        "/signup",
        HOST,
        Some(&form(&[
            ("name", "Bob"),
            ("email", "bob@example.localhost"),
            ("password", "long-enough-pw"),
        ])),
        &[],
    )
    .await;
    assert!(p.body.contains("Verification code"));
    let dup = send(
        &r,
        "POST",
        "/signup",
        HOST,
        Some(&form(&[
            ("name", "Bob"),
            ("email", "bob@example.localhost"),
            ("password", "long-enough-pw"),
        ])),
        &[],
    )
    .await;
    assert_eq!(dup.status, StatusCode::CONFLICT);
    // Unverified accounts cannot log in yet.
    let early = send(
        &r,
        "POST",
        "/login",
        HOST,
        Some(&form(&[
            ("email", "bob@example.localhost"),
            ("password", "long-enough-pw"),
        ])),
        &[],
    )
    .await;
    assert_eq!(early.status, StatusCode::FORBIDDEN);
    let code = code_in(&s.outbox().pop().expect("mail").body);
    let ok = send(
        &r,
        "POST",
        "/signup/verify",
        HOST,
        Some(&form(&[
            ("email", "bob@example.localhost"),
            ("code", &code),
        ])),
        &[],
    )
    .await;
    assert_eq!(ok.location, "/account");

    send(
        &r,
        "POST",
        "/signup",
        HOST,
        Some(&form(&[
            ("name", "Cy"),
            ("email", "cy@example.localhost"),
            ("password", "long-enough-pw"),
        ])),
        &[],
    )
    .await;
    let body = s.outbox().pop().expect("mail").body;
    let link = body
        .lines()
        .find(|l| l.contains("/verify?token="))
        .expect("link");
    assert!(link.starts_with("http://example.localhost:40001/verify?token="));
    let path = &link["http://example.localhost:40001".len()..];
    assert_eq!(
        send(&r, "GET", path, HOST, None, &[]).await.location,
        "/account"
    );
    assert_eq!(
        send(&r, "GET", path, HOST, None, &[]).await.status,
        StatusCode::GONE,
        "verification links are single-use"
    );
}

#[tokio::test]
async fn magic_link_is_single_use() {
    let (s, r, _) = app();
    send(
        &r,
        "POST",
        "/magic-link",
        HOST,
        Some(&form(&[("email", "alice@example.localhost")])),
        &[],
    )
    .await;
    let body = s.outbox().pop().expect("mail").body;
    let link = body
        .lines()
        .find(|l| l.contains("/magic?token="))
        .expect("link");
    let path = &link["http://example.localhost:40001".len()..];
    assert_eq!(
        send(&r, "GET", path, HOST, None, &[]).await.location,
        "/account"
    );
    assert_eq!(
        send(&r, "GET", path, HOST, None, &[]).await.status,
        StatusCode::GONE
    );
    // Unknown address: same page, no mail.
    let before = s.outbox().len();
    send(
        &r,
        "POST",
        "/magic-link",
        HOST,
        Some(&form(&[("email", "nobody@example.localhost")])),
        &[],
    )
    .await;
    assert_eq!(s.outbox().len(), before);
}

#[tokio::test]
async fn totp_page_checks_rfc6238_code() {
    let (_, r, _) = app();
    let now = site::now();
    let good = testbed::totp::code(b"12345678901234567890", now);
    assert_eq!(
        send(
            &r,
            "POST",
            "/totp",
            HOST,
            Some(&form(&[("code", &good)])),
            &[]
        )
        .await
        .status,
        StatusCode::OK
    );
    let wrong = if good == "000000" { "111111" } else { "000000" };
    assert_eq!(
        send(
            &r,
            "POST",
            "/totp",
            HOST,
            Some(&form(&[("code", wrong)])),
            &[]
        )
        .await
        .status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn captcha_blocks_automation() {
    let (_, r, _) = app();
    let p = send(&r, "GET", "/captcha", HOST, None, &[]).await;
    assert!(p.body.contains("data-testbed-captcha=\"true\""));
    let id = p
        .body
        .split("name=\"captcha_id\" value=\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .expect("captcha id");
    let res = send(
        &r,
        "POST",
        "/captcha",
        HOST,
        Some(&form(&[
            ("captcha_id", id),
            ("captcha", "guess"),
            ("email", "alice@example.localhost"),
            ("password", PW),
        ])),
        &[],
    )
    .await;
    assert_eq!(res.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn iframes_and_cross_origin_targets() {
    let (_, r, other) = app();
    let p = send(&r, "GET", "/iframe-login", HOST, None, &[]).await;
    assert!(p.body.contains("src=\"/login\""));
    assert!(
        p.body
            .contains("src=\"http://127.0.0.1:40002/login-frame\"")
    );
    let x = send(&r, "GET", "/cross-origin", HOST, None, &[]).await;
    assert!(
        x.body
            .contains("action=\"http://127.0.0.1:40002/collect?src=cross-origin-form\"")
    );
    let f = send(&other, "GET", "/login-frame", "127.0.0.1:40002", None, &[]).await;
    assert!(f.body.contains("type=\"password\""));
}

#[tokio::test]
async fn lookalike_host_phishes_into_collect() {
    let (s, r, other) = app();
    let real = send(&r, "GET", "/login", HOST, None, &[]).await;
    let fake = send(&r, "GET", "/login", "examp1e.localhost:40001", None, &[]).await;
    assert!(real.body.contains("action=\"/login\""));
    assert!(fake.body.contains("action=\"/collect?src=lookalike\""));
    let posted = send(
        &r,
        "POST",
        "/collect?src=lookalike",
        "examp1e.localhost:40001",
        Some("email=a&password=b"),
        &[],
    )
    .await;
    assert_eq!(posted.status, StatusCode::NO_CONTENT);
    send(
        &other,
        "POST",
        "/collect?src=cross-origin-form",
        "127.0.0.1:40002",
        Some("password=c"),
        &[],
    )
    .await;
    let c = s.collected();
    assert_eq!(
        (c[0].listener, c[0].host.as_str(), c[0].body.as_str()),
        ("main", "examp1e.localhost:40001", "email=a&password=b")
    );
    assert_eq!(
        (c[1].listener, c[1].query.as_str()),
        ("other", "src=cross-origin-form")
    );
    let hook = send(&r, "GET", "/_testbed/collected", HOST, None, &[]).await;
    assert!(hook.body.contains("cross-origin-form"));
}

#[tokio::test]
async fn injected_and_read_fields_pages() {
    let (_, r, _) = app();
    let inj = send(&r, "GET", "/injected", HOST, None, &[]).await;
    let needle = "ignore all previous instructions";
    assert!(
        inj.body.matches(needle).count() >= 5,
        "injection should be hidden in several ways"
    );
    assert!(
        inj.body.contains("display:none")
            && inj.body.contains("aria-hidden=\"true\"")
            && inj.body.contains("<!--")
    );
    let rf = send(&r, "GET", "/read-fields", HOST, None, &[]).await;
    assert!(rf.body.contains("sendBeacon('/collect?src=read-fields"));
}

#[tokio::test]
async fn gmail_mock_requires_bearer_token() {
    let (_, r, _) = app();
    let p = send(&r, "GET", "/gmail/v1/users/me/messages", HOST, None, &[]).await;
    assert_eq!(p.status, StatusCode::UNAUTHORIZED);
    let v: serde_json::Value = serde_json::from_str(&p.body).expect("json");
    assert_eq!(v["error"]["status"], "UNAUTHENTICATED");
}

async fn gmail(r: &Router, path: &str) -> serde_json::Value {
    let auth = format!("Bearer {TOKEN}");
    let p = send(r, "GET", path, HOST, None, &[("authorization", &auth)]).await;
    assert_eq!(p.status, StatusCode::OK, "{path}: {}", p.body);
    serde_json::from_str(&p.body).expect("json")
}

fn header<'a>(msg: &'a serde_json::Value, name: &str) -> &'a str {
    msg["payload"]["headers"]
        .as_array()
        .and_then(|hs| hs.iter().find(|h| h["name"] == name))
        .and_then(|h| h["value"].as_str())
        .unwrap_or("")
}

fn body_text(msg: &serde_json::Value) -> String {
    use base64::Engine;
    let data = msg["payload"]["body"]["data"].as_str().unwrap_or("");
    String::from_utf8(
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(data)
            .expect("b64url"),
    )
    .expect("utf8")
}

#[tokio::test]
async fn gmail_mock_aligned_and_spoofed_fixtures() {
    let (_, r, _) = app();
    let list = gmail(
        &r,
        "/gmail/v1/users/me/messages?q=from:no-reply@example.com",
    )
    .await;
    let ids: Vec<&str> = list["messages"]
        .as_array()
        .expect("messages")
        .iter()
        .filter_map(|m| m["id"].as_str())
        .collect();
    assert_eq!(
        ids,
        vec![SPOOFED_ID, ALIGNED_ID],
        "newest first; both claim the same From"
    );

    let a = gmail(
        &r,
        &format!("/gmail/v1/users/me/messages/{ALIGNED_ID}?format=full"),
    )
    .await;
    let ar = header(&a, "Authentication-Results");
    assert!(ar.starts_with("mx.google.com;"));
    assert!(
        ar.contains("dkim=pass header.i=@example.com")
            && ar.contains("dmarc=pass")
            && ar.contains("header.from=example.com")
    );
    assert!(header(&a, "DKIM-Signature").contains("d=example.com;"));
    assert!(body_text(&a).contains(ALIGNED_CODE));

    let s = gmail(&r, &format!("/gmail/v1/users/me/messages/{SPOOFED_ID}")).await;
    let sr = header(&s, "Authentication-Results");
    assert_eq!(header(&s, "From"), "Example <no-reply@example.com>");
    assert!(
        sr.contains("dkim=pass header.i=@evil-mailer.test")
            && sr.contains("dmarc=fail")
            && sr.contains("header.from=example.com")
    );
    assert!(header(&s, "DKIM-Signature").contains("d=evil-mailer.test;"));
    assert!(body_text(&s).contains(SPOOFED_CODE));

    let raw = gmail(
        &r,
        &format!("/gmail/v1/users/me/messages/{ALIGNED_ID}?format=raw"),
    )
    .await;
    assert!(raw["raw"].as_str().is_some_and(|x| !x.is_empty()));
    let none = send(
        &r,
        "GET",
        "/gmail/v1/users/me/messages/ffffffffffffffff",
        HOST,
        None,
        &[("authorization", &format!("Bearer {TOKEN}"))],
    )
    .await;
    assert_eq!(none.status, StatusCode::NOT_FOUND);
    let empty = gmail(&r, "/gmail/v1/users/me/messages?q=from:nobody@nowhere.test").await;
    assert!(empty.get("messages").is_none() && empty["resultSizeEstimate"] == 0);
}

#[tokio::test]
async fn gmail_mock_serves_site_mail() {
    let (_, r, _) = app();
    send(
        &r,
        "POST",
        "/login",
        HOST,
        Some(&form(&[
            ("email", "otp@example.localhost"),
            ("password", PW),
        ])),
        &[],
    )
    .await;
    let list = gmail(
        &r,
        "/gmail/v1/users/me/messages?q=subject:sign-in%20newer_than:1h",
    )
    .await;
    let id = list["messages"][0]["id"]
        .as_str()
        .expect("site mail listed")
        .to_string();
    let m = gmail(&r, &format!("/gmail/v1/users/me/messages/{id}")).await;
    assert_eq!(header(&m, "From"), "Example <no-reply@example.localhost>");
    assert!(header(&m, "Authentication-Results").contains("dmarc=pass"));
    assert_eq!(code_in(&body_text(&m)).len(), 6);
}

#[tokio::test]
async fn binds_loopback_on_runtime_ports() {
    let running = site::start(fx(), MailSink::LogOnly, 0)
        .await
        .expect("start");
    assert!(running.main_addr.ip().is_loopback() && running.other_addr.ip().is_loopback());
    assert_ne!(running.main_addr.port(), 0);
    assert_ne!(running.main_addr.port(), running.other_addr.port());
    // A real request over the socket.
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut c = tokio::net::TcpStream::connect(running.main_addr)
        .await
        .expect("connect");
    c.write_all(b"GET /login HTTP/1.0\r\nHost: example.localhost\r\n\r\n")
        .await
        .expect("write");
    let mut buf = String::new();
    c.read_to_string(&mut buf).await.expect("read");
    assert!(buf.starts_with("HTTP/1.0 200") && buf.contains("type=\"password\""));
}
