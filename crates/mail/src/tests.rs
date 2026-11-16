//! Hand-written fixture messages for `extract_otp`, and the HTTP sources against a tiny local
//! server. Every code below is a made-up test value.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use logindesk_core::Secret;

use super::*;

const SITE: &str = "example.com";

fn t0() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_794_441_600)
}

fn q() -> MailQuery {
    MailQuery {
        site: SITE.into(),
        since: t0(),
    }
}

fn msg(id: &str, after_secs: i64, raw: &str) -> RawMessage {
    let received = if after_secs >= 0 {
        t0() + Duration::from_secs(after_secs.unsigned_abs())
    } else {
        t0() - Duration::from_secs(after_secs.unsigned_abs())
    };
    RawMessage {
        id: id.into(),
        received,
        bytes: Secret::new(raw.as_bytes().to_vec()),
    }
}

fn plain(from: &str, subject: &str, body: &str) -> String {
    format!(
        "From: {from}\r\nTo: <me@mail.test>\r\nSubject: {subject}\r\nDate: Thu, 12 Nov 2026 00:00:10 +0000\r\nMessage-ID: <a@b>\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{body}"
    )
}

fn run(msgs: &[RawMessage]) -> OtpOutcome {
    extract_otp(msgs, &q(), &mut UsedCodes::default())
}

fn code(o: &OtpOutcome) -> Option<String> {
    match o {
        OtpOutcome::Code(c) => Some(c.expose().clone()),
        _ => None,
    }
}

fn link(o: &OtpOutcome) -> Option<String> {
    match o {
        OtpOutcome::Link(c) => Some(c.expose().clone()),
        _ => None,
    }
}

fn one(raw: &str) -> OtpOutcome {
    run(&[msg("m1", 5, raw)])
}

const FROM: &str = "\"Example\" <no-reply@example.com>";

// ---------- fixtures ----------

#[test]
fn f01_plain_code() {
    let o = one(&plain(
        FROM,
        "Your sign-in code",
        "Your Example sign-in code is 482913.\r\nIt expires in 10 minutes.\r\n",
    ));
    assert_eq!(code(&o).as_deref(), Some("482913"));
}

#[test]
fn f02_lf_only_and_folded_headers() {
    let raw = "From: \"Example\"\n <no-reply@example.com>\nSubject: Your\n verification code\n\nUse 7731 to continue.\n";
    assert_eq!(code(&one(raw)).as_deref(), Some("7731"));
}

#[test]
fn f03_quoted_printable() {
    let raw = "From: no-reply@example.com\r\nSubject: Code\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nVotre code de v=C3=A9rification est 59=\r\n1046. Merci=3D\r\n";
    assert_eq!(code(&one(raw)).as_deref(), Some("591046"));
}

#[test]
fn f04_multipart_alternative_prefers_plain() {
    let raw = "From: no-reply@example.com\r\nSubject: Sign in\r\nMIME-Version: 1.0\r\nContent-Type: multipart/alternative; boundary=\"b1\"\r\n\r\npreamble\r\n--b1\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nYour one-time code: 300125\r\n--b1\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<p>Your one-time code: <b>300125</b></p><p style=\"x\">ref 88112233</p>\r\n--b1--\r\n";
    assert_eq!(code(&one(raw)).as_deref(), Some("300125"));
}

#[test]
fn f05_html_only() {
    let raw = "From: no-reply@example.com\r\nSubject: Verify\r\nContent-Type: text/html\r\n\r\n<html><head><style>.c{width:123456px}</style></head><body><p>Your verification&nbsp;code is</p><h2>640218</h2><!-- 999999 --></body></html>";
    assert_eq!(code(&one(raw)).as_deref(), Some("640218"));
}

#[test]
fn f06_base64_body() {
    // "Your passcode is 818273\n"
    let raw = "From: no-reply@example.com\r\nSubject: Hi\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\nWW91ciBwYXNz\r\nY29kZSBpcyA4MTgyNzMK\r\n";
    assert_eq!(code(&one(raw)).as_deref(), Some("818273"));
}

#[test]
fn f07_wrong_domain_sender_rejected() {
    let o = one(&plain(
        "<no-reply@evil.test>",
        "Your code",
        "Your code is 112233",
    ));
    assert!(matches!(o, OtpOutcome::NotFound));
}

#[test]
fn f08_lookalike_domain_rejected() {
    for from in [
        "<no-reply@examp1e.com>",
        "<no-reply@example.com.evil.test>",
        "<no-reply@example-com.test>",
    ] {
        let o = one(&plain(from, "Your code", "Your code is 112233"));
        assert!(matches!(o, OtpOutcome::NotFound), "{from}");
    }
}

#[test]
fn f09_subdomain_sender_accepted() {
    let o = one(&plain(
        "Example <auth@mail.example.com>",
        "Code",
        "Your code is 445566",
    ));
    assert_eq!(code(&o).as_deref(), Some("445566"));
}

#[test]
fn f10_display_name_spoof_rejected() {
    let o = one(&plain(
        "\"no-reply@example.com\" <x@evil.test>",
        "Your code",
        "Your code is 112233",
    ));
    assert!(matches!(o, OtpOutcome::NotFound));
}

#[test]
fn f11_two_from_headers_rejected() {
    let raw = "From: <no-reply@example.com>\r\nFrom: <x@evil.test>\r\nSubject: Code\r\n\r\nYour code is 112233\r\n";
    assert!(matches!(one(raw), OtpOutcome::NotFound));
    let raw = "From: <no-reply@example.com>, <x@evil.test>\r\nSubject: Code\r\n\r\nYour code is 112233\r\n";
    assert!(matches!(one(raw), OtpOutcome::NotFound));
}

#[test]
fn f12_two_codes_ambiguous() {
    let o = one(&plain(
        FROM,
        "Codes",
        "Your login code is 123456. Your backup code is 654321.",
    ));
    assert!(matches!(o, OtpOutcome::Ambiguous));
}

#[test]
fn f13_same_code_in_subject_and_body_is_one() {
    let o = one(&plain(
        FROM,
        "209741 is your Example code",
        "Enter 209741 to sign in.",
    ));
    assert_eq!(code(&o).as_deref(), Some("209741"));
}

#[test]
fn f14_link_only() {
    let o = one(&plain(
        FROM,
        "Sign in to Example",
        "Click to sign in:\r\nhttps://auth.example.com/magic?token=abcDEF123\r\nThe link expires soon.",
    ));
    assert_eq!(
        link(&o).as_deref(),
        Some("https://auth.example.com/magic?token=abcDEF123")
    );
}

#[test]
fn f15_off_site_link_not_found() {
    let o = one(&plain(
        FROM,
        "Sign in to Example",
        "Click: https://example.com.evil.test/verify?t=1 or https://tracker.test/login/x",
    ));
    assert!(matches!(o, OtpOutcome::NotFound));
}

#[test]
fn f16_http_link_on_real_site_not_found() {
    let o = one(&plain(
        FROM,
        "Confirm",
        "Confirm: http://example.com/confirm?t=1",
    ));
    assert!(matches!(o, OtpOutcome::NotFound));
}

#[test]
fn f17_message_before_since_skipped() {
    let old = msg("old", -60, &plain(FROM, "Code", "Your code is 111111"));
    assert!(matches!(run(&[old]), OtpOutcome::NotFound));
}

#[test]
fn f18_used_id_skipped() {
    let a = msg("a", 10, &plain(FROM, "Code", "Your code is 222222"));
    let b = msg("b", 5, &plain(FROM, "Code", "Your code is 333333"));
    let mut used = UsedCodes::default();
    used.insert("a");
    let o = extract_otp(&[a, b], &q(), &mut used);
    assert_eq!(code(&o).as_deref(), Some("333333"));
    assert!(used.contains("b"));
}

#[test]
fn f19_non_english_german() {
    let o = one(&plain(
        "<noreply@example.com>",
        "=?utf-8?Q?Ihr_Best=C3=A4tigungscode?=",
        "Hallo,\r\nIhr Bestätigungscode lautet: 739201\r\nEr ist 10 Minuten gültig.",
    ));
    assert_eq!(code(&o).as_deref(), Some("739201"));
}

#[test]
fn f20_non_english_spanish_and_japanese() {
    let o = one(&plain(FROM, "Verificación", "Tu código es 551903"));
    assert_eq!(code(&o).as_deref(), Some("551903"));
    let o = one(&plain(
        FROM,
        "=?UTF-8?B?44Kz44O844OJ?=",
        "確認コード: 802264",
    ));
    assert_eq!(code(&o).as_deref(), Some("802264"));
}

#[test]
fn f21_code_only_in_encoded_subject() {
    // Subject: "Your code is 417305"
    let o = one(&plain(
        FROM,
        "=?utf-8?B?WW91ciBjb2RlIGlzIDQxNzMwNQ==?=",
        "Thanks for signing up.",
    ));
    assert_eq!(code(&o).as_deref(), Some("417305"));
}

#[test]
fn f22_uppercase_alnum_code() {
    let o = one(&plain(
        FROM,
        "Verification",
        "Your verification code: K7Q2ZX9\r\nDo not share it.",
    ));
    assert_eq!(code(&o).as_deref(), Some("K7Q2ZX9"));
}

#[test]
fn f23_phone_and_year_ignored() {
    let o = one(&plain(
        FROM,
        "Your code",
        "Your code is 604411.\r\nQuestions? Call +1 555 123 4567 or (555) 123-4567.\r\n© 2026 Example Inc.",
    ));
    assert_eq!(code(&o).as_deref(), Some("604411"));
}

#[test]
fn f24_digits_in_url_ignored() {
    let o = one(&plain(
        FROM,
        "Code",
        "Your code is 908172. Manage: https://example.com/settings/123456/prefs?id=654321",
    ));
    assert_eq!(code(&o).as_deref(), Some("908172"));
}

#[test]
fn f25_newest_accepted_wins_and_is_marked_used() {
    let old = msg("old", 5, &plain(FROM, "Code", "Your code is 100001"));
    let new = msg("new", 20, &plain(FROM, "Code", "Your code is 200002"));
    let spam = msg("spam", 30, &plain("<x@evil.test>", "Code", "code 300003"));
    let mut used = UsedCodes::default();
    let msgs = [old, new, spam];
    assert_eq!(
        code(&extract_otp(&msgs, &q(), &mut used)).as_deref(),
        Some("200002")
    );
    assert!(used.contains("new"));
    // The next call skips the used message and falls back to the older one.
    assert_eq!(
        code(&extract_otp(&msgs, &q(), &mut used)).as_deref(),
        Some("100001")
    );
    assert!(matches!(
        extract_otp(&msgs, &q(), &mut used),
        OtpOutcome::NotFound
    ));
}

#[test]
fn f26_ambiguous_does_not_mark_used() {
    let m = msg("m", 5, &plain(FROM, "Code", "code 123456 or code 654321"));
    let mut used = UsedCodes::default();
    assert!(matches!(
        extract_otp(&[m], &q(), &mut used),
        OtpOutcome::Ambiguous
    ));
    assert!(!used.contains("m"));
}

#[test]
fn f27_attachment_and_nested_multipart() {
    let raw = "From: no-reply@example.com\r\nSubject: Sign-in\r\nContent-Type: multipart/mixed; boundary=outer\r\n\r\n--outer\r\nContent-Type: multipart/alternative; boundary=inner\r\n\r\n--inner\r\nContent-Type: text/plain\r\n\r\nYour sign-in code is 274650\r\n--inner\r\nContent-Type: text/html\r\n\r\n<b>274650</b>\r\n--inner--\r\n--outer\r\nContent-Type: text/plain\r\nContent-Disposition: attachment; filename=x.txt\r\n\r\ncode 999888\r\n--outer--\r\n";
    assert_eq!(code(&one(raw)).as_deref(), Some("274650"));
}

#[test]
fn f28_no_keyword_not_found() {
    let o = one(&plain(
        FROM,
        "Weekly digest",
        "Order 48213 shipped. Tracking 774411.",
    ));
    assert!(matches!(o, OtpOutcome::NotFound));
}

#[test]
fn f29_two_onsite_links_ambiguous_one_link_in_html_href() {
    let o = one(&plain(
        FROM,
        "Confirm",
        "https://example.com/confirm?t=AAA and https://example.com/confirm?t=BBB",
    ));
    assert!(matches!(o, OtpOutcome::Ambiguous));
    let raw = "From: no-reply@example.com\r\nSubject: Confirm your email\r\nContent-Type: text/html\r\n\r\n<a href=\"https://example.com/verify-email?t=X1&amp;u=2\">Confirm</a> <a href=\"https://help.other.test/faq\">Help</a>";
    assert_eq!(
        link(&one(raw)).as_deref(),
        Some("https://example.com/verify-email?t=X1&u=2")
    );
}

#[test]
fn f30_testbed_shape_http_localhost_link_and_code() {
    let q = MailQuery {
        site: "example.localhost".into(),
        since: t0(),
    };
    let raw = "From: \"Example\" <no-reply@example.localhost>\r\nSubject: Your Example sign-in code\r\nContent-Type: text/plain; charset=\"UTF-8\"\r\n\r\nYour Example sign-in code is 052187.\r\nIt expires in 10 minutes.\r\n";
    let o = extract_otp(&[msg("x", 1, raw)], &q, &mut UsedCodes::default());
    assert_eq!(code(&o).as_deref(), Some("052187"));
    let raw = "From: <no-reply@example.localhost>\r\nSubject: Your sign-in link\r\n\r\nSign in: http://example.localhost:40001/magic?token=Zt9\r\n";
    let o = extract_otp(&[msg("y", 1, raw)], &q, &mut UsedCodes::default());
    assert_eq!(
        link(&o).as_deref(),
        Some("http://example.localhost:40001/magic?token=Zt9")
    );
}

#[test]
fn f31_garbage_does_not_panic() {
    for raw in [
        "",
        "\r\n\r\n",
        "From: <a@example.com>\r\nContent-Type: multipart/alternative\r\n\r\n--x",
        "From: <a@example.com>\r\nContent-Type: text/html\r\n\r\n<a href=",
        "From: <a@example.com>\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n=\r=Z=",
        "From: <a@example.com>\r\nSubject: =?utf-8?Q?broken\r\n\r\n&#xFFFFFFFF; &é; code ÉÉÉ",
    ] {
        let _ = one(raw);
    }
}

#[test]
fn outcome_debug_is_redacted() {
    let o = one(&plain(FROM, "Code", "Your code is 482913"));
    assert!(!format!("{o:?}").contains("482913"));
}

// ---------- HTTP sources ----------

/// Serve `(path → (status, body))` for `n` requests on a random loopback port.
fn serve(routes: Vec<(String, u16, String)>, n: usize) -> String {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = l.local_addr().expect("addr");
    std::thread::spawn(move || {
        for _ in 0..n {
            let Ok((mut s, _)) = l.accept() else { return };
            let mut buf = [0u8; 4096];
            let k = s.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..k]).into_owned();
            let path = req.split_whitespace().nth(1).unwrap_or("").to_string();
            let (status, body) = routes
                .iter()
                .find(|r| r.0 == path)
                .map_or((404, String::new()), |r| (r.1, r.2.clone()));
            let _ = write!(
                s,
                "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    format!("http://{addr}")
}

#[test]
fn http_refused_is_not_connected() {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let base = format!("http://{}", l.local_addr().expect("addr"));
    drop(l);
    let src = MailpitSource { base_url: base };
    assert_eq!(src.search(&q()).err(), Some(MailError::NotConnected));
}

#[test]
fn http_5xx_is_transient_4xx_internal_bad_json_internal() {
    let base = serve(
        vec![("/api/v1/messages?limit=50".into(), 503, String::new())],
        1,
    );
    assert_eq!(
        MailpitSource { base_url: base }.search(&q()).err(),
        Some(MailError::Transient)
    );
    let base = serve(vec![], 1);
    assert_eq!(
        MailpitSource { base_url: base }.search(&q()).err(),
        Some(MailError::Internal)
    );
    let base = serve(vec![("/_testbed/outbox".into(), 200, "nope".into())], 1);
    assert_eq!(
        OutboxSource { base_url: base }.search(&q()).err(),
        Some(MailError::Internal)
    );
}

#[test]
fn http_only_loopback() {
    for base in [
        "https://127.0.0.1:1",
        "http://mail.example.com",
        "file:///x",
    ] {
        assert_eq!(
            MailpitSource {
                base_url: base.into()
            }
            .search(&q())
            .err(),
            Some(MailError::Internal),
            "{base}"
        );
    }
}

#[test]
fn mailpit_shape_filter_order_and_raw() {
    // Mailpit v1 `GET /api/v1/messages` shape (documented fields only).
    let list = r#"{"total":4,"unread":4,"count":4,"messages_count":4,"start":0,"tags":[],"messages":[
      {"ID":"new1","MessageID":"n@x","Read":false,"From":{"Name":"Example","Address":"no-reply@example.com"},"To":[],"Subject":"Code","Created":"2026-11-12T00:01:00.250Z","Size":10,"Attachments":0,"Snippet":""},
      {"ID":"evil","MessageID":"e@x","Read":false,"From":{"Name":"","Address":"x@evil.test"},"To":[],"Subject":"Code","Created":"2026-11-12T00:02:00Z","Size":10,"Attachments":0,"Snippet":""},
      {"ID":"mid2","MessageID":"m@x","Read":false,"From":{"Name":"","Address":"a@mail.example.com"},"To":[],"Subject":"Code","Created":"2026-11-12T01:00:30+01:00","Size":10,"Attachments":0,"Snippet":""},
      {"ID":"old3","MessageID":"o@x","Read":false,"From":{"Name":"","Address":"no-reply@example.com"},"To":[],"Subject":"Code","Created":"2026-11-11T23:59:00Z","Size":10,"Attachments":0,"Snippet":""},
      {"ID":"../x","MessageID":"b@x","Read":false,"From":{"Name":"","Address":"no-reply@example.com"},"To":[],"Subject":"Code","Created":"2026-11-12T00:03:00Z","Size":10,"Attachments":0,"Snippet":""}
    ]}"#;
    let raw_new = plain(FROM, "Code", "Your code is 616161");
    let raw_mid = plain(FROM, "Code", "Your code is 525252");
    let base = serve(
        vec![
            ("/api/v1/messages?limit=50".into(), 200, list.into()),
            ("/api/v1/message/new1/raw".into(), 200, raw_new),
            ("/api/v1/message/mid2/raw".into(), 200, raw_mid),
        ],
        3,
    );
    let got = MailpitSource { base_url: base }
        .search(&q())
        .expect("search");
    let ids: Vec<&str> = got.iter().map(|m| m.id.as_str()).collect();
    assert_eq!(ids, ["new1", "mid2"]);
    assert_eq!(
        code(&extract_otp(&got, &q(), &mut UsedCodes::default())).as_deref(),
        Some("616161")
    );
}

#[test]
fn outbox_synthesizes_and_filters() {
    let out = r#"[
      {"to":"otp@example.com","from_addr":"no-reply@example.com","subject":"Your code","body":"Your code is 131313.\nBye\n","message_id":"m1@example.com","sent_at":1794441600},
      {"to":"otp@example.com","from_addr":"no-reply@example.com","subject":"Your code","body":"Your code is 242424.\n","message_id":"m2@example.com","sent_at":1794441600},
      {"to":"otp@example.com","from_addr":"no-reply@example.com","subject":"Your code","body":"Your code is 999999.\n","message_id":"m0@example.com","sent_at":1794441599},
      {"to":"otp@example.com","from_addr":"x@evil.test","subject":"Your code","body":"code 777777","message_id":"e@evil.test","sent_at":1794441700}
    ]"#;
    let base = serve(vec![("/_testbed/outbox".into(), 200, out.into())], 1);
    let got = OutboxSource { base_url: base }
        .search(&q())
        .expect("search");
    let ids: Vec<&str> = got.iter().map(|m| m.id.as_str()).collect();
    assert_eq!(ids, ["m2@example.com", "m1@example.com"]);
    let mut used = UsedCodes::default();
    assert_eq!(
        code(&extract_otp(&got, &q(), &mut used)).as_deref(),
        Some("242424")
    );
}
