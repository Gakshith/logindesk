//! IMAP over TLS (port 993) with an app password. Just the five commands a code search needs:
//! `LOGIN`, `EXAMINE INBOX` (read-only), `UID SEARCH SINCE <day> FROM "<site>"`,
//! `UID FETCH <newest 5> (UID INTERNALDATE BODY.PEEK[])` (never marks mail read), `LOGOUT`.
//!
//! Each message must arrive after `since` (INTERNALDATE) and pass the topmost
//! `Authentication-Results` header (DKIM/DMARC aligned with the site). For Gmail's IMAP the
//! header must also come from `mx.google.com`.
//!
//! Errors: `LOGIN` refused → `NotConnected`; network, TLS or timeout → `Transient`; a reply
//! that makes no sense → `Internal`.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use logindesk_core::limits::OTP_MAX_MESSAGES;
use logindesk_core::{Secret, SecretString};
use zeroize::Zeroizing;

use crate::auth::dkim_aligned;
use crate::mime::MAX_MESSAGE_BYTES;
use crate::time::{imap_date, parse_imap_internal};
use crate::{MailError, MailQuery, MailSource, RawMessage};

const TIMEOUT: Duration = Duration::from_secs(15);
const MAX_LINE: usize = 64 * 1024;

/// IMAP login: the user name and an app password.
pub struct ImapAuth {
    /// Usually the email address.
    pub user: String,
    password: SecretString,
}

impl std::fmt::Debug for ImapAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImapAuth")
            .field("user", &self.user)
            .finish_non_exhaustive()
    }
}

impl ImapAuth {
    /// From the values `connect imap` stored in the vault.
    pub fn new(user: String, password: SecretString) -> Self {
        Self { user, password }
    }
}

/// An IMAP mailbox.
#[derive(Debug, Clone)]
pub struct ImapSource {
    /// e.g. `imap.gmail.com`
    pub host: String,
    /// 993.
    pub port: u16,
    /// Credentials.
    pub auth: Arc<ImapAuth>,
    /// Required authserv-id of the topmost `Authentication-Results` header, if known.
    pub authserv: Option<String>,
    tls: bool,
}

impl ImapSource {
    /// TLS to `host:port`. Gmail's IMAP gets its authserv-id pinned.
    pub fn new(host: String, port: u16, auth: Arc<ImapAuth>) -> Self {
        let authserv =
            (host.eq_ignore_ascii_case("imap.gmail.com")).then(|| "mx.google.com".into());
        Self {
            host,
            port,
            auth,
            authserv,
            tls: true,
        }
    }

    /// Plain TCP, for the in-crate fake server only.
    #[cfg(test)]
    pub(crate) fn plain_for_test(host: String, port: u16, auth: Arc<ImapAuth>) -> Self {
        Self {
            tls: false,
            ..Self::new(host, port, auth)
        }
    }

    fn connect(&self) -> Result<Box<dyn Stream>, MailError> {
        let addr = (self.host.as_str(), self.port)
            .to_socket_addrs()
            .map_err(|_| MailError::Transient)?
            .next()
            .ok_or(MailError::Transient)?;
        let tcp = TcpStream::connect_timeout(&addr, TIMEOUT).map_err(|_| MailError::Transient)?;
        tcp.set_read_timeout(Some(TIMEOUT))
            .and_then(|()| tcp.set_write_timeout(Some(TIMEOUT)))
            .map_err(|_| MailError::Transient)?;
        if !self.tls {
            return Ok(Box::new(tcp));
        }
        let roots = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|_| MailError::Internal)?
        .with_root_certificates(roots)
        .with_no_client_auth();
        let name = rustls::pki_types::ServerName::try_from(self.host.clone())
            .map_err(|_| MailError::Internal)?;
        let conn = rustls::ClientConnection::new(Arc::new(config), name)
            .map_err(|_| MailError::Internal)?;
        Ok(Box::new(rustls::StreamOwned::new(conn, tcp)))
    }
}

trait Stream: Read + Write + Send {}
impl<T: Read + Write + Send> Stream for T {}

/// One piece of a response line: text, or a `{n}` literal's bytes.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Part {
    Text(String),
    Lit(Vec<u8>),
}

/// Outcome of a tagged command.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Done {
    Ok,
    No,
    Bad,
}

pub(crate) struct Session<S: Read + Write> {
    io: BufReader<S>,
    next: u32,
}

impl<S: Read + Write> Session<S> {
    pub(crate) fn new(stream: S) -> Self {
        Self {
            io: BufReader::new(stream),
            next: 1,
        }
    }

    fn line(&mut self) -> Result<Vec<u8>, MailError> {
        let mut buf = Vec::new();
        let n = (&mut self.io)
            .take(MAX_LINE as u64)
            .read_until(b'\n', &mut buf)
            .map_err(|_| MailError::Transient)?;
        if n == 0 {
            return Err(MailError::Transient);
        }
        if !buf.ends_with(b"\n") {
            return Err(MailError::Internal);
        }
        while buf.ends_with(b"\n") || buf.ends_with(b"\r") {
            buf.pop();
        }
        Ok(buf)
    }

    /// One logical response: text lines joined across `{n}` literals.
    pub(crate) fn response(&mut self) -> Result<Vec<Part>, MailError> {
        let mut parts = Vec::new();
        loop {
            let raw = self.line()?;
            let text = String::from_utf8_lossy(&raw).into_owned();
            match literal_len(&text) {
                Some((head, n)) => {
                    if n > MAX_MESSAGE_BYTES * 2 {
                        return Err(MailError::Internal);
                    }
                    parts.push(Part::Text(head.to_string()));
                    let mut lit = vec![0u8; n];
                    self.io
                        .read_exact(&mut lit)
                        .map_err(|_| MailError::Transient)?;
                    parts.push(Part::Lit(lit));
                }
                None => {
                    parts.push(Part::Text(text));
                    return Ok(parts);
                }
            }
        }
    }

    /// Greeting: `* OK ...`.
    pub(crate) fn greeting(&mut self) -> Result<(), MailError> {
        match self.response()?.first() {
            Some(Part::Text(t)) if t.starts_with("* OK") || t.starts_with("* PREAUTH") => Ok(()),
            _ => Err(MailError::Internal),
        }
    }

    /// Send `<tag> <cmd>` and collect untagged replies until the tagged one.
    pub(crate) fn run(&mut self, cmd: &str) -> Result<(Done, Vec<Vec<Part>>), MailError> {
        let tag = format!("A{}", self.next);
        self.next += 1;
        let line = Zeroizing::new(format!("{tag} {cmd}\r\n"));
        let w = self.io.get_mut();
        w.write_all(line.as_bytes())
            .and_then(|()| w.flush())
            .map_err(|_| MailError::Transient)?;
        let mut untagged = Vec::new();
        loop {
            let r = self.response()?;
            let Some(Part::Text(first)) = r.first() else {
                return Err(MailError::Internal);
            };
            if let Some(rest) = first.strip_prefix(&tag).and_then(|r| r.strip_prefix(' ')) {
                let word = rest.split_whitespace().next().unwrap_or("");
                let done = match word.to_ascii_uppercase().as_str() {
                    "OK" => Done::Ok,
                    "NO" => Done::No,
                    _ => Done::Bad,
                };
                return Ok((done, untagged));
            }
            if first.starts_with("* ") {
                untagged.push(r);
            } else {
                // A continuation request ("+") is never expected here.
                return Err(MailError::Internal);
            }
        }
    }
}

/// `... {123}` or `... {123+}` at the end of a line → (text before, 123).
pub(crate) fn literal_len(line: &str) -> Option<(&str, usize)> {
    let body = line.strip_suffix('}')?;
    let open = body.rfind('{')?;
    let n = body[open + 1..].trim_end_matches('+');
    if n.is_empty() || !n.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((&line[..open], n.parse().ok()?))
}

/// An IMAP quoted string. CR, LF, NUL and non-ASCII are refused.
pub(crate) fn quote(s: &str) -> Option<Zeroizing<String>> {
    if !s.is_ascii() || s.bytes().any(|b| matches!(b, b'\r' | b'\n' | 0)) {
        return None;
    }
    let mut out = Zeroizing::new(String::with_capacity(s.len() + 2));
    out.push('"');
    for c in s.chars() {
        if c == '"' || c == '\\' {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    Some(out)
}

/// UIDs from `* SEARCH 1 2 3` responses.
pub(crate) fn parse_search(untagged: &[Vec<Part>]) -> Vec<u32> {
    let mut out = Vec::new();
    for r in untagged {
        if let Some(Part::Text(t)) = r.first()
            && let Some(rest) = t.strip_prefix("* SEARCH")
        {
            out.extend(
                rest.split_whitespace()
                    .filter_map(|n| n.parse::<u32>().ok()),
            );
        }
    }
    out
}

/// `[UIDVALIDITY n]` from `EXAMINE`'s untagged replies.
pub(crate) fn parse_uidvalidity(untagged: &[Vec<Part>]) -> Option<u32> {
    untagged.iter().find_map(|r| match r.first() {
        Some(Part::Text(t)) => {
            let i = t.find("[UIDVALIDITY ")?;
            let rest = &t[i + 13..];
            rest[..rest.find(']')?].trim().parse().ok()
        }
        _ => None,
    })
}

/// One fetched message.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Fetched {
    pub uid: u32,
    pub internal: Option<SystemTime>,
    pub body: Vec<u8>,
}

/// `* n FETCH (UID u INTERNALDATE "..." BODY[] {len}<bytes>)`, items in any order.
pub(crate) fn parse_fetch(r: Vec<Part>) -> Option<Fetched> {
    let mut texts = String::new();
    let mut body = None;
    let mut want_body = false;
    for p in r {
        match p {
            Part::Text(t) => {
                want_body = t.trim_end().to_ascii_uppercase().ends_with("BODY[]");
                texts.push_str(&t);
                texts.push(' ');
            }
            Part::Lit(b) if want_body && body.is_none() => body = Some(b),
            Part::Lit(_) => {}
        }
    }
    let upper = texts.to_ascii_uppercase();
    if !upper.starts_with("* ") || !upper.contains(" FETCH ") {
        return None;
    }
    let uid = upper
        .find("UID ")
        .and_then(|i| upper[i + 4..].split(|c: char| !c.is_ascii_digit()).next())
        .and_then(|n| n.parse().ok())?;
    let internal = upper.find("INTERNALDATE \"").and_then(|i| {
        let rest = &texts[i + 14..];
        parse_imap_internal(&rest[..rest.find('"')?])
    });
    Some(Fetched {
        uid,
        internal,
        body: body?,
    })
}

impl ImapSource {
    fn session<S: Read + Write>(
        &self,
        s: &mut Session<S>,
        q: &MailQuery,
    ) -> Result<Vec<RawMessage>, MailError> {
        s.greeting()?;
        let user = quote(&self.auth.user).ok_or(MailError::NotConnected)?;
        let pass = quote(self.auth.password.expose()).ok_or(MailError::NotConnected)?;
        let login = Zeroizing::new(format!("LOGIN {} {}", user.as_str(), pass.as_str()));
        match s.run(&login)?.0 {
            Done::Ok => {}
            Done::No => return Err(MailError::NotConnected),
            Done::Bad => return Err(MailError::Internal),
        }
        let (done, ex) = s.run("EXAMINE INBOX")?;
        if done != Done::Ok {
            return Err(MailError::Internal);
        }
        let validity = parse_uidvalidity(&ex).unwrap_or(0);
        let site = quote(&q.site).ok_or(MailError::Internal)?;
        let (done, found) = s.run(&format!(
            "UID SEARCH SINCE {} FROM {}",
            imap_date(q.since),
            site.as_str()
        ))?;
        if done != Done::Ok {
            return Err(MailError::Internal);
        }
        let mut uids = parse_search(&found);
        uids.sort_unstable_by(|a, b| b.cmp(a));
        uids.dedup();
        uids.truncate(OTP_MAX_MESSAGES);
        let mut out = Vec::new();
        if !uids.is_empty() {
            let set = uids
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(",");
            let (done, fetched) =
                s.run(&format!("UID FETCH {set} (UID INTERNALDATE BODY.PEEK[])"))?;
            if done != Done::Ok {
                return Err(MailError::Internal);
            }
            for f in fetched.into_iter().filter_map(parse_fetch) {
                let Some(received) = f.internal else { continue };
                if received < q.since
                    || f.body.len() > MAX_MESSAGE_BYTES
                    || !dkim_aligned(&f.body, &q.site, self.authserv.as_deref())
                {
                    continue;
                }
                out.push(RawMessage {
                    id: format!("imap:{validity}:{}", f.uid),
                    received,
                    bytes: Secret::new(f.body),
                });
            }
        }
        let _ = s.run("LOGOUT");
        out.sort_by_key(|m| std::cmp::Reverse(m.received));
        Ok(out)
    }
}

impl MailSource for ImapSource {
    fn search(&self, q: &MailQuery) -> Result<Vec<RawMessage>, MailError> {
        let stream = self.connect()?;
        self.session(&mut Session::new(stream), q)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::net::TcpListener;
    use std::time::UNIX_EPOCH;

    use super::*;

    #[test]
    fn literals_quotes_and_search() {
        assert_eq!(
            literal_len("* 1 FETCH (BODY[] {12}"),
            Some(("* 1 FETCH (BODY[] ", 12))
        );
        assert_eq!(literal_len("x {3+}"), Some(("x ", 3)));
        assert_eq!(literal_len("x {a}"), None);
        assert_eq!(literal_len("x }"), None);
        assert_eq!(
            quote(r#"a"b\c"#).as_deref().map(String::as_str),
            Some(r#""a\"b\\c""#)
        );
        assert!(quote("a\r\nb").is_none());
        assert!(quote("pässword").is_none());
        let s = vec![vec![Part::Text("* SEARCH 3 9 4".into())]];
        assert_eq!(parse_search(&s), [3, 9, 4]);
        let e = vec![vec![Part::Text(
            "* OK [UIDVALIDITY 6141] UIDs valid".into(),
        )]];
        assert_eq!(parse_uidvalidity(&e), Some(6141));
    }

    #[test]
    fn response_reader_and_fetch_parse() {
        let wire = b"* 2 FETCH (INTERNALDATE \"12-Nov-2026 00:00:05 +0000\" UID 41 BODY[] {5}\r\nhello)\r\nA1 OK done\r\n";
        let mut s = Session::new(Cursor::new(wire.to_vec()));
        let r = s.response().expect("response");
        assert_eq!(r.len(), 3);
        let f = parse_fetch(r).expect("fetch");
        assert_eq!(f.uid, 41);
        assert_eq!(f.body, b"hello");
        assert_eq!(
            f.internal,
            Some(UNIX_EPOCH + Duration::from_secs(1_794_441_605))
        );
        assert!(parse_fetch(vec![Part::Text("* 3 EXISTS".into())]).is_none());
    }

    const AR: &str = "Authentication-Results: mx.google.com; dkim=pass header.i=@example.com; dmarc=pass header.from=example.com\r\n";

    fn fake_server(fail_login: bool, body: String) -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = l.local_addr().expect("addr").port();
        std::thread::spawn(move || {
            let Ok((s, _)) = l.accept() else { return };
            let mut r = BufReader::new(s.try_clone().expect("clone"));
            let mut w = s;
            let _ = w.write_all(b"* OK fake IMAP ready\r\n");
            let mut line = String::new();
            while r.read_line(&mut line).unwrap_or(0) > 0 {
                let tag = line.split_whitespace().next().unwrap_or("").to_string();
                let cmd = line.to_ascii_uppercase();
                let reply = if cmd.contains(" LOGIN ") {
                    if fail_login || !line.contains("\"app pw\"") {
                        format!("{tag} NO [AUTHENTICATIONFAILED] Invalid credentials\r\n")
                    } else {
                        format!("{tag} OK logged in\r\n")
                    }
                } else if cmd.contains(" EXAMINE ") {
                    format!(
                        "* 3 EXISTS\r\n* OK [UIDVALIDITY 77] ok\r\n{tag} OK [READ-ONLY] done\r\n"
                    )
                } else if cmd.contains(" UID SEARCH ") {
                    assert!(cmd.contains("FROM \"EXAMPLE.COM\""));
                    format!("* SEARCH 7 8\r\n{tag} OK done\r\n")
                } else if cmd.contains(" UID FETCH ") {
                    assert!(cmd.contains("BODY.PEEK[]"), "must not mark mail read");
                    let old = format!("{AR}From: <a@example.com>\r\n\r\nYour code is 111111");
                    format!(
                        "* 1 FETCH (UID 8 INTERNALDATE \"12-Nov-2026 00:00:30 +0000\" BODY[] {{{}}}\r\n{body})\r\n* 2 FETCH (UID 7 INTERNALDATE \"11-Nov-2026 23:00:00 +0000\" BODY[] {{{}}}\r\n{old})\r\n{tag} OK done\r\n",
                        body.len(),
                        old.len()
                    )
                } else {
                    format!("* BYE\r\n{tag} OK bye\r\n")
                };
                let _ = w.write_all(reply.as_bytes());
                line.clear();
            }
        });
        port
    }

    fn q() -> MailQuery {
        MailQuery {
            site: "example.com".into(),
            since: UNIX_EPOCH + Duration::from_secs(1_794_441_600),
        }
    }

    #[test]
    fn session_against_fake_server() {
        let body = format!(
            "{AR}From: <no-reply@example.com>\r\nSubject: Code\r\n\r\nYour code is 650433\r\n"
        );
        let port = fake_server(false, body);
        let auth = Arc::new(ImapAuth::new(
            "me@mail.test".into(),
            SecretString::new("app pw".into()),
        ));
        let src = ImapSource::plain_for_test("127.0.0.1".into(), port, auth);
        let got = src.search(&q()).expect("search");
        // UID 7 is older than `since`; only UID 8 is kept.
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].id, "imap:77:8");
        match crate::extract_otp(&got, &q(), &mut crate::UsedCodes::default()) {
            crate::OtpOutcome::Code(c) => assert!(c.expose() == "650433"),
            other => panic!("expected a code, got {other:?}"),
        }
    }

    #[test]
    fn rejected_login_is_not_connected_and_unsigned_mail_dropped() {
        let port = fake_server(true, String::new());
        let auth = Arc::new(ImapAuth::new(
            "me@mail.test".into(),
            SecretString::new("app pw".into()),
        ));
        let src = ImapSource::plain_for_test("127.0.0.1".into(), port, auth.clone());
        assert_eq!(src.search(&q()).err(), Some(MailError::NotConnected));

        let unsigned = "From: <no-reply@example.com>\r\n\r\nYour code is 650433\r\n".to_string();
        let port = fake_server(false, unsigned);
        let src = ImapSource::plain_for_test("127.0.0.1".into(), port, auth);
        assert!(src.search(&q()).expect("search").is_empty());
    }

    #[test]
    fn refused_connection_is_transient() {
        let l = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = l.local_addr().expect("addr").port();
        drop(l);
        let auth = Arc::new(ImapAuth::new("u".into(), SecretString::new("p".into())));
        let src = ImapSource::plain_for_test("127.0.0.1".into(), port, auth);
        assert_eq!(src.search(&q()).err(), Some(MailError::Transient));
    }
}
