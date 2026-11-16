//! Just enough RFC 5322 / MIME to read a one-time-code mail: unfolded headers, `From`, `Date`,
//! `Subject` (with RFC 2047 encoded words) and the text of the body. Quoted-printable and base64
//! transfer encodings, nested multiparts (depth-limited), text/plain preferred over text/html.
//!
//! Everything decoded here is message content, so it lives in `Zeroizing` buffers and never
//! reaches an error or a log.

use std::time::SystemTime;

use zeroize::Zeroizing;

/// Bytes past this are ignored (a code mail is a few KiB).
pub const MAX_MESSAGE_BYTES: usize = 1024 * 1024;
const MAX_DEPTH: usize = 5;

/// The parts of a message the OTP finder needs.
#[derive(Default)]
pub struct Parsed {
    /// Lowercase domain of the single `From` address, if there is exactly one.
    pub from_domain: Option<String>,
    /// `Date` header, if it parses.
    pub date: Option<SystemTime>,
    /// Decoded subject.
    pub subject: Zeroizing<String>,
    /// text/plain body, if any.
    pub plain: Option<Zeroizing<String>>,
    /// text/html body, if any (raw HTML).
    pub html: Option<Zeroizing<String>>,
}

impl std::fmt::Debug for Parsed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Parsed")
            .field("from_domain", &self.from_domain)
            .finish_non_exhaustive()
    }
}

/// Parse a raw message.
pub fn parse(raw: &[u8]) -> Parsed {
    let raw = &raw[..raw.len().min(MAX_MESSAGE_BYTES)];
    let (headers, body) = split_head_body(raw);
    let hs = parse_headers(headers);
    let mut out = Parsed::default();

    let froms: Vec<&Zeroizing<String>> = hs
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("from"))
        .map(|(_, v)| v)
        .collect();
    if let [one] = froms.as_slice() {
        out.from_domain = from_domain(one);
    }
    out.date = header(&hs, "date").and_then(crate::time::parse_rfc2822);
    if let Some(s) = header(&hs, "subject") {
        out.subject = Zeroizing::new(decode_words(s));
    }
    walk(&hs, body, 0, &mut out);
    out
}

fn header<'a>(hs: &'a [(String, Zeroizing<String>)], name: &str) -> Option<&'a str> {
    hs.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// Split at the first empty line (CRLF or LF).
fn split_head_body(raw: &[u8]) -> (&[u8], &[u8]) {
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == b'\n' {
            if raw.get(i + 1) == Some(&b'\n') {
                return (&raw[..i], &raw[i + 2..]);
            }
            if raw.get(i + 1) == Some(&b'\r') && raw.get(i + 2) == Some(&b'\n') {
                return (&raw[..i], &raw[i + 3..]);
            }
        }
        i += 1;
    }
    (raw, &[])
}

/// Unfolded `(name, value)` pairs, in order.
fn parse_headers(head: &[u8]) -> Vec<(String, Zeroizing<String>)> {
    let text = Zeroizing::new(String::from_utf8_lossy(head).into_owned());
    let mut out: Vec<(String, Zeroizing<String>)> = Vec::new();
    for line in text.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.starts_with([' ', '\t']) {
            if let Some((_, v)) = out.last_mut() {
                v.push(' ');
                v.push_str(line.trim());
            }
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            let k = k.trim();
            if !k.is_empty() && !k.contains(' ') {
                out.push((k.to_string(), Zeroizing::new(v.trim().to_string())));
            }
        }
    }
    out
}

/// Domain of the one address in a `From` value. `"a@b" <c@d>` → `d`. Several addresses → None.
pub fn from_domain(v: &str) -> Option<String> {
    // Drop quoted display names so an address inside quotes is never taken.
    let mut unq = String::new();
    let mut in_q = false;
    let mut esc = false;
    for c in v.chars() {
        match (in_q, esc, c) {
            (true, true, _) => esc = false,
            (true, false, '\\') => esc = true,
            (_, false, '"') => in_q = !in_q,
            (false, _, c) => unq.push(c),
            _ => {}
        }
    }
    if unq.contains(',') || unq.matches('@').count() != 1 {
        return None;
    }
    let addr = match (unq.rfind('<'), unq.rfind('>')) {
        (Some(a), Some(b)) if a < b => &unq[a + 1..b],
        (None, None) => unq.as_str(),
        _ => return None,
    };
    let (local, dom) = addr.trim().rsplit_once('@')?;
    let dom = dom.trim().trim_end_matches('.').to_ascii_lowercase();
    if local.is_empty() || dom.is_empty() || dom.contains(char::is_whitespace) {
        return None;
    }
    Some(dom)
}

struct ContentType {
    mime: String,
    boundary: Option<String>,
    charset: Option<String>,
}

fn content_type(v: Option<&str>) -> ContentType {
    let v = v.unwrap_or("text/plain");
    let mut parts = v.split(';');
    let mime = parts.next().unwrap_or("").trim().to_ascii_lowercase();
    let (mut boundary, mut charset) = (None, None);
    for p in parts {
        if let Some((k, val)) = p.split_once('=') {
            let val = val.trim().trim_matches('"').to_string();
            match k.trim().to_ascii_lowercase().as_str() {
                "boundary" => boundary = Some(val),
                "charset" => charset = Some(val.to_ascii_lowercase()),
                _ => {}
            }
        }
    }
    ContentType {
        mime: if mime.is_empty() {
            "text/plain".into()
        } else {
            mime
        },
        boundary,
        charset,
    }
}

fn walk(hs: &[(String, Zeroizing<String>)], body: &[u8], depth: usize, out: &mut Parsed) {
    if depth > MAX_DEPTH {
        return;
    }
    let ct = content_type(header(hs, "content-type"));
    let disposition = header(hs, "content-disposition").unwrap_or("");
    if disposition
        .trim_start()
        .to_ascii_lowercase()
        .starts_with("attachment")
    {
        return;
    }
    if ct.mime.starts_with("multipart/") {
        let Some(b) = ct.boundary else { return };
        for part in split_multipart(body, &b) {
            let (h, bd) = split_head_body(part);
            walk(&parse_headers(h), bd, depth + 1, out);
        }
        return;
    }
    let is_plain = ct.mime == "text/plain";
    let is_html = ct.mime == "text/html";
    if !(is_plain || is_html) {
        return;
    }
    if (is_plain && out.plain.is_some()) || (is_html && out.html.is_some()) {
        return;
    }
    let cte = header(hs, "content-transfer-encoding")
        .unwrap_or("7bit")
        .trim()
        .to_ascii_lowercase();
    let bytes = match cte.as_str() {
        "quoted-printable" => Zeroizing::new(decode_qp(body, false)),
        "base64" => Zeroizing::new(decode_b64(body)),
        _ => Zeroizing::new(body.to_vec()),
    };
    let text = Zeroizing::new(to_text(&bytes, ct.charset.as_deref()));
    if is_plain {
        out.plain = Some(text);
    } else {
        out.html = Some(text);
    }
}

/// Body parts between `--boundary` lines, up to `--boundary--`.
fn split_multipart<'a>(body: &'a [u8], boundary: &str) -> Vec<&'a [u8]> {
    let delim = format!("--{boundary}");
    let d = delim.as_bytes();
    let mut parts = Vec::new();
    let mut start: Option<usize> = None;
    let mut i = 0;
    while i <= body.len() {
        let line_end = body[i..]
            .iter()
            .position(|&b| b == b'\n')
            .map_or(body.len(), |p| i + p);
        let line = &body[i..line_end];
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.starts_with(d) {
            let rest = &line[d.len()..];
            if let Some(s) = start {
                // The CRLF before the delimiter belongs to the delimiter.
                let mut e = i;
                if e > s && body[e - 1] == b'\n' {
                    e -= 1;
                    if e > s && body[e - 1] == b'\r' {
                        e -= 1;
                    }
                }
                parts.push(&body[s..e]);
            }
            if rest.starts_with(b"--") {
                return parts;
            }
            start = Some((line_end + 1).min(body.len()));
        }
        i = line_end + 1;
    }
    parts
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Quoted-printable (RFC 2045). `header` = RFC 2047 Q form (`_` is a space).
fn decode_qp(input: &[u8], header: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        let c = input[i];
        if c == b'=' {
            // Soft line break.
            if input.get(i + 1) == Some(&b'\n') {
                i += 2;
                continue;
            }
            if input.get(i + 1) == Some(&b'\r') && input.get(i + 2) == Some(&b'\n') {
                i += 3;
                continue;
            }
            if let (Some(h), Some(l)) = (
                input.get(i + 1).copied().and_then(hex),
                input.get(i + 2).copied().and_then(hex),
            ) {
                out.push(h << 4 | l);
                i += 3;
                continue;
            }
            out.push(c);
        } else if header && c == b'_' {
            out.push(b' ');
        } else {
            out.push(c);
        }
        i += 1;
    }
    out
}

/// Base64, ignoring whitespace and anything outside the alphabet.
pub fn decode_b64(input: &[u8]) -> Vec<u8> {
    fn val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some(u32::from(c - b'A')),
            b'a'..=b'z' => Some(u32::from(c - b'a') + 26),
            b'0'..=b'9' => Some(u32::from(c - b'0') + 52),
            b'+' | b'-' => Some(62),
            b'/' | b'_' => Some(63),
            _ => None,
        }
    }
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for &c in input {
        if c == b'=' {
            break;
        }
        let Some(v) = val(c) else { continue };
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    out
}

/// Bytes to text: Latin-1 family mapped byte-for-char, everything else UTF-8 (lossy).
fn to_text(b: &[u8], charset: Option<&str>) -> String {
    match charset {
        Some("iso-8859-1" | "latin1" | "latin-1" | "windows-1252" | "cp1252" | "us-ascii") => {
            b.iter().map(|&c| char::from(c)).collect()
        }
        _ => String::from_utf8_lossy(b).into_owned(),
    }
}

/// Decode RFC 2047 encoded words (`=?utf-8?Q?...?=`, `=?utf-8?B?...?=`) in a header value.
pub fn decode_words(v: &str) -> String {
    let mut out = String::new();
    let mut rest = v;
    let mut last_was_word = false;
    while let Some(start) = rest.find("=?") {
        let before = &rest[..start];
        let after = &rest[start + 2..];
        let word = after.split_once('?').and_then(|(cs, r)| {
            let (enc, r) = r.split_once('?')?;
            let (text, tail) = r.split_once("?=")?;
            Some((cs, enc, text, tail))
        });
        let Some((cs, enc, text, tail)) = word else {
            break;
        };
        // Whitespace between two adjacent encoded words is dropped (RFC 2047 §6.2).
        if !(last_was_word && before.trim().is_empty()) {
            out.push_str(before);
        }
        let bytes = match enc.to_ascii_lowercase().as_str() {
            "q" => decode_qp(text.as_bytes(), true),
            "b" => decode_b64(text.as_bytes()),
            _ => text.as_bytes().to_vec(),
        };
        let cs = cs.split('*').next().unwrap_or("").to_ascii_lowercase();
        out.push_str(&to_text(&bytes, Some(&cs)));
        rest = tail;
        last_was_word = true;
    }
    out.push_str(rest);
    out
}

/// Visible text of an HTML body: scripts/styles dropped, tags to whitespace, entities decoded.
pub fn html_to_text(html: &str) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(html.len()));
    let lower = Zeroizing::new(html.to_ascii_lowercase());
    let mut i = 0;
    while i < html.len() {
        let rest = &html[i..];
        if rest.starts_with("<!--") {
            i += rest.find("-->").map_or(rest.len(), |p| p + 3);
            continue;
        }
        if rest.starts_with('<') {
            let lr = &lower[i..];
            for skip in ["script", "style", "head"] {
                if lr[1..].starts_with(skip) {
                    let close = format!("</{skip}");
                    if let Some(p) = lr.find(&close) {
                        i += p;
                    }
                    break;
                }
            }
            let rest = &html[i..];
            let end = rest.find('>').map_or(rest.len(), |p| p + 1);
            let tag = &lower[i..i + end];
            let block = [
                "<br", "<p", "</p", "<div", "</div", "<tr", "</tr", "<li", "<h", "</h",
            ]
            .iter()
            .any(|t| tag.starts_with(t));
            out.push(if block { '\n' } else { ' ' });
            i += end;
            continue;
        }
        if rest.starts_with('&')
            && let Some(semi) = rest.find(';').filter(|&s| s <= 12)
            && let Some(c) = entity(&rest[1..semi])
        {
            out.push(c);
            i += semi + 1;
            continue;
        }
        let Some(c) = rest.chars().next() else { break };
        out.push(c);
        i += c.len_utf8();
    }
    out
}

fn entity(name: &str) -> Option<char> {
    Some(match name {
        "amp" => '&',
        "lt" => '<',
        "gt" => '>',
        "quot" => '"',
        "apos" | "#39" => '\'',
        "nbsp" => ' ',
        _ => {
            let n = name.strip_prefix('#')?;
            let v = match n.strip_prefix(['x', 'X']) {
                Some(h) => u32::from_str_radix(h, 16).ok()?,
                None => n.parse().ok()?,
            };
            char::from_u32(v)?
        }
    })
}

/// `href="..."` values in an HTML body, entity-decoded.
pub fn html_hrefs(html: &str) -> Vec<Zeroizing<String>> {
    let lower = Zeroizing::new(html.to_ascii_lowercase());
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(p) = lower[from..].find("href") {
        let mut i = from + p + 4;
        from = i;
        let b = lower.as_bytes();
        while i < b.len() && b[i].is_ascii_whitespace() {
            i += 1;
        }
        if b.get(i) != Some(&b'=') {
            continue;
        }
        i += 1;
        while i < b.len() && b[i].is_ascii_whitespace() {
            i += 1;
        }
        let (q, start) = match b.get(i) {
            Some(&c @ (b'"' | b'\'')) => (Some(c), i + 1),
            _ => (None, i),
        };
        let end = b[start..]
            .iter()
            .position(|&c| match q {
                Some(q) => c == q,
                None => c.is_ascii_whitespace() || c == b'>',
            })
            .map_or(b.len(), |e| start + e);
        out.push(Zeroizing::new(html[start..end].replace("&amp;", "&")));
        from = end;
    }
    out
}
