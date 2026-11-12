//! Canary leak harness (build plan §5, invariant 1).
//!
//! 1. [`Canary::new`] makes unique high-entropy markers. Each one mixes alphanumerics with characters
//!    that change under URL and JSON encoding (`"`, `\`, `/`, `+`, `&`, `%`, space, `é`), so every encoding
//!    really is a different byte string.
//! 2. Flows put those markers wherever a secret would go (vault, mail fixtures, form values).
//! 3. A [`Capture`] collects every channel a secret could escape through: MCP responses, stdout, stderr,
//!    log files, the audit log, panic output, temp files, snapshots.
//! 4. [`Canary::scan`] searches every channel for every marker as raw text, base64 (standard and
//!    URL-safe, at all three byte alignments), hex (lower and upper), URL-encoded (`%20` and `+` forms),
//!    JSON-escaped, and every 8-character window of the raw, URL and JSON forms.
//!
//! The report says which marker, which channel and which encoding. A clean report is the pass condition.

use std::collections::BTreeSet;
use std::fmt;
use std::path::{Path, PathBuf};

use base64::Engine;
use rand::RngExt;

const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const SPECIALS: [char; 8] = ['"', '\\', '/', '+', '&', '%', ' ', 'é'];
const WINDOW: usize = 8;

/// One planted marker.
#[derive(Clone)]
pub struct Marker {
    /// Stable label for reports, e.g. `vault.password.0`.
    pub id: String,
    /// The marker value (what a test plants as the "secret").
    pub value: String,
}

impl fmt::Debug for Marker {
    // The value is fake, but keep reports short and do not echo it twice.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Marker")
            .field("id", &self.id)
            .field("len", &self.value.len())
            .finish()
    }
}

impl Marker {
    /// A fresh marker: 32 random alphanumerics with each special character inserted once at a random place.
    pub fn random(id: impl Into<String>) -> Self {
        let mut rng = rand::rng();
        let mut chars: Vec<char> = (0..32)
            .map(|_| char::from(ALNUM[rng.random_range(0..ALNUM.len())]))
            .collect();
        for s in SPECIALS {
            // Keep the first and last character alphanumeric so the marker never starts or ends with whitespace.
            let at = rng.random_range(1..chars.len());
            chars.insert(at, s);
        }
        Self {
            id: id.into(),
            value: chars.into_iter().collect(),
        }
    }

    /// Every text form a secret can take before any binary encoding is applied.
    fn text_forms(&self) -> Vec<(&'static str, String)> {
        let raw = self.value.clone();
        let url = percent_encode(&raw, false);
        vec![
            ("raw", raw.clone()),
            ("json", json_escape(&raw)),
            ("json-ascii", json_escape_ascii(&raw)),
            ("url-lower", url_lower_hex(&url)),
            ("form-url", percent_encode(&raw, true)),
            ("url", url),
        ]
    }

    /// Every (encoding name, needle) pair the scanner looks for.
    ///
    /// For each text form (raw, JSON-escaped, JSON `\u`-escaped, URL, form-URL, lower-case URL) it adds:
    /// - the form itself and every 8-char window of it;
    /// - base64 and base64url of it at all three byte alignments;
    /// - hex of it, lower and upper case.
    ///
    /// So composites are caught too: `base64url({"password": marker})` (JWT payloads, cookies, `data:` URLs)
    /// and `hex(json)` match the JSON form's needles.
    pub fn needles(&self) -> Vec<(String, String)> {
        let mut out: Vec<(String, String)> = Vec::new();
        let mut seen = BTreeSet::new();
        let mut push = |out: &mut Vec<(String, String)>, name: String, needle: String| {
            if seen.insert(needle.clone()) {
                out.push((name, needle));
            }
        };
        for (form, text) in self.text_forms() {
            push(&mut out, form.to_string(), text.clone());
            let bytes = text.as_bytes();
            // base64: the encoding depends on the text's alignment inside the surrounding data.
            // Encode with 0, 1 and 2 bytes of prefix, then drop the boundary blocks that mix in
            // unknown neighbouring bytes. The long middle part is what any embedding must contain.
            for (name, engine) in [
                ("base64", &base64::engine::general_purpose::STANDARD),
                ("base64url", &base64::engine::general_purpose::URL_SAFE),
            ] {
                for k in 0..3usize {
                    let mut buf = vec![0u8; k];
                    buf.extend_from_slice(bytes);
                    let enc = engine.encode(&buf);
                    let start = if k == 0 { 0 } else { 4 };
                    let end = enc.trim_end_matches('=').len().saturating_sub(4);
                    if end > start + WINDOW {
                        push(
                            &mut out,
                            format!("{name}({form})@{k}"),
                            enc[start..end].to_string(),
                        );
                    }
                }
            }
            let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
            push(&mut out, format!("hex({form})"), hex.to_uppercase());
            push(&mut out, format!("hex({form})"), hex);
            let cs: Vec<char> = text.chars().collect();
            for i in 0..cs.len().saturating_sub(WINDOW - 1) {
                let w: String = cs[i..i + WINDOW].iter().collect();
                // A window made only of encoding punctuation would match unrelated text.
                if w.chars().filter(char::is_ascii_alphanumeric).count() >= 5 {
                    push(&mut out, format!("window8({form})@{i}"), w);
                }
            }
        }
        out
    }
}

fn percent_encode(s: &str, plus_for_space: bool) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                char::from(b).to_string()
            }
            b' ' if plus_for_space => "+".to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

fn url_lower_hex(url: &str) -> String {
    let mut out = String::new();
    let mut it = url.chars();
    while let Some(c) = it.next() {
        out.push(c);
        if c == '%' {
            for _ in 0..2 {
                if let Some(h) = it.next() {
                    out.push(h.to_ascii_lowercase());
                }
            }
        }
    }
    out
}

fn json_escape(s: &str) -> String {
    let quoted = serde_json::to_string(s).unwrap_or_default();
    quoted.trim_matches('"').to_string()
}

fn json_escape_ascii(s: &str) -> String {
    json_escape(s)
        .chars()
        .map(|c| {
            if c.is_ascii() {
                c.to_string()
            } else {
                c.encode_utf16(&mut [0; 2])
                    .iter()
                    .map(|u| format!("\\u{u:04x}"))
                    .collect()
            }
        })
        .collect()
}

/// One captured channel.
#[derive(Debug, Clone)]
pub struct Channel {
    /// e.g. `stderr`, `mcp:tools/call#3`, `file:/tmp/x/audit.jsonl`.
    pub name: String,
    /// The captured bytes.
    pub data: Vec<u8>,
}

/// Everything captured from one run.
#[derive(Debug, Default, Clone)]
pub struct Capture {
    /// The channels in capture order.
    pub channels: Vec<Channel>,
    /// Files or directories that could not be read. Any entry makes the report fail:
    /// a wrong path must never turn into a "clean" scan.
    pub errors: Vec<String>,
}

impl Capture {
    /// Empty capture.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an in-memory channel (MCP response, stdout, stderr, panic output, snapshot …).
    pub fn text(&mut self, name: impl Into<String>, data: impl AsRef<[u8]>) -> &mut Self {
        self.channels.push(Channel {
            name: name.into(),
            data: data.as_ref().to_vec(),
        });
        self
    }

    /// Add one file (log file, audit log …). A missing or unreadable file is a capture error,
    /// which fails the report.
    pub fn file(&mut self, path: impl AsRef<Path>) -> &mut Self {
        let p = path.as_ref();
        match std::fs::read(p) {
            Ok(data) => self.channels.push(Channel {
                name: format!("file:{}", p.display()),
                data,
            }),
            Err(e) => self
                .errors
                .push(format!("missing:file:{} ({e})", p.display())),
        }
        self
    }

    /// Add every regular file under `dir`, recursively (temp dirs, data dirs). File names are scanned too.
    pub fn dir(&mut self, dir: impl AsRef<Path>) -> &mut Self {
        let mut stack: Vec<PathBuf> = vec![dir.as_ref().to_path_buf()];
        while let Some(d) = stack.pop() {
            let rd = match std::fs::read_dir(&d) {
                Ok(rd) => rd,
                Err(e) => {
                    self.errors
                        .push(format!("missing:dir:{} ({e})", d.display()));
                    continue;
                }
            };
            for e in rd {
                let e = match e {
                    Ok(e) => e,
                    Err(err) => {
                        self.errors
                            .push(format!("unreadable:entry-in:{} ({err})", d.display()));
                        continue;
                    }
                };
                let p = e.path();
                self.channels.push(Channel {
                    name: format!("filename:{}", p.display()),
                    data: p.display().to_string().into_bytes(),
                });
                match e.file_type() {
                    Ok(t) if t.is_dir() => stack.push(p),
                    Ok(t) if t.is_file() => {
                        self.file(&p);
                    }
                    Ok(_) => {}
                    Err(err) => self
                        .errors
                        .push(format!("unreadable:type:{} ({err})", p.display())),
                }
            }
        }
        self
    }
}

/// One hit.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Finding {
    /// Which marker.
    pub marker: String,
    /// Which channel.
    pub channel: String,
    /// Which encoding matched (e.g. `raw`, `base64@1`, `window8(json)@5`).
    pub encoding: String,
}

/// The result of a scan.
#[derive(Debug, Default, Clone)]
pub struct Report {
    /// Every distinct (marker, channel, encoding) hit.
    pub findings: Vec<Finding>,
    /// How many channels were scanned.
    pub channels_scanned: usize,
    /// Capture errors (missing or unreadable files and directories). Any entry fails the report.
    pub capture_errors: Vec<String>,
}

impl Report {
    /// True when no marker was found anywhere **and** every requested file and directory was read.
    pub fn is_clean(&self) -> bool {
        self.findings.is_empty() && self.capture_errors.is_empty()
    }

    /// True if `marker` was found in a channel whose name contains `channel`.
    pub fn found(&self, marker: &str, channel: &str) -> bool {
        self.findings
            .iter()
            .any(|f| f.marker == marker && f.channel.contains(channel))
    }

    /// Panic with a readable report unless clean. Use as the last line of a leak test.
    pub fn assert_clean(&self) {
        assert!(self.is_clean(), "canary leak(s) found:\n{self}");
    }
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_clean() {
            return writeln!(
                f,
                "canary: clean ({} channels scanned)",
                self.channels_scanned
            );
        }
        writeln!(
            f,
            "canary: {} leak(s), {} capture error(s) in {} channels scanned",
            self.findings.len(),
            self.capture_errors.len(),
            self.channels_scanned
        )?;
        for e in &self.capture_errors {
            writeln!(f, "  CAPTURE ERROR {e}")?;
        }
        for x in &self.findings {
            writeln!(
                f,
                "  LEAK marker={} channel={} encoding={}",
                x.marker, x.channel, x.encoding
            )?;
        }
        Ok(())
    }
}

/// A set of markers and the scanner.
#[derive(Debug, Clone)]
pub struct Canary {
    markers: Vec<Marker>,
}

impl Canary {
    /// `ids.len()` fresh markers with those ids.
    pub fn new<S: Into<String>>(ids: impl IntoIterator<Item = S>) -> Self {
        Self {
            markers: ids.into_iter().map(Marker::random).collect(),
        }
    }

    /// The marker with `id`.
    ///
    /// # Panics
    /// If no marker has that id (a bug in the test).
    pub fn get(&self, id: &str) -> &Marker {
        self.markers
            .iter()
            .find(|m| m.id == id)
            .unwrap_or_else(|| panic!("no canary marker named {id}"))
    }

    /// All markers.
    pub fn markers(&self) -> &[Marker] {
        &self.markers
    }

    /// Search every channel for every marker in every encoding.
    pub fn scan(&self, cap: &Capture) -> Report {
        let mut found = BTreeSet::new();
        let prepared: Vec<(&Marker, Vec<(String, String)>)> =
            self.markers.iter().map(|m| (m, m.needles())).collect();
        for ch in &cap.channels {
            let hay = String::from_utf8_lossy(&ch.data);
            for (m, needles) in &prepared {
                for (enc, needle) in needles {
                    if hay.contains(needle.as_str()) {
                        found.insert(Finding {
                            marker: m.id.clone(),
                            channel: ch.name.clone(),
                            encoding: enc.clone(),
                        });
                    }
                }
            }
        }
        Report {
            findings: found.into_iter().collect(),
            channels_scanned: cap.channels.len(),
            capture_errors: cap.errors.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one() -> Canary {
        Canary::new(["m"])
    }

    fn hit(c: &Canary, data: &str) -> Report {
        let mut cap = Capture::new();
        cap.text("t", data);
        c.scan(&cap)
    }

    #[test]
    fn markers_are_unique_and_contain_specials() {
        let c = Canary::new((0..50).map(|i| format!("m{i}")));
        let set: BTreeSet<&str> = c.markers().iter().map(|m| m.value.as_str()).collect();
        assert_eq!(set.len(), 50);
        for m in c.markers() {
            for s in SPECIALS {
                assert!(m.value.contains(s));
            }
        }
    }

    #[test]
    fn finds_raw_and_each_encoding_embedded_in_noise() {
        let c = one();
        let v = c.get("m").value.clone();
        let b = v.as_bytes();
        let cases: Vec<(&str, String)> = vec![
            ("raw", format!("noise {v} noise")),
            (
                "base64",
                format!(
                    "xx{}yy",
                    base64::engine::general_purpose::STANDARD.encode(b)
                ),
            ),
            (
                "base64@1",
                base64::engine::general_purpose::STANDARD
                    .encode([b"A".as_slice(), b, b"tail"].concat()),
            ),
            (
                "base64@2",
                base64::engine::general_purpose::STANDARD
                    .encode([b"AB".as_slice(), b, b"t"].concat()),
            ),
            (
                "base64url",
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode([b"ABC".as_slice(), b].concat()),
            ),
            ("hex", b.iter().map(|x| format!("{x:02x}")).collect()),
            ("HEX", b.iter().map(|x| format!("{x:02X}")).collect()),
            ("url", format!("q={}&x=1", percent_encode(&v, false))),
            ("form-url", format!("password={}", percent_encode(&v, true))),
            ("json", serde_json::json!({"value": v}).to_string()),
            (
                "json-ascii",
                serde_json::to_string(&serde_json::json!({"value": v}))
                    .unwrap_or_default()
                    .replace('é', "\\u00e9"),
            ),
            // Composites: JSON or URL first, then a binary encoding (review round 1).
            (
                "jwt-style base64url(json)",
                format!(
                    "eyJhbGciOiJub25lIn0.{}.",
                    base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .encode(serde_json::json!({"password": v}).to_string())
                ),
            ),
            (
                "hex(json)",
                serde_json::json!({"password": v})
                    .to_string()
                    .bytes()
                    .map(|x| format!("{x:02x}"))
                    .collect(),
            ),
            (
                "base64(json) in a data: URL",
                format!(
                    "data:application/json;base64,{}",
                    base64::engine::general_purpose::STANDARD
                        .encode(serde_json::json!({"k": [1, v]}).to_string())
                ),
            ),
            (
                "base64(form-url)",
                base64::engine::general_purpose::STANDARD
                    .encode(format!("user=a&password={}", percent_encode(&v, true))),
            ),
            (
                "HEX(url)",
                percent_encode(&v, false)
                    .bytes()
                    .map(|x| format!("{x:02X}"))
                    .collect(),
            ),
            (
                "truncated",
                format!("…{}…", v.chars().skip(3).take(12).collect::<String>()),
            ),
        ];
        for (name, data) in cases {
            let r = hit(&c, &data);
            assert!(!r.is_clean(), "encoding {name} was not detected");
        }
    }

    #[test]
    fn clean_text_is_clean() {
        let c = Canary::new(["a", "b"]);
        let r = hit(
            &c,
            "ordinary log line: login ok for alice@example.localhost; status=logged_in; 0123456789abcdef",
        );
        assert!(r.is_clean(), "{r}");
    }

    #[test]
    fn report_names_marker_channel_encoding() {
        let c = Canary::new(["vault.password"]);
        let v = c.get("vault.password").value.clone();
        let mut cap = Capture::new();
        cap.text(
            "mcp:tools/call#1",
            serde_json::json!({"result": v}).to_string(),
        );
        let r = c.scan(&cap);
        assert!(r.findings.iter().any(|f| f.marker == "vault.password"
            && f.channel == "mcp:tools/call#1"
            && f.encoding == "json"));
        assert!(
            r.to_string()
                .contains("LEAK marker=vault.password channel=mcp:tools/call#1")
        );
    }

    #[test]
    fn missing_file_or_dir_fails_the_report() {
        let c = one();
        let mut cap = Capture::new();
        cap.text("stderr", "nothing here")
            .file("/nonexistent/logindesk/audit.jsonl")
            .dir("/nonexistent/logindesk/tmp");
        let r = c.scan(&cap);
        assert!(r.findings.is_empty());
        assert!(!r.is_clean(), "a capture error must not count as clean");
        assert_eq!(r.capture_errors.len(), 2, "{r}");
        let text = r.to_string();
        assert!(text.contains("CAPTURE ERROR missing:file:/nonexistent/logindesk/audit.jsonl"));
        assert!(text.contains("CAPTURE ERROR missing:dir:/nonexistent/logindesk/tmp"));
        assert!(std::panic::catch_unwind(|| r.assert_clean()).is_err());
    }
}
