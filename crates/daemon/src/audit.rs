//! Append-only, hash-chained audit log (contract §9).
//!
//! One JSON object per line: `{ts, client, op, site, status, reason, prev, hash}`.
//! `hash = sha256(prev || canonical)`, where `canonical` is the line's JSON
//! without the `hash` field, with fields in exactly that order. The first
//! line's `prev` is 64 zeros. Only typed values go in: never a secret, a URL
//! or page text.

use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// `prev` of the first line.
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Longest client name kept in the log.
const CLIENT_MAX: usize = 64;

/// One event, before chaining.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event<'a> {
    /// Declared client name (unverified).
    pub client: &'a str,
    /// Op wire name.
    pub op: &'a str,
    /// Registrable domain, or empty.
    pub site: &'a str,
    /// Status wire tag.
    pub status: &'a str,
    /// Reason wire tag, or empty.
    pub reason: &'a str,
}

/// The hashed part of a line, in canonical field order.
#[derive(Serialize)]
struct Canonical<'a> {
    ts: u64,
    client: &'a str,
    op: &'a str,
    site: &'a str,
    status: &'a str,
    reason: &'a str,
    prev: &'a str,
}

/// A full line as read back.
#[derive(Debug, Deserialize)]
struct Line {
    ts: u64,
    client: String,
    op: String,
    site: String,
    status: String,
    reason: String,
    prev: String,
    hash: String,
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::with_capacity(64), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn chain_hash(prev: &str, canonical: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(prev.as_bytes());
    h.update(canonical);
    hex(&h.finalize())
}

fn clip(s: &str) -> &str {
    match s.char_indices().nth(CLIENT_MAX) {
        Some((i, _)) => &s[..i],
        None => s,
    }
}

/// Why a log failed to verify.
#[derive(Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// Could not read it.
    Io(String),
    /// This 1-based line is malformed, out of chain, or its hash is wrong.
    Broken(usize),
}

/// Check every line's chain and hash. Returns the line count and last hash.
pub fn verify(path: &Path) -> Result<(usize, String), VerifyError> {
    let f = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok((0, GENESIS.to_string())),
        Err(e) => return Err(VerifyError::Io(e.to_string())),
    };
    let mut prev = GENESIS.to_string();
    let mut n = 0;
    for (i, raw) in BufReader::new(f).lines().enumerate() {
        let raw = raw.map_err(|e| VerifyError::Io(e.to_string()))?;
        let l: Line = serde_json::from_str(&raw).map_err(|_| VerifyError::Broken(i + 1))?;
        if l.prev != prev {
            return Err(VerifyError::Broken(i + 1));
        }
        let c = Canonical {
            ts: l.ts,
            client: &l.client,
            op: &l.op,
            site: &l.site,
            status: &l.status,
            reason: &l.reason,
            prev: &l.prev,
        };
        let bytes = serde_json::to_vec(&c).map_err(|_| VerifyError::Broken(i + 1))?;
        let want = chain_hash(&l.prev, &bytes);
        // Re-serialising must reproduce the stored line exactly, so a change in
        // whitespace or field order is also caught.
        let mut expect = bytes;
        expect.pop(); // the closing brace
        let expect = format!("{},\"hash\":\"{want}\"}}", String::from_utf8_lossy(&expect));
        if l.hash != want || raw != expect {
            return Err(VerifyError::Broken(i + 1));
        }
        prev = l.hash;
        n += 1;
    }
    Ok((n, prev))
}

/// The open log.
#[derive(Debug)]
pub struct Audit {
    path: PathBuf,
    file: File,
    prev: String,
}

impl Audit {
    /// Open (or create, mode 0600) the log and continue its chain. A broken
    /// chain is reported on stderr and continued from its last line, so the
    /// break stays visible to `verify`.
    pub fn open(path: &Path) -> io::Result<Self> {
        let prev = match verify(path) {
            Ok((_, last)) => last,
            Err(e) => {
                eprintln!(
                    "logindesk: WARNING: audit log {} does not verify: {e:?}",
                    path.display()
                );
                last_hash(path)?.unwrap_or_else(|| GENESIS.to_string())
            }
        };
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(path)?;
        Ok(Self {
            path: path.to_owned(),
            file,
            prev,
        })
    }

    /// Where it lives.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append one event.
    pub fn record(&mut self, ev: &Event<'_>) -> io::Result<()> {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let c = Canonical {
            ts,
            client: clip(ev.client),
            op: ev.op,
            site: ev.site,
            status: ev.status,
            reason: ev.reason,
            prev: &self.prev,
        };
        let mut bytes = serde_json::to_vec(&c).map_err(io::Error::other)?;
        let hash = chain_hash(&self.prev, &bytes);
        bytes.pop();
        bytes.extend_from_slice(format!(",\"hash\":\"{hash}\"}}\n").as_bytes());
        self.file.write_all(&bytes)?;
        self.file.sync_data()?;
        self.prev = hash;
        Ok(())
    }
}

fn last_hash(path: &Path) -> io::Result<Option<String>> {
    let f = File::open(path)?;
    let mut last = None;
    for raw in BufReader::new(f).lines() {
        if let Ok(l) = serde_json::from_str::<Line>(&raw?) {
            last = Some(l.hash);
        }
    }
    Ok(last)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("ld-audit-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d.join("audit.jsonl")
    }

    fn ev<'a>(site: &'a str, status: &'a str) -> Event<'a> {
        Event {
            client: "claude-code",
            op: "login",
            site,
            status,
            reason: "",
        }
    }

    #[test]
    fn chain_verifies_and_edits_break_it() {
        let p = tmp("chain");
        {
            let mut a = Audit::open(&p).unwrap();
            a.record(&ev("example.com", "logged_in")).unwrap();
            a.record(&ev("example.org", "denied")).unwrap();
        }
        // Reopen continues the same chain.
        {
            let mut a = Audit::open(&p).unwrap();
            a.record(&ev("example.net", "failed")).unwrap();
        }
        let (n, _) = verify(&p).unwrap();
        assert_eq!(n, 3);
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let good = std::fs::read_to_string(&p).unwrap();
        // Edit a field in the middle line.
        let bad = good.replacen("\"site\":\"example.org\"", "\"site\":\"evil.org\"", 1);
        std::fs::write(&p, &bad).unwrap();
        assert_eq!(verify(&p), Err(VerifyError::Broken(2)));
        // Delete the first line.
        let lines: Vec<&str> = good.lines().collect();
        std::fs::write(&p, format!("{}\n{}\n", lines[1], lines[2])).unwrap();
        assert_eq!(verify(&p), Err(VerifyError::Broken(1)));
        // Swap two lines.
        std::fs::write(&p, format!("{}\n{}\n{}\n", lines[0], lines[2], lines[1])).unwrap();
        assert_eq!(verify(&p), Err(VerifyError::Broken(2)));
        // An edited line whose own hash is recomputed still breaks the next link.
        let l: Line = serde_json::from_str(lines[1]).unwrap();
        let c = Canonical {
            ts: l.ts,
            client: &l.client,
            op: &l.op,
            site: "evil.org",
            status: &l.status,
            reason: &l.reason,
            prev: &l.prev,
        };
        let mut forged = serde_json::to_vec(&c).unwrap();
        let h = chain_hash(&l.prev, &forged);
        forged.pop();
        let forged = format!("{},\"hash\":\"{h}\"}}", String::from_utf8(forged).unwrap());
        std::fs::write(&p, format!("{}\n{forged}\n{}\n", lines[0], lines[2])).unwrap();
        assert_eq!(verify(&p), Err(VerifyError::Broken(3)));
        std::fs::write(&p, &good).unwrap();
        assert!(verify(&p).is_ok());
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }

    #[test]
    fn client_name_is_clipped() {
        assert_eq!(clip(&"x".repeat(100)).len(), CLIENT_MAX);
        assert_eq!(clip("short"), "short");
    }
}
