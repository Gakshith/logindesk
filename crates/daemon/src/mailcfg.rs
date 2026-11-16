//! `<data dir>/mail.json`: which mailbox the daemon reads emailed codes from.
//! Not secret (a kind and a local URL). The CLI writes it; the daemon re-reads
//! it on every login, so `logindesk mail set` takes effect at once.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use logindesk_mail::{MailSource, MailpitSource};
use serde::{Deserialize, Serialize};

/// Mailbox kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MailKind {
    /// Mailpit's HTTP API.
    Mailpit,
    /// The test bed's outbox endpoint.
    Outbox,
}

/// The file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MailConfig {
    /// Kind.
    pub kind: MailKind,
    /// Base URL, e.g. `http://127.0.0.1:8025`.
    pub url: String,
}

impl MailConfig {
    /// `mail.json` in the data dir.
    pub fn path(data_dir: &Path) -> PathBuf {
        data_dir.join("mail.json")
    }

    /// Load; a missing file is `None` (no mailbox).
    pub fn load(data_dir: &Path) -> io::Result<Option<Self>> {
        match std::fs::read(Self::path(data_dir)) {
            Ok(b) => serde_json::from_slice(&b)
                .map(Some)
                .map_err(io::Error::other),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Save atomically with mode 0600.
    pub fn save(&self, data_dir: &Path) -> io::Result<()> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let path = Self::path(data_dir);
        let tmp = path.with_extension("json.tmp");
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(&serde_json::to_vec_pretty(self).map_err(io::Error::other)?)?;
        f.sync_all()?;
        std::fs::rename(tmp, path)
    }

    /// Remove the file (no mailbox).
    pub fn remove(data_dir: &Path) -> io::Result<()> {
        match std::fs::remove_file(Self::path(data_dir)) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        }
    }

    /// The mailbox this config names.
    pub fn source(&self) -> Option<Arc<dyn MailSource>> {
        match self.kind {
            MailKind::Mailpit => Some(Arc::new(MailpitSource {
                base_url: self.url.clone(),
            })),
            // LANE-MAIL adds `OutboxSource { base_url }`; it is not in the frozen
            // stub this lane builds against. Wire it here after the merge.
            MailKind::Outbox => {
                eprintln!("logindesk: the outbox mail source is not in this build yet");
                None
            }
        }
    }
}

/// Where the broker gets its mailbox for one login.
pub trait MailProvider: Send + Sync {
    /// The configured mailbox, or `None`.
    fn current(&self) -> Option<Arc<dyn MailSource>>;
}

/// Reads `mail.json` from the data dir each time.
#[derive(Debug, Clone)]
pub struct FileMail(pub PathBuf);

impl MailProvider for FileMail {
    fn current(&self) -> Option<Arc<dyn MailSource>> {
        match MailConfig::load(&self.0) {
            Ok(Some(c)) => c.source(),
            Ok(None) => None,
            Err(e) => {
                eprintln!("logindesk: mail.json unreadable ({e}); treating email as not connected");
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn round_trip() {
        let d = std::env::temp_dir().join(format!("ld-mailcfg-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        assert_eq!(MailConfig::load(&d).unwrap(), None);
        let c = MailConfig {
            kind: MailKind::Mailpit,
            url: "http://127.0.0.1:8025".into(),
        };
        c.save(&d).unwrap();
        assert_eq!(MailConfig::load(&d).unwrap(), Some(c));
        let raw = std::fs::read_to_string(MailConfig::path(&d)).unwrap();
        assert!(raw.contains("\"kind\": \"mailpit\""));
        assert!(FileMail(d.clone()).current().is_some());
        MailConfig::remove(&d).unwrap();
        MailConfig::remove(&d).unwrap();
        assert!(FileMail(d.clone()).current().is_none());
        let _ = std::fs::remove_dir_all(&d);
    }
}
