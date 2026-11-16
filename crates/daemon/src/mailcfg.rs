//! `<data dir>/mail.json`: which mailbox the daemon reads emailed codes from.
//! Not secret (a kind and a URL). The CLI writes it; the daemon re-reads it on
//! every login, so `logindesk mail set` takes effect at once.
//!
//! Gmail and IMAP also need secrets, which live in the vault as `mail` records
//! (see [`MailCreds`]). The daemon reads them once at start, so after
//! `logindesk connect gmail|imap` the daemon must be restarted.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use logindesk_mail::{
    GOOGLE_TOKEN_URL, GmailAuth, GmailRestSource, ImapAuth, ImapSource, MailSource, MailpitSource,
    OutboxSource,
};
use logindesk_vault::{Keys, NewRecord, RecordKind, Vault};
use serde::{Deserialize, Serialize};

/// Mailbox kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MailKind {
    /// Mailpit's HTTP API.
    Mailpit,
    /// The test bed's outbox endpoint.
    Outbox,
    /// Gmail REST with an OAuth refresh token (`logindesk connect gmail`).
    Gmail,
    /// IMAP over TLS with an app password (`logindesk connect imap`).
    Imap,
}

/// The file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MailConfig {
    /// Kind.
    pub kind: MailKind,
    /// Base URL, e.g. `http://127.0.0.1:8025`. Gmail: empty for Google's API.
    /// IMAP: `imaps://<user>@<host>:<port>`.
    #[serde(default)]
    pub url: String,
}

/// `site` of the vault records `connect gmail` writes.
pub const GMAIL_RECORD_SITE: &str = "gmail.oauth";
/// `site` of the vault record `connect imap` writes.
pub const IMAP_RECORD_SITE: &str = "imap.login";
/// `notes` of the Gmail refresh-token record.
pub const NOTE_REFRESH: &str = "refresh_token";
/// `notes` of the Gmail client-secret record.
pub const NOTE_CLIENT_SECRET: &str = "client_secret";

/// Mailbox secrets from the vault, shared by every source the daemon builds.
#[derive(Debug, Clone, Default)]
pub struct MailCreds {
    /// From `connect gmail`.
    pub gmail: Option<Arc<GmailAuth>>,
    /// From `connect imap`.
    pub imap: Option<Arc<ImapAuth>>,
}

impl MailCreds {
    /// Read the `mail` records `connect` wrote. Missing or unreadable → empty.
    pub fn from_vault(vault: &Vault, keys: &Keys) -> Self {
        let Ok(records) = vault.records(keys) else {
            return Self::default();
        };
        let mut out = Self::default();
        let (mut refresh, mut secret, mut client_id) = (None, None, String::new());
        for r in records {
            if r.meta.kind != RecordKind::MailCredential {
                continue;
            }
            match (r.meta.site.as_str(), r.meta.notes.as_str()) {
                (GMAIL_RECORD_SITE, NOTE_REFRESH) => {
                    client_id = r.meta.username.clone();
                    refresh = Some(r.secret);
                }
                (GMAIL_RECORD_SITE, NOTE_CLIENT_SECRET) => secret = Some(r.secret),
                (IMAP_RECORD_SITE, _) => {
                    out.imap = Some(Arc::new(ImapAuth::new(r.meta.username.clone(), r.secret)));
                }
                _ => {}
            }
        }
        if let (Some(refresh), Some(secret)) = (refresh, secret) {
            out.gmail = Some(Arc::new(GmailAuth::new(client_id, secret, refresh)));
        }
        out
    }

    /// Delete every record `connect` wrote (both kinds). Returns how many.
    pub fn remove_from_vault(vault: &mut Vault, keys: &Keys) -> logindesk_vault::Result<usize> {
        let ids: Vec<_> = vault
            .list(keys)?
            .into_iter()
            .filter(|m| {
                m.kind == RecordKind::MailCredential
                    && (m.site == GMAIL_RECORD_SITE || m.site == IMAP_RECORD_SITE)
            })
            .map(|m| m.id)
            .collect();
        for id in &ids {
            vault.delete(keys, *id)?;
        }
        Ok(ids.len())
    }

    /// A `mail` record for [`Self::from_vault`] to find.
    pub fn record(
        site: &str,
        username: &str,
        notes: &str,
        secret: logindesk_core::SecretString,
    ) -> NewRecord {
        NewRecord {
            kind: RecordKind::MailCredential,
            site: site.into(),
            username: username.into(),
            secret,
            created_by: "connect".into(),
            notes: notes.into(),
        }
    }
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

    /// The mailbox this config names. Gmail/IMAP without vault credentials → `None`.
    pub fn source(&self, creds: &MailCreds) -> Option<Arc<dyn MailSource>> {
        match self.kind {
            MailKind::Mailpit => Some(Arc::new(MailpitSource {
                base_url: self.url.clone(),
            })),
            MailKind::Outbox => Some(Arc::new(OutboxSource {
                base_url: self.url.clone(),
            })),
            MailKind::Gmail => {
                let auth = creds.gmail.clone()?;
                let mut src = GmailRestSource::new(auth);
                if !self.url.is_empty() {
                    // A test mock serves both the API and the token endpoint.
                    src.api_base = self.url.clone();
                    src.token_url = format!("{}/token", self.url.trim_end_matches('/'));
                } else {
                    src.token_url = GOOGLE_TOKEN_URL.into();
                }
                Some(Arc::new(src))
            }
            MailKind::Imap => {
                let auth = creds.imap.clone()?;
                let (host, port) = imap_host(&self.url)?;
                Some(Arc::new(ImapSource::new(host, port, auth)))
            }
        }
    }
}

/// Where the broker gets its mailbox for one login.
pub trait MailProvider: Send + Sync {
    /// The configured mailbox, or `None`.
    fn current(&self) -> Option<Arc<dyn MailSource>>;
}

/// `imaps://user@host:port` → (host, port). Port defaults to 993.
pub fn imap_host(url: &str) -> Option<(String, u16)> {
    let u = url::Url::parse(url).ok()?;
    if u.scheme() != "imaps" {
        return None;
    }
    Some((u.host_str()?.to_string(), u.port().unwrap_or(993)))
}

/// Reads `mail.json` from the data dir each time; secrets come from the vault at start.
#[derive(Debug, Clone)]
pub struct FileMail(pub PathBuf, pub MailCreds);

impl MailProvider for FileMail {
    fn current(&self) -> Option<Arc<dyn MailSource>> {
        match MailConfig::load(&self.0) {
            Ok(Some(c)) => c.source(&self.1),
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
        assert!(
            FileMail(d.clone(), MailCreds::default())
                .current()
                .is_some()
        );
        MailConfig::remove(&d).unwrap();
        MailConfig::remove(&d).unwrap();
        assert!(
            FileMail(d.clone(), MailCreds::default())
                .current()
                .is_none()
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn gmail_and_imap_need_vault_creds() {
        let g: MailConfig = serde_json::from_str(r#"{"kind":"gmail"}"#).unwrap();
        assert_eq!(g.kind, MailKind::Gmail);
        assert!(g.source(&MailCreds::default()).is_none());
        let i = MailConfig {
            kind: MailKind::Imap,
            url: "imaps://me%40mail.test@imap.mail.me.com:993".into(),
        };
        assert!(i.source(&MailCreds::default()).is_none());
        assert_eq!(imap_host(&i.url), Some(("imap.mail.me.com".into(), 993)));
        assert_eq!(imap_host("http://x"), None);
    }

    #[test]
    fn creds_round_trip_through_the_vault() {
        let d = std::env::temp_dir().join(format!("ld-mailcreds-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let pw = logindesk_core::SecretString::new("correct horse battery".into());
        let (mut v, k) =
            Vault::create(&d.join("v.db"), &pw, logindesk_vault::KdfParams::MIN).unwrap();
        let s = |x: &str| logindesk_core::SecretString::new(x.into());
        v.add(
            &k,
            MailCreds::record(GMAIL_RECORD_SITE, "cid", NOTE_REFRESH, s("rt")),
        )
        .unwrap();
        v.add(
            &k,
            MailCreds::record(GMAIL_RECORD_SITE, "cid", NOTE_CLIENT_SECRET, s("cs")),
        )
        .unwrap();
        v.add(
            &k,
            MailCreds::record(
                IMAP_RECORD_SITE,
                "me@mail.test",
                "imap.mail.me.com",
                s("ap"),
            ),
        )
        .unwrap();
        let c = MailCreds::from_vault(&v, &k);
        assert_eq!(c.gmail.as_ref().unwrap().client_id, "cid");
        assert_eq!(c.imap.as_ref().unwrap().user, "me@mail.test");
        let g = MailConfig {
            kind: MailKind::Gmail,
            url: String::new(),
        };
        assert!(g.source(&c).is_some());
        assert_eq!(MailCreds::remove_from_vault(&mut v, &k).unwrap(), 3);
        assert!(MailCreds::from_vault(&v, &k).gmail.is_none());
        let _ = std::fs::remove_dir_all(&d);
    }
}
