//! `<data dir>/identity.json`: who signups are made as (not secret).
//! Written by `logindesk identity set`; re-read on every signup.

use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// The signup identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    /// Default email; signups use its plus-address per site.
    pub email: String,
    /// Full name, filled when a form asks for one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

impl Identity {
    /// `identity.json` in the data dir.
    pub fn path(data_dir: &Path) -> PathBuf {
        data_dir.join("identity.json")
    }

    /// Load; missing file → `None`.
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
        if !valid_email(&self.email) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not an email address",
            ));
        }
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
}

/// One `@`, a non-empty local part, a dotted domain, no spaces.
pub fn valid_email(e: &str) -> bool {
    let Some((local, domain)) = e.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !e.contains(char::is_whitespace)
        && !domain.contains('@')
}

/// `you@x.com` → `you+<label>@x.com`, where `label` is the first label of the
/// site's registrable domain (`[a-z0-9-]` only). An address that already has
/// a `+` tag is returned unchanged.
pub fn plus_address(email: &str, site: &str) -> String {
    let Some((local, domain)) = email.split_once('@') else {
        return email.to_string();
    };
    let label: String = site
        .split('.')
        .next()
        .unwrap_or("")
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .collect::<String>()
        .to_ascii_lowercase();
    if local.contains('+') || label.is_empty() {
        return email.to_string();
    }
    format!("{local}+{label}@{domain}")
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn plus_addresses() {
        assert_eq!(
            plus_address("you@gmail.com", "github.com"),
            "you+github@gmail.com"
        );
        assert_eq!(
            plus_address("you@x.test", "example.localhost"),
            "you+example@x.test"
        );
        assert_eq!(plus_address("you+tag@x.com", "github.com"), "you+tag@x.com");
        assert_eq!(plus_address("bad", "github.com"), "bad");
    }

    #[test]
    fn emails() {
        assert!(valid_email("a@b.co"));
        for bad in ["", "a", "a@b", "@b.co", "a@.co", "a b@c.co", "a@b@c.co"] {
            assert!(!valid_email(bad), "{bad}");
        }
    }

    #[test]
    fn round_trip() {
        let d = std::env::temp_dir().join(format!("ld-ident-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        assert_eq!(Identity::load(&d).unwrap(), None);
        let i = Identity {
            email: "you@x.test".into(),
            name: Some("Ann Example".into()),
        };
        i.save(&d).unwrap();
        assert_eq!(Identity::load(&d).unwrap(), Some(i));
        let bad = Identity {
            email: "nope".into(),
            name: None,
        };
        assert!(bad.save(&d).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }
}
