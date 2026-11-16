//! Per-site grants: what an agent may do on a site, and whether the user is asked each time.
//!
//! Stored as JSON next to the vault (not secret). Only the CLI writes it; the daemon
//! re-reads it on every request, so `logindesk grant` takes effect at once.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// How a login on a site is approved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    /// The agent logs in on its own. The user granted this once, in a terminal.
    Auto,
    /// Touch ID / Mac password every time.
    Ask,
    /// Never.
    Deny,
}

/// The grants file.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Grants {
    /// registrable domain → login tier.
    #[serde(default)]
    pub login: BTreeMap<String, Tier>,
}

impl Grants {
    /// Default location: `grants.json` beside the vault.
    pub fn path_beside(vault: &Path) -> PathBuf {
        vault.with_file_name("grants.json")
    }

    /// Load; a missing file is empty grants.
    pub fn load(path: &Path) -> io::Result<Self> {
        match std::fs::read(path) {
            Ok(b) => serde_json::from_slice(&b).map_err(io::Error::other),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e),
        }
    }

    /// Save atomically with mode 0600.
    pub fn save(&self, path: &Path) -> io::Result<()> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
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

    /// Tier for a login on `site` (a registrable domain). No grant → Ask.
    pub fn login_tier(&self, site: &str) -> Tier {
        self.login.get(site).copied().unwrap_or(Tier::Ask)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_default() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("grants.json");
        let mut g = Grants::load(&p).unwrap();
        assert_eq!(g.login_tier("example.com"), Tier::Ask);
        g.login.insert("example.com".into(), Tier::Auto);
        g.save(&p).unwrap();
        assert_eq!(
            Grants::load(&p).unwrap().login_tier("example.com"),
            Tier::Auto
        );
    }
}
