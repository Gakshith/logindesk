//! Shared helpers for the vault integration tests.
#![allow(clippy::unwrap_used)] // test code: a panic is a test failure
#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use logindesk_core::SecretString;
use logindesk_vault::{KdfParams, Keys, NewRecord, RecordKind, Vault};

/// A unique temp directory, removed on drop.
pub struct TempDir(pub PathBuf);

impl TempDir {
    pub fn new(tag: &str) -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        let p = std::env::temp_dir().join(format!(
            "logindesk-test-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
    pub fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub fn pw(s: &str) -> SecretString {
    SecretString::new(s.to_owned())
}

/// Test vaults use the OWASP minimum so the suite stays fast.
pub fn new_vault(dir: &TempDir) -> (Vault, Keys) {
    Vault::create(
        &dir.path("vault.sqlite"),
        &pw("correct horse battery"),
        KdfParams::MIN,
    )
    .unwrap()
}

pub fn login(site: &str, user: &str, secret: &str) -> NewRecord {
    NewRecord {
        kind: RecordKind::Login,
        site: site.into(),
        username: user.into(),
        secret: SecretString::new(secret.into()),
        created_by: "test".into(),
        notes: String::new(),
    }
}
