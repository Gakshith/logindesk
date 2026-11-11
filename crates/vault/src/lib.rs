//! logindesk-vault: the encrypted local vault.
//!
//! - One SQLite file. Every record is encrypted; nothing about a record
//!   (site, username, kind label, notes) is stored in the clear except its
//!   random id, a kind number and a version number.
//! - Key: Argon2id(vault password, salt) → HKDF-SHA256 subkeys.
//! - Records: XChaCha20-Poly1305 under a fresh per-record DEK, which is
//!   itself wrapped by the vault KEK. Associated data is
//!   `record_id | kind | version`.
//! - An encrypted manifest lists every record's `(id, kind, version)`, so a
//!   swapped, replayed, injected or deleted record fails closed.
//!
//! See `docs/crypto-spec.md` for the full specification.
#![deny(unsafe_code)]

mod crypto;
mod csv_io;
mod error;
pub mod format;
// The ONLY module in the workspace allowed to use `unsafe`: page-locked key
// memory (mlock), core-dump suppression (setrlimit) and PT_DENY_ATTACH.
// Every block carries a `// SAFETY:` justification.
#[allow(unsafe_code)]
pub mod hardening;
mod keys;
mod record;
mod session;
mod store;
mod vault;

pub use csv_io::{ImportRow, parse_import_csv, write_plaintext_csv};
pub use error::{Error, Result};
pub use format::KdfParams;
pub use keys::Keys;
pub use record::{NewRecord, Record, RecordId, RecordKind, RecordMeta};
pub use session::{AUTO_LOCK_AFTER, Clock, ManualClock, SystemClock, Timestamp, VaultSession};
pub use vault::Vault;
