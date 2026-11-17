//! Vault errors. No variant ever carries secret material or record content.

use core::fmt;

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, Error>;

/// Everything that can go wrong in the vault. Messages are safe to show to
/// the user and to log: they never contain a secret or record content.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The password did not unlock the vault (or the header was modified).
    WrongPassword,
    /// The operation needs an unlocked vault.
    Locked,
    /// No record with that id.
    NotFound,
    /// The vault file already exists.
    AlreadyExists,
    /// The vault file does not exist.
    NoVault,
    /// Authenticated data did not verify: the file was modified, a record was
    /// swapped, replayed, injected or deleted. Fails closed.
    Tampered(&'static str),
    /// The file is not a valid logindesk vault (bad structure or lengths).
    Corrupt(&'static str),
    /// A newer or unknown format version.
    Unsupported(&'static str),
    /// A caller-supplied value was rejected.
    InvalidInput(&'static str),
    /// A CSV import or export problem, with the 1-based line when known.
    Csv {
        line: Option<u64>,
        reason: &'static str,
    },
    /// The OS random number generator failed.
    Rng,
    /// File system error.
    Io(std::io::Error),
    /// SQLite error.
    Db(rusqlite::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongPassword => {
                f.write_str("wrong vault password (or the vault header was modified)")
            }
            Self::Locked => f.write_str("the vault is locked"),
            Self::NotFound => f.write_str("no such record"),
            Self::AlreadyExists => f.write_str("a vault already exists at that path"),
            Self::NoVault => f.write_str("no vault found; run `logindesk setup` first"),
            Self::Tampered(what) => write!(f, "vault integrity check failed: {what}"),
            Self::Corrupt(what) => write!(f, "vault file is corrupt: {what}"),
            Self::Unsupported(what) => write!(f, "unsupported vault format: {what}"),
            Self::InvalidInput(what) => write!(f, "invalid input: {what}"),
            Self::Csv {
                line: Some(l),
                reason,
            } => write!(f, "CSV line {l}: {reason}"),
            Self::Csv { line: None, reason } => write!(f, "CSV: {reason}"),
            Self::Rng => f.write_str("the OS random number generator failed"),
            Self::Io(e) => write!(f, "file error: {e}"),
            Self::Db(e) => write!(f, "database error: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Db(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        Self::Db(e)
    }
}
