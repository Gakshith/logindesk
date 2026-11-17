//! Record types.

use core::fmt;
use core::str::FromStr;

use logindesk_core::SecretString;

use crate::error::Error;

/// A random 128-bit record id, shown as 32 lowercase hex characters.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecordId(pub(crate) [u8; 16]);

impl RecordId {
    /// The raw bytes.
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Display for RecordId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|b| write!(f, "{b:02x}"))
    }
}

impl fmt::Debug for RecordId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RecordId({self})")
    }
}

impl FromStr for RecordId {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Error> {
        let bad = Error::InvalidInput("a record id is 32 hex characters");
        if s.len() != 32 || !s.is_ascii() {
            return Err(bad);
        }
        let mut out = [0u8; 16];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16)
                .map_err(|_| Error::InvalidInput("a record id is 32 hex characters"))?;
        }
        Ok(Self(out))
    }
}

/// What a record holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RecordKind {
    /// A website login (username + password).
    Login,
    /// An API key or token captured from a site.
    ApiKey,
    /// Credentials for a mail source (IMAP app password, Gmail refresh token).
    MailCredential,
    /// A secret note.
    Note,
}

impl RecordKind {
    /// Stable on-disk code.
    pub fn code(self) -> u8 {
        match self {
            Self::Login => 1,
            Self::ApiKey => 2,
            Self::MailCredential => 3,
            Self::Note => 4,
        }
    }

    /// Inverse of [`Self::code`].
    pub fn from_code(c: u8) -> Option<Self> {
        Some(match c {
            1 => Self::Login,
            2 => Self::ApiKey,
            3 => Self::MailCredential,
            4 => Self::Note,
            _ => return None,
        })
    }

    /// CLI name.
    pub fn name(self) -> &'static str {
        match self {
            Self::Login => "login",
            Self::ApiKey => "api-key",
            Self::MailCredential => "mail",
            Self::Note => "note",
        }
    }
}

impl FromStr for RecordKind {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Error> {
        match s {
            "login" => Ok(Self::Login),
            "api-key" => Ok(Self::ApiKey),
            "mail" => Ok(Self::MailCredential),
            "note" => Ok(Self::Note),
            _ => Err(Error::InvalidInput(
                "kind must be login, api-key, mail or note",
            )),
        }
    }
}

impl fmt::Display for RecordKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Input for [`crate::Vault::add`].
#[derive(Debug)]
pub struct NewRecord {
    /// Kind.
    pub kind: RecordKind,
    /// Site (as entered).
    pub site: String,
    /// Username or email.
    pub username: String,
    /// The secret.
    pub secret: SecretString,
    /// Who created it (e.g. "cli", "import").
    pub created_by: String,
    /// Non-secret notes.
    pub notes: String,
}

/// Everything about a record except the secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordMeta {
    /// Id.
    pub id: RecordId,
    /// Kind.
    pub kind: RecordKind,
    /// Version, +1 per write.
    pub version: u64,
    /// Site.
    pub site: String,
    /// Username or email.
    pub username: String,
    /// Creator.
    pub created_by: String,
    /// Notes.
    pub notes: String,
    /// Unix seconds.
    pub created_at: u64,
    /// Unix seconds.
    pub updated_at: u64,
}

/// A decrypted record. `Debug` redacts the secret.
#[derive(Debug)]
pub struct Record {
    /// Metadata.
    pub meta: RecordMeta,
    /// The secret.
    pub secret: SecretString,
}
