//! SQLite storage. Knows nothing about cryptography: it stores the header,
//! the sealed manifest and opaque record envelopes.

use std::fs::{self, OpenOptions};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};

use crate::error::{Error, Result};

/// SQLite `application_id` for logindesk vaults ("LDV1").
const APP_ID: i32 = 0x4C44_5631;
/// Schema version (`user_version`).
const SCHEMA_VERSION: i32 = 1;

pub(crate) const META_HEADER: &str = "header";
pub(crate) const META_MANIFEST: &str = "manifest";

/// A raw record row.
pub(crate) struct Row {
    pub id: [u8; 16],
    pub kind: u8,
    pub version: u64,
    pub envelope: Vec<u8>,
}

pub(crate) struct Store {
    conn: Connection,
}

impl core::fmt::Debug for Store {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Store")
    }
}

fn pragmas(conn: &Connection) -> Result<()> {
    conn.pragma_update(None, "secure_delete", "ON")?;
    conn.pragma_update(None, "trusted_schema", "OFF")?;
    Ok(())
}

impl Store {
    /// Creates a new vault file (mode 0600). Refuses to overwrite. Creates a
    /// missing parent directory with mode 0700.
    pub fn create(path: &Path) -> Result<Self> {
        if let Some(parent) = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty() && !p.exists())
        {
            fs::create_dir_all(parent)?;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        }
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    Error::AlreadyExists
                } else {
                    Error::Io(e)
                }
            })?;
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        pragmas(&conn)?;
        conn.execute_batch(&format!(
            "BEGIN;
             PRAGMA application_id = {APP_ID};
             PRAGMA user_version = {SCHEMA_VERSION};
             CREATE TABLE meta (key TEXT PRIMARY KEY, value BLOB NOT NULL) STRICT;
             CREATE TABLE records (
                 id BLOB PRIMARY KEY,
                 kind INTEGER NOT NULL,
                 version INTEGER NOT NULL,
                 envelope BLOB NOT NULL
             ) STRICT;
             COMMIT;"
        ))?;
        Ok(Self { conn })
    }

    /// Opens an existing vault file.
    pub fn open(path: &Path, read_only: bool) -> Result<Self> {
        if !path.exists() {
            return Err(Error::NoVault);
        }
        let mode = if read_only {
            OpenFlags::SQLITE_OPEN_READ_ONLY
        } else {
            OpenFlags::SQLITE_OPEN_READ_WRITE
        };
        let conn = Connection::open_with_flags(path, mode | OpenFlags::SQLITE_OPEN_NO_MUTEX)?;
        let not_vault = |_| Error::Corrupt("not a logindesk vault");
        let app: i32 = conn
            .pragma_query_value(None, "application_id", |r| r.get(0))
            .map_err(not_vault)?;
        let ver: i32 = conn
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .map_err(not_vault)?;
        if app != APP_ID {
            return Err(Error::Corrupt("not a logindesk vault"));
        }
        if ver != SCHEMA_VERSION {
            return Err(Error::Unsupported("schema version"));
        }
        if !read_only {
            pragmas(&conn)?;
        }
        Ok(Self { conn })
    }

    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    /// Starts a write transaction that takes the write lock immediately, so
    /// read-modify-write of the manifest cannot lose an update.
    pub fn write_tx(&mut self) -> Result<Transaction<'_>> {
        Ok(self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?)
    }
}

pub(crate) fn get_meta(conn: &Connection, key: &str) -> Result<Option<Vec<u8>>> {
    Ok(conn
        .query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0))
        .optional()?)
}

pub(crate) fn put_meta(conn: &Connection, key: &str, value: &[u8]) -> Result<()> {
    conn.execute("INSERT INTO meta (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value", params![key, value])?;
    Ok(())
}

fn row_from(id: Vec<u8>, kind: i64, version: i64, envelope: Vec<u8>) -> Result<Row> {
    let id: [u8; 16] = id
        .try_into()
        .map_err(|_| Error::Corrupt("record id length"))?;
    let kind = u8::try_from(kind).map_err(|_| Error::Corrupt("record kind"))?;
    let version = u64::try_from(version).map_err(|_| Error::Corrupt("record version"))?;
    Ok(Row {
        id,
        kind,
        version,
        envelope,
    })
}

pub(crate) fn get_row(conn: &Connection, id: &[u8; 16]) -> Result<Option<Row>> {
    let raw = conn
        .query_row(
            "SELECT id, kind, version, envelope FROM records WHERE id = ?1",
            [&id[..]],
            |r| {
                Ok((
                    r.get::<_, Vec<u8>>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, Vec<u8>>(3)?,
                ))
            },
        )
        .optional()?;
    raw.map(|(a, b, c, d)| row_from(a, b, c, d)).transpose()
}

/// Every row, ordered by id (byte order, same as the manifest).
pub(crate) fn all_rows(conn: &Connection) -> Result<Vec<Row>> {
    let mut stmt = conn.prepare("SELECT id, kind, version, envelope FROM records ORDER BY id")?;
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, Vec<u8>>(0)?,
            r.get::<_, i64>(1)?,
            r.get::<_, i64>(2)?,
            r.get::<_, Vec<u8>>(3)?,
        ))
    })?;
    rows.map(|r| {
        let (a, b, c, d) = r?;
        row_from(a, b, c, d)
    })
    .collect()
}

pub(crate) fn put_row(conn: &Connection, row: &Row) -> Result<()> {
    let version =
        i64::try_from(row.version).map_err(|_| Error::InvalidInput("record version overflow"))?;
    conn.execute(
        "INSERT INTO records (id, kind, version, envelope) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(id) DO UPDATE SET kind = excluded.kind, version = excluded.version, envelope = excluded.envelope",
        params![&row.id[..], row.kind, version, row.envelope],
    )?;
    Ok(())
}

pub(crate) fn delete_row(conn: &Connection, id: &[u8; 16]) -> Result<()> {
    conn.execute("DELETE FROM records WHERE id = ?1", [&id[..]])?;
    Ok(())
}
