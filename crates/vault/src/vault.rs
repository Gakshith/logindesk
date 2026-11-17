//! The vault: create, open, unlock, and record operations.

use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use logindesk_core::SecretString;
use rusqlite::Connection;
use zeroize::Zeroizing;

use crate::crypto::{open, random, seal};
use crate::error::{Error, Result};
use crate::format::{
    Envelope, Header, KEY_LEN, KdfParams, MAX_MANIFEST_CT, Manifest, ManifestEntry, PayloadFields,
    SALT_LEN, Sealed, WRAPPED_DEK_LEN, decode_payload, encode_payload,
};
use crate::keys::Keys;
use crate::record::{NewRecord, Record, RecordId, RecordKind, RecordMeta};
use crate::store::{self, META_HEADER, META_MANIFEST, Row, Store};

/// Fixed plaintext of the key-check value.
const CHECK_PLAINTEXT: &[u8] = b"logindesk key check v1";
/// Associated data of the sealed manifest.
const MANIFEST_AD: &[u8] = b"logindesk/v1/manifest";
/// Domain prefix for the DEK-wrap associated data.
const WRAP_AD_PREFIX: &[u8] = b"logindesk/v1/dek|";

/// Associated data for a record body: `record_id(16) | kind(1) | version(u64 BE)`.
pub(crate) fn record_ad(e: &ManifestEntry) -> [u8; 25] {
    let mut ad = [0u8; 25];
    ad[..16].copy_from_slice(&e.id);
    ad[16] = e.kind;
    ad[17..].copy_from_slice(&e.version.to_be_bytes());
    ad
}

fn wrap_ad(e: &ManifestEntry) -> Vec<u8> {
    let mut ad = WRAP_AD_PREFIX.to_vec();
    ad.extend_from_slice(&record_ad(e));
    ad
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// An open vault file. Holding a `Vault` reveals nothing; every record
/// operation needs the [`Keys`] from [`Vault::unlock`].
#[derive(Debug)]
pub struct Vault {
    store: Store,
    header: Header,
    path: PathBuf,
}

impl Vault {
    /// Creates a new vault at `path` (mode 0600; refuses to overwrite) and
    /// returns it unlocked.
    pub fn create(path: &Path, password: &SecretString, params: KdfParams) -> Result<(Self, Keys)> {
        if password.expose().is_empty() {
            return Err(Error::InvalidInput("the vault password must not be empty"));
        }
        let params = params.validate()?;
        let salt: [u8; SALT_LEN] = random()?;
        let keys = Keys::derive(password.expose().as_bytes(), params, &salt)?;
        let prefix = Header::encode_prefix(params, &salt);
        let check = seal(keys.check(), &prefix, CHECK_PLAINTEXT)?;
        let header = Header {
            params,
            salt,
            check,
        };
        let mut store = Store::create(path)?;
        {
            let tx = store.write_tx()?;
            store::put_meta(&tx, META_HEADER, &header.encode())?;
            write_manifest(&tx, &keys, &Manifest::default())?;
            tx.commit()?;
        }
        Ok((
            Self {
                store,
                header,
                path: path.to_owned(),
            },
            keys,
        ))
    }

    /// Opens an existing vault file without unlocking it.
    pub fn open(path: &Path) -> Result<Self> {
        Self::open_with(path, false)
    }

    /// Opens read-only (used by the fuzzer and by checks).
    pub fn open_read_only(path: &Path) -> Result<Self> {
        Self::open_with(path, true)
    }

    fn open_with(path: &Path, read_only: bool) -> Result<Self> {
        let store = Store::open(path, read_only)?;
        let bytes =
            store::get_meta(store.conn(), META_HEADER)?.ok_or(Error::Corrupt("header missing"))?;
        let header = Header::decode(&bytes)?;
        Ok(Self {
            store,
            header,
            path: path.to_owned(),
        })
    }

    /// The file this vault lives in.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The Argon2id parameters of this vault.
    pub fn kdf_params(&self) -> KdfParams {
        self.header.params
    }

    /// Unlocks the vault. Always runs the full Argon2id derivation before
    /// checking the key, so a wrong password costs exactly the same work as
    /// a right one; the check itself is a constant-time AEAD tag comparison.
    pub fn unlock(&self, password: &SecretString) -> Result<Keys> {
        let keys = Keys::derive(
            password.expose().as_bytes(),
            self.header.params,
            &self.header.salt,
        )?;
        let prefix = Header::encode_prefix(self.header.params, &self.header.salt);
        match open(keys.check(), &prefix, &self.header.check)? {
            Some(pt) if pt.as_slice() == CHECK_PLAINTEXT => {}
            _ => return Err(Error::WrongPassword),
        }
        // The manifest must authenticate under the same password.
        read_manifest(self.store.conn(), &keys)?;
        Ok(keys)
    }

    /// Adds a record and returns its new id.
    pub fn add(&mut self, keys: &Keys, new: NewRecord) -> Result<RecordId> {
        if new.site.trim().is_empty() {
            return Err(Error::InvalidInput("site must not be empty"));
        }
        let id = RecordId(random()?);
        let now = now_unix();
        let fields = PayloadFields {
            created_at: now,
            updated_at: now,
            site: new.site,
            username: new.username,
            created_by: new.created_by,
            notes: new.notes,
        };
        let tx = self.store.write_tx()?;
        let mut manifest = read_manifest(&tx, keys)?;
        if manifest.get(&id.0).is_some() || store::get_row(&tx, &id.0)?.is_some() {
            return Err(Error::Rng); // a 128-bit random collision means the RNG is broken
        }
        let entry = ManifestEntry {
            id: id.0,
            kind: new.kind.code(),
            version: 1,
        };
        write_record(
            &tx,
            keys,
            &mut manifest,
            entry,
            &fields,
            new.secret.expose().as_bytes(),
        )?;
        tx.commit()?;
        Ok(id)
    }

    /// Replaces a record's secret (its version goes up by one).
    pub fn update_secret(&mut self, keys: &Keys, id: RecordId, secret: SecretString) -> Result<()> {
        let tx = self.store.write_tx()?;
        let mut manifest = read_manifest(&tx, keys)?;
        let old = read_record(&tx, keys, &manifest, &id.0)?;
        let entry = ManifestEntry {
            id: id.0,
            kind: old.meta.kind.code(),
            version: old.meta.version + 1,
        };
        let fields = PayloadFields {
            created_at: old.meta.created_at,
            updated_at: now_unix(),
            site: old.meta.site,
            username: old.meta.username,
            created_by: old.meta.created_by,
            notes: old.meta.notes,
        };
        write_record(
            &tx,
            keys,
            &mut manifest,
            entry,
            &fields,
            secret.expose().as_bytes(),
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Replaces a record's username and/or notes, keeping its secret (version +1).
    /// Used by signup: a record is stored `pending` before submit, then marked active.
    pub fn update_meta(
        &mut self,
        keys: &Keys,
        id: RecordId,
        username: Option<String>,
        notes: Option<String>,
    ) -> Result<()> {
        let tx = self.store.write_tx()?;
        let mut manifest = read_manifest(&tx, keys)?;
        let old = read_record(&tx, keys, &manifest, &id.0)?;
        let entry = ManifestEntry {
            id: id.0,
            kind: old.meta.kind.code(),
            version: old.meta.version + 1,
        };
        let fields = PayloadFields {
            created_at: old.meta.created_at,
            updated_at: now_unix(),
            site: old.meta.site,
            username: username.unwrap_or(old.meta.username),
            created_by: old.meta.created_by,
            notes: notes.unwrap_or(old.meta.notes),
        };
        write_record(
            &tx,
            keys,
            &mut manifest,
            entry,
            &fields,
            old.secret.expose().as_bytes(),
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Reads and decrypts one record.
    pub fn get(&self, keys: &Keys, id: RecordId) -> Result<Record> {
        let conn = self.store.conn();
        let manifest = read_manifest(conn, keys)?;
        read_record(conn, keys, &manifest, &id.0)
    }

    /// Lists every record's metadata (no secrets). Verifies the whole vault:
    /// every row must match the manifest exactly and authenticate.
    pub fn list(&self, keys: &Keys) -> Result<Vec<RecordMeta>> {
        Ok(self.records(keys)?.into_iter().map(|r| r.meta).collect())
    }

    /// Every record, decrypted, after the same full verification as [`Self::list`].
    pub fn records(&self, keys: &Keys) -> Result<Vec<Record>> {
        let conn = self.store.conn();
        let manifest = read_manifest(conn, keys)?;
        let rows = store::all_rows(conn)?;
        if rows.len() != manifest.entries.len() {
            return Err(Error::Tampered(
                "records and manifest disagree (injected or deleted record)",
            ));
        }
        rows.iter()
            .zip(&manifest.entries)
            .map(|(row, e)| {
                if row.id != e.id {
                    return Err(Error::Tampered(
                        "records and manifest disagree (injected or deleted record)",
                    ));
                }
                check_row_and_decrypt(keys, e, row)
            })
            .collect()
    }

    /// Deletes a record.
    pub fn delete(&mut self, keys: &Keys, id: RecordId) -> Result<()> {
        let tx = self.store.write_tx()?;
        let mut manifest = read_manifest(&tx, keys)?;
        read_record(&tx, keys, &manifest, &id.0)?; // verify before deleting
        store::delete_row(&tx, &id.0)?;
        manifest.remove(&id.0);
        manifest.generation += 1;
        write_manifest(&tx, keys, &manifest)?;
        tx.commit()?;
        Ok(())
    }

    /// Writes an encrypted copy of the whole vault (same password) to `out`.
    /// `out` is created with mode 0600 and must not exist.
    pub fn export_encrypted(&self, out: &Path) -> Result<()> {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(out)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    Error::AlreadyExists
                } else {
                    Error::Io(e)
                }
            })?;
        let target = out
            .to_str()
            .ok_or(Error::InvalidInput("export path must be UTF-8"))?;
        self.store.conn().execute("VACUUM INTO ?1", [target])?;
        Ok(())
    }
}

fn read_manifest(conn: &Connection, keys: &Keys) -> Result<Manifest> {
    let bytes = store::get_meta(conn, META_MANIFEST)?.ok_or(Error::Tampered("manifest missing"))?;
    let sealed = Sealed::decode(&bytes, MAX_MANIFEST_CT)?;
    let pt = open(keys.manifest(), MANIFEST_AD, &sealed)?
        .ok_or(Error::Tampered("manifest does not authenticate"))?;
    Manifest::decode(&pt)
}

fn write_manifest(conn: &Connection, keys: &Keys, manifest: &Manifest) -> Result<()> {
    let sealed = seal(keys.manifest(), MANIFEST_AD, &manifest.encode())?;
    store::put_meta(conn, META_MANIFEST, &sealed.encode())
}

/// Seals a record under a fresh DEK, stores it, and updates the manifest
/// (generation + 1). Caller commits the transaction.
fn write_record(
    conn: &Connection,
    keys: &Keys,
    manifest: &mut Manifest,
    entry: ManifestEntry,
    fields: &PayloadFields,
    secret: &[u8],
) -> Result<()> {
    let payload = encode_payload(fields, secret)?;
    let dek: Zeroizing<[u8; KEY_LEN]> = Zeroizing::new(random()?);
    let body = seal(&dek[..], &record_ad(&entry), &payload)?;
    let wrapped = seal(keys.kek(), &wrap_ad(&entry), &dek[..])?;
    let wrapped_dek: [u8; WRAPPED_DEK_LEN] = wrapped
        .ct
        .as_slice()
        .try_into()
        .map_err(|_| Error::Corrupt("wrapped key length"))?;
    let envelope = Envelope {
        dek_nonce: wrapped.nonce,
        wrapped_dek,
        body,
    };
    store::put_row(
        conn,
        &Row {
            id: entry.id,
            kind: entry.kind,
            version: entry.version,
            envelope: envelope.encode(),
        },
    )?;
    manifest.upsert(entry);
    manifest.generation += 1;
    write_manifest(conn, keys, manifest)
}

fn read_record(
    conn: &Connection,
    keys: &Keys,
    manifest: &Manifest,
    id: &[u8; 16],
) -> Result<Record> {
    match (manifest.get(id), store::get_row(conn, id)?) {
        (None, None) => Err(Error::NotFound),
        (None, Some(_)) => Err(Error::Tampered(
            "record is not in the manifest (injected or restored after delete)",
        )),
        (Some(_), None) => Err(Error::Tampered("record listed in the manifest is missing")),
        (Some(e), Some(row)) => check_row_and_decrypt(keys, e, &row),
    }
}

fn check_row_and_decrypt(keys: &Keys, e: &ManifestEntry, row: &Row) -> Result<Record> {
    if row.kind != e.kind || row.version != e.version {
        return Err(Error::Tampered(
            "record kind or version does not match the manifest (replayed or swapped)",
        ));
    }
    let env = Envelope::decode(&row.envelope)?;
    let wrapped = Sealed {
        nonce: env.dek_nonce,
        ct: env.wrapped_dek.to_vec(),
    };
    let dek = open(keys.kek(), &wrap_ad(e), &wrapped)?
        .ok_or(Error::Tampered("record key does not authenticate"))?;
    // AD comes from the authenticated manifest, not from the row.
    let payload = open(&dek, &record_ad(e), &env.body)?
        .ok_or(Error::Tampered("record does not authenticate"))?;
    let (fields, secret) = decode_payload(&payload)?;
    let secret =
        String::from_utf8(secret.to_vec()).map_err(|_| Error::Corrupt("secret is not UTF-8"))?;
    let kind = RecordKind::from_code(e.kind).ok_or(Error::Unsupported("record kind"))?;
    Ok(Record {
        meta: RecordMeta {
            id: RecordId(e.id),
            kind,
            version: e.version,
            site: fields.site,
            username: fields.username,
            created_by: fields.created_by,
            notes: fields.notes,
            created_at: fields.created_at,
            updated_at: fields.updated_at,
        },
        secret: SecretString::new(secret),
    })
}
