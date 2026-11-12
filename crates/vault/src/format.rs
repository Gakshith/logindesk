//! Binary formats stored inside the vault file, and their strict parsers.
//!
//! Every decoder here takes untrusted bytes, never panics, never allocates
//! more than its input justifies, and rejects trailing bytes. These are the
//! `cargo fuzz` targets (see `fuzz/`).
//!
//! All integers are little-endian.

use crate::error::{Error, Result};

/// Magic bytes at the start of the vault header.
pub const HEADER_MAGIC: &[u8; 8] = b"LDVAULT\0";
/// Current format version for header, envelope, manifest and payload.
pub const FORMAT_VERSION: u16 = 1;
/// Salt length for Argon2id.
pub const SALT_LEN: usize = 32;
/// XChaCha20-Poly1305 nonce length.
pub const NONCE_LEN: usize = 24;
/// Poly1305 tag length.
pub const TAG_LEN: usize = 16;
/// Key length (DEK, KEK, subkeys).
pub const KEY_LEN: usize = 32;
/// A wrapped DEK: 32-byte key + tag.
pub const WRAPPED_DEK_LEN: usize = KEY_LEN + TAG_LEN;
/// Upper bound on one encrypted record body (1 MiB).
pub const MAX_BODY_LEN: usize = 1 << 20;
/// Upper bound on records in one vault.
pub const MAX_RECORDS: usize = 1_000_000;
/// Upper bound on one text field inside a payload (64 KiB).
pub const MAX_FIELD_LEN: usize = 64 * 1024;
/// Payload plaintext is padded to a multiple of this.
pub const PAD_BUCKET: usize = 256;

/// Argon2id cost parameters, stored in the header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory in KiB.
    pub m_kib: u32,
    /// Iterations.
    pub t: u32,
    /// Lanes.
    pub p: u32,
}

impl KdfParams {
    /// Defaults for new vaults, tuned for 0.5–1.0 s unlock on an M-series
    /// Mac. See `docs/crypto-spec.md` for the measurement and the OWASP check.
    pub const DEFAULT: Self = Self {
        m_kib: 512 * 1024,
        t: 3,
        p: 1,
    };
    /// The OWASP Password Storage Cheat Sheet minimum (19 MiB, t=2, p=1).
    /// No vault, new or opened, may go below it.
    pub const MIN: Self = Self {
        m_kib: 19 * 1024,
        t: 2,
        p: 1,
    };
    /// Upper bounds, so a modified header cannot make unlock hang or OOM.
    pub const MAX_M_KIB: u32 = 4 * 1024 * 1024;
    /// Maximum iterations.
    pub const MAX_T: u32 = 64;
    /// Maximum lanes.
    pub const MAX_P: u32 = 16;

    /// Checks the parameters against [`Self::MIN`] and the upper bounds.
    pub fn validate(self) -> Result<Self> {
        let ok = self.m_kib >= Self::MIN.m_kib
            && self.m_kib <= Self::MAX_M_KIB
            && self.t >= Self::MIN.t
            && self.t <= Self::MAX_T
            && self.p >= Self::MIN.p
            && self.p <= Self::MAX_P
            && self.m_kib >= 8 * self.p;
        if ok {
            Ok(self)
        } else {
            Err(Error::Unsupported("Argon2id parameters out of range"))
        }
    }
}

/// A nonce plus ciphertext-with-tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sealed {
    /// XChaCha20 nonce.
    pub nonce: [u8; NONCE_LEN],
    /// Ciphertext followed by the 16-byte tag.
    pub ct: Vec<u8>,
}

impl Sealed {
    /// `nonce | len(u32) | ct`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(NONCE_LEN + 4 + self.ct.len());
        out.extend_from_slice(&self.nonce);
        put_bytes(&mut out, &self.ct);
        out
    }

    /// Strict decoder; `max_ct` bounds the ciphertext length.
    pub fn decode(bytes: &[u8], max_ct: usize) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let nonce = r.array::<NONCE_LEN>()?;
        let ct = r.bytes(TAG_LEN, max_ct)?.to_vec();
        r.finish()?;
        Ok(Self { nonce, ct })
    }
}

/// Largest sealed manifest: header fields plus every entry, plus the tag.
pub const MAX_MANIFEST_CT: usize = 14 + MAX_RECORDS * 25 + TAG_LEN;

/// The vault header (stored in `meta.header`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// Argon2id parameters.
    pub params: KdfParams,
    /// Argon2id salt.
    pub salt: [u8; SALT_LEN],
    /// Key-check value: a fixed plaintext sealed under the check subkey, with
    /// the encoded header prefix (magic..salt) as associated data.
    pub check: Sealed,
}

/// Length of the header prefix that the key-check value authenticates.
pub const HEADER_PREFIX_LEN: usize = 8 + 2 + 4 + 4 + 4 + SALT_LEN;

impl Header {
    /// Encodes `magic | version | m | t | p | salt` (the authenticated prefix).
    pub fn encode_prefix(params: KdfParams, salt: &[u8; SALT_LEN]) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_PREFIX_LEN);
        out.extend_from_slice(HEADER_MAGIC);
        out.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
        out.extend_from_slice(&params.m_kib.to_le_bytes());
        out.extend_from_slice(&params.t.to_le_bytes());
        out.extend_from_slice(&params.p.to_le_bytes());
        out.extend_from_slice(salt);
        out
    }

    /// Full encoding: prefix, then the sealed key-check value.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Self::encode_prefix(self.params, &self.salt);
        out.extend_from_slice(&self.check.nonce);
        put_bytes(&mut out, &self.check.ct);
        out
    }

    /// Strict decoder for untrusted bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        if r.take(8)? != HEADER_MAGIC {
            return Err(Error::Corrupt("bad header magic"));
        }
        if r.u16()? != FORMAT_VERSION {
            return Err(Error::Unsupported("header version"));
        }
        let params = KdfParams {
            m_kib: r.u32()?,
            t: r.u32()?,
            p: r.u32()?,
        }
        .validate()?;
        let salt = r.array::<SALT_LEN>()?;
        let nonce = r.array::<NONCE_LEN>()?;
        let ct = r.bytes(TAG_LEN, 1024)?.to_vec();
        r.finish()?;
        Ok(Self {
            params,
            salt,
            check: Sealed { nonce, ct },
        })
    }
}

/// One encrypted record as stored in `records.envelope`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// Nonce for the DEK wrap.
    pub dek_nonce: [u8; NONCE_LEN],
    /// The DEK sealed under the KEK.
    pub wrapped_dek: [u8; WRAPPED_DEK_LEN],
    /// The padded payload sealed under the DEK.
    pub body: Sealed,
}

impl Envelope {
    /// `version(u16) | dek_nonce | wrapped_dek | body_nonce | len(u32) | body`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(2 + NONCE_LEN * 2 + WRAPPED_DEK_LEN + 4 + self.body.ct.len());
        out.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
        out.extend_from_slice(&self.dek_nonce);
        out.extend_from_slice(&self.wrapped_dek);
        out.extend_from_slice(&self.body.nonce);
        put_bytes(&mut out, &self.body.ct);
        out
    }

    /// Strict decoder for untrusted bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        if r.u16()? != FORMAT_VERSION {
            return Err(Error::Unsupported("record envelope version"));
        }
        let dek_nonce = r.array::<NONCE_LEN>()?;
        let wrapped_dek = r.array::<WRAPPED_DEK_LEN>()?;
        let nonce = r.array::<NONCE_LEN>()?;
        let ct = r.bytes(TAG_LEN, MAX_BODY_LEN + TAG_LEN)?.to_vec();
        r.finish()?;
        Ok(Self {
            dek_nonce,
            wrapped_dek,
            body: Sealed { nonce, ct },
        })
    }
}

/// One manifest entry: what the vault expects a record row to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ManifestEntry {
    /// Record id.
    pub id: [u8; 16],
    /// Record kind code.
    pub kind: u8,
    /// Record version (starts at 1, +1 per write).
    pub version: u64,
}

/// The manifest plaintext: a write counter and every record's expected
/// `(id, kind, version)`, sorted by id.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Manifest {
    /// Incremented on every write.
    pub generation: u64,
    /// Sorted by id, ids unique.
    pub entries: Vec<ManifestEntry>,
}

impl Manifest {
    /// `version(u16) | generation(u64) | count(u32) | (id[16] kind version(u64))*`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(14 + self.entries.len() * 25);
        out.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
        out.extend_from_slice(&self.generation.to_le_bytes());
        out.extend_from_slice(&(self.entries.len() as u32).to_le_bytes());
        for e in &self.entries {
            out.extend_from_slice(&e.id);
            out.push(e.kind);
            out.extend_from_slice(&e.version.to_le_bytes());
        }
        out
    }

    /// Strict decoder: ids must be strictly ascending (sorted, unique).
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        if r.u16()? != FORMAT_VERSION {
            return Err(Error::Unsupported("manifest version"));
        }
        let generation = r.u64()?;
        let count = r.u32()? as usize;
        if count > MAX_RECORDS || count.saturating_mul(25) != r.remaining() {
            return Err(Error::Corrupt("manifest length"));
        }
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            let e = ManifestEntry {
                id: r.array::<16>()?,
                kind: r.u8()?,
                version: r.u64()?,
            };
            if entries
                .last()
                .is_some_and(|prev: &ManifestEntry| prev.id >= e.id)
            {
                return Err(Error::Corrupt("manifest ids not sorted and unique"));
            }
            entries.push(e);
        }
        r.finish()?;
        Ok(Self {
            generation,
            entries,
        })
    }

    /// Finds the entry for `id`.
    pub fn get(&self, id: &[u8; 16]) -> Option<&ManifestEntry> {
        self.entries
            .binary_search_by(|e| e.id.cmp(id))
            .ok()
            .map(|i| &self.entries[i])
    }

    /// Inserts or replaces the entry for `e.id`, keeping the order.
    pub fn upsert(&mut self, e: ManifestEntry) {
        match self.entries.binary_search_by(|x| x.id.cmp(&e.id)) {
            Ok(i) => self.entries[i] = e,
            Err(i) => self.entries.insert(i, e),
        }
    }

    /// Removes the entry for `id`; returns whether it existed.
    pub fn remove(&mut self, id: &[u8; 16]) -> bool {
        match self.entries.binary_search_by(|x| x.id.cmp(id)) {
            Ok(i) => {
                self.entries.remove(i);
                true
            }
            Err(_) => false,
        }
    }
}

/// Decrypted record content. The secret stays in a zeroizing buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadFields {
    /// Unix seconds.
    pub created_at: u64,
    /// Unix seconds.
    pub updated_at: u64,
    /// Site as entered (eTLD+1 normalisation belongs to the policy crate).
    pub site: String,
    /// Username or email.
    pub username: String,
    /// Who created it (e.g. "cli", or an agent name).
    pub created_by: String,
    /// Free-form, non-secret notes.
    pub notes: String,
}

/// Encodes a payload: `content_len(u32) | content | zero padding` to a
/// multiple of [`PAD_BUCKET`], where content is
/// `version | created_at | updated_at | site | username | created_by | notes | secret`
/// with every text field length-prefixed (u32). The result must be zeroized
/// by the caller (it contains the secret).
pub fn encode_payload(
    fields: &PayloadFields,
    secret: &[u8],
) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    for s in [
        &fields.site,
        &fields.username,
        &fields.created_by,
        &fields.notes,
    ] {
        if s.len() > MAX_FIELD_LEN {
            return Err(Error::InvalidInput("a text field is longer than 64 KiB"));
        }
    }
    if secret.len() > MAX_FIELD_LEN {
        return Err(Error::InvalidInput("the secret is longer than 64 KiB"));
    }
    let content_len = 2
        + 8
        + 8
        + 5 * 4
        + fields.site.len()
        + fields.username.len()
        + fields.created_by.len()
        + fields.notes.len()
        + secret.len();
    let total = (4 + content_len).div_ceil(PAD_BUCKET) * PAD_BUCKET;
    let mut out = zeroize::Zeroizing::new(Vec::with_capacity(total));
    out.extend_from_slice(&(content_len as u32).to_le_bytes());
    out.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    out.extend_from_slice(&fields.created_at.to_le_bytes());
    out.extend_from_slice(&fields.updated_at.to_le_bytes());
    for s in [
        &fields.site,
        &fields.username,
        &fields.created_by,
        &fields.notes,
    ] {
        put_bytes(&mut out, s.as_bytes());
    }
    put_bytes(&mut out, secret);
    out.resize(total, 0);
    Ok(out)
}

/// Strict payload decoder. Returns the fields and the secret bytes (in a
/// zeroizing buffer). Padding must be all zero.
pub fn decode_payload(bytes: &[u8]) -> Result<(PayloadFields, zeroize::Zeroizing<Vec<u8>>)> {
    if bytes.is_empty() || !bytes.len().is_multiple_of(PAD_BUCKET) {
        return Err(Error::Corrupt("payload padding"));
    }
    let mut outer = Reader::new(bytes);
    let content_len = outer.u32()? as usize;
    // Canonical: exactly the minimal padding (found by cargo fuzz, 2026-11-11).
    if (4 + content_len).div_ceil(PAD_BUCKET) * PAD_BUCKET != bytes.len() {
        return Err(Error::Corrupt("payload padding"));
    }
    let content = outer.take(content_len)?;
    if outer.rest().iter().any(|&b| b != 0) {
        return Err(Error::Corrupt("payload padding"));
    }
    let mut r = Reader::new(content);
    if r.u16()? != FORMAT_VERSION {
        return Err(Error::Unsupported("payload version"));
    }
    let created_at = r.u64()?;
    let updated_at = r.u64()?;
    let site = r.string()?;
    let username = r.string()?;
    let created_by = r.string()?;
    let notes = r.string()?;
    let secret = zeroize::Zeroizing::new(r.bytes(0, MAX_FIELD_LEN)?.to_vec());
    r.finish()?;
    Ok((
        PayloadFields {
            created_at,
            updated_at,
            site,
            username,
            created_by,
            notes,
        },
        secret,
    ))
}

fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_le_bytes());
    out.extend_from_slice(b);
}

/// Bounds-checked cursor over untrusted bytes.
struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }
    fn remaining(&self) -> usize {
        self.buf.len()
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if n > self.buf.len() {
            return Err(Error::Corrupt("truncated"));
        }
        let (head, tail) = self.buf.split_at(n);
        self.buf = tail;
        Ok(head)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let mut a = [0u8; N];
        a.copy_from_slice(self.take(N)?);
        Ok(a)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.array::<1>()?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.array()?))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.array()?))
    }
    /// A u32-length-prefixed byte string with `min..=max` length.
    fn bytes(&mut self, min: usize, max: usize) -> Result<&'a [u8]> {
        let n = self.u32()? as usize;
        if n < min || n > max {
            return Err(Error::Corrupt("field length out of range"));
        }
        self.take(n)
    }
    fn string(&mut self) -> Result<String> {
        let b = self.bytes(0, MAX_FIELD_LEN)?;
        String::from_utf8(b.to_vec()).map_err(|_| Error::Corrupt("text field is not UTF-8"))
    }
    fn rest(&mut self) -> &'a [u8] {
        core::mem::take(&mut self.buf)
    }
    fn finish(&self) -> Result<()> {
        if self.buf.is_empty() {
            Ok(())
        } else {
            Err(Error::Corrupt("trailing bytes"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decoders_reject_empty_and_garbage() {
        for b in [&[][..], &[0u8; 3], &[0xff; 100]] {
            assert!(Header::decode(b).is_err());
            assert!(Envelope::decode(b).is_err());
            assert!(Manifest::decode(b).is_err());
            assert!(decode_payload(b).is_err());
            assert!(Sealed::decode(b, MAX_MANIFEST_CT).is_err());
        }
    }

    #[test]
    fn header_rejects_params_below_owasp_minimum() {
        let weak = KdfParams {
            m_kib: 1024,
            t: 1,
            p: 1,
        };
        let mut b = Header::encode_prefix(weak, &[0; SALT_LEN]);
        b.extend_from_slice(&[0; NONCE_LEN]);
        put_bytes(&mut b, &[0; TAG_LEN]);
        assert!(matches!(Header::decode(&b), Err(Error::Unsupported(_))));
    }

    #[test]
    fn manifest_rejects_unsorted_ids() {
        let mut m = Manifest::default();
        m.entries.push(ManifestEntry {
            id: [2; 16],
            kind: 1,
            version: 1,
        });
        m.entries.push(ManifestEntry {
            id: [1; 16],
            kind: 1,
            version: 1,
        });
        assert!(Manifest::decode(&m.encode()).is_err());
    }

    #[test]
    fn payload_is_padded_to_bucket() {
        let f = PayloadFields {
            created_at: 1,
            updated_at: 2,
            site: "example.test".into(),
            username: "u".into(),
            created_by: "cli".into(),
            notes: String::new(),
        };
        let a = encode_payload(&f, b"x").unwrap();
        let b = encode_payload(&f, &[b'y'; 150]).unwrap();
        assert_eq!(a.len(), PAD_BUCKET);
        assert_eq!(b.len(), PAD_BUCKET);
    }

    #[test]
    fn over_padded_payload_is_rejected() {
        // Regression: fuzz crash-102e28da (a 60-byte payload padded to 512).
        let f = PayloadFields {
            created_at: 1,
            updated_at: 2,
            site: "example.test".into(),
            username: "alice".into(),
            created_by: "cli".into(),
            notes: String::new(),
        };
        let mut b = encode_payload(&f, b"pw").unwrap().to_vec();
        assert!(decode_payload(&b).is_ok());
        b.resize(b.len() + PAD_BUCKET, 0);
        assert!(matches!(decode_payload(&b), Err(Error::Corrupt(_))));
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let m = Manifest::default();
        let mut b = m.encode();
        b.push(0);
        assert!(Manifest::decode(&b).is_err());
    }
}
