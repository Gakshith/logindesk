//! Key derivation: Argon2id(password, salt) → HKDF-SHA256 subkeys, all held
//! in one mlocked, zeroize-on-drop page.

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::error::{Error, Result};
use crate::format::{KEY_LEN, KdfParams, SALT_LEN};
use crate::hardening::LockedPage;

const KEK: core::ops::Range<usize> = 0..KEY_LEN;
const CHECK: core::ops::Range<usize> = KEY_LEN..2 * KEY_LEN;
const MANIFEST: core::ops::Range<usize> = 2 * KEY_LEN..3 * KEY_LEN;
const MASTER: core::ops::Range<usize> = 3 * KEY_LEN..4 * KEY_LEN;

/// HKDF salt (domain separation for the whole format).
pub(crate) const HKDF_SALT: &[u8] = b"logindesk/v1";
const INFO_KEK: &[u8] = b"logindesk/v1/kek";
const INFO_CHECK: &[u8] = b"logindesk/v1/key-check";
const INFO_MANIFEST: &[u8] = b"logindesk/v1/manifest";

/// The unlocked vault keys. Opaque, not `Clone`, page-locked, zeroized on
/// drop. Dropping it locks the vault.
pub struct Keys {
    page: LockedPage,
}

impl core::fmt::Debug for Keys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Keys([REDACTED])")
    }
}

impl Keys {
    /// Runs Argon2id in full, then HKDF. Always the same work for any
    /// password: there is no early exit.
    pub(crate) fn derive(
        password: &[u8],
        params: KdfParams,
        salt: &[u8; SALT_LEN],
    ) -> Result<Self> {
        let params = params.validate()?;
        let argon = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(params.m_kib, params.t, params.p, Some(KEY_LEN))
                .map_err(|_| Error::Unsupported("Argon2id parameters"))?,
        );
        let mut page = LockedPage::new();
        argon
            .hash_password_into(password, salt, &mut page.as_mut_slice()[MASTER])
            .map_err(|_| Error::InvalidInput("password or salt length"))?;
        let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), &page.as_slice()[MASTER]);
        page.as_mut_slice()[MASTER].zeroize();
        for (range, info) in [
            (KEK, INFO_KEK),
            (CHECK, INFO_CHECK),
            (MANIFEST, INFO_MANIFEST),
        ] {
            hk.expand(info, &mut page.as_mut_slice()[range])
                .map_err(|_| Error::InvalidInput("HKDF output length"))?;
        }
        Ok(Self { page })
    }

    pub(crate) fn kek(&self) -> &[u8] {
        &self.page.as_slice()[KEK]
    }
    pub(crate) fn check(&self) -> &[u8] {
        &self.page.as_slice()[CHECK]
    }
    pub(crate) fn manifest(&self) -> &[u8] {
        &self.page.as_slice()[MANIFEST]
    }

    /// Whether the key page is locked in RAM (`mlock` succeeded).
    pub fn is_memory_locked(&self) -> bool {
        self.page.is_mlocked()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Argon2id known-answer test. Vector: RFC 9106 §5.3 ("Argon2id Test
    /// Vectors"), <https://www.rfc-editor.org/rfc/rfc9106.html#section-5.3>.
    #[test]
    fn argon2id_kat_rfc9106_5_3() {
        let password = [0x01u8; 32];
        let salt = [0x02u8; 16];
        let secret = [0x03u8; 8];
        let ad = [0x04u8; 12];
        let params = argon2::ParamsBuilder::new()
            .m_cost(32)
            .t_cost(3)
            .p_cost(4)
            .data(argon2::AssociatedData::new(&ad).unwrap())
            .output_len(32)
            .build()
            .unwrap();
        let a =
            Argon2::new_with_secret(&secret, Algorithm::Argon2id, Version::V0x13, params).unwrap();
        let mut out = [0u8; 32];
        a.hash_password_into(&password, &salt, &mut out).unwrap();
        assert_eq!(
            out.to_vec(),
            hex("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659")
        );
    }

    /// HKDF-SHA256 known-answer test. Vector: RFC 5869 Appendix A.1 (Test
    /// Case 1), <https://www.rfc-editor.org/rfc/rfc5869.html#appendix-A.1>.
    #[test]
    fn hkdf_sha256_kat_rfc5869_a_1() {
        let ikm = [0x0bu8; 22];
        let salt = hex("000102030405060708090a0b0c");
        let info = hex("f0f1f2f3f4f5f6f7f8f9");
        let (prk, hk) = Hkdf::<Sha256>::extract(Some(&salt), &ikm);
        assert_eq!(
            prk.to_vec(),
            hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
        );
        let mut okm = [0u8; 42];
        hk.expand(&info, &mut okm).unwrap();
        assert_eq!(
            okm.to_vec(),
            hex(
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
            )
        );
    }

    #[test]
    fn subkeys_are_distinct_and_deterministic() {
        let salt = [9u8; SALT_LEN];
        let a = Keys::derive(b"pw-one", KdfParams::MIN, &salt).unwrap();
        let b = Keys::derive(b"pw-one", KdfParams::MIN, &salt).unwrap();
        let c = Keys::derive(b"pw-two", KdfParams::MIN, &salt).unwrap();
        assert_eq!(a.kek(), b.kek());
        assert_ne!(a.kek(), c.kek());
        assert_ne!(a.kek(), a.check());
        assert_ne!(a.kek(), a.manifest());
        assert!(
            a.page.as_slice()[MASTER].iter().all(|&x| x == 0),
            "master key left in memory"
        );
        assert_eq!(format!("{a:?}"), "Keys([REDACTED])");
    }

    #[test]
    fn params_below_minimum_are_refused() {
        let weak = KdfParams {
            m_kib: 64,
            t: 1,
            p: 1,
        };
        assert!(Keys::derive(b"pw", weak, &[0; SALT_LEN]).is_err());
    }
}
