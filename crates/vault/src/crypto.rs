//! XChaCha20-Poly1305 seal/open and the OS RNG.

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::format::{NONCE_LEN, Sealed};

/// `N` bytes from the OS RNG.
pub(crate) fn random<const N: usize>() -> Result<[u8; N]> {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).map_err(|_| Error::Rng)?;
    Ok(b)
}

fn cipher(key: &[u8]) -> Result<XChaCha20Poly1305> {
    XChaCha20Poly1305::new_from_slice(key).map_err(|_| Error::InvalidInput("key length"))
}

/// Seals `pt` under `key` with a fresh random 24-byte nonce.
pub(crate) fn seal(key: &[u8], ad: &[u8], pt: &[u8]) -> Result<Sealed> {
    let nonce: [u8; NONCE_LEN] = random()?;
    let ct = cipher(key)?
        .encrypt(&XNonce::from(nonce), Payload { msg: pt, aad: ad })
        .map_err(|_| Error::InvalidInput("plaintext too long"))?;
    Ok(Sealed { nonce, ct })
}

/// Opens `sealed`; `None` if the tag does not verify (constant-time check).
pub(crate) fn open(key: &[u8], ad: &[u8], sealed: &Sealed) -> Result<Option<Zeroizing<Vec<u8>>>> {
    Ok(cipher(key)?
        .decrypt(
            &XNonce::from(sealed.nonce),
            Payload {
                msg: &sealed.ct,
                aad: ad,
            },
        )
        .ok()
        .map(Zeroizing::new))
}

#[cfg(test)]
mod tests {
    //! Known-answer test for XChaCha20-Poly1305.
    //!
    //! Vector: draft-irtf-cfrg-xchacha-03, Appendix A.3.1 ("Example and Test
    //! Vector for AEAD_XCHACHA20_POLY1305"),
    //! <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03#appendix-A.3.1>.
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    const PT: &[u8] = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

    #[test]
    fn xchacha20poly1305_kat_draft_irtf_cfrg_xchacha_03_a_3_1() {
        let aad = hex("50515253c0c1c2c3c4c5c6c7");
        let key = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        let nonce: [u8; 24] = hex("404142434445464748494a4b4c4d4e4f5051525354555657")
            .try_into()
            .unwrap();
        let expected_ct = hex(
            "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb
             731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452
             2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9
             21f9664c97637da9768812f615c68b13b52e",
        );
        let expected_tag = hex("c0875924c1c7987947deafd8780acf49");

        let out = cipher(&key)
            .unwrap()
            .encrypt(&XNonce::from(nonce), Payload { msg: PT, aad: &aad })
            .unwrap();
        assert_eq!(&out[..PT.len()], &expected_ct[..]);
        assert_eq!(&out[PT.len()..], &expected_tag[..]);

        let sealed = Sealed { nonce, ct: out };
        assert_eq!(open(&key, &aad, &sealed).unwrap().unwrap().as_slice(), PT);
        // Any change to the AD, nonce or ciphertext fails closed.
        assert!(open(&key, b"other", &sealed).unwrap().is_none());
        let mut bad = sealed.clone();
        bad.ct[0] ^= 1;
        assert!(open(&key, &aad, &bad).unwrap().is_none());
        let mut bad = sealed;
        bad.nonce[0] ^= 1;
        assert!(open(&key, &aad, &bad).unwrap().is_none());
    }

    #[test]
    fn seal_uses_fresh_nonces() {
        let key = [7u8; 32];
        let a = seal(&key, b"ad", b"same").unwrap();
        let b = seal(&key, b"ad", b"same").unwrap();
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.ct, b.ct);
    }
}
