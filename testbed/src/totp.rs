//! RFC 6238 TOTP (SHA-1, 30 s step, 6 digits) for the fake site's `/totp` page.

use hmac::{KeyInit, Mac};

/// The 6-digit code for `seed` at `unix_secs`.
pub fn code(seed: &[u8], unix_secs: u64) -> String {
    format!("{:06}", hotp(seed, unix_secs / 30) % 1_000_000)
}

/// True if `candidate` matches the code for the current, previous or next step.
pub fn verify(seed: &[u8], unix_secs: u64, candidate: &str) -> bool {
    let step = unix_secs / 30;
    [step.saturating_sub(1), step, step + 1]
        .iter()
        .any(|s| format!("{:06}", hotp(seed, *s) % 1_000_000) == candidate.trim())
}

fn hotp(seed: &[u8], counter: u64) -> u32 {
    let Ok(mut mac) = hmac::Hmac::<sha1::Sha1>::new_from_slice(seed) else {
        return 0;
    };
    mac.update(&counter.to_be_bytes());
    let h = mac.finalize().into_bytes();
    let off = usize::from(h[h.len() - 1] & 0x0f);
    (u32::from(h[off] & 0x7f) << 24)
        | (u32::from(h[off + 1]) << 16)
        | (u32::from(h[off + 2]) << 8)
        | u32::from(h[off + 3])
}

#[cfg(test)]
mod tests {
    #[test]
    fn rfc6238_sha1_vector() {
        // RFC 6238 Appendix B: T = 59 s → 94287082 (8 digits); the last 6 are 287082.
        assert_eq!(super::code(b"12345678901234567890", 59), "287082");
        assert!(super::verify(b"12345678901234567890", 59, "287082"));
        assert!(!super::verify(b"12345678901234567890", 59, "000000"));
    }
}
