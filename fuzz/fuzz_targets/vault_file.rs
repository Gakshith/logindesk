//! Fuzzes every parser that reads the vault file.
//!
//! The first input byte picks the parser; the rest is the untrusted input.
//! Binary formats are canonical, so a successful decode must re-encode to
//! exactly the input bytes. Selector 6 writes the input to a file and opens
//! it as a vault (SQLite + header parsing), read-only.
#![no_main]

use std::path::PathBuf;
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use logindesk_vault::format::{Envelope, Header, MAX_MANIFEST_CT, Manifest, Sealed, decode_payload, encode_payload};
use logindesk_vault::{Vault, parse_import_csv};

fn scratch_file() -> &'static PathBuf {
    static P: OnceLock<PathBuf> = OnceLock::new();
    P.get_or_init(|| std::env::temp_dir().join(format!("logindesk-fuzz-{}.sqlite", std::process::id())))
}

fuzz_target!(|data: &[u8]| {
    let Some((&sel, input)) = data.split_first() else { return };
    match sel % 7 {
        0 => {
            if let Ok(h) = Header::decode(input) {
                assert_eq!(h.encode(), input);
            }
        }
        1 => {
            if let Ok(e) = Envelope::decode(input) {
                assert_eq!(e.encode(), input);
            }
        }
        2 => {
            if let Ok(m) = Manifest::decode(input) {
                assert_eq!(m.encode(), input);
            }
        }
        3 => {
            if let Ok((fields, secret)) = decode_payload(input) {
                assert_eq!(encode_payload(&fields, &secret).unwrap().as_slice(), input);
            }
        }
        4 => {
            if let Ok(s) = Sealed::decode(input, MAX_MANIFEST_CT) {
                assert_eq!(s.encode(), input);
            }
        }
        5 => {
            let _ = parse_import_csv(input);
        }
        _ => {
            let p = scratch_file();
            let _ = std::fs::remove_file(p);
            if std::fs::write(p, input).is_ok() {
                let _ = Vault::open_read_only(p);
            }
        }
    }
});
