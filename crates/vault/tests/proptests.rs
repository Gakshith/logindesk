//! Phase 2 gate: proptest round-trips for every on-disk format and for whole
//! records through the vault.
#![allow(clippy::unwrap_used)] // test code: a panic is a test failure

mod common;

use common::{TempDir, new_vault, pw};
use logindesk_core::SecretString;
use logindesk_vault::format::{
    Envelope, Header, KdfParams, Manifest, ManifestEntry, PayloadFields, Sealed, decode_payload,
    encode_payload,
};
use logindesk_vault::{NewRecord, RecordKind};
use proptest::prelude::*;

fn kind() -> impl Strategy<Value = RecordKind> {
    prop_oneof![
        Just(RecordKind::Login),
        Just(RecordKind::ApiKey),
        Just(RecordKind::MailCredential),
        Just(RecordKind::Note)
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn payload_round_trips(
        created_at: u64, updated_at: u64,
        site in ".{0,200}", username in ".{0,100}", created_by in ".{0,40}", notes in ".{0,300}",
        secret in proptest::collection::vec(any::<u8>(), 0..2000),
    ) {
        let f = PayloadFields { created_at, updated_at, site, username, created_by, notes };
        let enc = encode_payload(&f, &secret).unwrap();
        prop_assert_eq!(enc.len() % 256, 0);
        let (g, s) = decode_payload(&enc).unwrap();
        prop_assert_eq!(f, g);
        prop_assert_eq!(&secret[..], &s[..]);
    }

    #[test]
    fn envelope_round_trips(dek_nonce: [u8; 24], wrapped in proptest::collection::vec(any::<u8>(), 48), nonce: [u8; 24],
                            ct in proptest::collection::vec(any::<u8>(), 16..4096)) {
        let e = Envelope { dek_nonce, wrapped_dek: wrapped.try_into().unwrap(), body: Sealed { nonce, ct } };
        prop_assert_eq!(Envelope::decode(&e.encode()).unwrap(), e);
    }

    #[test]
    fn manifest_round_trips(generation: u64, mut ids in proptest::collection::btree_set(any::<[u8; 16]>(), 0..200),
                            kinds in proptest::collection::vec(1u8..=4, 200), versions in proptest::collection::vec(1u64.., 200)) {
        let entries: Vec<_> = std::mem::take(&mut ids).into_iter().enumerate()
            .map(|(i, id)| ManifestEntry { id, kind: kinds[i], version: versions[i] }).collect();
        let m = Manifest { generation, entries };
        prop_assert_eq!(Manifest::decode(&m.encode()).unwrap(), m);
    }

    #[test]
    fn header_round_trips(m_kib in KdfParams::MIN.m_kib..=KdfParams::MAX_M_KIB, t in 2u32..=64, p in 1u32..=16,
                          salt: [u8; 32], nonce: [u8; 24], ct in proptest::collection::vec(any::<u8>(), 16..64)) {
        let h = Header { params: KdfParams { m_kib, t, p }, salt, check: Sealed { nonce, ct } };
        prop_assert_eq!(Header::decode(&h.encode()).unwrap(), h);
    }

    #[test]
    fn decoders_never_panic_on_arbitrary_bytes(bytes in proptest::collection::vec(any::<u8>(), 0..1024)) {
        let _ = Header::decode(&bytes);
        let _ = Envelope::decode(&bytes);
        let _ = Manifest::decode(&bytes);
        let _ = decode_payload(&bytes);
    }
}

proptest! {
    // Each case creates a vault (Argon2id at the OWASP minimum), so fewer cases.
    #![proptest_config(ProptestConfig::with_cases(24))]

    #[test]
    fn records_round_trip_through_the_vault(
        records in proptest::collection::vec((kind(), "[a-z0-9.-]{1,60}", ".{0,60}", ".{1,300}", ".{0,100}"), 1..6),
        update in ".{1,100}",
    ) {
        let dir = TempDir::new("prop");
        let (mut v, k) = new_vault(&dir);
        let mut ids = Vec::new();
        for (kind, site, username, secret, notes) in &records {
            let id = v.add(&k, NewRecord {
                kind: *kind, site: site.clone(), username: username.clone(),
                secret: SecretString::new(secret.clone()), created_by: "prop".into(), notes: notes.clone(),
            }).unwrap();
            ids.push(id);
        }
        for (id, (kind, site, username, secret, notes)) in ids.iter().zip(&records) {
            let r = v.get(&k, *id).unwrap();
            prop_assert_eq!(r.meta.kind, *kind);
            prop_assert_eq!(&r.meta.site, site);
            prop_assert_eq!(&r.meta.username, username);
            prop_assert_eq!(&r.meta.notes, notes);
            prop_assert_eq!(r.secret.expose(), secret);
        }
        v.update_secret(&k, ids[0], pw(&update)).unwrap();
        let r = v.get(&k, ids[0]).unwrap();
        prop_assert_eq!(r.secret.expose(), &update);
        prop_assert_eq!(r.meta.version, 2);
        prop_assert_eq!(v.list(&k).unwrap().len(), records.len());
    }
}
