//! Phase 2 gate: tampered, swapped, replayed, injected and deleted records
//! fail closed; a wrong password is rejected; the header is authenticated.
#![allow(clippy::unwrap_used)] // test code: a panic is a test failure

mod common;

use common::{TempDir, login, new_vault, pw};
use logindesk_vault::{Error, RecordId, Vault};
use rusqlite::Connection;

fn raw(dir: &TempDir) -> Connection {
    Connection::open(dir.path("vault.sqlite")).unwrap()
}

fn envelope(c: &Connection, id: RecordId) -> Vec<u8> {
    c.query_row(
        "SELECT envelope FROM records WHERE id = ?1",
        [&id.as_bytes()[..]],
        |r| r.get(0),
    )
    .unwrap()
}

fn row(c: &Connection, id: RecordId) -> (i64, i64, Vec<u8>) {
    c.query_row(
        "SELECT kind, version, envelope FROM records WHERE id = ?1",
        [&id.as_bytes()[..]],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )
    .unwrap()
}

fn assert_tampered<T: std::fmt::Debug>(r: Result<T, Error>) {
    match r {
        Err(Error::Tampered(_)) => {}
        other => panic!("expected Tampered, got {other:?}"),
    }
}

#[test]
fn round_trip_and_reopen() {
    let dir = TempDir::new("rt");
    let (mut v, k) = new_vault(&dir);
    let id = v
        .add(&k, login("example.test", "alice", "CANARY-rt-1"))
        .unwrap();
    drop((v, k));
    let v = Vault::open(&dir.path("vault.sqlite")).unwrap();
    let k = v.unlock(&pw("correct horse battery")).unwrap();
    let r = v.get(&k, id).unwrap();
    assert_eq!(r.secret.expose(), "CANARY-rt-1");
    assert_eq!(r.meta.site, "example.test");
    assert_eq!(r.meta.version, 1);
    assert_eq!(v.list(&k).unwrap().len(), 1);
}

#[test]
fn wrong_password_is_rejected() {
    let dir = TempDir::new("wrongpw");
    let (v, _k) = new_vault(&dir);
    for bad in ["", "correct horse batter", "correct horse battery ", "x"] {
        assert!(
            matches!(v.unlock(&pw(bad)), Err(Error::WrongPassword)),
            "{bad:?}"
        );
    }
}

#[test]
fn flipped_byte_in_any_envelope_position_fails_closed() {
    let dir = TempDir::new("flip");
    let (mut v, k) = new_vault(&dir);
    let id = v
        .add(&k, login("example.test", "alice", "CANARY-flip"))
        .unwrap();
    let c = raw(&dir);
    let orig = envelope(&c, id);
    for i in 0..orig.len() {
        let mut bad = orig.clone();
        bad[i] ^= 0x01;
        c.execute(
            "UPDATE records SET envelope = ?1 WHERE id = ?2",
            rusqlite::params![bad, &id.as_bytes()[..]],
        )
        .unwrap();
        let r = v.get(&k, id);
        assert!(
            matches!(
                r,
                Err(Error::Tampered(_) | Error::Corrupt(_) | Error::Unsupported(_))
            ),
            "byte {i}: {r:?}"
        );
    }
}

#[test]
fn swapped_records_fail_closed() {
    let dir = TempDir::new("swap");
    let (mut v, k) = new_vault(&dir);
    let a = v
        .add(&k, login("a.test", "alice", "CANARY-swap-a"))
        .unwrap();
    let b = v.add(&k, login("b.test", "bob", "CANARY-swap-b")).unwrap();
    let c = raw(&dir);
    // Swap only the envelopes.
    let (ea, eb) = (envelope(&c, a), envelope(&c, b));
    c.execute(
        "UPDATE records SET envelope = ?1 WHERE id = ?2",
        rusqlite::params![eb, &a.as_bytes()[..]],
    )
    .unwrap();
    c.execute(
        "UPDATE records SET envelope = ?1 WHERE id = ?2",
        rusqlite::params![ea, &b.as_bytes()[..]],
    )
    .unwrap();
    assert_tampered(v.get(&k, a));
    assert_tampered(v.get(&k, b));
    assert_tampered(v.list(&k));
}

#[test]
fn kind_change_fails_closed() {
    let dir = TempDir::new("kind");
    let (mut v, k) = new_vault(&dir);
    let a = v.add(&k, login("a.test", "alice", "CANARY-kind")).unwrap();
    raw(&dir)
        .execute(
            "UPDATE records SET kind = 2 WHERE id = ?1",
            [&a.as_bytes()[..]],
        )
        .unwrap();
    assert_tampered(v.get(&k, a));
}

#[test]
fn replayed_old_record_fails_closed() {
    let dir = TempDir::new("replay");
    let (mut v, k) = new_vault(&dir);
    let a = v.add(&k, login("a.test", "alice", "CANARY-old")).unwrap();
    let c = raw(&dir);
    let (kind, ver, old_env) = row(&c, a);
    v.update_secret(&k, a, pw("CANARY-new")).unwrap();
    assert_eq!(v.get(&k, a).unwrap().secret.expose(), "CANARY-new");

    // Restore the whole old row (version 1).
    c.execute(
        "UPDATE records SET kind = ?1, version = ?2, envelope = ?3 WHERE id = ?4",
        rusqlite::params![kind, ver, old_env, &a.as_bytes()[..]],
    )
    .unwrap();
    assert_tampered(v.get(&k, a));
    // Restore the old envelope but claim the new version.
    c.execute(
        "UPDATE records SET version = 2 WHERE id = ?1",
        [&a.as_bytes()[..]],
    )
    .unwrap();
    assert_tampered(v.get(&k, a));
}

#[test]
fn injected_record_fails_closed() {
    let dir = TempDir::new("inject");
    let (mut v, k) = new_vault(&dir);
    let a = v.add(&k, login("a.test", "alice", "CANARY-inj")).unwrap();
    let c = raw(&dir);
    let (kind, ver, env) = row(&c, a);
    let fake = [0x42u8; 16];
    c.execute(
        "INSERT INTO records (id, kind, version, envelope) VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![&fake[..], kind, ver, env],
    )
    .unwrap();
    assert_tampered(v.list(&k));
    let fake_id: RecordId = "42424242424242424242424242424242".parse().unwrap();
    assert_tampered(v.get(&k, fake_id));
}

#[test]
fn deleted_record_and_restored_record_fail_closed() {
    let dir = TempDir::new("delete");
    let (mut v, k) = new_vault(&dir);
    let a = v.add(&k, login("a.test", "alice", "CANARY-del-a")).unwrap();
    let b = v.add(&k, login("b.test", "bob", "CANARY-del-b")).unwrap();
    let c = raw(&dir);
    let (kind, ver, env) = row(&c, b);

    // Silently deleting a row is detected.
    c.execute("DELETE FROM records WHERE id = ?1", [&a.as_bytes()[..]])
        .unwrap();
    assert_tampered(v.get(&k, a));
    assert_tampered(v.list(&k));

    // A properly deleted record that is put back is detected.
    let dir2 = TempDir::new("delete2");
    let (mut v2, k2) = new_vault(&dir2);
    let x = v2.add(&k2, login("x.test", "x", "CANARY-del-x")).unwrap();
    let c2 = raw(&dir2);
    let (xk, xv, xe) = row(&c2, x);
    v2.delete(&k2, x).unwrap();
    assert!(matches!(v2.get(&k2, x), Err(Error::NotFound)));
    c2.execute(
        "INSERT INTO records (id, kind, version, envelope) VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![&x.as_bytes()[..], xk, xv, xe],
    )
    .unwrap();
    assert_tampered(v2.get(&k2, x));
    let _ = (kind, ver, env);
}

#[test]
fn rolled_back_manifest_fails_closed() {
    let dir = TempDir::new("manifest");
    let (mut v, k) = new_vault(&dir);
    let c = raw(&dir);
    let old: Vec<u8> = c
        .query_row("SELECT value FROM meta WHERE key = 'manifest'", [], |r| {
            r.get(0)
        })
        .unwrap();
    let a = v.add(&k, login("a.test", "alice", "CANARY-man")).unwrap();
    c.execute("UPDATE meta SET value = ?1 WHERE key = 'manifest'", [old])
        .unwrap();
    assert_tampered(v.get(&k, a));
    assert_tampered(v.list(&k));
}

#[test]
fn modified_manifest_fails_closed() {
    let dir = TempDir::new("manifest2");
    let (v, k) = new_vault(&dir);
    let c = raw(&dir);
    let mut m: Vec<u8> = c
        .query_row("SELECT value FROM meta WHERE key = 'manifest'", [], |r| {
            r.get(0)
        })
        .unwrap();
    let last = m.len() - 1;
    m[last] ^= 1;
    c.execute("UPDATE meta SET value = ?1 WHERE key = 'manifest'", [m])
        .unwrap();
    assert_tampered(v.list(&k));
    assert!(v.unlock(&pw("correct horse battery")).is_err());
}

#[test]
fn modified_header_rejects_unlock() {
    let dir = TempDir::new("header");
    let (v, _k) = new_vault(&dir);
    drop(v);
    let c = raw(&dir);
    let h: Vec<u8> = c
        .query_row("SELECT value FROM meta WHERE key = 'header'", [], |r| {
            r.get(0)
        })
        .unwrap();
    // Byte 14 is the first byte of `t` (iterations): 2 -> 3. Byte 40 is in the salt.
    for i in [14usize, 40] {
        let mut bad = h.clone();
        bad[i] ^= 1;
        c.execute("UPDATE meta SET value = ?1 WHERE key = 'header'", [&bad])
            .unwrap();
        let v = Vault::open(&dir.path("vault.sqlite")).unwrap();
        assert!(
            matches!(
                v.unlock(&pw("correct horse battery")),
                Err(Error::WrongPassword)
            ),
            "byte {i}"
        );
    }
}

#[test]
fn non_vault_files_are_refused() {
    let dir = TempDir::new("notvault");
    let p = dir.path("other.sqlite");
    Connection::open(&p)
        .unwrap()
        .execute_batch("CREATE TABLE t(x);")
        .unwrap();
    assert!(matches!(Vault::open(&p), Err(Error::Corrupt(_))));
    assert!(matches!(
        Vault::open(&dir.path("missing.sqlite")),
        Err(Error::NoVault)
    ));
}

#[test]
fn create_refuses_to_overwrite_and_sets_0600() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new("perm");
    let (v, _k) = new_vault(&dir);
    let mode = std::fs::metadata(v.path()).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    assert!(matches!(
        Vault::create(
            v.path(),
            &pw("another password"),
            logindesk_vault::KdfParams::MIN
        ),
        Err(Error::AlreadyExists)
    ));
}

#[test]
fn errors_and_debug_output_never_contain_secrets() {
    let dir = TempDir::new("canary");
    let (mut v, k) = new_vault(&dir);
    let id = v
        .add(&k, login("a.test", "alice", "CANARY-dbg-7f1e"))
        .unwrap();
    let rec = v.get(&k, id).unwrap();
    let out = format!("{rec:?} {:?} {k:?} {v:?}", v.list(&k).unwrap());
    assert!(!out.contains("CANARY-dbg-7f1e"));
    assert!(!out.contains("correct horse battery"));
    let err = v.unlock(&pw("CANARY-wrong-pw")).unwrap_err();
    assert!(!format!("{err} {err:?}").contains("CANARY"));
}

#[test]
fn encrypted_export_round_trips_and_refuses_overwrite() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new("export");
    let (mut v, k) = new_vault(&dir);
    v.add(&k, login("a.test", "alice", "CANARY-exp")).unwrap();
    let out = dir.path("backup.sqlite");
    v.export_encrypted(&out).unwrap();
    assert_eq!(
        std::fs::metadata(&out).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(matches!(
        v.export_encrypted(&out),
        Err(Error::AlreadyExists)
    ));
    let b = Vault::open(&out).unwrap();
    let bk = b.unlock(&pw("correct horse battery")).unwrap();
    let recs = b.records(&bk).unwrap();
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].secret.expose(), "CANARY-exp");
    let raw_bytes = std::fs::read(&out).unwrap();
    assert!(
        !raw_bytes.windows(10).any(|w| w == b"CANARY-exp"),
        "plaintext in encrypted export"
    );
}

#[test]
fn vault_file_never_contains_plaintext() {
    let dir = TempDir::new("plain");
    let (mut v, k) = new_vault(&dir);
    let id = v
        .add(
            &k,
            login("site-CANARY.test", "user-CANARY", "pw-CANARY-9a8b"),
        )
        .unwrap();
    v.update_secret(&k, id, pw("pw-CANARY-new")).unwrap();
    drop((v, k));
    for name in ["vault.sqlite", "vault.sqlite-journal"] {
        if let Ok(bytes) = std::fs::read(dir.path(name)) {
            assert!(
                !bytes.windows(6).any(|w| w == b"CANARY"),
                "{name} holds plaintext"
            );
        }
    }
}

#[test]
fn plaintext_csv_export_is_0600_and_refuses_overwrite() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new("csv");
    let (mut v, k) = new_vault(&dir);
    v.add(&k, login("a.test", "alice", "CANARY-csv")).unwrap();
    let out = dir.path("export.csv");
    let recs = v.records(&k).unwrap();
    logindesk_vault::write_plaintext_csv(&out, &recs).unwrap();
    assert_eq!(
        std::fs::metadata(&out).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(matches!(
        logindesk_vault::write_plaintext_csv(&out, &recs),
        Err(Error::AlreadyExists)
    ));
    let back = logindesk_vault::parse_import_csv(std::fs::File::open(&out).unwrap()).unwrap();
    assert_eq!(back[0].secret.expose(), "CANARY-csv");
}

#[test]
fn update_meta_keeps_the_secret_and_bumps_the_version() {
    let dir = TempDir::new("meta");
    let (mut v, k) = new_vault(&dir);
    let a = v.add(&k, login("a.test", "alice", "CANARY-meta")).unwrap();
    v.update_meta(&k, a, Some("alice+a@x.test".into()), Some("active".into()))
        .unwrap();
    let r = v.get(&k, a).unwrap();
    assert_eq!(r.secret.expose(), "CANARY-meta");
    assert_eq!(r.meta.username, "alice+a@x.test");
    assert_eq!(r.meta.notes, "active");
    assert_eq!(r.meta.version, 2);
    v.update_meta(&k, a, None, Some("x".into())).unwrap();
    let r = v.get(&k, a).unwrap();
    assert_eq!(
        (r.meta.username.as_str(), r.meta.notes.as_str()),
        ("alice+a@x.test", "x")
    );
    assert_eq!(v.list(&k).unwrap().len(), 1);
}
