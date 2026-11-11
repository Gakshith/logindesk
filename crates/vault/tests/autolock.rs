//! Phase 2 gate: auto-lock after 15 minutes idle, with an injectable clock.
#![allow(clippy::unwrap_used)] // test code: a panic is a test failure

mod common;

use std::time::Duration;

use common::{TempDir, login, new_vault, pw};
use logindesk_vault::{AUTO_LOCK_AFTER, Error, ManualClock, Vault, VaultSession};

fn session(dir: &TempDir) -> (VaultSession<ManualClock>, ManualClock) {
    let (v, k) = new_vault(dir);
    drop(k);
    drop(v);
    let clock = ManualClock::new();
    let s = VaultSession::new(
        Vault::open(&dir.path("vault.sqlite")).unwrap(),
        clock.clone(),
    );
    (s, clock)
}

#[test]
fn the_constant_is_fifteen_minutes() {
    assert_eq!(AUTO_LOCK_AFTER, Duration::from_secs(900));
}

#[test]
fn locks_after_fifteen_idle_minutes() {
    let dir = TempDir::new("al1");
    let (mut s, clock) = session(&dir);
    assert!(!s.is_unlocked());
    assert!(matches!(s.with_vault(|_, _| Ok(())), Err(Error::Locked)));
    s.unlock(&pw("correct horse battery")).unwrap();
    assert!(s.is_unlocked());
    clock.advance(AUTO_LOCK_AFTER - Duration::from_secs(1));
    assert!(s.is_unlocked());
    clock.advance(Duration::from_secs(1));
    assert!(!s.is_unlocked());
    assert!(matches!(s.with_vault(|_, _| Ok(())), Err(Error::Locked)));
}

#[test]
fn use_resets_the_idle_timer() {
    let dir = TempDir::new("al2");
    let (mut s, clock) = session(&dir);
    s.unlock(&pw("correct horse battery")).unwrap();
    for _ in 0..4 {
        clock.advance(Duration::from_secs(10 * 60));
        s.with_vault(|v, k| v.add(k, login("a.test", "u", "CANARY-al")).map(|_| ()))
            .unwrap();
    }
    assert!(s.is_unlocked());
    clock.advance(AUTO_LOCK_AFTER);
    assert!(s.tick(), "tick should report that it locked");
    assert!(!s.is_unlocked());
}

#[test]
fn sleep_counts_as_idle() {
    // On macOS the monotonic clock stops during sleep; the wall clock does not.
    let dir = TempDir::new("al3");
    let (mut s, clock) = session(&dir);
    s.unlock(&pw("correct horse battery")).unwrap();
    clock.advance_wall_only(Duration::from_secs(60 * 60));
    assert!(!s.is_unlocked());
}

#[test]
fn explicit_lock_and_relock_with_wrong_password() {
    let dir = TempDir::new("al4");
    let (mut s, _clock) = session(&dir);
    s.unlock(&pw("correct horse battery")).unwrap();
    s.lock();
    assert!(!s.is_unlocked());
    assert!(matches!(s.unlock(&pw("nope")), Err(Error::WrongPassword)));
    assert!(!s.is_unlocked());
}
