//! Phase 2 gate: a wrong password is rejected in constant work.
//!
//! Structurally, `Vault::unlock` always runs the full Argon2id derivation and
//! then a constant-time AEAD tag check; there is no early exit. This test
//! checks it empirically: the median time for wrong passwords (of several
//! lengths) is within a generous band of the median for the right one.
#![allow(clippy::unwrap_used)] // test code: a panic is a test failure

mod common;

use std::time::{Duration, Instant};

use common::{TempDir, new_vault, pw};

fn median(mut v: Vec<Duration>) -> Duration {
    v.sort();
    v[v.len() / 2]
}

#[test]
fn wrong_password_costs_the_same_work_as_the_right_one() {
    let dir = TempDir::new("ct");
    let (v, _k) = new_vault(&dir);
    let time = |p: &str| {
        let t = Instant::now();
        let _ = v.unlock(&pw(p));
        t.elapsed()
    };
    let _ = time("warm-up");
    let long = "y".repeat(256);
    for wrong in ["", "x", "correct horse batterz", long.as_str()] {
        // Interleave right and wrong so machine-load drift hits both equally.
        let (mut r, mut w) = (Vec::new(), Vec::new());
        for _ in 0..9 {
            r.push(time("correct horse battery"));
            w.push(time(wrong));
        }
        let (right, w) = (median(r), median(w));
        let ratio = w.as_secs_f64() / right.as_secs_f64();
        eprintln!(
            "right={right:?} wrong(len {})={w:?} ratio={ratio:.3}",
            wrong.len()
        );
        // An early exit would make a wrong password ~1000x cheaper (no
        // Argon2id), so a 0.5x floor catches it while tolerating noisy CI.
        assert!(
            (0.5..2.0).contains(&ratio),
            "wrong-password unlock took {ratio:.2}x the right one"
        );
    }
}
