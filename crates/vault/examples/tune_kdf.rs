//! Measures vault unlock time for a grid of Argon2id parameters.
//! Run: `cargo run --release -p logindesk-vault --example tune_kdf`
//! Results feed `docs/crypto-spec.md` (target: 0.5–1.0 s on an M-series Mac).
#![allow(clippy::unwrap_used)] // a dev tool: a panic is a failed measurement

use std::time::{Duration, Instant};

use logindesk_core::SecretString;
use logindesk_vault::{KdfParams, Vault};

fn main() {
    let dir = std::env::temp_dir().join(format!("logindesk-tune-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let pw = SecretString::new("a tuning password, not a real one".into());
    let grid: &[(u32, u32)] = &[
        (128, 3),
        (256, 2),
        (256, 4),
        (256, 6),
        (384, 4),
        (512, 2),
        (512, 3),
        (512, 4),
    ];
    eprintln!(
        "{:>8} {:>3} {:>3}  {:>10}  {:>10}  {:>10}",
        "m (MiB)", "t", "p", "min", "median", "max"
    );
    for (i, &(m_mib, t)) in grid.iter().enumerate() {
        let params = KdfParams {
            m_kib: m_mib * 1024,
            t,
            p: 1,
        };
        let path = dir.join(format!("v{i}.sqlite"));
        let (vault, keys) = Vault::create(&path, &pw, params).unwrap();
        drop(keys);
        let mut times: Vec<Duration> = (0..5)
            .map(|_| {
                let s = Instant::now();
                drop(vault.unlock(&pw).unwrap());
                s.elapsed()
            })
            .collect();
        times.sort();
        eprintln!(
            "{m_mib:>8} {t:>3} {:>3}  {:>9.3}s  {:>9.3}s  {:>9.3}s",
            1,
            times[0].as_secs_f64(),
            times[2].as_secs_f64(),
            times[4].as_secs_f64()
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}
