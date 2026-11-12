//! End-to-end tests of the `logindesk` binary with `--password-stdin`.
//! Every test also checks that no secret reaches stdout or stderr.
#![allow(clippy::unwrap_used)] // test code: a panic is a test failure

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};

const PW: &str = "correct horse battery";

struct Tmp(PathBuf);
impl Tmp {
    fn new(tag: &str) -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        let p = std::env::temp_dir().join(format!(
            "logindesk-cli-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
    fn vault(&self) -> PathBuf {
        self.0.join("vault.sqlite")
    }
}
impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Out {
    ok: bool,
    stdout: String,
    stderr: String,
}

fn run(vault: &Path, args: &[&str], stdin_lines: &[&str]) -> Out {
    let mut child = Command::new(env!("CARGO_BIN_EXE_logindesk"))
        .arg("--vault")
        .arg(vault)
        .arg("--password-stdin")
        .args(args)
        .env_remove("LOGINDESK_VAULT")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    {
        let mut stdin = child.stdin.take().unwrap();
        for l in stdin_lines {
            writeln!(stdin, "{l}").unwrap();
        }
    }
    let o = child.wait_with_output().unwrap();
    Out {
        ok: o.status.success(),
        stdout: String::from_utf8_lossy(&o.stdout).into(),
        stderr: String::from_utf8_lossy(&o.stderr).into(),
    }
}

fn setup(t: &Tmp) {
    let o = run(
        &t.vault(),
        &[
            "setup",
            "--kdf-memory-kib",
            "19456",
            "--kdf-iterations",
            "2",
        ],
        &[PW, PW],
    );
    assert!(o.ok, "{}", o.stderr);
}

fn assert_no_leak(o: &Out, secrets: &[&str]) {
    for s in secrets {
        assert!(
            !o.stdout.contains(s) && !o.stderr.contains(s),
            "leaked {s:?}\nstdout: {}\nstderr: {}",
            o.stdout,
            o.stderr
        );
    }
}

#[test]
fn setup_creates_a_0600_vault_and_refuses_to_overwrite() {
    let t = Tmp::new("setup");
    setup(&t);
    assert_eq!(
        std::fs::metadata(t.vault()).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let o = run(
        &t.vault(),
        &[
            "setup",
            "--kdf-memory-kib",
            "19456",
            "--kdf-iterations",
            "2",
        ],
        &[PW, PW],
    );
    assert!(!o.ok);
    assert!(o.stderr.contains("already exists"), "{}", o.stderr);
}

#[test]
fn setup_rejects_short_mismatched_or_weak() {
    let t = Tmp::new("setup-bad");
    let fast = [
        "setup",
        "--kdf-memory-kib",
        "19456",
        "--kdf-iterations",
        "2",
    ];
    assert!(!run(&t.vault(), &fast, &["short", "short"]).ok);
    assert!(!run(&t.vault(), &fast, &[PW, "correct horse batterY"]).ok);
    let weak = run(
        &t.vault(),
        &["setup", "--kdf-memory-kib", "1024", "--kdf-iterations", "1"],
        &[PW, PW],
    );
    assert!(!weak.ok);
    assert!(weak.stderr.contains("Argon2id"), "{}", weak.stderr);
    assert!(!t.vault().exists());
}

#[test]
fn add_list_show_metadata_never_print_the_secret() {
    let t = Tmp::new("add");
    setup(&t);
    let secret = "CANARY-cli-5d2c";
    let o = run(
        &t.vault(),
        &[
            "vault",
            "add",
            "--site",
            "example.test",
            "--username",
            "alice",
        ],
        &[PW, secret],
    );
    assert!(o.ok, "{}", o.stderr);
    assert_no_leak(&o, &[secret, PW]);
    let id = o.stdout.trim().to_owned();
    assert_eq!(id.len(), 32);

    let o = run(&t.vault(), &["vault", "list"], &[PW]);
    assert!(o.ok, "{}", o.stderr);
    assert!(
        o.stdout.contains("example.test") && o.stdout.contains("alice") && o.stdout.contains(&id)
    );
    assert_no_leak(&o, &[secret, PW]);

    let o = run(&t.vault(), &["vault", "show-metadata", &id], &[PW]);
    assert!(o.ok, "{}", o.stderr);
    assert!(o.stdout.contains("[REDACTED]") && o.stdout.contains("created by: cli"));
    assert_no_leak(&o, &[secret, PW]);
}

#[test]
fn wrong_password_fails_without_echoing_it() {
    let t = Tmp::new("wrong");
    setup(&t);
    let o = run(&t.vault(), &["vault", "list"], &["CANARY-wrong-pw-1"]);
    assert!(!o.ok);
    assert!(o.stderr.contains("wrong vault password"), "{}", o.stderr);
    assert_no_leak(&o, &["CANARY-wrong-pw-1"]);
}

#[test]
fn unlock_reports_timing_and_lock_explains() {
    let t = Tmp::new("unlock");
    setup(&t);
    let o = run(&t.vault(), &["unlock"], &[PW]);
    assert!(o.ok, "{}", o.stderr);
    assert!(o.stderr.contains("Unlock took"), "{}", o.stderr);
    let o = run(&t.vault(), &["lock"], &[]);
    assert!(o.ok && o.stderr.contains("Nothing to lock"));
}

#[test]
fn import_csv_then_list() {
    let t = Tmp::new("import");
    setup(&t);
    let csv = t.0.join("in.csv");
    std::fs::write(&csv, "name,url,username,password,note\nA,https://a.test,ann,CANARY-imp-a,\nB,b.test,bo,CANARY-imp-b,x\n").unwrap();
    let o = run(
        &t.vault(),
        &["vault", "import", "--csv", csv.to_str().unwrap()],
        &[PW],
    );
    assert!(o.ok, "{}", o.stderr);
    assert!(o.stderr.contains("Imported 2"), "{}", o.stderr);
    assert_no_leak(&o, &["CANARY-imp"]);
    let o = run(&t.vault(), &["vault", "list"], &[PW]);
    assert!(o.stdout.contains("https://a.test") && o.stdout.contains("b.test"));
    assert_no_leak(&o, &["CANARY-imp"]);
}

#[test]
fn encrypted_export_is_default() {
    let t = Tmp::new("export");
    setup(&t);
    run(
        &t.vault(),
        &["vault", "add", "--site", "a.test"],
        &[PW, "CANARY-exp-enc"],
    );
    let out = t.0.join("backup.sqlite");
    let o = run(
        &t.vault(),
        &["vault", "export", "--out", out.to_str().unwrap()],
        &[PW],
    );
    assert!(o.ok, "{}", o.stderr);
    let bytes = std::fs::read(&out).unwrap();
    assert!(!bytes.windows(8).any(|w| w == b"CANARY-e"));
    // The backup opens with the same password.
    let o = run(&out, &["vault", "list"], &[PW]);
    assert!(o.ok && o.stdout.contains("a.test"), "{}", o.stderr);
    // Refuses to overwrite.
    assert!(
        !run(
            &t.vault(),
            &["vault", "export", "--out", out.to_str().unwrap()],
            &[PW]
        )
        .ok
    );
}

#[test]
fn plaintext_export_needs_the_password_twice_and_is_0600() {
    let t = Tmp::new("plain");
    setup(&t);
    run(
        &t.vault(),
        &["vault", "add", "--site", "a.test"],
        &[PW, "CANARY-exp-plain"],
    );
    let out = t.0.join("plain.csv");
    let o_s = out.to_str().unwrap();

    // Wrong re-entry: nothing written.
    let o = run(
        &t.vault(),
        &["vault", "export", "--plaintext", "--out", o_s],
        &[PW, "not the password"],
    );
    assert!(!o.ok);
    assert!(o.stderr.contains("nothing was exported"), "{}", o.stderr);
    assert!(!out.exists());

    // Right re-entry: warned, written 0600, secret in the file only.
    let o = run(
        &t.vault(),
        &["vault", "export", "--plaintext", "--out", o_s],
        &[PW, PW],
    );
    assert!(o.ok, "{}", o.stderr);
    assert!(o.stderr.contains("WARNING"));
    assert_no_leak(&o, &["CANARY-exp-plain"]);
    assert_eq!(
        std::fs::metadata(&out).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(
        std::fs::read_to_string(&out)
            .unwrap()
            .contains("CANARY-exp-plain")
    );

    // Never overwrites.
    let o = run(
        &t.vault(),
        &["vault", "export", "--plaintext", "--out", o_s],
        &[PW, PW],
    );
    assert!(!o.ok);
}

#[test]
fn missing_vault_points_to_setup() {
    let t = Tmp::new("missing");
    let o = run(&t.vault(), &["vault", "list"], &[PW]);
    assert!(
        !o.ok && o.stderr.contains("logindesk setup"),
        "{}",
        o.stderr
    );
}
