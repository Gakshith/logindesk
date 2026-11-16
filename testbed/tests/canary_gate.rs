//! GATE (build plan Phase 3): the canary harness must FAIL on a planted leak and PASS on a clean run.

use std::process::Command;

use testbed::canary::{Canary, Capture};

/// A child process that leaks marker A to stderr (raw) and marker B to a temp file (base64),
/// while its stdout and a log file stay clean.
#[test]
fn planted_leak_is_caught_in_stderr_and_temp_file() {
    let canary = Canary::new(["vault.password", "mail.otp_seed", "never.leaked"]);
    let a = canary.get("vault.password").value.clone();
    let b = canary.get("mail.otp_seed").value.clone();
    let dir = tempfile::tempdir().expect("tempdir");
    let leak_file = dir.path().join("session-cache.tmp");
    let log_file = dir.path().join("daemon.log");
    std::fs::write(
        &log_file,
        "2026-11-11T12:00:00Z INFO login ok site=example.localhost status=logged_in\n",
    )
    .expect("log");

    // The "buggy build": prints a secret on stderr and base64-encodes another into a temp file.
    let out = Command::new("sh")
        .arg("-c")
        .arg(r#"printf '{"jsonrpc":"2.0","id":1,"result":{"status":"logged_in"}}\n'; printf 'debug: filled password=%s\n' "$LEAK_A" >&2; printf '%s' "$LEAK_B" | base64 > "$LEAK_FILE""#)
        .env("LEAK_A", &a)
        .env("LEAK_B", &b)
        .env("LEAK_FILE", &leak_file)
        .output()
        .expect("spawn sh");
    assert!(out.status.success());

    let mut cap = Capture::new();
    cap.text("mcp:stdout", &out.stdout)
        .text("stderr", &out.stderr)
        .file(&log_file)
        .dir(dir.path());
    let report = canary.scan(&cap);
    eprintln!("{report}");

    assert!(!report.is_clean(), "the harness missed a planted leak");
    assert!(
        report.found("vault.password", "stderr"),
        "stderr leak not caught"
    );
    assert!(
        report.found("mail.otp_seed", "session-cache.tmp"),
        "temp-file leak not caught"
    );
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.marker == "mail.otp_seed" && f.encoding.starts_with("base64")),
        "the temp-file leak should be reported as base64"
    );
    assert!(
        !report.found("never.leaked", ""),
        "false positive for a marker that was never written"
    );
    assert!(
        !report.found("vault.password", "mcp:stdout"),
        "stdout was clean"
    );
    assert!(
        !report.found("vault.password", "daemon.log"),
        "the log file was clean"
    );
    // assert_clean() must panic on this report: that is what makes CI fail.
    assert!(std::panic::catch_unwind(|| report.assert_clean()).is_err());
}

/// The same run without the leak: every channel is scanned and the report is clean.
#[test]
fn clean_run_passes() {
    let canary = Canary::new(["vault.password", "mail.otp_seed"]);
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        dir.path().join("daemon.log"),
        "INFO login ok site=example.localhost status=logged_in\n",
    )
    .expect("log");
    std::fs::write(
        dir.path().join("audit.jsonl"),
        "{\"seq\":1,\"event\":\"login\",\"site\":\"example.localhost\",\"approved\":true}\n",
    )
    .expect("audit");
    let out = Command::new("sh")
        .arg("-c")
        .arg(r#"printf '{"jsonrpc":"2.0","id":1,"result":{"status":"logged_in"}}\n'; echo 'filled password field (value withheld)' >&2"#)
        .output()
        .expect("spawn sh");
    let mut cap = Capture::new();
    cap.text("mcp:stdout", &out.stdout)
        .text("stderr", &out.stderr)
        .text("panic", "")
        .text(
            "snapshot",
            r#"[{"role":"textbox","name":"Password","value":"••••••••"}]"#,
        )
        .dir(dir.path());
    let report = canary.scan(&cap);
    eprintln!("{report}");
    assert!(report.channels_scanned >= 6);
    report.assert_clean();
}

/// Panic output is a channel too: a panic message that formats a secret is caught.
#[test]
fn panic_output_is_scanned() {
    let canary = Canary::new(["vault.key"]);
    let v = canary.get("vault.key").value.clone();
    let out = Command::new("sh")
        .arg("-c")
        .arg(r#"printf "thread 'main' panicked at src/vault.rs:42:9:\nunexpected key %s\n" "$K" >&2; exit 101"#)
        .env("K", &v)
        .output()
        .expect("spawn sh");
    let mut cap = Capture::new();
    cap.text("panic", &out.stderr);
    assert!(canary.scan(&cap).found("vault.key", "panic"));
}

/// A non-English page snapshot the way Phase 5 will capture it: AX-tree JSON with UTF-8 accents,
/// the same JSON `\u`-escaped, URL-encoded links and a form-encoded body (`%C3%A9`, `%C3%BC`, `+`).
fn non_english_snapshot() -> String {
    let labels = [
        "Adresse e-mail",
        "Mot de passe oublié ?",
        "Créer un compte",
        "Se connecter",
        "Déjà inscrit ?",
        "Préférences de sécurité",
        "Vérifiez votre boîte de réception",
        "Numéro de téléphone",
        "Passwort vergessen?",
        "Größe ändern",
        "Übersicht",
        "Zurück zur Startseite",
        "Lösung anzeigen",
        "Bestätigungscode eingeben",
        "Schließen",
        "Straße und Hausnummer",
        "Über uns",
        "Prüfen",
    ];
    let mut nodes = Vec::new();
    for (i, l) in labels.iter().cycle().take(180).enumerate() {
        let role = ["textbox", "button", "link", "StaticText", "heading"][i % 5];
        nodes.push(serde_json::json!({"ref": format!("e{i}"), "role": role, "name": l, "value": if role == "textbox" { "••••••••" } else { "" }}));
    }
    let utf8 = serde_json::to_string(
        &serde_json::json!({"url": "http://example.localhost/connexion", "nodes": nodes}),
    )
    .expect("json");
    let ascii: String = utf8
        .chars()
        .map(|c| {
            if c.is_ascii() {
                c.to_string()
            } else {
                c.encode_utf16(&mut [0; 2])
                    .iter()
                    .map(|u| format!("\\u{u:04x}"))
                    .collect()
            }
        })
        .collect();
    let mut s = format!("{utf8}\n{ascii}\n");
    for (i, l) in labels.iter().enumerate() {
        let enc: String = l
            .bytes()
            .map(|b| {
                if b.is_ascii_alphanumeric() {
                    char::from(b).to_string()
                } else if b == b' ' {
                    "+".into()
                } else {
                    format!("%{b:02X}")
                }
            })
            .collect();
        s.push_str(&format!("GET /recherche?q={enc}&page={i}&lang=fr-FR HTTP/1.1\nbody: champ={enc}&f%C3%BCr=%C3%BCber&caf%C3%A9=cr%C3%A8me\n"));
        s.push_str(&format!("GET /suche?q={} HTTP/1.1\n", enc.to_lowercase()));
    }
    s
}

#[test]
fn non_english_snapshot_is_clean() {
    let snap = non_english_snapshot();
    assert!(
        snap.len() > 20_000
            && snap.contains("\\u00e9")
            && snap.contains("%C3%A9")
            && snap.contains("%C3%BC")
            && snap.contains('é')
    );
    let mut dirty = Vec::new();
    for _ in 0..200 {
        let canary = Canary::new((0..10).map(|i| format!("m{i}")));
        let mut cap = Capture::new();
        cap.text("snapshot", &snap);
        let r = canary.scan(&cap);
        if !r.is_clean() {
            dirty.push(r.to_string());
        }
    }
    assert!(
        dirty.is_empty(),
        "{} of 200 scans falsely dirty; first:\n{}",
        dirty.len(),
        dirty[0]
    );
}

/// The leak gate still holds on the same non-English page: a marker hidden in it is found.
#[test]
fn leak_inside_non_english_snapshot_is_caught() {
    let canary = Canary::new(["vault.password"]);
    let v = canary.get("vault.password").value.clone();
    let mut snap = non_english_snapshot();
    let pos = snap.len() / 2;
    snap.insert_str(pos, &serde_json::to_string(&v).expect("json"));
    let mut cap = Capture::new();
    cap.text("snapshot", &snap);
    assert!(canary.scan(&cap).found("vault.password", "snapshot"));
}
