//! Signup end to end with real headless Chrome: the broker signs up on the fake
//! site's `/signup`, reads the verification mail through `OutboxSource`, fills
//! the code, and reports `created`. Skips (with a note) when no Chrome is installed.
#![allow(clippy::unwrap_used)] // test code: a panic is a test failure

use std::sync::Arc;

use logindesk_approver::NoApprover;
use logindesk_core::SecretString;
use logindesk_daemon::browser::ChromeLauncher;
use logindesk_daemon::identity::Identity;
use logindesk_daemon::mailcfg::MailProvider;
use logindesk_daemon::proto::{Op, Request};
use logindesk_daemon::{Broker, Config, Deps};
use logindesk_executor::{BrowserConfig, ExecError, Session};
use logindesk_mail::{MailSource, OutboxSource};
use logindesk_policy::{Grants, Tier};
use logindesk_vault::{KdfParams, Vault};
use testbed::fixtures::Fixtures;
use testbed::site::{self, MailSink};

const SITE: &str = "example.localhost";
const PW: &str = "correct horse battery";

struct Outbox(String);
impl MailProvider for Outbox {
    fn current(&self) -> Option<Arc<dyn MailSource>> {
        Some(Arc::new(OutboxSource {
            base_url: self.0.clone(),
        }))
    }
}

fn chrome_available() -> bool {
    let d = tempfile::tempdir().unwrap();
    match Session::launch(&BrowserConfig {
        chrome: None,
        profile_dir: d.path().to_path_buf(),
        headless: true,
    }) {
        Ok(s) => {
            s.close();
            true
        }
        Err(ExecError::NoChrome) => false,
        Err(e) => panic!("launch: {e}"),
    }
}

fn req(op: Op) -> Request {
    Request {
        token: String::new(),
        client_name: "signup-e2e".into(),
        op,
    }
}

#[test]
fn signup_on_the_fake_site_reaches_created_with_email_verification() {
    if !chrome_available() {
        eprintln!("SKIP: no Chrome/Chromium found (set LOGINDESK_CHROME)");
        return;
    }
    let rt = tokio::runtime::Runtime::new().unwrap();
    let run = rt
        .block_on(site::start(Fixtures::random(), MailSink::LogOnly, 0))
        .unwrap();
    let base = run.site.base();

    let dir = tempfile::tempdir().unwrap();
    let vault_path = dir.path().join("vault.sqlite");
    let (vault, keys) =
        Vault::create(&vault_path, &SecretString::new(PW.into()), KdfParams::MIN).unwrap();
    let cfg = Config::for_vault(&vault_path);
    let mut g = Grants::default();
    g.signup.insert(SITE.into(), Tier::Auto);
    g.save(&cfg.grants_path).unwrap();
    Identity {
        email: "you@mail.test".into(),
        name: Some("Ann Example".into()),
    }
    .save(dir.path())
    .unwrap();
    let deps = Deps {
        approver: Box::new(NoApprover),
        launcher: Box::new(ChromeLauncher),
        mail: Box::new(Outbox(base.clone())),
    };
    let broker = Arc::new(Broker::new(cfg, deps, vault, keys).unwrap());

    let r = broker.handle(&req(Op::Signup {
        site: SITE.into(),
        url: Some(format!("{base}/signup")),
    }));
    assert_eq!(r.status, "created", "{r:?}");
    let email = r.data.as_ref().unwrap()["email_used"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(email, "you+example@mail.test");
    let sid = r.session_id.clone().unwrap();

    // The site sent exactly one verification mail, to the plus-address.
    let mails = run.site.outbox();
    assert_eq!(mails.len(), 1);
    assert_eq!(mails[0].to, email);

    // Signed in: the session is on the account page.
    let snap = broker.handle(&req(Op::Snapshot { session_id: sid }));
    assert_eq!(snap.status, "ok");
    let url = snap.data.unwrap()["url"].as_str().unwrap().to_string();
    assert!(url.ends_with("/account"), "{url}");

    // The vault holds the active record; the reply never held the password.
    let v = Vault::open(&vault_path).unwrap();
    let k = v.unlock(&SecretString::new(PW.into())).unwrap();
    let recs = v.records(&k).unwrap();
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].meta.username, email);
    assert_eq!(recs[0].meta.notes, "active");
    assert_eq!(recs[0].meta.site, format!("{base}/login"));
    let pw = recs[0].secret.expose().clone();
    assert_eq!(pw.chars().count(), 20);
    assert!(!serde_json::to_string(&r).unwrap().contains(&pw));
    let audit = std::fs::read_to_string(dir.path().join("audit.jsonl")).unwrap();
    assert!(audit.contains("\"op\":\"account_created\""));
    assert!(!audit.contains(&pw));

    // The new account logs in with the stored password.
    let mut g = Grants::load(&Grants::path_beside(&vault_path)).unwrap();
    g.login.insert(SITE.into(), Tier::Auto);
    g.save(&Grants::path_beside(&vault_path)).unwrap();
    let r = broker.handle(&req(Op::Login {
        site: SITE.into(),
        account: None,
    }));
    assert_eq!(r.status, "logged_in", "{r:?}");
    broker.shutdown();
}
