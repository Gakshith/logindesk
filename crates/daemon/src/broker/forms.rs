//! Agent-driven forms (contract §12): `open`, `type`, `fill_secret`, `press_enter`.
//!
//! The agent drives the page step by step (snapshot, type, click, press Enter);
//! the broker fills only the secrets, into the field ref the agent names. The
//! agent never sees a password or code, and cannot type one: the executor
//! refuses text in password and code fields.
//!
//! Gates, per session (all reset when the session closes):
//! - `password`: the login tier (deny / ask / auto). One approval covers that
//!   session and that account.
//! - `code`: the login tier, once per session; needs a connected mailbox.
//! - `email`, `new_password`: the signup tier and the signup blocklist, one
//!   approval per session. `new_password` also refuses a second account for the
//!   identity and applies the daily limit, stores the generated password as a
//!   pending record before filling it, and reuses it for the confirm box.
//! - On close, a pending record is confirmed (active, `account_created`) unless
//!   the page is still a signup form, in which case it stays pending.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::SystemTime;

use logindesk_approver::{Action, ApprovalToken};
use logindesk_core::SecretString;
use logindesk_core::ids::{AccountId, SessionId};
use logindesk_core::limits::OTP_LOOKBACK;
use logindesk_core::status::{FailReason, Status};
use logindesk_executor::{ExecError, PageState, SecretField};
use logindesk_policy::{signup_blocked, url_site};
use logindesk_vault::RecordId;
use serde_json::json;

use super::signup::ACTIVE;
use super::{
    Broker, MailSecret, OTP_SINCE_SLACK, Outcome, Slot, account_id, exec_status, failed,
    link_on_site, lock,
};
use crate::identity::{Identity, plus_address};
use crate::password;
use crate::proto::{MAX_TYPE_CHARS, SecretKind};

/// The fill that runs once a form gate is passed.
type FormRun = Box<dyn FnOnce(&Broker, &Slot) -> Outcome + Send>;

/// A generated password waiting for the signup to complete.
struct PendingPw {
    record: RecordId,
    password: SecretString,
    client: String,
}

/// Per-session state of agent-driven forms.
pub(super) struct FormState {
    opened_at: SystemTime,
    approved_accounts: HashSet<AccountId>,
    code_approved: bool,
    signup_approved: bool,
    email_used: Option<String>,
    pending: Option<PendingPw>,
}

impl FormState {
    pub(super) fn new() -> Self {
        Self {
            opened_at: SystemTime::now(),
            approved_accounts: HashSet::new(),
            code_approved: false,
            signup_approved: false,
            email_used: None,
            pending: None,
        }
    }
}

fn ok(site: &str) -> Outcome {
    Outcome::new(&Status::Ok, site)
}

fn with_message(mut o: Outcome, m: &str) -> Outcome {
    o.reply.message = Some(m.to_string());
    o
}

fn http_site(url: &str) -> Option<(url::Url, String)> {
    let u = url::Url::parse(url).ok()?;
    if u.scheme() != "https" && u.scheme() != "http" {
        return None;
    }
    let site = url_site(&u)?;
    Some((u, site))
}

impl Broker {
    /// `open{url}`: a new session on the URL's site. No secret, no prompt.
    pub(super) fn open(&self, url: &str) -> Outcome {
        let Some((u, site)) = http_site(url) else {
            return Outcome::new(&failed(FailReason::FenceBlocked), "");
        };
        self.close_site(&site);
        let mut b = match self.launch(&site) {
            Ok(b) => b,
            Err(s) => return Outcome::new(&s, site),
        };
        if let Err(e) = b.navigate(u.as_str()) {
            b.close();
            return Outcome::new(&exec_status(e), site);
        }
        let now = b.current_url().unwrap_or_default();
        let id = SessionId::random();
        self.keep_session(id, &site, b);
        let mut o = ok(&site);
        o.reply.session_id = Some(id.to_string());
        o.reply.data = Some(json!({ "url": now }));
        o
    }

    /// `type{session_id, ref, text}`. The text is never logged or audited.
    pub(super) fn type_text(&self, session_id: &str, node_ref: u64, text: &str) -> Outcome {
        if text.chars().count() > MAX_TYPE_CHARS {
            return with_message(
                Outcome::new(&failed(FailReason::Internal), ""),
                "text is longer than 512 characters",
            );
        }
        let (r, site) = self.with_browser(session_id, |b, site| {
            b.type_text(site, node_ref, text).map_err(exec_status)
        });
        match r {
            Ok(()) => ok(&site),
            Err(s) => Outcome::new(&s, site),
        }
    }

    /// `press_enter{session_id, ref}`.
    pub(super) fn press_enter(&self, session_id: &str, node_ref: u64) -> Outcome {
        let (r, site) = self.with_browser(session_id, |b, site| {
            b.press_enter_at(site, node_ref).map_err(exec_status)?;
            b.current_url().map_err(exec_status)
        });
        match r {
            Ok(url) => {
                let mut o = ok(&site);
                o.reply.data = Some(json!({ "url": url }));
                o
            }
            Err(s) => Outcome::new(&s, site),
        }
    }

    /// `fill_secret{session_id, ref, secret, account?}`.
    pub(super) fn fill_secret(
        self: &Arc<Self>,
        client: &str,
        session_id: &str,
        node_ref: u64,
        kind: SecretKind,
        account: Option<&str>,
    ) -> Outcome {
        let slot = match self.slot(session_id) {
            Ok(s) => s,
            Err(s) => return Outcome::new(&s, ""),
        };
        match kind {
            SecretKind::Password => self.fill_password(client, slot, node_ref, account),
            SecretKind::Code => self.fill_code(client, slot, node_ref),
            SecretKind::Email => self.fill_email(client, slot, node_ref),
            SecretKind::NewPassword => self.fill_new_password(client, slot, node_ref),
        }
    }

    /// Fill `value` into the field `node_ref` of the slot's page.
    fn fill_into(
        &self,
        slot: &Slot,
        node_ref: u64,
        field: SecretField,
        value: &SecretString,
    ) -> Result<(), Status> {
        slot.touch();
        let mut g = lock(&slot.browser);
        let b = g.as_mut().ok_or(failed(FailReason::SessionNotFound))?;
        b.fill_at(&slot.site, node_ref, field, value)
            .map_err(exec_status)
    }

    fn fill_password(
        self: &Arc<Self>,
        client: &str,
        slot: Arc<Slot>,
        node_ref: u64,
        account: Option<&str>,
    ) -> Outcome {
        let site = slot.site.clone();
        if !self.is_unlocked() {
            return Outcome::new(&Status::VaultLocked, site);
        }
        let creds = match self.creds(&site, account) {
            Ok(c) => c,
            Err(s) => return Outcome::new(&s, site),
        };
        let acct = creds.account_id;
        let run = move |b: &Broker, slot: &Slot| {
            let mut o = match b.fill_into(slot, node_ref, SecretField::Password, &creds.password) {
                Ok(()) => ok(&slot.site),
                Err(s) => Outcome::new(&s, slot.site.clone()),
            };
            o.reply.account_id = acct.map(|a| a.to_string());
            o
        };
        let approved = acct.is_some_and(|a| lock(&slot.forms).approved_accounts.contains(&a));
        if approved {
            return run(self, &slot);
        }
        let tier = match self.grants() {
            Ok(g) => g.login_tier(&site),
            Err(s) => return Outcome::new(&s, site),
        };
        let s2 = site.clone();
        self.gate(
            client,
            Action::Login,
            &site,
            Vec::new(),
            tier,
            Box::new(move |b, token, _req| {
                if let Err(o) = spend(token, Action::Login, &s2) {
                    return *o;
                }
                if let Some(a) = acct {
                    lock(&slot.forms).approved_accounts.insert(a);
                }
                run(b, &slot)
            }),
        )
    }

    fn fill_code(self: &Arc<Self>, client: &str, slot: Arc<Slot>, node_ref: u64) -> Outcome {
        let site = slot.site.clone();
        // Cheap pre-check before any prompt: without a mailbox there is no code.
        if self.deps.mail.current().is_none() {
            return Outcome::new(&Status::EmailNotConnected, site);
        }
        let run = move |b: &Broker, slot: &Slot| {
            let opened = lock(&slot.forms).opened_at;
            let floor = SystemTime::now()
                .checked_sub(OTP_LOOKBACK)
                .unwrap_or(SystemTime::UNIX_EPOCH);
            let since = opened
                .checked_sub(OTP_SINCE_SLACK)
                .unwrap_or(SystemTime::UNIX_EPOCH)
                .max(floor);
            match b.next_mail_secret(&slot.site, since) {
                Ok(MailSecret::Code(code)) => {
                    match b.fill_into(slot, node_ref, SecretField::Code, &code) {
                        Ok(()) => ok(&slot.site),
                        Err(s) => Outcome::new(&s, slot.site.clone()),
                    }
                }
                // The mail held a link instead of a code: open it (on the site only).
                Ok(MailSecret::Link(link)) => {
                    if !link_on_site(&link, &slot.site) {
                        return Outcome::new(&failed(FailReason::FenceBlocked), slot.site.clone());
                    }
                    let r = match lock(&slot.browser).as_mut() {
                        Some(br) => br.navigate(link.expose()).map_err(exec_status),
                        None => Err(failed(FailReason::SessionNotFound)),
                    };
                    match r {
                        Ok(()) => with_message(
                            ok(&slot.site),
                            "the email held a link, not a code; it was opened in this session. Take a snapshot.",
                        ),
                        Err(s) => Outcome::new(&s, slot.site.clone()),
                    }
                }
                Err(s) => Outcome::new(&s, slot.site.clone()),
            }
        };
        if lock(&slot.forms).code_approved {
            return run(self, &slot);
        }
        let tier = match self.grants() {
            Ok(g) => g.login_tier(&site),
            Err(s) => return Outcome::new(&s, site),
        };
        let s2 = site.clone();
        self.gate(
            client,
            Action::Login,
            &site,
            Vec::new(),
            tier,
            Box::new(move |b, token, _req| {
                if let Err(o) = spend(token, Action::Login, &s2) {
                    return *o;
                }
                lock(&slot.forms).code_approved = true;
                run(b, &slot)
            }),
        )
    }

    /// Checks shared by `email` and `new_password`, before any prompt.
    fn signup_precheck(&self, site: &str) -> Result<Identity, Box<Outcome>> {
        if signup_blocked(site) {
            return Err(Box::new(with_message(
                Outcome::new(&failed(FailReason::GrantDenied), site),
                "logindesk never signs up on bank, government, health, payment or email-provider sites",
            )));
        }
        match Identity::load(&self.cfg.data_dir) {
            Ok(Some(i)) => Ok(i),
            Ok(None) => Err(Box::new(with_message(
                Outcome::new(&failed(FailReason::Internal), site),
                "run `logindesk identity set --email <you@example.com>` in a terminal, then retry",
            ))),
            Err(e) => {
                eprintln!("logindesk: identity.json unreadable: {e}");
                Err(Box::new(Outcome::new(&failed(FailReason::Internal), site)))
            }
        }
    }

    /// Run `run` behind the session's signup approval (asked at most once per session).
    fn signup_gated(self: &Arc<Self>, client: &str, slot: Arc<Slot>, run: FormRun) -> Outcome {
        if lock(&slot.forms).signup_approved {
            return run(self, &slot);
        }
        let site = slot.site.clone();
        let tier = match self.grants() {
            Ok(g) => g.signup_tier(&site),
            Err(s) => return Outcome::new(&s, site),
        };
        let s2 = site.clone();
        self.gate(
            client,
            Action::Signup,
            &site,
            vec!["email".to_string()],
            tier,
            Box::new(move |b, token, _req| {
                if let Err(o) = spend(token, Action::Signup, &s2) {
                    return *o;
                }
                lock(&slot.forms).signup_approved = true;
                run(b, &slot)
            }),
        )
    }

    fn fill_email(self: &Arc<Self>, client: &str, slot: Arc<Slot>, node_ref: u64) -> Outcome {
        let identity = match self.signup_precheck(&slot.site) {
            Ok(i) => i,
            Err(o) => return *o,
        };
        let email = plus_address(&identity.email, &slot.site);
        let run = Box::new(move |b: &Broker, slot: &Slot| {
            let value = SecretString::new(email.clone());
            if let Err(s) = b.fill_into(slot, node_ref, SecretField::Email, &value) {
                return Outcome::new(&s, slot.site.clone());
            }
            let pending = {
                let mut f = lock(&slot.forms);
                f.email_used = Some(email.clone());
                f.pending.as_ref().map(|p| p.record)
            };
            if let Some(id) = pending {
                b.update_record(id, Some(email.clone()), None);
            }
            let mut o = ok(&slot.site);
            o.reply.data = Some(json!({ "email_used": email }));
            o
        });
        self.signup_gated(client, slot, run)
    }

    fn fill_new_password(
        self: &Arc<Self>,
        client: &str,
        slot: Arc<Slot>,
        node_ref: u64,
    ) -> Outcome {
        let site = slot.site.clone();
        // The confirm box: the same password again, no new record, no new prompt.
        let again = lock(&slot.forms)
            .pending
            .as_ref()
            .map(|p| (p.record, SecretString::new(p.password.expose().clone())));
        if let Some((id, pw)) = again {
            let mut o = match self.fill_into(&slot, node_ref, SecretField::Password, &pw) {
                Ok(()) => ok(&site),
                Err(s) => Outcome::new(&s, site),
            };
            o.reply.account_id = account_id(&id).map(|a| a.to_string());
            return o;
        }
        if !self.is_unlocked() {
            return Outcome::new(&Status::VaultLocked, site);
        }
        let identity = match self.signup_precheck(&site) {
            Ok(i) => i,
            Err(o) => return *o,
        };
        let plain = identity.email.clone();
        let plus = plus_address(&plain, &site);
        match self.existing_identity_account(&site, &[plain.as_str(), plus.as_str()]) {
            Ok(Some(user)) => {
                return with_message(
                    Outcome::new(&failed(FailReason::AccountAmbiguous), site),
                    &format!(
                        "an account already exists on this site as {user}; use fill_secret password instead"
                    ),
                );
            }
            Ok(None) => {}
            Err(s) => return Outcome::new(&s, site),
        }
        match self.signups_today() {
            Ok(n) if n >= self.cfg.signups_per_day => {
                return Outcome::new(&failed(FailReason::RateLimited), site);
            }
            Ok(_) => {}
            Err(s) => return Outcome::new(&s, site),
        }
        let client2 = client.to_string();
        let run = Box::new(move |b: &Broker, slot: &Slot| {
            b.new_password_run(&client2, slot, node_ref, &plus)
        });
        self.signup_gated(client, slot, run)
    }

    /// After approval: generate (page rules), store pending, fill.
    fn new_password_run(&self, client: &str, slot: &Slot, node_ref: u64, plus: &str) -> Outcome {
        let site = slot.site.as_str();
        let (rules, here) = {
            let mut g = lock(&slot.browser);
            let Some(b) = g.as_mut() else {
                return Outcome::new(&failed(FailReason::SessionNotFound), site);
            };
            let rules = match b.password_rules(site) {
                Ok(r) => r,
                Err(e) => return Outcome::new(&exec_status(e), site),
            };
            (rules, b.current_url().unwrap_or_default())
        };
        let pw = password::generate(rules.as_deref());
        // A later login starts at the site's /login on the same origin.
        let record_site = url::Url::parse(&here)
            .ok()
            .map(|u| format!("{}/login", u.origin().ascii_serialization()))
            .unwrap_or_else(|| site.to_string());
        let email = lock(&slot.forms)
            .email_used
            .clone()
            .unwrap_or_else(|| plus.to_string());
        // Pending BEFORE the password goes into the page.
        let id = match self.store_pending(&record_site, &email, &pw) {
            Ok(id) => id,
            Err(s) => return Outcome::new(&s, site),
        };
        let copy = SecretString::new(pw.expose().clone());
        lock(&slot.forms).pending = Some(PendingPw {
            record: id,
            password: copy,
            client: client.to_string(),
        });
        let mut o = match self.fill_into(slot, node_ref, SecretField::Password, &pw) {
            Ok(()) => ok(site),
            Err(s) => {
                // Refused / fenced / unmapped: nothing reached the page; forget it.
                lock(&slot.forms).pending = None;
                self.drop_record(id);
                return Outcome::new(&s, site);
            }
        };
        o.reply.account_id = account_id(&id).map(|a| a.to_string());
        o
    }

    /// Close a session; first confirm its pending signup unless the page is
    /// still a signup form (then it stays pending: the password is never lost).
    pub(super) fn close_slot(&self, slot: &Slot) {
        let pending = lock(&slot.forms).pending.take();
        if let Some(p) = pending {
            let state = lock(&slot.browser).as_mut().map(|b| b.page_state());
            match state {
                Some(Ok(PageState::SignupForm)) | Some(Err(_)) | None => {}
                Some(Ok(_)) => {
                    self.update_record(p.record, None, Some(ACTIVE.into()));
                    self.audit_account_created(&p.client, &slot.site);
                }
            }
        }
        slot.close();
    }
}

/// Spend a token for `action` on `site`, or the `grant_denied` outcome.
fn spend(token: ApprovalToken, action: Action, site: &str) -> Result<(), Box<Outcome>> {
    token
        .spend(action, site)
        .map(|_| ())
        .map_err(|_| Box::new(Outcome::new(&super::exec_status(ExecError::Token), site)))
}
