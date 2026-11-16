//! Signup: identity + generated password → pending record → fill + submit →
//! email verification → active record + `account_created` audit entry.
//!
//! The password is stored as `pending` BEFORE the form is submitted, so a
//! crash after submit never loses it. A failure before anything was submitted
//! deletes the pending record; one after keeps it (recoverable).

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use logindesk_approver::{Action, ApprovalOutcome, ApprovalRequest, ApprovalToken};
use logindesk_core::SecretString;
use logindesk_core::ids::SessionId;
use logindesk_core::status::{FailReason, NeedsUserReason, Status};
use logindesk_executor::{ExecError, PageState};
use logindesk_policy::{signup_blocked, site_of, url_site};
use logindesk_vault::{NewRecord, RecordId, RecordKind};

use super::{Broker, Outcome, account_id, exec_status, failed, lock, needs};
use crate::audit::Event;
use crate::browser::Browser;
use crate::identity::{Identity, plus_address};
use crate::password;

/// Default daily signup limit.
pub(super) const SIGNUPS_PER_DAY: usize = 10;
/// `notes` of a record whose signup is not verified yet.
pub(super) const PENDING: &str = "pending";
/// `notes` once the account is verified.
const ACTIVE: &str = "active";
/// `created_by` of signup records (the daily limit counts these).
const CREATED_BY: &str = "signup";
const DAY_SECS: u64 = 24 * 60 * 60;

/// Everything the flow needs after approval.
struct Ctx {
    client: String,
    site: String,
    /// Where the signup form is.
    start: String,
    /// What the record stores as its site (where a later login starts).
    record_site: String,
    identity: Identity,
    started: SystemTime,
}

/// How a signup ended.
struct End {
    status: Status,
    /// Keep the browser as a session (created, or the user must act in it).
    keep: bool,
    session_id: SessionId,
    record: Option<RecordId>,
}

impl End {
    fn fail(status: Status) -> Self {
        Self {
            status,
            keep: false,
            session_id: SessionId::random(),
            record: None,
        }
    }
}

fn with_message(mut o: Outcome, m: &str) -> Outcome {
    o.reply.message = Some(m.to_string());
    o
}

impl Broker {
    /// `signup{site, url?}`.
    pub(super) fn signup(
        self: &Arc<Self>,
        client: &str,
        input: &str,
        url: Option<&str>,
    ) -> Outcome {
        let started = SystemTime::now();
        let Some(site) = site_of(input) else {
            return with_message(
                Outcome::new(&failed(FailReason::Internal), ""),
                "site is not a website host or URL",
            );
        };
        if signup_blocked(&site) {
            return with_message(
                Outcome::new(&failed(FailReason::GrantDenied), site),
                "logindesk never signs up on bank, government, health, payment or email-provider sites",
            );
        }
        let (start, record_site) = match url {
            Some(u) => {
                let parsed = url::Url::parse(u).ok().filter(|p| {
                    (p.scheme() == "https" || p.scheme() == "http")
                        && url_site(p).as_deref() == Some(site.as_str())
                });
                let Some(p) = parsed else {
                    return Outcome::new(&failed(FailReason::FenceBlocked), site);
                };
                let origin = p.origin().ascii_serialization();
                (p.to_string(), format!("{origin}/login"))
            }
            None => (format!("https://{site}/signup"), site.clone()),
        };
        if !self.is_unlocked() {
            return Outcome::new(&Status::VaultLocked, site);
        }
        let identity = match Identity::load(&self.cfg.data_dir) {
            Ok(Some(i)) => i,
            Ok(None) => {
                return with_message(
                    Outcome::new(&failed(FailReason::Internal), site),
                    "run `logindesk identity set --email <you@example.com>` in a terminal, then retry",
                );
            }
            Err(e) => {
                eprintln!("logindesk: identity.json unreadable: {e}");
                return Outcome::new(&failed(FailReason::Internal), site);
            }
        };
        // Never create a second account with the user's own identity on a site:
        // a taken plus-address must not silently fall back to a duplicate account.
        let plain = identity.email.clone();
        let plus = plus_address(&plain, &site);
        match self.existing_identity_account(&site, &[plain.as_str(), plus.as_str()]) {
            Ok(Some(user)) => {
                return with_message(
                    Outcome::new(&failed(FailReason::AccountAmbiguous), site),
                    &format!(
                        "an account already exists on this site as {user}; call login instead"
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
        let tier = match self.grants() {
            Ok(g) => g.signup_tier(&site),
            Err(s) => return Outcome::new(&s, site),
        };
        let mut shares = vec!["email".to_string()];
        if identity.name.as_deref().is_some_and(|n| !n.is_empty()) {
            shares.push("name".to_string());
        }
        let ctx = Ctx {
            client: client.to_string(),
            site: site.clone(),
            start,
            record_site,
            identity,
            started,
        };
        self.gate(
            client,
            Action::Signup,
            &site,
            shares,
            tier,
            Box::new(move |b, token, req| b.signup_run(ctx, token, req)),
        )
    }

    /// A non-pending login record on `site` whose username is one of `emails`.
    fn existing_identity_account(
        &self,
        site: &str,
        emails: &[&str],
    ) -> Result<Option<String>, Status> {
        let st = lock(&self.state);
        let keys = st.keys.as_ref().ok_or(Status::VaultLocked)?;
        let metas = st.vault.list(keys).map_err(|e| {
            eprintln!("logindesk: vault list failed: {e}");
            failed(FailReason::Internal)
        })?;
        Ok(metas
            .into_iter()
            .filter(|m| m.kind == RecordKind::Login && m.notes != PENDING)
            .filter(|m| site_of(&m.site).as_deref() == Some(site))
            .find(|m| emails.iter().any(|e| m.username.eq_ignore_ascii_case(e)))
            .map(|m| m.username))
    }

    /// Signup records created in the last 24 hours (survives restarts: read from the vault).
    fn signups_today(&self) -> Result<usize, Status> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let st = lock(&self.state);
        let keys = st.keys.as_ref().ok_or(Status::VaultLocked)?;
        let metas = st.vault.list(keys).map_err(|e| {
            eprintln!("logindesk: vault list failed: {e}");
            failed(FailReason::Internal)
        })?;
        Ok(metas
            .iter()
            .filter(|m| m.created_by == CREATED_BY && now.saturating_sub(m.created_at) < DAY_SECS)
            .count())
    }

    fn signup_run(&self, c: Ctx, token: ApprovalToken, req: &ApprovalRequest) -> Outcome {
        self.close_site(&c.site);
        let mut browser = match self.launch(&c.site) {
            Ok(b) => b,
            Err(s) => return Outcome::new(&s, c.site.clone()),
        };
        let end = self.drive_signup(browser.as_mut(), &c, token, req);
        let mut out = Outcome::new(&end.status, c.site.clone());
        if end.keep {
            self.keep_session(end.session_id, &c.site, browser);
            out.reply.session_id = Some(end.session_id.to_string());
        } else {
            browser.close();
        }
        if let Some(id) = end.record {
            out.reply.account_id = account_id(&id).map(|a| a.to_string());
        }
        out
    }

    fn add_pending(&self, c: &Ctx, email: &str, pw: &SecretString) -> Result<RecordId, Status> {
        let mut st = lock(&self.state);
        let st = &mut *st;
        let keys = st.keys.as_ref().ok_or(Status::VaultLocked)?;
        st.vault
            .add(
                keys,
                NewRecord {
                    kind: RecordKind::Login,
                    site: c.record_site.clone(),
                    username: email.to_string(),
                    // The vault takes its own copy; `pw` stays for the fill.
                    secret: SecretString::new(pw.expose().clone()),
                    created_by: CREATED_BY.into(),
                    notes: PENDING.into(),
                },
            )
            .map_err(|e| {
                eprintln!("logindesk: storing the pending signup failed: {e}");
                failed(FailReason::Internal)
            })
    }

    fn update_record(&self, id: RecordId, username: Option<String>, notes: Option<String>) {
        let mut st = lock(&self.state);
        let st = &mut *st;
        let Some(keys) = st.keys.as_ref() else { return };
        if let Err(e) = st.vault.update_meta(keys, id, username, notes) {
            eprintln!("logindesk: updating the signup record failed: {e}");
        }
    }

    /// Nothing reached the site: the pending password is useless, drop it.
    fn drop_record(&self, id: RecordId) {
        let mut st = lock(&self.state);
        let st = &mut *st;
        let Some(keys) = st.keys.as_ref() else { return };
        if let Err(e) = st.vault.delete(keys, id) {
            eprintln!("logindesk: removing the unused signup record failed: {e}");
        }
    }

    fn drive_signup(
        &self,
        b: &mut dyn Browser,
        c: &Ctx,
        token: ApprovalToken,
        req: &ApprovalRequest,
    ) -> End {
        let site = c.site.as_str();
        if let Err(e) = b.navigate(&c.start) {
            return End::fail(exec_status(e));
        }
        let rules = match b.password_rules(site) {
            Ok(r) => r,
            Err(e) => return End::fail(exec_status(e)),
        };
        let pw = password::generate(rules.as_deref());
        let plain = c.identity.email.as_str();
        let plus = plus_address(plain, site);
        let name = c.identity.name.as_deref().unwrap_or("");

        // Pending BEFORE submit.
        let id = match self.add_pending(c, &plus, &pw) {
            Ok(id) => id,
            Err(s) => return End::fail(s),
        };
        let mut email_used = plus.clone();
        let mut state = match b.fill_signup(site, &plus, name, &pw, token) {
            Ok(s) => s,
            Err(e) => return self.fill_failed(id, e),
        };
        // The site refused the plus-address: once more with the plain address.
        if matches!(state, PageState::SignupForm | PageState::Rejected) && plus != plain {
            self.update_record(id, Some(plain.to_string()), None);
            if let Err(e) = b.navigate(&c.start) {
                return End {
                    record: Some(id),
                    ..End::fail(exec_status(e))
                };
            }
            // The user's approval covers this signup, including its retry.
            let Some(retry) = ApprovalToken::from_outcome(req, ApprovalOutcome::Approved) else {
                return End::fail(failed(FailReason::Internal));
            };
            state = match b.fill_signup(site, plain, name, &pw, retry) {
                Ok(s) => s,
                Err(e) => return self.fill_failed(id, e),
            };
            email_used = plain.to_string();
        }
        drop(pw);

        let state = match state {
            PageState::NeedsOtp | PageState::VerifyEmail => {
                match self.verify_by_mail(b, site, c.started) {
                    Ok(st) => st,
                    Err(s) => {
                        let keep = matches!(s, Status::NeedsUser { .. });
                        return End {
                            status: s,
                            keep,
                            session_id: SessionId::random(),
                            record: Some(id),
                        };
                    }
                }
            }
            other => other,
        };
        let pending = |status: Status, keep: bool| End {
            status,
            keep,
            session_id: SessionId::random(),
            record: Some(id),
        };
        match state {
            PageState::LoggedIn | PageState::LoginForm => {
                self.update_record(id, None, Some(ACTIVE.into()));
                let session_id = SessionId::random();
                self.audit_created(c);
                let Some(account_id) = account_id(&id) else {
                    return End::fail(failed(FailReason::Internal));
                };
                End {
                    status: Status::Created {
                        account_id,
                        session_id,
                        email_used,
                    },
                    keep: true,
                    session_id,
                    record: Some(id),
                }
            }
            // The site said no: no account exists, so the password is useless.
            PageState::SignupForm | PageState::Rejected => {
                self.drop_record(id);
                End::fail(failed(FailReason::CredentialsRejected))
            }
            PageState::Captcha => pending(needs(NeedsUserReason::Captcha), true),
            PageState::NeedsConsent | PageState::Unknown | PageState::VerifyEmail => {
                pending(needs(NeedsUserReason::UnknownPage), true)
            }
            PageState::NeedsOtp => pending(failed(FailReason::CredentialsRejected), false),
        }
    }

    /// A fill error: before submit (fence, mapping, token) nothing reached the
    /// site and the record goes; otherwise it stays pending.
    fn fill_failed(&self, id: RecordId, e: ExecError) -> End {
        let before_submit = matches!(
            e,
            ExecError::Fence | ExecError::Mapping(_) | ExecError::Token | ExecError::Refused
        );
        if before_submit {
            self.drop_record(id);
            End::fail(exec_status(e))
        } else {
            End {
                record: Some(id),
                ..End::fail(exec_status(e))
            }
        }
    }

    fn audit_created(&self, c: &Ctx) {
        let ev = Event {
            client: &c.client,
            op: "account_created",
            site: &c.site,
            status: "created",
            reason: "",
        };
        if let Err(e) = lock(&self.audit).record(&ev) {
            eprintln!("logindesk: audit write failed: {e}");
        }
    }
}
