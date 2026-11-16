//! The broker: one request in, one [`Reply`] out. Holds the vault keys for the
//! daemon's lifetime (like ssh-agent) so the agent never waits on the user.
//!
//! Locking: `state` is held only for short, in-memory work. The approval
//! prompt, browser launch, page loads and the OTP wait run without it. Each
//! browser has its own lock, so one slow page does not stall other sessions.
//!
//! Every login and signup passes the approval [`gate`]: `auto` and `deny`
//! answer at once; `ask` prompts on its own thread so an unanswered prompt
//! becomes an `awaiting_approval` handle the agent can `wait` on.

mod gate;
mod signup;

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime};

use logindesk_approver::{Action, ApprovalToken, Approver};
use logindesk_core::SecretString;
use logindesk_core::ids::{AccountId, Handle, RequestId, SessionId};
use logindesk_core::limits::{
    APPROVAL_IN_CALL, APPROVAL_WAIT_MAX, OTP_POLL_EVERY, OTP_WAIT_MAX, SESSION_IDLE_CLOSE,
};
use logindesk_core::status::{FailReason, NeedsUserReason, Status};
use logindesk_executor::{BrowserConfig, ExecError, PageState};
use logindesk_mail::{MailError, MailQuery, MailSource, OtpOutcome, UsedCodes, extract_otp};
use logindesk_policy::{Grants, site_of, url_site};
use logindesk_vault::{Keys, RecordKind, Vault};
use serde_json::json;

use crate::audit::{Audit, Event};
use crate::browser::{Browser, Launcher};
use crate::mailcfg::MailProvider;
use crate::proto::{Op, Reply, Request};

/// How far before the login started an emailed code may have arrived.
const OTP_SINCE_SLACK: Duration = Duration::from_secs(30);

/// Broker settings.
#[derive(Debug, Clone)]
pub struct Config {
    /// `<data dir>`: socket, token, audit, profiles, mail.json.
    pub data_dir: PathBuf,
    /// `grants.json` (beside the vault).
    pub grants_path: PathBuf,
    /// Headless Chrome unless false.
    pub headless: bool,
    /// Chrome binary override.
    pub chrome: Option<PathBuf>,
    /// Wipe the keys after this long with no request. `None` = never.
    pub lock_after: Option<Duration>,
    /// OTP poll interval.
    pub otp_poll_every: Duration,
    /// OTP wait limit.
    pub otp_wait_max: Duration,
    /// Idle browser sessions close after this.
    pub idle_close: Duration,
    /// How long a call blocks on an `ask` prompt before returning a handle.
    pub approval_in_call: Duration,
    /// How long an `ask` prompt stays open in all.
    pub approval_wait_max: Duration,
    /// Most signups in any 24 hours.
    pub signups_per_day: usize,
}

impl Config {
    /// Defaults from `logindesk_core::limits` for a vault at `vault_path`,
    /// with the data dir beside it.
    pub fn for_vault(vault_path: &Path) -> Self {
        let data_dir = vault_path
            .parent()
            .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
        Self {
            grants_path: Grants::path_beside(vault_path),
            data_dir,
            headless: true,
            chrome: None,
            lock_after: None,
            otp_poll_every: OTP_POLL_EVERY,
            otp_wait_max: OTP_WAIT_MAX,
            idle_close: SESSION_IDLE_CLOSE,
            approval_in_call: APPROVAL_IN_CALL,
            approval_wait_max: APPROVAL_WAIT_MAX,
            signups_per_day: signup::SIGNUPS_PER_DAY,
        }
    }
}

/// What the broker needs from outside.
pub struct Deps {
    /// Asks the user (`MacApprover` / `NoApprover`; `Scripted` in tests).
    pub approver: Box<dyn Approver>,
    /// Starts browsers.
    pub launcher: Box<dyn Launcher>,
    /// The mailbox, re-read on every login.
    pub mail: Box<dyn MailProvider>,
}

impl std::fmt::Debug for Deps {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Deps").finish_non_exhaustive()
    }
}

/// One live browser session.
struct Slot {
    site: String,
    browser: Mutex<Option<Box<dyn Browser>>>,
    last_used: Mutex<Instant>,
}

impl Slot {
    fn touch(&self) {
        *lock(&self.last_used) = Instant::now();
    }
    fn idle_for(&self, now: Instant) -> Duration {
        now.saturating_duration_since(*lock(&self.last_used))
    }
    fn close(&self) {
        if let Some(b) = lock(&self.browser).take() {
            b.close();
        }
    }
}

struct State {
    vault: Vault,
    keys: Option<Keys>,
    last_request: Instant,
    sessions: HashMap<SessionId, Arc<Slot>>,
    by_site: HashMap<String, SessionId>,
    spent: HashSet<RequestId>,
}

/// The broker.
pub struct Broker {
    cfg: Config,
    deps: Deps,
    state: Mutex<State>,
    used_codes: Mutex<UsedCodes>,
    audit: Mutex<Audit>,
    pending: Mutex<HashMap<Handle, Arc<gate::Pending>>>,
}

impl std::fmt::Debug for Broker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Broker")
            .field("data_dir", &self.cfg.data_dir)
            .finish_non_exhaustive()
    }
}

/// A poisoned lock only means another thread panicked mid-request; the data
/// it guards (maps, a file handle) is still usable.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn failed(reason: FailReason) -> Status {
    Status::Failed { reason }
}

fn needs(reason: NeedsUserReason) -> Status {
    Status::NeedsUser { reason }
}

/// `ExecError` → status (contract mapping).
pub fn exec_status(e: ExecError) -> Status {
    match e {
        ExecError::Fence => failed(FailReason::FenceBlocked),
        ExecError::Unreachable => failed(FailReason::SiteUnreachable),
        ExecError::Timeout => failed(FailReason::Timeout),
        ExecError::Mapping(m) => {
            // The agent sees only field_mapping_failed; the sub-reason (a fixed tag,
            // never a field value) goes to stderr and the audit line.
            eprintln!("logindesk: field mapping failed: {}", m.wire());
            crate::audit::note_map_fail(m.wire());
            failed(FailReason::FieldMappingFailed)
        }
        ExecError::Token => failed(FailReason::GrantDenied),
        ExecError::NoChrome | ExecError::Protocol | ExecError::Browser(_) => {
            failed(FailReason::Internal)
        }
    }
}

/// A login record's id as the public account id (same 32 hex chars).
fn account_id(id: &logindesk_vault::RecordId) -> Option<AccountId> {
    id.to_string().parse().ok()
}

/// Where a login starts: the record's site if it is a URL, else `https://<site>/login`.
fn start_url(record_site: &str) -> String {
    let t = record_site.trim();
    if t.contains("://") {
        t.to_string()
    } else {
        format!("https://{}/login", t.trim_end_matches('/'))
    }
}

/// Outcome of one handled request, for the reply and the audit line.
struct Outcome {
    reply: Reply,
    site: String,
}

impl Outcome {
    fn new(status: &Status, site: impl Into<String>) -> Self {
        Self {
            reply: status.into(),
            site: site.into(),
        }
    }
}

/// Credentials pulled out of the vault for one login. Dropped (and zeroized)
/// as soon as the fill returns.
struct Creds {
    username: String,
    password: SecretString,
    record_site: String,
    account_id: Option<AccountId>,
}

impl Broker {
    /// A broker over an unlocked vault.
    pub fn new(cfg: Config, deps: Deps, vault: Vault, keys: Keys) -> std::io::Result<Self> {
        let audit = Audit::open(&cfg.data_dir.join("audit.jsonl"))?;
        Ok(Self {
            cfg,
            deps,
            state: Mutex::new(State {
                vault,
                keys: Some(keys),
                last_request: Instant::now(),
                sessions: HashMap::new(),
                by_site: HashMap::new(),
                spent: HashSet::new(),
            }),
            used_codes: Mutex::new(UsedCodes::default()),
            audit: Mutex::new(audit),
            pending: Mutex::new(HashMap::new()),
        })
    }

    /// Settings.
    pub fn config(&self) -> &Config {
        &self.cfg
    }

    /// True while the keys are held.
    pub fn is_unlocked(&self) -> bool {
        lock(&self.state).keys.is_some()
    }

    /// Handle one parsed, already-authenticated request.
    pub fn handle(self: &Arc<Self>, req: &Request) -> Reply {
        lock(&self.state).last_request = Instant::now();
        let out = match &req.op {
            Op::Ping => Outcome::new(&Status::Ok, ""),
            Op::Lock => {
                self.lock_keys();
                Outcome::new(&Status::Ok, "")
            }
            Op::ListAccounts { site } => self.list_accounts(site.as_deref()),
            Op::Login { site, account } => self.login(&req.client_name, site, account.as_deref()),
            Op::Snapshot { session_id } => self.snapshot(session_id),
            Op::Navigate { session_id, url } => self.navigate(session_id, url),
            Op::Click {
                session_id,
                node_ref,
            } => self.click(session_id, *node_ref),
            Op::CloseSession { session_id } => self.close_session(session_id),
            Op::Signup { site, url } => self.signup(&req.client_name, site, url.as_deref()),
            Op::Wait { handle } => self.wait(handle),
        };
        self.audit(&req.client_name, req.op.name(), &out.site, &out.reply);
        out.reply
    }

    /// Record a request the server refused before it reached `handle`.
    pub fn audit_refused(&self, client: &str, op: &str, reply: &Reply) {
        self.audit(client, op, "", reply);
    }

    fn audit(&self, client: &str, op: &str, site: &str, reply: &Reply) {
        let ev = Event {
            client,
            op,
            site,
            status: &reply.status,
            reason: reply.reason.as_deref().unwrap_or(""),
        };
        if let Err(e) = lock(&self.audit).record(&ev) {
            eprintln!("logindesk: audit write failed: {e}");
        }
    }

    /// Drop the keys (zeroized on drop).
    pub fn lock_keys(&self) {
        let keys = lock(&self.state).keys.take();
        drop(keys);
    }

    /// Periodic housekeeping: close idle sessions and apply `lock_after`.
    /// `now` is a parameter so tests can move time.
    pub fn tick(&self, now: Instant) {
        let idle: Vec<Arc<Slot>> = {
            let mut st = lock(&self.state);
            if let Some(after) = self.cfg.lock_after
                && st.keys.is_some()
                && now.saturating_duration_since(st.last_request) > after
            {
                st.keys = None;
                eprintln!(
                    "logindesk: no request for {} min; keys wiped",
                    after.as_secs() / 60
                );
            }
            let gone: Vec<SessionId> = st
                .sessions
                .iter()
                .filter(|(_, s)| s.idle_for(now) > self.cfg.idle_close)
                .map(|(id, _)| *id)
                .collect();
            gone.iter()
                .filter_map(|id| Self::forget(&mut st, id))
                .collect()
        };
        for s in idle {
            s.close();
        }
        self.purge_pending(now);
    }

    /// Close every session (daemon shutdown).
    pub fn shutdown(&self) {
        let all: Vec<Arc<Slot>> = {
            let mut st = lock(&self.state);
            st.by_site.clear();
            st.sessions.drain().map(|(_, s)| s).collect()
        };
        for s in all {
            s.close();
        }
        self.lock_keys();
    }

    fn forget(st: &mut State, id: &SessionId) -> Option<Arc<Slot>> {
        let slot = st.sessions.remove(id)?;
        if st.by_site.get(&slot.site) == Some(id) {
            st.by_site.remove(&slot.site);
        }
        Some(slot)
    }

    fn list_accounts(&self, site: Option<&str>) -> Outcome {
        let want = match site {
            Some(s) => match site_of(s) {
                Some(d) => Some(d),
                None => return Outcome::new(&failed(FailReason::NoAccount), ""),
            },
            None => None,
        };
        let st = lock(&self.state);
        let Some(keys) = st.keys.as_ref() else {
            return Outcome::new(&Status::VaultLocked, want.unwrap_or_default());
        };
        let metas = match st.vault.list(keys) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("logindesk: vault list failed: {e}");
                return Outcome::new(&failed(FailReason::Internal), want.unwrap_or_default());
            }
        };
        let mut rows: Vec<serde_json::Value> = metas
            .iter()
            .filter(|m| m.kind == RecordKind::Login)
            .filter_map(|m| {
                let d = site_of(&m.site)?;
                if want.as_deref().is_some_and(|w| w != d) {
                    return None;
                }
                let mut row = json!({
                    "account_id": account_id(&m.id)?.to_string(),
                    "site": d,
                    "username": m.username,
                });
                if m.notes == signup::PENDING {
                    row["pending"] = true.into();
                }
                Some(row)
            })
            .collect();
        rows.sort_by_key(ToString::to_string);
        let mut o = Outcome::new(&Status::Ok, want.unwrap_or_default());
        o.reply = o.reply.with_data(json!({ "accounts": rows }));
        o
    }

    /// Pick the one login record for `site`.
    fn creds(&self, site: &str, account: Option<&str>) -> Result<Creds, Status> {
        let st = lock(&self.state);
        let keys = st.keys.as_ref().ok_or(Status::VaultLocked)?;
        let records = st.vault.records(keys).map_err(|e| {
            eprintln!("logindesk: vault read failed: {e}");
            failed(FailReason::Internal)
        })?;
        drop(st);
        let mut matches: Vec<_> = records
            .into_iter()
            .filter(|r| r.meta.kind == RecordKind::Login)
            .filter(|r| site_of(&r.meta.site).as_deref() == Some(site))
            .filter(|r| {
                account.is_none_or(|a| {
                    r.meta.username == a || r.meta.id.to_string() == a.to_ascii_lowercase()
                })
            })
            .collect();
        match matches.len() {
            0 => Err(failed(FailReason::NoAccount)),
            1 => {
                let r = matches.remove(0);
                Ok(Creds {
                    account_id: account_id(&r.meta.id),
                    username: r.meta.username,
                    record_site: r.meta.site,
                    password: r.secret,
                })
            }
            _ => Err(failed(FailReason::AccountAmbiguous)),
        }
    }

    /// grants.json, re-read on every request.
    fn grants(&self) -> Result<Grants, Status> {
        Grants::load(&self.cfg.grants_path).map_err(|e| {
            eprintln!("logindesk: grants.json unreadable: {e}");
            failed(FailReason::Internal)
        })
    }

    /// Close any live session for `site` (one profile dir = one Chrome).
    fn close_site(&self, site: &str) {
        let old = {
            let mut st = lock(&self.state);
            st.by_site
                .get(site)
                .copied()
                .and_then(|id| Self::forget(&mut st, &id))
        };
        if let Some(s) = old {
            s.close();
        }
    }

    fn launch(&self, site: &str) -> Result<Box<dyn Browser>, Status> {
        let profile_dir = self.cfg.data_dir.join("profiles").join(site);
        if let Err(e) = std::fs::create_dir_all(&profile_dir) {
            eprintln!("logindesk: cannot create profile dir: {e}");
            return Err(failed(FailReason::Internal));
        }
        let cfg = BrowserConfig {
            chrome: self.cfg.chrome.clone(),
            profile_dir,
            headless: self.cfg.headless,
        };
        self.deps.launcher.launch(&cfg).map_err(|e| {
            eprintln!("logindesk: browser launch failed: {e}");
            exec_status(e)
        })
    }

    fn login(self: &Arc<Self>, client: &str, input: &str, account: Option<&str>) -> Outcome {
        let started = SystemTime::now();
        let Some(site) = site_of(input) else {
            return Outcome::new(&failed(FailReason::NoAccount), "");
        };
        if !self.is_unlocked() {
            return Outcome::new(&Status::VaultLocked, site);
        }
        let creds = match self.creds(&site, account) {
            Ok(c) => c,
            Err(s) => return Outcome::new(&s, site),
        };
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
            Box::new(move |b, token, _req| b.login_run(&s2, creds, token, started)),
        )
    }

    /// The login after approval: browser, fill, emailed code, session.
    fn login_run(
        &self,
        site: &str,
        creds: Creds,
        token: ApprovalToken,
        started: SystemTime,
    ) -> Outcome {
        self.close_site(site);
        let mut browser = match self.launch(site) {
            Ok(b) => b,
            Err(s) => return Outcome::new(&s, site),
        };
        let status = self.drive_login(browser.as_mut(), site, creds_ref(&creds), token, started);
        let account_id = creds.account_id;
        drop(creds); // zeroizes the password now, not at end of scope

        let keep = matches!(status, Status::LoggedIn { .. } | Status::NeedsUser { .. });
        let mut out = Outcome::new(&status, site);
        if keep {
            let id = match &status {
                Status::LoggedIn { session_id } => *session_id,
                _ => SessionId::random(),
            };
            self.keep_session(id, site, browser);
            out.reply.session_id = Some(id.to_string());
        } else {
            browser.close();
        }
        out.reply.account_id = account_id.map(|a| a.to_string());
        out
    }

    /// Register a live browser as session `id` for `site`.
    fn keep_session(&self, id: SessionId, site: &str, browser: Box<dyn Browser>) {
        let slot = Arc::new(Slot {
            site: site.to_string(),
            browser: Mutex::new(Some(browser)),
            last_used: Mutex::new(Instant::now()),
        });
        let mut st = lock(&self.state);
        st.sessions.insert(id, slot);
        st.by_site.insert(site.to_string(), id);
    }

    /// Navigate, fill, and follow an emailed code if the site asks for one.
    fn drive_login(
        &self,
        b: &mut dyn Browser,
        site: &str,
        c: CredsRef<'_>,
        token: ApprovalToken,
        started: SystemTime,
    ) -> Status {
        if let Err(e) = b.navigate(&start_url(c.record_site)) {
            return exec_status(e);
        }
        let state = match b.fill_login(site, c.username, c.password, token) {
            Ok(s) => s,
            Err(e) => return exec_status(e),
        };
        match state {
            PageState::NeedsOtp => match self.verify_by_mail(b, site, started) {
                Ok(st) => page_status(st),
                Err(s) => s,
            },
            other => page_status(other),
        }
    }

    /// Poll the mailbox for the code or link the site just sent, and use it.
    /// `Ok` is the page state afterwards; `Err` a terminal status.
    fn verify_by_mail(
        &self,
        b: &mut dyn Browser,
        site: &str,
        started: SystemTime,
    ) -> Result<PageState, Status> {
        let mail = self.deps.mail.current().ok_or(Status::EmailNotConnected)?;
        let q = MailQuery {
            site: site.to_string(),
            since: started
                .checked_sub(OTP_SINCE_SLACK)
                .unwrap_or(SystemTime::UNIX_EPOCH),
        };
        let deadline = Instant::now() + self.cfg.otp_wait_max;
        loop {
            match self.poll_once(mail.as_ref(), &q) {
                Poll::Wait => {}
                Poll::Done(s) => return Err(s),
                Poll::Code(code) => {
                    return match b.fill_otp(site, &code) {
                        // The code field is still there: refused.
                        Ok(PageState::NeedsOtp) => Ok(PageState::Rejected),
                        Ok(st) => Ok(st),
                        Err(e) => Err(exec_status(e)),
                    };
                }
                Poll::Link(link) => {
                    let on_site = url::Url::parse(link.expose())
                        .ok()
                        .filter(|u| u.scheme() == "https" || u.scheme() == "http")
                        .and_then(|u| url_site(&u))
                        .is_some_and(|d| d == site);
                    if !on_site {
                        return Err(failed(FailReason::FenceBlocked));
                    }
                    b.navigate(link.expose()).map_err(exec_status)?;
                    return b.page_state().map_err(exec_status);
                }
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(failed(FailReason::Timeout));
            }
            std::thread::sleep(self.cfg.otp_poll_every.min(deadline - now));
        }
    }

    fn poll_once(&self, mail: &dyn MailSource, q: &MailQuery) -> Poll {
        let msgs = match mail.search(q) {
            Ok(m) => m,
            Err(MailError::NotConnected) => return Poll::Done(Status::EmailNotConnected),
            Err(MailError::Transient) => return Poll::Wait,
            Err(MailError::Internal) => return Poll::Done(failed(FailReason::Internal)),
        };
        match extract_otp(&msgs, q, &mut lock(&self.used_codes)) {
            OtpOutcome::Code(c) => Poll::Code(c),
            OtpOutcome::Link(l) => Poll::Link(l),
            OtpOutcome::Ambiguous => Poll::Done(needs(NeedsUserReason::AmbiguousOtp)),
            OtpOutcome::NotFound => Poll::Wait,
        }
    }

    fn slot(&self, session_id: &str) -> Result<Arc<Slot>, Status> {
        let id: SessionId = session_id
            .parse()
            .map_err(|_| failed(FailReason::SessionNotFound))?;
        let slot = lock(&self.state)
            .sessions
            .get(&id)
            .cloned()
            .ok_or(failed(FailReason::SessionNotFound))?;
        slot.touch();
        Ok(slot)
    }

    /// Run `f` on the session's browser.
    fn with_browser<T>(
        &self,
        session_id: &str,
        f: impl FnOnce(&mut dyn Browser, &str) -> Result<T, Status>,
    ) -> (Result<T, Status>, String) {
        let slot = match self.slot(session_id) {
            Ok(s) => s,
            Err(s) => return (Err(s), String::new()),
        };
        let mut guard = lock(&slot.browser);
        let r = match guard.as_mut() {
            Some(b) => f(b.as_mut(), &slot.site),
            None => Err(failed(FailReason::SessionNotFound)),
        };
        (r, slot.site.clone())
    }

    fn snapshot(&self, session_id: &str) -> Outcome {
        let (r, site) = self.with_browser(session_id, |b, _| {
            let s = b.snapshot().map_err(exec_status)?;
            Ok(json!({ "url": s.url, "title": s.title, "lines": s.lines }))
        });
        reply_data(r, site)
    }

    fn navigate(&self, session_id: &str, url: &str) -> Outcome {
        let (r, site) = self.with_browser(session_id, |b, site| {
            let target = url::Url::parse(url).map_err(|_| failed(FailReason::FenceBlocked))?;
            let ok_scheme = target.scheme() == "https" || target.scheme() == "http";
            if !ok_scheme || url_site(&target).as_deref() != Some(site) {
                return Err(failed(FailReason::FenceBlocked));
            }
            b.navigate(target.as_str()).map_err(exec_status)?;
            let now = b.current_url().map_err(exec_status)?;
            Ok(json!({ "url": now }))
        });
        reply_data(r, site)
    }

    fn click(&self, session_id: &str, node_ref: u64) -> Outcome {
        let (r, site) = self.with_browser(session_id, |b, _| {
            b.click(node_ref).map_err(exec_status)?;
            let now = b.current_url().map_err(exec_status)?;
            Ok(json!({ "url": now }))
        });
        reply_data(r, site)
    }

    fn close_session(&self, session_id: &str) -> Outcome {
        let Ok(id) = session_id.parse::<SessionId>() else {
            return Outcome::new(&failed(FailReason::SessionNotFound), "");
        };
        let slot = Self::forget(&mut lock(&self.state), &id);
        match slot {
            Some(s) => {
                let site = s.site.clone();
                s.close();
                Outcome::new(&Status::Ok, site)
            }
            None => Outcome::new(&failed(FailReason::SessionNotFound), ""),
        }
    }

    /// Live session count (tests, status).
    pub fn session_count(&self) -> usize {
        lock(&self.state).sessions.len()
    }
}

enum Poll {
    Wait,
    Done(Status),
    Code(SecretString),
    Link(SecretString),
}

#[derive(Clone, Copy)]
struct CredsRef<'a> {
    username: &'a str,
    password: &'a SecretString,
    record_site: &'a str,
}

fn creds_ref(c: &Creds) -> CredsRef<'_> {
    CredsRef {
        username: &c.username,
        password: &c.password,
        record_site: &c.record_site,
    }
}

/// `PageState` after a fill → status. `LoggedIn` gets its session id later.
fn page_status(s: PageState) -> Status {
    match s {
        PageState::LoggedIn => Status::LoggedIn {
            session_id: SessionId::random(),
        },
        PageState::LoginForm | PageState::Rejected | PageState::SignupForm => {
            failed(FailReason::CredentialsRejected)
        }
        PageState::Captcha => needs(NeedsUserReason::Captcha),
        PageState::Unknown | PageState::VerifyEmail | PageState::NeedsConsent => {
            needs(NeedsUserReason::UnknownPage)
        }
        // A second code prompt after the first was handled: treat as refused.
        PageState::NeedsOtp => failed(FailReason::CredentialsRejected),
    }
}

fn reply_data(r: Result<serde_json::Value, Status>, site: String) -> Outcome {
    match r {
        Ok(d) => {
            let mut o = Outcome::new(&Status::Ok, site);
            o.reply = o.reply.with_data(d);
            o
        }
        Err(s) => Outcome::new(&s, site),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_urls() {
        assert_eq!(start_url("example.com"), "https://example.com/login");
        assert_eq!(
            start_url("http://example.localhost:8080/signin"),
            "http://example.localhost:8080/signin"
        );
    }

    #[test]
    fn exec_mapping() {
        let r = |e| match exec_status(e) {
            Status::Failed { reason } => reason,
            _ => FailReason::Internal,
        };
        assert_eq!(r(ExecError::Fence), FailReason::FenceBlocked);
        assert_eq!(r(ExecError::Unreachable), FailReason::SiteUnreachable);
        assert_eq!(r(ExecError::Timeout), FailReason::Timeout);
        assert_eq!(
            r(ExecError::Mapping(logindesk_executor::MapFail::NoForm)),
            FailReason::FieldMappingFailed
        );
        assert_eq!(r(ExecError::Token), FailReason::GrantDenied);
        assert_eq!(r(ExecError::NoChrome), FailReason::Internal);
    }
}
