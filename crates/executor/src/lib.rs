//! logindesk-executor: the sealed browser.
//!
//! One [`Session`] = one Chrome process with one page, driven over a private
//! `--remote-debugging-pipe` (no TCP port; `Runtime.enable` is never sent).
//! The executor fills secrets into the page itself. Callers only ever get a
//! masked [`Snapshot`] (text-field values are never returned) and a [`PageState`].
//!
//! FROZEN API (docs/contract.md §10).

mod cdp;
mod map;
mod pure;
#[allow(unsafe_code)]
mod spawn;

use std::fmt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use logindesk_approver::{Action, ApprovalToken};
use logindesk_core::SecretString;
use logindesk_core::limits::{PAGE_LOAD_MAX, SNAPSHOT_MAX};
use serde_json::{Value, json};
use url::Url;

pub use map::{FormKind, FormShape};

/// Why an executor call failed. Never carries page text or a secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecError {
    /// No Chrome/Chromium found (set `LOGINDESK_CHROME`).
    NoChrome,
    /// The page did not load (`Page.navigate` returned an error text).
    Unreachable,
    /// Out of time (page load, CDP reply).
    Timeout,
    /// The page, form action or field is not on the token's site.
    Fence,
    /// No login / signup / code field could be found; the reason says which.
    Mapping(MapFail),
    /// The approval token was expired or for another action/site.
    Token,
    /// The field at this ref is not the kind the call allows (e.g. `type_text`
    /// on a password field, or a password into a plain text box).
    Refused,
    /// CDP returned an error.
    Protocol,
    /// Browser crashed / pipe closed / other internal error.
    Browser(&'static str),
}

/// Why the fields could not be mapped. A fixed tag: never a field value or page text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapFail {
    /// A signup form with no visible email field.
    NoEmailField,
    /// A password field with no visible username field next to it.
    NoUsernameField,
    /// After the username step, no password field appeared.
    NoPasswordField,
    /// No login or signup form on the page, even after opener clicks.
    NoForm,
    /// The element to click has no box (not rendered).
    NoBoxModel,
    /// The fields exist but are hidden or off-screen.
    NotVisible,
    /// No visible one-time-code field.
    NoCodeField,
}

impl MapFail {
    /// snake_case tag for logs and the audit line.
    pub fn wire(self) -> &'static str {
        match self {
            Self::NoEmailField => "no_email_field",
            Self::NoUsernameField => "no_username_field",
            Self::NoPasswordField => "no_password_field",
            Self::NoForm => "no_form",
            Self::NoBoxModel => "no_box_model",
            Self::NotVisible => "not_visible",
            Self::NoCodeField => "no_code_field",
        }
    }
}

impl fmt::Display for ExecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for ExecError {}

/// Which secret a field may receive, chosen by the broker and checked by the executor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretField {
    /// A stored or generated password: only `input[type=password]`.
    Password,
    /// An emailed one-time code: a code-like or plain text/number/tel input, never a password field.
    Code,
    /// The identity's (plus-addressed) email: an email or text input, never a password field.
    Email,
}

/// How to launch the browser.
#[derive(Debug, Clone)]
pub struct BrowserConfig {
    /// Chrome binary; `None` = `LOGINDESK_CHROME`, then the usual install paths.
    pub chrome: Option<PathBuf>,
    /// Persistent profile dir (cookies survive between sessions). One live Session per dir.
    pub profile_dir: PathBuf,
    /// `--headless=new` when true.
    pub headless: bool,
}

/// What the current page looks like, judged by the executor (no model involved).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageState {
    /// No login/OTP form, no error: signed in.
    LoggedIn,
    /// A one-time-code field is showing.
    NeedsOtp,
    /// The login form is back with an error, or the code was refused.
    Rejected,
    /// A CAPTCHA is showing.
    Captcha,
    /// A login form (username/password) is showing.
    LoginForm,
    /// A signup form (a new-password field) is showing, e.g. back with an error.
    SignupForm,
    /// "Check your email": the site sent a verification mail and shows no code field.
    VerifyEmail,
    /// Fields are filled but a required checkbox (terms, consent) is unticked.
    /// The broker never ticks one; the user must, then submit.
    NeedsConsent,
    /// Anything else.
    Unknown,
}

/// A masked view of the page for the agent.
#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    /// Current URL.
    pub url: String,
    /// Document title.
    pub title: String,
    /// One line per interesting accessibility node: `[ref] role "name"`.
    /// Text fields show `(filled)` / `(empty)`, never their value.
    /// `ref` is the CDP backendDOMNodeId, usable with [`Session::click`].
    pub lines: Vec<String>,
}

/// One browser + one page.
pub struct Session {
    cdp: cdp::Cdp,
    child: std::process::Child,
    target: String,
    /// When a `<select>` was last typed into (the browser's type-to-select buffer
    /// lasts about a second; a new pick must not continue the old one).
    typeahead_at: Option<Instant>,
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session").finish_non_exhaustive()
    }
}

/// Inputs that take a one-time code, most specific first.
const OTP_FIELD: &str = "input[autocomplete~=one-time-code i], input[name*=otp i], \
input[id*=otp i], input[name=code i], input[id=code i], input[name*=one-time i], \
input[name*=onetime i], input[name*=verification i]";

/// The new-password field of a signup form, most specific first.
const NEW_PW: &str = "input[autocomplete~=new-password i]";
/// Email field of a signup form.
const EMAIL_FIELDS: &[&str] = &[
    "input[autocomplete~=email i]:not([type=hidden])",
    "input[type=email i]",
    "input[name*=email i]:not([type=hidden]):not([type=password]), \
     input[id*=email i]:not([type=hidden]):not([type=password])",
];
/// Full-name field of a signup form (`~=` is a token match: never "username").
const NAME_FIELDS: &[&str] = &[
    "input[autocomplete~=name i]:not([type=hidden])",
    "input[name=name i]:not([type=hidden]), input[id=name i]:not([type=hidden]), \
     input[name*=fullname i]:not([type=hidden]), input[name*=full_name i]:not([type=hidden])",
];
/// Words on a "go read your mail" page.
const VERIFY_WORDS: &[&str] = &[
    "check your email",
    "verify your email",
    "confirm your email",
];

const CAPTCHA_DOM: &str = "[class*=captcha i], [id*=captcha i], [name*=captcha i], \
[data-testbed-captcha], iframe[src*=captcha i], iframe[title*=captcha i]";

/// How long to wait for a navigation to start after a click / Enter.
const NAV_START: Duration = Duration::from_secs(3);
/// fill_login / fill_otp: total wait for the post-submit load.
const SUBMIT_LOAD: Duration = Duration::from_secs(10);

/// The current user's login name, from `id -un`.
fn login_name() -> Option<String> {
    let out = Command::new("/usr/bin/id")
        .arg("-un")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    let name = String::from_utf8(out.stdout).ok()?.trim().to_string();
    (out.status.success() && !name.is_empty()).then_some(name)
}

fn find_chrome(cfg: &BrowserConfig) -> Option<PathBuf> {
    if let Some(p) = &cfg.chrome {
        return p.is_file().then(|| p.clone());
    }
    if let Some(p) = std::env::var_os("LOGINDESK_CHROME").filter(|p| !p.is_empty()) {
        let p = PathBuf::from(p);
        return p.is_file().then_some(p);
    }
    let fixed = [
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Chromium.app/Contents/MacOS/Chromium",
    ];
    if let Some(p) = fixed.iter().map(Path::new).find(|p| p.is_file()) {
        return Some(p.to_path_buf());
    }
    let path = std::env::var_os("PATH")?;
    ["google-chrome", "chromium"].iter().find_map(|bin| {
        std::env::split_paths(&path)
            .map(|d| d.join(bin))
            .find(|p| p.is_file())
    })
}

impl Session {
    /// Launch Chrome with the pipe, attach to its page, enable `Page` and `DOM` only.
    pub fn launch(cfg: &BrowserConfig) -> Result<Self, ExecError> {
        let chrome = find_chrome(cfg).ok_or(ExecError::NoChrome)?;
        let mut cmd = Command::new(chrome);
        cmd.arg("--remote-debugging-pipe")
            .arg(format!("--user-data-dir={}", cfg.profile_dir.display()))
            .args([
                "--no-first-run",
                "--no-default-browser-check",
                "--disable-extensions",
                "--disable-sync",
                "--password-store=basic",
            ]);
        if cfg.headless {
            cmd.arg("--headless=new");
        }
        // Chrome on macOS stalls at startup when USER is missing (a bare launchd or
        // `env -i` environment). Give the child the login name in that case.
        if std::env::var_os("USER").is_none_or(|u| u.is_empty())
            && let Some(name) = login_name()
        {
            cmd.env("USER", &name).env("LOGNAME", &name);
        }
        cmd.arg("about:blank")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let (child, tx, rx) =
            spawn::spawn_with_pipe(cmd).map_err(|_| ExecError::Browser("spawn failed"))?;
        // From here on, Drop closes the browser if attaching fails.
        let mut s = Self {
            cdp: cdp::Cdp::new(tx, rx),
            child,
            target: String::new(),
            typeahead_at: None,
        };
        s.target = s.find_page_target()?;
        let attached = s.cdp.call(
            "Target.attachToTarget",
            json!({"targetId": s.target, "flatten": true}),
        )?;
        let sid = attached["sessionId"]
            .as_str()
            .ok_or(ExecError::Browser("no session id"))?;
        s.cdp.session = Some(sid.to_string());
        // Page + DOM only. Never Runtime.* (contract §10).
        s.cdp.call("Page.enable", json!({}))?;
        s.cdp.call("DOM.enable", json!({}))?;
        Ok(s)
    }

    /// The first page target; Chrome may need a moment to create it.
    fn find_page_target(&mut self) -> Result<String, ExecError> {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let t = self.cdp.call("Target.getTargets", json!({}))?;
            let page = t["targetInfos"]
                .as_array()
                .and_then(|a| a.iter().find(|t| t["type"] == "page"))
                .and_then(|p| p["targetId"].as_str());
            if let Some(id) = page {
                return Ok(id.to_string());
            }
            if Instant::now() >= deadline {
                return Err(ExecError::Timeout);
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Navigate and wait for load (limit `PAGE_LOAD_MAX`).
    pub fn navigate(&mut self, url: &str) -> Result<(), ExecError> {
        self.cdp.clear_events();
        let r = self.cdp.call("Page.navigate", json!({"url": url}))?;
        if r["errorText"].as_str().is_some_and(|e| !e.is_empty()) {
            return Err(ExecError::Unreachable);
        }
        self.cdp
            .wait_event("Page.loadEventFired", PAGE_LOAD_MAX)
            .map(|_| ())
    }

    fn target_info(&mut self) -> Result<Value, ExecError> {
        let r = self.cdp.send(
            "Target.getTargetInfo",
            json!({"targetId": self.target}),
            None,
            Duration::from_secs(15),
        )?;
        Ok(r["targetInfo"].clone())
    }

    /// Current page URL.
    pub fn current_url(&mut self) -> Result<String, ExecError> {
        let info = self.target_info()?;
        info["url"]
            .as_str()
            .map(str::to_string)
            .ok_or(ExecError::Protocol)
    }

    fn page_url(&mut self) -> Result<Url, ExecError> {
        let u = self.current_url()?;
        Url::parse(&u).map_err(|_| ExecError::Fence)
    }

    fn ax_tree(&mut self) -> Result<Value, ExecError> {
        let s = self.cdp.session.clone();
        self.cdp.send(
            "Accessibility.getFullAXTree",
            json!({}),
            s.as_deref(),
            SNAPSHOT_MAX,
        )
    }

    /// Masked accessibility snapshot (limit `SNAPSHOT_MAX`).
    pub fn snapshot(&mut self) -> Result<Snapshot, ExecError> {
        let t0 = Instant::now();
        let info = self.target_info()?;
        let tree = self.ax_tree()?;
        let kinds = self.field_kinds(&tree, SNAPSHOT_MAX.saturating_sub(t0.elapsed()));
        Ok(Snapshot {
            url: info["url"].as_str().unwrap_or("").to_string(),
            title: info["title"].as_str().unwrap_or("").to_string(),
            lines: pure::ax_lines_kinds(&tree, &kinds),
        })
    }

    /// Click the node with this snapshot ref; waits briefly for any navigation.
    pub fn click(&mut self, node_ref: u64) -> Result<(), ExecError> {
        let node = json!({"backendNodeId": node_ref});
        // Best effort: an element already on screen needs no scroll.
        let _ = self.cdp.call("DOM.scrollIntoViewIfNeeded", node.clone());
        let model = self
            .cdp
            .call("DOM.getBoxModel", node)
            .map_err(|_| ExecError::Mapping(MapFail::NoBoxModel))?;
        let (x, y) = pure::quad_centre(&model).ok_or(ExecError::Mapping(MapFail::NoBoxModel))?;
        self.cdp.clear_events();
        for kind in ["mousePressed", "mouseReleased"] {
            self.cdp.call(
                "Input.dispatchMouseEvent",
                json!({"type": kind, "x": x, "y": y, "button": "left", "clickCount": 1}),
            )?;
        }
        self.settle(PAGE_LOAD_MAX)
    }

    /// After an input that may navigate: if a load starts within `NAV_START`, wait for
    /// it to finish (up to `total`). A page that never navigates is not an error.
    fn settle(&mut self, total: Duration) -> Result<(), ExecError> {
        let t0 = Instant::now();
        let started = self.cdp.wait_any(
            &[
                "Page.frameStartedLoading",
                "Page.frameNavigated",
                "Page.loadEventFired",
            ],
            NAV_START.min(total),
        );
        let ev = match started {
            Ok(ev) => ev,
            Err(ExecError::Timeout) => return Ok(()),
            Err(e) => return Err(e),
        };
        if ev["method"] == "Page.loadEventFired" {
            return Ok(());
        }
        let left = total.saturating_sub(t0.elapsed());
        match self.cdp.wait_event("Page.loadEventFired", left) {
            Ok(_) | Err(ExecError::Timeout) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// `nodeId` of the document root (fresh: node ids die with each navigation).
    fn root(&mut self) -> Result<Value, ExecError> {
        let d = self.cdp.call("DOM.getDocument", json!({"depth": 0}))?;
        Ok(d["root"]["nodeId"].clone())
    }

    /// First match of `selector` under `node`, or None.
    fn query(&mut self, node: &Value, selector: &str) -> Result<Option<Value>, ExecError> {
        let r = self.cdp.call(
            "DOM.querySelector",
            json!({"nodeId": node, "selector": selector}),
        )?;
        Ok(match r["nodeId"].as_u64() {
            Some(0) | None => None,
            Some(_) => Some(r["nodeId"].clone()),
        })
    }

    /// Classify the current page.
    pub fn page_state(&mut self) -> Result<PageState, ExecError> {
        let url = self.current_url()?;
        if url.is_empty() || url == "about:blank" || url.starts_with("chrome-error://") {
            return Ok(PageState::Unknown);
        }
        let root = self.root()?;
        if self.query(&root, OTP_FIELD)?.is_some() {
            return Ok(PageState::NeedsOtp);
        }
        let tree = self.ax_tree()?;
        if self.query(&root, CAPTCHA_DOM)?.is_some() || pure::ax_text(&tree).contains("captcha") {
            return Ok(PageState::Captcha);
        }
        let has_pw = self.query(&root, "input[type=password i]")?.is_some();
        let alert = pure::ax_has_alert(&tree) || self.query(&root, "[role=alert]")?.is_some();
        Ok(match (has_pw, alert) {
            (true, true) => PageState::Rejected,
            (true, false) => PageState::LoginForm,
            // An error page in reply to a submit often drops the form entirely.
            (false, true) => PageState::Rejected,
            (false, false) => {
                if pure::ax_lines(&tree).is_empty() {
                    PageState::Unknown
                } else {
                    PageState::LoggedIn
                }
            }
        })
    }

    /// The fence: the page is on `site`, and so is `form`'s resolved action (and every
    /// `formaction` override inside it).
    fn fence(&mut self, site: &str, form: Option<&Value>) -> Result<(), ExecError> {
        let page = self.page_url()?;
        if !pure::on_site(&page, site) {
            return Err(ExecError::Fence);
        }
        let Some(form) = form else { return Ok(()) };
        let attrs = self
            .cdp
            .call("DOM.getAttributes", json!({"nodeId": form}))?;
        if !pure::action_on_site(&page, pure::attr(&attrs, "action"), site) {
            return Err(ExecError::Fence);
        }
        let over = self.cdp.call(
            "DOM.querySelectorAll",
            json!({"nodeId": form, "selector": "[formaction]"}),
        )?;
        for n in over["nodeIds"].as_array().cloned().unwrap_or_default() {
            let a = self.cdp.call("DOM.getAttributes", json!({"nodeId": n}))?;
            if !pure::action_on_site(&page, pure::attr(&a, "formaction"), site) {
                return Err(ExecError::Fence);
            }
        }
        Ok(())
    }

    /// Focus `node`, select whatever is in it, and type `text` over it.
    fn fill(&mut self, node: &Value, text: &str, secret: bool) -> Result<(), ExecError> {
        self.cdp.call("DOM.focus", json!({"nodeId": node}))?;
        self.cdp.call(
            "Input.dispatchKeyEvent",
            json!({"type": "rawKeyDown", "commands": ["selectAll"]}),
        )?;
        if secret {
            self.cdp.insert_secret_text(text)
        } else {
            self.cdp
                .call("Input.insertText", json!({"text": text}))
                .map(|_| ())
        }
    }

    /// Focus `node` and press Enter (implicit form submission).
    fn press_enter(&mut self, node: &Value) -> Result<(), ExecError> {
        self.cdp.call("DOM.focus", json!({"nodeId": node}))?;
        self.cdp.clear_events();
        for kind in ["keyDown", "keyUp"] {
            let mut ev = json!({
                "type": kind, "key": "Enter", "code": "Enter",
                "windowsVirtualKeyCode": 13, "nativeVirtualKeyCode": 13,
            });
            if kind == "keyDown" {
                ev["text"] = json!("\r");
            }
            self.cdp.call("Input.dispatchKeyEvent", ev)?;
        }
        Ok(())
    }

    /// Spend `token` for (Login, `site`), check the page and the form action are on `site`
    /// (registrable domain), fill username + password, submit, wait, classify.
    pub fn fill_login(
        &mut self,
        site: &str,
        username: &str,
        password: &SecretString,
        token: ApprovalToken,
    ) -> Result<PageState, ExecError> {
        token
            .spend(Action::Login, site)
            .map_err(|_| ExecError::Token)?;
        // Page fence first: a lookalike fails before anything is read from it. Then
        // wait for the (possibly JS-built) form, opening a "Sign in" panel if needed.
        // A password field only inside an iframe is not in this document: Mapping.
        let mut clicks = 0;
        // Map and fill (no submit), again if the page re-renders under us.
        let m = self.retry_on_stale(|s| {
            let m = s.map_login(site, &mut clicks)?;
            let user = m
                .user
                .as_ref()
                .ok_or(ExecError::Mapping(MapFail::NoUsernameField))?;
            s.fill(user, username, false)?;
            if let Some(pw) = &m.password {
                s.fill(pw, password.expose(), true)?;
            }
            Ok(m)
        })?;
        let (Some(user), None) = (&m.user, &m.password) else {
            let pw = m
                .password
                .as_ref()
                .ok_or(ExecError::Mapping(MapFail::NoPasswordField))?;
            self.press_enter(pw)?;
            self.settle(SUBMIT_LOAD)?;
            return self.page_state();
        };
        // Two-step: username submitted, then the password on the next page (fenced
        // again there).
        self.press_enter(user)?;
        self.settle(SUBMIT_LOAD)?;
        let step = self.retry_on_stale(|s| {
            let step = s.map_password_step(site)?;
            if let map::StepTwo::Password { field, .. } = &step {
                s.fill(field, password.expose(), true)?;
            }
            Ok(step)
        })?;
        if let map::StepTwo::Password { field, .. } = &step {
            self.press_enter(field)?;
            self.settle(SUBMIT_LOAD)?;
        }
        self.page_state()
    }

    /// Check the page is on `site`, fill the one-time code, submit, wait, classify.
    pub fn fill_otp(&mut self, site: &str, code: &SecretString) -> Result<PageState, ExecError> {
        let field = self.retry_on_stale(|s| {
            let (_form, field) = s.map_code(site)?;
            s.fill(&field, code.expose(), true)?;
            Ok(field)
        })?;
        self.press_enter(&field)?;
        self.settle(SUBMIT_LOAD)?;
        let root = self.root()?;
        if self.query(&root, OTP_FIELD)?.is_some() {
            return Ok(PageState::Rejected);
        }
        self.page_state()
    }

    /// The `passwordrules` attribute of the signup form's new-password field, if any.
    /// Page data, not a secret. Checks the page is on `site` first.
    pub fn password_rules(&mut self, site: &str) -> Result<Option<String>, ExecError> {
        self.fence(site, None)?;
        let root = self.root()?;
        let Some(pw) = self.signup_password_field(&root)? else {
            return Ok(None);
        };
        let a = self.cdp.call("DOM.getAttributes", json!({"nodeId": pw}))?;
        Ok(pure::attr(&a, "passwordrules").map(str::to_string))
    }

    fn signup_password_field(&mut self, scope: &Value) -> Result<Option<Value>, ExecError> {
        match self.query(scope, NEW_PW)? {
            Some(n) => Ok(Some(n)),
            None => self.query(scope, "input[type=password i]"),
        }
    }

    /// Every match of `selector` under `node`.
    fn query_all(&mut self, node: &Value, selector: &str) -> Result<Vec<Value>, ExecError> {
        let r = self.cdp.call(
            "DOM.querySelectorAll",
            json!({"nodeId": node, "selector": selector}),
        )?;
        Ok(r["nodeIds"].as_array().cloned().unwrap_or_default())
    }

    /// Spend `token` for (Signup, `site`), fence the page and the form action like
    /// [`Self::fill_login`], fill email, name (when asked and given) and every password
    /// field (new + confirm), then submit and classify. Checkboxes are never ticked: an
    /// unticked required one leaves the form filled but unsubmitted ([`PageState::NeedsConsent`]).
    pub fn fill_signup(
        &mut self,
        site: &str,
        email: &str,
        name: &str,
        password: &SecretString,
        token: ApprovalToken,
    ) -> Result<PageState, ExecError> {
        token
            .spend(Action::Signup, site)
            .map_err(|_| ExecError::Token)?;
        let mut clicks = 0;
        let m = self.retry_on_stale(|s| {
            let m = s.map_signup(site, &mut clicks)?;
            s.fill(&m.email, email, false)?;
            if let Some(n) = &m.name
                && !name.is_empty()
            {
                s.fill(n, name, false)?;
            }
            // New password and its confirmation: same value in each (visible ones
            // only: an off-screen honeypot stays empty).
            for p in &m.passwords {
                s.fill(p, password.expose(), true)?;
            }
            Ok(m)
        })?;
        let first_pw = m
            .passwords
            .first()
            .cloned()
            .ok_or(ExecError::Mapping(MapFail::NoPasswordField))?;
        let scope = m.form.clone().unwrap_or_else(|| m.root.clone());
        // Never tick a box. A required one left unticked stops here, unsubmitted.
        for cb in self.query_all(&scope, "input[type=checkbox i][required]")? {
            let a = self.cdp.call("DOM.getAttributes", json!({"nodeId": cb}))?;
            if pure::attr(&a, "checked").is_none() {
                return Ok(PageState::NeedsConsent);
            }
        }
        self.press_enter(&first_pw)?;
        self.settle(SUBMIT_LOAD)?;
        self.signup_state()
    }

    /// Classify the page after a signup submit.
    fn signup_state(&mut self) -> Result<PageState, ExecError> {
        let url = self.current_url()?;
        if url.is_empty() || url == "about:blank" || url.starts_with("chrome-error://") {
            return Ok(PageState::Unknown);
        }
        let root = self.root()?;
        if self.query(&root, OTP_FIELD)?.is_some() {
            return Ok(PageState::NeedsOtp);
        }
        let tree = self.ax_tree()?;
        if self.query(&root, CAPTCHA_DOM)?.is_some() || pure::ax_text(&tree).contains("captcha") {
            return Ok(PageState::Captcha);
        }
        if self.query(&root, NEW_PW)?.is_some() {
            return Ok(PageState::SignupForm);
        }
        let text = pure::ax_text(&tree);
        if self.query(&root, "input[type=password i]")?.is_none()
            && VERIFY_WORDS.iter().any(|w| text.contains(w))
        {
            return Ok(PageState::VerifyEmail);
        }
        self.page_state()
    }

    /// Type agent-supplied text into the field with this snapshot ref, replacing its
    /// content; a `<select>` picks the option whose label or value matches. Checks the
    /// page (and the field's form action) is on `site`. Refuses password fields,
    /// one-time-code fields and anything that is not a text input, textarea, select
    /// or contenteditable (`Refused`). Never presses Enter.
    pub fn type_text(&mut self, site: &str, node_ref: u64, text: &str) -> Result<(), ExecError> {
        self.agent_type(site, node_ref, text)
    }

    /// Fill a secret into the field with this snapshot ref. The field must suit
    /// `field` (see [`SecretField`]) or the call is `Refused`; the page and the
    /// field's form action must be on `site` (`Fence`). Never presses Enter.
    pub fn fill_at(
        &mut self,
        site: &str,
        node_ref: u64,
        field: SecretField,
        value: &SecretString,
    ) -> Result<(), ExecError> {
        self.agent_fill(site, node_ref, field, value)
    }

    /// Press Enter in the field with this snapshot ref (submits its form), then wait
    /// for any navigation. Checks the page is on `site`.
    pub fn press_enter_at(&mut self, site: &str, node_ref: u64) -> Result<(), ExecError> {
        self.agent_enter(site, node_ref)
    }

    /// Close the browser.
    pub fn close(self) {}
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self
            .cdp
            .send("Browser.close", json!({}), None, Duration::from_secs(2));
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            if let Ok(Some(_)) = self.child.try_wait() {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
