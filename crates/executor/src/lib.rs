//! logindesk-executor: the sealed browser.
//!
//! One [`Session`] = one Chrome process with one page, driven over a private
//! `--remote-debugging-pipe` (no TCP port; `Runtime.enable` is never sent).
//! The executor fills secrets into the page itself. Callers only ever get a
//! masked [`Snapshot`] (text-field values are never returned) and a [`PageState`].
//!
//! FROZEN API (docs/contract.md §10).

mod cdp;
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
    /// No login / code field could be found.
    Mapping,
    /// The approval token was expired or for another action/site.
    Token,
    /// CDP returned an error.
    Protocol,
    /// Browser crashed / pipe closed / other internal error.
    Browser(&'static str),
}

impl fmt::Display for ExecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for ExecError {}

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

/// Username field inside the login form, in order of preference.
const USER_FIELDS: &[&str] = &[
    "input[autocomplete~=username i]:not([type=hidden])",
    "input[type=email i]",
    "input[name*=user i]:not([type=hidden]):not([type=password]), \
     input[id*=user i]:not([type=hidden]):not([type=password]), \
     input[name*=email i]:not([type=hidden]):not([type=password]), \
     input[id*=email i]:not([type=hidden]):not([type=password]), \
     input[name*=login i]:not([type=hidden]):not([type=password]), \
     input[id*=login i]:not([type=hidden]):not([type=password])",
    "input[type=text i], input:not([type])",
];

const CAPTCHA_DOM: &str = "[class*=captcha i], [id*=captcha i], [name*=captcha i], \
[data-testbed-captcha], iframe[src*=captcha i], iframe[title*=captcha i]";

/// How long to wait for a navigation to start after a click / Enter.
const NAV_START: Duration = Duration::from_secs(3);
/// fill_login / fill_otp: total wait for the post-submit load.
const SUBMIT_LOAD: Duration = Duration::from_secs(10);

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
        let info = self.target_info()?;
        let tree = self.ax_tree()?;
        Ok(Snapshot {
            url: info["url"].as_str().unwrap_or("").to_string(),
            title: info["title"].as_str().unwrap_or("").to_string(),
            lines: pure::ax_lines(&tree),
        })
    }

    /// Click the node with this snapshot ref; waits briefly for any navigation.
    pub fn click(&mut self, node_ref: u64) -> Result<(), ExecError> {
        let node = json!({"backendNodeId": node_ref});
        // Best effort: an element already on screen needs no scroll.
        let _ = self.cdp.call("DOM.scrollIntoViewIfNeeded", node.clone());
        let model = self.cdp.call("DOM.getBoxModel", node)?;
        let (x, y) = pure::quad_centre(&model).ok_or(ExecError::Mapping)?;
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

    /// The `<form>` that holds `field`, if any.
    fn form_of(&mut self, root: &Value, selector: &str) -> Result<Option<Value>, ExecError> {
        self.query(root, &format!("form:has({selector})"))
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
        // The page itself first: a lookalike fails here before anything is read from it.
        self.fence(site, None)?;
        let root = self.root()?;
        // A password field only inside an iframe is not in this document: Mapping.
        let form = self.form_of(&root, "input[type=password i]")?;
        let scope = match &form {
            Some(f) => f.clone(),
            None => {
                self.query(&root, "input[type=password i]")?
                    .ok_or(ExecError::Mapping)?;
                root.clone()
            }
        };
        self.fence(site, form.as_ref())?;
        let pw = self
            .query(&scope, "input[type=password i]")?
            .ok_or(ExecError::Mapping)?;
        let mut user = None;
        for sel in USER_FIELDS {
            if let Some(n) = self.query(&scope, sel)? {
                user = Some(n);
                break;
            }
        }
        let user = user.ok_or(ExecError::Mapping)?;
        self.fill(&user, username, false)?;
        self.fill(&pw, password.expose(), true)?;
        self.press_enter(&pw)?;
        self.settle(SUBMIT_LOAD)?;
        self.page_state()
    }

    /// Check the page is on `site`, fill the one-time code, submit, wait, classify.
    pub fn fill_otp(&mut self, site: &str, code: &SecretString) -> Result<PageState, ExecError> {
        self.fence(site, None)?;
        let root = self.root()?;
        let field = self.query(&root, OTP_FIELD)?.ok_or(ExecError::Mapping)?;
        let form = self.form_of(&root, OTP_FIELD)?;
        self.fence(site, form.as_ref())?;
        self.fill(&field, code.expose(), true)?;
        self.press_enter(&field)?;
        self.settle(SUBMIT_LOAD)?;
        let root = self.root()?;
        if self.query(&root, OTP_FIELD)?.is_some() {
            return Ok(PageState::Rejected);
        }
        self.page_state()
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
