//! logindesk-executor: the sealed browser.
//!
//! One [`Session`] = one Chrome process with one page, driven over a private
//! `--remote-debugging-pipe` (no TCP port; `Runtime.enable` is never sent).
//! The executor fills secrets into the page itself. Callers only ever get a
//! masked [`Snapshot`] (text-field values are never returned) and a [`PageState`].
//!
//! FROZEN API (docs/contract.md §10). Bodies marked LANE-EXECUTOR are stubs.

#[allow(dead_code)] // LANE-EXECUTOR: remove once the bodies land
mod cdp;
#[allow(unsafe_code)]
mod spawn;

use std::fmt;
use std::path::PathBuf;

use logindesk_approver::ApprovalToken;
use logindesk_core::SecretString;

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
    #[allow(dead_code)]
    cdp: cdp::Cdp,
    #[allow(dead_code)]
    child: std::process::Child,
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session").finish_non_exhaustive()
    }
}

impl Session {
    /// Launch Chrome with the pipe, attach to its page, enable `Page` and `DOM` only.
    pub fn launch(cfg: &BrowserConfig) -> Result<Self, ExecError> {
        let _ = (cfg, spawn::spawn_with_pipe, cdp::Cdp::new);
        Err(ExecError::Browser("LANE-EXECUTOR: launch"))
    }

    /// Navigate and wait for load (limit `PAGE_LOAD_MAX`).
    pub fn navigate(&mut self, url: &str) -> Result<(), ExecError> {
        let _ = url;
        Err(ExecError::Browser("LANE-EXECUTOR: navigate"))
    }

    /// Current page URL.
    pub fn current_url(&mut self) -> Result<String, ExecError> {
        Err(ExecError::Browser("LANE-EXECUTOR: current_url"))
    }

    /// Masked accessibility snapshot (limit `SNAPSHOT_MAX`).
    pub fn snapshot(&mut self) -> Result<Snapshot, ExecError> {
        Err(ExecError::Browser("LANE-EXECUTOR: snapshot"))
    }

    /// Click the node with this snapshot ref; waits briefly for any navigation.
    pub fn click(&mut self, node_ref: u64) -> Result<(), ExecError> {
        let _ = node_ref;
        Err(ExecError::Browser("LANE-EXECUTOR: click"))
    }

    /// Classify the current page.
    pub fn page_state(&mut self) -> Result<PageState, ExecError> {
        Err(ExecError::Browser("LANE-EXECUTOR: page_state"))
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
        let _ = (site, username, password, token);
        Err(ExecError::Browser("LANE-EXECUTOR: fill_login"))
    }

    /// Check the page is on `site`, fill the one-time code, submit, wait, classify.
    pub fn fill_otp(&mut self, site: &str, code: &SecretString) -> Result<PageState, ExecError> {
        let _ = (site, code);
        Err(ExecError::Browser("LANE-EXECUTOR: fill_otp"))
    }

    /// Close the browser.
    pub fn close(self) {}
}
