//! The browser behind a small trait, so the broker can be tested with a fake.
//! The real implementation is `logindesk_executor::Session`.

use logindesk_approver::ApprovalToken;
use logindesk_core::SecretString;
use logindesk_executor::{BrowserConfig, ExecError, PageState, Session, Snapshot};

/// One live browser page.
pub trait Browser: Send {
    /// Navigate and wait for load.
    fn navigate(&mut self, url: &str) -> Result<(), ExecError>;
    /// Current URL.
    fn current_url(&mut self) -> Result<String, ExecError>;
    /// Masked snapshot.
    fn snapshot(&mut self) -> Result<Snapshot, ExecError>;
    /// Click a snapshot ref.
    fn click(&mut self, node_ref: u64) -> Result<(), ExecError>;
    /// Classify the page.
    fn page_state(&mut self) -> Result<PageState, ExecError>;
    /// Spend the token and fill the login form.
    fn fill_login(
        &mut self,
        site: &str,
        username: &str,
        password: &SecretString,
        token: ApprovalToken,
    ) -> Result<PageState, ExecError>;
    /// Fill an emailed code.
    fn fill_otp(&mut self, site: &str, code: &SecretString) -> Result<PageState, ExecError>;
    /// The signup form's `passwordrules`, if any.
    fn password_rules(&mut self, site: &str) -> Result<Option<String>, ExecError>;
    /// Spend the token and fill + submit the signup form (never ticks a checkbox).
    fn fill_signup(
        &mut self,
        site: &str,
        email: &str,
        name: &str,
        password: &SecretString,
        token: ApprovalToken,
    ) -> Result<PageState, ExecError>;
    /// Close the browser.
    fn close(self: Box<Self>);
}

/// Starts browsers.
pub trait Launcher: Send + Sync {
    /// Launch one browser with this profile.
    fn launch(&self, cfg: &BrowserConfig) -> Result<Box<dyn Browser>, ExecError>;
}

/// Launches the sealed Chrome from `logindesk-executor`.
#[derive(Debug, Default)]
pub struct ChromeLauncher;

impl Launcher for ChromeLauncher {
    fn launch(&self, cfg: &BrowserConfig) -> Result<Box<dyn Browser>, ExecError> {
        Ok(Box::new(Session::launch(cfg)?))
    }
}

impl Browser for Session {
    fn navigate(&mut self, url: &str) -> Result<(), ExecError> {
        Session::navigate(self, url)
    }
    fn current_url(&mut self) -> Result<String, ExecError> {
        Session::current_url(self)
    }
    fn snapshot(&mut self) -> Result<Snapshot, ExecError> {
        Session::snapshot(self)
    }
    fn click(&mut self, node_ref: u64) -> Result<(), ExecError> {
        Session::click(self, node_ref)
    }
    fn page_state(&mut self) -> Result<PageState, ExecError> {
        Session::page_state(self)
    }
    fn fill_login(
        &mut self,
        site: &str,
        username: &str,
        password: &SecretString,
        token: ApprovalToken,
    ) -> Result<PageState, ExecError> {
        Session::fill_login(self, site, username, password, token)
    }
    fn fill_otp(&mut self, site: &str, code: &SecretString) -> Result<PageState, ExecError> {
        Session::fill_otp(self, site, code)
    }
    fn password_rules(&mut self, site: &str) -> Result<Option<String>, ExecError> {
        Session::password_rules(self, site)
    }
    fn fill_signup(
        &mut self,
        site: &str,
        email: &str,
        name: &str,
        password: &SecretString,
        token: ApprovalToken,
    ) -> Result<PageState, ExecError> {
        Session::fill_signup(self, site, email, name, password, token)
    }
    fn close(self: Box<Self>) {
        Session::close(*self);
    }
}
