//! logindesk-mcp: the MCP stdio server an agent talks to.
//!
//! Every tool is a thin client of the daemon socket: one frame out, the
//! daemon's reply JSON back as text. This crate holds no secret, ever: it does
//! not depend on the vault, the browser or the mailbox. Passwords and emailed
//! codes are filled by the broker inside its sealed browser and never returned.
//!
//! stdout is the MCP channel; every log line goes to stderr.
#![forbid(unsafe_code)]

pub mod client;

use std::path::PathBuf;

use rmcp::handler::server::wrapper::Parameters;
use rmcp::service::RequestContext;
use rmcp::{RoleServer, ServiceExt, tool, tool_router};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};

/// `login` arguments.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct LoginArgs {
    /// Site to log in to: a host like `github.com` or a URL.
    pub site: String,
    /// Username or account_id, only when the site has more than one stored account.
    #[serde(default)]
    pub account: Option<String>,
}

/// `list_accounts` arguments.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListAccountsArgs {
    /// Only accounts for this site (host or URL).
    #[serde(default)]
    pub site: Option<String>,
}

/// Arguments naming a session.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct SessionArgs {
    /// session_id returned by `login`.
    pub session_id: String,
}

/// `signup` arguments.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct SignupArgs {
    /// Site to create an account on: a host like `example.com` or a URL.
    pub site: String,
    /// The signup page URL, when it is not `https://<site>/signup`. Must be on the same site.
    #[serde(default)]
    pub url: Option<String>,
}

/// `wait` arguments.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct WaitArgs {
    /// The handle from an `awaiting_approval` reply.
    pub handle: String,
}

/// `navigate` arguments.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct NavigateArgs {
    /// session_id returned by `login`.
    pub session_id: String,
    /// URL on the same site the session logged in to; other sites are refused.
    pub url: String,
}

/// `click` arguments.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ClickArgs {
    /// session_id returned by `login`.
    pub session_id: String,
    /// The number in `[ref]` at the start of a snapshot line.
    #[serde(rename = "ref")]
    #[schemars(rename = "ref")]
    pub node_ref: u64,
}

/// `open` arguments.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct OpenArgs {
    /// The http(s) page to open, e.g. a site's sign-up or sign-in page.
    pub url: String,
}

/// `type` arguments.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct TypeArgs {
    /// session_id from `open`, `login` or `signup`.
    pub session_id: String,
    /// The number in `[ref]` at the start of a snapshot line.
    #[serde(rename = "ref")]
    #[schemars(rename = "ref")]
    pub node_ref: u64,
    /// Non-secret text (a name, phone number, search, ...), at most 512 characters.
    pub text: String,
}

/// Which secret the broker fills. You name the kind; the broker holds the value.
#[derive(Debug, Clone, Copy, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    /// The stored password of this site's account (a sign-in password field).
    Password,
    /// A new password the broker generates and stores (sign-up password AND its confirm box).
    NewPassword,
    /// The user's email address for this site (the broker's identity, plus-addressed).
    Email,
    /// The one-time code the site just emailed (the broker reads the mailbox).
    Code,
}

impl SecretKind {
    fn wire(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::NewPassword => "new_password",
            Self::Email => "email",
            Self::Code => "code",
        }
    }
}

/// `fill_secret` arguments.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct FillSecretArgs {
    /// session_id from `open`, `login` or `signup`.
    pub session_id: String,
    /// The number in `[ref]` of the field to fill, from the latest snapshot.
    #[serde(rename = "ref")]
    #[schemars(rename = "ref")]
    pub node_ref: u64,
    /// password | new_password | email | code
    pub secret: SecretKind,
    /// For `password` only: username or account_id when the site has several accounts.
    #[serde(default)]
    pub account: Option<String>,
}

/// `press_enter` arguments.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct PressEnterArgs {
    /// session_id from `open`, `login` or `signup`.
    pub session_id: String,
    /// The number in `[ref]` of a field in the form to submit.
    #[serde(rename = "ref")]
    #[schemars(rename = "ref")]
    pub node_ref: u64,
}

/// The MCP server.
#[derive(Debug, Clone)]
pub struct Logindesk {
    data_dir: PathBuf,
}

impl Logindesk {
    /// A server talking to the daemon whose socket is in `data_dir`.
    pub fn new(data_dir: PathBuf) -> Self {
        Self { data_dir }
    }

    async fn send(&self, ctx: &RequestContext<RoleServer>, op: Value) -> String {
        let client = client_name(ctx.client_info().map(|i| i.name).as_deref());
        let dir = self.data_dir.clone();
        let reply = tokio::task::spawn_blocking(move || client::call(&dir, &client, op))
            .await
            .unwrap_or_else(|_| client::daemon_down());
        reply.to_string()
    }
}

/// Fallback when the client sends no `clientInfo`.
pub const UNKNOWN_CLIENT: &str = "unknown-mcp-client";

/// The agent's declared name (unverified), as shown in the approval prompt and
/// the audit log. `clientInfo.name` comes from the MCP `initialize` handshake,
/// or, on the 2026-07-28 lifecycle, from each request's `_meta`
/// (`RequestContext::client_info` checks both). Control characters are
/// dropped and the length is capped so a hostile name cannot forge prompt lines.
pub fn client_name(declared: Option<&str>) -> String {
    let clean: String = declared
        .unwrap_or("")
        .chars()
        .filter(|c| !c.is_control())
        .take(64)
        .collect();
    let clean = clean.trim();
    if clean.is_empty() {
        UNKNOWN_CLIENT.to_string()
    } else {
        clean.to_string()
    }
}

#[tool_router(server_handler)]
impl Logindesk {
    /// Log in to a website with the user's stored account. Secrets are filled by the broker
    /// and never returned: the password and any emailed one-time code go straight into the
    /// broker's own sealed browser. Returns JSON: {"status":"logged_in","session_id":...}
    /// on success, or a status such as denied, vault_locked, email_not_connected,
    /// needs_user (reason) or failed (reason). This is the fast path. If it returns
    /// failed/field_mapping_failed or the page needs extra steps, drive the page yourself
    /// with open, snapshot, type, click, fill_secret and press_enter.
    #[tool]
    async fn login(
        &self,
        Parameters(a): Parameters<LoginArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> String {
        let mut op = json!({"op": "login", "site": a.site});
        if let Some(acct) = a.account {
            op["account"] = acct.into();
        }
        self.send(&ctx, op).await
    }

    /// Create an account on a website with the user's identity (email, name) and a password
    /// the broker generates and stores. Secrets are filled by the broker and never returned;
    /// the emailed verification code or link is handled by the broker too. Returns JSON:
    /// {"status":"created","account_id":...,"session_id":...,"data":{"email_used":...}} on
    /// success; or denied, awaiting_approval (call wait), email_not_connected, needs_user
    /// (reason) or failed (reason). Refused for banks, government, health, payment and
    /// email-provider sites. This is the fast path. If it returns failed/field_mapping_failed
    /// or the form needs extra fields (name, phone, dropdowns, more steps), drive the page
    /// yourself with open, snapshot, type, click, fill_secret and press_enter.
    #[tool]
    async fn signup(
        &self,
        Parameters(a): Parameters<SignupArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> String {
        let mut op = json!({"op": "signup", "site": a.site});
        if let Some(u) = a.url {
            op["url"] = u.into();
        }
        self.send(&ctx, op).await
    }

    /// Wait for a login or signup that returned awaiting_approval (the user has not answered
    /// the Touch ID prompt yet). Returns the flow's final status, or awaiting_approval again
    /// if the user still has not answered. Secrets are filled by the broker and never returned.
    #[tool]
    async fn wait(
        &self,
        Parameters(a): Parameters<WaitArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> String {
        self.send(&ctx, json!({"op": "wait", "handle": a.handle}))
            .await
    }

    /// Open a page (e.g. a sign-up or sign-in page) in a new broker browser session and
    /// return its session_id. No secret, no prompt. Next: call snapshot to read the page.
    /// Secrets are filled by the broker and never returned.
    #[tool]
    async fn open(
        &self,
        Parameters(a): Parameters<OpenArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> String {
        self.send(&ctx, json!({"op": "open", "url": a.url})).await
    }

    /// Type NON-SECRET text (name, phone, address, username, search) into the field with
    /// this ref. Read snapshot first to find the ref. Never use this for a password,
    /// confirm-password, one-time code or the user's own email: those fields are refused
    /// (failed/field_refused). Use fill_secret for them. Never ask the user for a password
    /// or code. Secrets are filled by the broker and never returned.
    #[tool(name = "type")]
    async fn type_text(
        &self,
        Parameters(a): Parameters<TypeArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> String {
        self.send(
            &ctx,
            json!({"op": "type", "session_id": a.session_id, "ref": a.node_ref, "text": a.text}),
        )
        .await
    }

    /// Have the broker fill a secret it holds into the field with this ref. Read snapshot
    /// first: lines show field kinds like `[12] textbox "Password" (password, empty)` or
    /// `(code, empty)`. Use secret=password for a sign-in password, new_password for a
    /// sign-up password AND again for its confirm box (same generated password),
    /// email for the user's email address on a sign-up form, code for an emailed one-time
    /// code. You never see the value and must never ask the user for a password or code.
    /// May ask the user to approve (Touch ID); awaiting_approval means call wait.
    /// Secrets are filled by the broker and never returned.
    #[tool]
    async fn fill_secret(
        &self,
        Parameters(a): Parameters<FillSecretArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> String {
        let mut op = json!({
            "op": "fill_secret",
            "session_id": a.session_id,
            "ref": a.node_ref,
            "secret": a.secret.wire(),
        });
        if let Some(acct) = a.account {
            op["account"] = acct.into();
        }
        self.send(&ctx, op).await
    }

    /// Press Enter in the field with this ref to submit its form, then wait for the page.
    /// Take a snapshot afterwards to see the result. Secrets are filled by the broker and
    /// never returned.
    #[tool]
    async fn press_enter(
        &self,
        Parameters(a): Parameters<PressEnterArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> String {
        self.send(
            &ctx,
            json!({"op": "press_enter", "session_id": a.session_id, "ref": a.node_ref}),
        )
        .await
    }

    /// List the stored accounts the broker can log in with: account_id, site and username
    /// only. Secrets are filled by the broker and never returned.
    #[tool]
    async fn list_accounts(
        &self,
        Parameters(a): Parameters<ListAccountsArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> String {
        let mut op = json!({"op": "list_accounts"});
        if let Some(site) = a.site {
            op["site"] = site.into();
        }
        self.send(&ctx, op).await
    }

    /// A masked view of the logged-in page: URL, title and one line per element as
    /// `[ref] role "name"`. Text fields show (filled)/(empty), never their value.
    /// Secrets are filled by the broker and never returned.
    #[tool]
    async fn snapshot(
        &self,
        Parameters(a): Parameters<SessionArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> String {
        self.send(&ctx, json!({"op": "snapshot", "session_id": a.session_id}))
            .await
    }

    /// Open a URL in the session. Only URLs on the session's own site are allowed
    /// (anything else returns failed/fence_blocked). Secrets are filled by the broker and
    /// never returned.
    #[tool]
    async fn navigate(
        &self,
        Parameters(a): Parameters<NavigateArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> String {
        self.send(
            &ctx,
            json!({"op": "navigate", "session_id": a.session_id, "url": a.url}),
        )
        .await
    }

    /// Click the element with this ref from the latest snapshot. Secrets are filled by the
    /// broker and never returned.
    #[tool]
    async fn click(
        &self,
        Parameters(a): Parameters<ClickArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> String {
        self.send(
            &ctx,
            json!({"op": "click", "session_id": a.session_id, "ref": a.node_ref}),
        )
        .await
    }

    /// Close a browser session when you are done with it. Secrets are filled by the broker
    /// and never returned.
    #[tool]
    async fn close_session(
        &self,
        Parameters(a): Parameters<SessionArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> String {
        self.send(
            &ctx,
            json!({"op": "close_session", "session_id": a.session_id}),
        )
        .await
    }
}

/// Serve MCP on stdin/stdout until the client disconnects.
pub fn run(data_dir: PathBuf) -> std::io::Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async move {
        let svc = Logindesk::new(data_dir)
            .serve(rmcp::transport::stdio())
            .await
            .map_err(std::io::Error::other)?;
        svc.waiting().await.map_err(std::io::Error::other)?;
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_names() {
        assert_eq!(client_name(Some("claude-code")), "claude-code");
        assert_eq!(client_name(Some("  ")), UNKNOWN_CLIENT);
        assert_eq!(client_name(None), UNKNOWN_CLIENT);
        assert_eq!(client_name(Some("evil\nApprove")), "evilApprove");
        assert_eq!(client_name(Some(&"x".repeat(200))).len(), 64);
    }
}
