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
    /// needs_user (reason) or failed (reason).
    #[tool]
    async fn login(&self, Parameters(a): Parameters<LoginArgs>, ctx: RequestContext<RoleServer>) -> String {
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
    /// email-provider sites.
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
    async fn wait(&self, Parameters(a): Parameters<WaitArgs>, ctx: RequestContext<RoleServer>) -> String {
        self.send(&ctx, json!({"op": "wait", "handle": a.handle}))
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
    async fn click(&self, Parameters(a): Parameters<ClickArgs>, ctx: RequestContext<RoleServer>) -> String {
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
