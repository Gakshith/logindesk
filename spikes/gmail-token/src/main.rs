//! Phase 0 spike 4: Gmail refresh-token lifetime for an "In production", unverified OAuth client.
//!   gmail-token login <client_secret.json>   loopback + PKCE consent for gmail.readonly, stores the token
//!   gmail-token check                        refreshes the token, calls users.getProfile, appends one line to check.log
//! State lives OUTSIDE the repo: ~/Library/Application Support/logindesk-spike/ (dir 0700, files 0600).
//! Nothing secret is ever printed or logged (no tokens, no client secret, no email address).
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;

use anyhow::{anyhow, bail, Context};
use oauth2::basic::BasicClient;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge, RedirectUrl,
    RefreshToken, Scope, TokenResponse, TokenUrl,
};
use serde::{Deserialize, Serialize};

const SCOPE: &str = "https://www.googleapis.com/auth/gmail.readonly";

#[derive(Serialize, Deserialize)]
struct Stored {
    client_id: String,
    client_secret: String,
    refresh_token: String,
    created_at: String,
}

fn dir() -> anyhow::Result<PathBuf> {
    let d = PathBuf::from(std::env::var("HOME")?).join("Library/Application Support/logindesk-spike");
    std::fs::create_dir_all(&d)?;
    std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700))?;
    Ok(d)
}

fn write_private(path: &PathBuf, bytes: &[u8]) -> anyhow::Result<()> {
    let mut f = std::fs::OpenOptions::new().create(true).write(true).truncate(true).mode(0o600).open(path)?;
    f.write_all(bytes)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn append_log(line: &str) -> anyhow::Result<()> {
    let p = dir()?.join("check.log");
    let mut f = std::fs::OpenOptions::new().create(true).append(true).mode(0o600).open(&p)?;
    writeln!(f, "{line}")?;
    println!("{line}\n(logged to {})", p.display());
    Ok(())
}

fn http() -> oauth2::reqwest::Client {
    oauth2::reqwest::ClientBuilder::new()
        .redirect(oauth2::reqwest::redirect::Policy::none())
        .build()
        .expect("http client")
}

fn client(id: &str, secret: &str) -> anyhow::Result<oauth2::basic::BasicClient<oauth2::EndpointSet, oauth2::EndpointNotSet, oauth2::EndpointNotSet, oauth2::EndpointNotSet, oauth2::EndpointSet>> {
    Ok(BasicClient::new(ClientId::new(id.into()))
        .set_client_secret(ClientSecret::new(secret.into()))
        .set_auth_uri(AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".into())?)
        .set_token_uri(TokenUrl::new("https://oauth2.googleapis.com/token".into())?))
}

async fn login(client_file: &str) -> anyhow::Result<()> {
    let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(client_file).context("read client json")?)?;
    let inst = v.get("installed").ok_or_else(|| anyhow!("expected a Desktop-app client JSON with an \"installed\" key"))?;
    let id = inst["client_id"].as_str().ok_or_else(|| anyhow!("no client_id"))?.to_string();
    let secret = inst["client_secret"].as_str().ok_or_else(|| anyhow!("no client_secret"))?.to_string();

    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    let redirect = format!("http://127.0.0.1:{port}");
    let c = client(&id, &secret)?.set_redirect_uri(RedirectUrl::new(redirect)?);
    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    let (url, state) = c
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new(SCOPE.into()))
        .add_extra_param("access_type", "offline")
        .add_extra_param("prompt", "consent")
        .set_pkce_challenge(challenge)
        .url();
    eprintln!("Opening Google's consent page in your browser (listening on 127.0.0.1:{port})...");
    std::process::Command::new("open").arg(url.as_str()).status()?;

    let (mut stream, _) = listener.accept()?;
    let mut req_line = String::new();
    BufReader::new(&stream).read_line(&mut req_line)?;
    let path = req_line.split_whitespace().nth(1).unwrap_or("/");
    let cb = url::Url::parse(&format!("http://127.0.0.1{path}"))?;
    let q: std::collections::HashMap<_, _> = cb.query_pairs().into_owned().collect();
    let body = if q.contains_key("code") { "logindesk spike: consent received. You can close this tab." } else { "logindesk spike: consent failed. See the terminal." };
    write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())?;
    if let Some(e) = q.get("error") {
        bail!("consent error: {e}");
    }
    if q.get("state").map(String::as_str) != Some(state.secret().as_str()) {
        bail!("state mismatch");
    }
    let code = q.get("code").ok_or_else(|| anyhow!("no code"))?;
    let tok = c
        .exchange_code(AuthorizationCode::new(code.clone()))
        .set_pkce_verifier(verifier)
        .request_async(&http())
        .await
        .map_err(|e| anyhow!("token exchange failed: {e}"))?;
    let refresh = tok.refresh_token().ok_or_else(|| anyhow!("Google returned no refresh token"))?;
    let granted: Vec<String> = tok.scopes().map(|s| s.iter().map(|x| x.to_string()).collect()).unwrap_or_default();
    let stored = Stored {
        client_id: id,
        client_secret: secret,
        refresh_token: refresh.secret().clone(),
        created_at: chrono::Utc::now().to_rfc3339(),
    };
    let p = dir()?.join("gmail-token.json");
    write_private(&p, &serde_json::to_vec_pretty(&stored)?)?;
    append_log(&format!("{} LOGIN ok scopes={granted:?} token_file={} (0600)", stored.created_at, p.display()))
}

async fn check() -> anyhow::Result<()> {
    let p = dir()?.join("gmail-token.json");
    let s: Stored = serde_json::from_slice(&std::fs::read(&p).context("no token yet; run `gmail-token login <client.json>` first")?)?;
    let now = chrono::Utc::now();
    let age = chrono::DateTime::parse_from_rfc3339(&s.created_at).map(|t| now.signed_duration_since(t)).ok();
    let age_s = age.map(|a| format!("{:.2}d", a.num_minutes() as f64 / 1440.0)).unwrap_or("?".into());
    let c = client(&s.client_id, &s.client_secret)?;
    match c.exchange_refresh_token(&RefreshToken::new(s.refresh_token.clone())).request_async(&http()).await {
        Ok(tok) => {
            let r = http()
                .get("https://gmail.googleapis.com/gmail/v1/users/me/profile")
                .bearer_auth(tok.access_token().secret())
                .send()
                .await?;
            let status = r.status();
            let total = r.text().await.ok().and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok()).and_then(|v| v["messagesTotal"].as_u64());
            append_log(&format!("{} CHECK ok refresh=ok token_age={age_s} getProfile={status} messagesTotal={total:?}", now.to_rfc3339()))
        }
        Err(e) => {
            // RequestTokenError Display does not include the token; keep only the error kind.
            let msg = match &e {
                oauth2::RequestTokenError::ServerResponse(r) => format!("server_error={:?} desc={:?}", r.error(), r.error_description()),
                other => format!("{other}"),
            };
            append_log(&format!("{} CHECK FAIL token_age={age_s} {msg}", now.to_rfc3339()))
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let a: Vec<String> = std::env::args().collect();
    match (a.get(1).map(String::as_str), a.get(2)) {
        (Some("login"), Some(f)) => login(f).await,
        (Some("check"), _) => check().await,
        _ => {
            eprintln!("usage: gmail-token login <client_secret.json> | check");
            Ok(())
        }
    }
}
