//! Phase 0 spike 1: LocalAuthentication popup from an unsigned `cargo build` binary. Throwaway.
//!   la-popup check                 canEvaluatePolicy(deviceOwnerAuthentication)
//!   la-popup auth [n]              evaluatePolicy n times in one process (default 2) and time each
//!   la-popup fallback              typed vault-password prompt via osascript hidden-answer dialog
//!   la-popup mcp                   stdio MCP server with tools approve_touchid / approve_password
//! Every outcome is printed to stderr and appended to $SPIKE_LOG (default $TMPDIR/la-popup.log).
use std::io::{IsTerminal, Write};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use block2::RcBlock;
use objc2::runtime::Bool;
use objc2_foundation::{NSError, NSString};
use objc2_local_authentication::{LAContext, LAPolicy};

/// The spike's fake vault password. NOT a secret; the fallback test only checks the typed value matches it.
const SPIKE_VAULT_PASSWORD: &str = "spike-vault";

fn log(msg: impl AsRef<str>) {
    let line = format!("{} pid={} ppid={} tty={} {}",
        chrono::Local::now().format("%H:%M:%S%.3f"), std::process::id(),
        std::os::unix::process::parent_id(), std::io::stdin().is_terminal(), msg.as_ref());
    eprintln!("{line}");
    let path = std::env::var("SPIKE_LOG")
        .unwrap_or_else(|_| std::env::temp_dir().join("la-popup.log").display().to_string());
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(f, "{line}");
    }
}

fn err_str(e: &NSError) -> String {
    format!("domain={} code={} desc={:?}", e.domain(), e.code(), e.localizedDescription().to_string())
}

pub fn check() -> String {
    let ctx = unsafe { LAContext::new() };
    let r = match unsafe { ctx.canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthentication) } {
        Ok(()) => "canEvaluate=ok".to_string(),
        Err(e) => format!("canEvaluate=ERR {}", err_str(&e)),
    };
    let bt = unsafe { ctx.biometryType() };
    let r = format!("{r} biometryType={bt:?}");
    log(format!("CHECK {r}"));
    r
}

/// One evaluatePolicy call. Blocks the calling thread until the reply block fires (max 120 s).
pub fn auth_once(reason: &str) -> String {
    let ctx = unsafe { LAContext::new() };
    let (tx, rx) = mpsc::channel::<String>();
    let block = RcBlock::new(move |ok: Bool, err: *mut NSError| {
        let msg = if ok.as_bool() {
            "SUCCESS".to_string()
        } else if let Some(e) = unsafe { err.as_ref() } {
            format!("FAIL {}", err_str(e))
        } else {
            "FAIL (no error object)".to_string()
        };
        let _ = tx.send(msg);
    });
    let t = Instant::now();
    log(format!("AUTH evaluatePolicy(deviceOwnerAuthentication) reason={reason:?}"));
    unsafe {
        ctx.evaluatePolicy_localizedReason_reply(
            LAPolicy::DeviceOwnerAuthentication,
            &NSString::from_str(reason),
            &block,
        )
    };
    let out = match rx.recv_timeout(Duration::from_secs(120)) {
        Ok(m) => m,
        Err(_) => {
            unsafe { ctx.invalidate() };
            "TIMEOUT 120s (no reply)".into()
        }
    };
    let out = format!("{out} after {}ms", t.elapsed().as_millis());
    log(format!("AUTH result: {out}"));
    out
}

/// Fallback: ask for the vault password in a system dialog (works without a TTY).
/// Never logs the typed value, only whether it matched.
pub fn fallback(reason: &str) -> String {
    let script = format!(
        "display dialog \"{}\" & return & return & \"Type your logindesk vault password:\" default answer \"\" with hidden answer with title \"logindesk\" buttons {{\"Deny\", \"Approve\"}} default button \"Approve\" cancel button \"Deny\" with icon caution giving up after 110\ntext returned of result",
        reason.replace('"', "'")
    );
    let t = Instant::now();
    log("FALLBACK osascript hidden-answer dialog shown");
    let out = std::process::Command::new("/usr/bin/osascript").arg("-e").arg(script).output();
    let res = match out {
        Ok(o) if o.status.success() => {
            let typed = String::from_utf8_lossy(&o.stdout).trim_end_matches('\n').to_string();
            if typed.is_empty() {
                "TIMED_OUT_OR_EMPTY".into()
            } else if typed == SPIKE_VAULT_PASSWORD {
                "PASSWORD_MATCH".into()
            } else {
                "PASSWORD_MISMATCH".into()
            }
        }
        Ok(o) => format!("DENIED_OR_ERROR status={} stderr={:?}", o.status, String::from_utf8_lossy(&o.stderr).trim()),
        Err(e) => format!("SPAWN_ERROR {e}"),
    };
    let res = format!("{res} after {}ms", t.elapsed().as_millis());
    log(format!("FALLBACK result: {res}"));
    res
}

mod mcp {
    use rmcp::{tool, tool_router, ServiceExt};

    #[derive(Clone)]
    pub struct Popup;

    #[tool_router(server_handler)]
    impl Popup {
        /// Shows the macOS LocalAuthentication sheet (Touch ID or Mac password) and returns the outcome.
        #[tool]
        async fn approve_touchid(&self) -> String {
            let c = super::check();
            let r = tokio::task::spawn_blocking(|| super::auth_once("approve a TEST login to example.test (logindesk spike)"))
                .await
                .unwrap_or_else(|e| format!("join error {e}"));
            format!("{c}; {r}")
        }
        /// Shows the typed vault-password fallback dialog and returns whether the password matched.
        #[tool]
        async fn approve_password(&self) -> String {
            tokio::task::spawn_blocking(|| super::fallback("Approve a TEST login to example.test (logindesk spike)"))
                .await
                .unwrap_or_else(|e| format!("join error {e}"))
        }
    }

    pub async fn serve() -> anyhow::Result<()> {
        super::log("MCP server start");
        let s = Popup.serve(rmcp::transport::stdio()).await?;
        let r = s.waiting().await;
        super::log(format!("MCP server exit {r:?}"));
        Ok(())
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("check") => {
            check();
        }
        Some("auth") => {
            let n: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(2);
            check();
            for i in 1..=n {
                log(format!("--- attempt {i}/{n}"));
                auth_once("approve a TEST login to example.test (logindesk spike)");
            }
        }
        Some("fallback") => {
            fallback("Approve a TEST login to example.test (logindesk spike)");
        }
        Some("mcp") => mcp::serve().await?,
        _ => eprintln!("usage: la-popup check | auth [n] | fallback | mcp"),
    }
    Ok(())
}
