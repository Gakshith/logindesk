//! Phase 0 spike 3: rmcp 3.9 stdio server with one tool that blocks up to N seconds
//! (default 40) sending progress notifications every 5 s. Throwaway code.
//! Every event is appended to $SPIKE_LOG (default: $TMPDIR/rmcp-wait.log) with a timestamp.
use std::io::Write;
use std::time::{Duration, Instant};

use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{ProgressNotificationParam, RequestMetaObject};
use rmcp::service::RequestContext;
use rmcp::{tool, tool_router, Peer, RoleServer, ServiceExt};
use serde::Deserialize;

fn log(msg: impl AsRef<str>) {
    let path = std::env::var("SPIKE_LOG")
        .unwrap_or_else(|_| std::env::temp_dir().join("rmcp-wait.log").display().to_string());
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(path).unwrap();
    let _ = writeln!(f, "{} pid={} {}", chrono::Local::now().format("%H:%M:%S%.3f"), std::process::id(), msg.as_ref());
}

#[derive(Deserialize, schemars::JsonSchema)]
struct WaitArgs {
    /// How many seconds to block (default 40).
    seconds: Option<u64>,
    /// If true, send no progress notifications (to test the client timeout without keep-alives).
    quiet: Option<bool>,
}

#[derive(Clone)]
struct Spike;

#[tool_router(server_handler)]
impl Spike {
    /// Simulates waiting for a user approval popup. Blocks for `seconds` (default 40),
    /// sending a progress notification every 5 s, then returns "approved".
    #[tool]
    async fn wait_approval(
        &self,
        Parameters(args): Parameters<WaitArgs>,
        meta: RequestMetaObject,
        peer: Peer<RoleServer>,
        ctx: RequestContext<RoleServer>,
    ) -> String {
        let total = args.seconds.unwrap_or(40);
        let quiet = args.quiet.unwrap_or(false);
        let token = if quiet { None } else { meta.get_progress_token() };
        let client = peer.peer_info().map(|i| format!("{} {} proto={:?}", i.client_info.name, i.client_info.version, i.protocol_version));
        log(format!("CALL start seconds={total} quiet={quiet} progress_token={token:?} client={client:?} id={:?}", ctx.id));
        let start = Instant::now();
        let mut tick = 0u64;
        while start.elapsed() < Duration::from_secs(total) {
            tokio::select! {
                _ = ctx.ct.cancelled() => {
                    log(format!("CALL cancelled by client after {:.1}s", start.elapsed().as_secs_f64()));
                    return "cancelled".into();
                }
                _ = tokio::time::sleep(Duration::from_secs(total).saturating_sub(start.elapsed()).min(Duration::from_secs(5))) => {}
            }
            tick = start.elapsed().as_secs().min(total);
            match &token {
                Some(t) => {
                    let p = ProgressNotificationParam::new(t.clone(), tick as f64)
                        .with_total(total as f64)
                        .with_message(format!("waiting for approval: {tick}s / {total}s"));
                    let r = peer.notify_progress(p).await;
                    log(format!("progress {tick}/{total} sent ok={}", r.is_ok()));
                }
                None => log(format!("tick {tick}/{total} (no progress token, nothing sent)")),
            }
        }
        log(format!("CALL done after {:.1}s -> returning result", start.elapsed().as_secs_f64()));
        format!("approved after {total}s")
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    log("SERVER start");
    let svc = Spike.serve(rmcp::transport::stdio()).await?;
    let r = svc.waiting().await;
    log(format!("SERVER exit {r:?}"));
    Ok(())
}
