//! The Unix socket: `<data dir>/daemon.sock` (0600, dir 0700), a fresh client
//! token per start in `<data dir>/client.token` (0600), one thread per
//! connection, length-prefixed JSON frames (docs/socket.md).

use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use logindesk_core::status::FailReason;
use serde_json::Value;

use crate::broker::Broker;
use crate::proto::{MAX_FRAME, Reply, Request, read_frame, write_frame};

/// Socket file name in the data dir.
pub const SOCKET: &str = "daemon.sock";
/// Token file name in the data dir.
pub const TOKEN: &str = "client.token";

const OPS: [&str; 14] = [
    "login",
    "signup",
    "wait",
    "list_accounts",
    "snapshot",
    "navigate",
    "click",
    "close_session",
    "lock",
    "ping",
    "open",
    "type",
    "fill_secret",
    "press_enter",
];

/// How often idle sessions and `lock_after` are checked.
const TICK: Duration = Duration::from_secs(15);

/// Socket path for a data dir.
pub fn socket_path(data_dir: &Path) -> io::Result<PathBuf> {
    logindesk_core::paths::socket_path(data_dir)
}

/// Token path for a data dir.
pub fn token_path(data_dir: &Path) -> PathBuf {
    data_dir.join(TOKEN)
}

fn random_token() -> io::Result<String> {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).map_err(|_| io::Error::other("OS random number generator failed"))?;
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}

/// Constant-time compare (length leaks, content does not).
fn token_eq(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

/// A bound socket, ready to serve.
#[derive(Debug)]
pub struct Server {
    listener: UnixListener,
    token: String,
    socket: PathBuf,
    token_file: PathBuf,
    stop: Arc<AtomicBool>,
}

impl Server {
    /// Make the data dir 0700, refuse if a daemon already answers on the
    /// socket, bind it 0600 and write a fresh token (0600).
    pub fn bind(data_dir: &Path) -> io::Result<Self> {
        std::fs::create_dir_all(data_dir)?;
        std::fs::set_permissions(data_dir, std::fs::Permissions::from_mode(0o700))?;
        let socket = socket_path(data_dir)?;
        if socket.exists() {
            if UnixStream::connect(&socket).is_ok() {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "a logindesk daemon is already running",
                ));
            }
            std::fs::remove_file(&socket)?;
        }
        let listener = UnixListener::bind(&socket)?;
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))?;
        let token = random_token()?;
        let token_file = token_path(data_dir);
        let tmp = token_file.with_extension("tmp");
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(token.as_bytes())?;
        f.sync_all()?;
        std::fs::rename(&tmp, &token_file)?;
        Ok(Self {
            listener,
            token,
            socket,
            token_file,
            stop: Arc::new(AtomicBool::new(false)),
        })
    }

    /// A flag that stops `serve` at the next connection or tick.
    pub fn stop_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.stop)
    }

    /// Socket path.
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// Accept forever (until the stop flag), one thread per connection,
    /// plus a housekeeping thread.
    pub fn serve(self, broker: Arc<Broker>) -> io::Result<()> {
        let token: Arc<str> = Arc::from(self.token.as_str());
        {
            let b = Arc::clone(&broker);
            let stop = Arc::clone(&self.stop);
            std::thread::Builder::new()
                .name("logindesk-tick".into())
                .spawn(move || {
                    while !stop.load(Ordering::Relaxed) {
                        std::thread::sleep(TICK);
                        b.tick(Instant::now());
                    }
                })?;
        }
        for conn in self.listener.incoming() {
            if self.stop.load(Ordering::Relaxed) {
                break;
            }
            let Ok(stream) = conn else { continue };
            let b = Arc::clone(&broker);
            let t = Arc::clone(&token);
            let _ = std::thread::Builder::new()
                .name("logindesk-conn".into())
                .spawn(move || serve_conn(stream, &b, &t));
        }
        broker.shutdown();
        Ok(())
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket);
        let _ = std::fs::remove_file(&self.token_file);
    }
}

/// One connection: frames until EOF. An oversize or unreadable frame gets one
/// `failed/internal` reply and the connection closes.
pub fn serve_conn(mut s: UnixStream, broker: &Arc<Broker>, token: &str) {
    loop {
        let body = match read_frame(&mut s) {
            Ok(Some(b)) => b,
            Ok(None) => return,
            Err(e) => {
                let msg = if e.kind() == io::ErrorKind::InvalidData {
                    "frame too large"
                } else {
                    "bad frame"
                };
                let r = Reply::failed(FailReason::Internal).with_message(msg);
                broker.audit_refused("", "frame", &r);
                let _ = write_frame(&mut s, &r.to_bytes());
                return;
            }
        };
        let reply = answer(&body, broker, token);
        if write_frame(&mut s, &reply.to_bytes()).is_err() {
            return;
        }
    }
}

/// Authenticate and dispatch one frame body.
pub fn answer(body: &[u8], broker: &Arc<Broker>, token: &str) -> Reply {
    debug_assert!(body.len() <= MAX_FRAME);
    let Ok(v) = serde_json::from_slice::<Value>(body) else {
        return Reply::failed(FailReason::Internal).with_message("request is not JSON");
    };
    let client = v
        .get("client_name")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    // Only known op names reach the audit log; anything else is "unknown".
    let op = v
        .get("op")
        .and_then(Value::as_str)
        .and_then(|o| OPS.iter().find(|k| **k == o))
        .copied()
        .unwrap_or("unknown");
    let presented = v.get("token").and_then(Value::as_str).unwrap_or("");
    if !token_eq(presented, token) {
        let r = Reply::failed(FailReason::NotPaired).with_message(
            "start `logindesk daemon`, then retry; the client token changes on every start",
        );
        broker.audit_refused(&client, op, &r);
        return r;
    }
    match serde_json::from_value::<Request>(v) {
        Ok(req) => broker.handle(&req),
        Err(_) => {
            let r = Reply::failed(FailReason::Internal).with_message("unknown op or bad fields");
            broker.audit_refused(&client, op, &r);
            r
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_compare() {
        assert!(token_eq("abc", "abc"));
        assert!(!token_eq("abc", "abd"));
        assert!(!token_eq("abc", "abcd"));
        assert!(!token_eq("", "a"));
    }

    #[test]
    fn tokens_are_32_hex() {
        let t = random_token().unwrap_or_default();
        assert_eq!(t.len(), 32);
        assert!(
            t.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
    }
}
