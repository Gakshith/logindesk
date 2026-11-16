//! The socket client: read `client.token`, send one frame, return the reply
//! JSON. Used by the MCP tools and by `logindesk login` / `lock`.
//! Frame format: docs/socket.md. Nothing here ever sees a secret.

use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use serde_json::{Value, json};

/// Largest reply accepted (same as the daemon's limit).
pub const MAX_FRAME: usize = 1 << 20;

/// A login can wait on an approval (40 s), page loads and an emailed code
/// (3 min); give it room.
const REPLY_WAIT: Duration = Duration::from_secs(10 * 60);

/// The reply when the daemon cannot be reached.
pub fn daemon_down() -> Value {
    json!({
        "status": "failed",
        "reason": "internal",
        "message": "start `logindesk daemon` in a terminal",
    })
}

fn exchange(data_dir: &Path, body: &[u8]) -> io::Result<Vec<u8>> {
    let mut s = UnixStream::connect(data_dir.join("daemon.sock"))?;
    s.set_read_timeout(Some(REPLY_WAIT))?;
    let n = u32::try_from(body.len()).map_err(|_| io::Error::other("request too large"))?;
    if body.len() > MAX_FRAME {
        return Err(io::Error::other("request too large"));
    }
    s.write_all(&n.to_be_bytes())?;
    s.write_all(body)?;
    s.flush()?;
    let mut len = [0u8; 4];
    s.read_exact(&mut len)?;
    let n = u32::from_be_bytes(len) as usize;
    if n > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "reply too large",
        ));
    }
    let mut buf = vec![0u8; n];
    s.read_exact(&mut buf)?;
    Ok(buf)
}

/// Send `op` (an object with `"op"` and its fields) as `client_name`.
/// Any failure to reach the daemon is [`daemon_down`].
pub fn call(data_dir: &Path, client_name: &str, op: Value) -> Value {
    let Ok(token) = std::fs::read_to_string(data_dir.join("client.token")) else {
        return daemon_down();
    };
    let mut req = match op {
        Value::Object(m) => m,
        _ => return daemon_down(),
    };
    req.insert("token".into(), Value::String(token.trim().to_string()));
    req.insert("client_name".into(), Value::String(client_name.to_string()));
    let Ok(body) = serde_json::to_vec(&Value::Object(req)) else {
        return daemon_down();
    };
    match exchange(data_dir, &body) {
        Ok(reply) => serde_json::from_slice(&reply).unwrap_or_else(|_| daemon_down()),
        Err(e) => {
            eprintln!("logindesk mcp: daemon unreachable: {e}");
            daemon_down()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_daemon_is_a_status_not_an_error() {
        let d = std::env::temp_dir().join(format!("ld-mcp-none-{}", std::process::id()));
        let v = call(&d, "t", json!({"op":"ping"}));
        assert_eq!(v, daemon_down());
        assert_eq!(v["message"], "start `logindesk daemon` in a terminal");
    }
}
