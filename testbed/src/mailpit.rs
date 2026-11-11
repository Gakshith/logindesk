//! Mailpit in Docker, pinned by tag and digest. Both ports are published on `127.0.0.1` only,
//! with Docker choosing free host ports. The container is removed when [`Mailpit`] is dropped.
//!
//! Mailpit speaks SMTP (in) and HTTP (web UI and `/api/v1`). It has no IMAP server, so the IMAP
//! backend needs a separate fixture (see docs/testing.md).

use std::net::SocketAddr;
use std::process::Command;
use std::time::{Duration, Instant};

/// The pinned image: tag for humans, digest (multi-arch OCI index) for integrity.
pub const IMAGE: &str = "axllent/mailpit:v1.33.1@sha256:aef2aacc11f075ec0fb6874275ee4a421e688e11a96ebb296134d1735c7761ce";

/// A running Mailpit container.
#[derive(Debug)]
pub struct Mailpit {
    /// Container name (unique per run).
    pub container: String,
    /// SMTP address on loopback.
    pub smtp: SocketAddr,
    /// HTTP address on loopback (web UI and REST API).
    pub http: SocketAddr,
}

/// True when the `docker` CLI exists and the daemon answers.
pub fn docker_available() -> bool {
    Command::new("docker")
        .args(["info", "--format", "{{.ServerVersion}}"])
        .output()
        .is_ok_and(|o| o.status.success())
}

fn port_of(container: &str, inner: &str) -> Result<SocketAddr, String> {
    let out = Command::new("docker")
        .args(["port", container, inner])
        .output()
        .map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&out.stdout);
    text.lines()
        .find_map(|l| l.trim().parse::<SocketAddr>().ok())
        .filter(|a| a.ip().is_loopback())
        .ok_or_else(|| format!("docker port {container} {inner}: unexpected output {text:?}"))
}

impl Mailpit {
    /// Start the container and wait until SMTP accepts connections (30 s max).
    pub fn start() -> Result<Self, String> {
        let container = format!(
            "logindesk-testbed-mailpit-{}-{}",
            std::process::id(),
            crate::fixtures::random_alnum(6).to_lowercase()
        );
        let out = Command::new("docker")
            .args([
                "run",
                "-d",
                "--rm",
                "--name",
                &container,
                "-p",
                "127.0.0.1::1025",
                "-p",
                "127.0.0.1::8025",
                IMAGE,
            ])
            .output()
            .map_err(|e| format!("docker run: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "docker run failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        // Construct first so Drop removes the container even if a later step fails.
        let mut mp = Self {
            container,
            smtp: SocketAddr::from(([127, 0, 0, 1], 0)),
            http: SocketAddr::from(([127, 0, 0, 1], 0)),
        };
        mp.smtp = port_of(&mp.container, "1025/tcp")?;
        mp.http = port_of(&mp.container, "8025/tcp")?;
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if smtp_greets(mp.smtp) {
                return Ok(mp);
            }
            if Instant::now() > deadline {
                return Err("Mailpit did not accept SMTP within 30 s".into());
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    /// GET a Mailpit API path (e.g. `/api/v1/messages`) and return the body.
    pub fn api_get(&self, path: &str) -> Result<String, String> {
        use std::io::{Read, Write};
        let mut s = std::net::TcpStream::connect_timeout(&self.http, Duration::from_secs(5))
            .map_err(|e| e.to_string())?;
        s.set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|e| e.to_string())?;
        write!(
            s,
            "GET {path} HTTP/1.0\r\nHost: {}\r\nConnection: close\r\n\r\n",
            self.http
        )
        .map_err(|e| e.to_string())?;
        let mut buf = String::new();
        s.read_to_string(&mut buf).map_err(|e| e.to_string())?;
        let (head, body) = buf
            .split_once("\r\n\r\n")
            .ok_or("malformed HTTP response")?;
        if head.split_whitespace().nth(1) != Some("200") {
            return Err(format!(
                "Mailpit API {path}: {}",
                head.lines().next().unwrap_or("")
            ));
        }
        Ok(body.to_string())
    }
}

/// A real SMTP greeting ("220 ..."), not just an open port (Docker's proxy accepts early).
fn smtp_greets(addr: SocketAddr) -> bool {
    use std::io::Read;
    let Ok(mut s) = std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(500)) else {
        return false;
    };
    if s.set_read_timeout(Some(Duration::from_millis(1000)))
        .is_err()
    {
        return false;
    }
    let mut b = [0u8; 3];
    s.read_exact(&mut b).is_ok() && &b == b"220"
}

impl Drop for Mailpit {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "-f", &self.container])
            .output();
    }
}
