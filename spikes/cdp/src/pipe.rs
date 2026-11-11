//! Raw CDP over --remote-debugging-pipe (fd 3 = Chrome reads, fd 4 = Chrome writes,
//! messages are JSON terminated by '\0'). Never sends Runtime.enable.
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::FromRawFd;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::mpsc::{channel, Receiver};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

struct Cdp {
    tx: File,
    rx: Receiver<Value>,
    next: u64,
    events: BTreeMap<String, u32>,
    backlog: Vec<Value>,
}

impl Cdp {
    fn send(&mut self, method: &str, params: Value, session: Option<&str>) -> anyhow::Result<Value> {
        self.next += 1;
        let id = self.next;
        let mut msg = json!({"id": id, "method": method, "params": params});
        if let Some(s) = session {
            msg["sessionId"] = json!(s);
        }
        let mut bytes = serde_json::to_vec(&msg)?;
        bytes.push(0);
        self.tx.write_all(&bytes)?;
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let v = self.rx.recv_timeout(deadline - Instant::now())?;
            if v["id"].as_u64() == Some(id) {
                if let Some(e) = v.get("error") {
                    anyhow::bail!("{method} failed: {e}");
                }
                return Ok(v["result"].clone());
            }
            self.note(v);
        }
    }
    fn note(&mut self, v: Value) {
        if let Some(m) = v["method"].as_str() {
            *self.events.entry(m.to_string()).or_default() += 1;
            self.backlog.push(v);
        }
    }
    fn wait_event(&mut self, method: &str, secs: u64) -> anyhow::Result<()> {
        if let Some(i) = self.backlog.iter().position(|v| v["method"] == method) {
            self.backlog.remove(i);
            return Ok(());
        }
        let deadline = Instant::now() + Duration::from_secs(secs);
        loop {
            let v = self.rx.recv_timeout(deadline - Instant::now())?;
            let hit = v["method"] == method;
            self.note(v);
            if hit {
                return Ok(());
            }
        }
    }
    fn drain(&mut self, ms: u64) {
        while let Ok(v) = self.rx.recv_timeout(Duration::from_millis(ms)) {
            self.note(v);
        }
    }
}

fn mkpipe() -> (i32, i32) {
    let mut fds = [0i32; 2];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    for fd in fds {
        unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
    }
    (fds[0], fds[1])
}

pub fn run(lang: Vec<String>) -> anyhow::Result<()> {
    let url = crate::serve_page();
    let profile = crate::fresh_profile("pipe");
    let (to_chrome_r, to_chrome_w) = mkpipe();
    let (from_chrome_r, from_chrome_w) = mkpipe();

    let mut cmd = Command::new(crate::CHROME);
    cmd.arg("--remote-debugging-pipe")
        .arg(format!("--user-data-dir={}", profile.display()))
        .args(["--no-first-run", "--no-default-browser-check", "--disable-extensions"])
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    cmd.args(&lang);
    cmd.arg("about:blank");
    unsafe {
        cmd.pre_exec(move || {
            // move both ends above 10 first so dup2 onto 3/4 can't clobber each other
            let a = libc::fcntl(to_chrome_r, libc::F_DUPFD, 10);
            let b = libc::fcntl(from_chrome_w, libc::F_DUPFD, 10);
            if a < 0 || b < 0 || libc::dup2(a, 3) < 0 || libc::dup2(b, 4) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = cmd.spawn()?;
    unsafe {
        libc::close(to_chrome_r);
        libc::close(from_chrome_w);
    }
    eprintln!("[pipe] chrome pid {} launched with --remote-debugging-pipe (no TCP port opened)", child.id());

    let (etx, erx) = channel();
    let mut reader = unsafe { File::from_raw_fd(from_chrome_r) };
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 65536];
        loop {
            let n = match reader.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            buf.extend_from_slice(&chunk[..n]);
            while let Some(p) = buf.iter().position(|&b| b == 0) {
                let msg: Vec<u8> = buf.drain(..=p).collect();
                if let Ok(v) = serde_json::from_slice::<Value>(&msg[..msg.len() - 1]) {
                    if etx.send(v).is_err() {
                        return;
                    }
                }
            }
        }
    });
    let mut c = Cdp {
        tx: unsafe { File::from_raw_fd(to_chrome_w) },
        rx: erx,
        next: 0,
        events: Default::default(),
        backlog: vec![],
    };

    let ver = c.send("Browser.getVersion", json!({}), None)?;
    eprintln!("[pipe] Browser.getVersion: {} / protocol {}", ver["product"], ver["protocolVersion"]);
    let targets = c.send("Target.getTargets", json!({}), None)?;
    let page = targets["targetInfos"]
        .as_array()
        .and_then(|a| a.iter().find(|t| t["type"] == "page"))
        .ok_or_else(|| anyhow::anyhow!("no page target"))?;
    let tid = page["targetId"].as_str().unwrap().to_string();
    let sid = c.send("Target.attachToTarget", json!({"targetId": tid, "flatten": true}), None)?["sessionId"]
        .as_str()
        .unwrap()
        .to_string();
    let s = Some(sid.as_str());
    c.send("Page.enable", json!({}), s)?;
    c.send("Page.navigate", json!({"url": url}), s)?;
    c.wait_event("Page.loadEventFired", 15)?;
    c.drain(1200);

    let tree = c.send("Accessibility.getFullAXTree", json!({}), s)?;
    eprintln!("[pipe] AX nodes: {}", tree["nodes"].as_array().map(|a| a.len()).unwrap_or(0));
    for l in crate::ax_lines(&tree) {
        eprintln!("[pipe]   {l}");
    }

    let root = c.send("DOM.getDocument", json!({"depth": 0}), s)?["root"]["nodeId"].clone();
    for (sel, text) in [("#email", "spike@example.test"), ("#pw", crate::SECRET)] {
        let nid = c.send("DOM.querySelector", json!({"nodeId": root, "selector": sel}), s)?["nodeId"].clone();
        c.send("DOM.focus", json!({"nodeId": nid}), s)?;
        c.send("Input.insertText", json!({"text": text}), s)?;
    }
    c.drain(300);
    let tree = c.send("Accessibility.getFullAXTree", json!({}), s)?;
    eprintln!("[pipe] after DOM.focus + Input.insertText:");
    for l in crate::ax_lines(&tree).into_iter().filter(|l| l.starts_with("textbox") || l.contains("RUNTIME") || l.contains("clean")) {
        eprintln!("[pipe]   {l}");
    }
    let shot = c.send("Page.captureScreenshot", json!({"format": "png"}), s)?;
    let png = base64_decode(shot["data"].as_str().unwrap_or(""));
    let shot_path = profile.join("pipe.png");
    std::fs::write(&shot_path, png)?;
    eprintln!("[pipe] screenshot: {}", shot_path.display());

    let runtime: Vec<_> = c.events.keys().filter(|k| k.starts_with("Runtime.")).cloned().collect();
    eprintln!("[pipe] CDP events received: {:?}", c.events);
    eprintln!("[pipe] Runtime.* events: {runtime:?} (empty = Runtime domain never enabled)");
    let _ = c.send("Browser.close", json!({}), None);
    let _ = child.wait();
    Ok(())
}

fn base64_decode(s: &str) -> Vec<u8> {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0);
    for ch in s.bytes() {
        let Some(v) = T.iter().position(|&c| c == ch) else { continue };
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    out
}
