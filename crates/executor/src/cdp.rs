//! Minimal CDP client over the pipe: NUL-terminated JSON messages. Never sends `Runtime.enable`.

use std::io::{BufRead, BufReader, PipeReader, PipeWriter, Write};
use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use zeroize::Zeroize;

use crate::ExecError;

pub(crate) struct Cdp {
    tx: PipeWriter,
    rx: Receiver<Value>,
    next: u64,
    backlog: Vec<Value>,
    pub(crate) session: Option<String>,
}

impl Cdp {
    pub(crate) fn new(tx: PipeWriter, rx: PipeReader) -> Self {
        let (etx, erx) = channel();
        std::thread::spawn(move || {
            let mut r = BufReader::new(rx);
            let mut buf = Vec::new();
            loop {
                buf.clear();
                match r.read_until(0, &mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        if buf.last() == Some(&0) {
                            buf.pop();
                        }
                        if let Ok(v) = serde_json::from_slice::<Value>(&buf)
                            && etx.send(v).is_err()
                        {
                            break;
                        }
                    }
                }
            }
        });
        Self {
            tx,
            rx: erx,
            next: 0,
            backlog: Vec::new(),
            session: None,
        }
    }

    /// Send on the page session (or the browser when no session is attached).
    pub(crate) fn call(&mut self, method: &str, params: Value) -> Result<Value, ExecError> {
        let s = self.session.clone();
        self.send(method, params, s.as_deref(), Duration::from_secs(15))
    }

    pub(crate) fn send(
        &mut self,
        method: &str,
        params: Value,
        session: Option<&str>,
        limit: Duration,
    ) -> Result<Value, ExecError> {
        self.next += 1;
        let id = self.next;
        let mut msg = json!({"id": id, "method": method, "params": params});
        if let Some(s) = session {
            msg["sessionId"] = json!(s);
        }
        let bytes = serde_json::to_vec(&msg).map_err(|_| ExecError::Browser("encode"))?;
        self.write_and_wait(id, bytes, limit)
    }

    /// `Input.insertText` on the page session for a secret. The frame is built by hand
    /// (no `serde_json::Value` holding a copy) and every buffer is zeroized after the write.
    pub(crate) fn insert_secret_text(&mut self, text: &str) -> Result<(), ExecError> {
        self.next += 1;
        let id = self.next;
        let mut head = json!({"id": id, "method": "Input.insertText"});
        if let Some(s) = &self.session {
            head["sessionId"] = json!(s);
        }
        let head = serde_json::to_vec(&head).map_err(|_| ExecError::Browser("encode"))?;
        let mut quoted = serde_json::to_vec(text).map_err(|_| ExecError::Browser("encode"))?;
        let mut bytes = Vec::with_capacity(head.len() + quoted.len() + 16);
        // `head` ends with '}': reopen it to append the params object.
        bytes.extend_from_slice(&head[..head.len() - 1]);
        bytes.extend_from_slice(br#","params":{"text":"#);
        bytes.extend_from_slice(&quoted);
        bytes.extend_from_slice(b"}}");
        quoted.zeroize();
        self.write_and_wait(id, bytes, Duration::from_secs(15))
            .map(|_| ())
    }

    /// Write one frame (zeroized afterwards) and wait for the reply with `id`.
    fn write_and_wait(
        &mut self,
        id: u64,
        mut bytes: Vec<u8>,
        limit: Duration,
    ) -> Result<Value, ExecError> {
        bytes.push(0);
        let wrote = self.tx.write_all(&bytes);
        // The buffer may hold a secret (Input.insertText): wipe it before anything else.
        bytes.zeroize();
        wrote.map_err(|_| ExecError::Browser("pipe closed"))?;
        let deadline = Instant::now() + limit;
        loop {
            let v = self.recv(deadline)?;
            if v["id"].as_u64() == Some(id) {
                if v.get("error").is_some() {
                    return Err(ExecError::Protocol);
                }
                return Ok(v["result"].clone());
            }
            if v.get("method").is_some() {
                self.backlog.push(v);
            }
        }
    }

    fn recv(&mut self, deadline: Instant) -> Result<Value, ExecError> {
        let left = deadline.saturating_duration_since(Instant::now());
        self.rx.recv_timeout(left).map_err(|e| match e {
            RecvTimeoutError::Timeout => ExecError::Timeout,
            RecvTimeoutError::Disconnected => ExecError::Browser("browser exited"),
        })
    }

    pub(crate) fn clear_events(&mut self) {
        self.backlog.clear();
        while self.rx.try_recv().is_ok() {}
    }

    /// Wait for an event, consuming it. Times out with `ExecError::Timeout`.
    pub(crate) fn wait_event(&mut self, method: &str, limit: Duration) -> Result<Value, ExecError> {
        self.wait_any(&[method], limit)
    }

    /// Wait for the first event whose method is in `methods`, consuming it.
    pub(crate) fn wait_any(
        &mut self,
        methods: &[&str],
        limit: Duration,
    ) -> Result<Value, ExecError> {
        let hit = |v: &Value| v["method"].as_str().is_some_and(|m| methods.contains(&m));
        if let Some(i) = self.backlog.iter().position(hit) {
            return Ok(self.backlog.remove(i));
        }
        let deadline = Instant::now() + limit;
        loop {
            let v = self.recv(deadline)?;
            if hit(&v) {
                return Ok(v);
            }
        }
    }
}
