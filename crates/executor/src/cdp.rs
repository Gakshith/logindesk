//! Minimal CDP client over the pipe: NUL-terminated JSON messages. Never sends `Runtime.enable`.

use std::io::{BufRead, BufReader, PipeReader, PipeWriter, Write};
use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

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
                        if let Ok(v) = serde_json::from_slice::<Value>(&buf) {
                            if etx.send(v).is_err() {
                                break;
                            }
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
        let mut bytes = serde_json::to_vec(&msg).map_err(|_| ExecError::Browser("encode"))?;
        bytes.push(0);
        self.tx
            .write_all(&bytes)
            .map_err(|_| ExecError::Browser("pipe closed"))?;
        // Zero the outgoing buffer: it may hold a secret from Input.insertText.
        bytes.iter_mut().for_each(|b| *b = 0);
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
        if let Some(i) = self.backlog.iter().position(|v| v["method"] == method) {
            return Ok(self.backlog.remove(i));
        }
        let deadline = Instant::now() + limit;
        loop {
            let v = self.recv(deadline)?;
            if v["method"] == method {
                return Ok(v);
            }
        }
    }
}
