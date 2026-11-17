//! The mcp ↔ daemon wire format (docs/socket.md).
//!
//! A frame is a 4-byte big-endian length, then that many bytes of UTF-8 JSON.
//! Requests carry the client token; replies are always built from a
//! [`Status`]. No frame ever carries a secret.

use std::io::{self, Read, Write};

use logindesk_core::status::{EMAIL_NOT_CONNECTED_MSG, FailReason, Status};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Largest frame either side accepts.
pub const MAX_FRAME: usize = 1 << 20;

/// Read one frame. `Ok(None)` on a clean EOF before the length.
/// A length over [`MAX_FRAME`] is `InvalidData` and nothing more is read.
pub fn read_frame(r: &mut impl Read) -> io::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let n = u32::from_be_bytes(len) as usize;
    if n > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf)?;
    Ok(Some(buf))
}

/// Write one frame.
pub fn write_frame(w: &mut impl Write, body: &[u8]) -> io::Result<()> {
    if body.len() > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "frame too large",
        ));
    }
    let n = u32::try_from(body.len()).map_err(|_| io::Error::other("frame too large"))?;
    w.write_all(&n.to_be_bytes())?;
    w.write_all(body)?;
    w.flush()
}

/// One operation. Wire form: `"op": "<snake_case>"` beside its fields.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Op {
    /// Log in to a site with a stored account.
    Login {
        /// Host or URL; resolved to its registrable domain.
        site: String,
        /// Username or account id, when the site has more than one account.
        #[serde(default)]
        account: Option<String>,
    },
    /// Stored accounts (no secrets).
    ListAccounts {
        /// Only this site (host or URL).
        #[serde(default)]
        site: Option<String>,
    },
    /// Masked page snapshot.
    Snapshot {
        /// Session from `login`.
        session_id: String,
    },
    /// Go to a URL on the session's site.
    Navigate {
        /// Session from `login`.
        session_id: String,
        /// Target; must be on the session's registrable domain.
        url: String,
    },
    /// Click a node from the last snapshot.
    Click {
        /// Session from `login`.
        session_id: String,
        /// The `[ref]` from a snapshot line.
        #[serde(rename = "ref")]
        node_ref: u64,
    },
    /// Create an account on a site with the user's identity and a generated password.
    Signup {
        /// Host or URL; resolved to its registrable domain.
        site: String,
        /// The signup page, when not `https://<site>/signup`. Must be on `site`.
        #[serde(default)]
        url: Option<String>,
    },
    /// Open a page in a new session (no secret, no prompt).
    Open {
        /// http(s) URL; the session's site is its registrable domain.
        url: String,
    },
    /// Type non-secret text into a field (never a password or code field).
    Type {
        /// Session from `open`, `login` or `signup`.
        session_id: String,
        /// The `[ref]` from a snapshot line.
        #[serde(rename = "ref")]
        node_ref: u64,
        /// At most [`MAX_TYPE_CHARS`] characters. Never logged or audited.
        text: String,
    },
    /// Have the broker fill a secret it holds into a field.
    FillSecret {
        /// Session from `open`, `login` or `signup`.
        session_id: String,
        /// The `[ref]` from a snapshot line.
        #[serde(rename = "ref")]
        node_ref: u64,
        /// Which secret.
        secret: SecretKind,
        /// Username or account id for `password`, when the site has several.
        #[serde(default)]
        account: Option<String>,
    },
    /// Press Enter in a field (submits its form).
    PressEnter {
        /// Session from `open`, `login` or `signup`.
        session_id: String,
        /// The `[ref]` from a snapshot line.
        #[serde(rename = "ref")]
        node_ref: u64,
    },
    /// Wait for a flow that returned `awaiting_approval`.
    Wait {
        /// The handle from `awaiting_approval`.
        handle: String,
    },
    /// Close a browser session.
    CloseSession {
        /// Session from `login`.
        session_id: String,
    },
    /// Wipe the vault keys from the daemon.
    Lock,
    /// Liveness check.
    Ping,
}

impl Op {
    /// Wire name, for the audit log.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Login { .. } => "login",
            Self::ListAccounts { .. } => "list_accounts",
            Self::Snapshot { .. } => "snapshot",
            Self::Navigate { .. } => "navigate",
            Self::Click { .. } => "click",
            Self::Signup { .. } => "signup",
            Self::Open { .. } => "open",
            Self::Type { .. } => "type",
            Self::FillSecret { .. } => "fill_secret",
            Self::PressEnter { .. } => "press_enter",
            Self::Wait { .. } => "wait",
            Self::CloseSession { .. } => "close_session",
            Self::Lock => "lock",
            Self::Ping => "ping",
        }
    }
}

/// Longest text `type` accepts.
pub const MAX_TYPE_CHARS: usize = 512;

/// The secret `fill_secret` fills. The agent names the kind, never the value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    /// The stored password of the session site's account (gated like `login`).
    Password,
    /// A generated password for a new account, stored pending (gated like `signup`).
    /// A second one in the same session (the confirm box) is the same password.
    NewPassword,
    /// The identity's plus-address for this site (gated like `signup`).
    Email,
    /// An emailed one-time code from the session's site (gated by the login tier).
    Code,
}

/// A request frame.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Request {
    /// Contents of `<data dir>/client.token`.
    pub token: String,
    /// What the client calls itself (unverified).
    #[serde(default)]
    pub client_name: String,
    /// The operation.
    #[serde(flatten)]
    pub op: Op,
}

/// A reply frame. Every field but `status` is optional and omitted when empty.
#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize)]
pub struct Reply {
    /// [`Status::wire`].
    pub status: String,
    /// `needs_user` / `failed` reason tag.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Session to act in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Account the status is about.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    /// `awaiting_approval`: pass to `wait`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    /// Fixed human text (never page text, never a secret).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Snapshot lines, the URL, or the account list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl From<&Status> for Reply {
    fn from(s: &Status) -> Self {
        let mut r = Self {
            status: s.wire().to_string(),
            ..Self::default()
        };
        match s {
            Status::LoggedIn { session_id } => r.session_id = Some(session_id.to_string()),
            Status::Created {
                account_id,
                session_id,
                email_used,
            } => {
                r.account_id = Some(account_id.to_string());
                r.session_id = Some(session_id.to_string());
                r.data = Some(serde_json::json!({ "email_used": email_used }));
            }
            Status::AwaitingApproval { handle } => {
                r.handle = Some(handle.to_string());
                r.message =
                    Some("waiting for the user to approve; call wait with this handle".to_string());
            }
            Status::EmailNotConnected => r.message = Some(EMAIL_NOT_CONNECTED_MSG.to_string()),
            Status::NeedsUser { reason } => r.reason = Some(reason.wire().to_string()),
            Status::Failed { reason } => r.reason = Some(reason.wire().to_string()),
            Status::Ok | Status::Denied | Status::VaultLocked => {}
        }
        r
    }
}

impl From<Status> for Reply {
    fn from(s: Status) -> Self {
        Self::from(&s)
    }
}

impl Reply {
    /// `failed/<reason>`.
    pub fn failed(reason: FailReason) -> Self {
        Status::Failed { reason }.into()
    }

    /// Attach a fixed, secret-free message.
    pub fn with_message(mut self, m: &str) -> Self {
        self.message = Some(m.to_string());
        self
    }

    /// Attach data.
    pub fn with_data(mut self, d: Value) -> Self {
        self.data = Some(d);
        self
    }

    /// Serialise for the wire.
    pub fn to_bytes(&self) -> Vec<u8> {
        // A struct of strings and a Value always serialises.
        serde_json::to_vec(self)
            .unwrap_or_else(|_| br#"{"status":"failed","reason":"internal"}"#.to_vec())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use logindesk_core::ids::SessionId;
    use logindesk_core::status::NeedsUserReason;

    #[test]
    fn frames_round_trip_and_limit() {
        let mut buf = Vec::new();
        write_frame(&mut buf, b"{\"a\":1}").unwrap();
        assert_eq!(&buf[..4], &[0, 0, 0, 7]);
        let mut r = buf.as_slice();
        assert_eq!(read_frame(&mut r).unwrap().unwrap(), b"{\"a\":1}");
        assert!(read_frame(&mut r).unwrap().is_none());

        let mut big = ((MAX_FRAME + 1) as u32).to_be_bytes().to_vec();
        big.extend_from_slice(b"xx");
        let e = read_frame(&mut big.as_slice()).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
        assert!(write_frame(&mut Vec::new(), &vec![0u8; MAX_FRAME + 1]).is_err());
    }

    #[test]
    fn request_wire_form() {
        let r: Request = serde_json::from_str(
            r#"{"token":"t","client_name":"c","op":"click","session_id":"s","ref":7}"#,
        )
        .unwrap();
        assert_eq!(
            r.op,
            Op::Click {
                session_id: "s".into(),
                node_ref: 7
            }
        );
        let r: Request =
            serde_json::from_str(r#"{"token":"t","op":"login","site":"x.com"}"#).unwrap();
        assert_eq!(
            r.op,
            Op::Login {
                site: "x.com".into(),
                account: None
            }
        );
        assert!(serde_json::from_str::<Request>(r#"{"token":"t","op":"steal"}"#).is_err());
    }

    #[test]
    fn reply_shapes() {
        let id = SessionId::random();
        let r = Reply::from(Status::LoggedIn { session_id: id });
        assert_eq!(
            serde_json::to_string(&r).unwrap(),
            format!(r#"{{"status":"logged_in","session_id":"{id}"}}"#)
        );
        let r = Reply::from(Status::NeedsUser {
            reason: NeedsUserReason::Captcha,
        });
        assert_eq!(r.reason.as_deref(), Some("captcha"));
        let r = Reply::from(Status::EmailNotConnected);
        assert_eq!(r.message.as_deref(), Some(EMAIL_NOT_CONNECTED_MSG));
    }
}
