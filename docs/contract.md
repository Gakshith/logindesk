# Cross-crate contract

The interfaces two or more crates (and two builders) depend on. Frozen for the
0.1 build: change one only by editing this file in its own PR to `dev`, and say
which crates it breaks.

Anything not listed here is private to the crate that owns it.

## 1. `Secret<T>` (`logindesk-core`, exists)

- Every password, OTP, magic link, refresh token, API key and vault key travels
  as `Secret<T>` / `SecretString` from the moment it is read until it drops.
- No `Serialize`, `Clone`, `PartialEq` or `Deref`. `Debug`/`Display` print
  `[REDACTED]`. Reading takes `.expose()`.
- `.expose()` may appear only in `vault`, `executor` (the fill call), `mail`
  (parser internals), `approver` (password fallback compare) and `daemon`. Never
  in `mcp`, `policy` or `core` outside tests. Review greps for it.
- A secret never crosses the mcp ↔ daemon socket. `logindesk mcp` holds no
  secrets, ever.

## 2. Tool status (`logindesk-core::status`)

The only shape a tool result or a daemon reply can take. Wire form is the
snake_case tag shown; `mcp` serialises it, `core` stays serde-free.

```rust
pub enum Status {
    LoggedIn { session_id: SessionId },
    Created { account_id: AccountId, session_id: SessionId, email_used: String },
    Ok,
    AwaitingApproval { handle: Handle },        // "awaiting_approval"
    Denied,                                     // "denied"
    VaultLocked,                                // "vault_locked"
    EmailNotConnected,                          // "email_not_connected"
    NeedsUser { reason: NeedsUserReason },      // "needs_user"
    Failed { reason: FailReason },              // "failed"
}

pub enum NeedsUserReason { Captcha, Sms, SecondFactorOther, UnknownPage, AmbiguousOtp }

pub enum FailReason {
    CredentialsRejected, NoAccount, AccountAmbiguous, FieldMappingFailed,
    FenceBlocked, SiteUnreachable, Timeout, RateLimited, NotPaired,
    GrantDenied, SessionNotFound, Internal,
}
```

- Every enum is closed: no `String` reason, no `Other(String)`. An internal
  error maps to `Failed { Internal }` and its detail goes to the audit log
  (secret-free), never to the caller.
- `email_not_connected` carries the fixed message: *"Run `logindesk connect
  gmail` (or `connect imap`) in a terminal, then retry."*

## 3. Ids (`logindesk-core::ids`)

`SessionId`, `Handle`, `AccountId`, `ClientId`, `RequestId`: 128 random bits
from the OS RNG, shown as 32 lowercase hex chars on the wire. Opaque to every
caller; `Display` prints the hex, `FromStr` parses it. `RecordId` stays in
`vault`; `AccountId` is the public alias the MCP layer shows for a login record.

## 4. Limits (`logindesk-core::limits`)

One place for every timeout in plan §5 invariant 4. Crates import these
constants; none hard-codes its own.

| Constant | Value |
|---|---|
| `APPROVAL_IN_CALL` | 40 s |
| `APPROVAL_WAIT_MAX` | 10 min |
| `APPROVAL_TOKEN_TTL` | 60 s |
| `OTP_WAIT_MAX` | 3 min |
| `OTP_POLL_EVERY` | 3 s |
| `OTP_MAX_MESSAGES` | 5 |
| `OTP_LOOKBACK` | 15 min |
| `PAGE_LOAD_MAX` | 30 s |
| `SNAPSHOT_MAX` | 5 s |
| `SESSION_IDLE_CLOSE` | 30 min |

`vault::AUTO_LOCK_AFTER` (15 min) stays in `vault`.

## 5. Approvals (`logindesk-approver`, used by `daemon` and `executor`)

```rust
pub struct ApprovalRequest {
    pub request_id: RequestId,
    pub client_name: String,     // as declared by the client; shown "(unverified)"
    pub action: Action,          // Pair | Login | Signup | Submit | CaptureSecret
    pub site: String,            // registrable domain (eTLD+1), see §6
    pub shares: Vec<String>,     // signup: field labels to be shared; else empty
}

pub enum ApprovalOutcome { Approved, Denied, TimedOut, Unavailable }

pub trait Approver: Send + Sync {
    /// Blocks until the user answers or `limit` passes. Never panics.
    fn approve(&self, req: &ApprovalRequest, limit: Duration) -> ApprovalOutcome;
}
```

- `Approved` only from a fresh `LAContext` whose reply is `success == true`
  with no error. Every other path is `Denied`/`TimedOut`/`Unavailable`
  (spike 1 rule, `docs/spike-results.md`).
- The sheet text names the agent, the action and the site, and says that
  typing the Mac password approves.
- On `Approved` the daemon mints an `ApprovalToken { request_id, action, site,
  issued_at }`: no `Clone`, no `Copy`, no serde, consumed by value. The daemon
  also records `request_id` as spent, so a replay through the socket fails
  even though the type already prevents reuse in-process.
- A token older than `APPROVAL_TOKEN_TTL` is refused at use.
- The executor's fill and submit calls take `ApprovalToken` **by value** and
  check `action` and `site` match the call. No token, no fill.
- `Scripted` and any auto-approve type exist only under the `test-doubles`
  feature; the release CI job asserts their symbols are absent.

## 6. Sites (`logindesk-policy::site`)

```rust
/// Lowercase ASCII registrable domain (eTLD+1) of `host`, or None.
/// IP literals, `localhost` itself, empty and non-ASCII input → None
/// (callers punycode first). `*.localhost` and `*.test` resolve normally,
/// so the fake site's hosts work.
pub fn registrable_domain(host: &str) -> Option<String>;
```

Backed by `psl` (pinned). It is the only eTLD+1 function in the workspace:
`executor` (fence, same-site fill), `mail` (DKIM alignment, link domain) and
`daemon` all call it. No crate re-implements it.

## 7. Mail (`logindesk-mail`, used by `daemon`)

```rust
pub struct MailQuery { pub site: String, pub since: SystemTime }  // site = eTLD+1

pub trait MailSource: Send + Sync {
    /// At most OTP_MAX_MESSAGES raw RFC 5322 messages from `site`, newest first.
    fn search(&self, q: &MailQuery) -> Result<Vec<RawMessage>, MailError>;
}

pub struct RawMessage { pub id: String, pub received: SystemTime, pub bytes: Secret<Vec<u8>> }

pub enum MailError { NotConnected, Transient, Internal }   // NotConnected → Status::EmailNotConnected

pub enum OtpOutcome {
    Code(SecretString),
    Link(SecretString),        // https, on the site's registrable domain
    Ambiguous,                 // → NeedsUser { AmbiguousOtp }
    NotFound,
}

pub fn extract_otp(msgs: &[RawMessage], q: &MailQuery, used: &mut UsedCodes) -> OtpOutcome;
```

- `invalid_grant` and IMAP auth failures are `NotConnected`; nothing else is.
- The parser never calls a model, never follows a link, never logs a body.
- The daemon owns polling (every `OTP_POLL_EVERY`, up to `OTP_WAIT_MAX`, only
  while a flow waits). `mail` performs one search per call.

## 8. mcp ↔ daemon socket

Owned and specified by `logindesk-daemon` (Phase 4) in `docs/socket.md`;
`mcp` (Phase 6) consumes it. Rules fixed here: length-prefixed JSON frames, a
per-client token on every request, replies are always a §2 `Status`, and no
frame ever carries a secret.

## 9. Audit (`logindesk-daemon::audit`)

Append-only, hash-chained JSONL. Every crate reports auditable events to the
daemon as typed values (`action`, `site`, `client_id`, `status`), never as
free text that could carry a secret. The canary harness scans the audit file.

## 10. Executor (`logindesk-executor`, used by `daemon`)

The signatures in `crates/executor/src/lib.rs` are frozen: `BrowserConfig`,
`Session::{launch, navigate, current_url, snapshot, click, page_state,
fill_login, fill_otp, close}`, `PageState`, `Snapshot`, `ExecError`.

- `fill_login` takes the `ApprovalToken` by value, spends it for
  `(Action::Login, site)` (`ExecError::Token` on failure) and refuses
  (`ExecError::Fence`) unless the page URL **and** the login form's resolved
  action URL have `registrable_domain == site`.
- A `Snapshot` never contains a text-field value.
- `Runtime.enable` is never sent. No TCP debugging port is opened.

## 11. Grants (`logindesk-policy::grants`)

`grants.json` beside the vault maps a registrable domain to a login `Tier`:
`auto` (the agent logs in with no prompt: the user granted it once in a
terminal with `logindesk grant`), `ask` (Touch ID / Mac password each time,
the default) or `deny`. A standing grant mints
`ApprovalToken::from_standing_grant`; everything else goes through the
`Approver`.

## 12. Agent-driven forms: `open`, `type`, `fill_secret`

For pages `login` / `signup` cannot map on their own (extra fields, odd
layouts, passwordless sign-up), the agent drives the page step by step and
the broker fills only the secrets. The agent never sees a secret value.

**Executor (frozen, `crates/executor/src/lib.rs`):** `SecretField::{Password,
Code, Email}`, `Session::{type_text, fill_at, press_enter_at}`,
`ExecError::Refused` (→ `failed/field_refused`, `FailReason::FieldRefused`).
- `type_text` refuses password and one-time-code fields: the agent cannot
  type a secret, even one it guessed.
- `fill_at(Password)` fills only `input[type=password]`; `Code` and `Email`
  never fill a password field. Every call checks the page **and** the field's
  form action are on the session's site (`Fence`).
- Snapshot lines mark field kinds, e.g. `[12] textbox "Password" (password, empty)`,
  `[14] textbox "Code" (code, empty)`, so the agent knows which ref takes which secret.

**Socket ops (daemon):**
- `open {url}` → a session on `url`'s registrable domain. No secret, no prompt.
- `type {session_id, ref, text}` → `ok`. `text` ≤ 512 chars; the audit line
  records the op and site, never the text.
- `fill_secret {session_id, ref, secret, account?}` with `secret` one of:
  - `password`: the session site's stored account (`account` picks one).
    Gated like `login` (grant tier; `ask` = Touch ID naming the client); one
    approval covers that session + account until it closes.
  - `new_password`: generate a password (site rules), store it as a pending
    record for the identity email, fill it. Gated like `signup` (blocklist,
    daily limit, duplicate refusal). A second `new_password` in the same
    session (the confirm box) reuses the same password.
  - `email`: the identity's plus-address for this site (recorded as the
    pending record's username).
  - `code`: poll the connected mailbox for a code from the session's site
    (`extract_otp`, `UsedCodes`), fill it. Gated by the site's login tier.
- `press_enter {session_id, ref}` → submits the field's form.
- A pending `new_password` record is confirmed when the session closes on a
  page that is not a signup form; otherwise it stays pending (the password is
  never lost).
