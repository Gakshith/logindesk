# The mcp ↔ daemon socket

Owned by `logindesk-daemon` (`crates/daemon/src/proto.rs`, `server.rs`).
Consumed by `logindesk-mcp` (`crates/mcp/src/client.rs`) and the CLI
(`logindesk login`, `logindesk lock`). Contract §8 fixes the rules: framed
JSON, a client token on every request, replies built from a `Status`, and **no
frame ever carries a secret**.

## Files

All in the data dir, the folder that holds the vault
(`~/Library/Application Support/logindesk/` on macOS).

| File | Mode | What |
|---|---|---|
| (the dir) | 0700 | set by the daemon at start |
| `daemon.sock` | 0600 | the Unix socket |
| `client.token` | 0600 | 32 lowercase hex chars, fresh on every daemon start |
| `audit.jsonl` | 0600 | hash-chained log, see below |
| `grants.json` | 0600 | per-site `login` and `signup` tiers (written by `logindesk grant`) |
| `identity.json` | 0600 | `{"email","name"?}` signups are made as (`logindesk identity set`) |
| `mail.json` | 0600 | `{"kind":"mailpit"\|"outbox","url":"http://127.0.0.1:…"}`; absent = no mailbox |
| `profiles/<site>/` | | one Chrome profile per registrable domain |

A second daemon on the same dir refuses to start while the first answers on
the socket; a stale socket file is removed.

## Frames

```
[4 bytes: body length, big-endian u32][body: UTF-8 JSON]
```

- Max body 1 MiB (`MAX_FRAME`). A longer length prefix gets one
  `failed/internal` reply with message `frame too large`, then the connection
  closes without reading the body.
- One connection may carry many request/reply pairs, strictly in turn.

## Requests

```json
{"token":"<client.token>","client_name":"claude-code","op":"login","site":"github.com"}
```

| `op` | Fields | Success reply |
|---|---|---|
| `login` | `site` (host or URL), `account`? (username or account_id) | `logged_in` + `session_id`, `account_id` |
| `list_accounts` | `site`? | `ok` + `data.accounts[] = {account_id, site, username}` |
| `snapshot` | `session_id` | `ok` + `data = {url, title, lines[]}` |
| `navigate` | `session_id`, `url` | `ok` + `data.url` |
| `click` | `session_id`, `ref` (u64 from a snapshot line) | `ok` + `data.url` |
| `signup` | `site`, `url`? (signup page on the site) | `created` + `account_id`, `session_id`, `data.email_used` |
| `wait` | `handle` | the flow's final status, or `awaiting_approval` again |
| `close_session` | `session_id` | `ok` |
| `lock` | | `ok` (the daemon drops its vault keys) |
| `ping` | | `ok` |

The token is checked first (constant time). Missing or wrong →
`failed/not_paired`. Not JSON, an unknown op or bad fields →
`failed/internal` with a fixed message.

`client_name` is whatever the client declares (the MCP server passes the
peer's `clientInfo.name`). It is shown in prompts as "(unverified)" and
written to the audit log, clipped to 64 chars.

## Replies

```json
{"status":"failed","reason":"no_account"}
{"status":"logged_in","session_id":"<32 hex>","account_id":"<32 hex>"}
{"status":"email_not_connected","message":"Run `logindesk connect gmail` …"}
```

`status` is `Status::wire()`; `reason` is the `NeedsUserReason` /
`FailReason` tag. Optional fields are omitted when empty: `reason`,
`session_id`, `account_id`, `handle` (for `wait`), `message` (fixed text
only, never page text), `data` (snapshot lines, a URL, the account list, or
`email_used`).

## Approvals and `wait`

`login` and `signup` pass one gate. `deny` → `failed/grant_denied`; `auto` →
standing-grant token, no prompt; `ask` → Touch ID / Mac password on its own
thread, open up to 10 min. The call blocks up to 40 s for the answer. Answered:
it waits for the flow and returns its status. Not answered: it returns
`{"status":"awaiting_approval","handle":"<32 hex>"}` and the flow continues
when the user answers; `wait{handle}` blocks up to another 40 s and returns
the final status (or `awaiting_approval` again). A handle is collected once;
an unknown or collected handle is `failed/session_not_found`.

## Signup flow

1. Refused before any browser: a blocklisted site (banks, government, health,
   payments, email providers → `failed/grant_denied`), a `url` off the site
   (`fence_blocked`), no `identity.json` (`failed/internal` + how to set it),
   10 signups in the last 24 h (`failed/rate_limited`), the `signup` grant.
2. Approval `shares` = `["email", "name"?]`.
3. Browser on `url` or `https://<site>/signup`. A password is generated from
   the form's `passwordrules`, else 20 chars of upper/lower/digits/symbols.
4. **The record is stored `pending` before submit** (`created_by: "signup"`,
   site = `<origin>/login`, username = `you+<label>@domain`).
5. The executor fills email, name and every password field, never ticks a
   checkbox (a required unticked one → `needs_user/unknown_page`, unsubmitted),
   and submits. Plus-address refused → once more with the plain address.
6. A code or "check your email" page → the mailbox: a code is filled, a link
   on the site is opened.
7. Signed in (or at the login form) → record `active`, an `account_created`
   audit line, `created`. Rejected → record deleted. CAPTCHA →
   `needs_user/captcha`. Errors before submit (fence, mapping) delete the
   record; anything after keeps it `pending` (recoverable).

## Login flow

Order: account → grant → page → pre-check → **approval** → fill. No secret is
filled, and no password leaves the vault, before approval.

1. `site_of(site)`; keys wiped → `vault_locked`.
2. Login records whose `site_of(record.site)` matches, filtered by `account`
   (username or account_id): none → `no_account`, several → `account_ambiguous`.
3. `grants.json`, re-read on every request: `deny` → `failed/grant_denied`
   here, before any browser.
4. Any live session on the site closes first (one profile = one Chrome). The
   browser opens `record.site` if it is a URL, else `https://<site>/login`.
5. **Pre-check, before any prompt** (reads the page only, no secret): a
   CAPTCHA → `needs_user/captcha`; a page with no password field and no text
   field at all → `failed/field_mapping_failed`. Both end **without a Touch ID
   prompt**, so the user is not asked to approve a login that cannot happen. A
   page with any text field passes (a two-step sign-in shows only the email
   field first; the fill decides).
6. Approval: `auto` → standing-grant token, no prompt; `ask` (the default) →
   Touch ID / Mac password naming the agent (`client_name`, unverified):
   approved → token, denied or unavailable → `denied`, unanswered after 40 s →
   `awaiting_approval{handle}` (see `wait`). Each token's request id is
   recorded as spent.
7. The executor spends the token and fills the form. `LoggedIn` → `logged_in`;
   `LoginForm`/`Rejected` → `credentials_rejected`; `Captcha` →
   `needs_user/captcha`; `Unknown` → `needs_user/unknown_page` (the session
   stays open for both `needs_user` replies, with its `session_id`).
   `NeedsOtp`: no mailbox → `email_not_connected`; else poll every 3 s for up
   to 3 min for mail since login start − 30 s: a code is filled, a link on the
   site is opened, several codes → `needs_user/ambiguous_otp`, none →
   `failed/timeout`.
8. Executor errors: `Fence` → `fence_blocked`, `Unreachable` →
   `site_unreachable`, `Timeout` → `timeout`, `Mapping` →
   `field_mapping_failed`, `Token` → `grant_denied`, anything else →
   `internal` (detail on the daemon's stderr).

`client_name` is the MCP client's `clientInfo.name`: from the `initialize`
handshake, or from each request's `_meta` on the 2026-07-28 lifecycle. It is
cleaned (control characters dropped, 64 chars max) and shown in the prompt and
the audit log as declared, never trusted.

`navigate` refuses any URL that is not http(s) on the session's registrable
domain (`fence_blocked`) before the browser sees it. Sessions idle for 30 min
close. `logindesk daemon --lock-after N` drops the keys after N minutes with no
request.

## Audit log

One line per request, including refused ones:

```json
{"ts":1763251200,"client":"claude-code","op":"login","site":"github.com","status":"logged_in","reason":"","prev":"<64 hex>","hash":"<64 hex>"}
```

`hash = sha256(prev || canonical)`, where `canonical` is the line's JSON
without `hash`, fields in exactly the order above. The first `prev` is 64
zeros. `logindesk_daemon::audit::verify` rejects any edited, deleted,
reordered or re-serialised line. The log holds typed values only: no secret,
no URL, no page text.
