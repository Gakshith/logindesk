# Testing: test bed, Mailpit and the canary harness

Everything in `testbed/` is test-only. No `crates/*` crate depends on it.

## One command

```bash
cargo run -p testbed
```

This starts:
- **the fake site**
- **a second "other origin" listener**
- **Mailpit**, when Docker is available

Every URL, port and fixture credential is printed on stderr:

```text
[testbed] site        http://example.localhost:55020/
[testbed] lookalike   http://examp1e.localhost:55020/login
[testbed] other origin http://127.0.0.1:55021/
[testbed] gmail mock  http://example.localhost:55020/gmail/v1/users/me/messages  (Authorization: Bearer …)
[testbed] accounts    alice@example.localhost and otp@example.localhost (needs email code), password …
[testbed] mailpit     smtp 127.0.0.1:55017  ui http://127.0.0.1:55018/  (axllent/mailpit:v1.33.1@sha256:aef2…61ce)
[testbed] Ctrl-C or SIGTERM to stop
```

| Flag | Effect |
|---|---|
| (none) | Start Mailpit if `docker info` answers; otherwise run the site alone and keep mail in `/_testbed/outbox` |
| `--mailpit` | Require Mailpit; exit with an error if Docker is unavailable |
| `--no-mailpit` | Site only |
| `hostile` | Print the hostile-client attack list and exit |
| `TESTBED_PORT=<n>` | Fix the main port. The default is a free port picked at startup. The other origin always gets a free port. |

**Network rules:**
- Everything binds `127.0.0.1` only. Mailpit is published with `-p 127.0.0.1::1025 -p 127.0.0.1::8025`, so Docker picks free host ports.
- No fixed port is ever bound, so several worktrees can run at once.
- `*.localhost` resolves to loopback in Chrome and curl, so `example.localhost` and the lookalike `examp1e.localhost` need no DNS or `/etc/hosts` changes.
- Ctrl-C, SIGTERM or SIGHUP removes the Mailpit container.
- Every container is labelled `logindesk-testbed=1` and `logindesk-testbed.pid=<owner pid>`. If a test bed was killed with SIGKILL or crashed, the next start removes its leftover container. Containers whose owner is still running (another worktree's test bed) are left alone.

## The fake site

| Path | What it is for |
|---|---|
| `/login` | Password login. `alice@` signs in directly; `otp@` then needs a 6-digit code sent by email (`/login/otp`). |
| `/signup` | Signup. Sends a mail with a code (`/signup/verify`) and a single-use verification link (`/verify?token=`). Unverified accounts get 403 on login. |
| `/magic-link` | Emails a single-use sign-in link (`/magic?token=`). It does not reveal whether the account exists. |
| `/totp` | Authenticator-code page (RFC 6238, SHA-1, 30 s, 6 digits, ±1 step) using `Fixtures::totp_seed`. |
| `/captcha` | Login behind an image CAPTCHA. The answer exists only as SVG paths, never as text, so automation must stop with `needs_user`. |
| `/iframe-login` | The login form in a same-origin iframe and in a cross-origin iframe (`<other>/login-frame`). |
| `/cross-origin` | A login page on the real site whose form posts to `<other>/collect`. |
| `Host: examp1e.localhost` | Lookalike: same look, but the form posts to `/collect?src=lookalike`. |
| `/injected` | A login form plus `site::INJECTION_TEXT`, hidden 6 ways: HTML comment, `display:none`, off-screen `aria-hidden`, white-on-white text, `alt` text, `title`. |
| `/read-fields` | A login form plus a hostile script that copies every input value, passwords included, to `/collect` on input, change and every 500 ms. |
| `/collect` (both listeners) | The exfiltration sink. It records host, query and body. |
| `/_testbed/outbox`, `/_testbed/collected` | Test hooks (JSON): the mail sent and everything collected. |

## Gmail-REST mock

The mock serves `GET /gmail/v1/users/me/messages?q=&maxResults=` and `GET /gmail/v1/users/me/messages/{id}?format=full|metadata|minimal|raw` in Gmail's JSON shape. Bodies are base64url without padding.

**Auth:** requests need `Authorization: Bearer <gmail_token>`; otherwise the response is Google's 401 `UNAUTHENTICATED` error.

**Query:** `q` supports `from:`, `subject:`, `newer_than:Nd|Nh|Nm` and plain words.

**Messages:** results are newest first. The mock always holds two fixtures, plus every mail the site sent (DMARC-aligned for `example.localhost`):

| Fixture | From | DKIM `d=` | SPF `smtp.mailfrom` | DMARC | Code |
|---|---|---|---|---|---|
| `ALIGNED_ID` | `no-reply@example.com` | `example.com` | `no-reply@example.com` | pass | `ALIGNED_CODE` |
| `SPOOFED_ID` (newer) | `no-reply@example.com` | `evil-mailer.test` | `bounce@evil-mailer.test` | **fail** | `SPOOFED_CODE` |

`Authentication-Results` comes from `mx.google.com` and is folded the way Gmail folds it. Phase 8 must pick the aligned code even though the spoofed mail is newer.

## Mailpit

- **Image:** `testbed::mailpit::IMAGE` is pinned by tag **and** by the digest of the multi-arch OCI index: `axllent/mailpit:v1.33.1@sha256:aef2aacc…61ce`. To change it, pull the new tag, take the index digest from `docker buildx imagetools inspect`, and update both parts.
- **Delivery:** the site sends mail through a small built-in SMTP client (`testbed::smtp`). There is no TLS or auth, and it only talks to loopback.
- **No IMAP:** Mailpit has no IMAP server; it offers SMTP in, plus HTTP and POP3. The IMAP backend tests (Phase 8) need their own fixture, which is not part of Phase 3.

## Canary harness (`testbed::canary`)

```rust
let canary = Canary::new(["vault.password", "mail.otp_seed"]);
// plant canary.get("vault.password").value wherever a secret goes, run the flow, then:
let mut cap = Capture::new();
cap.text("mcp:stdout", &stdout).text("stderr", &stderr).text("panic", &panic_text)
   .text("snapshot", &snapshot_json).file(&audit_log).dir(&temp_dir);
canary.scan(&cap).assert_clean();
```

**Markers:** each is 32 random alphanumerics with `" \ / + & % space é` mixed in, so URL and JSON encoding really change the bytes.

**What the scanner matches.** It starts from every *text form* of each marker:
- raw
- JSON-escaped (UTF-8 and `\u` forms)
- URL-encoded (`%20`, `+`, lower-case hex)

Each text form is then matched:
- as itself
- as base64 and base64url at all 3 byte alignments
- as hex (lower and upper case)
- as every 8-character window that contains at least 5 alphanumerics

So composites are caught, for example `base64url({"password": marker})` in a JWT-style token or cookie, `hex(json)`, and `data:…;base64,` JSON.

`Capture::dir` scans file names as well as file contents. A file or directory that can't be read (a wrong audit-log path, say) is recorded as a `CAPTURE ERROR` and **fails** the report. It never counts as clean.

**Report:** one line per hit, `LEAK marker=<id> channel=<channel> encoding=<encoding>` (e.g. `base64url(json)@1`), plus one `CAPTURE ERROR …` line per unreadable path. `assert_clean()` panics on either.

**Gate** (`testbed/tests/canary_gate.rs`): a child process leaks one marker to stderr and writes another, base64-encoded, to a temp file. The test asserts that both are caught with the right channel and encoding, that untouched markers and clean channels give no false positives, and that `assert_clean()` fails. A matching clean run must pass. Panic output is checked the same way.

## Hostile MCP client (`testbed::hostile`)

`ATTACKS` names 37 attacks across every 0.1 tool and argument (`cargo run -p testbed -- hostile` lists them). `testbed/tests/hostile.rs` has one `#[ignore]` test per attack, and a live test checks that the list and the tests match. The tests become real in Phase 6, when the tools exist, and in Phases 7–8 for the flow attacks.

## Running the tests

```bash
cargo test -p testbed            # site, Gmail mock, canary gate, hostile list, Mailpit (if Docker)
cargo test -p testbed -- --ignored   # the hostile attacks: all fail with "not implemented" until Phase 6
```

**When the Mailpit test is skipped:** `tests/mailpit.rs` starts a real Mailpit container and checks that a site mail arrives. It **skips** (passes, printing a `SKIP` line) when `CI` is set or Docker is unavailable. CI therefore never pulls the image: GitHub's macOS runners have no Docker, and the Linux runners don't need the pull. Run it locally with Docker Desktop started.
