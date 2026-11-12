# Phase 0 spike results

Date: 2026-11-11 · Machine: macOS 26.6.2 (25G83), Apple silicon, Touch ID · Rust 1.97.1
Spike code: branch `spike/phase0`, folder `spikes/` (four standalone throwaway crates, never merged).

| # | Question | Answer |
|---|---|---|
| 1 | Does an unsigned binary get the LocalAuthentication sheet? | **Yes.** An unsigned `cargo build` binary (ad-hoc, linker-signed) got the sheet both when spawned with no TTY and as a Claude Code stdio MCP child. The `osascript` typed-password fallback works without a TTY too. The suspected "Cancel recorded as SUCCESS" is **explained: not a fail-open**. The user pressed "Use Password…" and the Mac login password was verified (unified log). The FAIL path maps correctly in 15/15 no-UI probes. |
| 2 | Can chromiumoxide drive installed Chrome over a pipe without `Runtime.enable`? | **No.** chromiumoxide 0.9.1 only does WebSocket and always sends `Runtime.enable`. A raw pipe client does all four things we need. |
| 3 | What does each client do with a 40 s tool call? | All three return the 40 s result. Cursor cancels at **60 s**, Codex 0.165 at **300 s** (progress doesn't extend it). Claude Code headless didn't time out at 330 s. |
| 4 | Does an "In production", unverified Gmail client keep its refresh token past 7 days? | **Deferred by the user** until the project is built end to end. The IMAP default stands. The `gmail-token` tool is ready on this branch. |

---

## 1. Approval popup (LocalAuthentication)

**Setup.** `spikes/la-popup` uses objc2-local-authentication 0.3.2:
- `canEvaluatePolicy` + `evaluatePolicy(.deviceOwnerAuthentication)`, with the reply block bridged to a channel. A 120 s timeout calls `invalidate()`.
- The fallback is an `osascript` `display dialog … with hidden answer` that compares the typed value with the fake vault password `spike-vault`. It logs only the match result, never the typed text.
- `la-popup mcp` serves `approve_touchid` and `approve_password` as an rmcp stdio server.
- The binary is an unsigned debug build. `codesign -dv` shows `Signature=adhoc`, `flags=0x20002(adhoc,linker-signed)`, and no Developer ID.

The lead session ran these on 2026-11-11 with the user at the Mac (Touch ID Mac, macOS 26.6.2). The ld-spikes code was unchanged.

| Run | How it was started | Result |
|---|---|---|
| (a) `la-popup auth 2` | spawned from an agent shell, **no TTY** (`tty=false` in the log) | `canEvaluate=ok biometryType=LABiometryType(1)`. Attempt 1: `SUCCESS after 7348ms`. Attempt 2: `SUCCESS after 52783ms` (meant to be Cancel; the user approved instead) |
| (b) `la-popup fallback` ×2 | same | Run 1: `PASSWORD_MISMATCH after 31189ms` (wrong text typed, correctly rejected). Run 2: `TIMED_OUT_OR_EMPTY after 873ms` (dialog dismissed at once, probably a held Enter) |
| (c) as a Claude Code stdio MCP child | `claude -p --mcp-config <temp json> --strict-mcp-config --allowedTools mcp__lapopup__approve_touchid,mcp__lapopup__approve_password` | `approve_touchid` → `canEvaluate=ok biometryType=LABiometryType(1); SUCCESS after 34876ms`. `approve_password` → `PASSWORD_MATCH after 18271ms`. The server log shows ppid = the `claude` process and `tty=false`. |
| (d) deny attempt, `la-popup auth 1` | same as (a) | `SUCCESS after 7728ms`. The user believed they clicked Cancel; the system log shows "Use Password…" followed by a verified Mac password (see below). |

Log excerpt for (a) and (b), from `$TMPDIR/la-popup.log` (ld-spikes copy):

```text
15:51:58.723 pid=46336 ppid=46332 tty=false CHECK canEvaluate=ok biometryType=LABiometryType(1)
15:52:06.083 pid=46336 ppid=46332 tty=false AUTH result: SUCCESS after 7348ms
15:52:58.908 pid=46336 ppid=46332 tty=false AUTH result: SUCCESS after 52783ms
15:53:36.023 pid=47481 ppid=47480 tty=false FALLBACK result: PASSWORD_MISMATCH after 31189ms
15:53:45.169 pid=48331 ppid=48329 tty=false FALLBACK result: TIMED_OUT_OR_EMPTY after 873ms
```

**Findings**
- **No -1000 on the first call.** The very first `evaluatePolicy` from a freshly built unsigned binary succeeded.
- **No TTY or app bundle needed.** Every run had `tty=false`, including the MCP child. LocalAuthentication showed its system sheet anyway, so the daemon can call it directly. (a) was not run in an interactive terminal tab; the no-TTY and MCP-child cases are the harder ones, and both passed.
- **An approval can take up to ~53 s.** That is already beyond the 40 s in-call budget (§3), so `awaiting_approval` + `wait(handle)` will happen in practice.
- **Run (b)2 shows a held key can dismiss the fallback dialog in under 1 s.** The fallback must treat empty or instant answers as "no answer", never as approval. It did here (`TIMED_OUT_OR_EMPTY`).
- **Every one of the four LA successes was approved with the Mac login password, never by Touch ID** (see the next section). That is valid for `.deviceOwnerAuthentication`, but it means the Touch ID path itself has not been exercised yet.

### Resolved (was OPEN): "Cancel recorded as SUCCESS"

**Claim:** the user clicked Cancel on the 15:55:31 sheet, yet `la-popup` logged `SUCCESS after 7728ms`. This was treated as a possible fail-open and investigated **without showing any more popups**.

**Evidence 1: the macOS unified log** shows what the sheet actually did.

Command:
```text
/usr/bin/log show --style compact --start '2026-11-11 15:55:31' --end '2026-11-11 15:55:41' \
  --predicate 'subsystem BEGINSWITH "com.apple.LocalAuthentication" OR process CONTAINS "coreauth"'
```

Excerpt:
```text
15:55:31.906 coreauthd  MechanismWatch isAvailable -> Error … Code=-11 "No AppleWatch was discovered."
15:55:32.054 coreautha  LAAuthBiometricsOrWatchDialogController cancel visible: 1, fallback visible: 1, show fallback immediately: 1
15:55:33.832 coreauthd  MechanismUI[655](run) has received UI event 3 (FallbackButtonPressed)
15:55:33.836 coreauthd  MechanismTouchId[652] has finished with Error … Code=-3 "Fallback authentication mechanism selected."
15:55:39.556 coreautha  -[LAAuthPasscodeDialogController okClicked:]
15:55:39.592 coreautha  MKB password verification for keybag 3 returned 0
15:55:39.592 coreauthd  MechanismUI[655](run) has received UI event 8 (PasscodeVerified)
15:55:39.594 coreauthd  -[MechanismUI uiSuccessWithResult:]
```

So the button pressed was **"Use Password…"**, not "Cancel". After that the user typed the **Mac login password**, and the system verified it before `la-popup` reported SUCCESS. The 15:52:02 and 15:52:11 runs show the same sequence: `FallbackButtonPressed` → `PasscodeVerified`. No Apple Watch is paired. The SUCCESS was a real, system-verified authentication, not a mis-decoded callback.

**Evidence 2: no-UI FAIL-path probes** (`la-popup probe 5`). They use a fresh `LAContext` per call and read the reply's `BOOL` as a raw byte through an ABI-identical `(u8, *mut NSError)` block. On aarch64, objc2's `BOOL` is C `_Bool`.

| Probe (×5 each) | Result, all 5 rounds |
|---|---|
| A `setInteractionNotAllowed(true)` | `raw_bool=0x00 as_bool=false`, `code=-1004 "User interaction required."`, 1–5 ms |
| B `invalidate()` before evaluate | `raw_bool=0x00 as_bool=false`, `code=-10`, 0 ms |
| C `.deviceOwnerAuthenticationWithWatch` (canEvaluate says no watch) | `raw_bool=0x00 as_bool=false`, `code=-11 "No companion device was discovered."` |

Across all 15 calls:
- the reply block fired **exactly once** (`reply calls=1 extra=[]`, checked 500 ms after the first reply)
- `touchIDAuthenticationAllowableReuseDuration` was `0`, so no reuse of an earlier unlock is possible
- the unified log shows **0** `showing UI` / `DidAppear` events in the probe window, so no sheet was shown

`auth_once` already creates a new `LAContext` for every call.

**Not checked:** the raw byte on a real Touch ID success (that would need a popup). The system log shows those successes were real on the OS side.

**What Phase 4's approver must do anyway:**
1. Approve **only** if the reply has `success == true` **and** `error == nil`, on a **fresh** `LAContext` created for that one request, with `touchIDAuthenticationAllowableReuseDuration = 0`. Read the `BOOL` through objc2's `Bool`. Anything else is a deny: any error, a missing reply, a timeout, a second reply, or a reply for another context.
2. Expect the Mac password path. `.deviceOwnerAuthentication` shows **"Use Password…" next to "Cancel" immediately** (`show fallback immediately: 1`), and the user pressed it every time thinking it was Cancel. The approval text must say clearly that typing the Mac password **approves**. If "Touch ID only" approvals are ever wanted, use `.deviceOwnerAuthenticationWithBiometrics` and accept that Macs without Touch ID then need the vault-password fallback.
3. Map errors to statuses: `-2 userCancel`, `-4 systemCancel`, `-9 appCancel`, `-1` and `-3` → `denied`; `-1004` (no UI possible) → `needs_user`; `-10` → internal error, never approve.
4. Treat an empty or instant (<1 s) answer in the typed vault-password fallback as "no answer", as run (b)2 did.

**Spike 1 is closed (lead decision, 2026-11-11).** No more popups. The Cancel code stays *expected (`-2 userCancel`), unrecorded*, and a real Touch ID approval is unrecorded too. Phase 4 follows the rule above.

---

## 2. Chrome over CDP

**Setup.** `spikes/cdp` serves a static sign-in page on `127.0.0.1:<random>` (no real sites). It runs two ways:
- `cdp oxide`: chromiumoxide 0.9.1 `Browser::launch`, headed, with installed Chrome 157.0.8103.50 and a fresh `--user-data-dir` under `$TMPDIR`.
- `cdp pipe`: about 200 lines of our own code. It starts Chrome with `--remote-debugging-pipe`, wiring fd 3 for Chrome's reads and fd 4 for its writes, with NUL-delimited JSON. It never sends `Runtime.enable`.

**Results**

| Check | chromiumoxide 0.9.1 (WebSocket) | Raw pipe client |
|---|---|---|
| Launches installed Chrome, headed, dedicated profile | yes | yes |
| Transport | WebSocket on a random port (`port: 0` is the default; URL parsed from stderr). **No pipe support:** `Connection` wraps `WebSocketStream` only (`src/conn.rs`). | pipe; no TCP port opened |
| `Runtime.enable` skippable? | **No.** `FrameManager::init_commands` (`src/handler/frame.rs:216`) always sends `Page.enable`, `Page.getFrameTree`, `Page.setLifecycleEventsEnabled` and `Runtime.enable` for every page. 2 `Runtime.executionContextCreated` events were seen. | **Yes.** 0 `Runtime.*` events across the whole run. |
| `Accessibility.getFullAXTree` | works (32 nodes; textbox "Email", textbox "Password", button "Sign in") | works (same 32 nodes) |
| `Input.insertText` into a focused field | works (`#pw.value == SECRET` → `true`) | works. Focus via `DOM.querySelector` + `DOM.focus`; no JS. The email box reads back `spike@example.test` in the AX tree. |
| Password field in the AX tree after fill | value shown as 28 `•` (one per character) | same |
| `navigator.webdriver` | `true` (chromiumoxide passes `--enable-automation`) | `true` by default; `false` with `--disable-blink-features=AutomationControlled` |

**Non-English locale.** `--lang=de` alone does **not** change the page locale on macOS (`navigator.language` stayed `en-US`). These two do:
- `--accept-lang=de-DE,de` → `navigator.language = de-DE / de-DE,de` (pipe and chromiumoxide)
- `-AppleLanguages (de)` as two separate argv items → `de-DE / de-DE,de,en-US,en`

The AX tree, focus and `insertText` behave the same under `de-DE`. Non-ASCII text (`Ünïcødé-✓`) is inserted intact.

Evidence (excerpt, `cdp pipe --accept-lang=de-DE,de --disable-blink-features=AutomationControlled`):

```text
[pipe] chrome pid 20568 launched with --remote-debugging-pipe (no TCP port opened)
[pipe] Browser.getVersion: "Chrome/157.0.8103.50" / protocol "1.3"
[pipe]   textbox | Email | spike@example.test
[pipe]   textbox | Password | ••••••••••••••••••••••••••••
[pipe]   StaticText | de-DE / de-DE,de / webdriver=false |
[pipe] CDP events received: {"DOM.setChildNodes": 4, "Page.domContentEventFired": 1, "Page.frameNavigated": 1,
       "Page.frameStartedLoading": 1, "Page.frameStartedNavigating": 1, "Page.frameStoppedLoading": 1,
       "Page.loadEventFired": 1, "Target.attachedToTarget": 1}
[pipe] Runtime.* events: [] (empty = Runtime domain never enabled)
```

```text
[oxide] ws url: ws://127.0.0.1:52692/devtools/browser/252747c7-…
[oxide] Runtime.executionContextCreated events seen: 2 (>0 means Runtime.enable is on)
[oxide] after Input.insertText: #pw.value == SECRET ? true
```

**Caveat.** The page also ran the old "console.debug an Error with a `stack` getter" probe for a `Runtime`-enabled client. It reported `clean` in **both** modes, so that probe is dead in Chrome 157 and proves nothing either way. The event counts above are the evidence.

Commands: `cargo build && ./target/debug/cdp pipe [--accept-lang=de-DE,de] [--disable-blink-features=AutomationControlled]` and `./target/debug/cdp oxide [--accept-lang=de-DE,de]`.

---

## 3. rmcp: a 40 s blocking tool

**Setup.** `spikes/rmcp-wait` is rmcp 3.9.0 (`server`, `transport-io`, `request-state`, `macros`) over stdio. It has one tool, `wait_approval(seconds=40, quiet=false)`, which sends `notifications/progress` every 5 s when the client supplied a `progressToken`, watches the request's cancellation token, and logs every event with a timestamp. Each client was registered only for a scratch project directory outside the repo, then removed (see "Config entries added and removed").

**Results (all headless).**

| Client | Mode | progressToken sent? | 40 s call | Longer call | Its timeout behaviour |
|---|---|---|---|---|---|
| Claude Code 2.1.318 | `claude -p … --allowedTools mcp__rmcpwait__wait_approval` | yes | `approved after 40s` | 330 s with progress: `approved after 330s`. **330 s quiet: `approved after 330s`** | no timeout seen up to 330 s, with or without progress (headless; interactive not measured) |
| Codex 0.165.0 | `codex exec` with `-c mcp_servers.rmcpwait.*` overrides | yes (protocol `2025-06-18`) | `approved after 40s` | 90 s with progress: ok. **90 s quiet (no progress): ok.** 400 s with progress: **cancelled at 300.0 s**, `timed out awaiting tools/call after 300s`. 400 s quiet: also cancelled at 300.0 s. | hard **300 s** in 0.165; progress notifications do **not** extend it (not the 60 s the research expected) |
| Cursor CLI 2026.11.05 | `cursor-agent -p --trust --mode ask --approve-mcps` | **no** | `approved after 40s` | 330 s: **cancelled at 60.0 s**, agent saw `MCP error -32001: Request timed out` | hard 60 s; sends `notifications/cancelled` |

Server log excerpts:

```text
# Cursor, seconds=330
15:35:40.090 CALL start seconds=330 progress_token=None client=Some("Cursor 1.0.0 proto=…\"2025-11-25\"")
15:36:40.099 CALL cancelled by client after 60.0s
# Codex, seconds=400 with progress every 5 s
15:35:19.308 CALL start seconds=400 quiet=false progress_token=Some(ProgressToken(Number(1)))
15:40:19.321 CALL cancelled by client after 300.0s
# Codex, seconds=90 quiet
15:35:19.627 CALL start seconds=90 quiet=true progress_token=None client=Some("codex-mcp-client 0.165.0 …")
15:36:49.625 CALL done after 90.0s -> returning result
# Claude Code, seconds=330
15:30:16.631 CALL start seconds=330 progress_token=Some(ProgressToken(Number(1)))
15:35:46.621 CALL done after 330.0s -> returning result
```

**Client quirks found (they matter for Phase 10 `connect`):**
- **Codex.** In `exec`, an MCP tool call fails with `MCP tool call requires approval, but approval policy is never` unless the server entry has `default_tools_approval_mode = "approve"` (valid values: `auto`, `prompt`, `writes`, `approve`).
- **Cursor CLI.** In `-p --mode ask` it rejects the call (`Tool rejected: User rejected MCP: rmcpwait-wait_approval`) unless the project's `.cursor/cli.json` allows it: `{"permissions":{"allow":["Mcp(rmcpwait:wait_approval)"]}}`. `--approve-mcps` only approves loading the server, not calling its tools. `--force` was never used.
- **Cursor sends no `progressToken`,** so progress cannot keep a Cursor call alive.
- **Claude Code** passed no `clientInfo` that rmcp's `peer_info()` exposed at call time. This is cosmetic.

---

## 4. Gmail refresh-token lifetime

**Status: deferred by the user (2026-11-11)** until logindesk is built end to end. No Google Cloud client was created, no token was minted and no launchd job was installed.

What is ready on `spike/phase0`, for when it resumes:
- `spikes/gmail-token`: `login <client_secret.json>` runs a loopback (`127.0.0.1:<random>`) + PKCE S256 consent for `gmail.readonly` (`access_type=offline`, `prompt=consent`). It verifies `state` and stores the refresh token in `~/Library/Application Support/logindesk-spike/gmail-token.json` (dir 0700, file 0600, outside the repo).
- `check` refreshes the token, calls `users.getProfile`, and appends one timestamped line to `check.log`, e.g. `CHECK ok refresh=ok token_age=…d` or `CHECK FAIL … server_error=invalid_grant`. It never prints a token, the client secret or the address.
- The Google Cloud steps (project → Gmail API → Google Auth Platform, External → **Publish app: In production**, unverified → `gmail.readonly` → Desktop client) are in the lead's notes. They go into `docs/` with Phase 8.
- Built and run without a token: `gmail-token check` → `no token yet; run gmail-token login <client.json> first`.

**Consequence:** the 7-day question stays open. The build plan's IMAP (app password) default stands, and Gmail REST stays the opt-in backend. The Phase 3 test bed's Gmail-REST mock covers the code path without a real token.

---

## Config entries added and removed

All client runs used two scratch project dirs outside the repo (`$TMPDIR/…/scratchpad/clientproj` and `…/cursorproj`).

| Client | Added | Removed / verified |
|---|---|---|
| Claude Code | `claude mcp add -s local rmcpwait -e SPIKE_LOG=… -- <spike bin>`, i.e. `~/.claude.json` → `projects["…/clientproj"].mcpServers.rmcpwait` | `claude mcp remove rmcpwait -s local`; `claude mcp get rmcpwait` → "No MCP server named rmcpwait"; that project's `mcpServers` = `{}` |
| Codex | nothing persisted; `-c mcp_servers.rmcpwait.{command,env,default_tools_approval_mode}` per run, `--ephemeral` | `~/.codex/config.toml` byte-identical to the pre-spike copy (`diff -q`) |
| Cursor CLI | `…/cursorproj/.cursor/mcp.json` and `…/cursorproj/.cursor/cli.json` (allow `Mcp(rmcpwait:wait_approval)`); cursor-agent itself created `~/.cursor/projects/<…-scratchpad-cursorproj>/` (mcp-approvals.json, .workspace-trusted, transcripts) | `.cursor/` deleted; the `~/.cursor/projects/…cursorproj` dir moved to Trash; `~/.cursor/mcp.json` and `cli-config.json` permissions unchanged |

The popup spike (§1) wrote no client config: the lead ran it with `claude -p --mcp-config <temp file> --strict-mcp-config`, so nothing was added to `~/.claude.json`.

---

## Decisions this implies

| Phase | Decision | Why (evidence above) |
|---|---|---|
| **4 — approver** | macOS LocalAuthentication `.deviceOwnerAuthentication` from the **unsigned** daemon is the primary approver. The `osascript` hidden-answer vault-password dialog is the fallback. | §1: the sheet works with no TTY, from an unsigned binary, and as a Claude Code stdio child; the fallback works without a TTY. |
| 4 — approver rule | Approve **only** on `success == true && error == nil` from a **fresh** `LAContext` per request, with reuse duration 0. Everything else is a deny: errors, timeout, missing or second reply. `-1004` → `needs_user`. An empty or instant fallback answer = no answer. | §1: FAIL path mapped correctly in 15/15 no-UI probes, with exactly one reply each. |
| 4 — approval text | The sheet offers **"Use Password…" next to "Cancel" from the start**. Typing the Mac password approves. The reason string must say so. Touch ID-only would need `.deviceOwnerAuthenticationWithBiometrics`. | §1: every test approval went through "Use Password…" while the user believed they were cancelling. |
| 4 / 6 — long approvals | Block for at most **40 s**, sending progress; then return `awaiting_approval` + handle and let the agent call `wait`. | §3: Cursor hard-cancels at **60 s**; Codex 0.165 at **300 s** (progress doesn't extend it); Claude Code headless survived 330 s. A real approval took 53 s in §1. |
| **5 — CDP transport** | **Our own minimal CDP client over `--remote-debugging-pipe`** (fd 3/4, NUL-delimited JSON). No TCP port, never `Runtime.enable`. Not chromiumoxide. Launch with `--disable-blink-features=AutomationControlled`. Fill with `DOM.focus` + `Input.insertText`; snapshot with `Accessibility.getFullAXTree`. | §2: chromiumoxide 0.9.1 is WebSocket-only and always enables Runtime; the ~200-line pipe client did everything needed, also under `de-DE`. |
| 5 — snapshot masking | Mask password values to a **fixed-width** placeholder; Chrome's AX tree shows one `•` per character, which leaks the length. Set the locale with `--accept-lang`; `--lang` does nothing on macOS. | §2. |
| 10 — client config | `connect codex` writes `default_tools_approval_mode = "approve"` for logindesk's server. `connect cursor` documents (or writes, with consent) the `Mcp(logindesk:*)` allow rule. | §3: without them, headless Codex and Cursor refuse the call. |
| **8 — mail** | **IMAP with an app password stays the default.** Gmail REST stays opt-in until spike 4 has its day-8 result. | §4: deferred by the user. |

