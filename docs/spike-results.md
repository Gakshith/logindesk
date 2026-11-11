# Phase 0 spike results

Date: 2026-11-11 · Machine: macOS 26.6.2 (25G83), Apple silicon, Touch ID · Rust 1.97.1
Spike code: branch `spike/phase0`, folder `spikes/` (four standalone throwaway crates, never merged).

| # | Question | Answer |
|---|---|---|
| 1 | Does an unsigned binary get the LocalAuthentication sheet? | _PENDING: needs the user at the Mac_ |
| 2 | Can chromiumoxide drive installed Chrome over a pipe without `Runtime.enable`? | **No.** chromiumoxide 0.9.1 only does WebSocket and always sends `Runtime.enable`. A raw pipe client does all four things we need. |
| 3 | What does each client do with a 40 s tool call? | All three return the 40 s result. Cursor cancels at **60 s**, Codex 0.165 at **300 s** (progress doesn't extend it). Claude Code headless didn't time out at 330 s. |
| 4 | Does an "In production", unverified Gmail client keep its refresh token past 7 days? | _PENDING: needs the user to create the client; the day-8 result is filed later_ |

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

## 1. Approval popup (LocalAuthentication)

_PENDING_

---

## 4. Gmail refresh-token lifetime

_PENDING_

---

## Config entries added and removed

All client runs used two scratch project dirs outside the repo (`$TMPDIR/…/scratchpad/clientproj` and `…/cursorproj`).

| Client | Added | Removed / verified |
|---|---|---|
| Claude Code | `claude mcp add -s local rmcpwait -e SPIKE_LOG=… -- <spike bin>`, i.e. `~/.claude.json` → `projects["…/clientproj"].mcpServers.rmcpwait` | `claude mcp remove rmcpwait -s local`; `claude mcp get rmcpwait` → "No MCP server named rmcpwait"; that project's `mcpServers` = `{}` |
| Codex | nothing persisted; `-c mcp_servers.rmcpwait.{command,env,default_tools_approval_mode}` per run, `--ephemeral` | `~/.codex/config.toml` byte-identical to the pre-spike copy (`diff -q`) |
| Cursor CLI | `…/cursorproj/.cursor/mcp.json` and `…/cursorproj/.cursor/cli.json` (allow `Mcp(rmcpwait:wait_approval)`); cursor-agent itself created `~/.cursor/projects/<…-scratchpad-cursorproj>/` (mcp-approvals.json, .workspace-trusted, transcripts) | `.cursor/` deleted; the `~/.cursor/projects/…cursorproj` dir moved to Trash; `~/.cursor/mcp.json` and `cli-config.json` permissions unchanged |

The popup spike (§1) adds and removes its own entry; it will be listed here too.

---

## Decisions this implies

_PENDING_
