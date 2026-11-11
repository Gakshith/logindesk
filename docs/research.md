# logindesk: research report

2026-11-11 · inputs: design brief v3, plus three parallel research passes over primary docs (MCP spec, client docs, Google/Microsoft/Apple docs, vendor pages). Items marked **UNVERIFIED** were not confirmed from a primary source and must be tested before we rely on them.

## 1. The verdict in five lines

1. **The gap is real.** The closest product, 1Password for Claude (July 2026), is closed source, Mac only, and works only with 1Password, the Claude app and Claude in Chrome. No open, local, any-agent broker that owns its own browser and vault exists.
2. **One Rust binary.** The official Rust MCP SDK (`rmcp` 3.x) is now Tier 1, so the TypeScript adapter in the brief can go. `logindesk mcp` is a stdio subcommand of the same binary. Nobody who clones it needs Node.
3. **Approvals must be native.** The MCP approval mechanism the brief relies on (URL-mode elicitation) is only verified in Claude Code and VS Code. Touch ID or an OS dialog from the daemon is the main path, and elicitation is a bonus.
4. **Big sites fight automation.** Instagram, Google and X show checkpoints and CAPTCHAs, and Meta's terms forbid automated access. "Hand the visible window to the user" is a core feature, not an edge case.
5. **Gmail works per user.** Each user makes their own Google OAuth client. That client can never be shipped in the repo.

## 2. Changes to the v3 brief

| Brief v3 said | Research says | New decision |
|---|---|---|
| MCP spec 2025-11-25 | Latest is **2026-07-28**: stateless, no `initialize`, elicitation via multi-round-trip `input_required` results. Clients are split across both eras. | Support both eras through `rmcp`. |
| TypeScript MCP adapter | `rmcp` v3.9 supports both spec eras, URL elicitation and the tasks extension. | **Rust only**: one binary, no Node. |
| Form mapping step 2: MCP sampling | Sampling is **deprecated** in 2026-07-28. | Drop it. Order: deterministic rules → user's own model key (optional) → ask the user. |
| Approval via URL-mode elicitation | Verified only in Claude Code and VS Code. Claude Desktop, Cursor, Codex and Gemini are unknown or buggy. | Native approval first. Elicitation is used only when the client declares `url`. |
| libsodium | Needs a C toolchain, which hurts cloners on other platforms. | RustCrypto: `chacha20poly1305`, `argon2`, `ed25519-dalek`, `x25519-dalek`, `zeroize`, `hpke-rs`. |
| Secure Enclave device keys, Touch ID | Biometric Keychain and Secure Enclave keys need a **signed binary with entitlements**. An unsigned build from source gets error -34018. | Two levels. The signed release gets Secure Enclave and Touch ID. A source build gets a passphrase-wrapped key in the OS keyring, plus a LocalAuthentication presence prompt (**UNVERIFIED**, needs testing). |
| Playwright sidecar | Works, but brings Node back. Rust CDP crates exist (`chromiumoxide` and forks), but their maintenance is uncertain. | Spike both in Phase 1. Lean towards Rust CDP, because the needed verbs are small: navigate, accessibility snapshot, click, `Input.insertText`. |
| Bundled Chromium | Real installed Chrome, headed, with a persistent profile, triggers fewer "browser not secure" blocks (anecdotal). | Use the user's installed Chrome with a dedicated logindesk profile. |
| Gmail "personal use exemption" | Google's docs show **no** such exemption. Unverified apps are capped at 100 users per project for life. "In production + unverified" seems to avoid 7-day token expiry (**UNVERIFIED**). | Per-user client plus a wizard. Test the token lifetime on a real account first. IMAP with an app password is the fallback. |

## 3. Architecture after research

```text
Agent (Claude Code, Cursor, …)
   │  stdio MCP: intent tools only, never a secret
   ▼
logindesk mcp          ← same binary, thin front
   │  Unix socket 0600 + peer-UID check
   ▼
logindesk daemon       ← vault, policy, approvals, audit, OTP parser
   ├── Chrome (headed, own profile) via CDP: fills secrets itself
   ├── Gmail API / IMAP: one narrow query, codes parsed by plain code
   └── Touch ID / OS dialog: every login and signup
```

**Tools stay as designed:** `accounts_find`, `login`, `signup`, `session_snapshot`, `session_act`, `capture_secret`, `session_close`. Two changes:

- **Slow approvals.** Claude Code's per-server timeout is a hard wall, and Codex gives a tool call 60 s. So `login` returns `awaiting_approval` plus a handle at once, and the agent polls it, unless the client supports the tasks extension.
- **Secret fill.** Values are typed with CDP `Input.insertText`, and only when the tab's eTLD+1 (from the `psl` crate) matches the vault entry. Values never go through `Runtime.evaluate`, never into logs, and never into a caller-visible snapshot.

## 4. "Anyone who clones it can use it": portability rules

These are the breakages real MCP servers hit, and the rule each one becomes:

| Breakage | Rule |
|---|---|
| Anything non-protocol on stdout corrupts stdio MCP | Logs go only to stderr or a file. A CI test spawns the server and checks that stdout is pure JSON-RPC. |
| macOS GUI apps (Claude Desktop, Cursor) don't inherit shell PATH, giving `spawn ENOENT` | `logindesk install --client <name>` writes the **absolute path** to the binary into that client's config. |
| Windows `npx` is `npx.cmd`, so quoting breaks | Ship a native binary, not an `npx` command. The npm wrapper is optional. |
| Codex allows 10 s for startup and 60 s per tool call by default | No downloads at spawn. Chrome is detected at install time, and the `doctor` command checks it. |
| Gemini CLI strips env vars matching `*TOKEN*`, `*SECRET*`, `*KEY*`, `*PASSWORD*` | The server needs no secret env vars. The socket path comes from the OS data dir. |
| Claude Code plugin root changes on every update | Persistent state goes in `${CLAUDE_PLUGIN_DATA}` or the OS data dir, never in the plugin folder. |
| Each client uses a different config format | One installer covers them all, plus `logindesk doctor` to verify each config. |

**Client config locations:**
- Claude Code: `claude mcp add logindesk -- /abs/path/logindesk mcp`, or the plugin.
- Claude Desktop: a `.mcpb` bundle (`server.type: binary`, `platform_overrides`).
- Cursor: `~/.cursor/mcp.json` (`mcpServers`).
- VS Code: `.vscode/mcp.json` (`servers`; **UNVERIFIED** schema).
- Codex: `~/.codex/config.toml` `[mcp_servers.logindesk]`.
- Gemini CLI: `~/.gemini/settings.json`. Gemini CLI was replaced by Antigravity CLI for free users in June 2026 (**UNVERIFIED** config path).

**Distribution:**
- GitHub Release binaries, signed and notarized.
- Homebrew tap and `cargo install logindesk`.
- An npm wrapper using per-platform `optionalDependencies` (the esbuild pattern).
- A Claude Code plugin with a marketplace.
- One `.mcpb` per OS for Claude Desktop.

## 5. Client support matrix (from primary docs where possible)

| Client | Spec era | Form elicitation | URL elicitation | Tasks |
|---|---|---|---|---|
| Claude Code | 2026-07-28 | yes | **yes** (interactive only) | yes (beta) |
| VS Code | 2025-11-25 (v1.107) | yes | yes (one source disputes) | yes |
| Cursor | unknown | yes, hang reports in 3.x | unknown | unknown |
| Claude Desktop | unknown | reported broken (hangs ~60 s) | likely no | unknown |
| Codex CLI | unknown | auto-declined (issue #60158) | unknown | unknown |
| Gemini / Antigravity | unknown | unknown | unknown | unknown |

The Phase 2 test bed must fill every "unknown" cell with a real smoke test, before the README claims "works everywhere".

## 6. Email and OTP

- **Gmail, default.**
  - The user creates a Google Cloud project, enables the Gmail API and sets the consent screen to External.
  - The scope is `gmail.readonly`, the narrowest scope that can read a message body. It is a "restricted" scope.
  - The user creates a Desktop OAuth client, publishes it "In production", and accepts the unverified-app warning once.
  - The refresh token goes into the vault.
  - **"Testing" status kills refresh tokens after 7 days.**
  - A shared client in the repo is impossible: it would hit the 100-user lifetime cap, and verification needs a yearly paid security assessment (CASA).
- **Gmail, quick fallback.** IMAP with an app password. It needs 2-Step Verification, and the password is revoked whenever the Google password changes. It has full mailbox access, so it is labelled "less safe".
- **Outlook.** An Entra app with device-code flow and `IMAP.AccessAsUser.All` plus `offline_access`.
- **iCloud.** An app-specific password over IMAP.
- **Polling, not push.** Push needs Pub/Sub and is unreliable for desktop apps. While a login is pending, poll `newer_than:2m` from the site's domain every 2–5 s.
- **Trust rule for a code or link:**
  - Read Gmail's top `Authentication-Results` header, or use the `mail-auth` crate when that header is absent.
  - Require `dkim=pass`, aligned to the site's eTLD+1.
  - The mail must arrive after the attempt started, and each code is used once.
  - Links must be https, on the site's own domain, and shown to the user.
- **Signup address.** The default is `you+site@gmail.com`. Some sites reject `+`, so fall back to the plain address. Optionally use an alias via the addy.io or SimpleLogin API (their docs need confirming).

## 7. Passwords for new accounts

- **Generation.** The OS random generator, constrained by the site's rules. Sources, in order:
  1. Apple's `password-manager-resources` quirks file (`password-rules.json`, per domain).
  2. The page's `passwordrules` attribute, parsed with 1Password's `password-rules-parser` crate.
  3. A 20-character default.
- **Save before submit.** The password is saved to the vault as `pending` **before** submit, so a crash never loses it.

## 8. Prior art: what each one leaves open

| Project | How it hides the secret | What's left for us |
|---|---|---|
| 1Password for Claude | Injects at runtime; Touch ID | Closed source, one vendor, one agent, Mac only |
| 1Password + Browserbase | Injects into a cloud browser | Cloud and enterprise only |
| Bitwarden Agent Access SDK | Encrypted tunnel; `aac run` puts secrets in env vars | `aac connect` prints the secret to the agent. Early preview. Possible interop later. |
| Browser Use `sensitive_data` | Placeholder swap | The secret lives in the agent's process and can leak via screenshots. Had a CVE in versions 0.7.8–0.11.0. |
| Skyvern | Placeholder IDs | A whole cloud agent platform, not a connector |
| op-mcp, Bitwarden MCP | Wrap a vault CLI | The agent can see values; no browser |

## 9. Legal and terms (not legal advice)

- **US law.** *Van Buren* (2021) narrowed the CFAA (the US anti-hacking law), so breaking a site's terms alone is not hacking. Contract and terms claims still apply. Logging in to **your own** account with your own password is the safest case. Mass signup is the risky one.
- **Meta / Instagram.** The terms forbid accessing or collecting "using automated means" without permission, and allow one account per person. **The real risk is that Meta restricts or bans the user's own Instagram account,** not legal action.
- **X.** Bans browser automation outside its API. Treat X as hostile.
- **GitHub.** Hosting the tool is fine. Promoting bulk or fake accounts is not.
- **Safe defaults that ship on:**
  - A human approval for every login and signup.
  - No CAPTCHA solving.
  - Per-site and per-day rate limits.
  - One account per site per identity.
  - Local audit.
  - A README notice that the user is responsible for each site's terms.

## 10. Questions for you

1. **Instagram and other Meta sites.** Meta forbids automated access, and your own account could get flagged. Options:
   - (a) Allow them with a one-time warning (recommended for your own use).
   - (b) Block them by default and let users opt in.
   - (c) Block them entirely.
2. **First demo site.** Should it be a low-risk site such as GitHub, or does it have to be Instagram?
3. **Apple Developer account ($99/yr).** It is needed for signed builds with real Touch ID and Secure Enclave and for notarization. Without it, source builds use passphrase plus keyring.
4. **Licence.** Apache-2.0 (recommended) or AGPL-3.0.
5. **Platforms for 0.1.** macOS only (recommended), or macOS plus Linux from the start?

## 11. Things to test before Phase 1 locks the design

- [ ] Does a Google OAuth client set to "In production", unverified, keep a refresh token past 7 days?
- [ ] Does an unsigned or ad-hoc-signed Rust binary get a Touch ID prompt from `LAContext.evaluatePolicy`?
- [ ] Rust CDP versus a Playwright or patchright sidecar: compare fill, accessibility snapshot and stealth on a throwaway site.
- [ ] Smoke-test each client (spawn, tool call, URL elicitation, a 3-minute approval wait) for Claude Desktop, Cursor, Codex and Antigravity/Gemini.
- [ ] Does Claude Desktop accept an unsigned native binary inside a `.mcpb`?
- [ ] Read Instagram's Terms of Use and Google's Terms directly; this pass only saw summaries.

## Sources

**MCP:**
- [Spec changelog 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/changelog)
- [Elicitation 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/client/elicitation)
- [Elicitation 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/client/elicitation)
- [Tasks](https://modelcontextprotocol.io/specification/2025-11-25/basic/utilities/tasks)
- [stdio transport](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/stdio)
- [Streamable HTTP](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http)
- [Security best practices](https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices)
- [SDK tiers](https://modelcontextprotocol.io/docs/sdk)
- [rmcp](https://github.com/modelcontextprotocol/rust-sdk)
- [TypeScript SDK](https://github.com/modelcontextprotocol/typescript-sdk)
- [canimcp URL elicitation](https://canimcp.dev/feature/elicitation.url/)

**Clients:**
- [Claude Code MCP](https://code.claude.com/docs/en/mcp)
- [Plugins reference](https://code.claude.com/docs/en/plugins-reference)
- [Marketplaces](https://code.claude.com/docs/en/plugin-marketplaces)
- [MCPB](https://claude.com/docs/connectors/building/mcpb)
- [MCPB manifest](https://github.com/modelcontextprotocol/mcpb/blob/main/MANIFEST.md)
- [VS Code 1.107](https://code.visualstudio.com/updates/v1_107)
- [Cursor MCP](https://cursor.com/docs/context/mcp)
- [Codex MCP](https://learn.chatgpt.com/docs/extend/mcp?surface=cli)
- [Codex #60158](https://github.com/openai/codex/issues/60158)
- [Gemini CLI MCP](https://geminicli.com/docs/tools/mcp-server/)
- [esbuild install pattern](https://esbuild.github.io/getting-started/#install-esbuild)

**Vault and browser:**
- [1Password for Claude](https://1password.com/blog/1password-for-claude)
- [Browserbase agentic autofill](https://browserbase.com/blog/1password-agentic-autofill)
- [Bitwarden agent-access](https://github.com/bitwarden/agent-access)
- [Browser Use sensitive data](https://docs.browser-use.com/customize/sensitive-data)
- [Skyvern credentials](https://skyvern.com/docs/developers/credentials/store-credentials)
- [Apple forum: keychain entitlements](https://developer.apple.com/forums/thread/696431)
- [keyring](https://docs.rs/keyring/latest/keyring/)
- [hpke-rs](https://docs.rs/hpke-rs)
- [patchright](https://github.com/Kaliiiiiiiiii-Vinyzu/patchright)
- [chromiumoxide](https://docs.rs/chromiumoxide)
- [psl](https://github.com/addr-rs/psl)
- [Apple password rules](https://developer.apple.com/password-rules)
- [password-manager-resources](https://github.com/apple/password-manager-resources)

**Email:**
- [Gmail scopes](https://developers.google.com/workspace/gmail/api/auth/scopes)
- [Unverified apps](https://support.google.com/cloud/answer/13463817)
- [OAuth token expiry](https://developers.google.com/identity/protocols/oauth2#expiration)
- [Less-secure-apps shutdown](https://knowledge.workspace.google.com/admin/sync/transition-from-less-secure-apps-to-oauth)
- [App passwords](https://support.google.com/mail/answer/185833)
- [Gmail push](https://developers.google.com/workspace/gmail/api/guides/push)
- [Microsoft IMAP OAuth](https://learn.microsoft.com/en-us/exchange/client-developer/legacy-protocols/how-to-authenticate-an-imap-pop-smtp-application-by-using-oauth)
- [Apple app-specific passwords](https://support.apple.com/en-us/102654)
- [mail-auth](https://github.com/stalwartlabs/mail-auth)

**Terms:**
- [Meta terms](https://www.facebook.com/terms)
- [X automation rules](https://help.x.com/en/rules-and-policies/x-automation)
- [GitHub acceptable use](https://docs.github.com/en/site-policy/acceptable-use-policies/github-acceptable-use-policies)
