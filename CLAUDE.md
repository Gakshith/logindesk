# logindesk

## Build / test
Homebrew's rustup is keg-only on some Macs: `export PATH="/opt/homebrew/opt/rustup/bin:$PATH"` if `cargo` is missing.

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check && cargo audit
```

## Layout
- `crates/*`: core, vault, policy, approver, executor, mail, daemon, mcp, cli (binary `logindesk`).
- `testbed/`: fake site, hostile MCP client, canary leak harness. Test-only; never a dependency of `crates/*`.
- Dependencies are pinned exactly (`=x.y.z`) in `[workspace.dependencies]`.

## Architecture
- `logindesk daemon`: unlocks the vault once and holds the keys; vault, grants, approvals (Touch ID), audit, mail/OTP. Everything that touches a secret lives here. Serves a Unix socket (`docs/socket.md`).
- `logindesk mcp`: thin stdio MCP server, a socket client with no secrets. Twelve tools; none returns a secret value.
- Executor: drives its own Chrome over `--remote-debugging-pipe` (no TCP port, never `Runtime.enable`), fills secrets itself, returns masked snapshots with field kinds.
- Two ways to fill a form: `login` / `signup` map it automatically; `open` + `type` + `fill_secret` let the agent drive odd pages while the broker fills only the secrets (`docs/contract.md` §12).
- Try it end to end with no real accounts: `scripts/try-it.sh`.

## Conventions
- **Secrets never cross the agent boundary.** Not in tool results, logs, errors, or test fixtures that look real.
- **Portable by default:** no absolute paths, no machine-specific config in the repo. Per-user state lives in the OS config/data dir. A fresh clone on another machine must install and run.
- **stdout belongs to MCP** in stdio mode. All logging goes to stderr or a file.
- Design and research live in `docs/`.
