# logindesk

## Build / test
No code yet. Commands get added here when the first crate lands.

## Architecture (planned)
- Rust broker daemon: vault, policy, approvals, audit, OTP parser. Everything that touches a secret lives here.
- MCP server: exposes intent tools only. No tool may ever return a secret value.
- Browser executor: fills secrets into the page itself; callers get masked snapshots.

## Conventions
- **Secrets never cross the agent boundary.** Not in tool results, logs, errors, or test fixtures that look real.
- **Portable by default:** no absolute paths, no machine-specific config in the repo. Per-user state lives in the OS config/data dir. A fresh clone on another machine must install and run.
- **stdout belongs to MCP** in stdio mode. All logging goes to stderr or a file.
- Design and research live in `docs/`.
