# logindesk

logindesk lets an AI agent log you in to websites, or sign you up, without the agent ever seeing your password or one-time code.

```text
You:     "Claude, log in to my GitHub and check the last deploy."
Claude → logindesk: login("github.com")
logindesk: finds the account in its encrypted vault, opens its own browser,
           fills the password itself, reads the emailed code itself
logindesk → Claude: { "status": "logged_in", "session_id": "…" }
```

**Status: working prototype (macOS).** Login, signup with email verification, Gmail/IMAP code reading, approvals and the MCP tools run end to end on the included fake site. Real sites vary: some login forms are not mapped yet. Not audited; do not rely on it for important accounts yet.

## Install from source

Needs Rust (see `rust-toolchain.toml`) and Google Chrome.

```bash
cargo build --release -p logindesk-cli
cp target/release/logindesk ~/.local/bin/
logindesk setup                                   # create the encrypted vault
logindesk install --client claude-code            # or claude-desktop, cursor, vscode, codex, gemini
logindesk daemon                                  # unlock once; leave it running
```

Or, in Claude Code, install the plugin (it still needs the binary and a running daemon):

```text
/plugin install logindesk --marketplace Gakshith/logindesk
```

## Try it on the fake site

```bash
scripts/try-it.sh
```

Starts a throwaway vault, a fake website and the daemon, and prints what to run and what to ask Claude. Nothing touches your real vault, sites or mailbox.

## Use it

```bash
logindesk vault import --csv passwords.csv --delete-csv   # Chrome, Firefox, Safari, Bitwarden, 1Password exports
logindesk vault dedupe                                    # merge duplicate logins (keeps the newest)
logindesk grant add github.com --tier auto                # this site: no prompt
logindesk grant add example.com --tier auto --action signup
logindesk identity set --email you@gmail.com --name "Your Name"
logindesk connect gmail                                   # read emailed codes (or: connect imap)
logindesk doctor                                          # check everything
```

Sites without a grant ask for Touch ID (or your Mac password) each time, and the prompt names the agent.

## Security model

- Secrets live only in the daemon (an encrypted vault, unlocked once like ssh-agent) and are typed into its own sealed browser. They never cross the MCP socket, so no tool result, log or audit line holds one.
- Every login or signup passes a per-site grant (`auto`, `ask`, `deny`). Pages and links are fenced to the site's registrable domain, and the browser never fills a form on another site.
- An append-only, hash-chained audit log records which agent did what, where.

Details: [`docs/socket.md`](docs/socket.md) (protocol and flows), [`docs/mail.md`](docs/mail.md), [`SECURITY.md`](SECURITY.md), [`RESPONSIBLE_USE.md`](RESPONSIBLE_USE.md).

## Licence

Apache-2.0. See [LICENSE](LICENSE).
