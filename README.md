# logindesk

**Status: design and research. Nothing is built yet.**

logindesk lets an AI agent log you in to websites, or sign you up, without the agent ever seeing your password.

```text
You:     "Claude, log in to my GitHub and check the last deploy."
Claude → logindesk: login("github.com")
logindesk: finds your account in its encrypted vault, opens its own browser,
           fills the password itself, reads the email code itself,
           asks you for one Touch ID tap
logindesk → Claude: { status: "logged_in", sessionId: "…" }
```

Claude gets the result and a logged-in page it can use. It never gets the password, the cookies or the one-time code.

## Why

- Agents stop at login walls. The common fix is pasting a password into chat, where any prompt-injected page can steal it.
- Every agent framework handles credentials in its own unsafe way.
- Signing up is repetitive: an email address, a password, a verification code, every time.

## How it works (planned)

- **A local broker.** One program on your machine holds the encrypted vault and drives a visible browser. It is the only part that ever sees a secret.
- **Plugs into any agent over MCP**: Claude Code, Claude Desktop, Cursor, VS Code and others. The agent gets intent tools (`login`, `signup`, `accounts_find`, …), never secrets.
- **You approve every login and signup** on your own device, and the prompt names which agent is asking.
- **Signups** use your email (`you+site@gmail.com`) and a generated password that goes straight into the vault.
- **Email codes** are read by plain code, not by a model, from your own Gmail connection.

## Documents

- [`docs/research.md`](docs/research.md): research report on the implementation, prior art, MCP client support, email access and risks.

## Run it

Not runnable yet.

## Licence

Apache-2.0. See [LICENSE](LICENSE).
