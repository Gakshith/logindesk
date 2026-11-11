# Security policy

logindesk holds passwords and reads one-time codes, so security reports are the most important issues we get.

## Status

logindesk is **pre-alpha and has not been audited**. There is no supported release yet. Do not store credentials you can't afford to lose in it.

| Version | Supported |
|---|---|
| unreleased (`dev`, `main`) | best effort |

## Reporting a vulnerability

Report privately through GitHub: **Security → Report a vulnerability** on this repository (private vulnerability reporting). Please don't open a public issue, pull request or discussion for a vulnerability.

Include what you can:
- what an attacker can do, and which attacker in [`docs/threat-model.md`](docs/threat-model.md) they are;
- steps or a proof of concept;
- the commit or version you tested.

Never include a real password, token or one-time code in a report. Use obvious canaries such as `CANARY-1234`.

What to expect:
- acknowledgement within 7 days;
- a fix or a decision within 90 days, sooner for anything that leaks a secret to the calling agent;
- credit in the advisory, unless you ask not to be named.

## In scope

Anything that breaks a guarantee in the threat model, especially:
- a secret (password, OTP, token, vault key) reaching an MCP result, log line, error, audit entry or snapshot;
- a secret filled into a field on a different site than the one approved;
- a login, signup, form submit or secret capture that happens without a fresh approval;
- a way for a local process to use the daemon without pairing.

## Out of scope

The non-goals listed in the threat model: malware already running as your user, malicious forks or unofficial builds, and sites' own bot detection.
