# Mail: sources and the one-time-code parser

`logindesk-mail` (contract §7). The daemon polls a `MailSource` every `OTP_POLL_EVERY` and
hands the result to `extract_otp`. No model, no link following, no body in any log or error.

## Sources

| Source | Reads | Use |
|---|---|---|
| `MailpitSource { base_url }` | `GET /api/v1/messages?limit=50`, then `GET /api/v1/message/{ID}/raw` | test bed over SMTP (Docker) |
| `OutboxSource { base_url }` | `GET /_testbed/outbox`, each entry turned into a minimal RFC 5322 message | end-to-end runs without Docker |
| `GmailRestSource` | `users/me/messages?q=from:<site> newer_than:15m&maxResults=5`, then `messages/{id}?format=raw` | real Gmail (`logindesk connect gmail`) |
| `ImapSource` | TLS, `LOGIN`, `EXAMINE INBOX`, `UID SEARCH SINCE <day> FROM "<site>"`, `UID FETCH <newest 5> (UID INTERNALDATE BODY.PEEK[])` | any IMAP box (`logindesk connect imap`) |

Mailpit and outbox: plain `http://` to a loopback host only (`127.0.0.1`, `::1`, `localhost`, `*.localhost`),
10 s per request, no redirects. They keep messages whose `From` registrable domain is the site
and whose time is at or after `since`, newest first, at most `OTP_MAX_MESSAGES`.

Errors: connection refused → `NotConnected`; 5xx, timeout or dropped connection →
`Transient`; anything else (4xx, bad JSON, non-loopback URL) → `Internal`.

## Real mailboxes

- **Gmail.** `logindesk connect gmail` prints the Google Cloud steps (project → Gmail API →
  consent screen External/Testing with yourself as test user → Desktop OAuth client), asks for
  the client ID and secret, and runs loopback consent with PKCE S256 on `127.0.0.1:<random>`.
  Scope: `gmail.readonly` only. The refresh token and client secret are stored in the vault as
  two `mail` records (site `gmail.oauth`, notes `refresh_token` / `client_secret`).
  Access tokens are minted on demand and cached until a minute before expiry.
- **IMAP.** `logindesk connect imap --preset gmail|icloud|outlook --user <you>` (or `--host`);
  the app password is prompted for and stored as one `mail` record (site `imap.login`).
- `mail.json` holds only `{kind: "gmail"}` or `{kind: "imap", url: "imaps://user@host:993"}`.
- The daemon reads the vault records once at start: restart it after `connect` / `disconnect`.
- `connect` tests the mailbox with one search; if the mailbox refuses, nothing is kept.
  `connect status [--check]` shows (and tests) it; `disconnect` deletes the records and `mail.json`.
- Errors: `invalid_grant` / `invalid_client`, a 401 after a fresh token, or an IMAP `LOGIN`
  refusal → `NotConnected` (`email_not_connected`). 5xx, network, TLS or timeout → `Transient`.
- **Sender check.** Real mail is kept only if the topmost `Authentication-Results` header says
  `dkim=pass` with a signing domain on the site, or `dmarc=pass` with `header.from` on the site.
  Gmail (REST and `imap.gmail.com`) must also show authserv-id `mx.google.com`, so a header the
  sender wrote is never trusted. Other IMAP hosts trust their topmost header as-is.

## Parser rules (`extract_otp`)

1. Skip a message whose id is in `used` or that arrived before `since`.
2. Keep it only if it has exactly one `From` header with exactly one address, and
   `registrable_domain(address domain) == site`. Quoted display names are ignored, so
   `"no-reply@site.com" <x@evil.test>` is rejected.
3. Read only the newest kept message (`received`, then `Date`).
4. Text = decoded `Subject` (RFC 2047) + the text/plain part, or the text/html part with tags
   stripped. Handles quoted-printable, base64, nested multipart; skips attachments.
5. Candidates: 4–8 digits, or 6–8 uppercase ASCII letters and digits with at least one digit,
   within 120 chars after or 60 chars before a keyword (code, verification, one-time, OTP,
   passcode, sign-in, login, plus a few non-English ones such as código, コード).
   Ignored: anything inside a URL, years (19xx/20xx), phone- and date-like groups
   (`555-123-4567`, `2026-11-16`), amounts and decimals.
6. One distinct candidate → `Code`. Several → `Ambiguous`.
7. No code: an https link on the site whose path has verify/confirm/magic/login/token → `Link`
   (two different such links → `Ambiguous`). Plain http is accepted only for `*.localhost`.
8. Otherwise `NotFound`. The message id is marked used only on `Code` or `Link`.

## Limits

- Mailpit and outbox trust `From` as-is (loopback test sources). Gmail and IMAP rely on the
  receiving server's `Authentication-Results`, not on verifying DKIM signatures themselves; an
  IMAP host that adds no such header yields no codes (a false negative, never a wrong code).
- A 4-digit code that looks like a year (e.g. `2041`) is never found.
- Only the newest on-site message is read; an older code is used only after the newer
  message is marked used.
- Messages are cut at 1 MiB. Charsets other than UTF-8 and the Latin-1 family decode lossily.
- `OutboxSource` times are whole seconds, so a mail from the same second as `since` counts.
