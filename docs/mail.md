# Mail: sources and the one-time-code parser

`logindesk-mail` (contract §7). The daemon polls a `MailSource` every `OTP_POLL_EVERY` and
hands the result to `extract_otp`. No model, no link following, no body in any log or error.

## Sources

| Source | Reads | Use |
|---|---|---|
| `MailpitSource { base_url }` | `GET /api/v1/messages?limit=50`, then `GET /api/v1/message/{ID}/raw` | test bed over SMTP (Docker) |
| `OutboxSource { base_url }` | `GET /_testbed/outbox`, each entry turned into a minimal RFC 5322 message | end-to-end runs without Docker |

Both: plain `http://` to a loopback host only (`127.0.0.1`, `::1`, `localhost`, `*.localhost`),
10 s per request, no redirects. They keep messages whose `From` registrable domain is the site
and whose time is at or after `since`, newest first, at most `OTP_MAX_MESSAGES`.

Errors: connection refused → `NotConnected`; 5xx, timeout or dropped connection →
`Transient`; anything else (4xx, bad JSON, non-loopback URL) → `Internal`.

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

- The `From` header is trusted as-is: no DKIM/ARC check yet. Fine for loopback test sources;
  the Gmail/IMAP sources must add DKIM alignment before real use.
- A 4-digit code that looks like a year (e.g. `2041`) is never found.
- Only the newest on-site message is read; an older code is used only after the newer
  message is marked used.
- Messages are cut at 1 MiB. Charsets other than UTF-8 and the Latin-1 family decode lossily.
- `OutboxSource` times are whole seconds, so a mail from the same second as `since` counts.
