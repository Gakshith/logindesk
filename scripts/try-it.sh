#!/usr/bin/env bash
# Try logindesk end to end on the fake site, with a throwaway vault.
# Nothing here touches a real vault, real site or real mailbox.
#
#   scripts/try-it.sh            build, start the fake site + daemon, print what to try
#   Ctrl-C                       stops everything
#
# Env: LOGINDESK_TRY_DIR (default ~/.logindesk-try), TESTBED_PORT (default 47811).
set -euo pipefail
cd "$(dirname "$0")/.."

command -v cargo >/dev/null || export PATH="/opt/homebrew/opt/rustup/bin:$PATH"
echo "building..." >&2
cargo build -q -p logindesk-cli -p testbed
B="${CARGO_TARGET_DIR:-$PWD/target}/debug"

DIR="${LOGINDESK_TRY_DIR:-$HOME/.logindesk-try}"
PORT="${TESTBED_PORT:-47811}"
rm -rf "$DIR"
mkdir -p "$DIR"
chmod 700 "$DIR"
export LOGINDESK_VAULT="$DIR/vault.sqlite"

TB="" DM=""
cleanup() { [ -n "$DM" ] && kill "$DM" 2>/dev/null; [ -n "$TB" ] && kill "$TB" 2>/dev/null; true; }
trap cleanup EXIT INT TERM

# 1. Fake site (mail is kept in its outbox; no Docker needed).
TESTBED_PORT="$PORT" "$B/testbed" --no-mailpit 2>"$DIR/testbed.log" &
TB=$!
for _ in $(seq 50); do grep -q "password pw-" "$DIR/testbed.log" 2>/dev/null && break; sleep 0.1; done
SITE_PW=$(sed -n 's/.*password \(pw-[A-Za-z0-9]*\).*/\1/p' "$DIR/testbed.log")
[ -n "$SITE_PW" ] || { echo "the fake site did not start; see $DIR/testbed.log" >&2; exit 1; }

# 2. Throwaway vault with the fake site's two accounts. Fast KDF: test vault only.
VAULT_PW="try-$(openssl rand -hex 12)"
printf '%s\n%s\n' "$VAULT_PW" "$VAULT_PW" |
  "$B/logindesk" --password-stdin setup --kdf-memory-kib 19456 --kdf-iterations 2 >/dev/null 2>&1
for u in alice otp; do
  printf '%s\n%s\n' "$VAULT_PW" "$SITE_PW" |
    "$B/logindesk" --password-stdin vault add --site "http://example.localhost:$PORT/login" \
      --username "$u@example.localhost" >/dev/null 2>&1
done
unset SITE_PW

# 3. Let agents log in to the fake site with no prompt, and read codes from its outbox.
"$B/logindesk" grant add example.localhost --tier auto >/dev/null 2>&1
"$B/logindesk" grant add example.localhost --tier auto --action signup >/dev/null 2>&1
"$B/logindesk" identity set --email "me@example.localhost" --name "Test User" >/dev/null 2>&1
"$B/logindesk" mail set outbox "http://example.localhost:$PORT" >/dev/null 2>&1

# 4. Daemon: unlocked once, then serves agents. ${LOGINDESK_HEADFUL:-0}=1 shows the browser.
( printf '%s\n' "$VAULT_PW"; exec tail -f /dev/null ) |
  "$B/logindesk" --password-stdin daemon 2>"$DIR/daemon.log" &
DM=$!
unset VAULT_PW
sleep 1

cat <<EOF

logindesk is running (fake site http://example.localhost:$PORT, data in $DIR).

In ANOTHER terminal:

  export LOGINDESK_VAULT="$LOGINDESK_VAULT"
  $B/logindesk login example.localhost --account alice@example.localhost
  $B/logindesk login example.localhost --account otp@example.localhost   # emailed code, read automatically
  $B/logindesk signup example.localhost --url http://example.localhost:$PORT/signup   # new account, verified by email
  $B/logindesk doctor

Let Claude Code log in by itself:

  claude mcp add logindesk -e LOGINDESK_VAULT="$LOGINDESK_VAULT" -- $B/logindesk mcp

  then ask:  "Use logindesk to log in to example.localhost as alice and tell me what the account page says."
        or:  "Use logindesk to sign up for example.localhost (signup page http://example.localhost:$PORT/signup)."

See it in a visible browser: stop this (Ctrl-C) and rerun with LOGINDESK_HEADFUL=1.
Audit log: $DIR/audit.jsonl     Ctrl-C here stops the site and the daemon.
EOF
wait "$DM"
