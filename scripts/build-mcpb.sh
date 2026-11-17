#!/usr/bin/env bash
# Build dist/logindesk.mcpb for Claude Desktop (macOS): a release binary + manifest, zipped.
# Usage: scripts/build-mcpb.sh            (host architecture)
#        TARGET=aarch64-apple-darwin scripts/build-mcpb.sh
set -euo pipefail

cd "$(dirname "$0")/.."
[ "$(uname -s)" = "Darwin" ] || { echo "build-mcpb: macOS only" >&2; exit 1; }

TARGET="${TARGET:-}"
if [ -n "$TARGET" ]; then
  cargo build --release -p logindesk-cli --target "$TARGET"
  BIN="target/$TARGET/release/logindesk"
else
  cargo build --release -p logindesk-cli
  BIN="target/release/logindesk"
fi

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/server" dist
cp packaging/mcpb/manifest.json "$STAGE/manifest.json"
cp "$BIN" "$STAGE/server/logindesk"
chmod 755 "$STAGE/server/logindesk"

# Keep the manifest version in step with the crate.
VERSION="$(cargo metadata --no-deps --format-version 1 \
  | sed -n 's/.*"name":"logindesk-cli","version":"\([^"]*\)".*/\1/p')"
if [ -n "$VERSION" ]; then
  sed -i '' "s/\"version\": \"[^\"]*\"/\"version\": \"$VERSION\"/" "$STAGE/manifest.json"
fi

OUT="$PWD/dist/logindesk.mcpb"
rm -f "$OUT"
if command -v mcpb >/dev/null 2>&1; then
  mcpb validate "$STAGE/manifest.json"
  mcpb pack "$STAGE" "$OUT"
else
  (cd "$STAGE" && zip -qr -X "$OUT" manifest.json server)
fi
echo "Built $OUT" >&2
