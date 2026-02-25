#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLUGIN_MANIFEST="$SCRIPT_DIR/http_title/Cargo.toml"

echo "[+] Building http_title (wasm32-unknown-unknown)..."
cargo build --release --target wasm32-unknown-unknown --manifest-path "$PLUGIN_MANIFEST"

BUILT="$SCRIPT_DIR/http_title/target/wasm32-unknown-unknown/release/http_title.wasm"
OUT="$SCRIPT_DIR/http_title.wasm"

cp -f "$BUILT" "$OUT"
echo "[+] Plugin ready: $OUT"
