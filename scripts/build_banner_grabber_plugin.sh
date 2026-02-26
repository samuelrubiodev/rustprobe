#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLUGIN_MANIFEST="$SCRIPT_DIR/banner_grabber/Cargo.toml"

echo "[+] Building banner_grabber (wasm32-unknown-unknown)..."
cargo build --release --target wasm32-unknown-unknown --manifest-path "$PLUGIN_MANIFEST"

BUILT="$SCRIPT_DIR/banner_grabber/target/wasm32-unknown-unknown/release/banner_grabber.wasm"
OUT="$SCRIPT_DIR/banner_grabber.wasm"

cp -f "$BUILT" "$OUT"
echo "[+] Plugin ready: $OUT"
