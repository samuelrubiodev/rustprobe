#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_TRIPLE="${RUSTPROBE_WASM_TARGET:-wasm32-unknown-unknown}"
RUNTIME_SCRIPTS_DIR="${RUSTPROBE_SCRIPTS_DIR:-}"

if [[ -z "$RUNTIME_SCRIPTS_DIR" ]]; then
  if [[ -n "${APPDATA:-}" ]]; then
    RUNTIME_SCRIPTS_DIR="$APPDATA/rustprobe/scripts"
  elif [[ "$(uname -s)" == "Darwin" ]]; then
    RUNTIME_SCRIPTS_DIR="$HOME/Library/Application Support/rustprobe/scripts"
  else
    RUNTIME_SCRIPTS_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/rustprobe/scripts"
  fi
fi

mkdir -p "$RUNTIME_SCRIPTS_DIR"

shopt -s nullglob
manifests=("$SCRIPT_DIR"/*/Cargo.toml)

if (( ${#manifests[@]} == 0 )); then
  echo "[!] No plugin manifests found under scripts/."
  exit 0
fi

build_one() {
  local manifest="$1"
  local plugin_dir
  local plugin_name
  local release_dir
  local built_wasm
  local output_wasm
  local fallback_candidates

  plugin_dir="$(dirname "$manifest")"
  plugin_name="$(basename "$plugin_dir")"

  echo "[+] Building $plugin_name ($TARGET_TRIPLE)..."
  cargo build --release --target "$TARGET_TRIPLE" --manifest-path "$manifest"

  release_dir="$plugin_dir/target/$TARGET_TRIPLE/release"
  built_wasm="$release_dir/$plugin_name.wasm"

  if [[ ! -f "$built_wasm" ]]; then
    fallback_candidates=("$release_dir"/*.wasm)
    if (( ${#fallback_candidates[@]} == 0 )); then
      echo "[!] Could not locate built .wasm for plugin: $plugin_name" >&2
      return 1
    fi
    built_wasm="${fallback_candidates[0]}"
  fi

  output_wasm="$SCRIPT_DIR/$plugin_name.wasm"
  cp -f "$built_wasm" "$output_wasm"
  echo "[+] Plugin ready: $output_wasm"

  runtime_wasm="$RUNTIME_SCRIPTS_DIR/$plugin_name.wasm"
  cp -f "$built_wasm" "$runtime_wasm"
  echo "[+] Plugin deployed: $runtime_wasm"
}

pids=()

for manifest in "${manifests[@]}"; do
  build_one "$manifest" &
  pids+=("$!")
done

failed=0
for pid in "${pids[@]}"; do
  if ! wait "$pid"; then
    failed=1
  fi
done

if (( failed != 0 )); then
  echo "[!] One or more plugin builds failed." >&2
  exit 1
fi

echo "[+] Completed. Built ${#manifests[@]} plugin(s)."
