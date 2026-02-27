#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_TRIPLE="${RUSTPROBE_WASM_TARGET:-wasm32-unknown-unknown}"
RUNTIME_SCRIPTS_DIR="${RUSTPROBE_SCRIPTS_DIR:-}"

# ── Resolve deploy targets ───────────────────────────────────────────────────
#
# rustprobe uses the `directories` crate (XDG data dir) to locate scripts.
# When invoked with `sudo`, that resolves to /root/.local/share/rustprobe/scripts.
# When invoked without `sudo`, it resolves to $HOME/.local/share/rustprobe/scripts.
# We need to deploy to BOTH so that scripts work regardless of how the binary
# is launched (SYN mode always requires sudo; other modes usually don't).

_xdg_data() {
  local home_dir="$1"
  echo "${XDG_DATA_HOME:-$home_dir/.local/share}/rustprobe/scripts"
}

_data_dir_for_home() {
  local home_dir="$1"
  if [[ -n "${APPDATA:-}" ]]; then
    echo "$APPDATA/rustprobe/scripts"
  elif [[ "$(uname -s)" == "Darwin" ]]; then
    echo "$home_dir/Library/Application Support/rustprobe/scripts"
  else
    echo "$(_xdg_data "$home_dir")"
  fi
}

declare -a DEPLOY_DIRS=()

if [[ -z "$RUNTIME_SCRIPTS_DIR" ]]; then
  # Primary: current effective user
  DEPLOY_DIRS+=("$(_data_dir_for_home "$HOME")")

  # Secondary: if running as non-root, also deploy to root (for sudo usage)
  if [[ $EUID -ne 0 ]]; then
    ROOT_HOME="$(getent passwd root | cut -d: -f6 2>/dev/null || echo /root)"
    DEPLOY_DIRS+=("$(_data_dir_for_home "$ROOT_HOME")")
  fi

  # Secondary: if running as root via sudo, also deploy to the invoking user
  if [[ $EUID -eq 0 && -n "${SUDO_USER:-}" ]]; then
    USER_HOME="$(getent passwd "$SUDO_USER" | cut -d: -f6 2>/dev/null || echo /home/"$SUDO_USER")"
    USER_DIR="$(_data_dir_for_home "$USER_HOME")"
    # avoid duplicating the primary dir
    if [[ "$USER_DIR" != "${DEPLOY_DIRS[0]}" ]]; then
      DEPLOY_DIRS+=("$USER_DIR")
    fi
  fi
else
  DEPLOY_DIRS+=("$RUNTIME_SCRIPTS_DIR")
fi

for dir in "${DEPLOY_DIRS[@]}"; do
  if ! mkdir -p "$dir" 2>/dev/null; then
    sudo mkdir -p "$dir" 2>/dev/null || true
  fi
done

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

  for deploy_dir in "${DEPLOY_DIRS[@]}"; do
    runtime_wasm="$deploy_dir/$plugin_name.wasm"
    if cp -f "$built_wasm" "$runtime_wasm" 2>/dev/null; then
      echo "[+] Plugin deployed: $runtime_wasm"
    elif sudo cp -f "$built_wasm" "$runtime_wasm" 2>/dev/null; then
      echo "[+] Plugin deployed (sudo): $runtime_wasm"
    else
      echo "[!] Could not deploy to $runtime_wasm (skipping)" >&2
    fi
  done
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
echo "[i] Plugins deployed to:"
for dir in "${DEPLOY_DIRS[@]}"; do
  echo "      $dir"
done
