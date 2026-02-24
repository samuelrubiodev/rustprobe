$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$pluginManifest = Join-Path $PSScriptRoot "sample_plugin\Cargo.toml"

Write-Host "[+] Building sample_plugin (wasm32-unknown-unknown)..."
cargo build --release --target wasm32-unknown-unknown --manifest-path $pluginManifest

$built = Join-Path $PSScriptRoot "sample_plugin\target\wasm32-unknown-unknown\release\sample_plugin.wasm"
$out = Join-Path $PSScriptRoot "sample_plugin.wasm"

Copy-Item -Path $built -Destination $out -Force
Write-Host "[+] Plugin ready: $out"
