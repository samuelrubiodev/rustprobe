$ErrorActionPreference = 'Stop'

$pluginManifest = Join-Path $PSScriptRoot "banner_grabber\Cargo.toml"

Write-Host "[+] Building banner_grabber (wasm32-unknown-unknown)..."
cargo build --release --target wasm32-unknown-unknown --manifest-path $pluginManifest

$built = Join-Path $PSScriptRoot "banner_grabber\target\wasm32-unknown-unknown\release\banner_grabber.wasm"
$out = Join-Path $PSScriptRoot "banner_grabber.wasm"

Copy-Item -Path $built -Destination $out -Force
Write-Host "[+] Plugin ready: $out"
