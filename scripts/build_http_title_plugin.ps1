$ErrorActionPreference = 'Stop'

$pluginManifest = Join-Path $PSScriptRoot "http_title\Cargo.toml"

Write-Host "[+] Building http_title (wasm32-unknown-unknown)..."
cargo build --release --target wasm32-unknown-unknown --manifest-path $pluginManifest

$built = Join-Path $PSScriptRoot "http_title\target\wasm32-unknown-unknown\release\http_title.wasm"
$out = Join-Path $PSScriptRoot "http_title.wasm"

Copy-Item -Path $built -Destination $out -Force
Write-Host "[+] Plugin ready: $out"
