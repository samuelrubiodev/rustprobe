$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSVersion.Major -ge 7) {
    $PSNativeCommandUseErrorActionPreference = $false
}

$scriptDir = $PSScriptRoot
$targetTriple = 'wasm32-unknown-unknown'
$maxParallelJobs = 4
$runtimeScriptsDir = if ($env:RUSTPROBE_SCRIPTS_DIR -and $env:RUSTPROBE_SCRIPTS_DIR.Trim().Length -gt 0) {
    $env:RUSTPROBE_SCRIPTS_DIR
} elseif ($env:APPDATA -and $env:APPDATA.Trim().Length -gt 0) {
    Join-Path $env:APPDATA 'rustprobe\data\scripts'
} else {
    $null
}

if ($runtimeScriptsDir) {
    New-Item -ItemType Directory -Path $runtimeScriptsDir -Force | Out-Null
}

$pluginManifests = Get-ChildItem -Path $scriptDir -Directory |
    ForEach-Object { Join-Path $_.FullName 'Cargo.toml' } |
    Where-Object { Test-Path $_ }

if (-not $pluginManifests -or $pluginManifests.Count -eq 0) {
    Write-Host '[!] No plugin manifests found under scripts/.'
    exit 0
}

$jobs = @()

foreach ($manifest in $pluginManifests) {
    while ((@($jobs | Where-Object { $_.State -eq 'Running' }).Count) -ge $maxParallelJobs) {
        Start-Sleep -Milliseconds 200
    }

    $jobs += Start-Job -ArgumentList $manifest, $scriptDir, $targetTriple, $runtimeScriptsDir -ScriptBlock {
        param($manifestPath, $scriptsRoot, $target, $runtimeRoot)

        $ErrorActionPreference = 'Continue'
        if ($PSVersionTable.PSVersion.Major -ge 7) {
            $PSNativeCommandUseErrorActionPreference = $false
        }

        $pluginDir = Split-Path $manifestPath -Parent
        $pluginName = Split-Path $pluginDir -Leaf

        Write-Host "[+] Building $pluginName ($target)..."
        & cargo build --release --target $target --manifest-path $manifestPath *> $null

        if ($LASTEXITCODE -ne 0) {
            throw "cargo build failed for plugin: $pluginName"
        }

        $releaseDir = Join-Path $pluginDir "target\$target\release"
        $builtWasm = Join-Path $releaseDir "$pluginName.wasm"

        if (-not (Test-Path $builtWasm)) {
            $fallback = Get-ChildItem -Path $releaseDir -Filter '*.wasm' -File | Select-Object -First 1
            if ($null -eq $fallback) {
                throw "Could not locate built .wasm for plugin: $pluginName"
            }
            $builtWasm = $fallback.FullName
        }

        $outputWasm = Join-Path $scriptsRoot "$pluginName.wasm"
        Copy-Item -Path $builtWasm -Destination $outputWasm -Force
        Write-Host "[+] Plugin ready: $outputWasm"

        if ($runtimeRoot) {
            New-Item -ItemType Directory -Path $runtimeRoot -Force | Out-Null
            $runtimeWasm = Join-Path $runtimeRoot "$pluginName.wasm"
            Copy-Item -Path $builtWasm -Destination $runtimeWasm -Force
            Write-Host "[+] Plugin deployed: $runtimeWasm"
        }
    }
}

$failed = $false
foreach ($job in $jobs) {
    Wait-Job -Job $job | Out-Null
    Receive-Job -Job $job -ErrorAction Continue
    if ($job.State -ne 'Completed') {
        $failed = $true
    }
    Remove-Job -Job $job
}

if ($failed) {
    throw 'One or more plugin builds failed.'
}

Write-Host "[+] Completed. Built $($pluginManifests.Count) plugin(s)."
