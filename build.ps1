$ErrorActionPreference = "Stop"

if (-not (Get-Command gcc -ErrorAction SilentlyContinue)) {
    Write-Host "error: gcc not found in PATH" -ForegroundColor Red
    exit 1
}

if (-not (Get-Command windres -ErrorAction SilentlyContinue)) {
    Write-Host "error: windres not found in PATH" -ForegroundColor Red
    exit 1
}

$res = "fuckace_res.o"

Push-Location $PSScriptRoot
try {
    windres fuckAce.rc -O coff -o $res
    if ($LASTEXITCODE -ne 0) {
        throw "windres failed (exit $LASTEXITCODE)"
    }

    gcc -Os -Wall -Wextra -municode -mconsole `
        -Isrc `
        -s -fno-asynchronous-unwind-tables `
        -ffunction-sections -fdata-sections `
        "-Wl,--gc-sections" "-Wl,--file-alignment=512" `
        "-Wl,--nxcompat" "-Wl,--dynamicbase" "-Wl,--high-entropy-va" `
        src/main.c src/config.c src/limiter.c src/ui.c src/engine.c $res -o fuckAce.exe
    if ($LASTEXITCODE -ne 0) {
        throw "gcc failed (exit $LASTEXITCODE)"
    }
}
finally {
    Remove-Item -Force $res -ErrorAction SilentlyContinue
    Pop-Location
}

Write-Host "build ok: $(Join-Path $PSScriptRoot 'fuckAce.exe')" -ForegroundColor Green
