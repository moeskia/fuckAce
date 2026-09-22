$ErrorActionPreference = "Stop"

if (-not (Get-Command gcc -ErrorAction SilentlyContinue)) {
    Write-Host "error: gcc not found in PATH" -ForegroundColor Red
    exit 1
}

windres fuckAce.rc -O coff -o fuckace_res.o
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

gcc -Os -Wall -Wextra -municode -mconsole `
    -Isrc `
    -s -fno-asynchronous-unwind-tables `
    -ffunction-sections -fdata-sections `
    "-Wl,--gc-sections" "-Wl,--file-alignment=512" `
    "-Wl,--nxcompat" "-Wl,--dynamicbase" "-Wl,--high-entropy-va" `
    src/main.c src/config.c src/limiter.c src/ui.c src/engine.c fuckace_res.o -o fuckAce.exe
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

Remove-Item -Force fuckace_res.o

Write-Host "build ok: $(Join-Path $PSScriptRoot 'fuckAce.exe')" -ForegroundColor Green
