$ErrorActionPreference = "Stop"

if (-not (Get-Command gcc -ErrorAction SilentlyContinue)) {
    Write-Host "error: gcc not found in PATH" -ForegroundColor Red
    exit 1
}

gcc -O2 -Wall -Wextra -municode -mconsole fuckace.c -lshell32 -o fuckAce.exe
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

Write-Host "build ok: $(Join-Path $PSScriptRoot 'fuckAce.exe')" -ForegroundColor Green
