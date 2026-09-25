$ErrorActionPreference = "Stop"
$out = Join-Path $PSScriptRoot "tests\fuckAceTests.exe"
Push-Location $PSScriptRoot
try {
    gcc -Os -Wall -Wextra -municode -mconsole -fstack-protector-strong -Isrc `
        tests/test_main.c src/config.c src/limiter.c src/elevate.c src/titoken.c src/ui.c `
        -lntdll -ladvapi32 -lshell32 -o $out
    if ($LASTEXITCODE -ne 0) {
        throw "test build failed"
    }
    & $out
    if ($LASTEXITCODE -ne 0) {
        throw "tests failed"
    }
}
finally {
    Remove-Item -Force $out -ErrorAction SilentlyContinue
    Pop-Location
}
