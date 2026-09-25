$ErrorActionPreference = "Stop"
$out = Join-Path $PSScriptRoot "tests\fuckAceTests.exe"
$sources = @("tests/test_main.c")
$sources += Get-ChildItem -Path (Join-Path $PSScriptRoot "src") -Recurse -Filter *.c |
    Where-Object { $_.Name -notin "main.c", "engine.c" } |
    Select-Object -ExpandProperty FullName

Push-Location $PSScriptRoot
try {
    gcc -Os -Wall -Wextra -municode -mconsole -fstack-protector-strong -Isrc `
        $sources `
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