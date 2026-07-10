$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Resolve-Path (Join-Path $ScriptDir "..\..\..")

$PACKAGES = if ($env:PACKAGES) { $env:PACKAGES } else { Join-Path $RootDir "tests\ipa" }
$PRIVATE_KEY = if ($env:PRIVATE_KEY) { $env:PRIVATE_KEY } else { Join-Path $RootDir "tests\assets\test.p12" }
$MOBILE_PROVISION = if ($env:MOBILE_PROVISION) { $env:MOBILE_PROVISION } else { Join-Path $RootDir "tests\assets\test.mobileprovision" }
$ORCHARDSEAL_BIN = if ($env:ORCHARDSEAL_BIN) { $env:ORCHARDSEAL_BIN } else { Join-Path $RootDir "build\Release\orchardseal.exe" }

if (-not (Test-Path $ORCHARDSEAL_BIN)) {
    Write-Error "orchardseal binary not found: $ORCHARDSEAL_BIN"
    exit 1
}

Get-ChildItem -Path $PACKAGES -Filter "*.ipa" -ErrorAction SilentlyContinue | ForEach-Object {
    $file = $_.FullName
    Write-Host "$file : " -NoNewline

    & $ORCHARDSEAL_BIN -q -U -k $PRIVATE_KEY -m $MOBILE_PROVISION $file *> $null
    $exitCode = $LASTEXITCODE

    if ($exitCode -eq 0) {
        Write-Host -ForegroundColor Green "OK."
    } else {
        Write-Host -ForegroundColor Red "FAILED."
    }
}
