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

if (-not (Test-Path -PathType Leaf $PRIVATE_KEY) -or -not (Test-Path -PathType Leaf $MOBILE_PROVISION)) {
    Write-Error "private signing assets not found; set PRIVATE_KEY and MOBILE_PROVISION"
    exit 1
}

$inputs = @(Get-ChildItem -Path $PACKAGES -Filter "*.ipa" -File -ErrorAction SilentlyContinue)
if ($inputs.Count -eq 0) {
    Write-Error "no IPA inputs found in $PACKAGES"
    exit 1
}

$outputDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ("orchardseal-windows-signing-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $outputDirectory -ErrorAction Stop | Out-Null
$failed = $false

try {
    foreach ($inputFile in $inputs) {
        $file = $inputFile.FullName
        $outputFile = Join-Path $outputDirectory $inputFile.Name
        Write-Host "$file : " -NoNewline

        & $ORCHARDSEAL_BIN -q -U -k $PRIVATE_KEY -m $MOBILE_PROVISION -o $outputFile $file *> $null
        $exitCode = $LASTEXITCODE

        if ($exitCode -eq 0 -and (Test-Path -PathType Leaf $outputFile) -and
            (Get-Item $outputFile).Length -gt 0) {
            Write-Host -ForegroundColor Green "OK."
        } else {
            Write-Host -ForegroundColor Red "FAILED."
            $failed = $true
        }
    }
} finally {
    Remove-Item -Recurse -Force $outputDirectory -ErrorAction SilentlyContinue
}

if ($failed) { exit 1 }
exit 0
