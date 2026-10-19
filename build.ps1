<#
build.ps1 - one-command pipeline: translations -> exe -> installer.

  powershell -NoProfile -ExecutionPolicy Bypass -File build.ps1 -Task all          # full release build
  powershell -NoProfile -ExecutionPolicy Bypass -File build.ps1 -Task i18n         # refresh .pot/.po and compile .mo
  powershell -NoProfile -ExecutionPolicy Bypass -File build.ps1 -Task exe          # PyInstaller one-folder build
  powershell -NoProfile -ExecutionPolicy Bypass -File build.ps1 -Task installer    # Inno Setup package (needs dist output)
#>
[CmdletBinding()]
param(
    [ValidateSet('i18n', 'exe', 'installer', 'all', 'clean')]
    [string]$Task = 'all',
    [string]$Py = 'py'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

function Invoke-Step([string]$name, [scriptblock]$body) {
    Write-Host "==> $name" -ForegroundColor Cyan
    & $body
    if ($LASTEXITCODE -ne 0) { throw "$name failed (exit $LASTEXITCODE)" }
}

function Get-Meta {
    $values = & $Py -c "from app.meta import APP_NAME, VERSION, PUBLISHER; print(APP_NAME); print(VERSION); print(PUBLISHER)"
    if ($LASTEXITCODE -ne 0) { throw 'Unable to read app/meta.py - is the interpreter correct?' }
    $values
}

function Resolve-Pybabel {
    $scripts = (& $Py -c "import sysconfig; print(sysconfig.get_path('scripts'))").Trim()
    foreach ($candidate in @((Join-Path $scripts 'pybabel.exe'), 'pybabel')) {
        $found = Get-Command $candidate -ErrorAction SilentlyContinue
        if ($found) { return $found.Source }
    }
    throw 'pybabel not found. Run: py -m pip install -r requirements-dev.txt'
}

function Resolve-Iscc {
    if ($env:ISCC) { return $env:ISCC }
    # This machine keeps Inno Setup on another drive and off PATH, so read the
    # uninstall registry first and prefer the highest installed version.
    $regPaths = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    $installed = Get-ItemProperty $regPaths -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -like 'Inno Setup*' -and $_.InstallLocation } |
        Sort-Object { [version]($_.DisplayVersion -replace '[^0-9.].*$','') } -Descending
    foreach ($entry in $installed) {
        $candidate = Join-Path $entry.InstallLocation 'ISCC.exe'
        if (Test-Path $candidate) { return $candidate }
    }
    $candidates = @(
        "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
        "${env:ProgramFiles}\Inno Setup 6\ISCC.exe",
        "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe"
    )
    $onPath = Get-Command ISCC.exe -ErrorAction SilentlyContinue
    if ($onPath) { $candidates += $onPath.Source }
    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path $candidate)) { return $candidate }
    }
    throw 'Inno Setup not found. Install it (winget install -e --id JRSoftware.InnoSetup) or point $env:ISCC at ISCC.exe.'
}

function Step-I18n {
    $meta = Get-Meta
    $pybabel = Resolve-Pybabel
    & $pybabel extract --project=$($meta[0]) --version=$($meta[1]) -F babel.cfg -o locale/app.pot .
    if ($LASTEXITCODE -ne 0) { throw 'pybabel extract failed' }
    & $pybabel update -D app -i locale/app.pot -d locale
    if ($LASTEXITCODE -ne 0) { throw 'pybabel update failed' }
    & $pybabel compile -D app -d locale
    if ($LASTEXITCODE -ne 0) { throw 'pybabel compile failed' }
}

function Step-Exe {
    & $Py -m PyInstaller --noconfirm --clean app.spec
    if ($LASTEXITCODE -ne 0) { throw 'PyInstaller failed' }
}

function Step-Installer {
    $meta = Get-Meta
    $iscc = Resolve-Iscc
    $innoDir = Split-Path -Parent $iscc
    & $iscc "/DAppName=$($meta[0])" "/DAppVersion=$($meta[1])" "/DPublisher=$($meta[2])" "/DInnoDir=$innoDir" installer/setup.iss
    # ISCC returns non-zero on a script error; without this check the pipeline would
    # report success while dist\installer kept the previous build.
    if ($LASTEXITCODE -ne 0) { throw 'ISCC failed to compile installer/setup.iss' }
}

function Step-Clean {
    foreach ($dir in 'build', 'dist') {
        if (Test-Path $dir) { Remove-Item -Recurse -Force $dir }
    }
}

switch ($Task) {
    'i18n'      { Step-I18n }
    'exe'       { Step-Exe }
    'installer' { Step-Installer }
    'clean'     { Step-Clean }
    'all' {
        Step-I18n
        Step-Exe
        Step-Installer
        $meta = Get-Meta
        Write-Host "`nDone." -ForegroundColor Green
        Write-Host "  app       : dist\$($meta[0])\$($meta[0]).exe"
        Write-Host "  installer : dist\installer\"
    }
}
