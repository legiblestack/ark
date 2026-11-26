# Installs ARK for the current user.
#
#   Run via INSTALL.bat, or:  powershell -ExecutionPolicy Bypass -File install.ps1
#   Uninstall:                powershell -ExecutionPolicy Bypass -File install.ps1 -Uninstall
#
# Installs to %LOCALAPPDATA%\Programs\ARK (no admin needed to install), creates
# Start Menu and Desktop shortcuts that launch elevated, and registers an entry
# in Apps & Features.

param(
    [switch]$Uninstall,
    [switch]$NoShortcuts,
    [switch]$WithNmap,   # install Nmap without prompting
    [switch]$SkipNmap    # never install Nmap, do not prompt
)

$ErrorActionPreference = 'Stop'

$AppName    = 'ARK'
$InstallDir = Join-Path $env:LOCALAPPDATA 'Programs\ARK'
$DataDir    = Join-Path $env:LOCALAPPDATA 'ARK'
$StartMenu  = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs'
$Desktop    = [Environment]::GetFolderPath('Desktop')
$RegKey     = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\ARK-NetworkSecurityMonitor'
$Version    = '1.3.0'

function Info($m) { Write-Host "  $m" }
function Ok($m)   { Write-Host "  OK  $m" -ForegroundColor Green }
function Warn($m) { Write-Host "  --  $m" -ForegroundColor DarkYellow }
function Die($m)  { Write-Host "  ERR $m" -ForegroundColor Red; exit 1 }

function Find-Nmap {
    $cmd = Get-Command nmap -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    foreach ($p in @("$env:ProgramFiles\Nmap\nmap.exe", "${env:ProgramFiles(x86)}\Nmap\nmap.exe")) {
        if (Test-Path $p) { return $p }
    }
    return $null
}

# Downloads the official Nmap installer and runs it.
#
# ARK does not redistribute Nmap. Nmap's own license, and Npcap's in particular,
# restrict bundling it inside another installer, so we fetch it from the vendor at
# install time instead. The download is verified by Authenticode signature before
# it is executed - a hash pinned in this script would go stale on every Nmap
# release, whereas the publisher signature stays valid.
function Install-Nmap {
    $existing = Find-Nmap
    if ($existing) { Ok "Nmap already installed: $existing"; return $true }

    Info 'Locating the current Nmap release...'
    $ver = $null
    try {
        $page = Invoke-WebRequest 'https://nmap.org/download.html' -UseBasicParsing -TimeoutSec 30
        $m = [regex]::Match($page.Content, 'nmap-(\d+\.\d+)-setup\.exe')
        if ($m.Success) { $ver = $m.Groups[1].Value }
    } catch { Warn "Could not reach nmap.org: $($_.Exception.Message)" }
    if (-not $ver) { Warn 'Could not determine the current Nmap version; skipping.'; return $false }

    $file = "nmap-$ver-setup.exe"
    $url  = "https://nmap.org/dist/$file"
    $dest = Join-Path $env:TEMP $file
    Info "Downloading $file from nmap.org (about 30 MB)..."
    try {
        Invoke-WebRequest $url -OutFile $dest -UseBasicParsing -TimeoutSec 600
    } catch {
        Warn "Download failed: $($_.Exception.Message)"
        return $false
    }

    Info 'Verifying the installer signature...'
    $sig = Get-AuthenticodeSignature $dest
    if ($sig.Status -ne 'Valid') {
        Warn "REFUSING TO RUN: signature status is '$($sig.Status)', not Valid."
        Remove-Item $dest -Force -ErrorAction SilentlyContinue
        return $false
    }
    $subject = $sig.SignerCertificate.Subject
    if ($subject -notmatch 'Nmap|Insecure\.Com') {
        Warn "REFUSING TO RUN: unexpected signer: $subject"
        Remove-Item $dest -Force -ErrorAction SilentlyContinue
        return $false
    }
    Ok "Signed by: $subject"

    Info 'Running the Nmap installer (it will ask for Administrator rights)...'
    Info 'Npcap is bundled with it and shows its own licence prompt - accept it or the scanner will not work.'
    try {
        $p = Start-Process $dest -PassThru -Wait
        if ($p.ExitCode -ne 0) { Warn "Nmap installer exited with code $($p.ExitCode)." }
    } catch {
        Warn "Could not launch the Nmap installer: $($_.Exception.Message)"
        return $false
    } finally {
        Remove-Item $dest -Force -ErrorAction SilentlyContinue
    }

    $found = Find-Nmap
    if ($found) { Ok "Nmap installed: $found"; return $true }
    Warn 'Nmap still not detected. Install it manually from https://nmap.org/download.html'
    return $false
}

function New-Shortcut($LinkPath, $Target, $Description) {
    $sh = New-Object -ComObject WScript.Shell
    $sc = $sh.CreateShortcut($LinkPath)
    $sc.TargetPath       = $Target
    $sc.WorkingDirectory = Split-Path $Target -Parent
    $sc.Description      = $Description
    $sc.IconLocation     = "$Target,0"
    $sc.Save()
    # Set the "run as administrator" bit (byte 21, flag 0x20) in the .lnk header.
    # ARK needs elevation for firewall logs, full registry visibility, and killing
    # processes owned by other accounts.
    $bytes = [System.IO.File]::ReadAllBytes($LinkPath)
    $bytes[0x15] = $bytes[0x15] -bor 0x20
    [System.IO.File]::WriteAllBytes($LinkPath, $bytes)
}

Write-Host ""
Write-Host "  ARK - Network Security Monitor" -ForegroundColor White
Write-Host "  ==============================" -ForegroundColor DarkGray
Write-Host ""

# ---------------------------------------------------------------- uninstall --
if ($Uninstall) {
    Info 'Uninstalling ARK...'

    Get-CimInstance Win32_Process -Filter "Name='ARK.exe'" -ErrorAction SilentlyContinue | ForEach-Object {
        try { Stop-Process -Id $_.ProcessId -Force -ErrorAction Stop; Ok "Stopped running ARK (PID $($_.ProcessId))" } catch { }
    }
    Start-Sleep -Milliseconds 500

    foreach ($lnk in @((Join-Path $StartMenu 'ARK.lnk'), (Join-Path $Desktop 'ARK.lnk'))) {
        if (Test-Path $lnk) { Remove-Item $lnk -Force; Ok "Removed shortcut: $lnk" }
    }
    if (Test-Path $RegKey)     { Remove-Item $RegKey -Recurse -Force; Ok 'Removed Apps & Features entry' }
    if (Test-Path $InstallDir) { Remove-Item $InstallDir -Recurse -Force; Ok "Removed $InstallDir" }

    if (Test-Path $DataDir) {
        Warn "Logs and quarantine backups kept at: $DataDir"
        Warn 'Delete that folder manually if you want them gone.'
    }
    Write-Host ""
    Ok 'ARK uninstalled.'
    Write-Host ""
    exit 0
}

# ------------------------------------------------------------------ install --
$srcExe = Join-Path $PSScriptRoot 'ARK.exe'
if (-not (Test-Path $srcExe)) {
    Die "ARK.exe not found next to this script. Run build-exe.ps1 first, then install from dist\."
}

Info "Installing to $InstallDir"

# Stop any running copy so the file isn't locked mid-copy.
$running = Get-CimInstance Win32_Process -Filter "Name='ARK.exe'" -ErrorAction SilentlyContinue
if ($running) {
    Info 'Stopping running instance...'
    $running | ForEach-Object { try { Stop-Process -Id $_.ProcessId -Force -ErrorAction Stop } catch { } }
    Start-Sleep -Seconds 1
}

New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
New-Item -ItemType Directory -Path $DataDir -Force | Out-Null

Copy-Item $srcExe (Join-Path $InstallDir 'ARK.exe') -Force
Ok 'Copied ARK.exe'

# Ship the docs and the uninstaller alongside it.
foreach ($doc in @('README.md', 'QUICK-REFERENCE.md', 'REGISTRY-MONITORING.md')) {
    $p = Join-Path $PSScriptRoot $doc
    if (Test-Path $p) { Copy-Item $p $InstallDir -Force }
}
Copy-Item $PSCommandPath (Join-Path $InstallDir 'install.ps1') -Force
Ok 'Copied docs and uninstaller'

$installedExe = Join-Path $InstallDir 'ARK.exe'

if (-not $NoShortcuts) {
    New-Shortcut (Join-Path $StartMenu 'ARK.lnk') $installedExe 'ARK - Network Security Monitor'
    Ok 'Start Menu shortcut created (runs as Administrator)'
    New-Shortcut (Join-Path $Desktop 'ARK.lnk') $installedExe 'ARK - Network Security Monitor'
    Ok 'Desktop shortcut created (runs as Administrator)'
}

# Register with Apps & Features so it uninstalls like any normal program.
New-Item -Path $RegKey -Force | Out-Null
$uninstallCmd = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$InstallDir\install.ps1`" -Uninstall"
Set-ItemProperty $RegKey 'DisplayName'     'ARK - Network Security Monitor'
Set-ItemProperty $RegKey 'DisplayVersion'  $Version
Set-ItemProperty $RegKey 'Publisher'       'ARK'
Set-ItemProperty $RegKey 'InstallLocation' $InstallDir
Set-ItemProperty $RegKey 'DisplayIcon'     $installedExe
Set-ItemProperty $RegKey 'UninstallString' $uninstallCmd
Set-ItemProperty $RegKey 'NoModify'        1 -Type DWord
Set-ItemProperty $RegKey 'NoRepair'        1 -Type DWord
Set-ItemProperty $RegKey 'EstimatedSize'   ([int]((Get-Item $installedExe).Length / 1KB)) -Type DWord
Ok 'Registered in Apps & Features'

# --------------------------------------------------------------- Nmap -------
# Optional: powers the Ports & Scanner tab. Everything else works without it.
Write-Host ""
$nmapPath = Find-Nmap
if ($nmapPath) {
    Ok "Nmap detected: $nmapPath"
} elseif ($SkipNmap) {
    Info 'Skipping Nmap (-SkipNmap). The scanner tab will report it as missing.'
} else {
    $doIt = $WithNmap
    if (-not $doIt) {
        Info 'Nmap is not installed. It powers the network scanner tab; ARK works fine without it.'
        Info 'It is downloaded from nmap.org and its signature is verified before running.'
        $answer = Read-Host '  Install Nmap now? [y/N]'
        $doIt = ($answer -match '^(y|yes)$')
    }
    if ($doIt) { [void](Install-Nmap) } else { Info 'Skipped. Re-run this installer later to add it.' }
}

Write-Host ""
Ok "ARK $Version installed."
Write-Host ""
Info "Launch:     Start Menu -> ARK  (or the desktop shortcut)"
Info "Installed:  $InstallDir"
Info "Logs:       $DataDir\ark.log"
Info "Uninstall:  Apps & Features -> ARK, or run install.ps1 -Uninstall"
Write-Host ""
