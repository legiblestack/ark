# Builds ARK.exe - a single self-contained executable with ui.html embedded.
# NOTE: keep this file ASCII-only. Windows PowerShell 5.1 reads .ps1 as ANSI, so
# non-ASCII characters (em-dashes, arrows) become parse errors there.
#
#   powershell -ExecutionPolicy Bypass -File build-exe.ps1
#
# Uses Node's built-in Single Executable Application support, so the only
# build-time dependency is `postject` (fetched on demand by npx). The produced
# .exe needs no Node install on the target machine.

$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

$BuildDir = Join-Path $PSScriptRoot 'build'
$DistDir  = Join-Path $PSScriptRoot 'dist'
$Exe      = Join-Path $DistDir 'ARK.exe'
$Blob     = Join-Path $BuildDir 'ark-sea.blob'

function Step($n, $msg) { Write-Host ("[{0}] {1}" -f $n, $msg) -ForegroundColor Cyan }
function Ok($msg)       { Write-Host ("    OK  {0}" -f $msg) -ForegroundColor Green }
function Warn($msg)     { Write-Host ("    --  {0}" -f $msg) -ForegroundColor DarkYellow }
function Die($msg)      { Write-Host ("    ERR {0}" -f $msg) -ForegroundColor Red; exit 1 }

Write-Host ""
Write-Host "  Building ARK single-file executable" -ForegroundColor White
Write-Host "  ===================================" -ForegroundColor DarkGray
Write-Host ""

# --- 1. Prerequisites --------------------------------------------------------
Step 1 'Checking prerequisites'
if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    Die 'Node.js not found on PATH. Install Node 20+ from https://nodejs.org/'
}
$nodeVer  = (node --version).TrimStart('v')
$nodeMajor = [int]($nodeVer.Split('.')[0])
if ($nodeMajor -lt 20) { Die "Node $nodeVer is too old for SEA builds. Need Node 20 or newer." }
Ok "Node $nodeVer"

foreach ($f in @('server.js', 'ui.html', 'sea-config.json')) {
    if (-not (Test-Path (Join-Path $PSScriptRoot $f))) { Die "Missing required file: $f" }
}
Ok 'Source files present'

# --- 2. Syntax gate ----------------------------------------------------------
# A syntax error in ui.html silently produces a dashboard that renders nothing,
# so refuse to ship one.
Step 2 'Validating server.js and ui.html'
node --check server.js
if ($LASTEXITCODE -ne 0) { Die 'server.js has a syntax error' }

$uiCheck = node -e @"
const fs=require('fs');
const h=fs.readFileSync('ui.html','utf8');
const re=/<script[^>]*>([\s\S]*?)<\/script>/gi;
let m,bad=0,n=0;
while((m=re.exec(h))){n++;try{new Function(m[1]);}catch(e){bad++;console.error('ui.html script #'+n+': '+e.message);}}
process.exit(bad?1:0);
"@
if ($LASTEXITCODE -ne 0) { Die 'ui.html contains a JavaScript syntax error' }
Ok 'Both files parse cleanly'

# --- 3. Clean output dirs ----------------------------------------------------
Step 3 'Preparing output directories'
foreach ($d in @($BuildDir, $DistDir)) {
    if (Test-Path $d) { Remove-Item $d -Recurse -Force }
    New-Item -ItemType Directory -Path $d -Force | Out-Null
}
Ok "build/ and dist/ ready"

# --- 4. Generate the SEA blob ------------------------------------------------
Step 4 'Generating SEA blob (bundles server.js + ui.html)'
node --experimental-sea-config sea-config.json
if ($LASTEXITCODE -ne 0 -or -not (Test-Path $Blob)) { Die 'SEA blob generation failed' }
Ok ("blob: {0:N0} KB" -f ((Get-Item $Blob).Length / 1KB))

# --- 5. Copy the Node binary -------------------------------------------------
Step 5 'Copying Node runtime as ARK.exe'
$nodeExe = (Get-Command node).Source
Copy-Item $nodeExe $Exe -Force
Ok ("from {0}" -f $nodeExe)

# --- 6. Strip the Authenticode signature -------------------------------------
# Injecting a resource invalidates Node's own signature; removing it first avoids
# shipping a binary with a signature that no longer verifies.
Step 6 'Removing inherited code signature (best effort)'
$signtool = Get-ChildItem 'C:\Program Files (x86)\Windows Kits\10\bin' -Filter signtool.exe -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match 'x64' } | Select-Object -First 1
if ($signtool) {
    & $signtool.FullName remove /s $Exe 2>&1 | Out-Null
    Ok 'Signature removed with signtool'
} else {
    Write-Host '    --  signtool not found; continuing (the exe still works, it just carries a stale signature)' -ForegroundColor DarkYellow
}

# --- 7. Inject the blob ------------------------------------------------------
Step 7 'Injecting application blob with postject'
$fuse = 'NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2'
npx --yes postject $Exe NODE_SEA_BLOB $Blob --sentinel-fuse $fuse
if ($LASTEXITCODE -ne 0) { Die 'postject injection failed (needs network access on first run to fetch postject)' }
Ok 'Blob injected'

# --- 8. Smoke test -----------------------------------------------------------
# Launch the real binary, confirm it answers on whatever port it settled on, and
# confirm the embedded UI is being served rather than the recovery page.
Step 8 'Smoke-testing the built executable'
$stdout = Join-Path $BuildDir 'smoke-out.txt'
$proc = Start-Process -FilePath $Exe -ArgumentList '--no-supervise' `
        -WorkingDirectory $BuildDir -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput $stdout -RedirectStandardError (Join-Path $BuildDir 'smoke-err.txt')

$health = $null
for ($i = 0; $i -lt 20; $i++) {
    Start-Sleep -Milliseconds 500
    $portFile = Join-Path $env:LOCALAPPDATA 'ARK\ark.port'
    if (Test-Path $portFile) {
        $p = (Get-Content $portFile -Raw).Trim()
        try { $health = Invoke-RestMethod "http://localhost:$p/api/health" -TimeoutSec 3; break } catch { }
    }
}
try { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue } catch { }

if (-not $health) {
    Write-Host '    --- server output ---' -ForegroundColor DarkGray
    if (Test-Path $stdout) { Get-Content $stdout | Select-Object -Last 20 }
    Die 'Built exe did not come up. See output above.'
}
if ($health.uiSource -eq 'fallback') { Die 'Exe runs, but ui.html was not embedded (serving recovery page)' }
Ok ("v{0} responded on port {1}; UI source = {2}" -f $health.version, $health.port, $health.uiSource)

# --- 9. Stage the distributable ---------------------------------------------
Step 9 'Staging dist/'
foreach ($f in @('install.ps1', 'INSTALL.bat', 'README.md', 'QUICK-REFERENCE.md', 'REGISTRY-MONITORING.md')) {
    $src = Join-Path $PSScriptRoot $f
    if (Test-Path $src) { Copy-Item $src $DistDir -Force } else { Warn "not staged (missing): $f" }
}
Ok 'Installer + docs staged'

$size = (Get-Item $Exe).Length / 1MB
Write-Host ""
Write-Host ("  Done - dist\ARK.exe ({0:N1} MB)" -f $size) -ForegroundColor Green
Write-Host "  Install it by running dist\INSTALL.bat (elevates automatically)."
Write-Host ""
