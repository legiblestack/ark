/*
 * ARK - Network Security Monitor (zero-dependency server)
 * Runs on Node's built-in http module. No npm install required.
 * Serves the UI and exposes JSON endpoints that run PowerShell / nmap.
 *
 *   node server.js
 *   then open http://localhost:8088
 */

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const dns = require('dns');
const { spawn } = require('child_process');

const VERSION = '1.3.0';

// --- Single-executable (SEA) awareness ---------------------------------------
// When bundled with `node --experimental-sea-config`, ui.html rides along as an
// embedded asset and __dirname points inside the binary, so resolve paths from
// the .exe location instead.
let sea = null;
try { sea = require('node:sea'); } catch (e) { /* older Node */ }
const IS_SEA = !!(sea && typeof sea.isSea === 'function' && sea.isSea());
const APP_DIR = IS_SEA ? path.dirname(process.execPath) : __dirname;

// Writable state lives outside Program Files so an installed copy never needs
// write access to its own directory.
const DATA_DIR = path.join(process.env.LOCALAPPDATA || os.tmpdir(), 'ARK');
const LOG_FILE = path.join(DATA_DIR, 'ark.log');
const PORT_FILE = path.join(DATA_DIR, 'ark.port');
// Backups of anything ARK removes. Kept beside the logs, not in the install
// directory, so it stays writable and survives an upgrade.
const QUARANTINE_DIR = path.join(DATA_DIR, 'quarantine');
const QUARANTINE_PS = QUARANTINE_DIR.replace(/'/g, "''"); // safe inside a PS single-quoted string

function ensureDataDir() {
  try { fs.mkdirSync(DATA_DIR, { recursive: true }); return true; } catch (e) { return false; }
}

// --- Logging (console + rotating file) ---------------------------------------
function log(level, msg) {
  const line = `[${new Date().toISOString()}] ${level} ${msg}`;
  if (level === 'ERROR') console.error(line); else console.log(line);
  try {
    ensureDataDir();
    try {
      const st = fs.statSync(LOG_FILE);
      if (st.size > 2 * 1024 * 1024) fs.renameSync(LOG_FILE, LOG_FILE + '.1');
    } catch (e) { /* no log yet */ }
    fs.appendFileSync(LOG_FILE, line + '\n');
  } catch (e) { /* logging must never be fatal */ }
}

// --- Never die on an unexpected error ----------------------------------------
// A monitoring tool that vanishes on one bad PowerShell response is worse than
// one that reports the error and keeps serving.
process.on('uncaughtException', (e) => log('ERROR', 'uncaughtException: ' + (e && e.stack || e)));
process.on('unhandledRejection', (e) => log('ERROR', 'unhandledRejection: ' + (e && e.stack || e)));

// --- Supervisor: relaunch the worker if it ever exits -------------------------
// The parent process does nothing but restart the child, so a hard crash heals
// itself instead of leaving a dead tab in the browser.
const SUPERVISE = process.env.ARK_ROLE !== 'worker' && !process.argv.includes('--no-supervise');
if (SUPERVISE) {
  // argv is [runtime, script-or-exe, ...userArgs]. Unpackaged we must re-pass the
  // script path; packaged the exe already knows its own entry point.
  const userArgs = process.argv.slice(2);
  const childArgs = IS_SEA ? userArgs : [process.argv[1]].concat(userArgs);
  let restarts = 0;
  let stopping = false;
  const start = () => {
    const child = spawn(process.execPath, childArgs, {
      stdio: 'inherit',
      env: Object.assign({}, process.env, { ARK_ROLE: 'worker' })
    });
    child.on('exit', (code, signal) => {
      if (stopping) return;
      if (code === 0) { process.exit(0); return; }
      restarts++;
      if (restarts > 10) {
        log('ERROR', 'Worker exited ' + restarts + ' times; giving up. See ' + LOG_FILE);
        process.exit(1);
      }
      const delay = Math.min(1000 * restarts, 10000);
      log('WARN', `Worker exited (code=${code} signal=${signal}); restarting in ${delay}ms (attempt ${restarts})`);
      setTimeout(start, delay);
    });
    child.on('error', (e) => log('ERROR', 'Failed to spawn worker: ' + e.message));
    const stop = () => { stopping = true; try { child.kill(); } catch (e) {} process.exit(0); };
    process.on('SIGINT', stop);
    process.on('SIGTERM', stop);
  };
  start();
  return;
}

// Preferred port first, then fallbacks, then 0 = "any free port the OS gives us".
// 7070 is deliberately absent: AnyDesk and several remote-desktop tools squat on it.
const PORT = parseInt(process.env.PORT, 10) || 8088;
const PORT_CANDIDATES = [PORT, 8090, 8188, 9088, 18088, 0];

// Per-run secret, handed to the dashboard when we serve it and required on every
// state-changing call. Regenerated each start, never written to disk.
const TOKEN = crypto.randomBytes(24).toString('hex');
const LOCAL_HOST_RE = /^(localhost|127\.0\.0\.1|\[::1\])(:\d+)?$/i;

// --- In-Bounds Connection Watchdog (Little Snitch-style) ----------------------
// Configurable mode: 'off' | 'notify' | 'ask'
let guardMode = (process.env.ARK_GUARD || 'notify').toLowerCase();
const GUARD_TICK_MS = 3000; // how often to poll for new incoming connections

// State file for persisting allow/block lists (outside Program Files)
const GUARD_STATE_FILE = path.join(DATA_DIR, 'guard-state.json');

// Simple state: { rules: [{direction:'in',proc:string,remote:string,port:number,action:'allow'|'block',expiresAt:number|null}, ...] }
let guardState = { rules: [] };

function loadGuardState() {
  try {
    const raw = fs.readFileSync(GUARD_STATE_FILE, 'utf8');
    const parsed = JSON.parse(raw);
    if (parsed && Array.isArray(parsed.rules)) {
      guardState = parsed;
      // Filter out expired rules
      const now = Date.now();
      guardState.rules = guardState.rules.filter(r => !r.expiresAt || r.expiresAt > now);
    }
  } catch (e) { /* fresh state */ }
}

function saveGuardState() {
  try { fs.writeFileSync(GUARD_STATE_FILE, JSON.stringify(guardState, null, 2), 'utf8'); } catch (e) {}
}

// PowerShell to list INBOUND connections (established or listening)
const PS_INBOUND = `
$connections = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Select-Object LocalAddress, LocalPort, OwningProcess, OwningProcess | ForEach-Object {
  [PSCustomObject]@{
    Type = 'listen'
    LocalAddress = $_.LocalAddress
    LocalPort = $_.LocalPort
    PID = $_.OwningProcess
  }
}
$conns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object {
  $_.RemoteAddress -match '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' -and $_.RemoteAddress -notmatch '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|0\.0\.0\.0)'
} | ForEach-Object {
  [PSCustomObject]@{
    Type = 'established'
    LocalAddress = $_.LocalAddress
    LocalPort = $_.LocalPort
    RemoteAddress = $_.RemoteAddress
    RemotePort = $_.RemotePort
    PID = $_.OwningProcess
  }
}
$connections | ConvertTo-Json -Depth 3
`;

// PowerShell to send a Windows toast notification
// Uses WScript.Shell as fallback since BurntToast may not be installed
const PS_SEND_TOAST = (title, message) => `
$ws = New-Object -ComObject "Wscript.Shell"
$ws.Popup("$message", 10, "$title", 0x0) | Out-Null
`;

// Check if a rule already controls this connection
function findExistingRule(dir, proc, remoteAddr, remotePort, localPort) {
  const now = Date.now();
  return guardState.rules.find(r =>
    r.direction === dir &&
    r.process === proc &&
    r.remote === remoteAddr &&
    r.remotePort === remotePort &&
    r.localPort === localPort &&
    (!r.expiresAt || r.expiresAt > now)
  );
}

// Check if a rule should allow/block this connection
function shouldAllowConnection(remoteAddr, remotePort, localPort, pid) {
  const now = Date.now();
  const rule = guardState.rules.find(r =>
    r.direction === 'in' &&
    (!r.remote && !r.remotePort) &&  // wildcard rule
    (!r.expiresAt || r.expiresAt > now)
  );
  if (rule) {
    if (rule.action === 'block') return { allowed: false, rule };
    if (rule.action === 'allow') return { allowed: true, rule };
  }
  return { allowed: true, rule: null };
}

// PowerShell to create an outbound firewall rule to block a specific connection
function psCreateFirewallRule(ruleName, profile = 'Domain,Private,Public') {
  return `
$ruleName = "$ruleName"
$profile = "$profile"
# Create an outbound rule to block the specific remote address
New-NetFirewallRule -DisplayName $ruleName -Direction Outbound -Action Block -Profile $profile -Enabled True -ErrorAction SilentlyContinue | Out-Null
`;
}

// --- Reverse DNS with caching + timeout (used for threat scoring) ------------
const rdnsCache = new Map();
function reverseDns(ip) {
  if (rdnsCache.has(ip)) return Promise.resolve(rdnsCache.get(ip));
  return new Promise((resolve) => {
    let done = false;
    const finish = (val) => { if (!done) { done = true; clearTimeout(t); rdnsCache.set(ip, val); resolve(val); } };
    const t = setTimeout(() => finish(null), 1500);
    try {
      dns.reverse(ip, (err, names) => finish(!err && names && names[0] ? names[0] : null));
    } catch (e) { finish(null); }
  });
}

function isExternalIp(ip) {
  if (!ip) return false;
  return !/^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|169\.254\.|127\.|0\.0\.0\.0|::1$|::$|fe80|fc|fd)/i.test(ip);
}

// Publishers we treat as well-known/reputable (matched against the binary's CompanyName)
const KNOWN_PUBLISHERS = [
  'microsoft','google','mozilla','apple','adobe','valve','steam','discord','spotify',
  'brave','cloudflare','amazon','dropbox','slack','zoom','intel','nvidia','realtek',
  'epic games','riot games','meta','whatsapp','telegram','signal','opera','vivaldi',
  'jetbrains','github','oracle','logitech','razer','node.js','openjs','python','docker'
];
// Reverse-DNS fragments that indicate a known hosting/CDN/provider
const KNOWN_RDNS = [
  '1e100.net','google','googlevideo','gstatic','youtube','akamai','cloudfront','amazonaws',
  'microsoft','msedge','windowsupdate','office','live.com','skype','fbcdn','facebook',
  'instagram','fastly','cloudflare','apple','icloud','mzstatic','mozilla','azure',
  'edgekey','edgesuite','twitch','discord','spotify','digitalocean','cdn'
];
const STD_PORTS = [443, 80, 8443];

// Heuristic threat score for one external connection. Higher = safer.
function scoreConnection(c, rdns) {
  const reasons = [];
  const sig = String(c.Signature || '').toLowerCase();
  const comp = String(c.Company || '').toLowerCase();
  const p = String(c.Path || '').toLowerCase();
  const port = parseInt(c.RemotePort, 10);

  // Process trust
  let proc;
  const knownPub = comp && KNOWN_PUBLISHERS.some((k) => comp.includes(k));
  if (sig === 'valid' && knownPub) { proc = 2; reasons.push('Signed by known publisher (' + c.Company + ')'); }
  else if (sig === 'valid')        { proc = 1; reasons.push('Digitally signed' + (c.Company ? ' (' + c.Company + ')' : '')); }
  else                             { proc = 0; reasons.push(sig === 'notsigned' || sig === '' ? 'Process NOT signed' : 'Signature: ' + (c.Signature || 'unknown')); }
  // Only genuinely suspect locations — NOT AppData broadly (many legit per-user apps live there).
  // Note: \temp\ also catches AppData\Local\Temp.
  if (/\\(temp|downloads|\$recycle\.bin)\\/.test(p)) {
    proc = Math.min(proc, -1);
    reasons.push('Runs from suspicious location (Temp/Downloads/Recycle Bin)');
  }

  // Destination trust
  let dest;
  const knownHost = rdns && KNOWN_RDNS.some((d) => rdns.toLowerCase().includes(d));
  if (knownHost)                 { dest = 2; reasons.push('Destination resolves to known provider: ' + rdns); }
  else if (rdns)                 { dest = 1; reasons.push('Resolves to ' + rdns); }
  else if (STD_PORTS.includes(port)) { dest = 0; reasons.push('No reverse DNS; standard port ' + port); }
  else                           { dest = -1; reasons.push('No reverse DNS; unusual port ' + port); }

  const score = proc + dest;
  let level, color;
  if (score >= 4)      { level = 'SAFE';     color = '#3ddc84'; }
  else if (score === 3){ level = 'LOW';      color = '#9ad94f'; }
  else if (score === 2){ level = 'MODERATE'; color = '#ffc107'; }
  else if (score === 1){ level = 'ELEVATED'; color = '#ff8c3a'; }
  else                 { level = 'UNKNOWN';  color = '#ff5252'; }

  return { level, color, score, reasons, rdns: rdns || null };
}

// --- Run a PowerShell snippet and parse its JSON stdout ----------------------
const PS_TIMEOUT_MS = parseInt(process.env.ARK_PS_TIMEOUT, 10) || 45000;

function runPowerShell(script, timeoutMs) {
  return new Promise((resolve) => {
    let ps;
    try {
      ps = spawn('powershell.exe', [
        '-NoProfile',
        '-NonInteractive',
        '-ExecutionPolicy', 'Bypass',
        '-Command', script
      ], { windowsHide: true });
    } catch (e) {
      log('ERROR', 'PowerShell spawn threw: ' + e.message);
      resolve({ ok: false, error: 'Could not start PowerShell: ' + e.message, data: [] });
      return;
    }

    let out = '';
    let err = '';
    let settled = false;
    const done = (v) => { if (settled) return; settled = true; clearTimeout(killer); resolve(v); };

    // A hung query must not hang the whole dashboard — kill it and report.
    const killer = setTimeout(() => {
      try { ps.kill(); } catch (e) {}
      log('WARN', 'PowerShell query timed out after ' + (timeoutMs || PS_TIMEOUT_MS) + 'ms');
      done({ ok: false, error: 'Query timed out after ' + Math.round((timeoutMs || PS_TIMEOUT_MS) / 1000) + 's. Retry, or run ARK as Administrator if this keeps happening.', data: [] });
    }, timeoutMs || PS_TIMEOUT_MS);

    ps.stdout.on('data', (d) => { if (out.length < 8e6) out += d.toString(); });
    ps.stderr.on('data', (d) => { if (err.length < 1e5) err += d.toString(); });
    ps.on('error', (e) => { log('ERROR', 'PowerShell error: ' + e.message); done({ ok: false, error: e.message, data: [] }); });
    ps.on('close', () => {
      const trimmed = out.trim();
      if (!trimmed) {
        done({ ok: true, data: [], error: err.trim() || null });
        return;
      }
      try {
        const parsed = JSON.parse(trimmed);
        done({ ok: true, data: Array.isArray(parsed) ? parsed : [parsed], error: null });
      } catch (e) {
        log('WARN', 'PowerShell returned non-JSON: ' + trimmed.slice(0, 200));
        done({ ok: false, error: 'JSON parse failed: ' + e.message, raw: trimmed.slice(0, 2000), data: [] });
      }
    });
  });
}

// --- Locate nmap --------------------------------------------------------------
// The Nmap installer does not always put nmap on PATH, and an elevated process
// started from a shortcut may not inherit a PATH change made after login. Check
// the standard install locations before giving up.
const NMAP_CANDIDATES = [
  path.join(process.env['ProgramFiles(x86)'] || 'C:\\Program Files (x86)', 'Nmap', 'nmap.exe'),
  path.join(process.env.ProgramFiles || 'C:\\Program Files', 'Nmap', 'nmap.exe')
];

let nmapPathCache;
function findNmap() {
  if (nmapPathCache !== undefined) return nmapPathCache;
  for (const p of NMAP_CANDIDATES) {
    try { if (fs.existsSync(p)) { nmapPathCache = p; return p; } } catch (e) {}
  }
  nmapPathCache = 'nmap'; // fall back to PATH lookup
  return nmapPathCache;
}

// --- Run nmap (returns raw text, not JSON) -----------------------------------
function runNmap(target) {
  return new Promise((resolve) => {
    // Basic sanitization: only allow hostname/IP/CIDR-ish characters
    if (!/^[A-Za-z0-9_.:\-/]+$/.test(target)) {
      resolve({ ok: false, error: 'Invalid target. Use a hostname, IP, or CIDR.', output: '' });
      return;
    }
    const exe = findNmap();
    const nmap = spawn(exe, ['-sV', '-T4', '--top-ports', '200', target], { windowsHide: true });
    let out = '';
    let err = '';
    let settled = false;
    const finish = (v) => { if (settled) return; settled = true; clearTimeout(killer); resolve(v); };

    // Scans of a slow or filtered host can run for a very long time; cap them.
    const killer = setTimeout(() => {
      try { nmap.kill(); } catch (e) {}
      finish({ ok: true, output: out + '\n\n[ARK] Scan stopped after 5 minutes.', error: null });
    }, 5 * 60 * 1000);

    nmap.stdout.on('data', (d) => { if (out.length < 4e6) out += d.toString(); });
    nmap.stderr.on('data', (d) => { if (err.length < 1e5) err += d.toString(); });
    nmap.on('error', (e) => {
      nmapPathCache = undefined; // re-probe next time; nmap may get installed while we run
      finish({
        ok: false,
        error: 'nmap is not installed (' + e.message + '). Re-run the ARK installer and choose to install Nmap, '
             + 'or get it from https://nmap.org/download.html',
        output: ''
      });
    });
    nmap.on('close', () => finish({ ok: true, output: out || err, error: null }));
  });
}

// --- PowerShell payloads (emit clean PSCustomObject JSON) --------------------
const PS = {
  connections: `
    $procs = @{}; Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $procs[$_.Id] = $_ }
    $cache = @{}
    function Get-ProcInfo($id) {
      if ($cache.ContainsKey($id)) { return $cache[$id] }
      $info = [PSCustomObject]@{ Name = 'Unknown'; Path = ''; Company = ''; Sig = 'unknown'; MemoryMB = 0 }
      $p = $procs[[int]$id]
      if ($p) {
        $info.Name = $p.ProcessName
        $info.MemoryMB = [math]::Round($p.WorkingSet64 / 1MB, 1)
        $info.Path = "$($p.Path)"
        if ($p.Path) {
          try { $info.Company = "$((Get-Item $p.Path -ErrorAction Stop).VersionInfo.CompanyName)" } catch {}
          try { $info.Sig = (Get-AuthenticodeSignature $p.Path -ErrorAction Stop).Status.ToString() } catch {}
        }
      }
      $cache[$id] = $info
      return $info
    }
    Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | ForEach-Object {
      $pi = Get-ProcInfo $_.OwningProcess
      [PSCustomObject]@{
        LocalAddress  = $_.LocalAddress
        LocalPort     = $_.LocalPort
        RemoteAddress = $_.RemoteAddress
        RemotePort    = $_.RemotePort
        State         = "$($_.State)"
        PID           = $_.OwningProcess
        ProcessName   = $pi.Name
        MemoryMB      = $pi.MemoryMB
        Company       = $pi.Company
        Signature     = $pi.Sig
        Path          = $pi.Path
      }
    } | ConvertTo-Json -Depth 3
  `,
  listening: `
    $procs = @{}; Get-Process | ForEach-Object { $procs[$_.Id] = $_ }
    Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | ForEach-Object {
      $p = $procs[[int]$_.OwningProcess]
      [PSCustomObject]@{
        LocalAddress = $_.LocalAddress
        LocalPort    = $_.LocalPort
        PID          = $_.OwningProcess
        ProcessName  = if ($p) { $p.ProcessName } else { 'Unknown' }
      }
    } | Sort-Object LocalPort | ConvertTo-Json -Depth 3
  `,
  firewall: `
    $profiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue | ForEach-Object {
      [PSCustomObject]@{ Name = "$($_.Name)"; Enabled = [bool]$_.Enabled; Inbound = "$($_.DefaultInboundAction)"; Outbound = "$($_.DefaultOutboundAction)" }
    }
    $rules = @()
    $item = Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules' -ErrorAction SilentlyContinue
    if ($item) {
      foreach ($p in ($item.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' })) {
        $h = @{}
        foreach ($part in ("$($p.Value)" -split '\\|')) {
          $idx = $part.IndexOf('=')
          if ($idx -gt 0) { $h[$part.Substring(0, $idx)] = $part.Substring($idx + 1) }
        }
        $rules += [PSCustomObject]@{
          Name = $h['Name']; Action = $h['Action']; Active = $h['Active']; Dir = $h['Dir']
          Protocol = $h['Protocol']; LPort = $h['LPort']; App = $h['App']; Profile = $h['Profile']; RA4 = $h['RA4']
        }
      }
    }
    [PSCustomObject]@{ profiles = $profiles; rules = $rules } | ConvertTo-Json -Depth 5
  `,
  registry: `
    $paths = @(
      'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
      'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
      'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
      'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce'
    )
    $rows = @()
    foreach ($path in $paths) {
      $item = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
      if ($item) {
        $item.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object {
          $rows += [PSCustomObject]@{ Path = $path; Name = $_.Name; Value = "$($_.Value)" }
        }
      }
    }
    $rows | ConvertTo-Json -Depth 3
  `,

  // Deep autostart scan: Run keys + Winlogon Shell/Userinit + startup folders
  startup: `
    $rows = @()
    $runPaths = @(
      @{ P = 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run';     S = 'HKLM Run' },
      @{ P = 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce'; S = 'HKLM RunOnce' },
      @{ P = 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run';     S = 'HKCU Run' },
      @{ P = 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce'; S = 'HKCU RunOnce' }
    )
    foreach ($r in $runPaths) {
      $item = Get-ItemProperty -Path $r.P -ErrorAction SilentlyContinue
      if ($item) {
        $item.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object {
          $rows += [PSCustomObject]@{ Source = $r.S; Name = $_.Name; Value = "$($_.Value)" }
        }
      }
    }
    foreach ($wl in @('HKLM:\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon','HKCU:\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon')) {
      $w = Get-ItemProperty -Path $wl -ErrorAction SilentlyContinue
      if ($w) {
        if ($w.Shell)    { $rows += [PSCustomObject]@{ Source = 'Winlogon Shell';    Name = 'Shell';    Value = "$($w.Shell)" } }
        if ($w.Userinit) { $rows += [PSCustomObject]@{ Source = 'Winlogon Userinit'; Name = 'Userinit'; Value = "$($w.Userinit)" } }
      }
    }
    $folders = @(
      @{ P = [Environment]::GetFolderPath('Startup');       S = 'User Startup Folder' },
      @{ P = [Environment]::GetFolderPath('CommonStartup'); S = 'Common Startup Folder' }
    )
    foreach ($f in $folders) {
      if ($f.P -and (Test-Path $f.P)) {
        Get-ChildItem -Path $f.P -File -Force -ErrorAction SilentlyContinue | ForEach-Object {
          $rows += [PSCustomObject]@{ Source = $f.S; Name = $_.Name; Value = "$($_.FullName)" }
        }
      }
    }
    $rows | ConvertTo-Json -Depth 3
  `,

  // Auto-start services whose binary lives outside the Windows dir (more likely to be 3rd-party / suspect)
  services: `
    Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
      Where-Object { $_.StartMode -eq 'Auto' -and $_.PathName -and $_.PathName -notmatch 'C:\\\\WINDOWS' } |
      ForEach-Object {
        [PSCustomObject]@{
          Name    = $_.Name
          Display = $_.DisplayName
          State   = $_.State
          Account = $_.StartName
          Path    = ($_.PathName -replace '^"([^"]+)".*','$1')
        }
      } | Sort-Object Display | ConvertTo-Json -Depth 3
  `,

  // Installed programs (flags missing publisher on the UI side)
  programs: `
    $paths = @(
      'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',
      'HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',
      'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'
    )
    $rows = @()
    foreach ($p in $paths) {
      Get-ItemProperty $p -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } | ForEach-Object {
        $rows += [PSCustomObject]@{
          Name      = "$($_.DisplayName)"
          Publisher = "$($_.Publisher)"
          Version   = "$($_.DisplayVersion)"
          Install   = "$($_.InstallDate)"
          Location  = "$($_.InstallLocation)"
        }
      }
    }
    $rows | Sort-Object Name -Unique | ConvertTo-Json -Depth 3
  `
};

// Parameterized PowerShell (pid is validated to an integer before interpolation)
function psProcessDetails(pid) {
  return `
    $p = Get-Process -Id ${pid} -ErrorAction SilentlyContinue
    if ($p) {
      $path = $p.Path; $company = ''; $product = ''; $sig = 'unknown'
      if ($path) {
        try { $vi = (Get-Item $path).VersionInfo; $company = "$($vi.CompanyName)"; $product = "$($vi.ProductName)" } catch {}
        try { $sig = (Get-AuthenticodeSignature $path).Status.ToString() } catch {}
      }
      [PSCustomObject]@{ Name = $p.ProcessName; Id = $p.Id; Path = "$path"; Company = $company; Product = $product; Signature = $sig } | ConvertTo-Json
    } else {
      [PSCustomObject]@{ Name = ''; Id = 0; Path = ''; Error = 'Process not found (may have exited)' } | ConvertTo-Json
    }
  `;
}
// Read a JSON request body
function readJsonBody(req) {
  return new Promise((resolve) => {
    let b = '';
    req.on('data', (c) => { b += c; if (b.length > 1e6) req.destroy(); });
    req.on('end', () => { try { resolve(JSON.parse(b || '{}')); } catch (e) { resolve(null); } });
    req.on('error', () => resolve(null));
  });
}

// Delete/quarantine selected startup items. Reads a JSON file of items (written by the
// server, so no shell-injection risk). Backs up everything; refuses Winlogon entries.
function psDeleteStartup(jsonPath) {
  return `
    $ErrorActionPreference = 'Stop'
    $root = '${QUARANTINE_PS}'
    New-Item -ItemType Directory -Force -Path $root | Out-Null
    New-Item -ItemType Directory -Force -Path "$root\\startup-files" | Out-Null
    $items = Get-Content -Raw -LiteralPath '${jsonPath}' | ConvertFrom-Json
    $map = @{
      'HKLM Run'     = 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'
      'HKLM RunOnce' = 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce'
      'HKCU Run'     = 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'
      'HKCU RunOnce' = 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce'
    }
    $stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
    $backupLog = "$root\\deleted-$stamp.log"
    $results = @()
    foreach ($it in $items) {
      $src = "$($it.source)"; $name = "$($it.name)"; $val = "$($it.value)"
      try {
        if ($src -like 'Winlogon*') {
          $results += [PSCustomObject]@{ name = $name; ok = $false; msg = 'Refused: Winlogon Shell/Userinit are critical to login and were NOT touched.' }
          continue
        }
        if ($map.ContainsKey($src)) {
          $path = $map[$src]
          Add-Content -LiteralPath $backupLog -Value ("REG" + [char]9 + $path + [char]9 + $name + [char]9 + $val)
          Remove-ItemProperty -Path $path -Name $name -ErrorAction Stop
          $results += [PSCustomObject]@{ name = $name; ok = $true; msg = "Removed from $src (backed up)" }
        }
        elseif ($src -like '*Startup Folder') {
          if (Test-Path -LiteralPath $val) {
            $dest = Join-Path "$root\\startup-files" ($stamp + '_' + (Split-Path -Leaf $val))
            Move-Item -LiteralPath $val -Destination $dest -Force
            Add-Content -LiteralPath $backupLog -Value ("FILE" + [char]9 + $val + [char]9 + "->" + [char]9 + $dest)
            $results += [PSCustomObject]@{ name = $name; ok = $true; msg = "Moved to quarantine" }
          } else {
            $results += [PSCustomObject]@{ name = $name; ok = $false; msg = 'File not found (already gone)' }
          }
        }
        else {
          $results += [PSCustomObject]@{ name = $name; ok = $false; msg = "Unknown source: $src" }
        }
      } catch {
        $results += [PSCustomObject]@{ name = $name; ok = $false; msg = "$($_.Exception.Message)" }
      }
    }
    [PSCustomObject]@{ backup = $backupLog; results = $results } | ConvertTo-Json -Depth 4
  `;
}

// Disable selected auto-start services (REVERSIBLE: sets Disabled + stops; backs up prior config).
// Hard-refuses Microsoft security + critical OS services.
function psDisableServices(jsonPath, dryRun) {
  return `
    $ErrorActionPreference = 'Stop'
    $root = '${QUARANTINE_PS}'; New-Item -ItemType Directory -Force -Path $root | Out-Null
    $items = Get-Content -Raw -LiteralPath '${jsonPath}' | ConvertFrom-Json
    $dry = ${dryRun ? '$true' : '$false'}
    $protected = @('windefend','wdnissvc','sense','securityhealthservice','mssecflt','webthreatdefsvc','wscsvc','mpssvc','msmpsvc','wdfilter','wdboot','dnscache','rpcss','lsm','plugplay','power','brokerinfrastructure','dcomlaunch','eventlog','schedule','samss','winmgmt')
    $stamp = (Get-Date).ToString('yyyyMMdd-HHmmss'); $log = "$root\\services-disabled-$stamp.log"
    $results = @()
    foreach ($it in $items) {
      $name = "$($it.name)"
      try {
        $svc = Get-CimInstance Win32_Service -Filter ("Name='" + ($name -replace "'","''") + "'") -ErrorAction SilentlyContinue
        if (-not $svc) { $results += [PSCustomObject]@{ name=$name; ok=$false; msg='Service not found' }; continue }
        if (($protected -contains $name.ToLower()) -or ($svc.PathName -match 'Windows Defender')) {
          $results += [PSCustomObject]@{ name=$name; ok=$false; msg='REFUSED: protected security/system service' }; continue
        }
        if ($dry) { $results += [PSCustomObject]@{ name=$name; ok=$true; msg=('Would disable (now StartMode=' + $svc.StartMode + ', State=' + $svc.State + ')') }; continue }
        Add-Content -LiteralPath $log -Value ($name + [char]9 + $svc.StartMode + [char]9 + $svc.PathName)
        Set-Service -Name $name -StartupType Disabled -ErrorAction Stop
        try { Stop-Service -Name $name -Force -ErrorAction Stop } catch {}
        $results += [PSCustomObject]@{ name=$name; ok=$true; msg='Disabled + stopped (prior config backed up)' }
      } catch { $results += [PSCustomObject]@{ name=$name; ok=$false; msg="$($_.Exception.Message)" } }
    }
    [PSCustomObject]@{ backup=$log; dryRun=$dry; results=$results } | ConvertTo-Json -Depth 4
  `;
}

// Uninstall selected programs via their registered uninstaller. Refuses Microsoft-published items.
function psUninstallPrograms(jsonPath, dryRun) {
  return `
    $ErrorActionPreference = 'Stop'
    $items = Get-Content -Raw -LiteralPath '${jsonPath}' | ConvertFrom-Json
    $dry = ${dryRun ? '$true' : '$false'}
    $hives = @('HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*','HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*','HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*')
    $results = @()
    foreach ($it in $items) {
      $name = "$($it.name)"
      try {
        $app = Get-ItemProperty $hives -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -eq $name } | Select-Object -First 1
        if (-not $app) { $results += [PSCustomObject]@{ name=$name; ok=$false; msg='Not found in uninstall registry' }; continue }
        $pub = "$($app.Publisher)"
        if ($pub -match 'Microsoft|Windows Defender') { $results += [PSCustomObject]@{ name=$name; ok=$false; msg=('REFUSED: Microsoft-published (' + $pub + ')') }; continue }
        $cmd = $app.QuietUninstallString; if (-not $cmd) { $cmd = $app.UninstallString }
        if (-not $cmd) { $results += [PSCustomObject]@{ name=$name; ok=$false; msg='No uninstall string registered' }; continue }
        if ($dry) { $results += [PSCustomObject]@{ name=$name; ok=$true; msg=('Would run: ' + $cmd) }; continue }
        Start-Process -FilePath 'cmd.exe' -ArgumentList '/c', $cmd
        $results += [PSCustomObject]@{ name=$name; ok=$true; msg='Launched uninstaller (its own window may appear)' }
      } catch { $results += [PSCustomObject]@{ name=$name; ok=$false; msg="$($_.Exception.Message)" } }
    }
    [PSCustomObject]@{ dryRun=$dry; results=$results } | ConvertTo-Json -Depth 4
  `;
}

function psKill(pid) {
  return `
    $id = ${pid}
    $isAdmin = (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $name = (Get-Process -Id $id -ErrorAction SilentlyContinue).ProcessName
    try {
      Stop-Process -Id $id -Force -ErrorAction Stop
      [PSCustomObject]@{ Killed = $true; Id = $id; Name = $name; Admin = $isAdmin } | ConvertTo-Json
    } catch {
      $msg = "$($_.Exception.Message)"
      # Fallback: taskkill (also kills child tree); same privilege rules apply
      $tk = (taskkill /PID $id /F /T 2>&1) -join ' '
      if ($LASTEXITCODE -eq 0) {
        [PSCustomObject]@{ Killed = $true; Id = $id; Name = $name; Admin = $isAdmin; Via = 'taskkill' } | ConvertTo-Json
      } else {
        $denied = ($msg -match 'denied' -or $tk -match 'denied|Access is denied')
        [PSCustomObject]@{ Killed = $false; Id = $id; Name = $name; Admin = $isAdmin; Denied = $denied; Error = $msg; Taskkill = $tk } | ConvertTo-Json
      }
    }
  `;
}

// --- Endpoint table ----------------------------------------------------------
// --- Firewall rule threat scoring (trust 0-100, higher = safer) --------------
const SENSITIVE_PORTS = { 3389:'RDP', 445:'SMB', 139:'NetBIOS', 135:'RPC', 22:'SSH', 23:'Telnet', 5900:'VNC', 5985:'WinRM', 5986:'WinRM', 1433:'MSSQL', 3306:'MySQL', 21:'FTP' };
const PROTO = { '6':'TCP', '17':'UDP', '1':'ICMP', '58':'ICMPv6' };
function scoreFirewallRule(rule) {
  const dir = rule.Dir, action = String(rule.Action || '').toLowerCase(), active = String(rule.Active || '').toUpperCase() === 'TRUE';
  const app = rule.App || '', appL = app.toLowerCase();
  const port = rule.LPort || '', profile = rule.Profile || 'All';
  const reasons = [];
  const inboundAllow = dir === 'In' && action === 'allow' && active;
  if (!inboundAllow) {
    if (action === 'block') return { ...rule, threat: { level: 'SAFE', color: '#3ddc84', score: 100, reasons: ['Block rule — denies traffic'], inboundAllow: false } };
    if (!active)            return { ...rule, threat: { level: 'OFF',  color: '#5a6b7a', score: null, reasons: ['Rule disabled'], inboundAllow: false } };
    return { ...rule, threat: { level: 'INFO', color: '#5a6b7a', score: null, reasons: [dir === 'Out' ? 'Outbound allow rule' : 'Informational'], inboundAllow: false } };
  }
  let trust = 70;
  if (!app || /^any$/i.test(app)) { trust -= 30; reasons.push('Allows ANY program (broad)'); }
  else if (/\\(temp|downloads|\$recycle)\\/i.test(appL)) { trust -= 40; reasons.push('Program in suspicious location (Temp/Downloads/Recycle)'); }
  else if (/\\program files|\\windows\\/i.test(appL)) { trust += 15; reasons.push('Program in standard location'); }
  else if (app) { reasons.push('Program: ' + app.split('\\').pop()); }
  const sp = SENSITIVE_PORTS[parseInt(port, 10)];
  if (sp) { trust -= 22; reasons.push('Exposes sensitive port ' + port + ' (' + sp + ')'); }
  if (!port || /any/i.test(port)) { trust -= 12; reasons.push('Any local port'); }
  if (/public/i.test(profile)) { trust -= 15; reasons.push('Active on PUBLIC networks'); }
  if (rule.RA4 && !/any/i.test(rule.RA4)) { trust += 12; reasons.push('Restricted to specific remote address'); }
  trust = Math.max(0, Math.min(100, trust));
  let level, color;
  if (trust >= 75)      { level = 'SAFE';     color = '#3ddc84'; }
  else if (trust >= 60) { level = 'LOW';      color = '#9ad94f'; }
  else if (trust >= 40) { level = 'MODERATE'; color = '#ffc107'; }
  else if (trust >= 20) { level = 'ELEVATED'; color = '#ff8c3a'; }
  else                  { level = 'HIGH';     color = '#ff5252'; }
  return { ...rule, Proto: PROTO[rule.Protocol] || rule.Protocol || '', threat: { level, color, score: trust, reasons, inboundAllow: true } };
}

async function getFirewall() {
  const r = await runPowerShell(PS.firewall);
  if (!r.ok) return r;
  const d = (r.data && r.data[0]) || { profiles: [], rules: [] };
  const profiles = d.profiles || [];
  const rules = (d.rules || []).map(scoreFirewallRule);
  return { ok: true, data: [{ profiles, rules }], error: null };
}

// Connections enriched with reverse-DNS + heuristic threat score per external row
async function getConnections() {
  const res = await runPowerShell(PS.connections);
  if (!res.ok) return res;
  const conns = res.data || [];
  const extIps = [...new Set(conns.filter((c) => isExternalIp(c.RemoteAddress)).map((c) => c.RemoteAddress))];
  const rmap = {};
  await Promise.all(extIps.map((ip) => reverseDns(ip).then((h) => { rmap[ip] = h; })));
  for (const c of conns) {
    if (isExternalIp(c.RemoteAddress)) {
      c.threat = scoreConnection(c, rmap[c.RemoteAddress]);
    } else {
      c.threat = { level: 'LOCAL', color: '#5a6b7a', score: 99, reasons: ['Private / loopback address'], rdns: null };
    }
  }
  return { ok: true, data: conns, error: null };
}

// --- Connection Watchdog API ---------------------------------------------------
// Returns current watch mode and any pending alerts
async function getGuardStatus() {
  loadGuardState();
  const now = Date.now();
  const pending = guardState.rules
    .filter(r => r.direction === 'in' && r.process === '' && (!r.expiresAt || r.expiresAt > now))
    .map(r => ({
      conversationId: r.conversationId,
      pid: r.pid,
      remote: r.remote,
      remotePort: r.remotePort,
      localAddress: r.localAddress,
      localPort: r.localPort,
      process: r.process,
      createdAt: r.createdAt
    }));
  return { ok: true, data: { mode: guardMode, pending, pendingCount: pending.length }, error: null };
}

// Save a user decision on a pending inbound connection
async function resolvePending(r) {
  const action = r && r.action;  // 'allow_once', 'allow_forever', 'block_forever', 'investigate'
  const conv = r && r.conversationId;
  if (!r || !action || !conv) {
    return { ok: false, error: 'Invalid request', data: [] };
  }
  const ruleIndex = guardState.rules.findIndex(x => x.conversationId === conv);
  if (ruleIndex < 0) return { ok: false, error: 'Conversation not found', data: [] };

  const rule = guardState.rules[ruleIndex];

  if (action === 'allow_forever') {
    rule.action = 'allow';
    rule.expiresAt = null;
    rule.process = 'resolved';
  } else if (action === 'allow_once') {
    rule.action = 'allow';
    rule.expiresAt = Date.now() + 60000; // 1 min
    rule.process = 'resolved';
  } else if (action === 'block_forever') {
    rule.action = 'block';
    rule.expiresAt = null;
    rule.process = 'resolved';
  } else if (action === 'investigate') {
    // Mark as needing investigation - user will manually investigate
    rule.action = 'investigate';
    rule.expiresAt = null;
    rule.process = 'needs-investigation';
  }

  saveGuardState();
  log('INFO', `Guard resolved: ${action} for ${rule.remote}:${rule.remotePort} via PID ${rule.pid}`);
  return { ok: true, data: { action }, error: null };
}

// --- In-Bounds Connection Watchdog (Little Snitch-style) ----------------------
// Polls for new inbound connections and triggers alerts based on mode
let watcherRunning = false;
let lastInboundCheck = 0;

async function checkInboundConnections() {
  if (guardMode === 'off') return;

  const res = await runPowerShell(PS_INBOUND);
  if (!res.ok) return;

  const now = Date.now();
  const connections = res.data || [];

  // Track inbound ports we've seen (to avoid re-alerting on same listening socket)
  const seenFile = path.join(DATA_DIR, 'guard-seen.json');
  let seenMap = {};
  try { const raw = fs.readFileSync(seenFile, 'utf8'); seenMap = JSON.parse(raw); } catch (e) {}

  for (const c of connections) {
    const key = c.Type + ':' + c.LocalAddress + ':' + c.LocalPort;
    if (seenMap[key]) continue;
    seenMap[key] = now;
  }

  // Save updated seen map (clean up old entries periodically)
  if (now - lastInboundCheck > 300000) { // every 5 min
    const cutoff = now - 3600000; // keep last hour
    for (const k of Object.keys(seenMap)) { if (seenMap[k] < cutoff) delete seenMap[k]; }
    lastInboundCheck = now;
    try { fs.writeFileSync(seenFile, JSON.stringify(seenMap), 'utf8'); } catch (e) {}
  }

  // For listening sockets, we need to check if they're actually being connected to
  // Get established connections to find recently accepted inbound
  const estRes = await runPowerShell(`
    Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
    Where-Object { $_.RemoteAddress -match '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' -and $_.RemoteAddress -notmatch '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.)' } |
    Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess |
    ConvertTo-Json -Depth 3
  `);

  if (estRes.ok) {
    const estConns = estRes.data || [];
    for (const ec of estConns) {
      // Check if we already have a rule for this connection (by remote+port combo)
      const existing = findExistingRule('in', '', ec.RemoteAddress, ec.RemotePort, ec.LocalPort);
      if (existing) continue;

      const convId = crypto.randomBytes(8).toString('hex');
      const pending = {
        conversationId: convId,
        pid: ec.PID,
        localAddress: ec.LocalAddress,
        localPort: ec.LocalPort,
        remote: ec.RemoteAddress,
        remotePort: ec.RemotePort,
        createdAt: now
      };

      // Add to rules for tracking (process is '' to indicate pending user decision)
      guardState.rules.push({ ...pending, direction: 'in', process: '', expiresAt: null });
      saveGuardState();

      if (guardMode === 'notify') {
        // Fire notification, don't block
        const notifyMsg = `Inbound connection from ${ec.RemoteAddress}:${ec.RemotePort} -> ${ec.LocalAddress}:${ec.LocalPort}`;
        log('INFO', `Inbound alert (notify): ${notifyMsg} (PID ${ec.PID})`);
        await runPowerShell(PS_SEND_TOAST('ARK Connection Alert', notifyMsg));
      } else if (guardMode === 'ask') {
        // User needs to decide via foreground dialog - just log for now, UI will poll
        const askMsg = `Inbound connection from ${ec.RemoteAddress}:${ec.RemotePort}`;
        log('INFO', `Inbound alert (ask): ${askMsg} -> ${ec.LocalAddress}:${ec.LocalPort} (PID ${ec.PID})`);
        // Signal to UI via a push or just let UI poll
      }
    }
  }
}

// Background watcher loop
function startWatcher() {
  if (watcherRunning) return;
  watcherRunning = true;
  log('INFO', 'Connection watchdog started (mode=' + guardMode + ')');
  setInterval(checkInboundConnections, GUARD_TICK_MS);
}

const handlers = {
  '/api/connections': () => getConnections(),
  '/api/listening':   () => runPowerShell(PS.listening),
  '/api/firewall':    () => getFirewall(),
  '/api/registry':    () => runPowerShell(PS.registry),
  '/api/startup':     () => runPowerShell(PS.startup),
  '/api/services':    () => runPowerShell(PS.services),
  '/api/programs':    () => runPowerShell(PS.programs),
  '/api/guard':       () => getGuardStatus(),
  '/api/guard/resolve': (req) => resolvePending(req),
};

// Are we elevated? (controls whether firewall/full registry will return data)
function checkAdmin() {
  return runPowerShell(`
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $admin = (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    [PSCustomObject]@{ Admin = $admin } | ConvertTo-Json
  `);
}

// --- UI loading with fallbacks ------------------------------------------------
// Order: a ui.html next to the binary (lets you hot-patch an installed copy),
// then the copy embedded in the executable, then a minimal built-in page so the
// server is never a blank screen.
const FALLBACK_UI = `<!doctype html><meta charset="utf-8"><title>ARK — recovery mode</title>
<style>body{background:#0e1116;color:#e6e6e6;font:15px/1.6 system-ui,sans-serif;margin:0;padding:40px}
h1{font-size:20px}code{background:#1b2029;padding:2px 6px;border-radius:4px}
a{color:#6ea8fe}.box{max-width:680px}.warn{border-left:3px solid #e5c07b;padding-left:14px}</style>
<div class="box"><h1>🛡️ ARK is running — but the dashboard file is missing</h1>
<p class="warn">The server started fine, but <code>ui.html</code> could not be found or read.
The API is still live, so ARK itself is healthy.</p>
<p>Reinstall ARK, or drop a copy of <code>ui.html</code> next to the executable and reload.</p>
<p>Confirm the server is alive: <a href="/api/health">/api/health</a></p>
<p class="warn">The data endpoints are not linkable here on purpose — they require this
run's security token, which is handed only to the real dashboard.</p></div>`;

let uiWarned = false;
function loadUi() {
  try {
    const p = path.join(APP_DIR, 'ui.html');
    if (fs.existsSync(p)) {
      const html = fs.readFileSync(p, 'utf8');
      if (html && html.length > 200) return { ok: true, html, source: 'disk:' + p };
    }
  } catch (e) { log('WARN', 'Could not read ui.html from disk: ' + e.message); }

  if (IS_SEA) {
    try {
      const html = sea.getAsset('ui.html', 'utf8');
      if (html && html.length > 200) return { ok: true, html, source: 'embedded' };
    } catch (e) { log('WARN', 'Could not read embedded ui.html: ' + e.message); }
  }

  if (!uiWarned) { uiWarned = true; log('ERROR', 'ui.html unavailable — serving recovery page'); }
  return { ok: false, html: FALLBACK_UI, source: 'fallback' };
}

// --- HTTP server -------------------------------------------------------------
let activePort = null;
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);
  const pathname = url.pathname;

  // --- Local-origin guard ----------------------------------------------------
  // Binding to 127.0.0.1 does NOT mean only you can reach this. Two real risks:
  //
  //  1. DNS rebinding — an attacker's domain re-resolves to 127.0.0.1, so the
  //     browser considers our pages same-origin and can read them. Rejecting
  //     unexpected Host headers defeats that.
  //  2. Cross-site request forgery — a cross-origin POST with no custom header
  //     is a CORS "simple request": the browser blocks the attacker from reading
  //     the reply, but the request still executes. Requiring a per-run token in
  //     a custom header forces a preflight no cross-origin page can satisfy.
  //
  // This matters more than usual here: ARK runs elevated and can kill processes,
  // disable services, and launch uninstallers.
  const deny = (why) => {
    log('WARN', `Blocked ${req.method} ${pathname} (${why}) host=${req.headers.host} origin=${req.headers.origin || '-'}`);
    res.writeHead(403, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: false, error: 'Forbidden: ' + why, data: [] }));
  };

  if (!LOCAL_HOST_RE.test(String(req.headers.host || ''))) return deny('unexpected Host header');
  const origin = req.headers.origin;
  if (origin) {
    let oh = null;
    try { oh = new URL(origin).host; } catch (e) {}
    if (!oh || !LOCAL_HOST_RE.test(oh)) return deny('cross-origin request');
  }

  // Every API route except /api/health needs the per-run token. Health stays open
  // so build smoke tests and "is it alive?" checks work without one.
  if (pathname.startsWith('/api/') && pathname !== '/api/health') {
    if (req.headers['x-ark-token'] !== TOKEN) return deny('missing or invalid ARK token');
  }

  // Static: serve the UI (with this run's token injected)
  if (pathname === '/' || pathname === '/index.html') {
    const ui = loadUi();
    const inject = `<script>window.__ARK_TOKEN__=${JSON.stringify(TOKEN)};</script>`;
    const html = ui.html.includes('</head>')
      ? ui.html.replace('</head>', inject + '</head>')
      : inject + ui.html;
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
    res.end(html);
    return;
  }

  // health / self-check
  if (pathname === '/api/health') {
    const ui = loadUi();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      ok: true,
      version: VERSION,
      port: activePort,
      packaged: IS_SEA,
      uiSource: ui.source,
      appDir: APP_DIR,
      logFile: LOG_FILE,
      uptimeSec: Math.round(process.uptime()),
      node: process.version
    }));
    return;
  }

  // nmap scan
  if (pathname === '/api/scan') {
    const target = url.searchParams.get('target') || '';
    const result = await runNmap(target);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(result));
    return;
  }

  // admin status
  if (pathname === '/api/admin') {
    const r = await checkAdmin();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: r.ok, admin: !!(r.data && r.data[0] && r.data[0].Admin) }));
    return;
  }

  // delete/quarantine selected startup items (POST with JSON body { items: [...] })
  if (pathname === '/api/startup/delete') {
    if (req.method !== 'POST') {
      res.writeHead(405, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: 'Use POST' }));
      return;
    }
    const body = await readJsonBody(req);
    const items = body && Array.isArray(body.items) ? body.items : null;
    if (!items || !items.length) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: 'No items provided', data: [] }));
      return;
    }
    try {
      const qdir = QUARANTINE_DIR;
      fs.mkdirSync(qdir, { recursive: true });
      const jsonPath = path.join(qdir, 'pending-delete.json');
      fs.writeFileSync(jsonPath, JSON.stringify(items), 'utf8');
      const r = await runPowerShell(psDeleteStartup(jsonPath));
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(r));
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: e.message, data: [] }));
    }
    return;
  }

  // disable selected services / uninstall selected programs (POST JSON { items, dryRun })
  if (pathname === '/api/services/disable' || pathname === '/api/programs/uninstall') {
    if (req.method !== 'POST') {
      res.writeHead(405, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: 'Use POST' }));
      return;
    }
    const body = await readJsonBody(req);
    const items = body && Array.isArray(body.items) ? body.items : null;
    if (!items || !items.length) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: 'No items provided', data: [] }));
      return;
    }
    try {
      const qdir = QUARANTINE_DIR;
      fs.mkdirSync(qdir, { recursive: true });
      const jsonPath = path.join(qdir, pathname === '/api/services/disable' ? 'pending-services.json' : 'pending-programs.json');
      fs.writeFileSync(jsonPath, JSON.stringify(items), 'utf8');
      const dry = !!(body && body.dryRun);
      const script = pathname === '/api/services/disable' ? psDisableServices(jsonPath, dry) : psUninstallPrograms(jsonPath, dry);
      const r = await runPowerShell(script);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(r));
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: e.message, data: [] }));
    }
    return;
  }

  // process details for a PID
  if (pathname === '/api/process') {
    const pid = parseInt(url.searchParams.get('pid'), 10);
    if (!Number.isInteger(pid) || pid <= 0) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: 'Invalid pid', data: [] }));
      return;
    }
    const r = await runPowerShell(psProcessDetails(pid));
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(r));
    return;
  }

  // kill a PID (POST only, to avoid accidental GET/prefetch)
  if (pathname === '/api/kill') {
    if (req.method !== 'POST') {
      res.writeHead(405, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: 'Use POST' }));
      return;
    }
    const pid = parseInt(url.searchParams.get('pid'), 10);
    if (!Number.isInteger(pid) || pid <= 0) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: 'Invalid pid', data: [] }));
      return;
    }
    const r = await runPowerShell(psKill(pid));
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(r));
    return;
  }

  // send toast notification (POST JSON { title, message })
  if (pathname === '/api/toast') {
    if (req.method !== 'POST') {
      res.writeHead(405, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: 'Use POST' }));
      return;
    }
    const body = await readJsonBody(req);
    if (!body || !body.title || !body.message) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: 'Missing title or message', data: [] }));
      return;
    }
    const r = await runPowerShell(PS_SEND_TOAST(body.title, body.message));
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: r.ok, data: r.data, error: r.error }));
    return;
  }

  // set guard mode (POST JSON { mode })
  if (pathname === '/api/guard/mode') {
    if (req.method !== 'POST') {
      res.writeHead(405, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: 'Use POST' }));
      return;
    }
    const body = await readJsonBody(req);
    const mode = (body && body.mode || 'notify').toLowerCase();
    if (!['off', 'notify', 'ask'].includes(mode)) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: 'Invalid mode. Use off, notify, or ask.', data: [] }));
      return;
    }
    guardMode = mode;  // Update the in-memory mode
    saveGuardState();  // Persist the mode change
    log('INFO', `Guard mode changed to: ${mode}`);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true, data: { mode }, error: null }));
    return;
  }

  // JSON endpoints
  if (handlers[pathname]) {
    try {
      const result = await handlers[pathname]();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(result));
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: e.message, data: [] }));
    }
    return;
  }

  res.writeHead(404);
  res.end('Not found');
});

// --- Listen, with automatic port fallback ------------------------------------
// EADDRINUSE means someone else got there first; on Windows an exclusive bind by
// another process surfaces as EACCES instead (this is how AnyDesk on 7070 used to
// break ARK). Both are recoverable: just try the next candidate.
function listenWithFallback(candidates, i = 0) {
  if (i >= candidates.length) {
    log('ERROR', 'No usable port found. Set one explicitly, e.g. set PORT=9099');
    process.exit(1);
  }
  const tryPort = candidates[i];

  const onFail = (e) => {
    server.removeListener('error', onFail);
    server.removeListener('listening', onListening);
    if (e.code === 'EADDRINUSE' || e.code === 'EACCES') {
      const who = e.code === 'EACCES' ? 'blocked or exclusively bound' : 'already in use';
      log('WARN', `Port ${tryPort} is ${who}; trying ${candidates[i + 1] === 0 ? 'an OS-assigned port' : candidates[i + 1]}`);
      setImmediate(() => listenWithFallback(candidates, i + 1));
      return;
    }
    log('ERROR', 'listen failed: ' + e.message);
    process.exit(1);
  };

  // Register the success handler explicitly rather than passing it to listen().
  // A callback passed to a listen() call that then fails is never unregistered,
  // so after a fallback every stale callback would also fire on the eventual
  // success — printing the startup banner once per failed attempt.
  const onListening = () => {
    server.removeListener('error', onFail);
    activePort = server.address().port;

    // Record the live port so launchers/shortcuts can open the right URL even
    // when we had to fall back off the preferred one.
    try { ensureDataDir(); fs.writeFileSync(PORT_FILE, String(activePort)); } catch (e) {}

    const url = 'http://localhost:' + activePort;
    console.log('');
    console.log('  ARK - Network Security Monitor  v' + VERSION + (IS_SEA ? '  (packaged)' : ''));
    console.log('  → Open  ' + url + '  in your browser');
    if (activePort !== PORT) console.log('  (port ' + PORT + ' was unavailable — fell back to ' + activePort + ')');
    console.log('  (Run as Administrator for firewall logs & full registry access)');
    console.log('  Log: ' + LOG_FILE);
    console.log('');
    log('INFO', 'Listening on ' + url + ' (requested ' + PORT + ')');

    // An installed copy is launched from a shortcut, so it opens its own browser
    // tab; running from source stays quiet unless asked. ARK_OPEN_BROWSER=0 opts out.
    const openBrowser = process.env.ARK_OPEN_BROWSER === '1' ||
                        (IS_SEA && process.env.ARK_OPEN_BROWSER !== '0');
    if (openBrowser) {
      try { spawn('cmd', ['/c', 'start', '', url], { detached: true, stdio: 'ignore', windowsHide: true }).unref(); }
      catch (e) { log('WARN', 'Could not open browser: ' + e.message); }
    }
  };

  server.once('error', onFail);
  server.once('listening', onListening);
  server.listen(tryPort, '127.0.0.1');
}

// If the listener ever dies underneath us, rebind rather than sitting there dead.
server.on('close', () => {
  // Only react to a listener that was actually up and has now genuinely gone
  // away — a failed bind attempt also emits 'close'.
  if (activePort !== null && !server.listening) {
    log('WARN', 'Listener closed unexpectedly; rebinding');
    activePort = null;
    setTimeout(() => listenWithFallback(PORT_CANDIDATES), 1000);
  }
});

// Start the connection watcher
startWatcher();

listenWithFallback(PORT_CANDIDATES);
