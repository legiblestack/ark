# ARK — Network Security Monitor

A lightweight, **zero-dependency** local security monitor for Windows. It runs a small Node
server that wraps Windows' own tools (PowerShell, nmap) and serves a single-page dashboard
in your browser. No Electron, no `npm install`, no build step.

## Install it

Build the standalone executable, then run the installer:

```powershell
powershell -ExecutionPolicy Bypass -File build-exe.ps1
```

That produces **`dist\ARK.exe`** — a single ~88 MB file with `ui.html` embedded and
the Node runtime bundled in. **Target machines do not need Node installed.**
Then double-click **`dist\INSTALL.bat`**.

The installer places ARK in `%LOCALAPPDATA%\Programs\ARK`, creates Start Menu and
Desktop shortcuts flagged **run as Administrator**, and registers an entry in
Apps & Features. Installing needs no elevation; only running does.

Uninstall from **Apps & Features → ARK**, or:

```powershell
powershell -ExecutionPolicy Bypass -File install.ps1 -Uninstall
```

Logs and quarantine backups in `%LOCALAPPDATA%\ARK` are deliberately kept on
uninstall — delete that folder by hand if you want them gone.

## Or run it from source

Double-click **`RUN-ADMIN.bat`** (auto-elevates to Administrator, starts the server, opens the browser).

Or from a terminal:

```powershell
node server.js        # or: npm start
```

Then open **http://localhost:8088**.

## Resilience

ARK is meant to keep running unattended, so it recovers from the failures that
actually happen rather than exiting:

| Failure | What ARK does |
|---------|---------------|
| **Preferred port taken** | Falls back through 8088 → 8090 → 8188 → 9088 → 18088 → any free port. On Windows an exclusive bind by another app (AnyDesk holds 7070, for instance) surfaces as `EACCES` rather than "in use"; both are handled. The live port is written to `%LOCALAPPDATA%\ARK\ark.port`. |
| **Worker process crashes** | A supervisor parent restarts it with backoff, up to 10 times, then stops and says so in the log. Pass `--no-supervise` to disable. |
| **A PowerShell query hangs** | Killed after 45s (`ARK_PS_TIMEOUT` to change) and reported in that panel instead of hanging the dashboard. |
| **An endpoint fails** | The panel shows the error and a Retry button rather than going blank. Requests time out and retry once automatically. |
| **`ui.html` missing or unreadable** | Falls back to the copy embedded in the executable, then to a built-in recovery page that still links the raw API. |
| **Unexpected exception** | Logged to `%LOCALAPPDATA%\ARK\ark.log` (rotated at 2 MB); the server keeps serving. |

`GET /api/health` reports version, live port, whether it's the packaged build,
where the UI came from, and uptime — the fastest way to tell what a given
instance is actually doing.

> Run as **Administrator** for Firewall Logs, full registry/service visibility, and the ability
> to kill processes owned by other accounts. `RUN-ADMIN.bat` does this for you.

## Features

| Tab | What it shows |
|-----|---------------|
| **Active Connections** | Live established TCP connections with process name, PID, memory, and **external IPs flagged in red**. Each row has **Investigate** (path + publisher + Authenticode signature) and **Kill**. |
| **Ports & Scanner** | All local listening ports with the owning process, plus an on-demand **nmap** scan of any target. |
| **Firewall Logs** | Recent Windows Filtering Platform allow/block events (requires Administrator). |
| **Registry & Startup** | Three sub-tabs: **Startup Items** (Run/RunOnce + Winlogon + startup folders), **Auto-Start Services** (third-party, outside `C:\WINDOWS`), and **Installed Programs** (flags missing publishers). Suspicious patterns are highlighted. |

## Requirements

- **Node.js 16+** — https://nodejs.org/
- **nmap** (optional, only for the scanner) — https://nmap.org/download.html
- Windows 10/11

## Files

```
ARK\
├── server.js        Zero-dependency Node HTTP server (runs PowerShell/nmap, serves JSON + UI)
├── ui.html          The entire dashboard (one file)
├── RUN-ADMIN.bat    One-click elevated launcher (source mode)
├── build-exe.ps1    Builds dist\ARK.exe via Node SEA; validates + smoke-tests before shipping
├── sea-config.json  SEA manifest (embeds ui.html as an asset)
├── install.ps1      Installer / uninstaller (-Uninstall)
├── INSTALL.bat      Double-click wrapper for install.ps1
├── package.json
├── REGISTRY-MONITORING.md   Reference: registry locations, malware patterns, removal steps
└── QUICK-REFERENCE.md       Reference: threat signatures + investigation checklist

%LOCALAPPDATA%\ARK\          Writable state (survives upgrades)
├── ark.log          Rotating log
├── ark.port         Port the running instance actually bound
└── quarantine\      Backups of anything ARK removes
```

> `build-exe.ps1` refuses to ship a build whose `ui.html` has a JavaScript syntax
> error. That failure mode is invisible at runtime — the page loads, the server
> answers, and the dashboard just renders nothing — so it is checked at build time.

## Investigation notes

- "External" just means the connection left your machine — browsers and apps do this constantly
  over HTTPS (port 443). The useful signal is an *unexpected* process connecting out, or an
  unsigned binary running from `Temp`/`AppData`.
- ARK surfaces autostart entries and signatures; it does **not** by itself prove tampering. If
  something looks off, take the file's path/hash to https://www.virustotal.com/ before removing it.
- The port is configurable: `set PORT=9099 && node server.js`.
