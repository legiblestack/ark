# Registry Monitoring Guide

Complete guide to the enhanced registry monitoring features in Network Security Monitor.

## What Gets Scanned

### 1. Startup Registry Paths
The following registry locations are monitored for unauthorized startup programs:

| Path | Purpose |
|------|---------|
| `HKLM:\Software\Microsoft\Windows\CurrentVersion\Run` | Machine-level startup programs |
| `HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce` | One-time machine startup |
| `HKCU:\Software\Microsoft\Windows\CurrentVersion\Run` | User-level startup programs |
| `HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce` | One-time user startup |
| `HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon` | Windows logon settings (Shell, Userinit) |
| `HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon` | User logon settings |
| `HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders` | Shell folder locations |
| `HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders` | User shell folders |
| `HKLM:\System\CurrentControlSet\Control\Session Manager\Environment` | System environment variables |
| `HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects` | Browser extensions |
| `HKLM:\System\CurrentControlSet\Services` | Windows services and drivers |

### 2. File System Locations
Monitored startup directories:

| Location | Purpose |
|----------|---------|
| `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` | User startup folder |
| `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup` | System startup folder |
| `%TEMP%` | Temporary files directory |
| `%APPDATA%` | User app data |
| `%LOCALAPPDATA%` | Local app data |

### 3. Installed Programs Registry
Scans both user and machine registry for all installed programs.

### 4. Registry Audit Log
Displays Windows security audit events for registry modifications.

---

## Registry Tab Sections

### 📋 Startup Entries
Shows all discovered registry entries in startup locations.

**What to look for:**
- Programs you don't recognize
- Unusual executable paths
- File paths containing TEMP, AppData, or Downloads
- PowerShell, CMD, or script commands

**Normal examples:**
```
C:\Program Files\Adobe\Reader\Reader.exe
C:\Program Files\Mozilla Firefox\firefox.exe
```

**Suspicious examples:**
```
powershell.exe -nop -w hidden -c "[code here]"
C:\Users\...\AppData\Local\Temp\random.exe
cmd.exe /c del ...
```

---

### ⚠️ Suspicious Items
Automatically flagged items based on pattern matching.

**High Risk Patterns (RED):**
- PowerShell commands
- CMD.exe execution
- RUNDLL32 (often used for DLL execution)
- VBS/JavaScript files
- .SCR files (screensaver - often disguised malware)
- Registry services (REGSVCS)
- Paths containing `temp`, `appdata`, `localappdata`

**Medium Risk Patterns (YELLOW):**
- Unknown file extensions
- Unfamiliar executable names
- Paths with special characters

**Severity Calculation:**
- 🔴 **HIGH RISK** - Direct command execution or suspicious patterns
- 🟡 **MEDIUM RISK** - Paths in temporary locations or publishers missing

---

### 📁 File Locations
Shows files in startup directories on disk.

**Check for:**
- Executable files (.exe, .bat, .vbs, .js)
- Files with random/obfuscated names
- Recent creation dates (may indicate recent malware installation)
- Files from unknown publishers

**Safe startup items:**
- Windows system files
- Known software (Adobe, Chrome, etc.)
- Organization-approved tools

---

### 📦 Installed Programs
Complete registry of all installed software.

**Suspicious indicators:**
- 🔴 **NO PUBLISHER** - Most legitimate software lists a publisher
- Programs with random names (TEMP, CACHE, RAND, etc.)
- Very recent installation dates (May indicate malware)
- Install location in `AppData` or `Temp` (very unusual)
- Multiple versions of the same program

**What to verify:**
1. Click on program name to search Google
2. Check if you remember installing it
3. Verify publisher is legitimate
4. Check install date matches when you installed it

**Common false positives (safe):**
- Visual Studio components
- Windows updates
- Development tools
- Drivers and firmware updates

---

### 📋 Audit Log
Registry modification events from Windows security logs.

**Requires:** Administrator privileges and security auditing enabled

**Event Types:**
- 4657: Registry value modified
- Registry key created/deleted
- Permission changes

**What to look for:**
- Run/RunOnce modifications
- Winlogon changes
- Services registry modifications
- Recent timestamps (ongoing compromise)

---

## Common Malware Patterns

### PowerShell Startup
```registry
HKLM:\Software\Microsoft\Windows\CurrentVersion\Run
  "MalwareName" = "powershell.exe -NoProfile -WindowStyle Hidden -Command ..."
```
**Risk: CRITICAL** - Direct script execution at startup

### CMD Startup
```registry
HKLM:\Software\Microsoft\Windows\CurrentVersion\Run
  "BadThing" = "cmd.exe /c del C:\..."
```
**Risk: CRITICAL** - Command execution at startup

### DLL Injection via RUNDLL32
```registry
HKCU:\Software\Microsoft\Windows\CurrentVersion\Run
  "System Update" = "rundll32.exe C:\Temp\bad.dll,Init"
```
**Risk: CRITICAL** - DLL execution masquerading as update

### VBS Script
```registry
HKLM:\Software\Microsoft\Windows\CurrentVersion\Run
  "Update" = "cscript.exe C:\Users\...\AppData\Local\Temp\script.vbs"
```
**Risk: CRITICAL** - Script-based malware

### Screensaver Substitution
```registry
HKCU:\Control Panel\Desktop
  "SCRNSAVE.EXE" = "C:\Users\...\AppData\Roaming\malware.scr"
```
**Risk: CRITICAL** - Masquerading as screensaver

### Winlogon Shell Replacement
```registry
HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon
  "Shell" = "explorer.exe C:\Temp\malware.exe"
```
**Risk: CRITICAL** - Replaces Windows shell

---

## What's NOT Suspicious

These are typically safe:

✅ **Microsoft signed executables**
- `C:\Windows\System32\*.exe`
- `C:\Program Files\Windows Defender\...`

✅ **Known software publishers**
- Adobe, Google, Mozilla, Microsoft, etc.
- Major antivirus vendors

✅ **System utilities**
- `svchost.exe` (Windows services)
- `rundll32.exe` (alone, without DLL execution)
- `wmic.exe` (management tool)

✅ **Development tools**
- `node.exe`, `python.exe`, `git.exe`
- IDE tools and build systems

---

## Investigation Workflow

### When You Find Something Suspicious

**Step 1: Note the Details**
- Program name
- File path
- Full command line
- Registry location

**Step 2: Search Online**
- Google: `"[program name]" malware`
- Check VirusTotal: https://www.virustotal.com/
- Check Windows security database

**Step 3: Verify Installation**
- Do you remember installing it?
- When was it installed? (Check Install Date)
- What's the publisher?

**Step 4: Check File Properties**
- Right-click file → Properties
- Check "Digital Signatures" tab
- Is it signed by a trusted company?

**Step 5: Check Running Processes**
- Open Task Manager
- Find process by name
- Right-click → Open file location
- Verify it matches expected path

**Step 6: Action**
- ✅ **Safe:** Leave it alone
- ❓ **Unknown:** Search more, disable and monitor
- 🔴 **Malicious:** Remove (See Removal Steps below)

---

## Removal Steps

### For Registry Entries (SAFE)

⚠️ **Backup first!**

1. Press `Win + R`, type `regedit`, press Enter
2. Navigate to suspicious registry path
3. Right-click the entry → Delete
4. Confirm deletion
5. Restart computer

### For Installed Programs

1. Control Panel → Programs → Programs and Features
2. Find the program → Uninstall
3. Follow prompts
4. Restart computer

### For Startup Files (SAFE)

1. Press `Win + R`, type `shell:startup`
2. Delete suspicious files
3. Empty Recycle Bin
4. Restart computer

### For Services (CAUTION)

⚠️ **Only remove if certain it's malware**

1. Press `Win + R`, type `services.msc`
2. Find service in list
3. Right-click → Properties
4. Set Startup Type → Disabled
5. Click Stop, OK
6. Restart computer

---

## False Positives

These may appear suspicious but are typically safe:

| Item | Why It Appears Suspicious | Actually Safe? |
|------|---------------------------|----------------|
| PowerShell in Task Scheduler | PowerShell script | ✅ Usually safe |
| System Restore entries | System recovery | ✅ Safe (Windows) |
| VBScript for system tasks | VBS is used for automation | ✅ Usually safe |
| Paths in AppData | Some programs install there | ⚠️ Check publisher |
| Batch files in Startup | Legitimate automation scripts | ⚠️ Check source |

**Always verify** before removing anything system-related!

---

## Comparison: Before and After

### Before Infection
```
HKLM:\Software\Microsoft\Windows\CurrentVersion\Run
  "SecurityEssentials" = "C:\Program Files\Windows Defender\MSASCuiL.exe"
  "Adobe Reader Speed Launcher" = "C:\Program Files\Adobe\Reader\Reader_SL.exe"
```

### After Infection (Suspicious)
```
HKLM:\Software\Microsoft\Windows\CurrentVersion\Run
  "SecurityEssentials" = "C:\Program Files\Windows Defender\MSASCuiL.exe"
  "Adobe Reader Speed Launcher" = "C:\Program Files\Adobe\Reader\Reader_SL.exe"
  "Windows Security Update" = "powershell.exe -nop -w hidden -command [obfuscated code]"
  "System Service" = "C:\Users\...\AppData\Local\Temp\svc.exe"
```

The two new entries are suspicious!

---

## Registry Protection Tips

### Monitor Regularly
- Scan at least weekly
- More frequently if you suspect compromise
- Keep notes of changes

### Disable Unnecessary Startups
- More startup items = more attack surface
- Disable items you don't recognize
- Use System Configuration (`msconfig`) for easier management

### Enable Audit Logging
Run in PowerShell as Administrator:
```powershell
auditpol /set /subcategory:"Registry" /success:enable /failure:enable
```

### Use Windows Defender
- Enable Real-time protection
- Enable Cloud protection
- Keeps malware definitions updated

### Keep Updates Current
- Windows Updates
- Software updates
- Browser extensions
- Antivirus definitions

---

## Advanced: Manual Registry Inspection

### View All Run Keys
```powershell
# Machine startup
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" | Select-Object * -ExcludeProperty PS* | Format-Table

# User startup
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" | Select-Object * -ExcludeProperty PS* | Format-Table
```

### Find Suspicious Executables
```powershell
# Find EXE files in temp/appdata
Get-ChildItem $env:TEMP -Filter "*.exe" -Recurse
Get-ChildItem $env:APPDATA -Filter "*.exe" -Recurse
Get-ChildItem $env:LOCALAPPDATA -Filter "*.exe" -Recurse
```

### Check File Properties
```powershell
# Get file details
(Get-Item "C:\path\to\file.exe").VersionInfo | Select-Object ProductName, CompanyName, FileVersion
```

### Get File Hash
```powershell
# Get SHA256 hash for malware scanning
(Get-FileHash "C:\path\to\file.exe").Hash
```

---

## Emergency Response

**If you suspect active infection:**

1. ✅ **Disconnect from network** (unplug ethernet or disable WiFi)
2. ✅ **Boot into Safe Mode with Networking**
   - Restart, press F8 before Windows boots
   - Or Shift+Restart → Troubleshoot → Advanced Options
3. ✅ **Run antivirus scan**
   - Windows Defender offline scan
   - Or run Malwarebytes
4. ✅ **Check this tool's findings**
   - Remove flagged startup entries
   - Note suspicious processes
5. ✅ **Restore from backup** if available
6. ✅ **Change all passwords** on a different computer
7. ✅ **Monitor credit reports** if financial malware

---

## Questions to Ask Yourself

When you find a suspicious entry:

- ❓ Did I install this program?
- ❓ Do I recognize this name?
- ❓ Is the path in a standard location?
- ❓ Is there a known publisher?
- ❓ When was it installed?
- ❓ What does it do? (Search online)
- ❓ Is it signed by Microsoft or a major company?
- ❓ Would I expect this to start automatically?

**If you answer "NO" to most questions, it's likely suspicious.**

---

## Additional Resources

- **Windows Registry Documentation:** https://docs.microsoft.com/en-us/windows/win32/sysinfo/registry
- **Autoruns Tool (Microsoft):** https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns
- **Malware hunting:** https://www.virustotal.com/
- **Threat intelligence:** https://www.abuseipdb.com/

---

**Remember:** When in doubt, backup and remove. You can always reinstall legitimate software. Malware likes to hide in obscure registry locations.
