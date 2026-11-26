# Quick Reference - Registry & Security Threats

Keep this handy while investigating your system.

---

## 🔴 CRITICAL THREAT SIGNS

| Sign | What It Means | Risk Level |
|------|---------------|-----------|
| PowerShell/CMD in Registry | Direct script injection | 🔴 CRITICAL |
| EXE in Temp folder | Runtime malware installation | 🔴 CRITICAL |
| RUNDLL32 execution | Hidden DLL malware | 🔴 CRITICAL |
| No publisher listed | Unsigned/rogue software | 🔴 CRITICAL |
| Duplicate system process | Process impersonation | 🔴 CRITICAL |
| Unknown external IP connection | C2 communication | 🔴 CRITICAL |

---

## 🟡 MEDIUM THREAT SIGNS

| Sign | What It Means | Risk Level |
|------|---------------|-----------|
| VBS/JS script at startup | Script-based malware | 🟡 MEDIUM |
| AppData/Temp in path | Non-standard installation | 🟡 MEDIUM |
| Multiple listening ports | Suspicious services | 🟡 MEDIUM |
| Firewall blocks to same IP | Potential attack | 🟡 MEDIUM |

---

## ✅ SAFE STARTUP ITEMS

These are typically okay to see:

```
C:\Program Files\Adobe\Reader\Reader.exe
C:\Program Files\Mozilla Firefox\firefox.exe
C:\Program Files (x86)\Google\Chrome\chrome.exe
C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE
C:\Program Files\Windows Defender\MSASCuiL.exe
C:\Windows\System32\OneDriveSetup.exe
```

---

## 🔥 MALWARE SIGNATURES TO WATCH FOR

### Registry-based Malware

**PowerShell:**
```
powershell.exe -nop -w hidden -c "..."
powershell.exe -enc [base64 code]
```
**THREAT:** Script execution, command & control

**RUNDLL32:**
```
rundll32.exe C:\Temp\*.dll,Init
rundll32.exe shell32.dll,ShellExec_RunDLL
```
**THREAT:** DLL injection, hidden execution

**VBS/Scripting:**
```
cscript.exe C:\Users\...\AppData\*.vbs
wscript.exe "bad.vbs"
```
**THREAT:** Script malware, worm propagation

**Suspicious Paths:**
```
C:\Users\...\AppData\Local\Temp\*
C:\Users\...\AppData\Roaming\*\*.exe
C:\$Recycle.Bin\*
C:\ProgramData\*\*.exe (non-standard)
```
**THREAT:** Obfuscation, temporary malware

---

## 🔍 WHAT TO CHECK WHEN YOU FIND SOMETHING SUSPICIOUS

### 1. File Properties
```
Right-click file → Properties → Details
  ✓ Check: Publisher name
  ✓ Check: Product name
  ✓ Check: Original filename
  ✓ Check: File version
  ✓ Check: Company name
```

### 2. File Signature
```
Right-click file → Properties → Digital Signatures
  ✓ Is it signed?
  ✓ By whom?
  ✓ Is cert valid?
```

### 3. Online Scan
```
Upload to VirusTotal.com
  ✓ How many AV vendors flag it?
  ✓ What do they call it?
  ✓ Any details available?
```

### 4. Location Check
```
Is it in a standard location?
  ✓ C:\Program Files\ = Usually safe
  ✓ C:\Program Files (x86)\ = Usually safe
  ✓ C:\Windows\System32\ = Should be Microsoft
  ✓ %TEMP%, %APPDATA%, Downloads = Often dangerous
```

---

## 📊 NETWORK INVESTIGATION CHECKLIST

### Active Connections Tab
```
□ Are there external IP connections? (marked RED)
□ Do I recognize all process names?
□ Are there listening ports I don't expect?
□ Are there high-frequency rapid connections?
□ Are there connections to blacklisted IPs?
```

### Suspicious Patterns
```
□ Process connecting to multiple external IPs
□ Process with random/obfuscated name
□ Process from temp folder
□ Process from AppData
□ Process from Downloads
□ High memory/CPU usage
□ Multiple instances of same process
```

### Action Items
```
□ Note process name and PID
□ Find file location in Task Manager
□ Scan file on VirusTotal.com
□ Check registry for launch point
□ Check firewall for this process
□ Disable in startup if suspicious
```

---

## 🔐 REGISTRY PATHS TO MONITOR MOST

**Highest Priority (Check Weekly):**
1. `HKLM:\Software\Microsoft\Windows\CurrentVersion\Run`
2. `HKCU:\Software\Microsoft\Windows\CurrentVersion\Run`
3. `HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce`
4. `HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce`

**High Priority:**
5. `HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon` (Shell, Userinit)
6. Startup folders: `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`

**Medium Priority:**
7. Browser Helper Objects
8. Services registry
9. Scheduled Tasks

---

## 📋 CHECKLIST: IS IT MALWARE?

Answer honestly:

```
□ Did I install this? (No = SUSPICIOUS)
□ Do I recognize the name? (No = SUSPICIOUS)
□ Is there a known publisher? (No = DANGEROUS)
□ Is it in Program Files? (No = SUSPICIOUS)
□ Is it from a trusted source? (No = SUSPICIOUS)
□ Can I find it online? (No = SUSPICIOUS)
□ Is it legitimately needed? (No = DANGEROUS)
```

**Score:**
- 0-2 suspicious signs → Probably safe
- 3-5 suspicious signs → Investigate further
- 6+ suspicious signs → **REMOVE IT**

---

## 🚨 EMERGENCY ACTIONS

**Immediate Actions:**
1. ✅ Unplug network cable (or disable WiFi)
2. ✅ Open Task Manager (Ctrl+Shift+Esc)
3. ✅ End suspicious processes (right-click → End Task)
4. ✅ Note the file location before ending
5. ✅ Run Windows Defender full scan
6. ✅ Remove from registry/startup

**Follow-up Actions:**
1. ✅ Change all passwords (from different device)
2. ✅ Check credit cards (from different device)
3. ✅ Enable Windows Defender
4. ✅ Run full Windows Update
5. ✅ Restore from backup if available
6. ✅ Consider professional help if uncertain

---

## 🛡️ PREVENTION CHECKLIST

```
□ Windows Defender enabled (real-time protection)
□ Windows Updates automatic
□ Browser extensions reviewed and minimal
□ Plugins (Flash, Java) updated or uninstalled
□ Regular backups of important files
□ Strong, unique passwords
□ Two-factor authentication where available
□ No programs from unknown publishers
□ Startup folder regularly reviewed
□ Scheduled registry scans (weekly)
```

---

## 💾 BACKUP YOUR REGISTRY

Before removing anything, backup:

```powershell
# Open Registry Editor
regedit

# File → Export
# Choose location
# Save as .reg file
```

**Then if something breaks:**
```powershell
# Double-click the .reg file to restore
```

---

## 📞 WHEN TO GET HELP

**Contact a professional if:**
- ❌ You're not sure what something is
- ❌ You're suspicious of active compromise
- ❌ You see file encryption/ransom messages
- ❌ Your computer is behaving very abnormally
- ❌ You discovered financial malware
- ❌ You removed something and now something broke

**Don't:**
- ❌ Don't browse the internet if compromised (use different device)
- ❌ Don't enter passwords if you suspect keylogger
- ❌ Don't delay if you suspect ransomware
- ❌ Don't post screenshots with sensitive info

---

## 🔗 USEFUL LINKS

- **File Scanner:** https://www.virustotal.com/
- **IP Lookup:** https://www.abuseipdb.com/
- **Registry Editor Docs:** https://docs.microsoft.com/windows/win32/sysinfo/registry
- **Windows Security:** https://support.microsoft.com/windows/security
- **Process Lookup:** https://www.bleepingcomputer.com/startups/
- **Autorun Analysis:** https://docs.microsoft.com/sysinternals/downloads/autoruns

---

## 📝 INVESTIGATION LOG TEMPLATE

```
Date: [___________]
Time: [___________]

FINDING:
Name: [___________]
Path: [___________]
Registry Location: [___________]
File Size: [___________]
Created: [___________]
Modified: [___________]

ANALYSIS:
Publisher: [___________]
Signed: Yes / No
VirusTotal Results: [___________]
Status: Safe / Unknown / Suspicious / Malware

ACTION TAKEN:
□ Left alone
□ Disabled
□ Removed
□ Quarantined
□ Reported

NOTES:
[___________]
```

---

**Last Updated:** 2026-06-03  
**Version:** 1.0
