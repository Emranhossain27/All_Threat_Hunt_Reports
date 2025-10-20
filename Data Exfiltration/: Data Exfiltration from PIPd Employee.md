
# 🕵️‍♂️ Data Exfiltration from PIP’d Employee

**Date:** October 20, 2025  
**Investigator:** Emran Hossain  
**Tool Used:** Microsoft Defender for Endpoint (MDE)  
**Device Investigated:** `windows-10-emra`  
**Employee:** John Doe (Administrator)  
**Department:** Sensitive Business Unit

---

## 🧩 Incident Overview
An employee named **John Doe**, recently placed on a **Performance Improvement Plan (PIP)**, was suspected of planning to **steal proprietary company data**. Management raised concerns after behavioral changes were observed.

Since John has **administrator privileges** and unrestricted application usage, the investigation focused on identifying potential **data exfiltration activities** — including file compression, script execution, and outbound data transfers.

---

## 🔍 Investigation Objective
To determine whether John Doe attempted or succeeded in **exfiltrating company data** from his corporate workstation using compression tools, PowerShell scripts, or external connections.

---

## ⚙️ Evidence Collected

### 1️⃣ Suspicious Script Execution
At **2025-10-20T16:42:08.7734266Z**, a PowerShell script named

```
C:\programdata\exfiltratedata.ps1
```

was executed using **ExecutionPolicy Bypass**.

**Command Line Observed**

```
powershell.exe -ExecutionPolicy Bypass -File C:\programdata\exfiltratedata.ps1
```

This indicates an attempt to run a **potentially malicious or exfiltration-related script**.

---

### 2️⃣ File Compression Tool Usage
KQL used:

```kql
let File = dynamic(["7z.exe", "winar.exe","powershell.exe","winzip.exe","Bandizip.exe",
"UniExtract.exe", "POWERARC.EXE", "IZArc.exe", "AshampooZIP.exe"]);
DeviceProcessEvents
| where DeviceName == "windows-10-emra"
| where Timestamp > ago(30m)
| where FileName has_any (File)
| order by Timestamp desc
```

**Findings:**  
- `7z.exe` was observed, confirming that a **7-Zip archive** was created or extracted.  
- This correlates with the PowerShell execution and may indicate automation of packaging sensitive data.

<img width="1296" height="471" alt="image" src="https://github.com/user-attachments/assets/5c7b24f9-4806-44a6-912a-d17678a993e0" />

---

### 3️⃣ File Creation and Deletion Patterns
KQL used:

```kql
DeviceFileEvents
| where DeviceName == "windows-10-emra"
| where Timestamp > ago(30m)
| project Timestamp,DeviceName, ActionType,FileName, InitiatingProcessCommandLine,FolderPath
| order by Timestamp desc
```

**Observations:**  
- Multiple file create/delete events recorded.  
- On **October 20, 2025**, files were created and removed by `cleanmgr.exe (Disk Cleanup)` and `svchost.exe (wsappx)` under the Temp directory.  
- Temporary `.dll` and `.mui` files tied to DISM and cleanup utilities were seen—some events could be benign system cleanup, others might be used to cover traces.

<img width="1272" height="397" alt="image" src="https://github.com/user-attachments/assets/837c7a2a-2d86-4d49-9d72-effa5a2ee357" />

Refined query by account:

```kql
DeviceFileEvents
| where DeviceName == "windows-10-emra"
| where Timestamp > ago(30m)
| where InitiatingProcessAccountName == "labuser"
| project Timestamp,DeviceName, ActionType,FileName, InitiatingProcessCommandLine,FolderPath,InitiatingProcessAccountName
| order by Timestamp desc
```

**Result:**  
Significant file modification and cleanup activity initiated by `labuser`, aligned with suspicious timeline.

---

### 4️⃣ Network Connections
KQL used:

```kql
DeviceNetworkEvents
| where DeviceName == "windows-10-emra"
| where Timestamp > ago(1h)
| order by Timestamp asc
```

**Findings:**  
- Numerous failed and successful connections observed.  
- No confirmed data exfiltration captured in MDE logs yet, but connection attempts warrant deeper review of endpoints, proxies, or firewall logs.
<img width="1213" height="287" alt="image" src="https://github.com/user-attachments/assets/818b78d9-0829-4ae8-a1d0-c96665f6c2aa" />

---

## 🧾 Summary of Findings

| Category | Finding | Severity | Notes |
|-----------|----------|----------|-------|
| Script Execution | `exfiltratedata.ps1` executed via PowerShell Bypass | 🔴 High | Potential data theft script |
| Compression Tools | 7-Zip usage detected | 🟠 Medium | Possible file packaging for exfiltration |
| File Activity | Multiple file create/delete events | 🟡 Medium | Potential cleanup/obfuscation activity |
| Network Activity | Repeated connection attempts | 🟠 Medium | Requires deeper packet or proxy log analysis |

---

## 🧰 Recommended Next Steps

1. **Isolate** `windows-10-emra` from the network to prevent further data movement.  
2. **Collect and analyze** `C:\programdata\exfiltratedata.ps1` (static & dynamic analysis).  
3. **Perform memory capture** (RAM) and perform forensic analysis for in-memory staging or scripts.  
4. **Correlate logs**: MDE, DLP, proxy, firewall, cloud storage access logs, and VPN logs.  
5. **Review endpoint backups** and shadow copies for missing or altered files.  
6. **Interview** the user with HR/Legal involvement.  
7. **Harden controls**: restrict execution policy, application allowlists, and block unauthorized compression utilities where feasible.  
8. **Search file repositories** (SharePoint, OneDrive, Google Drive) for newly created archives matching time windows and names.

---

## ✅ MITRE ATT&CK MAPPING (Expanded)

Below are likely MITRE ATT&CK techniques observed or reasonably inferred from the evidence. Each technique includes the ATT&CK ID, description, example detections, and suggested mitigations.

### Tactic: Collection / Exfiltration / Defense Evasion

---

### T1560 — **Archive Collected Data**
- **Description:** Adversaries may compress or archive data to reduce size or group data for exfiltration (e.g., 7z, WinRAR).
- **Evidence in this case:** `7z.exe` observed; archives extracted at `2025-10-20T16:42:08.7734266Z`.
- **Detection:** Monitor for execution of archiving utilities, sudden creation of large archives, or archive creation in user temp folders. Use `DeviceProcessEvents`/`DeviceFileEvents` correlation.
- **Mitigations:** Application allowlisting, monitor for unusual archive creation, DLP rules blocking upload of archives with sensitive file types.

---

### T1074 — **Data Staged**
- **Description:** Adversaries may stage collected data in a central location before exfiltration.
- **Evidence in this case:** Files created in Temp and ProgramData directories; a script `exfiltratedata.ps1` suggests possible staging.
- **Detection:** Look for multiple file copies to a single staging directory, new files created by non-standard processes (e.g., PowerShell creating many files).
- **Mitigations:** Monitor and alert on large numbers of file writes by single process/user and restrict access to sensitive directories.

---

### T1059.001 — **PowerShell**
- **Description:** Use of PowerShell for execution of scripts, often used for automation and evasion (e.g., ExecutionPolicy Bypass).
- **Evidence in this case:** `powershell.exe -ExecutionPolicy Bypass -File C:\programdata\exfiltratedata.ps1`.
- **Detection:** Monitor command line for `-ExecutionPolicy Bypass`, `-EncodedCommand`, or suspicious file paths under ProgramData/Temp.
- **Mitigations:** Constrain PowerShell usage (constrained language), enable script block logging, process command-line auditing, and use AppLocker/WDAC.

---

### T1027 — **Obfuscated Files or Information**
- **Description:** Techniques used to hide malicious content or strings in scripts or binaries.
- **Evidence in this case:** Use of ExecutionPolicy Bypass may indicate script obfuscation or attempts to hide behavior.
- **Detection:** Identify obfuscated scripts, long/encoded PowerShell commands, unusual file names and extensions.
- **Mitigations:** Enable script block logging and anti-malware scanning of script contents.

---

### T1041 — **Exfiltration Over C2 Channel**
- **Description:** Using command-and-control channels or other covert channels for data exfiltration.
- **Evidence in this case:** Network connections observed; further analysis required to identify endpoints.
- **Detection:** Unusual outbound connections, DNS tunneling, persistent connections to rare endpoints, anomalous data transfer sizes.
- **Mitigations:** Egress filtering, strict proxy controls, DLP, and monitoring of unusual DNS or HTTPS patterns.

---

### T1567.002 — **Exfiltration to Cloud Storage: Exfiltration to Public Cloud Storage**
- **Description:** Uploading data to cloud storage providers (OneDrive, Google Drive, Dropbox).
- **Evidence in this case:** No direct confirmation, but employee may upload archives to private cloud storage; network connections suggest attempts.
- **Detection:** Monitor for creation of archive files followed by outbound connections to known cloud storage IPs/domains or API endpoints.
- **Mitigations:** DLP policies for cloud uploads, CASB integration, and block or monitor unsanctioned cloud storage uploads.

---

## 🔎 Detection Queries (KQL) — Included as-is from your investigation

**Compression / Process check**

```kql
let File = dynamic(["7z.exe", "winar.exe","powershell.exe","winzip.exe","Bandizip.exe",
"UniExtract.exe", "POWERARC.EXE", "IZArc.exe", "AshampooZIP.exe"]);
DeviceProcessEvents
| where DeviceName == "windows-10-emra"
| where Timestamp > ago(30m)
| where FileName has_any (File)
| order by Timestamp desc
```

**Device file events (creation/deletion)**

```kql
DeviceFileEvents
| where DeviceName == "windows-10-emra"
| where Timestamp > ago(30m)
| project Timestamp,DeviceName, ActionType,FileName, InitiatingProcessCommandLine,FolderPath
| order by Timestamp desc
```

**Filtered by account**

```kql
DeviceFileEvents
| where DeviceName == "windows-10-emra"
| where Timestamp > ago(30m)
| where InitiatingProcessAccountName == "labuser"
| project Timestamp,DeviceName, ActionType,FileName, InitiatingProcessCommandLine,FolderPath,InitiatingProcessAccountName
| order by Timestamp desc
```

**Network events**

```kql
DeviceNetworkEvents
| where DeviceName == "windows-10-emra"
| where Timestamp > ago(1h)
| order by Timestamp asc
```

---

## 🧾 Conclusion
The evidence indicates **high confidence** in attempted data staging and packaging (PowerShell + 7-Zip). Although MDE logs did not capture a confirmed outbound data transfer in the examined window, the combination of script execution, archive creation, file staging, and network connection attempts **warrants escalation** to HR/Legal and further forensic actions (script retrieval, memory capture, DLP/proxy correlation).
---

*Report prepared by: Emran Hossain*


