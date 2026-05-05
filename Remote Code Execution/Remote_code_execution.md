# 🛡️ Custom Threat Detection & Automated VM Isolation — Microsoft Defender for Endpoint

A hands-on security lab where I built a custom KQL detection rule in Microsoft Defender for Endpoint (MDE) that automatically isolated a VM the moment it detected a suspicious PowerShell execution — all on a real internet-facing machine being actively targeted by threat actors.

---

## 📌 Overview

| Field | Details |
|---|---|
| **Platform** | Microsoft Azure |
| **Tools** | Microsoft Defender for Endpoint · KQL · Advanced Hunting · Log Analytics |
| **Techniques** | Custom Detection Rules · Automated Response · Forensic Investigation |
| **MITRE ATT&CK** | T1059.001 (PowerShell) · T1105 (Ingress Tool Transfer) · T1562.001 (Disable Firewall) |
| **Outcome** | Alert fired → VM auto-isolated → Investigation package collected |

---

## 🧪 Lab Setup

### 1. Provision the VM
- Created a Windows Virtual Machine on Azure (`emran-windows-1`)
- Used a strong, non-default password — default credentials like `labuser/Cyberlab123!` are actively exploited by internet-facing threat actors
- Tagged as **Internet facing** in MDE

### 2. Disable Windows Firewall
Intentionally disabled to make the VM discoverable by bad actors on the internet — simulating a misconfigured or neglected endpoint.

```
Start → Run → wf.msc → Turn off firewall for all profiles
```

> ⚠️ This is intentional for lab purposes only. Never do this in production.

### 3. Onboard to Microsoft Defender for Endpoint
- Followed the MDE onboarding process to register the VM
- Verified the device appeared in the MDE portal: [https://security.microsoft.com/machines](https://security.microsoft.com/machines)
- Confirmed logs were flowing using Advanced Hunting:

```kql
DeviceLogonEvents
| where DeviceName startswith "emran-windows-1"
| order by Timestamp desc
```

---

## 🔍 Detection Rule — PowerShell Remote Code Execution

### Threat Scenario
Attackers commonly use PowerShell's `Invoke-WebRequest` to silently download and execute malicious payloads. This detection targets that exact behavior scoped to a specific machine to avoid false positives across the shared environment.

### KQL Query

```kql
let target_machine = "emran-windows-1";
DeviceProcessEvents
| where DeviceName == target_machine
| where AccountName != "system"
| where InitiatingProcessCommandLine has_any("Invoke-WebRequest")
| order by TimeGenerated desc
```

![Advanced Hunting — Detection Query](<img width="1786" height="906" alt="image" src="https://github.com/user-attachments/assets/1657fe6c-2c44-4b12-a50c-a2d5141fe0a0" />
)

### Detection Rule Settings

| Setting | Value |
|---|---|
| **Rule name** | Emran_Detection |
| **Frequency** | Every 1 hour |
| **Scope** | `emran-windows-1` only |
| **Automated Actions** | ✅ Isolate Device · ✅ Collect Investigation Package |

> Scoping the rule to a single VM is critical in a shared lab environment — triggering isolation on the wrong machine would disrupt other users.

---

## 💥 Triggering the Alert

The following command was run on the VM to simulate a PowerShell-based remote code execution event — downloading and silently installing 7-Zip:

```cmd
cmd.exe /c powershell.exe -ExecutionPolicy Bypass -NoProfile -Command "Invoke-WebRequest -Uri 'https://sacyberrange00.blob.core.windows.net/vm-applications/7z2408-x64.exe' -OutFile C:\ProgramData\7z2408-x64.exe; Start-Process 'C:\programdata\7z2408-x64.exe' -ArgumentList '/S' -Wait"
```

### What the Logs Captured

| Timestamp | File | Path | Action |
|---|---|---|---|
| 5 May 2026 10:32:37 | `powershell.exe` | `C:\Windows\System32\` | ProcessCreated |
| 5 May 2026 10:32:39 | `7z2408-x64.exe` | `C:\ProgramData\` | ProcessCreated |

**Detection latency: 2 seconds.** PowerShell spawned at 10:32:37 — 7-Zip executing at 10:32:39 — alert fired and VM isolated automatically.

---

## 🔒 Automated Response

Once the detection rule fired:

- ✅ **Device Isolation** triggered automatically — VM cut off from the network
- ✅ **Investigation Package** collected — includes process trees, file/registry changes, network connections, event logs, and memory artifacts
- ✅ **Alert assigned** to my user account and resolved in the MDE portal

### VM State After Isolation

![VM Isolated in MDE Portal](<img width="1456" height="706" alt="image" src="https://github.com/user-attachments/assets/a8ddbe5a-330b-4c79-a8de-01aec0db88b3" />
)

| Field | Value |
|---|---|
| **Device** | emran-windows-1 |
| **Status** | Active · Isolated · Internet facing |
| **Risk Level** | 🔴 High |
| **Exposure Level** | 🔴 High |
| **Active Alerts** | 110 (High: 3 · Medium: 106 · Info: 1) |
| **Active Incidents** | 102 |
| **Vulnerabilities** | 20 (Critical: 3 · High: 6 · Medium: 3 · Low: 8) |
| **Last Action** | Device Isolation · Completed |
| **Action Source** | PowerShell execution process |

> The volume of alerts reflects real internet-facing threat actors actively targeting the exposed VM throughout the lab — not just the simulated trigger.

---

## 🧹 Cleanup

1. Alert assigned to user account and **resolved** in MDE
2. Custom detection rule **deleted** to avoid impacting other lab users
3. VM **released from isolation**
4. Azure VM **deleted** after lab completion

---

## 📖 Key Takeaways

- **Scoped detection rules matter.** A rule that isolates any VM matching a pattern in a shared environment is dangerous. Always scope to a specific device name during testing.
- **Automated response is powerful but irreversible in the moment.** Once isolation triggers, you lose RDP access. Plan your testing accordingly.
- **Real attackers don't wait.** The VM accumulated 110 alerts and 102 incidents from genuine internet threat actors simply by being exposed with the firewall disabled — within the lab window.
- **The full SOC loop in one lab:** Write detection → trigger event → alert fires → automated response → forensic investigation → resolve → cleanup.

---

## 🔗 Related Projects

| Project | Description |
|---|---|
| [Azure Sentinel Threat Maps](https://github.com/Emranhossain27/All_Threat_Hunt_Reports) | World map visualizations of live attack traffic using KQL + Sentinel Workbooks |
| [Threat Hunting Reports](https://github.com/Emranhossain27/All_Threat_Hunt_Reports) | Collection of threat hunting investigations across multiple attack scenarios |
