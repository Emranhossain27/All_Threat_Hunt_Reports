# 🛰️ Sudden Network Slowdowns — SOC Investigation Report

<p align="center">
  <img src="https://img.shields.io/badge/Incident-Investigation-blue?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Tool-Microsoft%20Defender%20%7C%20KQL-orange?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Analyst-Emran%20Hossain-success?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Date-October%2017%2C%202025-lightgrey?style=for-the-badge"/>
</p>

---

## 🎯 Goal
Set up the hunt by defining what you're looking for.  
The server team noticed significant **network performance degradation** on several older devices within the **10.0.0.0/16** network.  
After ruling out external **DDoS attacks**, the security team suspected an **internal cause**.

---

## 🧩 Activity

**Hypothesis:**  
Based on threat intelligence and observed security gaps, the slowdown may be due to **lateral movement** or **internal network scanning** activity.  

All traffic originating from within the local network is allowed by default by all hosts, and PowerShell usage is unrestricted.  

It’s possible someone is:
- Downloading large files within the network, or  
- Running **port scans** against internal hosts to identify open services.

---

## 🔍 Investigation Steps

### 1️⃣ Checking for External Access or Failed Connections
During the investigation, I verified if there was any **external access** to my environment.  
I discovered a large number of **failed connections** and **PowerShell executions** originating from `windows-10-emra`.

```kql
DeviceNetworkEvents
| where DeviceName == "windows-10-emra"
| where ActionType == "ConnectionFailed"
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, InitiatingProcessCommandLine
| order by Timestamp desc
```

**Findings:**  
Several failed connection attempts were recorded, indicating possible **port probing** or **unauthorized connection attempts** from within the local network.

---

### 2️⃣ Identifying Suspicious PowerShell Activity
Next, I examined **process-level events** for potential malicious script execution, particularly PowerShell.

```kql
DeviceProcessEvents
| where DeviceName == "windows-10-emra"
| where InitiatingProcessCommandLine contains "portscan.ps1"
| project InitiatingProcessCommandLine, Timestamp
| order by Timestamp desc
```

**Findings:**  
Evidence confirmed that a **PowerShell script (`portscan.ps1`)** was executed on the host.  
The script appears to have been used for **port scanning**, and logs suggest it may have **downloaded a suspicious file**.

---

## 🧾 Summary of Findings
- Multiple **failed connection attempts** were detected in the internal network.  
- A **PowerShell script (`portscan.ps1`)** executed, performing internal **port scanning**.  
- The activity originated from **`windows-10-emra`**, aligning with the network slowdown timeline.  
- Possible **unauthorized network reconnaissance** or **data exfiltration** attempts identified.

---

## 🧠 MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Description |
|:--|:--:|:--|:--|
| **Discovery** | T1046 | Network Service Discovery | Port scanning to find open services/hosts on the network. |
| **Execution** | T1059.001 | Command and Scripting Interpreter: PowerShell | Using PowerShell to run the `portscan.ps1` script. |
| **Ingress Tool Transfer** | T1105 | Ingress Tool Transfer | Downloading the PowerShell script from the Internet. |
| **Command and Control** | T1071.001 | Application Layer Protocol: Web Protocols | If the script was downloaded via HTTP/HTTPS (e.g., from GitHub). |
| **Lateral Movement (Possible)** | T1021 | Remote Services | Port scans could precede lateral movement to other systems. |

---

## 🧰 Detection & Mitigation Recommendations

### Detection Rules
- Alert on PowerShell processes that launch from non-admin paths or include suspicious URLs or encoded commands.  
- Detect high rates of failed connection attempts from a single host.  
- Monitor for downloads from public raw URLs (e.g., `raw.githubusercontent.com`) to system directories like `C:\ProgramData`.  
- Detect usage of PowerShell with `-ExecutionPolicy Bypass`.

### Mitigations
- Restrict PowerShell execution to **signed scripts** only.  
- Enable **PowerShell logging** (Script Block Logging, Module Logging) and send logs to the SIEM.  
- Apply **egress filtering** to restrict external script downloads.  
- Implement **AppLocker** or **WDAC** to block unauthorized PowerShell scripts.  
- Segment networks to limit lateral movement and enforce least privilege.

---

## 🚨 Next Steps
1. Isolate the affected host (`windows-10-emra`) for detailed analysis.  
2. Perform **memory and disk scans** for malicious scripts or payloads.  
3. Review **PowerShell 4104 logs** for detailed command traces.  
4. Enforce stricter outbound firewall and PowerShell execution policies.  
5. Create alerts for future scanning activity or mass connection failures.

---

## 🧑‍💻 SOC Analyst Notes
This mirrors a real SOC workflow:  
- **Detection & Analysis:** Identify abnormal PowerShell usage.  
- **Threat Hunting:** Use KQL to detect scanning activity.  
- **MITRE Mapping:** Classify attacker behavior using ATT&CK.  
- **Documentation:** Summarize findings in a formal incident report.  

---

### 📁 Suggested Repo Structure
```
📂 Incident_Reports/
 ├── Sudden_Network_Slowdowns/
 │    ├── README.md
 │    └── evidence/
 │         └── screenshots.png
```

**Tags:** `#SOCAnalyst` `#ThreatHunting` `#PowerShell` `#KQL` `#MITRE` `#MicrosoftDefender`  
> 🏆 Demonstrates real-world SOC analysis, detection, and incident reporting skills.

