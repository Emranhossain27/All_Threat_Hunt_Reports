# 🛡️ Brute Force Attempt Detection — Incident Report

## 🎯 Objective
Design a **Sentinel Scheduled Query Rule** within Log Analytics that will discover when the same remote IP address has failed to log in to the same local host (Azure VM) **10 times or more within the last 5 hours.**

---

## ⚠️ Observation
I have noticed that there was a **brute-force attack** trying to gain access to my account.

---

## 🧠 Detection Query

```kql
// 🔍 Detect multiple failed logon attempts on a specific device

DeviceLogonEvents
| where DeviceName == "windows-10-emra"           // Filter events from your device
| where ActionType == "LogonFailed"
| where TimeGenerated > ago(7d)                   // Only include failed logon attempts
| summarize totalAttempts = count()               // Count total attempts
          by AccountName, ActionType, RemoteIP, DeviceName   // Group by user and source IP
| where totalAttempts >= 5                        // Show only suspicious repeated attempts
| sort by totalAttempts desc                      // Optional: sort from highest to lowest
```

<img width="1417" height="821" alt="image" src="https://github.com/user-attachments/assets/036ec1e5-1e1e-4738-a42b-6770958fe01e" />

---

## 🧾 Summary of Findings
There were multiple attempts to gain access to the account, but the attacker **failed** to get access.

Once the query was verified, a **Scheduled Query Rule** was created in:
> **Sentinel → Analytics → Scheduled Query Rule**

---

## ⚙️ Analytics Rule Settings
- ✅ **Rule Enabled**
- ⚡ **Run query every:** 4 hours  
- ⏱️ **Lookup data for last:** 5 hours (defined in query)  
- 🚨 **Stop running query after alert is generated:** Yes  
- 🧩 **Entity Mappings:** `RemoteIP` and `DeviceName`  
- 🧱 **Incident Handling:** Automatically create an incident if triggered  
- 🧩 **Group Alerts:** Combine all alerts into a single incident per 24 hours  
- 🛑 **Stop running after alert:** Enabled (24 hours)

---

## 📊 Results
After creating the rules, we found:
- **14 Events** triggered  
- Activity came from **7 different IP addresses**  
- Targeted **2 different hosts**

### Example IP Addresses Involved:
```
146.19.24.26
80.94.93.233
80.94.93.119
193.46.255.244
```

<img width="1058" height="656" alt="image" src="https://github.com/user-attachments/assets/0c621dda-973d-4461-9c92-b26641ecc46b" />

---

## 🔎 Logon Success Check
No successful logons were detected from those IPs.

```kql
DeviceLogonEvents
| where RemoteIP in ("146.19.24.26","80.94.93.233","80.94.93.119","193.46.255.244")
| where ActionType == "LogonSuccess"
```

✅ **Result:** No successful logons found.

---

## 🧰 Mitigation Actions
- 🧩 Devices under attack were **isolated via Microsoft Defender for Endpoint (MDE)** for analysis.  
- 🦠 Conducted a **full antivirus (AV) scan** on affected hosts.  
- 🔒 **NSG (Network Security Group)** was locked down to prevent RDP attempts from the public internet.  
- 🧾 Proposed **corporate policy** requiring RDP restrictions for all VMs going forward (enforced via **Azure Policy**).

---

## 🧠 MITRE ATT&CK Mapping

| Category | Details |
|-----------|----------|
| **Tactic (Goal)** | Credential Access (**TA0006**) |
| **Technique** | Brute Force (**T1110**) |
| **Sub-Techniques** | - T1110.001 – Password Guessing  <br> - T1110.002 – Password Cracking <br> - T1110.003 – Password Spraying |
| **Follow-Up Tactic** | Initial Access (**TA0001**) via Valid Accounts (**T1078**) if successful |
| **Data Source** | DeviceLogonEvents (Microsoft Defender for Endpoint / Sentinel) |
| **Entity Mapping** | Host → `DeviceName` <br> Account → `AccountName` <br> IP → `RemoteIP` |
| **Detection Logic Summary** | Detects repeated failed logon attempts (≥5) from the same remote IP on the same host |
| **Impact** | Potential brute-force attack or credential-stuffing activity targeting exposed Windows endpoints |

---

## 🧩 Conclusion
The brute-force attempts were **detected, contained, and analyzed** successfully.  
No unauthorized access occurred. Security controls have been strengthened, and automated detection and isolation are now in place through **Microsoft Sentinel** and **Defender for Endpoint**.

---

### 📁 File Information
**Filename:** `brute_force.md`  
**Author:** Emran Hossain  
**Platform:** Microsoft Sentinel + Defender for Endpoint + Azure + Log Analytics 
**Date:** October 27, 2025

