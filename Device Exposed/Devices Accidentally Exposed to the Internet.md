# 🛡️ Devices Accidentally Exposed to the Internet

## 📘 Overview
During routine maintenance, the security team was tasked with investigating any virtual machines (VMs) in the shared services cluster — handling **DNS**, **Domain Services**, **DHCP**, and other infrastructure services — that may have been mistakenly exposed to the public internet.

The goal of this investigation was to:
- Identify any misconfigured VMs that were unintentionally reachable from the public internet.
- Check for possible brute-force login attempts or successful logins from external sources.

---

## ⚠️ Incident Description
During the period of exposure, it was possible that some external actors attempted **brute-force attacks** on several devices.  
Some of the older systems did not have account lockout policies configured for repeated failed logins, increasing the risk of potential compromise.

To validate the extent of exposure, we inspected **Device Logon Events** to identify:
- Devices that were exposed to the internet  
- The volume of failed login attempts  
- The source IP addresses and frequency of attempts  

---

## 🔍 Log Investigation
The following KQL query was used to analyze authentication activity and identify high-frequency failed logons from external IPs:

```kql
DeviceLogonEvents
| where LogonType has_any ("Network","Interactive","RemoteInteractive","Unknown")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize Attempts = count() by RemoteIP, DeviceName, ActionType, AccountName
| order by Attempts desc
```

---

## 📊 Findings
Upon running the above query, multiple devices were found to have received **numerous failed login attempts** originating from external IP addresses, indicating attempted brute-force activity.

**Top 5 External IPs:**
1. `80.64.18.199`
2. `194.165.16.166`
3. `60.216.99.98`
4. `178.22.24.247`
5. `80.64.18.199`

---

## ✅ Verification of Successful Logins
To verify whether any of these external IP addresses successfully authenticated to any virtual systems, the following query was executed:

```kql
let IpExposed = dynamic(["80.64.18.199","194.165.16.166","60.216.99.98","178.22.24.247","80.64.18.199"]);
DeviceLogonEvents
| where LogonType has_any ("Network","Interactive","RemoteInteractive","Unknown")
| where ActionType == "LogonSuccess"
| where isnotempty(RemoteIP)
| where RemoteIP has_any (IpExposed)
```

**Result:**  
No successful logins were detected from any of the listed IP addresses.  

**Conclusion:**  
All identified brute-force attempts were **unsuccessful**. No confirmed compromise of virtual systems was found.

---

## 🧾 Summary & Next Steps

| Action | Description |
|:-------|:-------------|
| ✅ Exposure Detection | Identified and confirmed multiple VMs were briefly exposed to the internet. |
| 🚫 Attack Attempts | Detected repeated brute-force login attempts from multiple external IPs. |
| 🔒 Compromise Status | No successful external logins found; systems remain uncompromised. |
| 🧩 Recommendation | Implement account lockout policies, restrict inbound traffic, and monitor login events continuously. |

---

## 🧠 MITRE ATT&CK Mapping

| Technique | ID | Description |
|:-----------|:---:|:------------|
| **Brute Force** | T1110 | Attackers attempted repeated password guessing against exposed systems. |
| **Valid Accounts** | T1078 | Technique mitigated — no successful credential use was detected. |
| **Network Service Discovery** | T1046 | Scanning and probing of public-facing IPs prior to brute-force attempts. |

---

## 🔐 Recommendations
- **Enable Account Lockout Policies** — Limit login retries to prevent brute-force attacks.  
- **Restrict Public Access** — Ensure shared services (DNS/DHCP/AD) are internal-only.  
- **Enable Geo-IP Blocking** — Block regions or IPs with repeated failed login attempts.  
- **Continuous Monitoring** — Set alerts for repeated login failures and unexpected source IPs.  
- **Patch & Audit Regularly** — Apply OS and service updates, and review firewall rules routinely.

---

## 🏁 Status
**Closed — No active compromise found**

---

**Prepared by:** Emran Hossain / *Security Analyst*  
**Date:** October 16, 2025

