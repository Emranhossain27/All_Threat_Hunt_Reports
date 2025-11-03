# 🧾 Microsoft Sentinel Detection Report  
## Potential Impossible Travel (Credential Compromise Detection)

---

### **Detection Objective**
Identify and alert when a single user logs into **multiple geographic regions** (for example, two or more distinct countries or cities) within a **7-day period** — an indicator of potential **credential compromise** or **account misuse**.

---

### **Data Source**
- **Table:** `SigninLogs`  
- **Workspace:** Azure Log Analytics  
- **Detection Platform:** Microsoft Sentinel, Microsoft Defender for Endpoint, Azure Portal 

---

### **KQL Query**

```kql
let numberofLogon = 2;
SigninLogs
| where TimeGenerated > ago(7d)
| summarize Count = count() by 
    UserPrincipalName, 
    UserId, 
    City = tostring(parse_json(LocationDetails.city)), 
    State = tostring(parse_json(LocationDetails.state)), 
    Country = tostring(parse_json(LocationDetails.country))
| project UserPrincipalName, UserId, City, State, Country
| summarize totalImpossibleTravel = count() by UserPrincipalName, UserId
| where totalImpossibleTravel > numberofLogon
```
<img width="1513" height="782" alt="image" src="https://github.com/user-attachments/assets/d8d7ddc5-fdfb-4515-8979-761ada97797d" />

✅ **Explanation**
- Looks back **7 days** for sign-ins.  
- Extracts **city**, **state**, and **country** from `LocationDetails`.  
- Counts logins per user and compares them to a threshold (`numberofLogon = 2`).  
- Flags users logging in from more than two regions.

---

### **Sentinel Scheduled Query Rule Configuration**

| **Setting** | **Value** |
|--------------|-----------|
| **Rule Name** | `Potential Impossible Travel (Multiple Geographic Logins)` |
| **Description** | Detects when a user logs in from multiple geographic locations (countries/cities) within 7 days. May indicate credential compromise or unauthorized access. |
| **Run Frequency** | Every 4 hours |
| **Lookup Data Range** | Last 5 hours |
| **Alert Trigger Condition** | When query returns results |
| **Stop After Alert** | ✅ Yes (24-hour window) |
| **Incident Creation** | Automatically create an incident |
| **Grouping** | Group all alerts into one incident per 24 hours |

---

### **Entity Mapping**

| **Entity Type** | **Identifier** | **Value** |
|------------------|----------------|-----------|
| **Account** | AadUserId | `UserId` |
| **Account** | DisplayName | `UserPrincipalName` |

---

### **MITRE ATT&CK Mapping**

| **Tactic (Goal)** | **Technique (How)** | **ID** | **Description** |
|--------------------|--------------------|---------|-----------------|
| **Initial Access (TA0001)** | **Valid Accounts** | **T1078** | Adversaries may use stolen or shared credentials to gain access. |
| **Lateral Movement (TA0008)** | **Valid Accounts: Cloud Accounts** | **T1078.004** | Compromised cloud accounts reused in multiple regions or environments. |
| *(Optional)* **Credential Access (TA0006)** | **Brute Force** | **T1110** | Multiple logins could also suggest password-guessing attempts. |

---

### **Response Plan**

#### **Containment**
- **Action:** Isolate affected systems to prevent further misuse.  
- **Next Step:** Disable the suspicious account in **Entra ID (Azure AD)** and notify the user and management.

#### **Verification**
- It was determined that the alert was a **TRUE POSITIVE**.  
  Example: User `jane.doe@contoso.com` logged in from **Ohio, USA** and **Berlin, Germany** within a **3-day period**, which is impossible.

#### **Immediate Actions**
- Disabled user account.  
- Management notified and investigation initiated.

---

### **Eradication and Recovery**
- No active threat or malware found.  
- Account reset and MFA re-enrolled.  
- Monitoring enabled for similar behavior.

---

### **Post-Incident Activities**
1. **Policy Updates:** Consider implementing geo-fencing or Conditional Access policies to restrict logins to approved countries.  
2. **Documentation:** Record all findings and decisions in Sentinel incident notes.  
3. **Awareness:** Notify users of phishing and credential hygiene best practices.

---

### **Closure**

| **Status** | **Resolution** | **Notes** |
|-------------|----------------|------------|
| ✅ **Closed** | Benign Positive / True Positive | Incident reviewed and closed after confirming corrective actions. |

