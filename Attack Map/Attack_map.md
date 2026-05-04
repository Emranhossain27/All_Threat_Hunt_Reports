# 🌍 Azure Sentinel Threat Visualization Workbooks

A set of Microsoft Sentinel workbooks built on top of the **LAW-Cyber-Range** Log Analytics Workspace. Each workbook renders a live world-map visualization of attack and activity traffic hitting the environment — sourced from a mix of student activity and real internet-facing threat actors.

---

## 📌 Overview

These workbooks translate raw log data into geographic heat maps using KQL queries and Sentinel's built-in map visualization. Bubble size and color (green → yellow → red) reflect event volume per source location, making it immediately obvious where traffic is originating.

All workbooks are scoped to the `law-cyber-range` workspace and use either:
- **Built-in geo fields** from `SigninLogs` / `AzureActivity`
- **GeoIP watchlist lookup** (`_GetWatchlist("geoip")`) for logs that only carry raw IPs

---

## 🗺️ Workbooks

### 1. Logon Success Map

Visualizes **successful Azure AD sign-ins** (ResultType == 0) by source location and identity.

![Logon Success Map](assets/logon-success-map.png)

**KQL Query:**
```kql
SigninLogs
| where ResultType == 0
| summarize LoginCount = count() by Identity,
    Latitude  = tostring(LocationDetails["geoCoordinates"]["latitude"]),
    Longitude = tostring(LocationDetails["geoCoordinates"]["longitude"]),
    City      = tostring(LocationDetails["city"]),
    Country   = tostring(LocationDetails["countryOrRegion"])
| project Identity, Latitude, Longitude, City, Country, LoginCount,
    friendly_label = strcat(Identity, " - ", City, ", ", Country)
```

**What you see:** Legitimate (and suspicious) successful logins mapped globally. A large red cluster over a region with no expected user presence is an immediate red flag.

**Map settings:** Size by `LoginCount` · Color heatmap `greenRed` · Label from `friendly_label`

---

### 2. Logon Failure Map

Visualizes **failed Azure AD sign-in attempts** (ResultType != 0), filtered to real user identities (excludes service principals containing `-`).

![Logon Failure Map](assets/logon-failed-map.png)

**KQL Query:**
```kql
SigninLogs
| where ResultType != 0 and Identity !contains "-"
| summarize LoginCount = count() by Identity,
    Latitude  = tostring(LocationDetails["geoCoordinates"]["latitude"]),
    Longitude = tostring(LocationDetails["geoCoordinates"]["longitude"]),
    City      = tostring(LocationDetails["city"]),
    Country   = tostring(LocationDetails["countryOrRegion"])
| order by LoginCount desc
| project Identity, Latitude, Longitude, City, Country, LoginCount,
    friendly_label = strcat(Identity, " - ", City, ", ", Country)
```

**What you see:** Credential stuffing, password spray, and brute-force attempts against Azure AD accounts. High volumes from unexpected countries are a strong indicator of automated attacks.

**Map settings:** Size by `LoginCount` · Color heatmap `greenRed` · Label from `friendly_label`

---

### 3. Azure Resource Creation Map

Visualizes **successful Azure resource write operations** (`WRITE` + `Success/Succeeded`) by the calling identity's IP address. Uses the GeoIP watchlist for geo-enrichment since `AzureActivity` doesn't include built-in coordinates.

> ⚠️ Only works with IPv4 addresses. GUID-format callers (service principals) are filtered out.

![Azure Resource Creation Map](assets/azure-resource-creation-map.png)

**KQL Query:**
```kql
// Only works for IPv4 Addresses
let GeoIPDB_FULL = _GetWatchlist("geoip");
let AzureActivityRecords = AzureActivity
| where not(Caller matches regex @"^[{(]?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}[)}]?$")
| where CallerIpAddress matches regex @"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
| where OperationNameValue endswith "WRITE"
    and (ActivityStatusValue == "Success" or ActivityStatusValue == "Succeeded")
| summarize ResouceCreationCount = count() by Caller, CallerIpAddress;
AzureActivityRecords
| evaluate ipv4_lookup(GeoIPDB_FULL, CallerIpAddress, network)
| project Caller,
    CallerPrefix      = split(Caller, "@")[0],
    CallerIpAddress,
    ResouceCreationCount,
    Country           = countryname,
    Latitude          = latitude,
    Longitude         = longitude,
    friendly_label    = strcat(split(Caller, "@")[0], " - ", cityname, ", ", countryname)
```

**What you see:** Who is spinning up resources and from where. Unexpected countries creating resources = potential compromise or insider threat.

**Map settings:** Size by `ResouceCreationCount` · Color heatmap `greenRed` · Label from `friendly_label`

📄 [Workbook JSON](https://github.com/joshmadakor1/lognpacific-public/blob/main/cyber-range/sentinel/Azure-Resource-Creation.json)

---

### 4. VM Authentication Failures Map

Visualizes **failed local logon attempts** against virtual machines in the environment, sourced from `DeviceLogonEvents`. Uses the GeoIP watchlist to map `RemoteIP` to geographic coordinates.

![VM Authentication Failures Map](assets/vm-auth-failures-map.png)

**KQL Query:**
```kql
let GeoIPDB_FULL = _GetWatchlist("geoip");
DeviceLogonEvents
| where ActionType == "LogonFailed"
| order by TimeGenerated desc
| evaluate ipv4_lookup(GeoIPDB_FULL, RemoteIP, network)
| summarize LoginAttempts = count() by RemoteIP,
    City              = cityname,
    Country           = countryname,
    friendly_location = strcat(cityname, " (", countryname, ")"),
    Latitude          = latitude,
    Longitude         = longitude
```

**What you see:** RDP/SSH brute-force and password spray attempts directly against VMs, mapped by the attacking IP's real-world location. Unlike the Azure AD maps, these hits are coming at the OS level.

**Map settings:** Size by `LoginAttempts` · Color heatmap `greenRed` · Label from `friendly_location`

📄 [Workbook JSON](https://github.com/joshmadakor1/lognpacific-public/blob/main/cyber-range/sentinel/VM-Authentication-Failures.json)

---

### 5. Malicious Inbound Traffic Map

Visualizes **malicious flows** flagged by NSG analytics — specifically `FlowType == "MaliciousFlow"` from `AzureNetworkAnalytics_CL`. Uses the GeoIP watchlist to geo-enrich source IPs.

![Malicious Inbound Traffic Map](assets/malicious-traffic-map.png)

**KQL Query:**
```kql
let GeoIPDB_FULL = _GetWatchlist("geoip");
let MaliciousFlows = AzureNetworkAnalytics_CL
| where FlowType_s == "MaliciousFlow"
| order by TimeGenerated desc
| project TimeGenerated,
    FlowType             = FlowType_s,
    IpAddress            = SrcIP_s,
    DestinationIpAddress = DestIP_s,
    DestinationPort      = DestPort_d,
    Protocol             = L7Protocol_s,
    NSGRuleMatched       = NSGRules_s;
MaliciousFlows
| evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network)
| project TimeGenerated, FlowType, IpAddress, DestinationIpAddress,
    DestinationPort, Protocol, NSGRuleMatched,
    latitude, longitude,
    city              = cityname,
    country           = countryname,
    friendly_location = strcat(cityname, " (", countryname, ")")
```

**What you see:** Internet-sourced malicious traffic hitting the network perimeter flagged by Microsoft's threat intelligence feed. Protocols in the data include RDP (3389), SSH (22), HTTP (80), HTTPS (443), and others. The NSG rule `danger-allow-all-inbound` is intentional — this is a honeypot-style cyber range, not a production environment.

**Map settings:** Size by flow count · Color heatmap `greenRed` · Label from `friendly_location`

📄 [Workbook JSON](https://github.com/joshmadakor1/lognpacific-public/blob/main/cyber-range/sentinel/Allowed-Inbound-Malicious-Flows.json)

---

## 🛠️ Setup

### Prerequisites
- Microsoft Sentinel enabled on a Log Analytics Workspace
- Relevant data connectors active:
  - **Azure Active Directory** → for `SigninLogs`
  - **Azure Activity** → for `AzureActivity`
  - **Microsoft Defender for Endpoint** → for `DeviceLogonEvents`
  - **Azure Network Watcher / NSG Flow Logs** → for `AzureNetworkAnalytics_CL`
- GeoIP watchlist (`geoip`) imported into Sentinel — required for workbooks 3, 4, and 5

### Creating a Workbook
1. Go to **Azure Portal → Microsoft Sentinel → Threat Management → Workbooks**
2. Click **+ Add Workbook**
3. Click the **`</>`** (code editor) button in the toolbar
4. Paste the relevant workbook JSON
5. Click **Apply** → **Save**

---

## 📊 Reading the Maps

| Bubble Color | Meaning |
|---|---|
| 🟢 Green | Low event volume from this location |
| 🟡 Yellow | Moderate event volume |
| 🔴 Red | High event volume — investigate |

Bubble **size** scales with event count. A large red bubble in an unexpected geography warrants immediate attention.

---

## ⚠️ Notes

- The `Identity !contains "-"` filter in the Logon Failure query strips out service principal object IDs, isolating human account attacks only.
- The regex in the Azure Resource Creation query filters out GUID-format callers to focus on human identities.
- `ResouceCreationCount` is a deliberate field name carried over from the source query — the typo is intentional to maintain consistency with the workbook JSON.
- `Results were limited to the first 100 rows` warnings mean the query returned more data than displayed — adjust time ranges or add a `top N` limit as needed.
- All workbooks default to **Last 24 hours**; widen the time picker for broader trend analysis.
- ⚠️ This environment uses `danger-allow-all-inbound` NSG rules intentionally — it is a **cyber range**, not a production setup. Do not replicate this configuration in live environments.
