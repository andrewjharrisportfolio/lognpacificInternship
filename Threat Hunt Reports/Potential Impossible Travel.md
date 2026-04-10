# Scenario 3: Potential Impossible Travel
**Platform:** Microsoft Sentinel  
**Status:** Closed — True Positive / Benign Positive (mixed)

---

## Objective
Detect unusual logon behavior by identifying users authenticating from multiple geographic locations within a 7-day period, investigate each account, and respond following the NIST 800-61 Incident Response Lifecycle.

---

## Part 1: Alert Rule — KQL Query

Created a Scheduled Query Rule in Sentinel to flag any user logging in from more than 7 distinct locations within a 7-day window:

```kql
// Locate Instances of Potential Impossible Travel
let TimePeriodThreshold = timespan(7d);
let NumberOfDifferentLocationsAllowed = 7;
SigninLogs
| where TimeGenerated > ago(TimePeriodThreshold)
| summarize Count = count() by UserPrincipalName, UserId, City = tostring(parse_json(LocationDetails).city), State = tostring(parse_json(LocationDetails).state), Country = tostring(parse_json(LocationDetails).countryOrRegion)
| project UserPrincipalName, UserId, City, State, Country
| summarize PotentialImpossibleTravelInstances = count() by UserPrincipalName, UserId
| where PotentialImpossibleTravelInstances > NumberOfDifferentLocationsAllowed
| order by PotentialImpossibleTravelInstances desc
```

---

## Part 2: Detection & Analysis

The rule surfaced the following top three accounts flagged for potential impossible travel:

| Account ID | Login Instances |
|---|---|
| 8314de07-7b94-4c82-bbc7-ee30b7ddbcb1 | 20 |
| bfd673bd-e246-40f0-93cb-24ee93c1a4b3 | 8 |
| 8133d43a-cd74-4c18-b458-691007f259e4 | 8 |

Each account was investigated individually using the following query to assess whether the travel pattern was physically possible:

```kql
// Investigate Potential Impossible Travel Instances
let TargetUserPrincipalName = "user@domain.com"; // Replace with target user
let TimePeriodThreshold = timespan(7d);
SigninLogs
| where TimeGenerated > ago(TimePeriodThreshold)
| where UserPrincipalName == TargetUserPrincipalName
| project TimeGenerated, UserPrincipalName, City = tostring(parse_json(LocationDetails).city), State = tostring(parse_json(LocationDetails).state), Country = tostring(parse_json(LocationDetails).countryOrRegion)
| order by TimeGenerated desc
```

**Account 8314de07 — True Positive**  
Login detected from Morocco at `4/7/2026 2:52 PM`, followed by a login from the United States at `4/7/2026 5:01 PM` — a two hour gap across continents. Physically impossible. Account flagged for compromise.

------
<img width="1599" height="670" alt="831 impossible travel" src="https://github.com/user-attachments/assets/434832d5-02bf-44e1-9345-2b67e63c4533" />

**Account bfd673bd — True Positive**  
All logins appeared domestic at first glance. Closer inspection revealed a login in New York at `4/6/2026 1:14 AM` followed by a login in Atlanta, Georgia at `4/6/2026 1:45 AM` — 31 minutes apart across a 900-mile distance. Flagged as suspicious.

------
<img width="1593" height="668" alt="bfd impossible travel" src="https://github.com/user-attachments/assets/1fb7932b-949f-4100-a202-f4aaca62efc0" />

**Account 8133d43a — Investigated / Benign**  
Login in Pompano Beach, Florida at `4/2/2026 2:02 PM` followed by a login in Columbus, Ohio at `4/2/2026 5:03 PM` — approximately 3 hours apart. Travel was investigated and confirmed plausible. No action taken.

---
<img width="1571" height="640" alt="813 impossible travel" src="https://github.com/user-attachments/assets/3aacb5e9-3ce2-4d0f-8b24-22bb428d2724" />


## Containment, Eradication & Recovery

- Accounts `8314de07` and `bfd673bd` disabled in Entra ID and all active remote sessions terminated
- Account `8133d43a` investigated — user confirmed travel, no action taken

---

## Post-Incident Activities

- Configured stricter conditional access policy in Entra ID
- Pushed change blocking all third-party VPN software
- Updated NSG to restrict RDP (port 3389) to whitelisted IP addresses only

---

## Closure

Incident closed as **True Positive** for accounts `8314de07` and `bfd673bd`. Account `8133d43a` closed as **Benign Positive** following travel confirmation. Affected accounts disabled and conditional access controls hardened to prevent recurrence.
