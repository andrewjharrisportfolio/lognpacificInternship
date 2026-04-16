# Cyber Range — Security Operations Portfolio

A collection of hands-on security operations projects completed through a simulated enterprise environment. Each scenario follows real-world SOC workflows using industry-standard tools including Microsoft Sentinel, Microsoft Defender for Endpoint, and Tenable Vulnerability Management.

---

## Projects

### 🔵 Threat Detection & Incident Response

| Scenario | Summary | Outcome |
|---|---|---|
| [VM Brute Force Detection](./Scenario_1_VM_Brute_Force.md) | Detected coordinated RDP brute force from a public /24 subnet across 3 VMs using custom KQL in Sentinel | True Positive — No breach confirmed. Subnet blocked, NSG hardened |
| [PowerShell Suspicious Web Request](./Scenario_2_PowerShell_Web_Request.md) | Identified malicious `Invoke-WebRequest` activity downloading and executing 3 post-exploitation scripts (port scanner, ransomware simulator, EICAR) | True Positive — Device isolated, scripts hashed and removed, PowerShell restricted |
| [Potential Impossible Travel](./Scenario_3_Impossible_Travel.md) | Investigated 3 flagged accounts for geographic login anomalies using `SigninLogs` KQL analysis | 2 True Positives (Morocco→US in 2hrs, NY→Atlanta in 31min) — Accounts disabled, conditional access hardened |

---

### 🟠 Threat Hunting

| Hunt | Summary | Outcome |
|---|---|---|
| [TOR Browser Usage](./Threat_Event_TOR_Usage.md) | Proactively hunted for unauthorized TOR installation and use across `DeviceFileEvents`, `DeviceProcessEvents`, and `DeviceNetworkEvents` | Confirmed full kill chain: silent install → AV probe → dark web browsing → shopping list creation → cleanup attempt. Device isolated, manager notified |

---

### 🔴 Vulnerability Management

| Project | Summary | Outcome |
|---|---|---|
| [Vulnerability Management Program](./Vulnerability_Management_Program.md) | Implemented a full vulnerability management lifecycle from policy creation to remediation across 5 rounds of scanning on a deliberately insecure Windows Server | **88% vulnerability reduction** (26 → 3). 100% of Critical and High findings resolved |

**Remediation breakdown:**

| Round | Target | Result |
|---|---|---|
| 1 | Outdated Wireshark removal | Eliminated all 2 Critical vulnerabilities |
| 2 | Insecure protocols & cipher suites | Reduced Medium exposure |
| 3 | Guest account group membership | Resolved High finding |
| 4 | Windows OS updates + WinTrust CVE-2013-3900 | Resolved remaining High findings |
| 5 | SMB Signing enforcement | Final High resolved |

---

## Tools & Technologies

- **SIEM:** Microsoft Sentinel
- **EDR:** Microsoft Defender for Endpoint
- **Vulnerability Management:** Tenable
- **Query Language:** KQL (Kusto Query Language)
- **Scripting:** PowerShell
- **Cloud:** Microsoft Azure

---

## Skills Demonstrated

- Incident detection, triage, and closure following NIST 800-61
- KQL query authoring across `DeviceLogonEvents`, `DeviceProcessEvents`, `DeviceFileEvents`, `DeviceNetworkEvents`, and `SigninLogs`
- Threat hunting with hypothesis-driven IoC discovery
- Vulnerability assessment, prioritization, and remediation tracking
- Malware analysis (static script review and attack chain reconstruction)
- Conditional access policy configuration and NSG hardening
