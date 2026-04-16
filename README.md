# Cyber Range — Security Operations Portfolio

A collection of security operations projects built on a live enterprise environment running real attack traffic and vulnerabilities. Each project was worked end-to-end — from writing detection logic and triaging alerts to containing threats and closing incidents — using the same tools and workflows found in production SOC environments.

---

## Projects

### 🔵 Threat Detection & Incident Response

| Scenario | Summary | Outcome |
|---|---|---|
| [VM Brute Force Detection](https://github.com/andrewjharrisportfolio/lognpacificInternship/blob/main/Threat%20Hunt%20Reports/Virtual%20Machine%20Brute%20Force%20Detection.md) | Detected coordinated RDP brute force from a public /24 subnet across 3 VMs using custom KQL in Sentinel | True Positive — No breach confirmed. Subnet blocked, NSG hardened |
| [PowerShell Suspicious Web Request](https://github.com/andrewjharrisportfolio/lognpacificInternship/blob/main/Threat%20Hunt%20Reports/PowerShell%20Suspicious%20Web%20Request.md) | Identified malicious `Invoke-WebRequest` activity downloading and executing 3 post-exploitation scripts (port scanner, ransomware simulator, EICAR) | True Positive — Device isolated, scripts hashed and removed, PowerShell restricted |
| [Potential Impossible Travel](https://github.com/andrewjharrisportfolio/lognpacificInternship/blob/main/Threat%20Hunt%20Reports/Potential%20Impossible%20Travel.md) | Investigated 3 flagged accounts for geographic login anomalies using `SigninLogs` KQL analysis | 2 True Positives (Morocco→US in 2hrs, NY→Atlanta in 31min) — Accounts disabled, conditional access hardened |

---

### 🟠 Threat Hunting

| Hunt | Summary | Outcome |
|---|---|---|
| [TOR Browser Usage](https://github.com/andrewjharrisportfolio/lognpacificInternship/blob/main/Threat%20Hunt%20Reports/ThreatEventTORUsage.md) | Conducted a proactive threat hunt for unauthorized TOR installation and use across `DeviceFileEvents`, `DeviceProcessEvents`, and `DeviceNetworkEvents` — reconstructing the full activity timeline from installation to cleanup | Confirmed full kill chain: silent install → AV probe → dark web browsing → shopping list creation → cleanup attempt. Device isolated, manager notified |
| [Scattered Spider BEC Hunt](https://github.com/andrewjharrisportfolio/lognpacificInternship/blob/main/Threat%20Hunt%20Reports/Scattered%20Spider%20BEC%20Hunt.md) | Investigated a Scattered Spider BEC attack against a finance employee — tracing MFA fatigue abuse, malicious inbox rule creation, and a fraudulent £24,500 wire transfer across `SigninLogs`, `CloudAppEvents`, and `EmailEvents` | Confirmed full attack chain across 73 correlated events. Inbox rules removed, sessions revoked, Conditional Access gap identified as primary defensive failure |

---

### 🔴 Vulnerability Management

| Project | Summary | Outcome |
|---|---|---|
| [Vulnerability Management Program](https://github.com/andrewjharrisportfolio/lognpacificInternship/blob/main/Vulnerability%20Management/Vulnerability_Management_Program.md) | Implemented a full vulnerability management lifecycle from policy creation to remediation across 5 rounds of scanning on a deliberately insecure Windows Server | **88% vulnerability reduction** (26 → 3). 100% of Critical and High findings resolved |

**Remediation breakdown:**

| Round | Target | Result |
|---|---|---|
| 1 | Outdated Wireshark removal | Eliminated all 2 Critical vulnerabilities |
| 2 | Insecure protocols & cipher suites | Reduced Medium exposure |
| 3 | Guest account group membership | Resolved High finding |
| 4 | Windows OS updates + WinTrust CVE-2013-3900 | Resolved remaining High findings |
| 5 | SMB Signing enforcement | Final High resolved |

---

### 🟡 STIG Remediation

| Project | Summary |
|---|---|
| [DISA STIG Remediation Scripts](https://github.com/andrewjharrisportfolio/lognpacificInternship/tree/main/STIGS) | Authored PowerShell remediation scripts targeting Windows Server DISA STIGs — covering registry hardening, audit policy enforcement, local account controls, user rights assignment via secedit, and CVE-2013-3900 mitigation |

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
- Custom KQL detection rule authoring across `DeviceLogonEvents`, `DeviceProcessEvents`, `DeviceFileEvents`, `DeviceNetworkEvents`, and `SigninLogs`
- Proactive threat hunting using IoC-driven investigation across multiple log sources
- Vulnerability assessment, prioritization, and remediation tracking across full scan cycles
- Static script analysis and attack chain reconstruction
- DISA STIG remediation scripting and Windows security hardening
- Conditional access policy configuration and NSG hardening

