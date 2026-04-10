## Scenario 1: Virtual Machine Brute Force Detection ##

*Platform: Microsoft Sentinel + Microsoft Defender for Endpoint*

### Objective ###


Detect and respond to RDP brute force attempts against Azure VMs using a custom Sentinel Scheduled Query Rule, then work the incident to closure following the NIST 800-61 Incident Response Lifecycle.

### Part 1: Alert Rule — KQL Query ###


Created a Scheduled Query Rule in Sentinel to detect when the same remote IP fails to log into the same VM 10+ times within 5 hours:


```kql
DeviceLogonEvents
| where TimeGenerated >= ago(5h)
| where ActionType == "LogonFailed"
| summarize NumberOfFailures = count() by RemoteIP, ActionType, DeviceName
| where NumberOfFailures >= 10
| order by NumberOfFailures desc
```



<img width="1919" height="854" alt="alert triggered based of kql rule" src="https://github.com/user-attachments/assets/8f476596-99cb-4439-8ae3-95aa657e0604" />

### Part 2: Detection & Analysis ###


Three VMs were targeted by brute force attempts from public IPs:

| Source IP | Target Device | Failed Logons |
|---|---|---|
| 94.26.68.55 | sever-mde-test | 98 |
| 94.26.68.55 | nh-wks-it-01.corp.nimbushealth.com | 91 |
| 94.26.68.54 | nh-wks-clin-01.corp.nimbushealth.com | 49 |


Queried to confirm no successful logons occurred from either source IP:


```kql
DeviceLogonEvents
| where RemoteIP in ("94.26.68.55", "94.26.68.54")
| where ActionType != "LogonFailed"
Result: No successful logons detected. No breach confirmed.
```
<img width="1901" height="819" alt="none of the ips successfully logged in" src="https://github.com/user-attachments/assets/d86f0d37-12ec-48c4-90e2-74b4935d6a98" />


### Part 3: Containment, Eradication & Recovery ###

Isolated all three affected devices via Microsoft Defender for Endpoint


Ran antimalware scans on all three devices within MDE

Password policy updated to enforce rotation every 90 days


Locked down NSG to restrict RDP access to whitelisted IPs within the subnet only


Both source IPs confirmed malicious via VirusTotal entire subnet 94.26.68.0/24 blocked


<img width="1918" height="863" alt="virus total scan 1" src="https://github.com/user-attachments/assets/0b0c49a4-1f4a-483f-893d-087f7cbaf643" />
<img width="1913" height="860" alt="virus total scan 2" src="https://github.com/user-attachments/assets/62543a2d-ba51-42c5-bca0-e229773d4b13" />





# Closure #

Incident closed as True Positive brute force confirmed, no successful authentication. All containment measures applied and verified.
