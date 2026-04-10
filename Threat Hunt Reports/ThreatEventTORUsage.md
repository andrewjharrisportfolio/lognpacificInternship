# Threat Event (Unauthorized TOR Usage)


**Unauthorized TOR Browser Installation and Use on Workstation: VMTORFINAL**

---

## Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

---

## Steps the "Bad Actor" Took to Create Logs and IoCs:
1. Silently installed TOR browser via command line: `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
2. Opened the TOR browser from the desktop
3. Connected to a site to verify location was anonymized
4. Visited the following sites:
   - https://onion.live/
   - Dread Forum: `http://dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad.onion`
   - Vortex Market
5. Created a file named `torshoppinglist.txt`
6. Deleted the file
7. Attempted to uninstall TOR from the command line (unsuccessful)
8. Deleted the TOR folder via GUI and emptied the Recycle Bin

---

## Tables Used to Detect IoCs:
| **Parameter** | **Description** |
|---|---|
| **Name** | DeviceFileEvents |
| **Info** | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table |
| **Purpose** | Used to detect TOR browser download, installation, shopping list creation and deletion, and cleanup activity. |

| **Parameter** | **Description** |
|---|---|
| **Name** | DeviceProcessEvents |
| **Info** | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table |
| **Purpose** | Used to detect silent installation of TOR and the launching of tor.exe and firefox.exe. |

| **Parameter** | **Description** |
|---|---|
| **Name** | DeviceNetworkEvents |
| **Info** | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table |
| **Purpose** | Used to detect TOR network activity via tor.exe and firefox.exe making outbound connections over port 443 to known TOR nodes. |

---

## Related Queries:

```kql
// TOR-related files detected on disk including shopping list
DeviceFileEvents
| where DeviceName contains "vmtorfinal"
| where FileName contains "torshopping" or FileName contains "tor."
| where FileName !in ("edge_checkout_page_validator.js", "edge_confirmation_page_validator.js", "edge_tracking_page_validator.js")
| order by Timestamp asc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName

// Silent installation of TOR browser detected
DeviceProcessEvents
| where DeviceName == 'vmtorfinal'
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.9.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, InitiatingProcessFileName, ProcessCommandLine

// TOR browser launched via tor.exe
DeviceProcessEvents
| where DeviceName == 'vmtorfinal'
| where FileName has_any ("tor.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, InitiatingProcessFileName, ProcessCommandLine



// Outbound connections made by TOR processes
DeviceNetworkEvents
| where DeviceName contains "vmtorfinal"
| where DeviceName != "system"
| where InitiatingProcessFileName has_any ("tor.exe", "firefox")
| project Timestamp, DeviceName, InitiatingProcessFileName, ActionType, RemoteIP, RemotePort, RemoteIPType, InitiatingProcessCommandLine
```

---

## Chronological Event Timeline:

| **Timestamp** | **Event** |
|---|---|
| 12:48:51 AM | TOR browser files appear on disk — tor.txt and tor.exe created under `C:\Users\drew\Desktop\Tor Browser\` |
| 12:49:25 AM | firefox.exe makes loopback connection to 127.0.0.1 — TOR Browser UI starting locally |
| 12:49:33 AM | tor.exe initializes local SOCKS and control services |
| 12:49:34 AM | firefox.exe connects to 127.0.0.1:9151 — browser communicating with TOR local control |
| 12:49:35 AM | First confirmed outbound TOR connection — tor.exe connects to 176.65.148.3:443 |
| 12:49:40 AM | Additional outbound TOR connections established to 64.65.63.30:443 and 85.121.5.97:443 |
| 12:49:51 AM | firefox.exe connects to 127.0.0.1:9150 — browser traffic routed through TOR SOCKS proxy |
| 12:50:01 AM | One failed connection attempt to 77.20.3.30:433 — sustained TOR activity confirmed |
| Post-connect | User verified anonymized location, visited onion.live, Dread Forum, and Vortex Market |
| 12:55:24 AM | torshoppinglist.txt created at `C:\Users\drew\Documents\torshoppinglist.txt` |
| Post-creation | Shopping list deleted, failed command-line uninstall attempt noted |
| 1:00:47 AM | tor.exe deleted from Desktop TOR folder — cleanup initiated |
| 1:00:53 AM | tor.exe deleted from Recycle Bin path — folder emptied via GUI |

---

## Summary

TOR was silently installed on `vmtorfinal`, launched, and used to establish external anonymized connections. The user visited onion.live, the Dread forum, and Vortex Market before creating a file named `torshoppinglist.txt`. The file was subsequently deleted and the user attempted to remove TOR via the command line (unsuccessfully), then deleted the TOR folder through the GUI and emptied the Recycle Bin. File and network evidence strongly supports the full chain of events.

---

## Response Taken

TOR usage was confirmed on endpoint `vmtorfinal`. The device was isolated and the user's direct manager was notified.

---

## Created By:
- **Author Name**: Andrew Harris
- **Author Contact**: (https://www.linkedin.com/in/andrewjharris8/)
- **Date**: April 8, 2026



---

## Additional Notes and Screenshots:
- The user's first silent install attempt failed due to using `/s` instead of `/S`, suggesting intentional evasion awareness.
- Outbound TOR connections occurred over port 443, blending with normal HTTPS traffic to evade detection.

<img width="1912" height="868" alt="showing firefox was used to launch tor" src="https://github.com/user-attachments/assets/3544aec2-a690-48b7-9dda-35c8bbfe759c" />
<img width="1863" height="820" alt="connections made to nodes" src="https://github.com/user-attachments/assets/f3b32a11-81ac-4e43-985d-3a98cb52fd3c" />
<img width="1900" height="856" alt="85 121 5 97 node" src="https://github.com/user-attachments/assets/884262cd-4e95-4d98-92ce-59df538fea43" />
<img width="1819" height="726" alt="64 65 63 30 node" src="https://github.com/user-attachments/assets/070fbeb0-dbd3-45eb-99b2-0fed69facae5" />

---

## Revision History:
| **Version** | **Changes** | **Date** | **Modified By** |
|---|---|---|---|
| 1.0 | Initial draft | `April 8, 2026` | `Andrew Harris` |
