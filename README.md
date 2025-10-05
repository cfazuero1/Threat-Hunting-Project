# Threat Hunting TOR Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/cfazuero1/Threat-Hunting-Project/blob/main/Threat_Hunt_Event_(TOR%20Usage).md)

## Platforms and Languages Leveraged
- **Operating Systems:** Windows 10 (Azure-hosted VMs)
- **Endpoints Investigated:** `pacificrim2`
- **Primary Accounts:** `swordead` (pacificrim2)
- **EDR/Telemetry:** Microsoft Defender for Endpoint
- **Query Language:** Kusto Query Language (KQL)
- **Target Application:** Tor Browser (portable installer)

## Scenario

Management suspects that certain users may be employing the Tor Browser to bypass enterprise network controls and create unmonitored communication channels. The threat-hunt objective is to **detect, validate, and document** any Tor activity (download, installation, execution, and network connection) and determine scope and risk.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---
## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

A search of the DeviceFileEvents table for filenames containing “tor” shows that the employee account downloaded a Tor installer. Shortly after, multiple Tor-related files appeared on the Desktop, along with a file named tor-shopping-list.txt. The initial activity was recorded at Oct 5, 2025 4:50:40 PM

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "pacificrim2"
| where InitiatingProcessAccountName == "swordead"
| where FileName contains "tor"
| where Timestamp >= datetime(2024-11-08T22:14:48.6065231Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
| order by Timestamp desc  
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/71402e84-8767-44f8-908c-1805be31122d">

---

### 2. Searched the `DeviceProcessEvents` Table

At 5:22:10 PM on October 5, 2025, a process creation event in the DeviceProcessEvents table was recorded on the device pacificrim2 under the account swordead. The action type logged was ProcessCreated, indicating the execution of a file named tor-browser-windows-x86_64-portable-14.5.7.exe located in the directory C:\Users\swordead\Downloads\. The process was initiated with the command line tor-browser-windows-x86_64-portable-14.5.7.exe /S, suggesting a silent installation of the Tor browser. The file’s integrity was verified with the SHA256 hash 61cff349bbc25b2f022fd424999bd334b26eebf2246fe2ba95ebba42fc490b2e.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "pacificrim2"
| where InitiatingProcessAccountName == "swordead"
| where ProcessCommandLine startswith "tor-browser-windows-x86_64-portable-"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/b07ac4b4-9cb3-4834-8fac-9f5f29709d78">

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

An examination of the DeviceProcessEvents table revealed that the user employee executed the Tor browser at Oct 5, 2025 4:19:16 PM. Subsequent analysis identified multiple related processes, including several instances of firefox.exe (Tor) and tor.exe, indicating continued Tor browser activity following the initial launch.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "threat-hunt-lab"  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/b13707ae-8c2d-4081-a381-2b521d3a0d8f">

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

A search of the DeviceNetworkEvents table was conducted to identify any network connections established by the Tor browser using known Tor-related ports. At Oct 5, 2025, 4:22:07 PM, an employee operating on the “threat-hunt-lab” workstation successfully established a connection to the remote IP address 198.244.212.57 over port 9001. This connection was initiated by the process tor.exe, located in the directory: C:\Users\employee\Desktop\tor browser\Browser\TorBrowser\tor\tor.exe. In addition to this event, several other outbound connections were observed to external sites over port 443, indicating potential secondary communication activity via standard HTTPS channels.

**Query used to locate events:**

```kql
let AccName = "InitiatingProcessAccountName";
DeviceNetworkEvents
| where DeviceName == "pacificrim2"
| where ActionType == "ConnectionSuccess"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where AccName != "system" and AccName != 'network service' and AccName != 'local service'
| where RemotePort in ("9001", "9002", "9040", "9050", "9051", "9150", "80", "443")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/87a02b5b-7d12-4f53-9255-f5e750d0e3cb">

---

## Chronological Event Timeline 

| # | Event Type                               | Timestamp (Local Time)      | Event Description                                                                                                                                      | Action                    | File / Process Details                                       | File Path / Network Info                                                                 |
|---|------------------------------------------|-----------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------|---------------------------|--------------------------------------------------------------|-------------------------------------------------------------------------------------------|
| 1 | File Download – Tor Installer            | Oct 5, 2025 4:14:48 PM      | The user “employee” downloaded the file tor-browser-windows-x86_64-portable-14.0.1.exe to the Downloads folder.                                       | File download detected    | File: tor-browser-windows-x86_64-portable-14.0.1.exe         | C:\\Users\\employee\\Downloads\\tor-browser-windows-x86_64-portable-14.0.1.exe           |
| 2 | Process Execution – Tor Browser Installation | Oct 5, 2025 4:16:47 PM   | The user “employee” executed tor-browser-windows-x86_64-portable-14.0.1.exe in silent mode, initiating a background installation of the Tor browser. | Process creation detected | Command: tor-browser-windows-x86_64-portable-14.0.1.exe /S   | C:\\Users\\employee\\Downloads\\tor-browser-windows-x86_64-portable-14.0.1.exe           |
| 3 | Process Execution – Tor Browser Launch   | Oct 5, 2025 4:17:21 PM      | The user “employee” opened the Tor browser. Subsequent processes such as firefox.exe and tor.exe were created, confirming the browser launched successfully. | Process creation detected | Processes: firefox.exe, tor.exe                              | C:\\Users\\employee\\Desktop\\Tor Browser\\Browser\\TorBrowser\\tor\\tor.exe             |
| 4 | Network Connection – Tor Network         | Oct 5, 2025 4:18:01 PM      | A network connection to IP 198.244.212.57 on port 9001 was established using tor.exe, confirming Tor network activity.                                | Connection success        | Process: tor.exe                                             | C:\\Users\\employee\\Desktop\\tor browser\\browser\\torbrowser\\tor\\tor.exe             |


---

## Summary

On Oct 5, 2025, the employee user downloaded tor-browser-windows-x86_64-portable-14.0.1.exe at 4:14:48 PM to the Downloads folder, executed it in silent mode (/S) at 4:16:47 PM to install Tor, and launched the browser at 4:17:21 PM, spawning firefox.exe and tor.exe processes. Minutes later, at 4:18:01 PM, tor.exe established an outbound connection to 198.244.212.57:9001, confirming active Tor network use from the host.

---

## Response Taken

TOR usage was confirmed on endpoint pacificrim2 by user swordead. The device was isolated and the user's direct manager was notified.

---
