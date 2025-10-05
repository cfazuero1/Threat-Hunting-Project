# Threat Event: Unauthorized Tor Browser Installation & Use

Simulates a user (“bad actor”) silently installing and using Tor Browser on a Windows workstation to evade monitoring. The scenario generates realistic telemetry (process, file, network, DNS/proxy) and produces huntable Indicators of Compromise (IoCs).

> **Safety:** Run only in a segmented lab VM. Do **not** access illegal content. Keep all `.onion` references **redacted**.

---

## Objectives
- Detect **unauthorized privacy/circumvention tools**.
- Enrich **process / file / network** telemetry for hunting.
- Validate **analytic rules** and **incident response** steps.
- Produce a clean **IOC & queries pack** for reuse.

---

## Lab Prerequisites
- Windows 10/11 VM (non-admin test user).
- Logging:
  - **Windows Security** (4688 process creation).
  - **Sysmon** (recommended): IDs 1, 3, 7, 11, 13, 23.
- Optional: **EDR** (e.g., Microsoft Defender for Endpoint), **Elastic Agent**, **Splunk UF**, **Proxy/DNS** visibility.

---

## Scenario Steps (Generate Telemetry)

1. **Download** Tor Browser (portable, latest) from official site.  
2. **Silent install / extract** to user profile:
   ```bat
   tor-browser-windows-x86_64-portable-14.0.1.exe /S
   ```
3. **Launch Tor Browser** from the extracted Desktop folder.
4. **Establish connectivity** (default). Browse a few innocuous sites.  
   - For hidden-service telemetry, open a **non-operational** placeholder such as:
     ```
     [redacted-hidden-service].onion
     [redacted-hidden-service]/placeholder
     ```
5. **Create artifact** on Desktop:
   ```
   tor-shopping-list.txt
   ```
   Add benign dummy items (e.g., “test-item-1”), then **delete** the file to log FileCreate/FileDelete.
6. **Close** the browser and record timestamps.

---

## Expected Artifacts & IoCs

### File/Folder
- `C:\Users\<user>\Desktop\Tor Browser\Browser\...`
- `C:\Users\<user>\Desktop\tor-shopping-list.txt` (created then deleted)

### Processes
- Installer (portable extractor) with `/S`
- `firefox.exe` (Tor Browser) under `...\Tor Browser\Browser\`
- `tor.exe` under `...\TorBrowser\Tor\`
- Parent chain often: `explorer.exe` → installer → `firefox.exe` / `tor.exe`

### Network
- Local SOCKS proxy: `127.0.0.1:9150`
- Many short-lived outbound TLS sessions (TCP 443; sometimes 9001) to diverse IPs
- DNS to torproject domains (if not strictly portable) and update checks
- UA resembling Firefox ESR (Tor Browser variant)

---

## Detections & Hunts

### Elastic (KQL) – Process Creation
```kql
// Tor process tree (Elastic Endpoint / Sysmon via Elastic Agent)
process where event.action == "start"
and (
  process.name : ("tor.exe", "firefox.exe")
  and process.executable : ("*\\Tor Browser\\Browser\\*", "*\\TorBrowser\\Tor\\*")
)
```

```kql
// Silent portable extraction (installer with /S)
process where event.action == "start"
and process.command_line : "*tor-browser* /S*"
```

### Elastic (KQL) – Network
```kql
// Local SOCKS proxy usage
network where destination.ip == "127.0.0.1" and destination.port == 9150
| stats count() by host.hostname, user.name, process.name, process.pid
```

```kql
// High IP churn over TLS (Tor-like pattern)
network where destination.port in (443, 9001)
| stats
    dc(destination.ip) as unique_ips,
    count() as events
  by host.hostname, user.name, process.name, process.pid, span(@timestamp, 15m)
| where unique_ips >= 20 and events >= 40
```

### Microsoft Defender for Endpoint (KQL)
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("tor.exe","firefox.exe")
| where FolderPath has_any ("\\Desktop\\Tor Browser\\Browser","\\TorBrowser\\Tor")
```

```kql
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where LocalIP == "127.0.0.1" and LocalPort == 9150
| summarize conn=count(), unique_rips=dcount(RemoteIP) by DeviceName, bin(Timestamp, 15m)
| where unique_rips >= 10
```

### Splunk (Sysmon)
```spl
// ProcessCreate
index=sysmon (EventCode=1)
(Image="*\\tor.exe" OR (Image="*\\firefox.exe" CommandLine="*\\Tor Browser\\Browser\\*"))
| stats values(CommandLine) as cmd count by host, Image, User, ParentImage
```

```spl
// Silent extractor
index=sysmon EventCode=1 CommandLine="*tor-browser* /S*"
| table _time host User Image CommandLine
```

```spl
// Local SOCKS proxy and high churn
index=sysmon EventCode=3 (DestinationPort=443 OR DestinationPort=9001 OR (DestinationIP="127.0.0.1" DestinationPort=9150))
| eval window=ceil(_time/900)  // 15m buckets
| stats dc(DestinationIP) as unique_ips, count by host, window
| where unique_ips>=20 AND count>=40
```

### Sigma (Starter Rule)

```yaml
title: Tor Browser Execution From User Desktop
id: 5b0c1a8b-3d6d-4d0f-9b7e-1a5b8db1e0a1
status: experimental
description: Detects Tor Browser and tor.exe launched from user Desktop portable path
author: Your Name
date: 2025/10/05
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 1
    Image|endswith:
      - '\\tor.exe'
      - '\\firefox.exe'
  filter_path:
    Image|contains:
      - '\\Desktop\\Tor Browser\\Browser\\'
      - '\\TorBrowser\\Tor\\'
  condition: selection and filter_path
fields:
  - Image
  - CommandLine
  - ParentImage
  - User
falsepositives:
  - Unapproved but legitimate privacy tooling by researchers
level: medium
tags:
  - attack.command_and_control
  - attack.t1090.003
```

---

## MITRE ATT&CK
- **T1090.003** – Proxy: Multi-hop Proxy (Tor)  
- **T1204** – User Execution  
- **T1071.001** – Web Protocols  
- **TA0011** – Command and Control

---

## Validation Checklist
- [ ] 4688 / Sysmon ID 1 for installer, `tor.exe`, `firefox.exe`  
- [ ] Sysmon ID 11 & 23 for `tor-shopping-list.txt` create/delete  
- [ ] Network events: `127.0.0.1:9150`, high-churn TLS to many IPs  
- [ ] Queries return hits; at least one alert fires

---

## Response Playbook (Lab)
1. **Isolate** the test host (simulated).  
2. **Terminate** `tor.exe` and Tor Browser.  
3. **Remove** portable folder & profiles.  
4. **Prevent** with AppLocker/WDAC/Defender ASR or EDR policy.  
5. **Egress controls:** block Tor directory/relay traffic; alert on local 9150.  
6. **Awareness:** reinforce acceptable-use policy with user.

---

## Deliverables (Include in Repo)
- `/queries/elastic-kql.ndjson`  
- `/queries/defender-kql.kql`  
- `/queries/splunk-savedsearches.conf`  
- `/detections/sigma/tor_portable_desktop.yml`  
- `/notes/timeline.md` (timestamps, artifacts, screenshots)  
- `/ioc/paths-hashes.csv` (hashes captured from **your** lab run)

---

## Notes on URLs
- Forum/market `.onion` addresses rotate and may be malicious or illegal. Keep them **redacted** in documentation. If you must simulate hidden-service visits, use non-resolving placeholders as shown above.

---

### Attribution & License
Created by Christian Azuero for blue-team training. Use in labs only. MIT License.
