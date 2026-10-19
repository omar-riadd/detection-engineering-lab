# Runbook: Ransomware File Encryption Activity with Known Extension — T1486

## Alert Summary
This alert triggers when Sysmon Event ID 11 (`FileCreate`) detects file creation events writing files with known ransomware extensions (`.lockbit`, `.conti`, `.encrypted`, `.crypted`, `.blackbasta`, `.ryuk`) or when Windows Security Event ID 4663 indicates a massive burst of file write/access requests targeting user document libraries. This represents an active, ongoing ransomware encryption detonator executing on the host.

## Immediate Triage Steps
1. **Identify the Encrypting Process**: Check `Image`, `ProcessId`, and `User` in Event ID 11. Isolate the exact PID executing the file writes.
2. **Execute Emergency Host Isolation**: **Immediately isolate the host from the network** via EDR network containment or firewall isolation to prevent lateral encryption of mapped SMB shares (`C$`, `ADMIN$`, corporate NAS).
3. **Terminate Offending Process Tree**: Terminate the encrypting process PID and all parent/child processes immediately to limit data loss.
4. **Identify Dropped Ransom Notes**: Search the file system for newly dropped ransom notes (`readme.txt`, `restore-my-files.txt`, `HOW_TO_DECRYPT.html`) in user document directories or the desktop.
5. **Inspect Volume Shadow Copies**: Determine whether local Volume Shadow Copies are intact or if they were purged by precursor commands (`vssadmin`).

## Investigation Queries
```kql
// Identify rapid file creation with known ransomware extensions
DeviceFileEvents
| where Timestamp between (datetime({AlertTime}) - 15m .. datetime({AlertTime}) + 15m)
| where FileName endswith ".lockbit" 
     or FileName endswith ".conti" 
     or FileName endswith ".encrypted"
     or FileName endswith ".crypted"
     or FileName endswith ".blackbasta"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
```

## Escalation Criteria
Escalate immediately to **Incident Commander / Emergency IR Team (P1/Critical Major Incident)** if:
- Files on the host or mapped network drives are actively being renamed or appended with ransomware extensions.
- Ransom notes are present on user desktops.
- Multiple endpoints exhibit concurrent encryption activity (widespread ransomware campaign).

## Known False Positives
- Extremely rare third-party commercial encryption software utilizing identical extensions (must be confirmed with user and software vendor).

## MITRE ATT&CK Reference
- **Technique:** T1486 (Data Encrypted for Impact)
- **Tactic:** Impact

## D3FEND Countermeasure
- **Countermeasure:** File Encryption Analysis / File Access Pattern Analysis
- **D3FEND ID:** D3-FEA
- **Link:** https://d3fend.mitre.org/technique/d3f:FileEncryptionAnalysis/
