# Runbook: Inhibit System Recovery via Vssadmin, Wbadmin, or Bcdedit — T1490

## Alert Summary
This alert triggers when Sysmon Event ID 1 (`ProcessCreate`) or Security Event ID 4688 detects command-line execution patterns designed to destroy volume shadow copies (`vssadmin delete shadows`), invalidate backup catalogs (`wbadmin delete catalog`), or disable Windows boot recovery configurations (`bcdedit /set {default} recoveryenabled no`). Ransomware threat actors (e.g., Conti, LockBit, Black Basta) execute these precursor commands immediately before file encryption to prevent victims from restoring data from local snapshots.

## Immediate Triage Steps
1. **Identify Executing Command and Host**: Examine `CommandLine`, `Image`, `Computer`, and `User`. Confirm if the command includes destructive arguments (`delete shadows /all /quiet`, `delete catalog -quiet`, `recoveryenabled no`, `ignoreallfailures`).
2. **Review Process Ancestry**: Inspect `ParentImage` and `ParentCommandLine`.
   - Critical: Spawning from interactive `cmd.exe`, `powershell.exe`, or unapproved binary in `C:\Users\Public\`, `C:\Windows\Temp\`, or network share.
   - Low risk: Authorized enterprise backup software running during a documented maintenance window.
3. **Check for Simultaneous Defense Tampering**: Search host telemetry for Defender disabling commands (`Set-MpPreference -DisableRealtimeMonitoring`) or service stop commands (`net stop`, `sc stop`).
4. **Inspect for Burst File Encryption Activity**: Query Sysmon Event ID 11 (`FileCreate`) or Security Event ID 4663 for mass file creation/access with ransomware extensions (`.lockbit`, `.conti`, `.encrypted`).
5. **Immediate P1 Containment**: If unauthorized, **isolate the host from the network immediately** and terminate the parent process tree to halt impending encryption.

## Investigation Queries
```kql
// Identify system recovery destruction precursor commands
DeviceProcessEvents
| where Timestamp between (datetime({AlertTime}) - 15m .. datetime({AlertTime}) + 15m)
| where FileName in~ ("vssadmin.exe", "wbadmin.exe", "bcdedit.exe", "wmic.exe")
| where (FileName =~ "vssadmin.exe" and ProcessCommandLine has_all ("delete", "shadows"))
    or (FileName =~ "wbadmin.exe" and ProcessCommandLine has_all ("delete", "catalog"))
    or (FileName =~ "bcdedit.exe" and ProcessCommandLine has_any ("recoveryenabled", "ignoreallfailures"))
    or (FileName =~ "wmic.exe" and ProcessCommandLine has_all ("shadowcopy", "delete"))
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, AccountName
```

## Escalation Criteria
Escalate immediately to **Tier 2 / Incident Response (P1/Critical Emergency)** if:
- Shadow copy deletion command was executed by an unauthorized administrative user or interactive shell.
- Command is accompanied by Defender disabling or process termination commands (`taskkill /f /im ...`).
- Multiple systems across the network execute shadow copy deletion within minutes of each other.

## Known False Positives
- Extremely rare disk re-partitioning or authorized system backup reconfiguration executed by enterprise storage engineers.

## MITRE ATT&CK Reference
- **Technique:** T1490 (Inhibit System Recovery)
- **Tactic:** Impact

## D3FEND Countermeasure
- **Countermeasure:** System Recovery Configuration Protection / Process Spawn Analysis
- **D3FEND ID:** D3-SRCP
- **Link:** https://d3fend.mitre.org/technique/d3f:SystemRecoveryConfigurationProtection/
