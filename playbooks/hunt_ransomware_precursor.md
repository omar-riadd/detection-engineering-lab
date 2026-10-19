# Threat Hunting Playbook: Ransomware Precursor & Recovery Inhabitation

## Hypothesis
Adversaries who have acquired administrative or interactive foothold access across the Windows enterprise are systematically dismantling host resilience—disabling endpoint protection (Windows Defender), destroying backup recovery channels (Volume Shadow Copies, Windows Backup catalogs, system boot recovery), and deploying autostart persistence mechanisms—in the critical pre-encryption staging window (hours to minutes before mass file encryption) to eliminate victim recovery options and guarantee ransomware impact.

## ATT&CK Techniques Covered
- **T1490**: Inhibit System Recovery (vssadmin, wbadmin, bcdedit)
- **T1562.001**: Impair Defenses: Disable or Modify Tools
- **T1053.005**: Scheduled Task/Job: Scheduled Task
- **T1547.001**: Boot or Logon Autostart Execution: Registry Run Keys
- **T1027**: Obfuscated Files or Information
- **T1486**: Data Encrypted for Impact
- **T1047**: Windows Management Instrumentation

## Data Source Requirements

| Source | Event IDs | Must-Have Field | Rationale |
|--------|-----------|-----------------|-----------|
| Sysmon Process Creation | EID 1 | `Image`, `CommandLine`, `ParentImage` | Detects precursor command execution (`vssadmin`, `bcdedit`, `wbadmin`, `wmic`) |
| Windows Security Task Auditing | EID 4698 | `TaskName`, `TaskContent`, `SubjectUserName` | Detects immediate task persistence staging payload binaries |
| Sysmon Registry Value Set | EID 13 | `TargetObject`, `Details` | Audits Run/RunOnce autostart keys and Windows Defender registry tampering |
| Windows Security File System | EID 4663 | `ObjectName`, `AccessMask`, `ProcessId` | Audits burst file access patterns across critical document shares |
| Sysmon File Creation | EID 11 | `TargetFilename`, `Image` | Tracks rapid file creation with anomalous ransomware extensions |

## Hunt Queries

### Broad Hypothesis Query (Cast Wide)
```kql
// Broad KQL: Identify system recovery inhibition, defender tampering, and persistence creation
let RecoveryTamper = DeviceProcessEvents
| where Timestamp >= ago(7d)
| where (FileName in~ ("vssadmin.exe", "wbadmin.exe", "bcdedit.exe", "wmic.exe") 
         and ProcessCommandLine has_any ("delete shadows", "resize shadowstorage", "delete catalog", "recoveryenabled no", "bootstatuspolicy ignoreallfailures", "shadowcopy delete"))
    or (FileName in~ ("powershell.exe", "pwsh.exe") 
         and ProcessCommandLine has_any ("Set-MpPreference", "DisableRealtimeMonitoring", "DisableBehaviorMonitoring", "DisableScriptScanning"))
| project Timestamp, DeviceName, ActionType="Precursor_Tamper", InitiatingProcessFileName, FileName, ProcessCommandLine, AccountName;
let SuspiciousTasks = SecurityEvent
| where Timestamp >= ago(7d)
| where EventID == 4698
| where TaskContent has_any (@"C:\Users\Public", @"C:\ProgramData", @"C:\Windows\Temp", @"AppData\Local\Temp", "powershell", "cmd.exe", "cscript")
| project Timestamp, DeviceName=Computer, ActionType="Persistence_Task", InitiatingProcessFileName="svchost.exe", FileName="taskeng.exe", ProcessCommandLine=TaskName, AccountName=SubjectUserName;
RecoveryTamper
| union SuspiciousTasks
| sort by Timestamp desc
```

### Narrow, High-Confidence Hunting Variant (Sigma Format)
```yaml
title: High-Confidence System Recovery Invalidation & Defense Impairment
name: hunt_recovery_and_defense_impairment
status: experimental
description: Identifies command execution sequences designed to delete shadow copies or disable Windows Defender prior to ransomware deployment.
logsource:
  product: windows
  category: process_creation
detection:
  selection_vssadmin:
    Image|endswith: '\vssadmin.exe'
    CommandLine|contains|all:
      - 'delete'
      - 'shadows'
  selection_wbadmin:
    Image|endswith: '\wbadmin.exe'
    CommandLine|contains|all:
      - 'delete'
      - 'catalog'
  selection_bcdedit:
    Image|endswith: '\bcdedit.exe'
    CommandLine|contains:
      - 'recoveryenabled'
      - 'ignoreallfailures'
  selection_defender_tamper:
    CommandLine|contains|all:
      - 'Set-MpPreference'
      - 'DisableRealtimeMonitoring'
  condition: selection_vssadmin or selection_wbadmin or selection_bcdedit or selection_defender_tamper
level: critical
```

## Triage Decision Tree

```
[Hunt Alert Fired: Ransomware Precursor Indicator]
                           │
       Does event contain shadow copy or backup deletion?
              ┌────────────┴────────────┐
             YES                        NO
              │                         │
Is it authorized IT backup maintenance?  Is it Defender tampering or task staging?
        ┌─────┴─────┐                         ┌─────┴─────┐
       YES          NO                       YES          NO
        │           │                         │           │
Validate ticket  CRITICAL P1 EMERGENCY    Investigate  Benign Task
Close alert      Isolate Host             PowerShell   Verification
                 Terminate Process Tree   AST / EID 4104
                 Trigger Ransomware Playbook   │
                                          Confirmed Tamper
                                               │
                                          CRITICAL P1
                                          Isolate Host
```

1. **If Shadow Copy Deletion (T1490)**: Check if `vssadmin delete shadows /all /quiet`, `wbadmin delete catalog -quiet`, or `wmic shadowcopy delete` was executed.
   - Cross-reference with backup software schedules (Veeam, Commvault, Windows Backup). If no active change window exists -> **Immediate Critical P1 Ransomware Containment**: Isolate the host from the network immediately and terminate the offending process tree.
2. **If Defender Tampering (T1562.001)**: Inspect `Set-MpPreference` commands or registry alterations to `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender`.
   - If executed by standard interactive administrator shell or script -> **Escalate to Incident Response (P1)**. Re-enable Defender real-time protection, gather memory dump, and analyze process parentage.
3. **If Scheduled Task or Autostart Staged (T1053.005 / T1547.001)**: Inspect the binary payload referenced in the task XML or registry Run key.
   - If pointing to `C:\Users\Public\`, `C:\Windows\Temp\`, or `C:\ProgramData\` -> Hash the payload, check VirusTotal, submit to sandbox, and isolate endpoint.
4. **If Burst File Renames or Mass File Access Detected (T1486)**:
   - Identify if files are being encrypted or appended with custom extensions.
   - Isolate domain controllers and file storage servers immediately to halt network share encryption.

## Known Blind Spots
- **Sysmon Absence of Native File-Rename Events**: Sysmon EID 14 only audits registry renames; mass file renames cannot be observed via EID 14. Detections must rely on Sysmon EID 11 (rapid file creation), EID 23/26 (file delete), and Windows Security EID 4663 (file handle auditing).
- **Direct Raw Disk / MBR Writing**: Low-level disk lockers (e.g., HermeticWiper, NotPetya) that write directly to `\\.\PhysicalDrive0` using administrative volume handles bypass file system event auditing entirely.
- **Minimal Safe Mode Reboot**: Ransomware strains (such as Black Basta and LockBit) that configure `bcdedit /set {default} safeboot minimal` and force a system reboot, causing Windows to load without security software drivers.
