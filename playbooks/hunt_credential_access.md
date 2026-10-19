# Threat Hunting Playbook: In-Memory & Directory Service Credential Harvesting

## Hypothesis
Adversaries who have established unprivileged foothold access on domain-joined endpoints are actively extracting credentials from memory (e.g., via LSASS handle acquisition, living-off-the-land minidumping utilities like `comsvcs.dll` or `procdump`, and in-memory PowerShell extraction) or executing remote Active Directory DCSync queries (via DRSUAPI RPC calls) to acquire Domain Admin and Kerberos ticket-granting service accounts (`krbtgt`) while bypassing traditional static file-signature controls.

## ATT&CK Techniques Covered
- **T1003.001**: OS Credential Dumping: LSASS Memory
- **T1003.006**: OS Credential Dumping: DCSync
- **T1059.001**: Command and Scripting Interpreter: PowerShell
- **T1218.011**: Signed Binary Proxy Execution: Rundll32
- **T1087.002**: Account Discovery: Domain Account

## Data Source Requirements

| Source | Event IDs | Must-Have Field | Rationale |
|--------|-----------|-----------------|-----------|
| Sysmon Process Access | EID 10 | `SourceImage`, `TargetImage`, `GrantedAccess`, `CallTrace` | Detects handle acquisition to `lsass.exe` with memory read permissions |
| Windows Security Directory Service | EID 4662 | `Properties`, `SubjectUserName`, `AccessMask` | Identifies Active Directory object read operations matching DRS replication GUIDs |
| Sysmon Process Creation | EID 1 | `Image`, `CommandLine`, `ParentImage`, `User` | Detects LOLBin abuse (`rundll32.exe comsvcs.dll`, `procdump.exe`, `net.exe`) |
| PowerShell Operational | EID 4104 | `ScriptBlockText`, `Path` | Unveils deobfuscated in-memory credential harvesting scripts |

## Hunt Queries

### Broad Hypothesis Query (Cast Wide)
```kql
// Broad KQL: Identify non-system processes accessing LSASS or invoking known dumping arguments
let SuspiciousProcesses = DeviceProcessEvents
| where Timestamp >= ago(7d)
| where ProcessCommandLine has_any ("lsass", "MiniDump", "comsvcs", "sekurlsa", "procdump", "nanodump", "dumpert")
    or (FileName in~ ("rundll32.exe", "powershell.exe", "cmd.exe") and ProcessCommandLine has_any ("MiniDump", "#24", "dump"))
| project Timestamp, DeviceName, FileName, ProcessCommandLine, AccountName, InitiatingProcessFileName;
let LSASSAccess = DeviceEvents
| where ActionType == "ProcessAccess"
| where TargetProcessFileName =~ "lsass.exe"
| where not(InitiatingProcessFileName in~ ("csrss.exe", "svchost.exe", "services.exe", "MsMpEng.exe", "SenseCncProxy.exe"))
| project Timestamp, DeviceName, InitiatingProcessFileName, TargetProcessFileName, AdditionalFields;
SuspiciousProcesses
| union LSASSAccess
| sort by Timestamp desc
```

### Narrow, High-Confidence Hunting Variant (Sigma Format)
```yaml
title: High-Confidence In-Memory LSASS Credential Harvesting Hunt
name: hunt_suspicious_lsass_access
status: experimental
description: Identifies non-standard executables requesting read/write access to LSASS memory or invoking comsvcs minidump exports.
logsource:
  product: windows
  category: process_access
detection:
  selection_target:
    TargetImage|endswith: '\lsass.exe'
  selection_rights:
    GrantedAccess|contains:
      - '0x1010'
      - '0x1F0FFF'
      - '0x1410'
      - '0x143a'
  filter_known_system:
    SourceImage|endswith:
      - '\svchost.exe'
      - '\csrss.exe'
      - '\services.exe'
      - '\MsMpEng.exe'
      - '\taskmgr.exe'
  condition: selection_target and selection_rights and not filter_known_system
level: high
```

## Triage Decision Tree

```
[Hunt Alert Fired: Credential Access Indicator]
                     │
         Is the event EID 4662 (DCSync)?
        ┌────────────┴────────────┐
       YES                        NO
        │                         │
Is SubjectUserName a DC?     Is target process LSASS (EID 10)?
  ┌─────┴─────┐                   ┌─────┴─────┐
 YES          NO                 YES          NO (CLI Dump / LOLBin)
  │           │                   │           │
Benign     CRITICAL P1       Examine       Examine CommandLine
Replication  Containment     GrantedAccess   (e.g., comsvcs / procdump)
             Isolate DC      & CallTrace     ┌─────┴─────┐
             Rotate Krbtgt        │          Suspicious  Authorized IT Script
                             0x1010/0x1F0FFF     │             │
                             Non-standard EXE    P1 Incident   Validate Ticket
                                  │                            & Close
                             CRITICAL P1
                             Isolate Host
```

1. **If DCSync event (EID 4662)**: Check if `SubjectUserName` ends with `$` (Domain Controller machine account) or matches Entra ID sync account (`MSOL_*`).
   - If user is a standard or non-DC domain account -> **Escalate to Critical P1 Incident immediately**. Initiate AD credential recovery runbook and isolate source machine.
2. **If Process Access (EID 10)**: Inspect `SourceImage` and `CallTrace`.
   - If calling module contains `dbghelp.dll`, `dbgcore.dll`, or unbacked memory regions -> **Escalate to Tier 2 / Incident Response**.
   - If `SourceImage` is signed EDR or system monitoring agent -> Document baseline variance, check digital signature, and mark benign.
3. **If CLI LOLBin (EID 1 / 4688)**: Check command line for `comsvcs.dll` ordinal export `#24` or `MiniDump`.
   - If present -> Search file system for output `.dmp` files, acquire memory image of host, and isolate endpoint.

## Known Blind Spots
- **Bring Your Own Vulnerable Driver (BYOVD)**: Threat actors utilizing kernel-mode drivers (e.g., `mhyprot2.sys`, `RTCore64.sys`) to read physical memory bypassing user-mode handle callbacks and Sysmon EID 10.
- **Direct System Calls**: Malware employing direct or indirect syscalls to invoke `NtOpenProcess` without passing through `ntdll.dll` API hooks (mitigated in this environment by Sysmon kernel driver callback auditing).
- **Active Directory DCSync over RPC without SACL**: If SACL auditing is not configured specifically for the Directory Service Root naming context (`DC=corp,DC=local`), EID 4662 will fail to record DRSUAPI requests.
