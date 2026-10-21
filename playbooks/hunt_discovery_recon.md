# Threat Hunting Playbook: Active Directory Reconnaissance & Trust Discovery

## Hypothesis
Adversaries who have obtained unprivileged foothold execution within the domain environment systematically perform Active Directory enumeration—querying domain user accounts, administrative groups, domain controllers, and cross-forest trust relationships via living-off-the-land utilities (`net.exe`, `nltest.exe`, `dsquery.exe`, PowerShell AD cmdlets) or in-memory LDAP tools—to construct network ingress maps and prioritize privileged targets before initiating rapid lateral movement (e.g., over SMB administrative shares or Remote Desktop).

## ATT&CK Techniques Covered
- **T1087.002**: Account Discovery: Domain Account (`net user /domain`, `net group "Domain Admins" /domain`)
- **T1482**: Domain Trust Discovery (`nltest /domain_trusts`, `nltest /all_trusts`)
- **T1021.002**: Lateral Movement: SMB/Windows Admin Shares (`IPC$`, `C$`, `ADMIN$`)
- **T1069.002**: Permission Groups Discovery: Domain Groups
- **T1018**: Remote System Discovery

## Data Source Requirements

| Source | Event IDs | Must-Have Field | Rationale |
|--------|-----------|-----------------|-----------|
| Sysmon Process Creation | EID 1 | `Image`, `CommandLine`, `ParentImage`, `User` | Detects LOLBin discovery utilities (`net.exe`, `net1.exe`, `nltest.exe`, `dsquery.exe`) |
| Windows Security Process Auditing | EID 4688 | `NewProcessName`, `CommandLine`, `SubjectUserName` | Captures command-line arguments on hosts where Sysmon is absent |
| Windows Security Directory Service | EID 4661 / 4662 | `ObjectName`, `AccessMask`, `SubjectUserName` | Audits direct SAMR and LDAP queries targeting sensitive directory objects |
| Windows Security Share Access | EID 5140 | `ShareName`, `IpAddress`, `SubjectUserName` | Detects post-reconnaissance lateral access to network shares |
| Windows Security Network Logon | EID 4624 (LogonType 3) | `TargetUserName`, `IpAddress`, `WorkstationName` | Correlates recon origin with remote authentication sessions |

## Hunt Queries

### Broad Hypothesis Query (Cast Wide)
```kql
// Broad KQL: Identify domain account and trust reconnaissance executed from non-admin endpoints
let ReconProcesses = DeviceProcessEvents
| where Timestamp >= ago(7d)
| where (FileName in~ ("net.exe", "net1.exe", "nltest.exe", "dsquery.exe", "dsget.exe", "csvde.exe", "ldifde.exe") 
         and ProcessCommandLine has_any ("/domain", "domain_trusts", "all_trusts", "domain_controllers", "dclist", "/user", "/group", "administrators", "Domain Admins", "Enterprise Admins"))
    or (FileName in~ ("powershell.exe", "pwsh.exe") 
         and ProcessCommandLine has_any ("Get-ADUser", "Get-ADComputer", "Get-ADGroupMember", "Get-DomainTrust", "Get-NetUser", "Get-NetDomainTrust", "Invoke-BloodHound"))
| project Timestamp, DeviceName, ActionType="Recon_Execution", InitiatingProcessFileName, FileName, ProcessCommandLine, AccountName;
let LateralShareAccess = SecurityEvent
| where Timestamp >= ago(7d)
| where EventID == 5140
| where ShareName in~ (@"\\*\IPC$", @"\\*\C$", @"\\*\ADMIN$")
| project Timestamp, DeviceName=Computer, ActionType="Lateral_Share_Access", InitiatingProcessFileName="System", FileName="smb", ProcessCommandLine=ShareName, AccountName=SubjectUserName;
ReconProcesses
| union LateralShareAccess
| sort by Timestamp desc
```

### Narrow, High-Confidence Hunting Variant (Sigma Format)
```yaml
title: High-Confidence Active Directory Domain Account and Trust Enumeration
name: hunt_ad_domain_trust_recon
status: experimental
description: Identifies command execution sequences designed to map Active Directory users, privileged groups, and cross-forest trusts from interactive user sessions.
logsource:
  product: windows
  category: process_creation
detection:
  selection_net:
    Image|endswith:
      - '\net.exe'
      - '\net1.exe'
    CommandLine|contains:
      - '/domain'
    CommandLine|contains:
      - 'user'
      - 'group'
      - 'accounts'
      - 'administrators'
  selection_nltest:
    Image|endswith: '\nltest.exe'
    CommandLine|contains:
      - 'domain_trusts'
      - 'all_trusts'
      - 'dclist'
  filter_system:
    User|endswith:
      - '$'
      - '\SYSTEM'
  condition: (selection_net or selection_nltest) and not filter_system
level: high
```

## Triage Decision Tree

```
[Hunt Alert Fired: AD Reconnaissance Indicator]
                       │
       Is executing account a Domain Admin or IT Admin?
             ┌─────────┴─────────┐
            YES                  NO
             │                   │
  Is there an active change   Check initiating process parent
  ticket or scheduled audit?  (e.g., cmd.exe spawned from Office/browser?)
        ┌────┴────┐                    ┌────┴────┐
       YES        NO                  YES        NO (Standard shell)
        │         │                    │         │
    Validate    Contact Admin      CRITICAL P1   Check for follow-on
    Ticket &    for Verification   Immediate     lateral share access (EID 5140)
    Close       Possible Cred      Containment   within 30-300 seconds
                Theft Investigation     │             ┌────┴────┐
                                   Isolate Host      YES        NO
                                                      │         │
                                                 CRITICAL P1   Escalate to
                                                 Isolate Both  Tier 2 Analyst
                                                 Endpoints     Deep Hunt
```

1. **If Domain Reconnaissance via `net.exe` / `nltest.exe` (T1087.002 / T1482)**:
   - Identify the source host and `SubjectUserName`.
   - Check process lineage: If spawned from `WINWORD.EXE`, `EXCEL.EXE`, `powershell.exe`, or unsigned script interpreters in user directories (`\AppData\`, `\Temp\`) -> **Immediate Critical P1 Escalation**.
2. **Evaluate Follow-on Lateral Movement (T1021.002)**:
   - Query Windows Security Event ID 5140 and Event ID 4624 (LogonType 3) from the same source IP within 60 minutes of recon commands.
   - If network connections to `IPC$`, `C$`, or `ADMIN$` shares on remote endpoints occur -> **Active Lateral Spread Confirmed**. Isolate both source and destination machines immediately.
3. **Inspect for Automated Tooling (BloodHound / SharpHound / PowerView)**:
   - Search disk for output archives: `*.zip`, `*_bloodhound.json`, `*_users.json`.
   - Query endpoint DNS telemetry for unusual LDAP / RPC query bursts targeting Domain Controllers.
   - If confirmed -> Revoke active Kerberos tickets for affected user sessions and reset domain passwords.

## Known Blind Spots
- **In-Memory .NET / Cobalt Strike BOF Execution**: Adversaries using Cobalt Strike Beacon Object Files (BOFs) or `execute-assembly` running SharpHound or PowerView in-memory without spawning `net.exe` or `nltest.exe` CLI processes. Detections must leverage ETW (`Microsoft-Windows-LDAP-Client` event ID 30) or process memory injection auditing (Sysmon EID 10).
- **Encrypted LDAPS Communication**: LDAP queries over TLS/SSL (port 636) are encrypted on the wire; without Directory Service diagnostic logging (NTDS Event ID 1644 - Expensive / Inefficient Queries), broad directory queries cannot be dissected at the network boundary.
- **Native Windows API SAMR Calls**: Direct invocation of `SamConnect`, `SamLookupNamesInDomain`, and `SamQueryInformationUser` via RPC bypasses command-line auditing completely.
