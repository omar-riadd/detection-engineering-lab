# Runbook: Access Token Manipulation and Privilege Inspection — T1134

## Alert Summary
This alert triggers when processes execute access token manipulation utilities (such as `incognito.exe`, Mimikatz token elevation cmdlets `token::elevate`, `token::impersonate`, `list_tokens`, or `DuplicateTokenEx` invocations) or execute `whoami.exe /priv` to audit sensitive user token privileges (`SeDebugPrivilege`, `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`, `SeTcbPrivilege`). Adversaries leverage token duplication and impersonation to inherit the security context of privileged accounts (e.g. `NT AUTHORITY\SYSTEM` or domain admins) without possessing plaintext credentials.

## Immediate Triage Steps
1. **Identify Executing Process and Account Context**: Inspect `Image`, `ProcessCommandLine`, `User`, `ParentImage`, and `ParentProcessCommandLine`. Determine if the activity originated from an interactive administrative session or an automated payload execution.
2. **Review Command Line and Target Tokens**: If token theft tools were used, identify the targeted PID or service account token being stolen or elevated. Check if `whoami /priv` was followed immediately by credential dumping tools (Mimikatz, comsvcs.dll, Procdump).
3. **Analyze Privileges Enumerated**: Check which privileges are held by the calling process context. `SeDebugPrivilege` enables cross-process memory inspection; `SeImpersonatePrivilege` (common in service accounts like `NETWORK SERVICE` or IIS pools) enables JuicyPotato/PrintSpoofer/RoguePotato privilege escalations to SYSTEM.
4. **Inspect Parent Process Chain**: Trace the parent process tree backward. Look for web shells (w3wp.exe spawning cmd.exe/powershell.exe), SQL server processes (sqlservr.exe), or remote execution services (psexesvc.exe, wsmprovhost.exe).
5. **Containment & Remediation**: If token manipulation is verified as unauthorized, immediately isolate the endpoint from the network. Terminate the malicious process tree and reset the credentials of any compromised accounts involved.

## Investigation Queries
```kql
// Identify token manipulation tools or privilege inspection
DeviceProcessEvents
| where Timestamp between (datetime({AlertTime}) - 30m .. datetime({AlertTime}) + 10m)
| where DeviceName == "{DeviceName}"
| where (ProcessCommandLine has_any ("list_tokens", "token::elevate", "token::impersonate", "incognito", "DuplicateTokenEx")
    or (FileName =~ "whoami.exe" and ProcessCommandLine has "/priv"))
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, AccountName
```

## Escalation Criteria
Escalate immediately to **Tier 2 / Incident Response (P1/Critical)** if:
- Token manipulation succeeded in elevating an unprivileged process or service account to `NT AUTHORITY\SYSTEM`.
- Activity was initiated from an Internet-facing service process (IIS `w3wp.exe`, `sqlservr.exe`, Tomcat).
- Token manipulation is accompanied by LSASS dumping, security software termination, or lateral SMB movement.

## Known False Positives
- System administrators or deployment scripts auditing user privileges during configuration management or troubleshooting.

## MITRE ATT&CK Reference
- **Technique:** T1134 (Access Token Manipulation)
- **Sub-techniques:** T1134.001 (Token Impersonation/Theft), T1134.002 (Create Process with Token)
- **Tactics:** Defense Evasion, Privilege Escalation

## D3FEND Countermeasure
- **Countermeasure:** Process Spawn Analysis / User Account Analysis
- **D3FEND ID:** D3-PSA
- **Link:** https://d3fend.mitre.org/technique/d3f:ProcessSpawnAnalysis/
