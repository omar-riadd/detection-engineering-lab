# Runbook: Suspicious WMI Process Call Execution via WMIC CLI — T1047

## Alert Summary
This alert triggers when Sysmon Event ID 1 (`ProcessCreate`) or Security Event ID 4688 detects command-line execution of `wmic.exe` invoking `process call create` to launch new processes. Adversaries leverage WMI to spawn processes locally or remotely across the network (`wmic /node:...`), evading direct process tree lineage inspection and executing living-off-the-land commands under the parentage of `WmiPrvSE.exe`.

## Immediate Triage Steps
1. **Identify Spawned Process and Arguments**: Inspect `CommandLine` in Event ID 1 to identify the binary being spawned (e.g., `cmd.exe /c ...`, `powershell.exe`, or malicious executables in `C:\Users\Public\`).
2. **Review User and Network Scope**: Check `User` and `CommandLine`. Was a `/node:` parameter used to target a remote network host?
3. **Correlate with WmiPrvSE.exe Spawn Events**: On the destination target system, query Sysmon Event ID 1 for processes where `ParentImage` is `C:\Windows\System32\wbem\WmiPrvSE.exe` occurring at the alert timestamp.
4. **Inspect Command Outputs**: If output redirection was specified (e.g., `> C:\Users\Public\out.txt`), locate and examine the output file for discovery or credential staging artifacts.
5. **Enforce Containment**: Terminate unauthorized processes spawned via WMI and restrict administrative WMI remote access if malicious lateral movement is detected.

## Investigation Queries
```kql
// Identify WMIC process call create executions and WmiPrvSE child processes
DeviceProcessEvents
| where Timestamp between (datetime({AlertTime}) - 15m .. datetime({AlertTime}) + 15m)
| where (FileName =~ "wmic.exe" and ProcessCommandLine has "process call create")
     or (InitiatingProcessFileName =~ "WmiPrvSE.exe" and FileName in~ ("cmd.exe", "powershell.exe", "cscript.exe", "rundll32.exe"))
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, AccountName
```

## Escalation Criteria
Escalate to **Tier 2 / Incident Response (P2/High)** if:
- `wmic.exe process call create` was used to execute commands across multiple remote network nodes.
- WMI spawned script interpreters executing encoded or hidden payloads.
- Execution occurs from an unprivileged user session or non-IT workstation.

## Known False Positives
- Enterprise systems management and inventory utilities utilizing WMIC for automated hardware or software inventory checks.

## MITRE ATT&CK Reference
- **Technique:** T1047 (Windows Management Instrumentation)
- **Tactic:** Execution

## D3FEND Countermeasure
- **Countermeasure:** Administrative Interface Analysis / Process Spawn Analysis
- **D3FEND ID:** D3-AIA
- **Link:** https://d3fend.mitre.org/technique/d3f:AdministrativeInterfaceAnalysis/
