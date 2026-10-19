# Runbook: Active Directory Domain Trust Discovery via Nltest — T1482

## Alert Summary
This alert triggers when Sysmon Event ID 1 (`ProcessCreate`) or Security Event ID 4688 detects execution of `nltest.exe` with domain trust enumeration switches (`/domain_trusts`, `/all_trusts`). Threat actors (including APT29 and various initial access brokers) leverage `nltest` to discover trust relationships between domains and forests, seeking transitive trust paths that allow lateral movement across corporate boundaries or toward higher-privilege environments.

## Immediate Triage Steps
1. **Identify Executing Host and User**: Check `Computer`, `User`, and `IntegrityLevel`. Is this command executing on a standard user workstation or an IT administration jump server?
2. **Review Process Lineage**: Examine `ParentImage` and `ParentCommandLine`.
   - High risk: `cmd.exe` or `powershell.exe` spawned by an office product, browser, malicious script, or running from `%TEMP%` or `%APPDATA%`.
   - Low risk: Interactive administrator shell from an authorized IT workstation.
3. **Check for Discovery Clustering**: Inspect the host timeline for associated discovery tools (`net.exe`, `dsquery`, `AdFind`, `PowerView`, `BloodHound`, or `SharpHound`).
4. **Identify Post-Discovery Actions**: Check if the trust enumeration was followed by cross-domain Kerberos ticket requests (EID 4769 with cross-domain service principals) or lateral connection attempts (SMB EID 5140 / RDP EID 4624) targeting trusted external domains.

## Investigation Queries
```kql
// Identify nltest domain trust discovery execution and surrounding commands
DeviceProcessEvents
| where Timestamp between (datetime({AlertTime}) - 15m .. datetime({AlertTime}) + 15m)
| where DeviceName == "{DeviceName}"
| where FileName =~ "nltest.exe"
| where ProcessCommandLine has_any ("/domain_trusts", "/all_trusts")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
```

## Escalation Criteria
Escalate to **Tier 2 / Incident Response (P3/Medium or P2/High)** if:
- `nltest.exe` was executed by a non-privileged user account.
- Execution occurs in conjunction with other reconnaissance or credential dumping activities (e.g., Mimikatz, BloodHound/SharpHound).
- Follow-on authentication or network connections target a newly enumerated trusted forest or domain.

## Known False Positives
- Domain administrators validating forest trust health during Active Directory maintenance or migrations.
- Commercial network asset discovery and configuration management inventory tools.

## MITRE ATT&CK Reference
- **Technique:** T1482 (Domain Trust Discovery)
- **Tactic:** Discovery

## D3FEND Countermeasure
- **Countermeasure:** Domain Trust Analysis / Process Spawn Analysis
- **D3FEND ID:** D3-DTA
- **Link:** https://d3fend.mitre.org/technique/d3f:DomainTrustAnalysis/
