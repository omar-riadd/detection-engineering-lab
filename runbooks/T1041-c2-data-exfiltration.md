# Runbook: Suspicious Outbound C2 Network Connection via LOLBin or Utility — T1041

## Alert Summary
This alert triggers when Sysmon Event ID 3 (`NetworkConnect`) detects outbound TCP network connections initiated by native system utilities or living-off-the-land binaries (`curl.exe`, `certutil.exe`, `bitsadmin.exe`, `powershell.exe`) connecting to non-standard ports (ports other than 80 or 443). Threat actors utilize LOLBins to bypass egress filtering, exfiltrate stolen credentials and staging archives, and maintain external command-and-control communication channels.

## Immediate Triage Steps
1. **Analyze Destination Address & Port**: Check `DestinationIp`, `DestinationHostname`, and `DestinationPort`. Query IP reputation sources (VirusTotal, AbuseIPDB, internal threat intel) to determine whether the remote endpoint is a known C2 beacon or malicious infrastructure.
2. **Review Initiating Process Lineage**: Examine `Image`, `ProcessId`, and parent process information via Sysmon Event ID 1. Was `curl.exe` or `certutil.exe` spawned by an interactive command prompt, a scheduled task, or an Office document?
3. **Inspect Transferred Data & Arguments**: Check process command-line arguments for staging flags (`-d`, `--data`, `-F`, `-upload`, or file targets in `C:\Users\Public\`).
4. **Determine Scope of Exfiltration**: Cross-reference firewall and NetFlow logs for the source IP to determine the total bytes uploaded during the session window.
5. **Enforce Host & Network Containment**: Block the remote destination IP at the perimeter firewall and isolate the initiating host pending forensic triage.

## Investigation Queries
```kql
// Identify outbound network connections from command utilities to non-standard ports
DeviceNetworkEvents
| where Timestamp between (datetime({AlertTime}) - 15m .. datetime({AlertTime}) + 15m)
| where InitiatingProcessFileName in~ ("curl.exe", "certutil.exe", "bitsadmin.exe", "powershell.exe")
| where not(RemotePort in (80, 443, 53, 123))
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemoteUrl, RemotePort
```

## Escalation Criteria
Escalate to **Tier 2 / Incident Response (P2/High)** if:
- Remote destination is an unclassified external IP or dynamic DNS hostname.
- Initiating command line references sensitive file paths, credential dumps, or zipped staging archives.
- Multiple hosts connect to the identical external IP address.

## Known False Positives
- Developers or DevOps engineers using `curl` or `powershell` for custom automated scripts against non-standard internal API ports (must verify user role and script validity).

## MITRE ATT&CK Reference
- **Technique:** T1041 (Exfiltration Over C2 Channel)
- **Tactic:** Exfiltration, Command and Control

## D3FEND Countermeasure
- **Countermeasure:** Outbound Traffic Analysis / Network Traffic Filtering
- **D3FEND ID:** D3-OTA
- **Link:** https://d3fend.mitre.org/technique/d3f:OutboundTrafficAnalysis/
