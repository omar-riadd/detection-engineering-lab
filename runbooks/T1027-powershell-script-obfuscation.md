# Runbook: Obfuscated PowerShell Script Block with Base64 Decoding — T1027

## Alert Summary
This alert triggers when PowerShell Script Block Logging (Event ID 4104) captures execution of scripts containing in-memory Base64 decoding routines (`[System.Convert]::FromBase64String`, `[System.Text.Encoding]::Unicode.GetString`) coupled with dynamic execution evaluation (`Invoke-Expression`, `IEX`). Adversaries use encoding and obfuscation to conceal payloads, evasion functions, and credential dumping scripts from static inspection and signature-based scanning controls.

## Immediate Triage Steps
1. **Extract and Decode Script Block Content**: Retrieve `ScriptBlockText` from Event ID 4104. Isolate the encoded Base64 payload string and decode it in an isolated analysis environment (CyberChef or local Python sandbox).
2. **Analyze Deobfuscated Code**: Review the revealed script logic. Look for standard malicious behaviors: API unhooking, AMSI patching, memory injection, credential extraction, or download cradles (`DownloadString`, `DownloadFile`).
3. **Review Execution Context**: Check `Path`, `User`, and parent process lineage (Sysmon EID 1). Was PowerShell invoked with `-WindowStyle Hidden`, `-NonInteractive`, or `-ExecutionPolicy Bypass`?
4. **Identify Memory Artifacts**: Query Sysmon Event ID 7 (`ImageLoaded`) or Event ID 10 (`ProcessAccess`) to observe whether the decoded script loaded unmanaged DLLs or accessed target memory spaces.
5. **Enforce Containment**: If malicious intent is confirmed from the decoded payload, isolate the endpoint and initiate credential revocation.

## Investigation Queries
```kql
// Identify PowerShell script block logs executing Base64 decoding
Event
| where Source == "Microsoft-Windows-PowerShell" and EventID == 4104
| where EventData has_any ("FromBase64String", "[System.Convert]::FromBase64String")
| where EventData has_any ("IEX", "Invoke-Expression", "GetString")
| project TimeGenerated, Computer, RenderedDescription
```

## Escalation Criteria
Escalate to **Tier 2 / Incident Response (P2/High)** if:
- Decoded payload contains malicious indicators (AMSI bypass, Mimikatz commands, C2 stagers).
- Process ran under hidden window style or was spawned by an office application or browser.
- Associated outbound network connections to suspicious external IP addresses are observed.

## Known False Positives
- Enterprise configuration management scripts (e.g., Boxstarter, Chocolatey, software inventory scripts) encoding multi-line automation commands.

## MITRE ATT&CK Reference
- **Technique:** T1027 (Obfuscated Files or Information)
- **Tactic:** Defense Evasion

## D3FEND Countermeasure
- **Countermeasure:** Script Deobfuscation Analysis / Script Execution Analysis
- **D3FEND ID:** D3-SDA
- **Link:** https://d3fend.mitre.org/technique/d3f:ScriptDeobfuscationAnalysis/
