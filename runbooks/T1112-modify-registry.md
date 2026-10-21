# Runbook: Modify Registry for Defense Evasion and SafeMode Persistence — T1112

## Alert Summary
This alert triggers when Sysmon Event ID 13 (Registry Value Set) detects modification to critical Windows security registry values or SafeMode boot persistence keys. Specifically, this detection monitors for:
- Disabling User Account Control (UAC) via `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA` set to `0`.
- Disabling Local Security Authority (LSA) Protected Process Light (PPL) via `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL` set to `0`.
- Registering malicious persistence services under `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal\` or `SafeBoot\Network\`.

Adversaries modify these registry keys to evade detection, disable operating system defensive boundaries, or force the host into SafeMode (via `bcdedit /set safeboot minimal`) where ransomware payloads execute unimpeded because third-party EDR/antivirus drivers are not loaded by default.

## Immediate Triage Steps
1. **Identify Modifying Process and User**: Inspect `Image`, `ProcessCommandLine`, `User`, and `ParentImage`. Legitimate updates to system policies typically originate from `trustedinstaller.exe`, `tiworker.exe`, or Group Policy (`svchost.exe -k netsvcs`). Any modification by interactive cmd.exe, powershell.exe, reg.exe, or third-party executables is suspicious.
2. **Determine Exact Value Changed**: Extract `TargetObject` and `Details` from the registry event. Verify if `EnableLUA` was set to `0`, `RunAsPPL` was removed/zeroed, or if a new service key was created under `SafeBoot`.
3. **Check for Preceding Privilege Escalation**: Disabling UAC or modifying SafeBoot requires elevated administrative (`NT AUTHORITY\SYSTEM` or local admin) privileges. Check for preceding token manipulation (T1134), credential dumping (T1003), or exploit artifacts.
4. **Inspect Boot Configuration (BCDEdit)**: Check Sysmon Event ID 1 for execution of `bcdedit.exe /set {current} safeboot minimal` or `/set safeboot network`. If paired with SafeBoot registry modifications, ransomware deployment or aggressive defense evasion is imminent.
5. **Immediate Remediation**: Revert the tampered registry key to secure enterprise defaults. If SafeMode boot tampering is confirmed, isolate the endpoint immediately to prevent automated reboot into SafeMode.

## Investigation Queries
```kql
// Identify tampering with UAC, RunAsPPL, or SafeBoot registry keys
DeviceRegistryEvents
| where Timestamp between (datetime({AlertTime}) - 30m .. datetime({AlertTime}) + 10m)
| where DeviceName == "{DeviceName}"
| where RegistryKey has_any (
    @"\Control\SafeBoot\Minimal\",
    @"\Control\SafeBoot\Network\",
    @"\Policies\System\EnableLUA",
    @"\Control\Lsa\RunAsPPL"
  )
| where InitiatingProcessFileName !in~ ("trustedinstaller.exe", "tiworker.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RegistryKey, RegistryValueName, RegistryValueData
```

## Escalation Criteria
Escalate immediately to **Tier 2 / Incident Response (P1/Critical)** if:
- SafeBoot registry additions are detected in conjunction with `bcdedit /set safeboot` commands.
- `EnableLUA` or `RunAsPPL` was disabled by an unapproved interactive user or script.
- Registry tampering was followed by volume shadow copy deletion (T1490) or batch file termination of security services.

## Known False Positives
- Enterprise endpoint management software (SCCM, Intune, Tanium) or Group Policy pushing authorized policy modifications fleet-wide.

## MITRE ATT&CK Reference
- **Technique:** T1112 (Modify Registry)
- **Tactic:** Defense Evasion

## D3FEND Countermeasure
- **Countermeasure:** System Init Configuration Analysis
- **D3FEND ID:** D3-SICA
- **Link:** https://d3fend.mitre.org/technique/d3f:SystemInitConfigurationAnalysis/
