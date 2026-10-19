# MITRE D3FEND Countermeasure Mapping Matrix

> **Document Version:** 1.0.0  
> **Last Updated:** 2026-10-19  
> **Status:** Scoped Reference Matrix  
> **Reference Standard:** [MITRE D3FEND (Defensive Tactics, Techniques, and Common Knowledge)](https://d3fend.mitre.org/)

---

## 1. Architectural Defensive Philosophy

Modern detection engineering is fundamentally incomplete if alerts exist in isolation without alignment to defensive countermeasures. Grounding detection rules in the **MITRE D3FEND** matrix enables defensive engineers to answer the critical architectural question:

> *"Is this detection rule our sole line of defense, or can the underlying attack technique be hardened, intercepted, or isolated architecturally?"*

Every detection rule authored in this project maps directly to a formal D3FEND defensive technique.

---

## 2. D3FEND Countermeasure Mapping Matrix

### Scenario A — Active Directory Intrusion Chain (APT29 / CISA AA21-116A)

| ATT&CK Sub-Technique | ATT&CK Name | Detection Rule (Sigma) | Triage Runbook | D3FEND Countermeasure | D3FEND ID | Architectural Defense Type |
|---|---|---|---|---|---|---|
| **T1566.001** | Spearphishing Attachment | [`win_file_susp_download_file_drop.yml`](../rules/sigma/windows/file_event/win_file_susp_download_file_drop.yml) | [`T1566.001-spearphishing-attachment.md`](../runbooks/T1566.001-spearphishing-attachment.md) | [Inbound Traffic Filtering](https://d3fend.mitre.org/technique/d3f:InboundTrafficFiltering/) / File Drop Isolation | **D3-ITF** | Detect / Model |
| **T1204.002** | Malicious File User Execution | [`win_proc_user_exec_untrusted_parent.yml`](../rules/sigma/windows/proc_creation/win_proc_user_exec_untrusted_parent.yml) | [`T1204.002-user-execution-malicious-file.md`](../runbooks/T1204.002-user-execution-malicious-file.md) | [Executable Allowlisting](https://d3fend.mitre.org/technique/d3f:ExecutableAllowlisting/) / Process Spawn Analysis | **D3-EAL** | Isolate / Detect |
| **T1059.001** | PowerShell Execution | [`posh_pm_susp_script_block.yml`](../rules/sigma/windows/proc_creation/posh_pm_susp_script_block.yml) | [`T1059.001-powershell-execution.md`](../runbooks/T1059.001-powershell-execution.md) | [Script Execution Analysis](https://d3fend.mitre.org/technique/d3f:ScriptExecutionAnalysis/) | **D3-SEA** | Detect / Verify |
| **T1218.011** | Rundll32 Proxy Execution | [`win_proc_rundll32_susp_execution.yml`](../rules/sigma/windows/proc_creation/win_proc_rundll32_susp_execution.yml) | [`T1218.011-rundll32-proxy-execution.md`](../runbooks/T1218.011-rundll32-proxy-execution.md) | [Process Spawn Analysis](https://d3fend.mitre.org/technique/d3f:ProcessSpawnAnalysis/) | **D3-PSA** | Detect / Analyze |
| **T1055.012** | Process Hollowing | [`win_proc_hollowing_remote_thread.yml`](../rules/sigma/windows/proc_creation/win_proc_hollowing_remote_thread.yml) | [`T1055.012-process-hollowing.md`](../runbooks/T1055.012-process-hollowing.md) | [Process Self-Modification Analysis](https://d3fend.mitre.org/technique/d3f:ProcessSelf-ModificationAnalysis/) | **D3-PSMA** | Detect / Verify |
| **T1003.001** | LSASS Memory Dumping | [`win_proc_access_lsass_memory.yml`](../rules/sigma/windows/proc_creation/win_proc_access_lsass_memory.yml) | [`T1003.001-lsass-memory-dump.md`](../runbooks/T1003.001-lsass-memory-dump.md) | [Credential Access Interception](https://d3fend.mitre.org/technique/d3f:CredentialAccessInterception/) | **D3-CAI** | Harden / Detect |
| **T1003.006** | DCSync Credential Replication | [`win_sec_dc_replication_access.yml`](../rules/sigma/windows/proc_creation/win_sec_dc_replication_access.yml) | [`T1003.006-dcsync-credential-replication.md`](../runbooks/T1003.006-dcsync-credential-replication.md) | [Directory Access Analysis](https://d3fend.mitre.org/technique/d3f:DirectoryAccessAnalysis/) | **D3-DAA** | Detect / Deceive |
| **T1021.002** | SMB/Windows Admin Shares | [`win_sec_net_lateral_smb_admin_share.yml`](../rules/sigma/windows/network/win_sec_net_lateral_smb_admin_share.yml) | [`T1021.002-smb-admin-shares.md`](../runbooks/T1021.002-smb-admin-shares.md) | [File Share Access Filtering](https://d3fend.mitre.org/technique/d3f:FileShareAccessFiltering/) | **D3-FSAF** | Harden / Detect |
| **T1087.002** | Domain Account Discovery | [`win_proc_domain_account_recon.yml`](../rules/sigma/windows/proc_creation/win_proc_domain_account_recon.yml) | [`T1087.002-domain-account-recon.md`](../runbooks/T1087.002-domain-account-recon.md) | [Directory Query Analysis](https://d3fend.mitre.org/technique/d3f:DirectoryQueryAnalysis/) | **D3-DQA** | Detect / Analyze |
| **T1482** | Domain Trust Discovery | [`win_proc_domain_trust_discovery.yml`](../rules/sigma/windows/proc_creation/win_proc_domain_trust_discovery.yml) | [`T1482-domain-trust-discovery.md`](../runbooks/T1482-domain-trust-discovery.md) | [Domain Trust Analysis](https://d3fend.mitre.org/technique/d3f:DomainTrustAnalysis/) | **D3-DTA** | Detect / Model |

---

### Scenario B — Ransomware Precursor Chain (Conti / Black Basta / LockBit)

| ATT&CK Sub-Technique | ATT&CK Name | Planned Detection Rule | D3FEND Countermeasure | D3FEND ID | Architectural Defense Type |
|---|---|---|---|---|---|
| **T1078.002** | Valid Accounts: Domain Accounts | `win_sec_anomalous_domain_logon.yml` | [User Account Authentication Analysis](https://d3fend.mitre.org/technique/d3f:UserAccountAuthenticationAnalysis/) | **D3-UAAA** | Detect / Model |
| **T1021.001** | Remote Desktop Protocol (RDP) | `win_sec_susp_rdp_lateral_logon.yml` | [Remote Terminal Session Analysis](https://d3fend.mitre.org/technique/d3f:RemoteTerminalSessionAnalysis/) | **D3-RTSA** | Detect / Isolate |
| **T1053.005** | Scheduled Task | `win_schtask_suspicious_creation.yml` | [Scheduled Job Analysis](https://d3fend.mitre.org/technique/d3f:ScheduledJobAnalysis/) | **D3-SJA** | Detect / Analyze |
| **T1547.001** | Registry Run Keys | `win_registry_run_keys_persistence.yml` | [System Init Configuration Analysis](https://d3fend.mitre.org/technique/d3f:SystemInitConfigurationAnalysis/) | **D3-SICA** | Harden / Detect |
| **T1490** | Inhibit System Recovery | `win_proc_inhibit_system_recovery.yml` | [System Recovery Configuration Protection](https://d3fend.mitre.org/technique/d3f:SystemRecoveryConfigurationProtection/) | **D3-SRCP** | Harden / Protect |
| **T1562.001** | Disable Windows Defender | `posh_tamper_defender_mp_preference.yml` | [Endpoint Protection Tamper Detection](https://d3fend.mitre.org/technique/d3f:EndpointProtectionTamperDetection/) | **D3-EPTD** | Detect / Protect |
| **T1486** | Data Encrypted for Impact | `win_file_mass_ransomware_activity.yml` | [File Encryption Analysis](https://d3fend.mitre.org/technique/d3f:FileEncryptionAnalysis/) | **D3-FEA** | Detect / Analyze |
| **T1041** | Exfiltration Over C2 Channel | `win_sysmon_net_susp_c2_exfil.yml` | [Outbound Traffic Analysis](https://d3fend.mitre.org/technique/d3f:OutboundTrafficAnalysis/) | **D3-OTA** | Detect / Filter |
| **T1027** | Obfuscated Files or Information | `posh_pm_obfuscated_script_block.yml` | [Script Deobfuscation Analysis](https://d3fend.mitre.org/technique/d3f:ScriptDeobfuscationAnalysis/) | **D3-SDA** | Detect / Verify |
| **T1047** | Windows Management Instrumentation | `win_proc_wmi_susp_command_exec.yml` | [Administrative Interface Analysis](https://d3fend.mitre.org/technique/d3f:AdministrativeInterfaceAnalysis/) | **D3-AIA** | Detect / Model |

---

## 3. Maintenance and Lifecycle

As each Sigma rule is drafted, reviewed, or hardened through purple-team testing, this table will be updated to link directly to the corresponding Sigma rule file in `rules/sigma/` and triage runbook in `runbooks/`.
