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

| ATT&CK Sub-Technique | ATT&CK Name | Detection Rule (Sigma) | Triage Runbook | D3FEND Countermeasure | D3FEND ID | Architectural Defense Type |
|---|---|---|---|---|---|---|
| **T1078.002** | Valid Accounts: Domain Accounts | [`win_sec_anomalous_domain_logon.yml`](../rules/sigma/windows/proc_creation/win_sec_anomalous_domain_logon.yml) | [`T1078.002-domain-accounts-logon.md`](../runbooks/T1078.002-domain-accounts-logon.md) | [User Account Authentication Analysis](https://d3fend.mitre.org/technique/d3f:UserAccountAuthenticationAnalysis/) | **D3-UAAA** | Detect / Model |
| **T1021.001** | Remote Desktop Protocol (RDP) | [`win_sec_susp_rdp_lateral_logon.yml`](../rules/sigma/windows/network/win_sec_susp_rdp_lateral_logon.yml) | [`T1021.001-remote-desktop-rdp.md`](../runbooks/T1021.001-remote-desktop-rdp.md) | [Remote Terminal Session Analysis](https://d3fend.mitre.org/technique/d3f:RemoteTerminalSessionAnalysis/) | **D3-RTSA** | Detect / Isolate |
| **T1053.005** | Scheduled Task | [`win_schtask_suspicious_creation.yml`](../rules/sigma/windows/proc_creation/win_schtask_suspicious_creation.yml) | [`T1053.005-scheduled-task-creation.md`](../runbooks/T1053.005-scheduled-task-creation.md) | [Scheduled Job Analysis](https://d3fend.mitre.org/technique/d3f:ScheduledJobAnalysis/) | **D3-SJA** | Detect / Analyze |
| **T1547.001** | Registry Run Keys | [`win_registry_run_keys_persistence.yml`](../rules/sigma/windows/registry/win_registry_run_keys_persistence.yml) | [`T1547.001-registry-run-keys-persistence.md`](../runbooks/T1547.001-registry-run-keys-persistence.md) | [System Init Configuration Analysis](https://d3fend.mitre.org/technique/d3f:SystemInitConfigurationAnalysis/) | **D3-SICA** | Harden / Detect |
| **T1490** | Inhibit System Recovery | [`win_proc_inhibit_system_recovery.yml`](../rules/sigma/windows/proc_creation/win_proc_inhibit_system_recovery.yml) / [`win_proc_vssadmin_resize_shadowstorage.yml`](../rules/sigma/windows/proc_creation/win_proc_vssadmin_resize_shadowstorage.yml) | [`T1490-inhibit-system-recovery.md`](../runbooks/T1490-inhibit-system-recovery.md) | [System Recovery Configuration Protection](https://d3fend.mitre.org/technique/d3f:SystemRecoveryConfigurationProtection/) | **D3-SRCP** | Harden / Protect |
| **T1562.001** | Disable Windows Defender | [`posh_tamper_defender_mp_preference.yml`](../rules/sigma/windows/proc_creation/posh_tamper_defender_mp_preference.yml) | [`T1562.001-disable-windows-defender.md`](../runbooks/T1562.001-disable-windows-defender.md) | [Endpoint Protection Tamper Detection](https://d3fend.mitre.org/technique/d3f:EndpointProtectionTamperDetection/) | **D3-EPTD** | Detect / Protect |
| **T1486** | Data Encrypted for Impact | [`win_file_mass_ransomware_activity.yml`](../rules/sigma/windows/file_event/win_file_mass_ransomware_activity.yml) | [`T1486-ransomware-mass-encryption.md`](../runbooks/T1486-ransomware-mass-encryption.md) | [File Encryption Analysis](https://d3fend.mitre.org/technique/d3f:FileEncryptionAnalysis/) | **D3-FEA** | Detect / Analyze |
| **T1041** | Exfiltration Over C2 Channel | [`win_sysmon_net_susp_c2_exfil.yml`](../rules/sigma/windows/network/win_sysmon_net_susp_c2_exfil.yml) | [`T1041-c2-data-exfiltration.md`](../runbooks/T1041-c2-data-exfiltration.md) | [Outbound Traffic Analysis](https://d3fend.mitre.org/technique/d3f:OutboundTrafficAnalysis/) | **D3-OTA** | Detect / Filter |
| **T1027** | Obfuscated Files or Information | [`posh_pm_obfuscated_script_block.yml`](../rules/sigma/windows/proc_creation/posh_pm_obfuscated_script_block.yml) | [`T1027-powershell-script-obfuscation.md`](../runbooks/T1027-powershell-script-obfuscation.md) | [Script Deobfuscation Analysis](https://d3fend.mitre.org/technique/d3f:ScriptDeobfuscationAnalysis/) | **D3-SDA** | Detect / Verify |
| **T1047** | Windows Management Instrumentation | [`win_proc_wmi_susp_command_exec.yml`](../rules/sigma/windows/proc_creation/win_proc_wmi_susp_command_exec.yml) | [`T1047-wmi-remote-command-execution.md`](../runbooks/T1047-wmi-remote-command-execution.md) | [Administrative Interface Analysis](https://d3fend.mitre.org/technique/d3f:AdministrativeInterfaceAnalysis/) | **D3-AIA** | Detect / Model |

---

### Scenario C — Complementary Windows & Linux Enterprise Intrusion Detections

| ATT&CK Sub-Technique | ATT&CK Name | Detection Rule (Sigma) | Triage Runbook | D3FEND Countermeasure | D3FEND ID | Architectural Defense Type |
|---|---|---|---|---|---|---|
| **T1003.001** | LSASS Memory Dumping | [`win_proc_comsvcs_lsass_dump.yml`](../rules/sigma/windows/proc_creation/win_proc_comsvcs_lsass_dump.yml) | [`T1003.001-lsass-memory-dump.md`](../runbooks/T1003.001-lsass-memory-dump.md) | [Credential Access Interception](https://d3fend.mitre.org/technique/d3f:CredentialAccessInterception/) | **D3-CAI** | Harden / Detect |
| **T1566.001** | Spearphishing Attachment | [`win_proc_office_spawn_child.yml`](../rules/sigma/windows/proc_creation/win_proc_office_spawn_child.yml) | [`T1566.001-spearphishing-attachment.md`](../runbooks/T1566.001-spearphishing-attachment.md) | [Process Spawn Analysis](https://d3fend.mitre.org/technique/d3f:ProcessSpawnAnalysis/) | **D3-PSA** | Isolate / Detect |
| **T1059.001** | PowerShell Execution | [`win_proc_powershell_download_cradle.yml`](../rules/sigma/windows/proc_creation/win_proc_powershell_download_cradle.yml) | [`T1059.001-powershell-execution.md`](../runbooks/T1059.001-powershell-execution.md) | [Script Execution Analysis](https://d3fend.mitre.org/technique/d3f:ScriptExecutionAnalysis/) | **D3-SEA** | Detect / Verify |
| **T1059.004** | Unix Shell | [`lnx_proc_reverse_shell.yml`](../rules/sigma/linux/lnx_proc_reverse_shell.yml) | [`T1059.004-unix-shell.md`](../runbooks/T1059.004-unix-shell.md) | [Process Spawn Analysis](https://d3fend.mitre.org/technique/d3f:ProcessSpawnAnalysis/) | **D3-PSA** | Isolate / Detect |
| **T1053.003** | Scheduled Task/Job: Cron | [`lnx_auditd_susp_cron_job.yml`](../rules/sigma/linux/lnx_auditd_susp_cron_job.yml) | [`T1053.003-cron-persistence.md`](../runbooks/T1053.003-cron-persistence.md) | [Scheduled Job Analysis](https://d3fend.mitre.org/technique/d3f:ScheduledJobAnalysis/) | **D3-SJA** | Detect / Harden |

---

### Scenario D — Defense Evasion, Privilege Escalation & Alternative Exfiltration

| ATT&CK Sub-Technique | ATT&CK Name | Detection Rule (Sigma) | Triage Runbook | D3FEND Countermeasure | D3FEND ID | Architectural Defense Type |
|---|---|---|---|---|---|---|
| **T1070.001** | Clear Windows Event Logs | [`win_proc_clear_event_log.yml`](../rules/sigma/windows/proc_creation/win_proc_clear_event_log.yml) | [`T1070.001-clear-event-logs.md`](../runbooks/T1070.001-clear-event-logs.md) | [System Event Log Analysis](https://d3fend.mitre.org/technique/d3f:SystemEventLogAnalysis/) | **D3-ELA** | Detect / Verify |
| **T1134** | Access Token Manipulation | [`win_proc_access_token_manipulation.yml`](../rules/sigma/windows/proc_creation/win_proc_access_token_manipulation.yml) | [`T1134-access-token-manipulation.md`](../runbooks/T1134-access-token-manipulation.md) | [Process Spawn Analysis](https://d3fend.mitre.org/technique/d3f:ProcessSpawnAnalysis/) | **D3-PSA** | Detect / Analyze |
| **T1048.003** | DNS Exfiltration | [`win_net_dns_exfil.yml`](../rules/sigma/windows/network/win_net_dns_exfil.yml) | [`T1048.003-dns-exfiltration.md`](../runbooks/T1048.003-dns-exfiltration.md) | [Network Traffic Analysis](https://d3fend.mitre.org/technique/d3f:NetworkTrafficAnalysis/) | **D3-NTA** | Detect / Filter |
| **T1112** | Modify Registry | [`win_registry_tamper_safemode_uac.yml`](../rules/sigma/windows/registry/win_registry_tamper_safemode_uac.yml) | [`T1112-modify-registry.md`](../runbooks/T1112-modify-registry.md) | [System Init Configuration Analysis](https://d3fend.mitre.org/technique/d3f:SystemInitConfigurationAnalysis/) | **D3-SICA** | Harden / Detect |

---

### Scenario E — Multi-Event Correlation & Stateful Attack Chains

| ATT&CK Sub-Technique | ATT&CK Name | Detection Rule (Sigma) | Triage Runbook | D3FEND Countermeasure | D3FEND ID | Architectural Defense Type |
|---|---|---|---|---|---|---|
| **T1110.001** | Password Guessing / Brute Force | [`win_sec_multiple_failed_logons.yml`](../rules/sigma/windows/proc_creation/win_sec_multiple_failed_logons.yml) | [`T1110.001-password-brute-force.md`](../runbooks/T1110.001-password-brute-force.md) | [User Account Authentication Analysis](https://d3fend.mitre.org/technique/d3f:UserAccountAuthenticationAnalysis/) | **D3-UAAA** | Detect / Model |
| **T1003.001** / **T1021.002** | Credential Dumping Followed by Lateral SMB Share Access | [`win_proc_credential_dump_lateral_sequence.yml`](../rules/sigma/windows/proc_creation/win_proc_credential_dump_lateral_sequence.yml) | [`T1003.001-lsass-memory-dump.md`](../runbooks/T1003.001-lsass-memory-dump.md) | [Credential Access Interception](https://d3fend.mitre.org/technique/d3f:CredentialAccessInterception/) / [File Share Access Filtering](https://d3fend.mitre.org/technique/d3f:FileShareAccessFiltering/) | **D3-CAI** / **D3-FSAF** | Detect / Correlate |

---

## 3. Maintenance and Lifecycle

As each Sigma rule is drafted, reviewed, or hardened through purple-team testing, this table will be updated to link directly to the corresponding Sigma rule file in `rules/sigma/` and triage runbook in `runbooks/`.
