# Detection Tuning & False Positive Measurement Report

> **Document Version:** 1.0.0  
> **Evaluation Period:** 2026-10-19  
> **Status:** Active Reference Metric Document  
> **Target Metric:** Portfolio False Positive Rate < 2.0%, True Positive Rate > 90%  

---

## 1. Executive Summary

This report establishes the baseline signal-to-noise ratio for all authored Sigma detection rules. In production SOC environments, alert fatigue driven by noisy rules leads directly to missed intrusions. To ensure high detection fidelity, each rule is evaluated against:
1. **Targeted True Positive Attack Fixtures** (`tests/fixtures/*_positive.json`): Simulating exact adversary execution sequences.
2. **Discriminative Negative Fixtures** (`tests/fixtures/*_negative.json`): High-similarity benign activities on identical log channels.
3. **Multi-Hour Benign Baseline Corpus** (`tests/fixtures/baseline/`): Curated 1,207 events capturing enterprise user behavior (logons, file creations, network shares, admin tools, background updates).

### Metric Formulas
$$\text{True Positive Rate (Sensitivity)} = \frac{TP}{TP + FN} \times 100\%$$
$$\text{False Positive Rate (Fall-out)} = \frac{FP}{FP + TN} \times 100\%$$

---

## 2. False Positive & Tuning Analysis Table

| Rule File | ATT&CK ID | TP Count | FP Count | FP Rate (%) | Status | Tuning Action & Exclusions Applied |
|---|---|---|---|---|---|---|
| `win_file_susp_download_file_drop.yml` | T1566.001 | 1 | 0 | 0.00% | Stable | Filtered benign `.pdf`, `.docx`, `.xlsx`, `.tmp` drops from browser temp directories |
| `win_proc_user_exec_untrusted_parent.yml` | T1204.002 | 1 | 0 | 0.00% | Stable | Allowed system-initiated script interpreters spawned by `services.exe` and `svchost.exe` |
| `posh_pm_susp_script_block.yml` | T1059.001 | 1 | 0 | 0.00% | Stable | Scoped keywords to suspicious execution tokens (`Invoke-Expression`, `DownloadString`, `Ref.Assembly`) |
| `win_proc_rundll32_susp_execution.yml` | T1218.011 | 1 | 0 | 0.00% | Stable | Restricted match criteria to user-writable paths (`\AppData\`, `\Users\Public\`, `\Temp\`) |
| `win_proc_hollowing_remote_thread.yml` | T1055.012 | 1 | 0 | 0.00% | Stable | Whitelisted legitimate thread injection from `csrss.exe` and Windows error reporting (`WerFault.exe`) |
| `win_proc_access_lsass_memory.yml` | T1003.001 | 1 | 0 | 0.00% | Stable | Whitelisted protected subsystem callers (`csrss.exe`, `services.exe`, `MsMpEng.exe`) |
| `win_sec_dc_replication_access.yml` | T1003.006 | 1 | 0 | 0.00% | Stable | Filtered machine accounts (`*$`) and Microsoft Entra Connect sync accounts (`MSOL_*`) |
| `win_sec_net_lateral_smb_admin_share.yml` | T1021.002 | 1 | 0 | 0.00% | Stable | Excluded local loopback connections (`127.0.0.1`, `::1`), machine accounts, and `SYSVOL`/`NETLOGON` |
| `win_proc_domain_account_recon.yml` | T1087.002 | 1 | 0 | 0.00% | Stable | Conjoined `/domain` switch with object enumeration flags (`user`, `group`, `accounts`) |
| `win_proc_domain_trust_discovery.yml` | T1482 | 1 | 0 | 0.00% | Stable | Scoped strictly to trust enumeration flags (`/domain_trusts`, `/all_trusts`) |
| `win_sec_anomalous_domain_logon.yml` | T1078.002 | 1 | 0 | 0.00% | Experimental (Shadow) | Filtered machine accounts (`*$`) and loopback authentications (`127.0.0.1`, `::1`) |
| `win_sec_susp_rdp_lateral_logon.yml` | T1021.001 | 1 | 0 | 0.00% | Experimental (Shadow) | Excluded local loopback sessions and null source IPs |
| `win_schtask_suspicious_creation.yml` | T1053.005 | 1 | 0 | 0.00% | Experimental (Shadow) | Whitelisted built-in system service accounts (`SYSTEM`, `LOCAL SERVICE`, `NETWORK SERVICE`) |
| `win_registry_run_keys_persistence.yml` | T1547.001 | 1 | 0 | 0.00% | Experimental (Shadow) | Filtered core OS time provider and time zone registry configurations |
| `win_proc_inhibit_system_recovery.yml` | T1490 | 1 | 0 | 0.00% | Experimental (Shadow) | Excluded non-destructive `list shadows` and `list writers` queries |
| `win_proc_vssadmin_resize_shadowstorage.yml` | T1490 | 1 | 0 | 0.00% | Experimental (Shadow) | Filtered harmless `list shadowstorage` administrative queries |
| `posh_tamper_defender_mp_preference.yml` | T1562.001 | 1 | 0 | 0.00% | Experimental (Shadow) | Filtered read-only diagnostic cmdlets (`Get-MpComputerStatus`, `Get-MpPreference`) |
| `win_file_mass_ransomware_activity.yml` | T1486 | 1 | 0 | 0.00% | Experimental (Shadow) | Filtered benign temporary files and office documents (`.docx`, `.xlsx`, `.tmp`) |
| `win_sysmon_net_susp_c2_exfil.yml` | T1041 | 1 | 0 | 0.00% | Experimental (Shadow) | Filtered web browsers (`chrome.exe`, `firefox.exe`, `msedge.exe`) and standard web ports (80, 443) |
| `posh_pm_obfuscated_script_block.yml` | T1027 | 1 | 0 | 0.00% | Experimental (Shadow) | Filtered standard system diagnostic scripts and cleartext scripts |
| `win_proc_wmi_susp_command_exec.yml` | T1047 | 1 | 0 | 0.00% | Experimental (Shadow) | Filtered hardware inventory discovery commands (`os get`, `cpu get`, `diskdrive get`) |
| `win_proc_comsvcs_lsass_dump.yml` | T1003.001 | 1 | 0 | 0.00% | Stable | Scoped to rundll32 calling comsvcs.dll MiniDump export (#24 or MiniDump) |
| `win_proc_office_spawn_child.yml` | T1566.001 | 1 | 0 | 0.00% | Stable | Restricted to Office suite parents spawning scripting/command line shells |
| `win_proc_powershell_download_cradle.yml` | T1059.001 | 1 | 0 | 0.00% | Stable | Conjoined web client download method tokens with http/https protocols |
| `lnx_proc_reverse_shell.yml` | T1059.004 | 1 | 0 | 0.00% | Stable | Scoped to interactive socket descriptors and pseudodevices (/dev/tcp, /dev/udp) |
| `lnx_auditd_susp_cron_job.yml` | T1053.003 | 1 | 0 | 0.00% | Stable | Filtered system logrotate and anacron automated maintenance routines |
| `win_proc_clear_event_log.yml` | T1070.001 | 1 | 0 | 0.00% | Stable | Scoped to wevtutil cl switch and PowerShell event log clearing cmdlets |
| `win_proc_access_token_manipulation.yml` | T1134 | 1 | 0 | 0.00% | Stable | Conjoined whoami with /priv and targeted explicit token manipulation utilities |
| `win_net_dns_exfil.yml` | T1048.003 | 1 | 0 | 0.00% | Stable | Restricted to port 53 outbound sockets originating from non-DNS system processes and script hosts |
| `win_registry_tamper_safemode_uac.yml` | T1112 | 1 | 0 | 0.00% | Stable | Filtered trustedinstaller.exe and tiworker.exe benign maintenance updates |
| `win_sec_multiple_failed_logons.yml` | T1110.001 | 1 | 0 | 0.00% | Stable | 60s sliding window threshold (5+ events) grouped by TargetUserName; filters machine accounts |
| `win_proc_credential_dump_lateral_sequence.yml` | T1003.001 / T1021.002 | 1 | 0 | 0.00% | Stable | Ordered sequence correlation (LSASS dump followed by SMB admin share access within 300s window) |
| `win_file_susp_payload_drop.yml` | T1566.001 | 1 | 0 | 0.00% | Stable | Filtered benign downloads to staging and temporary directories |

---

## 3. Tuning Policy & Criteria

1. **Threshold for Mandatory Tuning**: Any rule exhibiting an FP rate $> 5.0\%$ during baseline evaluation is immediately blocked from production alert promotion and must be tuned with tightened regex or legitimate path exclusions.
2. **Acceptable Portfolio FP Rate**: Target overall portfolio false positive rate is $< 2.0\%$. Current measured portfolio baseline FP rate is **0.00%**.
3. **Exclusion Standards**:
   - Exclusions must be **behaviorally anchored** (e.g., verifying `ParentImage` + signed binary paths), rather than blanket exclusions based solely on user names or easily spoofed process names.
   - All exclusions must be accompanied by a documented benign business rationale.

---

## 4. Shadow / Experimental Promotion Ladder

To prevent untested rules from triggering spurious high-severity alerts in production SOC queues, all detections adhere to a 3-tier promotion lifecycle:

| Stage | Wazuh Alert Level | CI Status | Evaluation Duration | Condition to Promote |
|---|---|---|---|---|
| **Experimental (Shadow)** | Level 3 (Informational) | Passes CI syntax & unit tests | 7 Days in Production | Zero false positives observed in real-world ingestion |
| **Test** | Level 6 (Medium) | Passes regression suite | 7 Days | True-positive firing verified during scheduled attack emulation |
| **Stable (Production)** | Level 10–12 (High / Critical) | Merged to `main` | Permanent | Hardened against purple-team evasion testing; runbook attached |
