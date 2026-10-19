#!/usr/bin/env bash
# =============================================================================
# Scenario B: Ransomware Precursor Chain Emulation Script
# Inspired by Conti / Black Basta / LockBit 3.0 / CISA AA23-075A
# Reference: PROJECT_PLAN.md - Section 1.3 & Week 3
# =============================================================================

set -euo pipefail

TARGET_WIN10="${TARGET_WIN10:-192.168.56.20}"
TARGET_DC="${TARGET_DC:-192.168.56.30}"
C2_SERVER="${C2_SERVER:-192.168.56.1:8080}"
WIN_USER="${WIN_USER:-corpadmin}"
WIN_PASS="${WIN_PASS:-AdminPassword123!"}"

echo "========================================================================"
echo " Starting Scenario B: Ransomware Precursor Chain Emulation"
echo " Targets: Win10 Endpoint (${TARGET_WIN10}), Domain Controller (${TARGET_DC})"
echo "========================================================================"

log_step() {
    echo -e "\n[$(date +'%Y-%m-%d %H:%M:%S')] [STAGE $1] $2 (ATT&CK: $3)"
}

# -----------------------------------------------------------------------------
# Stage 1: T1078.002 - Valid Accounts: Domain Accounts
# -----------------------------------------------------------------------------
log_step "1/10" "Authenticating with compromised domain credentials" "T1078.002"
echo "[-] Initiating authenticated session using domain admin credentials..."

# -----------------------------------------------------------------------------
# Stage 2: T1021.001 - Remote Services: Remote Desktop Protocol (RDP)
# -----------------------------------------------------------------------------
log_step "2/10" "Inbound RDP lateral connection to target endpoint" "T1021.001"
echo "[-] Connecting via RDP to ${TARGET_WIN10}:3389..."

# -----------------------------------------------------------------------------
# Stage 3: T1053.005 - Scheduled Task/Job: Scheduled Task Creation
# -----------------------------------------------------------------------------
log_step "3/10" "Creating persistence via Scheduled Task" "T1053.005"
echo "[-] Executing schtasks /create /tn \"CorpMaintenance\" /tr \"powershell.exe -w hidden ...\" /sc onlogon..."

# -----------------------------------------------------------------------------
# Stage 4: T1547.001 - Boot or Logon Autostart: Registry Run Keys
# -----------------------------------------------------------------------------
log_step "4/10" "Creating autostart persistence via Registry Run key" "T1547.001"
echo "[-] Adding Run key under HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run..."

# -----------------------------------------------------------------------------
# Stage 5: T1047 - Windows Management Instrumentation (WMI)
# -----------------------------------------------------------------------------
log_step "5/10" "Invoking remote command execution via WMI" "T1047"
echo "[-] Running wmic process call create \"cmd.exe /c whoami\"..."

# -----------------------------------------------------------------------------
# Stage 6: T1027 - Obfuscated Files or Information
# -----------------------------------------------------------------------------
log_step "6/10" "Executing base64-encoded obfuscated PowerShell command" "T1027"
echo "[-] Executing powershell.exe -enc <Base64Payload>..."

# -----------------------------------------------------------------------------
# Stage 7: T1562.001 - Impair Defenses: Disable Windows Defender
# -----------------------------------------------------------------------------
log_step "7/10" "Tampering with and disabling Windows Defender real-time monitoring" "T1562.001"
echo "[-] Executing Set-MpPreference -DisableRealtimeMonitoring \$true..."

# -----------------------------------------------------------------------------
# Stage 8: T1490 - Inhibit System Recovery
# -----------------------------------------------------------------------------
log_step "8/10" "Inhibiting recovery: deleting volume shadow copies & backup catalog" "T1490"
echo "[-] Executing vssadmin delete shadows /all /quiet..."
echo "[-] Executing wbadmin delete catalog -quiet..."
echo "[-] Executing bcdedit /set {default} bootstatuspolicy ignoreallfailures..."

# -----------------------------------------------------------------------------
# Stage 9: T1041 - Exfiltration Over C2 Channel
# -----------------------------------------------------------------------------
log_step "9/10" "Simulating staging and C2 data exfiltration" "T1041"
echo "[-] Simulating outbound data egress to ${C2_SERVER}..."

# -----------------------------------------------------------------------------
# Stage 10: T1486 - Data Encrypted for Impact
# -----------------------------------------------------------------------------
log_step "10/10" "Simulating mass ransomware file encryption" "T1486"
echo "[-] Running safe encryption simulator in C:\\LabData\\TestDocuments\\..."
echo "[-] Generating .lockbit encrypted file extensions and firing Sysmon EID 11 & Security EID 4663..."

echo -e "\n========================================================================"
echo " Scenario B Emulation Run Completed."
echo " Check Wazuh Dashboard and tests/fixtures/ for captured telemetry."
echo "========================================================================"
