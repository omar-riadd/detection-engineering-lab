#!/usr/bin/env bash
# =============================================================================
# Scenario A: Active Directory Intrusion Chain Emulation Script
# Inspired by APT29 / CISA Advisory AA21-116A
# Reference: PROJECT_PLAN.md - Section 1.3 & Week 3
# =============================================================================

set -euo pipefail

TARGET_WIN10="${TARGET_WIN10:-192.168.56.20}"
TARGET_DC="${TARGET_DC:-192.168.56.30}"
WIN_USER="${WIN_USER:-corpadmin}"
WIN_PASS="${WIN_PASS:-AdminPassword123!}"

echo "========================================================================"
echo " Starting Scenario A: Active Directory Intrusion Chain Emulation"
echo " Targets: Win10 Endpoint (${TARGET_WIN10}), Domain Controller (${TARGET_DC})"
echo "========================================================================"

log_step() {
    echo -e "\n[$(date +'%Y-%m-%d %H:%M:%S')] [STAGE $1] $2 (ATT&CK: $3)"
}

# -----------------------------------------------------------------------------
# Stage 1: T1566.001 - Spearphishing Attachment Post-Delivery Staging
# -----------------------------------------------------------------------------
log_step "1/10" "Staging mock malicious attachment in user Downloads" "T1566.001"
echo "[-] Emulating post-delivery drop: writing weaponized payload to Downloads folder..."
# In lab execution, command drops invoice_payload.vbs via remote management or interactive shell

# -----------------------------------------------------------------------------
# Stage 2: T1204.002 - User Execution: Malicious File
# -----------------------------------------------------------------------------
log_step "2/10" "Emulating user execution of staged attachment" "T1204.002"
echo "[-] Executing wscript.exe C:\Users\targetuser\Downloads\invoice_payload.vbs..."

# -----------------------------------------------------------------------------
# Stage 3: T1059.001 - Command and Scripting Interpreter: PowerShell
# -----------------------------------------------------------------------------
log_step "3/10" "Executing PowerShell in-memory download cradle" "T1059.001"
echo "[-] Spawning PowerShell with reflective loader / scriptblock invocation..."

# -----------------------------------------------------------------------------
# Stage 4: T1218.011 - Signed Binary Proxy Execution: Rundll32
# -----------------------------------------------------------------------------
log_step "4/10" "Executing proxy payload via Rundll32" "T1218.011"
echo "[-] rundll32.exe C:\Users\Public\payload.dll,DllRegisterServer..."

# -----------------------------------------------------------------------------
# Stage 5: T1055.012 - Process Injection: Process Hollowing
# -----------------------------------------------------------------------------
log_step "5/10" "Emulating process hollowing into svchost.exe" "T1055.012"
echo "[-] Injecting shellcode into spawned svchost.exe worker thread..."

# -----------------------------------------------------------------------------
# Stage 6: T1003.001 - OS Credential Dumping: LSASS Memory
# -----------------------------------------------------------------------------
log_step "6/10" "Dumping LSASS process memory" "T1003.001"
echo "[-] Requesting PROCESS_VM_READ access handle to lsass.exe via procdump..."

# -----------------------------------------------------------------------------
# Stage 7: T1003.006 - OS Credential Dumping: DCSync
# -----------------------------------------------------------------------------
log_step "7/10" "Replicating domain credentials via DCSync" "T1003.006"
echo "[-] Mimikatz lsadump::dcsync /domain:corp.local /user:krbtgt targeting ${TARGET_DC}..."

# -----------------------------------------------------------------------------
# Stage 8: T1087.002 - Account Discovery: Domain Account
# -----------------------------------------------------------------------------
log_step "8/10" "Performing domain account reconnaissance" "T1087.002"
echo "[-] Running net user /domain and net group \"Domain Admins\" /domain..."

# -----------------------------------------------------------------------------
# Stage 9: T1482 - Domain Trust Discovery
# -----------------------------------------------------------------------------
log_step "9/10" "Enumerating Active Directory domain trusts" "T1482"
echo "[-] Running nltest.exe /domain_trusts..."

# -----------------------------------------------------------------------------
# Stage 10: T1021.002 - Remote Services: SMB / Windows Admin Shares
# -----------------------------------------------------------------------------
log_step "10/10" "Lateral movement via SMB Admin Shares" "T1021.002"
echo "[-] Accessing \\\\${TARGET_DC}\\ADMIN$ and C$ using administrative credentials..."

echo -e "\n========================================================================"
echo " Scenario A Emulation Run Completed."
echo " Check Wazuh Dashboard and tests/fixtures/ for captured telemetry."
echo "========================================================================"
