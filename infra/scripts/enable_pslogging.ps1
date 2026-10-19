<#
.SYNOPSIS
    Configures PowerShell Script Block Logging, Process Command-Line Auditing,
    and Windows Advanced Audit Policies.
.DESCRIPTION
    Fulfills Telemetry Checklist from PROJECT_PLAN.md Section 3.5:
    - PowerShell Script Block Logging enabled (EID 4104)
    - PowerShell Module Logging enabled (EID 4103)
    - Process command-line auditing enabled (EID 4688 with command lines)
    - Advanced Audit Policies:
        * Audit File System (Success/Failure) -> Required for T1486 (EID 4663)
        * Audit Directory Service Access (Success/Failure) -> Required for DCSync (EID 4662)
        * Audit Detailed Process Tracking (Success) -> EID 4688
        * Audit File Share (Success/Failure) -> Required for SMB lateral movement (EID 5140)
        * Audit Logon / Logoff (Success/Failure) -> Required for T1078, T1021.001 (EID 4624/4625)
        * Audit Other Object Access Events (Success/Failure) -> EID 4698 (Scheduled Tasks)
#>

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

Write-Output "[*] Configuring Windows Advanced Audit Policies and PowerShell Telemetry..."

# =============================================================================
# 1. PowerShell Script Block & Module Logging Configuration
# =============================================================================
$PSPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"
$ScriptBlockPath = Join-Path $PSPolicyPath "ScriptBlockLogging"
$ModuleLoggingPath = Join-Path $PSPolicyPath "ModuleLogging"
$ModuleNamesPath = Join-Path $ModuleLoggingPath "ModuleNames"

# Ensure registry paths exist
if (!(Test-Path $PSPolicyPath)) { New-Item -Path $PSPolicyPath -Force | Out-Null }
if (!(Test-Path $ScriptBlockPath)) { New-Item -Path $ScriptBlockPath -Force | Out-Null }
if (!(Test-Path $ModuleLoggingPath)) { New-Item -Path $ModuleLoggingPath -Force | Out-Null }
if (!(Test-Path $ModuleNamesPath)) { New-Item -Path $ModuleNamesPath -Force | Out-Null }

# Enable ScriptBlock Logging (EID 4104)
Set-ItemProperty -Path $ScriptBlockPath -Name "EnableScriptBlockLogging" -Value 1 -Type DWord
Set-ItemProperty -Path $ScriptBlockPath -Name "EnableScriptBlockInvocationLogging" -Value 1 -Type DWord
Write-Output "[+] PowerShell Script Block Logging (EID 4104) enabled."

# Enable Module Logging (EID 4103)
Set-ItemProperty -Path $ModuleLoggingPath -Name "EnableModuleLogging" -Value 1 -Type DWord
Set-ItemProperty -Path $ModuleNamesPath -Name "*" -Value "*" -Type String
Write-Output "[+] PowerShell Module Logging (EID 4103) enabled for all modules."

# =============================================================================
# 2. Process Command-Line Auditing (EID 4688 with CommandLine)
# =============================================================================
$SystemAuditPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
if (!(Test-Path $SystemAuditPath)) { New-Item -Path $SystemAuditPath -Force | Out-Null }

Set-ItemProperty -Path $SystemAuditPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord
Write-Output "[+] Process Command-Line Auditing (EID 4688 full command line) enabled."

# =============================================================================
# 3. Windows Advanced Audit Policies (via auditpol.exe)
# =============================================================================
# Subcategory: File System (Required for T1486 ransomware mass file access - EID 4663)
& auditpol /set /subcategory:"File System" /success:enable /failure:enable
Write-Output "[+] Advanced Audit: File System auditing (EID 4663) enabled."

# Subcategory: Directory Service Access (Required for T1003.006 DCSync - EID 4662)
& auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
Write-Output "[+] Advanced Audit: Directory Service Access (EID 4662) enabled."

# Subcategory: Process Creation (EID 4688)
& auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
Write-Output "[+] Advanced Audit: Process Creation (EID 4688) enabled."

# Subcategory: File Share (Required for T1021.002 SMB Admin Shares - EID 5140)
& auditpol /set /subcategory:"File Share" /success:enable /failure:enable
Write-Output "[+] Advanced Audit: File Share access (EID 5140) enabled."

# Subcategory: Logon & Logoff (Required for T1078.002 & T1021.001 - EID 4624 / 4625)
& auditpol /set /subcategory:"Logon" /success:enable /failure:enable
& auditpol /set /subcategory:"Special Logon" /success:enable /failure:enable
Write-Output "[+] Advanced Audit: Logon and Special Logon (EID 4624/4625) enabled."

# Subcategory: Other Object Access Events (Required for Scheduled Task creation - EID 4698)
& auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable
Write-Output "[+] Advanced Audit: Other Object Access Events (EID 4698) enabled."

# Subcategory: Security Group Management & User Account Management
& auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
& auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
Write-Output "[+] Advanced Audit: Account & Group Management auditing enabled."

# =============================================================================
# 4. Increase Event Log Buffer Sizes for Lab Baselines
# =============================================================================
$Logs = @(
    "Security",
    "Microsoft-Windows-Sysmon/Operational",
    "Microsoft-Windows-PowerShell/Operational"
)

foreach ($Log in $Logs) {
    try {
        wevtutil sl $Log /ms:104857600 # 100 MB buffer
        Write-Output "[+] Maximum log size for '$Log' set to 100MB."
    } catch {
        Write-Warning "[!] Could not resize log buffer for '$Log'."
    }
}

Write-Output "[+] Windows Telemetry and Audit Policies successfully applied."
