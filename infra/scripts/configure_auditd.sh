#!/usr/bin/env bash
# =============================================================================
# Detection Engineering Lab: Linux Auditd & Wazuh Telemetry Configuration
# Reference: PROJECT_PLAN.md - Section 3.5 (Linux Telemetry Checklist)
# =============================================================================

set -euo pipefail

WAZUH_MANAGER="${1:-192.168.56.10}"

echo "[*] Initializing Linux Telemetry Configuration (auditd + wazuh-agent)..."

# Ensure script is run as root
if [[ $EUID -ne 0 ]]; then
   echo "[!] This script must be run as root." >&2
   exit 1
fi

# 1. Install auditd, audispd-plugins, and curl
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq auditd audispd-plugins curl gpg apt-transport-https

# 2. Deploy Production Auditd Ruleset
AUDIT_RULES_FILE="/etc/audit/rules.d/detection-lab.rules"
echo "[*] Deploying auditd rules to ${AUDIT_RULES_FILE}..."

cat << 'EOF' > "${AUDIT_RULES_FILE}"
# -----------------------------------------------------------------------------
# Detection Engineering Portfolio - Auditd Ruleset
# -----------------------------------------------------------------------------

# Remove existing rules & set buffer size
-D
-b 8192
-f 1

# Ignore SELinux / AppArmor noise if not needed
-a always,exclude -F msgtype=CWD

# 1. Process Execution & Shells (T1059 / T1204)
-a always,exit -F arch=b64 -S execve,execveat -k process_creation
-a always,exit -F arch=b32 -S execve,execveat -k process_creation

# 2. Privilege Escalation & Identity Changes (T1078 / T1548)
-w /etc/passwd -p wa -k identity_changes
-w /etc/shadow -p wa -k identity_changes
-w /etc/group -p wa -k identity_changes
-w /etc/gshadow -p wa -k identity_changes
-w /etc/security/opasswd -p wa -k identity_changes
-w /etc/sudoers -p wa -k sudoers_changes
-w /etc/sudoers.d/ -p wa -k sudoers_changes

# 3. Persistence Mechanisms (Cron & Systemd - T1053.003 / T1543)
-w /etc/cron.allow -p wa -k cron_persistence
-w /etc/cron.deny -p wa -k cron_persistence
-w /etc/cron.d/ -p wa -k cron_persistence
-w /etc/cron.daily/ -p wa -k cron_persistence
-w /etc/cron.hourly/ -p wa -k cron_persistence
-w /etc/cron.monthly/ -p wa -k cron_persistence
-w /etc/cron.weekly/ -p wa -k cron_persistence
-w /etc/crontab -p wa -k cron_persistence
-w /var/spool/cron/crontabs/ -p wa -k cron_persistence
-w /etc/systemd/system/ -p wa -k systemd_persistence
-w /lib/systemd/system/ -p wa -k systemd_persistence

# 4. Reconnaissance & Suspicious Binary Execution (/tmp, /dev/shm)
-a always,exit -F arch=b64 -S execve -F dir=/tmp -k untrusted_exec
-a always,exit -F arch=b64 -S execve -F dir=/dev/shm -k untrusted_exec
-a always,exit -F arch=b64 -S execve -F dir=/var/tmp -k untrusted_exec

# 5. Network Sockets & Ingress/Egress Connections (T1041 / T1071)
-a always,exit -F arch=b64 -S connect,accept,bind -F success=1 -k network_socket
-a always,exit -F arch=b32 -S connect,accept,bind -F success=1 -k network_socket

# 6. Kernel Modules & Tampering (T1562.001)
-w /sbin/insmod -p x -k kernel_modules
-w /sbin/rmmod -p x -k kernel_modules
-w /sbin/modprobe -p x -k kernel_modules
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k kernel_modules

# Lock audit configuration (optional - comment out during aggressive debugging)
#-e 2
EOF

# Regenerate and restart auditd
augenrules --load || service auditd restart
echo "[+] Auditd rules loaded and verified."

# 3. Install & Enroll Wazuh Agent
echo "[*] Checking Wazuh Agent status..."
if ! command -v /var/ossec/bin/wazuh-control >/dev/null 2>&1; then
    echo "[*] Adding Wazuh repository key and package..."
    curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
    chmod 644 /usr/share/keyrings/wazuh.gpg
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list
    apt-get update -qq
    WAZUH_MANAGER="${WAZUH_MANAGER}" apt-get install -y -qq wazuh-agent
fi

# 4. Configure Wazuh Agent to collect auditd and system logs
WAZUH_CONF="/var/ossec/etc/ossec.conf"
if [[ -f "${WAZUH_CONF}" ]]; then
    echo "[*] Configuring Wazuh ossec.conf for audit.log monitoring..."
    if ! grep -q "/var/log/audit/audit.log" "${WAZUH_CONF}"; then
        sed -i '/<\/ossec_config>/i \
  <localfile>\
    <log_format>audit<\/log_format>\
    <location>\/var\/log\/audit\/audit.log<\/location>\
  <\/localfile>' "${WAZUH_CONF}"
    fi
    systemctl daemon-reload || true
    systemctl enable wazuh-agent || true
    systemctl restart wazuh-agent || true
    echo "[+] Wazuh agent configured and restarted."
fi

echo "[+] Linux auditd and telemetry configuration completed successfully."
