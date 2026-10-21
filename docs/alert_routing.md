# Wazuh Alert Routing & Prioritization Policy

> **Document Status:** Complete Architecture & Implementation Guide  
> **Last Updated:** 2026-10-19  
> **Configuration File:** [`infra/wazuh/ossec_alert_routing.conf`](../infra/wazuh/ossec_alert_routing.conf)  

---

## 1. Overview & Triage Escalation Tiers

In high-throughput enterprise environments, forwarding every informational and low-level event to SOC analysts creates severe alert fatigue. To protect analyst focus, our detection architecture enforces strict, rule-level-driven alert routing:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        ALERT ROUTING ARCHITECTURE                      │
├─────────────┬─────────────┬─────────────────────┬──────────────────────┤
│ Severity    │ Wazuh Level │ Target Destination  │ Notification Method  │
├─────────────┼─────────────┼─────────────────────┼──────────────────────┤
│ Informational│ 3           │ Standard Index      │ Silent Indexing only │
│ Low (Shadow)│ 6           │ Standard Index      │ Daily Shadow Report  │
│ High        │ 10          │ Priority Index      │ SOC Tier 2 Email     │
│ Critical    │ 12          │ Priority Index      │ PagerDuty / Webhook  │
└─────────────┴─────────────┴─────────────────────┴──────────────────────┘
```

---

## 2. Routing Rules & Pipeline Implementation

### 2.1 Low Severity & Shadow Deployments (Level 3 & 6)
- **Rules Covered:** New rules deployed in shadow mode (7-day evaluation window) and baseline telemetry events.
- **Routing:** Evaluated silently by `analysisd`, written to `/var/ossec/logs/alerts/alerts.json`, and indexed into `wazuh-alerts-standard-*`.
- **Analyst Impact:** No pager or email interrupts. Analysts query this index during weekly tuning and false positive reviews.

### 2.2 High Severity Detections (Level 10)
- **Rules Covered:** Confirmed post-exploitation activities including Rundll32 proxy execution (`T1218.011`), C2 beaconing (`T1041`), Scheduled Task persistence (`T1053.005`), and Defense Impairment (`T1562.001`).
- **Routing:** 
  - Written immediately to dedicated priority index: `wazuh-alerts-priority-*`.
  - Dispatched via SMTP to Tier-2 SOC analysts (`soc-tier2@corp.local`).
  - Webhook notification pushed to SOC Slack/Teams incident triage channel.

### 2.3 Critical Severity Detections (Level 12)
- **Rules Covered:** Active intrusion objectives with immediate existential risk to the enterprise:
  - LSASS Credential Dumping (`T1003.001`)
  - DCSync Active Directory Replication (`T1003.006`)
  - Process Hollowing Remote Thread Injection (`T1055.012`)
  - Inhibit System Recovery / VSS Deletion (`T1490`)
  - Ransomware Mass Encryption Burst (`T1486`)
- **Routing:**
  - Emergency notification sent via high-priority email to `incident-response@corp.local`.
  - Real-time JSON payload delivered to Incident Response on-call rotation (PagerDuty webhook).
  - SIEM syslog forwarder relays raw JSON to cold storage syslog mirror for chain-of-custody preservation.

---

## 3. Configuration Verification

To apply and verify the alert routing policy in the Wazuh manager:

```bash
# 1. Backup existing configuration
cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.bak

# 2. Append alert routing blocks from infra/wazuh/ossec_alert_routing.conf
# 3. Test configuration syntax
/var/ossec/bin/wazuh-analysisd -t

# 4. Restart manager to activate routing
systemctl restart wazuh-manager
```
