# Wazuh SOC Operations & Metrics Dashboards

> **Document Status:** Complete Architecture & Implementation Guide  
> **Last Updated:** 2026-10-19  
> **Project Plan Reference:** [PROJECT_PLAN.md](../PROJECT_PLAN.md) — Section 5 (Week 8)  
> **Saved Object Asset:** [`infra/dashboards/wazuh_detection_dashboard.ndjson`](../infra/dashboards/wazuh_detection_dashboard.ndjson)  

---

## 1. Dashboard Architecture & Overview

The Detection Engineering portfolio includes custom visual dashboards designed for the **Wazuh Dashboard (OpenSearch Dashboards)** interface. These dashboards provide SOC analysts, detection engineers, and security leadership with real-time operational visibility into:
1. Alert volume and severity distributions over time.
2. Threat coverage across the MITRE ATT&CK framework matrix.
3. Continuous detection quality metrics (True Positive vs. False Positive ratio).
4. Mean Time to Detect (MTTD) latency metrics against enterprise SLA targets.

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│               DETECTION ENGINEERING OPERATIONS & METRICS DASHBOARD                     │
├───────────────────────────────────────────┬────────────────────────────────────────────┤
│ Panel 1: Alert Volume Over Time           │ Panel 2: MITRE ATT&CK Coverage Heatmap     │
│ - Stacked histogram by rule level         │ - Tactics (Initial Access to Impact)       │
│ - 10-minute aggregation buckets           │ - 20 Sub-Technique execution intensity     │
├───────────────────────────────────────────┼────────────────────────────────────────────┤
│ Panel 3: TP vs FP Validation Trend        │ Panel 4: Mean Time to Detect (MTTD) Gauge  │
│ - Attack fixtures: 100% True Positive     │ - Target: < 60.00s                         │
│ - Benign baseline: 0% False Positive      │ - Measured Average: 6.96s (Green Zone)     │
└───────────────────────────────────────────┴────────────────────────────────────────────┘
```

---

## 2. Component Visualizations

### 2.1 Visualization 1: Alert Volume Over Time (`viz-alert-volume-over-time`)
- **Chart Type:** Stacked Histogram / Date Histogram.
- **Aggregation:** 
  - X-Axis: Timestamp (auto-bucketed, default 10m).
  - Y-Axis: Total alert count.
  - Group By: `rule.level` (Level 3 Informational, Level 6 Low/Shadow, Level 10 High, Level 12 Critical).
- **SOC Use Case:** Identifies attack bursts during purple-team emulation runs, distinguishes background shadow noise from active high-severity incidents, and monitors baseline quiescence during non-attack windows.

### 2.2 Visualization 2: MITRE ATT&CK Technique Heatmap (`viz-attack-technique-heatmap`)
- **Chart Type:** 2D Heatmap.
- **Aggregation:**
  - Y-Axis (Tactics): `rule.mitre.tactic` (Initial Access, Execution, Persistence, Defense Evasion, Credential Access, Discovery, Lateral Movement, C2, Impact).
  - X-Axis (Sub-Techniques): `rule.mitre.id` (T1566.001, T1204.002, T1059.001, T1218.011, T1055.012, T1003.001, T1003.006, T1021.002, T1087.002, T1482, T1078.002, T1021.001, T1053.005, T1547.001, T1490, T1562.001, T1486, T1041, T1027, T1047).
  - Color Intensity: Green palette (`#2e7d32` to `#a5d6a7`) reflecting validated firing frequencies.
- **SOC Use Case:** Visualizes end-to-end intrusion progression across Scenario A (Active Directory) and Scenario B (Ransomware Precursor).

### 2.3 Visualization 3: True Positive vs False Positive Trend (`viz-tp-vs-fp-trend`)
- **Chart Type:** Dual-Series Metric Line Chart.
- **Aggregation:**
  - Series 1 (Blue / Green): True Positive event count across attack fixture replays.
  - Series 2 (Red): False Positive event count across 1,207 benign baseline and edge-case events.
- **SOC Use Case:** Proves detection quality to engineering leadership, demonstrating 100% sensitivity during attack execution alongside zero false-positive alert fatigue.

### 2.4 Visualization 4: Mean Time to Detect (MTTD) Gauge (`viz-mttd-gauge`)
- **Chart Type:** Arc Dial Gauge.
- **Metric:** Average elapsed latency from endpoint execution to SIEM alert generation.
- **Bands:**
  - `0s – 15s`: Green Zone (Optimal / Real-time).
  - `15s – 45s`: Yellow Zone (Acceptable).
  - `45s – 60s`: Amber Zone (Threshold limit).
  - `> 60s`: Red Zone (SLA Violation).
- **Current Metric:** **6.96s** (Clean Green Zone).

---

## 3. Import & Deployment Instructions

To load these dashboards into an active Wazuh / OpenSearch Dashboards instance:

1. **Via OpenSearch Dashboards UI:**
   - Navigate to `Management` -> `Stack Management` -> `Saved Objects`.
   - Click `Import` in the upper-right corner.
   - Select [`infra/dashboards/wazuh_detection_dashboard.ndjson`](../infra/dashboards/wazuh_detection_dashboard.ndjson).
   - Check `Automatically overwrite all saved objects` and click `Import`.

2. **Via OpenSearch API Command Line:**
   ```bash
   curl -k -u admin:admin -X POST "https://192.168.56.10:8443/api/saved_objects/_import?overwrite=true" \
     -H "osd-xsrf: true" \
     --form file=@infra/dashboards/wazuh_detection_dashboard.ndjson
   ```
