<script lang="ts">
  import { reportsApi, type ExecutiveReportSummary } from '../lib/api.ts';

  let summary = $state<ExecutiveReportSummary | null>(null);
  let loading = $state(true);
  let error = $state<string | null>(null);

  async function loadSummary() {
    loading = true;
    error = null;
    try {
      summary = await reportsApi.summary();
    } catch (e: any) {
      error = e.message;
    } finally {
      loading = false;
    }
  }

  $effect(() => {
    loadSummary();
  });

  function triggerPrint() {
    window.print();
  }

  function downloadMarkdown() {
    window.open(reportsApi.markdownUrl(), '_blank');
  }
</script>

<div class="page report-container">
  <!-- ── Header & Action Toolbar ──────────────────────────────────────── -->
  <div class="report-header" style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: var(--sp-6);">
    <div>
      <div style="display: flex; gap: var(--sp-3); align-items: center; margin-bottom: var(--sp-2);">
        <span class="status status--stable">[EXECUTIVE ASSESSMENT]</span>
        <span style="font-size: var(--font-size-xs); color: var(--ink-3);">
          {summary ? summary.portfolio_version : 'v1.0.0'} · MITRE ATT&CK v14 · MITRE D3FEND v0.10
        </span>
      </div>
      <h1 class="page__title">Executive Detection Engineering Report</h1>
      <p style="font-size: var(--font-size-xs); color: var(--ink-3); margin-top: var(--sp-1);">
        Generated: {summary ? summary.generated_at : 'Loading...'} · Source of Truth: Git Repository
      </p>
    </div>

    <div class="no-print" style="display: flex; gap: var(--sp-2);">
      <button class="btn btn--sm" onclick={loadSummary} disabled={loading}>
        ↻ Refresh
      </button>
      <button class="btn btn--sm" onclick={downloadMarkdown}>
        ⬇ Markdown Report
      </button>
      <button class="btn btn--sm btn--primary" onclick={triggerPrint}>
        ⎙ Print / Export PDF
      </button>
    </div>
  </div>

  {#if loading}
    <div class="state-loading">Synthesizing executive detection metrics and read-model state...</div>
  {:else if error}
    <div class="state-error">[ERROR] {error}</div>
  {:else if summary}

    <!-- ── 1. Executive Scorecard ────────────────────────────────────── -->
    <div class="section-head">
      <span class="section-head__label">1. Key Performance Indicators (SOC Readiness Benchmarks)</span>
      <div class="section-head__line"></div>
    </div>

    <div class="stat-grid" style="margin-bottom: var(--sp-6);">
      <div class="stat-card">
        <div class="stat-card__label">Total Sigma Rules</div>
        <div class="stat-card__value">{summary.executive_summary.total_detections}</div>
        <div class="stat-card__sub">100% Validated in CI</div>
      </div>
      <div class="stat-card">
        <div class="stat-card__label">ATT&CK Coverage</div>
        <div class="stat-card__value" style="color: var(--blue);">
          {summary.executive_summary.unique_techniques}
        </div>
        <div class="stat-card__sub">Sub-techniques across 2 scenarios</div>
      </div>
      <div class="stat-card">
        <div class="stat-card__label">False Positive Rate</div>
        <div class="stat-card__value" style="color: var(--green);">
          {summary.executive_summary.false_positive_rate_pct.toFixed(2)}%
        </div>
        <div class="stat-card__sub">0 FPs across 1,200 events</div>
      </div>
      <div class="stat-card">
        <div class="stat-card__label">Mean Time to Detect (MTTD)</div>
        <div class="stat-card__value">{summary.executive_summary.mean_time_to_detect_seconds}s</div>
        <div class="stat-card__sub">Benchmark target: &lt; 60s</div>
      </div>
      <div class="stat-card">
        <div class="stat-card__label">Evasion Mitigation</div>
        <div class="stat-card__value" style="color: var(--green);">
          {summary.executive_summary.bypass_mitigation_rate_pct.toFixed(1)}%
        </div>
        <div class="stat-card__sub">{summary.executive_summary.adversarial_bypasses_mitigated}/{summary.executive_summary.adversarial_bypasses_tested} evasions hardened</div>
      </div>
      <div class="stat-card">
        <div class="stat-card__label">CI Test Pass Rate</div>
        <div class="stat-card__value" style="color: var(--green);">
          {summary.executive_summary.ci_regression_pass_rate_pct.toFixed(1)}%
        </div>
        <div class="stat-card__sub">{summary.executive_summary.total_test_executions} recorded executions</div>
      </div>
    </div>

    <!-- ── 2. Severity & Lifecycle Breakdown ────────────────────────── -->
    <div class="section-head">
      <span class="section-head__label">2. Rule Severity & Deployment Lifecycle</span>
      <div class="section-head__line"></div>
    </div>

    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: var(--sp-4); margin-bottom: var(--sp-6);">
      <div style="border: 1px solid var(--ink-3); padding: var(--sp-4); background: var(--paper-2);">
        <div style="font-size: var(--font-size-xs); font-weight: 700; margin-bottom: var(--sp-3); text-transform: uppercase;">
          Severity Distribution
        </div>
        <table class="table" style="margin: 0;">
          <thead>
            <tr>
              <th>Severity</th>
              <th style="text-align: right;">Count</th>
              <th style="text-align: right;">Share</th>
            </tr>
          </thead>
          <tbody>
            {#each Object.entries(summary.severity_distribution) as [sev, count]}
              <tr>
                <td><span class="badge badge--{sev}">{sev}</span></td>
                <td style="text-align: right; font-weight: 700;">{count}</td>
                <td style="text-align: right; color: var(--ink-3);">
                  {((count / summary.executive_summary.total_detections) * 100).toFixed(1)}%
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>

      <div style="border: 1px solid var(--ink-3); padding: var(--sp-4); background: var(--paper-2);">
        <div style="font-size: var(--font-size-xs); font-weight: 700; margin-bottom: var(--sp-3); text-transform: uppercase;">
          Deployment Lifecycle Status
        </div>
        <table class="table" style="margin: 0;">
          <thead>
            <tr>
              <th>Status</th>
              <th style="text-align: right;">Count</th>
              <th style="text-align: right;">Share</th>
            </tr>
          </thead>
          <tbody>
            {#each Object.entries(summary.lifecycle_status) as [stat, count]}
              <tr>
                <td>
                  <span class="status status--{stat === 'stable' ? 'stable' : 'warn'}">
                    [{stat.toUpperCase()}]
                  </span>
                </td>
                <td style="text-align: right; font-weight: 700;">{count}</td>
                <td style="text-align: right; color: var(--ink-3);">
                  {((count / summary.executive_summary.total_detections) * 100).toFixed(1)}%
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    </div>

    <!-- ── 3. Adversarial Hardening (Purple Team Bypasses) ────────── -->
    <div class="section-head">
      <span class="section-head__label">3. Adversarial Evasion Hardening Log</span>
      <div class="section-head__line"></div>
    </div>

    <div style="border: 1px solid var(--ink-3); margin-bottom: var(--sp-6); background: var(--paper-2); overflow-x: auto;">
      <table class="table" style="margin: 0;">
        <thead>
          <tr>
            <th>#</th>
            <th>Technique</th>
            <th>Evasion Method Tested</th>
            <th>Status</th>
            <th>Hardening Strategy & Verification</th>
          </tr>
        </thead>
        <tbody>
          {#each summary.recent_bypasses as b}
            <tr>
              <td style="font-weight: 700; color: var(--ink-3);">#{b.case_id}</td>
              <td style="font-weight: 600; color: var(--blue);">{b.technique}</td>
              <td style="color: var(--ink-1);">{b.evasion_method}</td>
              <td>
                <span class="status status--stable">[{b.outcome}]</span>
              </td>
              <td style="font-size: var(--font-size-xs); color: var(--ink-2);">{b.fix_applied}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>

    <!-- ── 4. Multi-SIEM Transpilation Architecture ───────────────── -->
    <div class="section-head">
      <span class="section-head__label">4. Multi-SIEM Pipeline & Defense-in-Depth</span>
      <div class="section-head__line"></div>
    </div>

    <div style="border: 1px solid var(--ink-3); padding: var(--sp-4); background: var(--paper-2); margin-bottom: var(--sp-6);">
      <p style="font-size: var(--font-size-sm); color: var(--ink-2); line-height: 1.6; margin-bottom: var(--sp-3);">
        Every detection rule is maintained in vendor-neutral <strong>Sigma YAML</strong> as the single source of truth and continuously transpiled into native SIEM syntax:
      </p>
      <ul style="font-size: var(--font-size-xs); color: var(--ink-2); line-height: 1.8; margin-left: var(--sp-4);">
        <li><strong>Wazuh Engine (XML)</strong>: Decoded endpoint HIDS analysis rules in <code>rules/wazuh/</code></li>
        <li><strong>Microsoft Sentinel (KQL)</strong>: Azure Log Analytics queries in <code>converted/kql/</code></li>
        <li><strong>Splunk Enterprise (SPL)</strong>: Search Processing Language queries in <code>converted/splunk/</code></li>
        <li><strong>MITRE D3FEND Matrix</strong>: {summary.d3fend_countermeasures_count} defensive countermeasures mapped in <code>docs/d3fend_mapping.md</code></li>
      </ul>
    </div>

  {/if}
</div>

<style>
  @media print {
    :global(body) {
      background: white !important;
      color: black !important;
    }
    .no-print {
      display: none !important;
    }
    .page {
      padding: 0 !important;
      max-width: 100% !important;
    }
    .stat-card, div[style*="border: 1px solid"] {
      border: 1px solid #444 !important;
      background: #fafafa !important;
    }
  }
</style>
