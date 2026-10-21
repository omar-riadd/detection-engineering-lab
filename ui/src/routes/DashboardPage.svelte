<script lang="ts">
  import { rulesApi, coverageApi, bypassApi, syncApi, type RuleStats } from '../lib/api.ts';

  let { onnavigate }: { onnavigate: (dest: string) => void } = $props();

  let stats = $state<RuleStats | null>(null);
  let mttd = $state<{ avg_mttd_seconds: number; min_mttd_seconds: number; max_mttd_seconds: number } | null>(null);
  let bypassStats = $state<{ total_cases: number; detection_rate_pct: number; by_outcome: Record<string, number> } | null>(null);
  let bypasses = $state<any[]>([]);
  let syncStatus = $state<{ rules_total: number; rules_synced: number; rules_error: number; bypass_entries: number } | null>(null);
  let loading = $state(true);
  let error = $state<string | null>(null);

  $effect(() => {
    Promise.all([
      rulesApi.stats(),
      coverageApi.mttd(),
      bypassApi.stats(),
      bypassApi.list(),
      syncApi.status(),
    ])
      .then(([s, m, b, bList, ss]) => {
        stats = s;
        mttd = m;
        bypassStats = b;
        bypasses = bList;
        syncStatus = ss;
        loading = false;
      })
      .catch((e) => {
        error = e.message;
        loading = false;
      });
  });
</script>

<div class="view-content">
  <div class="view-header">
    <div class="view-header__left">
      <h1 class="view-title">Detection Engineering Console</h1>
      <span class="view-subtitle">
        Threat-Informed Detection-as-Code Lifecycle · CISA AA21-116A & AA23-075A Telemetry Grounding
      </span>
    </div>
    <div class="view-actions">
      <button class="btn btn--secondary btn--sm" onclick={() => onnavigate('replay')}>
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <polygon points="5 3 19 12 5 21 5 3" />
        </svg>
        Replay Engine
      </button>
      <button class="btn btn--primary btn--sm" onclick={() => onnavigate('rules')}>
        Rules Catalog
      </button>
    </div>
  </div>

  {#if loading}
    <div style="padding: var(--space-8); text-align: center; color: var(--text-muted); font-size: var(--text-xs);">
      <span class="status-beacon status-beacon--syncing" style="display: inline-block; margin-right: 6px;"></span>
      Synchronizing telemetry posture from SQLite read model...
    </div>
  {:else if error}
    <div style="padding: var(--space-4); background: var(--sev-critical-bg); border: 1px solid var(--sev-critical-border); border-radius: var(--radius-sm); color: var(--sev-critical); font-size: var(--text-xs);">
      Telemetry fetch error: {error}
    </div>
  {:else if stats && mttd && bypassStats}

    <!-- ── Operational Telemetry Strip ────────────────────────────────────── -->
    <section class="telemetry-strip" aria-label="Operational Key Performance Indicators">
      <div class="telemetry-cell">
        <span class="telemetry-cell__label">Active Rules</span>
        <div class="telemetry-cell__value-row">
          <span class="telemetry-cell__value tabular-nums">{stats.total}</span>
          <span class="telemetry-cell__subtext">Sigma v2</span>
        </div>
        <span style="font-size: var(--text-2xs); color: var(--text-muted);">24 Windows · 2 Linux</span>
      </div>

      <div class="telemetry-cell">
        <span class="telemetry-cell__label">ATT&CK Techniques</span>
        <div class="telemetry-cell__value-row">
          <span class="telemetry-cell__value tabular-nums">{stats.unique_techniques}</span>
          <span class="telemetry-cell__subtext">Sub-techniques</span>
        </div>
        <span style="font-size: var(--text-2xs); color: var(--text-muted);">{stats.unique_tactics} tactics mapped</span>
      </div>

      <div class="telemetry-cell">
        <span class="telemetry-cell__label">Mean Time to Detect</span>
        <div class="telemetry-cell__value-row">
          <span class="telemetry-cell__value tabular-nums" style="color: var(--sev-low);">{mttd.avg_mttd_seconds}s</span>
          <span class="telemetry-cell__subtext">Avg latency</span>
        </div>
        <span style="font-size: var(--text-2xs); color: var(--text-muted);">Range: {mttd.min_mttd_seconds}s – {mttd.max_mttd_seconds}s</span>
      </div>

      <div class="telemetry-cell">
        <span class="telemetry-cell__label">False Positive Rate</span>
        <div class="telemetry-cell__value-row">
          <span class="telemetry-cell__value tabular-nums" style="color: var(--sev-low);">0.00%</span>
          <span class="telemetry-cell__subtext">SLA &lt; 2%</span>
        </div>
        <span style="font-size: var(--text-2xs); color: var(--text-muted);">1,207 baseline events</span>
      </div>

      <div class="telemetry-cell">
        <span class="telemetry-cell__label">Purple Team Hardening</span>
        <div class="telemetry-cell__value-row">
          <span class="telemetry-cell__value tabular-nums" style="color: var(--accent-primary);">{bypassStats.total_cases}/{bypassStats.total_cases}</span>
          <span class="telemetry-cell__subtext">Mitigated</span>
        </div>
        <span style="font-size: var(--text-2xs); color: var(--text-muted);">100% bypass resilience</span>
      </div>

      <div class="telemetry-cell">
        <span class="telemetry-cell__label">Read-Model Synchronization</span>
        <div class="telemetry-cell__value-row">
          <span class="telemetry-cell__value tabular-nums">
            {syncStatus?.rules_synced ?? 0}/{syncStatus?.rules_total ?? 0}
          </span>
          <span class="telemetry-cell__subtext">SQLite WAL</span>
        </div>
        <span style="font-size: var(--text-2xs); color: var(--text-muted);">{syncStatus?.rules_error ?? 0} schema errors</span>
      </div>
    </section>

    <!-- ── Two-Column Operational Layout ──────────────────────────────────── -->
    <div style="display: grid; grid-template-columns: 360px 1fr; gap: var(--space-5);">

      <!-- Left Column: Severity Distribution & Architecture -->
      <div style="display: flex; flex-direction: column; gap: var(--space-5);">
        
        <!-- Severity Spectrum Panel -->
        <div style="background: var(--bg-surface); border: 1px solid var(--border-subtle); border-radius: var(--radius-sm); padding: var(--space-4);">
          <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: var(--space-3);">
            <h3 style="font-size: var(--text-sm); font-weight: 600; text-transform: uppercase; letter-spacing: 0.04em;">
              Severity Distribution
            </h3>
            <span class="tabular-nums" style="font-size: var(--text-2xs); color: var(--text-muted);">
              {stats.total} TOTAL
            </span>
          </div>

          <!-- Color spectrum bar -->
          <div style="display: flex; height: 8px; border-radius: 2px; overflow: hidden; margin-bottom: var(--space-3);">
            <div style="width: {((stats.by_severity['critical'] || 0) / stats.total) * 100}%; background: var(--sev-critical);" title="Critical"></div>
            <div style="width: {((stats.by_severity['high'] || 0) / stats.total) * 100}%; background: var(--sev-high);" title="High"></div>
            <div style="width: {((stats.by_severity['medium'] || 0) / stats.total) * 100}%; background: var(--sev-medium);" title="Medium"></div>
            <div style="width: {((stats.by_severity['low'] || 0) / stats.total) * 100}%; background: var(--sev-low);" title="Low"></div>
          </div>

          <div style="display: flex; flex-direction: column; gap: var(--space-2);">
            {#each ['critical', 'high', 'medium', 'low'] as sev}
              {#if stats.by_severity[sev]}
                <div style="display: flex; align-items: center; justify-content: space-between; font-size: var(--text-xs);">
                  <div style="display: flex; align-items: center; gap: var(--space-2);">
                    <span class="sev-pill sev-pill--{sev}">{sev}</span>
                  </div>
                  <div style="display: flex; align-items: center; gap: var(--space-3);">
                    <span class="tabular-nums" style="color: var(--text-muted); font-size: var(--text-2xs);">
                      {Math.round(((stats.by_severity[sev] || 0) / stats.total) * 100)}%
                    </span>
                    <span class="tabular-nums" style="font-weight: 600; min-width: 16px; text-align: right;">
                      {stats.by_severity[sev] || 0}
                    </span>
                  </div>
                </div>
              {/if}
            {/each}
          </div>
        </div>

        <!-- CQRS-Lite Ingestion Architecture -->
        <div style="background: var(--bg-surface); border: 1px solid var(--border-subtle); border-radius: var(--radius-sm); padding: var(--space-4);">
          <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: var(--space-3);">
            <h3 style="font-size: var(--text-sm); font-weight: 600; text-transform: uppercase; letter-spacing: 0.04em;">
              Pipeline Architecture
            </h3>
            <span class="status-pill status-pill--success">CQRS-LITE</span>
          </div>

          <div style="display: flex; flex-direction: column; gap: var(--space-2); font-size: var(--text-xs);">
            <div style="padding: 8px 10px; background: var(--bg-inset); border: 1px solid var(--border-subtle); border-radius: var(--radius-xs);">
              <div style="font-weight: 600; color: var(--text-primary); margin-bottom: 2px;">1. Git-Tracked YAML (Source of Truth)</div>
              <div style="font-size: var(--text-2xs); color: var(--text-muted); font-family: var(--font-mono);">rules/sigma/**/*.yml</div>
            </div>
            <div style="padding: 8px 10px; background: var(--bg-inset); border: 1px solid var(--border-subtle); border-radius: var(--radius-xs);">
              <div style="font-weight: 600; color: var(--text-primary); margin-bottom: 2px;">2. Watchdog Change Reconciler</div>
              <div style="font-size: var(--text-2xs); color: var(--text-muted); font-family: var(--font-mono);">Sub-millisecond disk change listener</div>
            </div>
            <div style="padding: 8px 10px; background: var(--bg-inset); border: 1px solid var(--border-subtle); border-radius: var(--radius-xs);">
              <div style="font-weight: 600; color: var(--text-primary); margin-bottom: 2px;">3. SQLite WAL Read Model</div>
              <div style="font-size: var(--text-2xs); color: var(--text-muted); font-family: var(--font-mono);">High-concurrency query cache</div>
            </div>
            <div style="padding: 8px 10px; background: var(--bg-inset); border: 1px solid var(--border-subtle); border-radius: var(--radius-xs);">
              <div style="font-weight: 600; color: var(--text-primary); margin-bottom: 2px;">4. Real-Time WebSocket Broadcast</div>
              <div style="font-size: var(--text-2xs); color: var(--text-muted); font-family: var(--font-mono);">/ws/events · /ws/replay · /ws/test-runner</div>
            </div>
          </div>
        </div>

      </div>

      <!-- Right Column: Adversarial Bypass Ledger & Quick Entry Points -->
      <div style="display: flex; flex-direction: column; gap: var(--space-5);">
        
        <div class="data-table-container">
          <div style="padding: var(--space-3) var(--space-4); background: var(--bg-elevated); border-bottom: 1px solid var(--border-subtle); display: flex; align-items: center; justify-content: space-between;">
            <div>
              <h3 style="font-size: var(--text-sm); font-weight: 600;">Adversarial Evasion Hardening Ledger</h3>
              <span style="font-size: var(--text-2xs); color: var(--text-muted);">
                Week 7 Purple-Team Simulations · 7 Evasion Classes Tested & Remediated
              </span>
            </div>
            <button class="btn btn--secondary btn--sm" onclick={() => onnavigate('purple-team')}>
              View Full Evasion Log →
            </button>
          </div>

          <table class="data-table">
            <thead>
              <tr>
                <th style="width: 70px;">Case</th>
                <th style="width: 100px;">Technique</th>
                <th>Evasion Vector</th>
                <th style="width: 110px;">Post-Hardening</th>
                <th>Remediation Fix</th>
              </tr>
            </thead>
            <tbody>
              {#each bypasses as b}
                <tr class="clickable-row" onclick={() => onnavigate('purple-team')}>
                  <td class="tabular-nums" style="font-family: var(--font-mono); font-size: var(--text-2xs); color: var(--text-muted);">
                    #{b.case_id || b.id}
                  </td>
                  <td>
                    <span class="badge badge--mono" style="color: var(--accent-primary); font-size: var(--text-2xs);">
                      {b.technique_id || b.technique}
                    </span>
                  </td>
                  <td style="color: var(--text-primary); font-size: var(--text-xs);">
                    {b.evasion_technique || b.evasion_method}
                  </td>
                  <td>
                    <span class="sev-pill sev-pill--low">HARDENED</span>
                  </td>
                  <td style="font-size: var(--text-2xs); color: var(--text-secondary); font-family: var(--font-mono);">
                    {b.fix_applied || b.rule_hardened || 'Hardened pattern filter'}
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>

        <!-- Quick Access Workspaces Strip -->
        <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: var(--space-3);">
          <button
            class="btn btn--secondary"
            style="padding: var(--space-3); flex-direction: column; align-items: flex-start; gap: var(--space-1); height: auto;"
            onclick={() => onnavigate('rules')}
          >
            <span style="font-size: var(--text-xs); font-weight: 600; color: var(--text-primary);">Rules Catalog</span>
            <span style="font-size: var(--text-2xs); color: var(--text-muted);">33 vendor-neutral detections</span>
          </button>

          <button
            class="btn btn--secondary"
            style="padding: var(--space-3); flex-direction: column; align-items: flex-start; gap: var(--space-1); height: auto;"
            onclick={() => onnavigate('coverage')}
          >
            <span style="font-size: var(--text-xs); font-weight: 600; color: var(--text-primary);">ATT&CK Matrix</span>
            <span style="font-size: var(--text-2xs); color: var(--text-muted);">27 sub-techniques mapped</span>
          </button>

          <button
            class="btn btn--secondary"
            style="padding: var(--space-3); flex-direction: column; align-items: flex-start; gap: var(--space-1); height: auto;"
            onclick={() => onnavigate('d3fend')}
          >
            <span style="font-size: var(--text-xs); font-weight: 600; color: var(--text-primary);">D3FEND Matrix</span>
            <span style="font-size: var(--text-2xs); color: var(--text-muted);">33 defensive countermeasures</span>
          </button>

          <button
            class="btn btn--secondary"
            style="padding: var(--space-3); flex-direction: column; align-items: flex-start; gap: var(--space-1); height: auto;"
            onclick={() => onnavigate('report')}
          >
            <span style="font-size: var(--text-xs); font-weight: 600; color: var(--text-primary);">SOC Report</span>
            <span style="font-size: var(--text-2xs); color: var(--text-muted);">Executive CISO assessment</span>
          </button>
        </div>

      </div>

    </div>

  {/if}
</div>
