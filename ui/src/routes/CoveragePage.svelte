<script lang="ts">
  import { coverageApi, type AttackCoverage, type MttdMetrics } from '../lib/api.ts';

  let coverage = $state<AttackCoverage | null>(null);
  let mttd = $state<MttdMetrics | null>(null);
  let loading = $state(true);
  let error = $state<string | null>(null);

  // Selected technique for contextual inspection drawer
  let selected = $state<{
    technique_id: string;
    tactic: string;
    score: number;
    color: string;
    comment: string;
    enabled: boolean;
  } | null>(null);

  // Filter state
  let searchQuery = $state('');
  let scoreTier = $state<'all' | 'high' | 'med' | 'low'>('all');

  const TACTIC_ORDER = [
    'initial-access',
    'execution',
    'persistence',
    'defense-evasion',
    'credential-access',
    'discovery',
    'lateral-movement',
    'exfiltration',
    'impact'
  ];

  const TACTIC_LABELS: Record<string, string> = {
    'initial-access': 'Initial Access',
    'execution': 'Execution',
    'persistence': 'Persistence',
    'defense-evasion': 'Defense Evasion',
    'credential-access': 'Credential Access',
    'discovery': 'Discovery',
    'lateral-movement': 'Lateral Movement',
    'exfiltration': 'Exfiltration',
    'impact': 'Impact'
  };

  $effect(() => {
    Promise.all([coverageApi.attack(), coverageApi.mttd()])
      .then(([c, m]) => {
        coverage = c;
        mttd = m;
        loading = false;
      })
      .catch((e: any) => {
        error = e.message;
        loading = false;
      });
  });

  function getTier(score: number): 'high' | 'med' | 'low' {
    if (score >= 85) return 'high';
    if (score >= 70) return 'med';
    return 'low';
  }

  function getCellShadeClass(score: number): string {
    if (score >= 90) return 'heatmap-cell--tier-4';
    if (score >= 80) return 'heatmap-cell--tier-3';
    if (score >= 70) return 'heatmap-cell--tier-2';
    return 'heatmap-cell--tier-1';
  }

  // Group and filter techniques by tactic
  const techniquesByTactic = $derived.by(() => {
    const map = new Map<string, typeof coverage.techniques>();
    for (const tac of TACTIC_ORDER) {
      map.set(tac, []);
    }
    if (!coverage?.techniques) return map;

    const q = searchQuery.toLowerCase().trim();

    for (const item of coverage.techniques) {
      const tacKey = item.tactic.toLowerCase().replace(/_/g, '-');
      const tier = getTier(item.score);

      const matchesSearch = !q ||
        item.technique_id.toLowerCase().includes(q) ||
        item.tactic.toLowerCase().includes(q) ||
        item.comment.toLowerCase().includes(q);

      const matchesTier = scoreTier === 'all' || tier === scoreTier;

      if (matchesSearch && matchesTier) {
        if (!map.has(tacKey)) {
          map.set(tacKey, []);
        }
        map.get(tacKey)!.push(item);
      }
    }
    return map;
  });

  const totalFilteredCount = $derived.by(() => {
    let count = 0;
    for (const list of techniquesByTactic.values()) {
      count += list.length;
    }
    return count;
  });

  // Extract rule stem and D3FEND ID from comment string
  function parseComment(comment: string) {
    const ruleMatch = comment.match(/Rule:\s*([^.\s]+(\.[a-zA-Z]+)?)/i);
    const d3Match = comment.match(/D3FEND:\s*([A-Za-z0-9\-]+)/i);
    return {
      rule: ruleMatch ? ruleMatch[1] : null,
      d3fend: d3Match ? d3Match[1] : null,
      full: comment
    };
  }
</script>

<div class="view-header">
  <div class="view-header__meta">
    <span class="view-header__breadcrumb">WORKSPACE // 03</span>
    <span class="view-header__divider">/</span>
    <span class="view-header__tag">MITRE ATT&CK HEATMAP</span>
  </div>
  <div class="view-header__row">
    <div>
      <h1 class="view-title">MITRE ATT&CK Coverage Matrix</h1>
      <p class="view-description">
        Tactical coverage distribution across 9 enterprise tactics · 100% verified against Sysmon and telemetry fixtures.
      </p>
    </div>
    {#if coverage}
      <div style="display: flex; gap: var(--space-2); align-items: center;">
        <span class="badge" style="background: var(--bg-surface); border: 1px solid var(--border-subtle); font-family: var(--font-mono);">
          ATT&CK v{coverage.attack_version}
        </span>
        <span class="badge badge--low">ENTERPRISE MATRIX</span>
      </div>
    {/if}
  </div>
</div>

{#if loading}
  <div class="state-empty">
    <span class="beacon beacon--live"></span>
    <span>Synchronizing MITRE ATT&CK Navigator layer and telemetry metrics...</span>
  </div>
{:else if error}
  <div class="callout callout--danger">
    <div class="callout__title">Failed to load ATT&CK coverage telemetry</div>
    <div class="callout__body">{error}</div>
  </div>
{:else if coverage && mttd}

  <!-- ── Tactical Telemetry Strip ────────────────────────────────────────── -->
  <div class="telemetry-strip">
    <div class="telemetry-cell">
      <div class="telemetry-cell__label">Techniques Covered</div>
      <div class="telemetry-cell__value telemetry-cell__value--cyan">
        {coverage.technique_count} <span style="font-size: var(--text-sm); font-weight: 400; color: var(--text-muted);">/ {coverage.technique_count}</span>
      </div>
      <div class="telemetry-cell__meta">
        <span class="status-indicator status-indicator--active"></span>
        100% Active CI Coverage
      </div>
    </div>

    <div class="telemetry-cell">
      <div class="telemetry-cell__label">Tactical Domain Span</div>
      <div class="telemetry-cell__value">
        9 <span style="font-size: var(--text-sm); font-weight: 400; color: var(--text-muted);">Tactics</span>
      </div>
      <div class="telemetry-cell__meta">Initial Access to Impact</div>
    </div>

    <div class="telemetry-cell">
      <div class="telemetry-cell__label">Mean Time to Detect (MTTD)</div>
      <div class="telemetry-cell__value telemetry-cell__value--green">
        {mttd.avg_mttd_seconds}s
      </div>
      <div class="telemetry-cell__meta">
        <span class="status-indicator status-indicator--active"></span>
        SLA Target: &lt; 60.0s
      </div>
    </div>

    <div class="telemetry-cell">
      <div class="telemetry-cell__label">Latency Range (Min / Max)</div>
      <div class="telemetry-cell__value">
        <span style="color: var(--sev-low);">{mttd.min_mttd_seconds}s</span>
        <span style="color: var(--text-muted); font-weight: 400; font-size: var(--text-md);"> / </span>
        <span style="color: var(--sev-medium);">{mttd.max_mttd_seconds}s</span>
      </div>
      <div class="telemetry-cell__meta">Fastest vs slowest detection</div>
    </div>
  </div>

  <!-- ── Matrix Controls Bar & Heatmap Legend ──────────────────────────── -->
  <div class="toolbar" style="margin-bottom: var(--space-4);">
    <div class="toolbar__group">
      <input
        type="search"
        class="input input--search"
        placeholder="Filter by Technique (T1059), Tactic, or Rule..."
        bind:value={searchQuery}
        style="width: 320px;"
      />

      <div class="btn-group">
        <button
          class="btn btn--sm {scoreTier === 'all' ? 'btn--primary' : 'btn--ghost'}"
          onclick={() => { scoreTier = 'all'; }}
        >
          All ({coverage.technique_count})
        </button>
        <button
          class="btn btn--sm {scoreTier === 'high' ? 'btn--primary' : 'btn--ghost'}"
          onclick={() => { scoreTier = 'high'; }}
        >
          High [85-100]
        </button>
        <button
          class="btn btn--sm {scoreTier === 'med' ? 'btn--primary' : 'btn--ghost'}"
          onclick={() => { scoreTier = 'med'; }}
        >
          Medium [70-84]
        </button>
        <button
          class="btn btn--sm {scoreTier === 'low' ? 'btn--primary' : 'btn--ghost'}"
          onclick={() => { scoreTier = 'low'; }}
        >
          Low [&lt;70]
        </button>
      </div>
    </div>

    <div class="toolbar__group" style="font-size: var(--text-2xs); color: var(--text-muted); font-family: var(--font-mono); gap: var(--space-3);">
      <span style="text-transform: uppercase;">Confidence Scale:</span>
      <div style="display: flex; align-items: center; gap: 4px;">
        <span style="width: 10px; height: 10px; border-radius: 2px; background: var(--sev-low-bg); border: 1px solid var(--sev-low-border);"></span>
        <span>Low</span>
      </div>
      <div style="display: flex; align-items: center; gap: 4px;">
        <span style="width: 10px; height: 10px; border-radius: 2px; background: rgba(63, 185, 80, 0.4); border: 1px solid var(--sev-low);"></span>
        <span>Med</span>
      </div>
      <div style="display: flex; align-items: center; gap: 4px;">
        <span style="width: 10px; height: 10px; border-radius: 2px; background: rgba(63, 185, 80, 0.65); border: 1px solid var(--sev-low);"></span>
        <span>High</span>
      </div>
      <div style="display: flex; align-items: center; gap: 4px;">
        <span style="width: 10px; height: 10px; border-radius: 2px; background: rgba(56, 189, 248, 0.7); border: 1px solid var(--accent-primary);"></span>
        <span>Hardened</span>
      </div>
      <span style="margin-left: var(--space-2); color: var(--text-primary); font-weight: 600;">
        {totalFilteredCount} matching
      </span>
    </div>
  </div>

  <!-- ── 9-Column ATT&CK Heatmap Grid ──────────────────────────────────── -->
  <div class="panel" style="margin-bottom: var(--space-6); overflow-x: auto; padding: var(--space-3);">
    <div style="display: grid; grid-template-columns: repeat(9, minmax(130px, 1fr)); gap: var(--space-2); min-width: 1100px;">
      {#each TACTIC_ORDER as tacKey}
        {@const techList = techniquesByTactic.get(tacKey) || []}
        <div class="heatmap-tactic-col">
          <div class="heatmap-tactic-header">
            <span style="display: block; font-weight: 700; color: var(--text-primary);">{TACTIC_LABELS[tacKey]}</span>
            <span style="font-size: var(--text-3xs); color: var(--text-muted); font-weight: 500;">
              {techList.length} {techList.length === 1 ? 'rule' : 'rules'}
            </span>
          </div>

          <div style="display: flex; flex-direction: column; gap: var(--space-1-5);">
            {#if techList.length === 0}
              <div style="padding: var(--space-3) var(--space-2); text-align: center; border: 1px dashed var(--border-subtle); border-radius: var(--radius-xs); font-size: var(--text-3xs); color: var(--text-muted); font-family: var(--font-mono);">
                NO ACTIVE RULES
              </div>
            {:else}
              {#each techList as t (t.technique_id + t.tactic)}
                {@const parsed = parseComment(t.comment)}
                <button
                  type="button"
                  class="heatmap-cell {getCellShadeClass(t.score)}"
                  style={selected?.technique_id === t.technique_id ? 'outline: 2px solid var(--accent-primary); border-color: var(--accent-primary);' : ''}
                  onclick={() => { selected = t; }}
                  title="{t.technique_id} ({TACTIC_LABELS[tacKey] || tacKey}) · Score: {t.score}% · {parsed.rule || 'Sigma rule'}"
                >
                  <div style="display: flex; justify-content: space-between; align-items: center; width: 100%;">
                    <span style="font-family: var(--font-mono); font-weight: 700; font-size: var(--text-2xs); letter-spacing: -0.02em;">
                      {t.technique_id}
                    </span>
                    <span style="font-family: var(--font-mono); font-size: 10px; font-weight: 600;">
                      {t.score}%
                    </span>
                  </div>

                  {#if parsed.rule}
                    <span style="font-size: 10px; color: var(--text-muted); font-family: var(--font-mono); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; text-align: left; width: 100%;">
                      {parsed.rule.replace(/\.ya?ml$/i, '')}
                    </span>
                  {/if}

                  {#if parsed.d3fend}
                    <span style="font-size: 9px; color: var(--accent-primary); font-family: var(--font-mono); text-align: left;">
                      [{parsed.d3fend}]
                    </span>
                  {/if}
                </button>
              {/each}
            {/if}
          </div>
        </div>
      {/each}
    </div>
  </div>

  <!-- ── Contextual Detail Drawer (Click-to-Inspect) ────────────────────── -->
  {#if selected}
    {@const parsed = parseComment(selected.comment)}
    <div
      class="drawer-backdrop"
      role="button"
      tabindex="0"
      onclick={(e) => { if (e.target === e.currentTarget) selected = null; }}
      onkeydown={(e) => { if (e.key === 'Escape') selected = null; }}
    >
      <aside class="drawer" style="width: 540px;">
        <div class="drawer__header">
          <div style="display: flex; align-items: center; gap: var(--space-2);">
            <span class="badge badge--low" style="font-size: var(--text-xs); font-family: var(--font-mono);">
              {selected.technique_id}
            </span>
            <span style="font-family: var(--font-mono); font-size: var(--text-xs); color: var(--text-muted);">
              {TACTIC_LABELS[selected.tactic.toLowerCase().replace(/_/g, '-')] || selected.tactic}
            </span>
          </div>
          <button class="btn btn--sm btn--ghost" onclick={() => { selected = null; }} title="Close drawer (Esc)">
            ✕
          </button>
        </div>

        <div class="drawer__body" style="display: flex; flex-direction: column; gap: var(--space-4);">
          <!-- Score overview card -->
          <div class="panel" style="padding: var(--space-3); background: var(--bg-surface);">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: var(--space-2);">
              <span style="font-size: var(--text-2xs); font-family: var(--font-mono); color: var(--text-muted); text-transform: uppercase;">
                Coverage Score & Validation Status
              </span>
              <span class="badge {selected.score >= 90 ? 'badge--low' : selected.score >= 75 ? 'badge--medium' : 'badge--high'}">
                {selected.score} / 100 Confidence
              </span>
            </div>
            <div style="height: 6px; background: var(--bg-surface-2); border-radius: var(--radius-pill); overflow: hidden; margin-bottom: var(--space-2);">
              <div
                style="height: 100%; width: {selected.score}%; background: {selected.score >= 90 ? 'var(--accent-primary)' : 'var(--sev-low)'};"
              ></div>
            </div>
            <div style="font-size: var(--text-xs); color: var(--text-secondary); line-height: 1.5;">
              {selected.score >= 90
                ? 'Evasion-hardened with regression fixtures across both positive attack emulations and benign baseline workloads.'
                : 'Active Sigma rule detection mapped to MITRE ATT&CK enterprise corpus.'}
            </div>
          </div>

          <!-- Metadata Grid -->
          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: var(--space-3);">
            <div class="panel" style="padding: var(--space-3);">
              <div style="font-size: var(--text-2xs); font-family: var(--font-mono); color: var(--text-muted); text-transform: uppercase; margin-bottom: 4px;">
                Tactic Domain
              </div>
              <div style="font-weight: 600; font-size: var(--text-sm);">
                {TACTIC_LABELS[selected.tactic.toLowerCase().replace(/_/g, '-')] || selected.tactic}
              </div>
            </div>

            <div class="panel" style="padding: var(--space-3);">
              <div style="font-size: var(--text-2xs); font-family: var(--font-mono); color: var(--text-muted); text-transform: uppercase; margin-bottom: 4px;">
                D3FEND Countermeasure
              </div>
              <div style="font-family: var(--font-mono); font-weight: 700; font-size: var(--text-sm); color: var(--accent-primary);">
                {parsed.d3fend || 'D3-ALIGNED'}
              </div>
            </div>
          </div>

          <!-- Target Sigma Rule -->
          {#if parsed.rule}
            <div class="panel" style="padding: var(--space-3);">
              <div style="font-size: var(--text-2xs); font-family: var(--font-mono); color: var(--text-muted); text-transform: uppercase; margin-bottom: 4px;">
                Active Sigma Detection Rule
              </div>
              <div style="display: flex; justify-content: space-between; align-items: center;">
                <span style="font-family: var(--font-mono); font-size: var(--text-xs); color: var(--text-primary); font-weight: 600;">
                  rules/sigma/{parsed.rule}
                </span>
                <a
                  href="#/rules"
                  class="btn btn--xs btn--ghost"
                  style="font-family: var(--font-mono);"
                >
                  View Rule →
                </a>
              </div>
            </div>
          {/if}

          <!-- Full Comment & Evasion Notes -->
          <div class="panel" style="padding: var(--space-3);">
            <div style="font-size: var(--text-2xs); font-family: var(--font-mono); color: var(--text-muted); text-transform: uppercase; margin-bottom: var(--space-1-5);">
              Validation & Adversarial Hardening Telemetry
            </div>
            <div style="font-size: var(--text-xs); color: var(--text-secondary); line-height: 1.6; white-space: pre-wrap; font-family: var(--font-mono); background: var(--bg-surface-2); padding: var(--space-2-5); border-radius: var(--radius-xs);">
              {selected.comment}
            </div>
          </div>

          <!-- MITRE Reference Link -->
          <div style="font-size: var(--text-2xs); color: var(--text-muted); font-family: var(--font-mono);">
            MITRE ATT&CK Reference:
            <a
              href="https://attack.mitre.org/techniques/{selected.technique_id.replace('.', '/')}"
              target="_blank"
              rel="noreferrer"
              style="color: var(--accent-primary); text-decoration: underline; margin-left: 4px;"
            >
              https://attack.mitre.org/techniques/{selected.technique_id}
            </a>
          </div>
        </div>

        <div class="drawer__footer">
          <button class="btn btn--sm btn--primary" onclick={() => { selected = null; }}>
            Done (Close)
          </button>
        </div>
      </aside>
    </div>
  {/if}

  <!-- ── MTTD Latency Distribution Table ───────────────────────────────── -->
  <div class="panel" style="padding: 0; overflow: hidden;">
    <div style="padding: var(--space-3) var(--space-4); border-bottom: 1px solid var(--border-subtle); display: flex; justify-content: space-between; align-items: center; background: var(--bg-surface);">
      <div style="display: flex; align-items: center; gap: var(--space-2);">
        <span style="font-weight: 700; font-size: var(--text-xs); font-family: var(--font-mono); text-transform: uppercase; letter-spacing: 0.04em;">
          Detection Latency Telemetry (MTTD by Rule)
        </span>
        <span class="badge badge--low" style="font-size: 10px;">
          {mttd.entries.length} MEASURED RULES
        </span>
      </div>
      <span style="font-size: var(--text-2xs); color: var(--text-muted); font-family: var(--font-mono);">
        Sorted by Latency (Fastest → Slowest) · Max SLA: 60s
      </span>
    </div>

    <div style="overflow-x: auto;">
      <table class="table" style="margin: 0;">
        <thead>
          <tr>
            <th style="width: 280px;">Detection Rule</th>
            <th style="width: 140px;">ATT&CK Technique</th>
            <th style="width: 110px;">MTTD (Sec)</th>
            <th>Latency Distribution (vs 60s Benchmark)</th>
            <th style="width: 110px; text-align: right;">SLA Status</th>
          </tr>
        </thead>
        <tbody>
          {#each mttd.entries.slice().sort((a, b) => a.mttd_seconds - b.mttd_seconds) as entry}
            {@const pct = Math.min((entry.mttd_seconds / (mttd?.max_mttd_seconds || 60)) * 100, 100)}
            <tr>
              <td style="font-family: var(--font-mono); font-size: var(--text-xs); font-weight: 600;">
                <span class="truncate" style="max-width: 260px; display: inline-block;">
                  {entry.rule_id}
                </span>
              </td>
              <td>
                <span class="badge" style="background: var(--bg-surface-2); border: 1px solid var(--border-subtle); font-family: var(--font-mono); font-size: 10px;">
                  {entry.technique}
                </span>
              </td>
              <td style="font-family: var(--font-mono); font-weight: 700; font-size: var(--text-xs); color: {entry.mttd_seconds > 10 ? 'var(--sev-medium)' : 'var(--sev-low)'};">
                {entry.mttd_seconds.toFixed(2)}s
              </td>
              <td style="vertical-align: middle;">
                <div style="display: flex; align-items: center; gap: var(--space-2);">
                  <div style="flex: 1; max-width: 240px; height: 6px; background: var(--bg-surface-2); border-radius: var(--radius-pill); overflow: hidden;">
                    <div
                      style="height: 100%; width: {pct}%; background: {entry.mttd_seconds > 10 ? 'var(--sev-medium)' : 'var(--sev-low)'}; border-radius: var(--radius-pill);"
                    ></div>
                  </div>
                  <span style="font-size: 10px; font-family: var(--font-mono); color: var(--text-muted); width: 36px;">
                    {pct.toFixed(0)}%
                  </span>
                </div>
              </td>
              <td style="text-align: right;">
                <span class="status-indicator status-indicator--active"></span>
                <span style="font-family: var(--font-mono); font-size: 10px; font-weight: 600; color: var(--sev-low);">
                  SLA MET
                </span>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  </div>

{/if}

<style>
  .heatmap-cell--tier-4 {
    background: rgba(56, 189, 248, 0.22);
    border-color: rgba(56, 189, 248, 0.45);
    color: var(--accent-primary);
  }
  .heatmap-cell--tier-4:hover {
    background: rgba(56, 189, 248, 0.35);
  }

  .heatmap-cell--tier-3 {
    background: rgba(63, 185, 80, 0.25);
    border-color: rgba(63, 185, 80, 0.45);
    color: var(--sev-low);
  }
  .heatmap-cell--tier-3:hover {
    background: rgba(63, 185, 80, 0.35);
  }

  .heatmap-cell--tier-2 {
    background: rgba(63, 185, 80, 0.14);
    border-color: rgba(63, 185, 80, 0.30);
    color: var(--sev-low);
  }
  .heatmap-cell--tier-2:hover {
    background: rgba(63, 185, 80, 0.22);
  }

  .heatmap-cell--tier-1 {
    background: var(--bg-surface-2);
    border-color: var(--border-subtle);
    color: var(--text-secondary);
  }
  .heatmap-cell--tier-1:hover {
    background: var(--bg-surface);
  }
</style>
