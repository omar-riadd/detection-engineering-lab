<script lang="ts">
  import { rulesApi, coverageApi, bypassApi, syncApi, type RuleStats } from '../lib/api.ts';

  let { onnavigate }: { onnavigate: (route: { name: string }) => void } = $props();

  let stats = $state<RuleStats | null>(null);
  let mttd = $state<{ avg_mttd_seconds: number; min_mttd_seconds: number; max_mttd_seconds: number } | null>(null);
  let bypassStats = $state<{ total_cases: number; detection_rate_pct: number; by_outcome: Record<string, number> } | null>(null);
  let syncStatus = $state<{ rules_total: number; rules_synced: number; rules_error: number; bypass_entries: number } | null>(null);
  let loading = $state(true);
  let error = $state<string | null>(null);

  $effect(() => {
    Promise.all([
      rulesApi.stats(),
      coverageApi.mttd(),
      bypassApi.stats(),
      syncApi.status(),
    ])
      .then(([s, m, b, ss]) => {
        stats = s;
        mttd = m;
        bypassStats = b;
        syncStatus = ss;
        loading = false;
      })
      .catch((e) => {
        error = e.message;
        loading = false;
      });
  });
</script>

<div class="page">
  <div class="page__header">
    <h1 class="page__title">Detection Engineering Lab</h1>
    <span class="page__subtitle">Portfolio — Active Directory Intrusion · Ransomware Precursor</span>
  </div>

  {#if loading}
    <div class="state-loading">Loading</div>
  {:else if error}
    <div class="state-error">[ERROR] {error}</div>
  {:else if stats && mttd && bypassStats}

    <!-- ── Key metrics ───────────────────────────────────────────────── -->
    <div class="stat-grid">
      <div class="stat-card">
        <div class="stat-card__label">Sigma Rules</div>
        <div class="stat-card__value">{stats.total}</div>
        <div class="stat-card__sub">Production</div>
      </div>
      <div class="stat-card">
        <div class="stat-card__label">ATT&CK Techniques</div>
        <div class="stat-card__value stat-card__value--blue">{stats.unique_techniques}</div>
        <div class="stat-card__sub">Covered</div>
      </div>
      <div class="stat-card">
        <div class="stat-card__label">Avg MTTD</div>
        <div class="stat-card__value stat-card__value--green">{mttd.avg_mttd_seconds}s</div>
        <div class="stat-card__sub">range {mttd.min_mttd_seconds}–{mttd.max_mttd_seconds}s</div>
      </div>
      <div class="stat-card">
        <div class="stat-card__label">FP Rate</div>
        <div class="stat-card__value stat-card__value--green">0.00%</div>
        <div class="stat-card__sub">1,207 baseline events</div>
      </div>
      <div class="stat-card">
        <div class="stat-card__label">Bypass Cases</div>
        <div class="stat-card__value">{bypassStats.total_cases}</div>
        <div class="stat-card__sub">{bypassStats.detection_rate_pct}% detected post-hardening</div>
      </div>
      <div class="stat-card">
        <div class="stat-card__label">DB Sync</div>
        <div class="stat-card__value stat-card__value--{syncStatus?.rules_error ? 'red' : 'green'}">
          {syncStatus?.rules_synced ?? 0}/{syncStatus?.rules_total ?? 0}
        </div>
        <div class="stat-card__sub">{syncStatus?.rules_error ?? 0} errors</div>
      </div>
    </div>

    <!-- ── Severity breakdown ─────────────────────────────────────────── -->
    <div class="section-head">
      <span class="section-head__label">Rules by Severity</span>
      <div class="section-head__line"></div>
    </div>

    <table class="data-table" style="margin-bottom: var(--sp-6);">
      <thead>
        <tr>
          <th>Severity</th>
          <th>Count</th>
          <th>Distribution</th>
        </tr>
      </thead>
      <tbody>
        {#each Object.entries(stats.by_severity).sort(([,a],[,b]) => b - a) as [sev, count]}
          <tr>
            <td><span class="badge badge--{sev}">{sev}</span></td>
            <td>{count}</td>
            <td>
              <div style="display:flex; gap: 2px; align-items: center;">
                <div style="
                  height: 10px;
                  width: {Math.round(count / stats!.total * 200)}px;
                  background: var(--ink-2);
                "></div>
                <span style="font-size: var(--font-size-xs); color: var(--ink-3);">
                  {Math.round(count / stats!.total * 100)}%
                </span>
              </div>
            </td>
          </tr>
        {/each}
      </tbody>
    </table>

    <!-- ── Quick nav ──────────────────────────────────────────────────── -->
    <div class="section-head">
      <span class="section-head__label">Quick Access</span>
      <div class="section-head__line"></div>
    </div>

    <div style="display: flex; gap: var(--sp-3); flex-wrap: wrap;">
      <button class="btn btn--primary" onclick={() => onnavigate({ name: 'rules' })}>
        → Browse All Rules
      </button>
      <button class="btn" onclick={() => onnavigate({ name: 'coverage' })}>
        → ATT&CK Coverage Map
      </button>
      <button class="btn" onclick={() => onnavigate({ name: 'replay' })}>
        → Run Replay Engine
      </button>
      <button class="btn" onclick={() => onnavigate({ name: 'purple-team' })}>
        → Purple Team Log
      </button>
    </div>

    <!-- ── Architecture note ──────────────────────────────────────────── -->
    <div class="section-head" style="margin-top: var(--sp-10);">
      <span class="section-head__label">Architecture</span>
      <div class="section-head__line"></div>
    </div>
    <div class="terminal" style="height: auto; max-height: 160px; font-size: 0.68rem;">rules/sigma/**/*.yml  ← SOURCE OF TRUTH (Git-tracked, CI/CD reads)
        │
        ▼  startup reconciliation + watchdog file watcher
SQLite WAL (detection_lab.db)  ← DERIVED READ MODEL (disposable)
        │
        ▼  FastAPI REST + WebSocket
Svelte 5 UI  ← CQRS-lite, files as write model, DB as query model</div>
  {/if}
</div>
