<script lang="ts">
  import { coverageApi, type AttackCoverage, type MttdMetrics } from '../lib/api.ts';

  let coverage = $state<AttackCoverage | null>(null);
  let mttd = $state<MttdMetrics | null>(null);
  let loading = $state(true);
  let error = $state<string | null>(null);
  let selected = $state<{ technique_id: string; tactic: string; score: number; comment: string } | null>(null);

  $effect(() => {
    Promise.all([coverageApi.attack(), coverageApi.mttd()])
      .then(([c, m]) => { coverage = c; mttd = m; loading = false; })
      .catch(e => { error = e.message; loading = false; });
  });

  function scoreClass(score: number): string {
    if (score >= 90) return 'attack-cell--90';
    if (score >= 80) return 'attack-cell--80';
    if (score >= 70) return 'attack-cell--70';
    if (score >= 60) return 'attack-cell--60';
    return 'attack-cell--low';
  }

  function scoreLabel(score: number): string {
    if (score >= 90) return '[HIGH]';
    if (score >= 80) return '[MED]';
    if (score >= 60) return '[LOW]';
    return '[NONE]';
  }


</script>

<div class="page">
  <div class="page__header">
    <h1 class="page__title">ATT&CK Coverage</h1>
    <span class="page__subtitle">MITRE ATT&CK v14 · Enterprise · Windows</span>
  </div>

  {#if loading}
    <div class="state-loading">Loading coverage data</div>
  {:else if error}
    <div class="state-error">[ERROR] {error}</div>
  {:else if coverage && mttd}

    <!-- ── Summary stats ───────────────────────────────────────────── -->
    <div class="stat-grid" style="margin-bottom: var(--sp-5);">
      <div class="stat-card">
        <div class="stat-card__label">Techniques Covered</div>
        <div class="stat-card__value stat-card__value--blue">{coverage.technique_count}</div>
        <div class="stat-card__sub">ATT&CK v{coverage.attack_version}</div>
      </div>
      <div class="stat-card">
        <div class="stat-card__label">Avg MTTD</div>
        <div class="stat-card__value stat-card__value--green">{mttd.avg_mttd_seconds}s</div>
        <div class="stat-card__sub">Mean time to detect</div>
      </div>
      <div class="stat-card">
        <div class="stat-card__label">Best MTTD</div>
        <div class="stat-card__value stat-card__value--green">{mttd.min_mttd_seconds}s</div>
        <div class="stat-card__sub">Fastest detection</div>
      </div>
      <div class="stat-card">
        <div class="stat-card__label">Worst MTTD</div>
        <div class="stat-card__value stat-card__value--amber">{mttd.max_mttd_seconds}s</div>
        <div class="stat-card__sub">Slowest detection</div>
      </div>
    </div>

    <!-- ── Legend ─────────────────────────────────────────────────── -->
    <div style="display: flex; gap: var(--sp-4); margin-bottom: var(--sp-4); flex-wrap: wrap;">
      {#each coverage.legend as item}
        <div style="display: flex; align-items: center; gap: var(--sp-2);">
          <div style="width: 12px; height: 12px; background: {item.color}; border: var(--border);"></div>
          <span style="font-size: var(--font-size-xs); color: var(--ink-2);">{item.label}</span>
        </div>
      {/each}
    </div>

    <!-- ── ATT&CK heatmap grid ─────────────────────────────────────── -->
    <div class="section-head">
      <span class="section-head__label">Technique Coverage Heatmap</span>
      <div class="section-head__line"></div>
    </div>

    <div class="attack-grid" style="margin-bottom: var(--sp-5);">
      {#each coverage.techniques as t (t.technique_id + t.tactic)}
        <button
          class="attack-cell {scoreClass(t.score)}"
          onclick={() => selected = t}
          title="{t.technique_id} · {t.tactic} · Score: {t.score}"
        >
          <span class="attack-cell__id">{t.technique_id}</span>
          <span style="font-size: 9px; color: var(--ink-3); display: block;">{t.tactic || ''}</span>
          <span class="attack-cell__score">{scoreLabel(t.score)}</span>
        </button>
      {/each}
    </div>

    <!-- ── Selected technique detail ─────────────────────────────── -->
    {#if selected}
      <div class="section-head">
        <span class="section-head__label">Technique Detail: {selected.technique_id}</span>
        <div class="section-head__line"></div>
        <button class="btn btn--sm" onclick={() => selected = null}>× Close</button>
      </div>
      <div style="padding: var(--sp-4); background: var(--paper-2); border: var(--border); margin-bottom: var(--sp-5);">
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: var(--sp-4);">
          <div>
            <div class="stat-card__label">Technique ID</div>
            <div style="font-weight: 700; font-size: var(--font-size-lg);">{selected.technique_id}</div>
          </div>
          <div>
            <div class="stat-card__label">Tactic</div>
            <div style="font-weight: 600;">{selected.tactic || '—'}</div>
          </div>
          <div>
            <div class="stat-card__label">Coverage Score</div>
            <div style="font-weight: 700; font-size: var(--font-size-lg); color: var(--green);">{selected.score}/100</div>
          </div>
          <div>
            <div class="stat-card__label">Comment</div>
            <div style="font-size: var(--font-size-sm); color: var(--ink-2);">{selected.comment || '—'}</div>
          </div>
        </div>
      </div>
    {/if}

    <!-- ── MTTD table ─────────────────────────────────────────────── -->
    <div class="section-head">
      <span class="section-head__label">MTTD by Rule</span>
      <div class="section-head__line"></div>
    </div>

    <table class="data-table">
      <thead>
        <tr>
          <th>Rule</th>
          <th>Technique</th>
          <th>MTTD (seconds)</th>
          <th>Bar</th>
        </tr>
      </thead>
      <tbody>
        {#each mttd.entries.sort((a, b) => a.mttd_seconds - b.mttd_seconds) as entry}
          <tr>
            <td class="truncate" style="max-width: 200px; font-size: var(--font-size-xs);">
              {entry.rule_id}
            </td>
            <td style="font-size: var(--font-size-xs);">{entry.technique}</td>
            <td style="font-weight: 600; color: {entry.mttd_seconds > 10 ? 'var(--amber)' : 'var(--green)'}">
              {entry.mttd_seconds}s
            </td>
            <td>
              <div style="
                height: 8px;
                width: {Math.min(entry.mttd_seconds / mttd!.max_mttd_seconds * 200, 200)}px;
                background: {entry.mttd_seconds > 10 ? 'var(--amber)' : 'var(--green)'};
              "></div>
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
</div>
