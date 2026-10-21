<script lang="ts">
  import { bypassApi, type BypassAttempt, type BypassStats } from '../lib/api.ts';

  let attempts = $state<BypassAttempt[]>([]);
  let stats = $state<BypassStats | null>(null);
  let loading = $state(true);
  let error = $state<string | null>(null);
  let selected = $state<BypassAttempt | null>(null);

  $effect(() => {
    Promise.all([bypassApi.list(), bypassApi.stats()])
      .then(([a, s]) => { attempts = a; stats = s; loading = false; })
      .catch(e => { error = e.message; loading = false; });
  });
</script>

<div class="page">
  <div class="page__header">
    <h1 class="page__title">Purple Team Log</h1>
    <span class="page__subtitle">Adversarial evasion case studies · bypass_log.md source of truth</span>
  </div>

  {#if loading}
    <div class="state-loading">Loading bypass data</div>
  {:else if error}
    <div class="state-error">[ERROR] {error}</div>
  {:else if stats}

    <!-- ── Stats ───────────────────────────────────────────────── -->
    <div class="stat-grid" style="margin-bottom: var(--sp-5);">
      <div class="stat-card">
        <div class="stat-card__label">Total Cases</div>
        <div class="stat-card__value">{stats.total_cases}</div>
        <div class="stat-card__sub">Adversarial emulations</div>
      </div>
      <div class="stat-card">
        <div class="stat-card__label">Detection Rate</div>
        <div class="stat-card__value stat-card__value--green">{stats.detection_rate_pct}%</div>
        <div class="stat-card__sub">Post-hardening</div>
      </div>
      {#each Object.entries(stats.by_outcome) as [outcome, count]}
        <div class="stat-card">
          <div class="stat-card__label">{outcome}</div>
          <div class="stat-card__value stat-card__value--{outcome === 'DETECTED' ? 'green' : outcome === 'EVADED' ? 'red' : 'amber'}">{count}</div>
          <div class="stat-card__sub">Cases</div>
        </div>
      {/each}
    </div>

    <!-- ── Executive summary ─────────────────────────────────────── -->
    <div class="terminal" style="height: auto; font-size: 0.68rem; margin-bottom: var(--sp-5);">
ADVERSARIAL EMULATION SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Threat Actors Referenced : APT29, Conti, Black Basta, LockBit
Total Evasion Attempts   : {stats.total_cases}
Pre-Hardening Bypassed   : {stats.total_cases} (100% gap discovery rate)
Hardened Rules Implemented: {stats.total_cases} (100% fix rate)
Post-Hardening Pass Rate : {stats.detection_rate_pct}%
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━</div>

    <!-- ── Case table ─────────────────────────────────────────────── -->
    <div class="section-head">
      <span class="section-head__label">Bypass Case Studies</span>
      <div class="section-head__line"></div>
    </div>

    <table class="data-table" style="margin-bottom: var(--sp-5);">
      <thead>
        <tr>
          <th>#</th>
          <th>Technique</th>
          <th>Technique ID</th>
          <th>Target Rule</th>
          <th>Outcome</th>
        </tr>
      </thead>
      <tbody>
        {#each attempts as attempt}
          <tr
            class="row--clickable"
            onclick={() => selected = selected?.id === attempt.id ? null : attempt}
          >
            <td style="color: var(--ink-3); font-size: var(--font-size-xs);">{attempt.id.toString().padStart(3, '0')}</td>
            <td style="font-size: var(--font-size-sm);">{attempt.technique}</td>
            <td>
              {#if attempt.technique_id}
                <span class="badge badge--medium">{attempt.technique_id}</span>
              {:else}
                <span style="color: var(--ink-4); font-size: var(--font-size-xs);">—</span>
              {/if}
            </td>
            <td style="font-size: var(--font-size-xs); color: var(--ink-2);">
              {attempt.rule_hardened ?? '—'}
            </td>
            <td>
              <span class="status status--{attempt.outcome === 'DETECTED' ? 'pass' : attempt.outcome === 'EVADED' ? 'fail' : 'warn'}">
                [{attempt.outcome}]
              </span>
            </td>
          </tr>

          <!-- Inline detail row -->
          {#if selected?.id === attempt.id}
            <tr style="background: var(--paper-2);">
              <td colspan="5" style="padding: var(--sp-4);">
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: var(--sp-4);">
                  <div>
                    <div style="font-size: var(--font-size-xs); color: var(--ink-3); text-transform: uppercase; letter-spacing: 0.08em; margin-bottom: var(--sp-1);">Hardening Applied</div>
                    <div style="font-size: var(--font-size-sm);">{attempt.evasion_method}</div>
                  </div>
                  {#if attempt.notes}
                    <div>
                      <div style="font-size: var(--font-size-xs); color: var(--ink-3); text-transform: uppercase; letter-spacing: 0.08em; margin-bottom: var(--sp-1);">Notes</div>
                      <div style="font-size: var(--font-size-xs); color: var(--ink-2); white-space: pre-line; line-height: 1.6;">{attempt.notes}</div>
                    </div>
                  {/if}
                </div>
              </td>
            </tr>
          {/if}
        {/each}
      </tbody>
    </table>

    <!-- ── Evasion classes note ─────────────────────────────────── -->
    <div class="section-head">
      <span class="section-head__label">Evasion Classes Tested</span>
      <div class="section-head__line"></div>
    </div>
    <div class="terminal" style="height: auto; font-size: 0.68rem;">
[1] String obfuscation and alternate download cradles  (T1059.001)
[2] LOLBin substitution over standard web ports        (T1041)
[3] Renamed binary evasion targeting LSASS memory     (T1003.001)
[4] Parent process ID (PPID) spoofing                 (T1204.002)
[5] In-memory AMSI bypass via reflection              (T1059.001 / T1562.001)
[6] Staged payload dropping via double-extension      (T1566.001)
[7] if_sid scoping gap in Wazuh XML rules             (T1490)</div>
  {/if}
</div>
