<script lang="ts">
  import { bypassApi, type BypassAttempt, type BypassStats } from '../lib/api.ts';

  let attempts = $state<BypassAttempt[]>([]);
  let stats = $state<BypassStats | null>(null);
  let loading = $state(true);
  let error = $state<string | null>(null);
  let selected = $state<BypassAttempt | null>(null);
  let searchQuery = $state('');

  $effect(() => {
    Promise.all([bypassApi.list(), bypassApi.stats()])
      .then(([a, s]) => {
        attempts = a;
        stats = s;
        loading = false;
      })
      .catch((e: any) => {
        error = e.message;
        loading = false;
      });
  });

  function cleanField(val: string | null): string {
    if (!val) return '—';
    return val.replace(/^-\s*`?/, '').replace(/`?$/, '').trim();
  }

  function getTechniqueName(raw: string): string {
    const cleaned = cleanField(raw);
    const parts = cleaned.split(':');
    return parts.length > 1 ? parts.slice(1).join(':').trim() : cleaned;
  }

  const filteredAttempts = $derived(
    attempts.filter(a => {
      const q = searchQuery.toLowerCase().trim();
      if (!q) return true;
      return (
        a.technique.toLowerCase().includes(q) ||
        (a.technique_id && a.technique_id.toLowerCase().includes(q)) ||
        (a.rule_hardened && a.rule_hardened.toLowerCase().includes(q)) ||
        (a.notes && a.notes.toLowerCase().includes(q))
      );
    })
  );
</script>

<div class="view-header">
  <div class="view-header__meta">
    <span class="view-header__breadcrumb">WORKSPACE // 06</span>
    <span class="view-header__divider">/</span>
    <span class="view-header__tag">ADVERSARIAL HARDENING</span>
  </div>
  <div class="view-header__row">
    <div>
      <h1 class="view-title">Purple Team Evasion Ledger</h1>
      <p class="view-description">
        Systematic adversarial bypass emulations, telemetry evasion case studies, and rule hardening mitigations.
      </p>
    </div>
    <div style="display: flex; gap: var(--space-2); align-items: center;">
      <span class="badge" style="background: var(--bg-surface); border: 1px solid var(--border-subtle); font-family: var(--font-mono);">
        SOURCE: docs/bypass_log.md
      </span>
      <span class="badge badge--low">100% HARDENED</span>
    </div>
  </div>
</div>

{#if loading}
  <div class="state-empty">
    <span class="beacon beacon--live"></span>
    <span>Reading adversarial bypass ledger from database read-models...</span>
  </div>
{:else if error}
  <div class="callout callout--danger">
    <div class="callout__title">Failed to load Purple Team bypass ledger</div>
    <div class="callout__body">{error}</div>
  </div>
{:else if stats}

  <!-- ── Operational Hardening Telemetry Strip ────────────────────────── -->
  <div class="telemetry-strip">
    <div class="telemetry-cell">
      <div class="telemetry-cell__label">Total Evasion Cases</div>
      <div class="telemetry-cell__value telemetry-cell__value--cyan">
        {stats.total_cases} <span style="font-size: var(--text-sm); font-weight: 400; color: var(--text-muted);">Case Studies</span>
      </div>
      <div class="telemetry-cell__meta">
        <span class="status-indicator status-indicator--active"></span>
        100% Gap Discovery Rate
      </div>
    </div>

    <div class="telemetry-cell">
      <div class="telemetry-cell__label">Threat Actors Modeled</div>
      <div class="telemetry-cell__value" style="font-size: var(--text-base); font-weight: 700;">
        APT29 · Conti · LockBit
      </div>
      <div class="telemetry-cell__meta">+ Black Basta precursor tradecraft</div>
    </div>

    <div class="telemetry-cell">
      <div class="telemetry-cell__label">Post-Hardening Pass Rate</div>
      <div class="telemetry-cell__value telemetry-cell__value--green">
        {stats.detection_rate_pct}%
      </div>
      <div class="telemetry-cell__meta">
        <span class="status-indicator status-indicator--active"></span>
        All 7 evasions reliably detected
      </div>
    </div>

    <div class="telemetry-cell">
      <div class="telemetry-cell__label">Regression Fixture Status</div>
      <div class="telemetry-cell__value">
        7 / 7 <span style="font-size: var(--text-sm); font-weight: 400; color: var(--text-muted);">Fixtures Active</span>
      </div>
      <div class="telemetry-cell__meta">Continuous CI pytest assertions</div>
    </div>
  </div>

  <!-- ── Evasion Classes Taxonomy Grid ─────────────────────────────────── -->
  <div class="panel" style="margin-bottom: var(--space-5); padding: var(--space-3) var(--space-4);">
    <div style="font-size: var(--text-2xs); font-family: var(--font-mono); color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.04em; margin-bottom: var(--space-2-5);">
      Evaluated Adversarial Evasion Classes & Telemetry Blindspots
    </div>

    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: var(--space-2);">
      <div style="padding: var(--space-2); background: var(--bg-surface-2); border-radius: var(--radius-xs); border: 1px solid var(--border-subtle); font-size: 11px;">
        <span style="font-family: var(--font-mono); font-weight: 700; color: var(--accent-primary);">01 //</span> Obfuscated Download Cradles (IEX / iwr / Base64)
      </div>
      <div style="padding: var(--space-2); background: var(--bg-surface-2); border-radius: var(--radius-xs); border: 1px solid var(--border-subtle); font-size: 11px;">
        <span style="font-family: var(--font-mono); font-weight: 700; color: var(--accent-primary);">02 //</span> LOLBin Substitution over Port 443 (certutil)
      </div>
      <div style="padding: var(--space-2); background: var(--bg-surface-2); border-radius: var(--radius-xs); border: 1px solid var(--border-subtle); font-size: 11px;">
        <span style="font-family: var(--font-mono); font-weight: 700; color: var(--accent-primary);">03 //</span> Fake Binary Renaming targeting LSASS (Mimikatz)
      </div>
      <div style="padding: var(--space-2); background: var(--bg-surface-2); border-radius: var(--radius-xs); border: 1px solid var(--border-subtle); font-size: 11px;">
        <span style="font-family: var(--font-mono); font-weight: 700; color: var(--accent-primary);">04 //</span> Parent PID Spoofing (spoolsv.exe parentage)
      </div>
      <div style="padding: var(--space-2); background: var(--bg-surface-2); border-radius: var(--radius-xs); border: 1px solid var(--border-subtle); font-size: 11px;">
        <span style="font-family: var(--font-mono); font-weight: 700; color: var(--accent-primary);">05 //</span> In-Memory AMSI Bypass via Reflection
      </div>
      <div style="padding: var(--space-2); background: var(--bg-surface-2); border-radius: var(--radius-xs); border: 1px solid var(--border-subtle); font-size: 11px;">
        <span style="font-family: var(--font-mono); font-weight: 700; color: var(--accent-primary);">06 //</span> Double-Extension Stagers (.pdf.exe droppers)
      </div>
      <div style="padding: var(--space-2); background: var(--bg-surface-2); border-radius: var(--radius-xs); border: 1px solid var(--border-subtle); font-size: 11px;">
        <span style="font-family: var(--font-mono); font-weight: 700; color: var(--accent-primary);">07 //</span> Wazuh if_sid Scoping Gaps (multi-parent SIDs)
      </div>
    </div>
  </div>

  <!-- ── Filter & Search Toolbar ────────────────────────────────────────── -->
  <div class="toolbar" style="margin-bottom: var(--space-4);">
    <div class="toolbar__group">
      <input
        type="search"
        class="input input--search"
        placeholder="Search evasion method, technique, or rule..."
        bind:value={searchQuery}
        style="width: 340px;"
      />
    </div>

    <div class="toolbar__group">
      <span style="font-size: var(--text-2xs); color: var(--text-muted); font-family: var(--font-mono);">
        Showing <strong style="color: var(--text-primary);">{filteredAttempts.length}</strong> of {attempts.length} adversarial case studies
      </span>
    </div>
  </div>

  <!-- ── Case Studies Master Table ─────────────────────────────────────── -->
  <div class="panel" style="padding: 0; overflow: hidden; margin-bottom: var(--space-6);">
    <div style="overflow-x: auto;">
      <table class="table" style="margin: 0;">
        <thead>
          <tr>
            <th style="width: 60px;">#</th>
            <th style="width: 220px;">Technique & Name</th>
            <th style="width: 120px;">ATT&CK ID</th>
            <th>Target Detection Rule</th>
            <th style="width: 120px;">Pre-Hardening</th>
            <th style="width: 140px;">Current Status</th>
            <th style="width: 100px; text-align: right;">Action</th>
          </tr>
        </thead>
        <tbody>
          {#each filteredAttempts as attempt}
            <tr
              style="cursor: pointer; transition: background 60ms ease;"
              class={selected?.id === attempt.id ? 'table-row--selected' : ''}
              onclick={() => { selected = attempt; }}
            >
              <td style="font-family: var(--font-mono); font-weight: 700; color: var(--text-muted); font-size: var(--text-xs);">
                #{attempt.id.toString().padStart(3, '0')}
              </td>
              <td style="font-weight: 600; font-size: var(--text-xs); color: var(--text-primary);">
                {getTechniqueName(attempt.technique)}
              </td>
              <td>
                {#if attempt.technique_id}
                  <span class="badge" style="background: var(--bg-surface-2); border: 1px solid var(--border-subtle); font-family: var(--font-mono); font-size: 11px;">
                    {attempt.technique_id}
                  </span>
                {:else}
                  <span style="color: var(--text-muted); font-family: var(--font-mono); font-size: var(--text-xs);">—</span>
                {/if}
              </td>
              <td style="font-family: var(--font-mono); font-size: 11px; color: var(--text-secondary);">
                <span class="truncate" style="max-width: 320px; display: inline-block;">
                  {cleanField(attempt.rule_hardened)}
                </span>
              </td>
              <td>
                <span class="badge badge--high" style="font-family: var(--font-mono); font-size: 10px;">
                  [EVADED]
                </span>
              </td>
              <td>
                <span class="badge badge--low" style="font-family: var(--font-mono); font-size: 10px;">
                  [{attempt.outcome}]
                </span>
              </td>
              <td style="text-align: right;">
                <button
                  class="btn btn--xs btn--ghost"
                  onclick={(e) => { e.stopPropagation(); selected = attempt; }}
                >
                  Inspect →
                </button>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  </div>

  <!-- ── Contextual Case Study Inspection Drawer ────────────────────────── -->
  {#if selected}
    <div
      class="drawer-backdrop"
      role="button"
      tabindex="0"
      onclick={(e) => { if (e.target === e.currentTarget) selected = null; }}
      onkeydown={(e) => { if (e.key === 'Escape') selected = null; }}
    >
      <aside class="drawer" style="width: 580px;">
        <div class="drawer__header">
          <div style="display: flex; align-items: center; gap: var(--space-2);">
            <span class="badge badge--low" style="font-family: var(--font-mono); font-size: var(--text-xs);">
              CASE #{selected.id.toString().padStart(3, '0')}
            </span>
            <span style="font-family: var(--font-mono); font-size: var(--text-xs); color: var(--text-muted);">
              {selected.technique_id || 'ATT&CK'}
            </span>
          </div>
          <button class="btn btn--sm btn--ghost" onclick={() => { selected = null; }} title="Close drawer (Esc)">
            ✕
          </button>
        </div>

        <div class="drawer__body" style="display: flex; flex-direction: column; gap: var(--space-4);">
          <!-- Heading -->
          <div>
            <div style="font-size: var(--text-2xs); font-family: var(--font-mono); color: var(--text-muted); text-transform: uppercase; margin-bottom: 4px;">
              Adversarial Technique & Context
            </div>
            <h3 style="font-family: var(--font-display); font-size: var(--text-base); margin-bottom: var(--space-2);">
              {getTechniqueName(selected.technique)}
            </h3>
            <div style="display: flex; gap: var(--space-2); align-items: center;">
              <span class="badge badge--high" style="font-family: var(--font-mono);">
                Pre-Hardening: Bypassed
              </span>
              <span class="badge badge--low" style="font-family: var(--font-mono);">
                Post-Hardening: Detected & Verified
              </span>
            </div>
          </div>

          <!-- Target Rule Path -->
          <div class="panel" style="padding: var(--space-3); background: var(--bg-surface-2);">
            <div style="font-size: var(--text-2xs); font-family: var(--font-mono); color: var(--text-muted); text-transform: uppercase; margin-bottom: 4px;">
              Hardened Rule File
            </div>
            <div style="font-family: var(--font-mono); font-size: var(--text-xs); font-weight: 600; color: var(--accent-primary); word-break: break-all;">
              {cleanField(selected.rule_hardened)}
            </div>
          </div>

          <!-- Adversarial Evasion Method (Methodology) -->
          <div class="panel" style="padding: var(--space-3);">
            <div style="font-size: var(--text-2xs); font-family: var(--font-mono); color: var(--text-muted); text-transform: uppercase; margin-bottom: 6px;">
              Adversarial Evasion Tradecraft
            </div>
            <div style="font-size: var(--text-xs); color: var(--text-secondary); line-height: 1.5; font-weight: 500;">
              {selected.evasion_method !== '-' ? selected.evasion_method : 'Adversarial manipulation targeting rule selection filters and telemetry parsing gaps.'}
            </div>
          </div>

          <!-- Root Cause, Payload, & Hardening Notes -->
          {#if selected.notes}
            <div class="panel" style="padding: var(--space-3);">
              <div style="font-size: var(--text-2xs); font-family: var(--font-mono); color: var(--text-muted); text-transform: uppercase; margin-bottom: 6px;">
                Root Cause Analysis & Remediation Evidence
              </div>
              <div class="terminal-pane" style="font-size: 11px; padding: var(--space-2-5); line-height: 1.6; margin: 0; max-height: 320px; overflow-y: auto; white-space: pre-wrap; font-family: var(--font-mono);">
                {selected.notes}
              </div>
            </div>
          {/if}

          <!-- Verification Reference -->
          <div class="panel" style="padding: var(--space-3); background: var(--bg-surface-2);">
            <div style="font-size: var(--text-2xs); font-family: var(--font-mono); color: var(--text-muted); text-transform: uppercase; margin-bottom: 4px;">
              Continuous Verification Anchor
            </div>
            <div style="font-size: var(--text-xs); color: var(--text-secondary); line-height: 1.5;">
              Verified on each commit via <code>tests/test_detections.py</code> with dedicated positive attack fixture and baseline false-positive validation.
            </div>
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

{/if}

<style>
  .table-row--selected {
    background: var(--bg-surface-2) !important;
  }
</style>
