<script lang="ts">
  import { coverageApi, type D3fendMapping } from '../lib/api.ts';

  let mappings = $state<D3fendMapping[]>([]);
  let loading = $state(true);
  let error = $state<string | null>(null);
  let filterType = $state('');
  let search = $state('');
  let selected = $state<D3fendMapping | null>(null);

  $effect(() => {
    coverageApi.d3fend()
      .then(res => {
        mappings = res.mappings;
        loading = false;
      })
      .catch((err: any) => {
        error = err.message;
        loading = false;
      });
  });

  const defenseTypes = $derived(
    Array.from(new Set(mappings.flatMap(m => m.defense_type.split('/').map(t => t.trim())))).filter(Boolean).sort()
  );

  const filteredMappings = $derived(
    mappings.filter(m => {
      const matchType = !filterType || m.defense_type.toLowerCase().includes(filterType.toLowerCase());
      const s = search.toLowerCase().trim();
      const matchSearch = !s ||
        m.technique_id.toLowerCase().includes(s) ||
        m.technique_name.toLowerCase().includes(s) ||
        m.countermeasure.toLowerCase().includes(s) ||
        m.d3fend_id.toLowerCase().includes(s) ||
        m.runbook.toLowerCase().includes(s);
      return matchType && matchSearch;
    })
  );

  function getDefenseBadgeClass(type: string): string {
    const t = type.toLowerCase();
    if (t.includes('harden')) return 'badge--low';
    if (t.includes('isolate')) return 'badge--medium';
    if (t.includes('protect')) return 'badge--info';
    if (t.includes('detect')) return 'badge--info';
    return '';
  }
</script>

<div class="view-header">
  <div class="view-header__meta">
    <span class="view-header__breadcrumb">WORKSPACE // 04</span>
    <span class="view-header__divider">/</span>
    <span class="view-header__tag">DEFENSIVE COUNTERMEASURES</span>
  </div>
  <div class="view-header__row">
    <div>
      <h1 class="view-title">MITRE D3FEND Countermeasures</h1>
      <p class="view-description">
        Architectural defense-in-depth matrix · Pairing offensive ATT&CK techniques with hardening, isolation, and detection primitives.
      </p>
    </div>
    <div style="display: flex; gap: var(--space-2); align-items: center;">
      <span class="badge" style="background: var(--bg-surface); border: 1px solid var(--border-subtle); font-family: var(--font-mono);">
        MITRE D3FEND v0.10
      </span>
      <span class="badge badge--low">100% TECHNIQUE ALIGNED</span>
    </div>
  </div>
</div>

{#if loading}
  <div class="state-empty">
    <span class="beacon beacon--live"></span>
    <span>Parsing MITRE D3FEND countermeasure mappings from repository...</span>
  </div>
{:else if error}
  <div class="callout callout--danger">
    <div class="callout__title">Failed to load D3FEND defensive matrix</div>
    <div class="callout__body">{error}</div>
  </div>
{:else}

  <!-- ── Defensive Telemetry Strip ──────────────────────────────────────── -->
  <div class="telemetry-strip">
    <div class="telemetry-cell">
      <div class="telemetry-cell__label">Total Countermeasures</div>
      <div class="telemetry-cell__value telemetry-cell__value--cyan">
        {mappings.length}
      </div>
      <div class="telemetry-cell__meta">
        <span class="status-indicator status-indicator--active"></span>
        1:1 Technique Alignment
      </div>
    </div>

    <div class="telemetry-cell">
      <div class="telemetry-cell__label">Defensive Philosophy</div>
      <div class="telemetry-cell__value" style="font-size: var(--text-md); font-weight: 600;">
        Architectural Isolation
      </div>
      <div class="telemetry-cell__meta">Harden & block rather than alert alone</div>
    </div>

    <div class="telemetry-cell">
      <div class="telemetry-cell__label">Active Defense Types</div>
      <div class="telemetry-cell__value telemetry-cell__value--green">
        {defenseTypes.length} <span style="font-size: var(--text-sm); font-weight: 400; color: var(--text-muted);">Prong Strategy</span>
      </div>
      <div class="telemetry-cell__meta">Detect · Harden · Isolate · Protect · Model</div>
    </div>

    <div class="telemetry-cell">
      <div class="telemetry-cell__label">Triage Runbooks</div>
      <div class="telemetry-cell__value">
        {mappings.length} <span style="font-size: var(--text-sm); font-weight: 400; color: var(--text-muted);">Standard Runbooks</span>
      </div>
      <div class="telemetry-cell__meta">Audited SOC investigation guides</div>
    </div>
  </div>

  <!-- ── Filter & Search Toolbar ────────────────────────────────────────── -->
  <div class="toolbar" style="margin-bottom: var(--space-4);">
    <div class="toolbar__group">
      <input
        type="search"
        class="input input--search"
        placeholder="Filter by Technique, D3FEND ID (D3-FSA), or Runbook..."
        bind:value={search}
        style="width: 320px;"
      />

      <div class="btn-group">
        <button
          class="btn btn--sm {!filterType ? 'btn--primary' : 'btn--ghost'}"
          onclick={() => { filterType = ''; }}
        >
          All Types
        </button>
        {#each defenseTypes as dtype}
          <button
            class="btn btn--sm {filterType.toLowerCase() === dtype.toLowerCase() ? 'btn--primary' : 'btn--ghost'}"
            onclick={() => { filterType = filterType === dtype ? '' : dtype; }}
          >
            {dtype}
          </button>
        {/each}
      </div>
    </div>

    <div class="toolbar__group">
      <span style="font-size: var(--text-2xs); color: var(--text-muted); font-family: var(--font-mono);">
        Showing <strong style="color: var(--text-primary);">{filteredMappings.length}</strong> of {mappings.length} countermeasures
      </span>
    </div>
  </div>

  <!-- ── High-Density Countermeasure Matrix Table ────────────────────────── -->
  <div class="panel" style="padding: 0; overflow: hidden; margin-bottom: var(--space-6);">
    <div style="overflow-x: auto;">
      <table class="table" style="margin: 0;">
        <thead>
          <tr>
            <th style="width: 120px;">ATT&CK ID</th>
            <th style="width: 220px;">Technique Name</th>
            <th style="width: 120px;">D3FEND ID</th>
            <th>D3FEND Countermeasure</th>
            <th style="width: 140px;">Defense Type</th>
            <th style="width: 220px;">Triage Runbook</th>
          </tr>
        </thead>
        <tbody>
          {#if filteredMappings.length === 0}
            <tr>
              <td colspan="6" style="padding: var(--space-6); text-align: center; color: var(--text-muted); font-family: var(--font-mono); font-size: var(--text-xs);">
                No D3FEND countermeasures match the current filter query.
              </td>
            </tr>
          {:else}
            {#each filteredMappings as row}
              <tr
                style="cursor: pointer; transition: background 60ms ease;"
                class={selected?.technique_id === row.technique_id ? 'table-row--selected' : ''}
                onclick={() => { selected = row; }}
              >
                <td>
                  <span class="badge" style="background: var(--bg-surface-2); border: 1px solid var(--border-subtle); font-family: var(--font-mono); font-size: 11px;">
                    {row.technique_id}
                  </span>
                </td>
                <td style="font-weight: 600; font-size: var(--text-xs); color: var(--text-primary);">
                  {row.technique_name}
                </td>
                <td>
                  <span class="badge badge--cyan" style="font-family: var(--font-mono); font-weight: 700; font-size: 11px;">
                    [{row.d3fend_id}]
                  </span>
                </td>
                <td style="font-size: var(--text-xs); color: var(--text-secondary); line-height: 1.5;">
                  {row.countermeasure}
                </td>
                <td>
                  <span class="badge {getDefenseBadgeClass(row.defense_type)}" style="font-size: 10px;">
                    {row.defense_type}
                  </span>
                </td>
                <td>
                  <span style="font-family: var(--font-mono); font-size: 10px; color: var(--text-muted);">
                    {row.runbook}
                  </span>
                </td>
              </tr>
            {/each}
          {/if}
        </tbody>
      </table>
    </div>
  </div>

  <!-- ── Contextual Detail Drawer ──────────────────────────────────────── -->
  {#if selected}
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
            <span class="badge badge--cyan" style="font-family: var(--font-mono); font-size: var(--text-xs);">
              [{selected.d3fend_id}]
            </span>
            <span style="font-family: var(--font-mono); font-size: var(--text-xs); color: var(--text-muted);">
              {selected.technique_id}
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
              Countermeasure Definition
            </div>
            <h3 style="font-family: var(--font-display); font-size: var(--text-md); margin-bottom: var(--space-2);">
              {selected.countermeasure}
            </h3>
            <span class="badge {getDefenseBadgeClass(selected.defense_type)}">
              Architectural Defense: {selected.defense_type}
            </span>
          </div>

          <!-- Mapped Offensive Technique -->
          <div class="panel" style="padding: var(--space-3); background: var(--bg-surface-2);">
            <div style="font-size: var(--text-2xs); font-family: var(--font-mono); color: var(--text-muted); text-transform: uppercase; margin-bottom: 4px;">
              Offensive ATT&CK Anchor
            </div>
            <div style="display: flex; justify-content: space-between; align-items: center;">
              <div>
                <span style="font-family: var(--font-mono); font-weight: 700; color: var(--text-primary); font-size: var(--text-sm);">
                  {selected.technique_id}
                </span>
                <span style="font-size: var(--text-xs); color: var(--text-secondary); margin-left: var(--space-2);">
                  {selected.technique_name}
                </span>
              </div>
              <a
                href="https://attack.mitre.org/techniques/{selected.technique_id.replace('.', '/')}"
                target="_blank"
                rel="noreferrer"
                class="btn btn--xs btn--ghost"
                style="font-family: var(--font-mono);"
              >
                ATT&CK ↗
              </a>
            </div>
          </div>

          <!-- Triage Runbook & Operational Guidance -->
          <div class="panel" style="padding: var(--space-3);">
            <div style="font-size: var(--text-2xs); font-family: var(--font-mono); color: var(--text-muted); text-transform: uppercase; margin-bottom: 6px;">
              Operational SOC Runbook
            </div>
            <div style="font-family: var(--font-mono); font-size: var(--text-xs); color: var(--accent-primary); background: var(--bg-surface-2); padding: var(--space-2); border-radius: var(--radius-xs); margin-bottom: var(--space-2);">
              {selected.runbook}
            </div>
            <p style="font-size: var(--text-xs); color: var(--text-secondary); line-height: 1.5; margin: 0;">
              This runbook guides triage analysts through isolating affected endpoints, inspecting process telemetry parentage, and validating whether architectural countermeasures (GPO, AppLocker, ASR rules) are actively enforced.
            </p>
          </div>

          <!-- D3FEND Knowledge Base Link -->
          <div class="panel" style="padding: var(--space-3);">
            <div style="font-size: var(--text-2xs); font-family: var(--font-mono); color: var(--text-muted); text-transform: uppercase; margin-bottom: 4px;">
              MITRE D3FEND Ontology Link
            </div>
            <a
              href="https://d3fend.mitre.org/technique/{selected.d3fend_id}"
              target="_blank"
              rel="noreferrer"
              style="font-size: var(--text-xs); font-family: var(--font-mono); color: var(--accent-primary); text-decoration: underline;"
            >
              https://d3fend.mitre.org/technique/{selected.d3fend_id}
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

{/if}

<style>
  .table-row--selected {
    background: var(--bg-surface-2) !important;
  }
</style>
