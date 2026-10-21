<script lang="ts">
  import { coverageApi, type D3fendMapping } from '../lib/api.ts';

  let mappings = $state<D3fendMapping[]>([]);
  let loading = $state(true);
  let error = $state<string | null>(null);
  let filterType = $state('');
  let search = $state('');

  $effect(() => {
    coverageApi.d3fend()
      .then(res => {
        mappings = res.mappings;
        loading = false;
      })
      .catch(err => {
        error = err.message;
        loading = false;
      });
  });

  const filteredMappings = $derived(
    mappings.filter(m => {
      const matchType = !filterType || m.defense_type.toLowerCase().includes(filterType.toLowerCase());
      const matchSearch = !search ||
        m.technique_id.toLowerCase().includes(search.toLowerCase()) ||
        m.technique_name.toLowerCase().includes(search.toLowerCase()) ||
        m.countermeasure.toLowerCase().includes(search.toLowerCase()) ||
        m.d3fend_id.toLowerCase().includes(search.toLowerCase());
      return matchType && matchSearch;
    })
  );

  const defenseTypes = $derived(
    Array.from(new Set(mappings.flatMap(m => m.defense_type.split('/').map(t => t.trim())))).filter(Boolean).sort()
  );
</script>

<div class="page">
  <div class="page__header">
    <div>
      <h1 class="page__title">MITRE D3FEND Countermeasures</h1>
      <span class="page__subtitle">Defensive Architecture Alignment · 100% Technique Mapping</span>
    </div>
  </div>

  {#if loading}
    <div class="state-loading">Loading D3FEND mappings</div>
  {:else if error}
    <div class="state-error">[ERROR] {error}</div>
  {:else}

    <!-- ── Summary Stats ────────────────────────────────────────────── -->
    <div class="stat-grid" style="margin-bottom: var(--sp-5);">
      <div class="stat-card">
        <div class="stat-card__label">Total Countermeasures</div>
        <div class="stat-card__value stat-card__value--green">{mappings.length}</div>
        <div class="stat-card__sub">100% Technique Alignment</div>
      </div>
      <div class="stat-card">
        <div class="stat-card__label">Framework</div>
        <div class="stat-card__value stat-card__value--blue">MITRE D3FEND</div>
        <div class="stat-card__sub">d3fend.mitre.org</div>
      </div>
      <div class="stat-card">
        <div class="stat-card__label">Architectural Defense Types</div>
        <div class="stat-card__value" style="font-size: var(--font-size-md); font-weight: 600; margin-top: var(--sp-2);">
          Detect · Harden · Isolate · Protect · Model
        </div>
        <div class="stat-card__sub">Defense-in-depth model</div>
      </div>
      <div class="stat-card">
        <div class="stat-card__label">Philosophy</div>
        <div style="font-size: var(--font-size-xs); color: var(--ink-2); line-height: 1.5; margin-top: var(--sp-1);">
          "Can the attack technique be hardened or isolated architecturally rather than just alerted?"
        </div>
      </div>
    </div>

    <!-- ── Filters ─────────────────────────────────────────────────── -->
    <div class="filter-bar" style="margin-bottom: var(--sp-4);">
      <input
        type="search"
        class="input"
        placeholder="Filter by Technique, D3FEND ID, or Countermeasure..."
        bind:value={search}
        style="max-width: 320px;"
      />

      <select class="select" bind:value={filterType}>
        <option value="">All Defense Types</option>
        {#each defenseTypes as dtype}
          <option value={dtype}>{dtype}</option>
        {/each}
      </select>

      <span style="font-size: var(--font-size-xs); color: var(--ink-3); margin-left: auto;">
        Showing {filteredMappings.length} of {mappings.length} mappings
      </span>
    </div>

    <!-- ── Table ───────────────────────────────────────────────────── -->
    <table class="data-table">
      <thead>
        <tr>
          <th style="width: 110px;">ATT&CK ID</th>
          <th style="width: 220px;">Technique Name</th>
          <th style="width: 100px;">D3FEND ID</th>
          <th>D3FEND Countermeasure</th>
          <th style="width: 140px;">Defense Type</th>
          <th style="width: 180px;">Triage Runbook</th>
        </tr>
      </thead>
      <tbody>
        {#each filteredMappings as row}
          <tr>
            <td>
              <span class="badge" style="background: var(--blue); color: #fff; font-size: 0.65rem;">
                {row.technique_id}
              </span>
            </td>
            <td style="font-weight: 600; font-size: var(--font-size-xs);">
              {row.technique_name}
            </td>
            <td>
              <span class="status status--stable" style="font-weight: 700;">
                [{row.d3fend_id}]
              </span>
            </td>
            <td style="font-size: var(--font-size-xs); color: var(--ink-1);">
              {row.countermeasure}
            </td>
            <td>
              <span style="font-size: var(--font-size-xs); color: var(--ink-2);">
                {row.defense_type}
              </span>
            </td>
            <td style="font-size: var(--font-size-xs); color: var(--ink-3); font-family: var(--font-mono);">
              {row.runbook}
            </td>
          </tr>
        {/each}
      </tbody>
    </table>

  {/if}
</div>
