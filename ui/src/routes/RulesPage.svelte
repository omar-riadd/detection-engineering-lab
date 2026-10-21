<script lang="ts">
  import { rulesApi, type Rule } from '../lib/api.ts';

  let { onselect }: { onselect: (id: string) => void } = $props();

  let rules = $state<Rule[]>([]);
  let loading = $state(true);
  let error = $state<string | null>(null);

  // Filters
  let filterSeverity = $state('');
  let filterStatus = $state('');
  let filterSearch = $state('');

  async function load() {
    loading = true;
    error = null;
    try {
      rules = await rulesApi.list({
        severity: filterSeverity || undefined,
        status: filterStatus || undefined,
        search: filterSearch || undefined,
      });
    } catch (e: unknown) {
      error = (e as Error).message;
    } finally {
      loading = false;
    }
  }

  $effect(() => { load(); });

  // Debounced search
  let searchTimer: ReturnType<typeof setTimeout>;
  function onSearchInput(e: Event) {
    filterSearch = (e.target as HTMLInputElement).value;
    clearTimeout(searchTimer);
    searchTimer = setTimeout(load, 300);
  }

  function severityOrder(s: string) {
    return { critical: 0, high: 1, medium: 2, low: 3 }[s] ?? 4;
  }

  let sorted = $derived(
    [...rules].sort((a, b) => severityOrder(a.severity) - severityOrder(b.severity))
  );
</script>

<div class="page">
  <div class="page__header">
    <h1 class="page__title">Sigma Rules</h1>
    <span class="page__subtitle">{rules.length} rules · YAML source of truth → SQLite read model</span>
  </div>

  <!-- ── Filters ─────────────────────────────────────────────────────── -->
  <div class="filter-bar">
    <input
      class="filter-input"
      placeholder="Search title / description..."
      oninput={onSearchInput}
      style="width: 260px;"
    />

    <select
      class="filter-select"
      bind:value={filterSeverity}
      onchange={load}
    >
      <option value="">All Severities</option>
      <option value="critical">Critical</option>
      <option value="high">High</option>
      <option value="medium">Medium</option>
      <option value="low">Low</option>
    </select>

    <select
      class="filter-select"
      bind:value={filterStatus}
      onchange={load}
    >
      <option value="">All Statuses</option>
      <option value="stable">Stable</option>
      <option value="test">Test</option>
      <option value="experimental">Experimental</option>
    </select>

    <button class="btn btn--sm" onclick={load}>↺ Refresh</button>
  </div>

  <!-- ── Table ──────────────────────────────────────────────────────── -->
  {#if loading}
    <div class="state-loading">Loading rules</div>
  {:else if error}
    <div class="state-error">[ERROR] {error}</div>
  {:else if sorted.length === 0}
    <div class="state-empty">No rules match the current filters.</div>
  {:else}
    <table class="data-table">
      <thead>
        <tr>
          <th>Severity</th>
          <th>Title</th>
          <th>Techniques</th>
          <th>Status</th>
          <th>Sync</th>
          <th>Last Test</th>
        </tr>
      </thead>
      <tbody>
        {#each sorted as rule (rule.id)}
          <tr
            class="row--clickable"
            onclick={() => onselect(rule.id)}
            title="Click to view rule detail"
          >
            <td><span class="badge badge--{rule.severity}">{rule.severity}</span></td>
            <td class="truncate" style="max-width: 360px;">
              <span class="mono" style="font-size: var(--font-size-sm);">{rule.title}</span>
            </td>
            <td style="font-size: var(--font-size-xs); color: var(--ink-2);">
              {rule.techniques.join(', ') || '—'}
            </td>
            <td>
              <span class="status status--{rule.status === 'stable' ? 'stable' : 'warn'}">
                [{rule.status.toUpperCase()}]
              </span>
            </td>
            <td>
              <span class="status status--{rule.sync_status}">
                [{rule.sync_status.toUpperCase()}]
              </span>
              {#if rule.sync_error}
                <span style="color: var(--red); font-size: var(--font-size-xs);" title={rule.sync_error}> ⚠</span>
              {/if}
            </td>
            <td>
              {#if rule.last_test_status}
                <span class="status status--{rule.last_test_status}">
                  [{rule.last_test_status.toUpperCase()}]
                </span>
              {:else}
                <span style="color: var(--ink-4); font-size: var(--font-size-xs);">—</span>
              {/if}
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
</div>
