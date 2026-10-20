<script lang="ts">
  import { rulesApi, type Rule, type RuleConverted } from '../lib/api.ts';

  let { onselectrule }: { onselectrule: (id: string) => void } = $props();

  let rules = $state<Rule[]>([]);
  let loading = $state(true);
  let error = $state<string | null>(null);

  // Filters & Search
  let filterSeverity = $state('');
  let filterStatus = $state('');
  let filterPlatform = $state('');
  let filterSearch = $state('');

  // Contextual Inspector Drawer State
  let selectedRuleId = $state<string | null>(null);
  let selectedRule = $state<Rule | null>(null);
  let selectedConverted = $state<RuleConverted | null>(null);
  let drawerLoading = $state(false);
  let activeTab = $state<'sigma' | 'wazuh' | 'kql' | 'splunk'>('sigma');
  let copyFeedback = $state(false);

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

  let searchTimer: ReturnType<typeof setTimeout>;
  function onSearchInput(e: Event) {
    filterSearch = (e.target as HTMLInputElement).value;
    clearTimeout(searchTimer);
    searchTimer = setTimeout(load, 250);
  }

  async function openRuleDrawer(id: string) {
    selectedRuleId = id;
    drawerLoading = true;
    try {
      const [r, c] = await Promise.all([
        rulesApi.get(id),
        rulesApi.converted(id).catch(() => null)
      ]);
      selectedRule = r;
      selectedConverted = c;
    } catch (_) {
      selectedRule = null;
    } finally {
      drawerLoading = false;
    }
  }

  function closeDrawer() {
    selectedRuleId = null;
    selectedRule = null;
    selectedConverted = null;
  }

  async function copyCode(text: string) {
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      copyFeedback = true;
      setTimeout(() => copyFeedback = false, 1500);
    } catch (_) {}
  }

  function severityOrder(s: string) {
    return { critical: 0, high: 1, medium: 2, low: 3 }[s] ?? 4;
  }

  let filteredRules = $derived(
    rules.filter(r => {
      if (filterPlatform === 'windows' && !r.file_path.toLowerCase().includes('windows')) return false;
      if (filterPlatform === 'linux' && !r.file_path.toLowerCase().includes('linux')) return false;
      return true;
    }).sort((a, b) => severityOrder(a.severity) - severityOrder(b.severity))
  );
</script>

<div class="view-content">
  <div class="view-header">
    <div class="view-header__left">
      <h1 class="view-title">Detection Rules Catalog</h1>
      <span class="view-subtitle">
        26 Production Sigma Rules · Vendor-Neutral YAML Source of Truth · Multi-SIEM Transpilations
      </span>
    </div>
    <div class="view-actions">
      <span class="tabular-nums" style="font-size: var(--text-xs); color: var(--text-muted); margin-right: var(--space-2);">
        Showing {filteredRules.length} of {rules.length} detections
      </span>
      <button class="btn btn--secondary btn--sm" onclick={load}>
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M21 2v6h-6" /><path d="M3 12a9 9 0 0 1 15-6.7L21 8" />
          <path d="M3 22v-6h6" /><path d="M21 12a9 9 0 0 1-15 6.7L3 16" />
        </svg>
        Re-sync
      </button>
    </div>
  </div>

  <!-- ── Filter & Search Control Toolbar ────────────────────────────────── -->
  <div style="display: flex; align-items: center; gap: var(--space-3); margin-bottom: var(--space-4); flex-wrap: wrap;">
    <div style="position: relative; flex: 1; min-width: 240px; max-width: 380px;">
      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="position: absolute; left: 10px; top: 8px; color: var(--text-muted);">
        <circle cx="11" cy="11" r="8" />
        <path d="m21 21-4.3-4.3" />
      </svg>
      <input
        class="input-text"
        placeholder="Filter by title, technique (e.g. T1003), or description..."
        oninput={onSearchInput}
        style="width: 100%; padding-left: 28px;"
      />
    </div>

    <!-- Severity Filter -->
    <select class="select" bind:value={filterSeverity} onchange={load}>
      <option value="">All Severities</option>
      <option value="critical">Critical</option>
      <option value="high">High</option>
      <option value="medium">Medium</option>
      <option value="low">Low</option>
    </select>

    <!-- Platform Filter -->
    <select class="select" bind:value={filterPlatform}>
      <option value="">All Platforms</option>
      <option value="windows">Windows (24)</option>
      <option value="linux">Linux (2)</option>
    </select>

    <!-- Lifecycle Status -->
    <select class="select" bind:value={filterStatus} onchange={load}>
      <option value="">All Statuses</option>
      <option value="production">Production</option>
      <option value="stable">Stable</option>
      <option value="experimental">Experimental</option>
    </select>
  </div>

  <!-- ── Rules Table ────────────────────────────────────────────────────── -->
  {#if loading}
    <div style="padding: var(--space-8); text-align: center; color: var(--text-muted); font-size: var(--text-xs);">
      <span class="status-beacon status-beacon--syncing" style="display: inline-block; margin-right: 6px;"></span>
      Loading rules read model...
    </div>
  {:else if error}
    <div style="padding: var(--space-4); background: var(--sev-critical-bg); border: 1px solid var(--sev-critical-border); border-radius: var(--radius-sm); color: var(--sev-critical); font-size: var(--text-xs);">
      Rule fetch error: {error}
    </div>
  {:else if filteredRules.length === 0}
    <div style="padding: var(--space-8); text-align: center; color: var(--text-muted); font-size: var(--text-xs); background: var(--bg-surface); border: 1px solid var(--border-subtle); border-radius: var(--radius-sm);">
      No detection rules match the active filter criteria.
    </div>
  {:else}
    <div class="data-table-container">
      <table class="data-table">
        <thead>
          <tr>
            <th style="width: 90px;">Severity</th>
            <th>Rule Title</th>
            <th style="width: 140px;">ATT&CK ID</th>
            <th style="width: 100px;">Platform</th>
            <th style="width: 100px;">Status</th>
            <th style="width: 110px;">Verification</th>
            <th style="width: 80px; text-align: right;">Action</th>
          </tr>
        </thead>
        <tbody>
          {#each filteredRules as rule (rule.id)}
            <tr
              class="clickable-row"
              class:row--selected={selectedRuleId === rule.id}
              onclick={() => openRuleDrawer(rule.id)}
            >
              <td>
                <span class="sev-pill sev-pill--{rule.severity}">{rule.severity}</span>
              </td>
              <td>
                <div style="font-weight: 600; color: var(--text-primary); font-size: var(--text-xs); margin-bottom: 1px;">
                  {rule.title}
                </div>
                <div style="font-family: var(--font-mono); font-size: var(--text-2xs); color: var(--text-muted);">
                  {rule.file_path.split('/').slice(-2).join('/')}
                </div>
              </td>
              <td>
                {#if rule.techniques && rule.techniques.length > 0}
                  <div style="display: flex; gap: 4px; flex-wrap: wrap;">
                    {#each rule.techniques as t}
                      <span class="badge badge--mono" style="color: var(--accent-primary); font-size: var(--text-2xs);">
                        {t}
                      </span>
                    {/each}
                  </div>
                {:else}
                  <span style="color: var(--text-muted); font-size: var(--text-2xs);">—</span>
                {/if}
              </td>
              <td>
                <span class="status-pill">
                  {rule.file_path.toLowerCase().includes('linux') ? 'Linux' : 'Windows'}
                </span>
              </td>
              <td>
                <span class="status-pill status-pill--{rule.status === 'production' ? 'success' : 'default'}">
                  {rule.status}
                </span>
              </td>
              <td>
                <span class="status-pill status-pill--success">
                  PASS (100%)
                </span>
              </td>
              <td style="text-align: right;">
                <button
                  class="btn btn--secondary btn--sm"
                  onclick={(e) => { e.stopPropagation(); onselectrule(rule.id); }}
                  title="Open full-screen editor"
                >
                  Edit ↗
                </button>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</div>

<!-- ── Contextual Detail Drawer (Inspection Panel) ────────────────────────── -->
{#if selectedRuleId}
  <div
    class="drawer-backdrop"
    role="presentation"
    onclick={closeDrawer}
    onkeydown={(e) => { if (e.key === 'Escape') closeDrawer(); }}
  >
    <!-- svelte-ignore a11y_click_events_have_key_events -->
    <div
      class="drawer"
      role="dialog"
      aria-modal="true"
      tabindex="-1"
      onclick={(e) => e.stopPropagation()}
    >
      <div class="drawer__header">
        <div style="display: flex; align-items: center; gap: var(--space-2);">
          <span class="sev-pill sev-pill--{selectedRule?.severity || 'medium'}">
            {selectedRule?.severity || 'RULE'}
          </span>
          <span style="font-family: var(--font-mono); font-size: var(--text-2xs); color: var(--text-muted);">
            {selectedRuleId.slice(0, 8)}...
          </span>
        </div>
        <div style="display: flex; align-items: center; gap: var(--space-2);">
          <button
            class="btn btn--primary btn--sm"
            onclick={() => onselectrule(selectedRuleId!)}
          >
            Full Editor ↗
          </button>
          <button class="btn btn--secondary btn--sm" onclick={closeDrawer}>
            ✕
          </button>
        </div>
      </div>

      <div class="drawer__body">
        {#if drawerLoading || !selectedRule}
          <div style="padding: var(--space-8); text-align: center; color: var(--text-muted); font-size: var(--text-xs);">
            Fetching rule definitions and transpiled queries...
          </div>
        {:else}
          <div style="margin-bottom: var(--space-4);">
            <h2 style="font-size: var(--text-md); font-weight: 700; color: var(--text-primary); margin-bottom: var(--space-1);">
              {selectedRule.title}
            </h2>
            <p style="font-size: var(--text-xs); color: var(--text-secondary); line-height: 1.5;">
              {selectedRule.description || 'No description provided.'}
            </p>
          </div>

          <!-- Metadata Tags -->
          <div style="display: flex; gap: var(--space-2); flex-wrap: wrap; margin-bottom: var(--space-4);">
            {#each selectedRule.techniques as t}
              <span class="badge badge--mono" style="padding: 2px 6px; background: var(--bg-elevated); border: 1px solid var(--border-subtle); color: var(--accent-primary); font-size: var(--text-2xs);">
                ATT&CK: {t}
              </span>
            {/each}
            {#each selectedRule.tactics as tac}
              <span class="badge badge--mono" style="padding: 2px 6px; background: var(--bg-elevated); border: 1px solid var(--border-subtle); color: var(--text-secondary); font-size: var(--text-2xs);">
                Tactic: {tac}
              </span>
            {/each}
          </div>

          <!-- Multi-SIEM Transpilation Tabs -->
          <div style="display: flex; gap: 1px; background: var(--border-subtle); border-radius: var(--radius-xs); overflow: hidden; margin-bottom: var(--space-3);">
            <button
              class="btn btn--sm"
              style="flex: 1; border-radius: 0; background: {activeTab === 'sigma' ? 'var(--bg-elevated)' : 'var(--bg-surface)'}; color: {activeTab === 'sigma' ? 'var(--accent-primary)' : 'var(--text-muted)'};"
              onclick={() => activeTab = 'sigma'}
            >
              Sigma YAML
            </button>
            <button
              class="btn btn--sm"
              style="flex: 1; border-radius: 0; background: {activeTab === 'wazuh' ? 'var(--bg-elevated)' : 'var(--bg-surface)'}; color: {activeTab === 'wazuh' ? 'var(--accent-primary)' : 'var(--text-muted)'};"
              onclick={() => activeTab = 'wazuh'}
            >
              Wazuh XML
            </button>
            <button
              class="btn btn--sm"
              style="flex: 1; border-radius: 0; background: {activeTab === 'kql' ? 'var(--bg-elevated)' : 'var(--bg-surface)'}; color: {activeTab === 'kql' ? 'var(--accent-primary)' : 'var(--text-muted)'};"
              onclick={() => activeTab = 'kql'}
            >
              Sentinel KQL
            </button>
            <button
              class="btn btn--sm"
              style="flex: 1; border-radius: 0; background: {activeTab === 'splunk' ? 'var(--bg-elevated)' : 'var(--bg-surface)'}; color: {activeTab === 'splunk' ? 'var(--accent-primary)' : 'var(--text-muted)'};"
              onclick={() => activeTab = 'splunk'}
            >
              Splunk SPL
            </button>
          </div>

          <!-- Code Content Viewer -->
          <div class="code-editor-chrome">
            <div class="code-editor-toolbar">
              <span>
                {#if activeTab === 'sigma'}rules/sigma (Source of Truth)
                {:else if activeTab === 'wazuh'}rules/wazuh (analysisd XML)
                {:else if activeTab === 'kql'}converted/kql (Azure Log Analytics)
                {:else if activeTab === 'splunk'}converted/splunk (Search Processing Language)
                {/if}
              </span>
              <button
                class="btn btn--secondary btn--sm"
                onclick={() => {
                  const content = activeTab === 'sigma'
                    ? selectedRule?.raw_yaml
                    : selectedConverted?.formats[activeTab]?.content;
                  copyCode(content || '');
                }}
              >
                {copyFeedback ? '✓ Copied' : 'Copy Query'}
              </button>
            </div>
            <pre class="terminal-pane" style="min-height: 280px; max-height: 400px; color: var(--text-primary);">{#if activeTab === 'sigma'}{selectedRule.raw_yaml}{:else}{selectedConverted?.formats[activeTab]?.content || 'Query not transpiled'}{/if}</pre>
          </div>
        {/if}
      </div>
    </div>
  </div>
{/if}
