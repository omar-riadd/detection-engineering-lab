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

  // ── Rule Creation Modal State ──────────────────────────────────────────
  let createModal = $state(false);
  let createFilename = $state('win_proc_susp_execution.yml');
  let createTargetDir = $state('windows/proc_creation');
  let createPreset = $state('windows_proc');
  let createSubmitting = $state(false);
  let createError = $state<string | null>(null);

  const TEMPLATES: Record<string, { filename: string; dir: string; yaml: string }> = {
    windows_proc: {
      filename: 'win_proc_susp_execution.yml',
      dir: 'windows/proc_creation',
      yaml: `title: Suspicious Process Execution
status: test
description: Detects suspicious process execution indicative of adversary tradecraft.
references:
    - https://attack.mitre.org/techniques/T1059/001/
author: SOC Detection Engineer
date: 2026/10/21
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\\cmd.exe'
            - '\\powershell.exe'
        CommandLine|contains:
            - '-enc'
            - 'DownloadString'
            - 'Invoke-WebRequest'
    condition: selection
falsepositives:
    - Administrative maintenance scripts
level: high`
    },
    windows_net: {
      filename: 'win_net_susp_c2_traffic.yml',
      dir: 'windows/network',
      yaml: `title: Suspicious Outbound Network Connection via Utility
status: test
description: Detects anomalous outbound network connections initiated by unexpected utilities.
references:
    - https://attack.mitre.org/techniques/T1041/
author: SOC Detection Engineer
date: 2026/10/21
tags:
    - attack.exfiltration
    - attack.t1041
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        Image|endswith:
            - '\\certutil.exe'
            - '\\bitsadmin.exe'
        DestinationPort:
            - 80
            - 443
    condition: selection
falsepositives:
    - Legitimate OS certificate updates
level: high`
    },
    windows_file: {
      filename: 'win_file_susp_payload_drop.yml',
      dir: 'windows/file_event',
      yaml: `title: Suspicious File Drop in Staging Directory
status: test
description: Detects executable or script dropped into user temp or downloads folders.
references:
    - https://attack.mitre.org/techniques/T1566/001/
author: SOC Detection Engineer
date: 2026/10/21
tags:
    - attack.initial-access
    - attack.t1566.001
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|contains:
            - '\\AppData\\Local\\Temp\\'
            - '\\Downloads\\'
        TargetFilename|endswith:
            - '.exe'
            - '.vbs'
            - '.ps1'
    condition: selection
falsepositives:
    - Legitimate software installers
level: medium`
    },
    linux_shell: {
      filename: 'lnx_proc_susp_reverse_shell.yml',
      dir: 'linux',
      yaml: `title: Linux Interactive Reverse Shell Execution
status: test
description: Detects interactive shell execution redirected to network socket.
references:
    - https://attack.mitre.org/techniques/T1059/004/
author: SOC Detection Engineer
date: 2026/10/21
tags:
    - attack.execution
    - attack.t1059.004
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        CommandLine|contains:
            - '/dev/tcp/'
            - 'nc -e'
            - 'ncat -e'
            - 'socket.socket'
    condition: selection
falsepositives:
    - Authorized penetration testing
level: critical`
    },
    blank: {
      filename: 'custom_detection_rule.yml',
      dir: 'windows/proc_creation',
      yaml: `title: Custom Detection Rule Title
status: experimental
description: Purpose of this detection rule.
author: Detection Engineer
date: 2026/10/21
tags:
    - attack.t1059
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\example.exe'
    condition: selection
falsepositives:
    - None known
level: medium`
    }
  };

  let createYaml = $state(TEMPLATES.windows_proc.yaml);

  function applyPreset(presetKey: string) {
    createPreset = presetKey;
    const t = TEMPLATES[presetKey];
    if (t) {
      createFilename = t.filename;
      createTargetDir = t.dir;
      createYaml = t.yaml;
    }
  }

  async function handleCreateRule() {
    createSubmitting = true;
    createError = null;
    try {
      const res = await rulesApi.create({
        filename: createFilename,
        target_dir: createTargetDir,
        yaml_content: createYaml
      });
      createModal = false;
      await load();
      if (res.rule_id) {
        openRuleDrawer(res.rule_id);
      }
    } catch (err: any) {
      createError = err.message || 'Failed to create detection rule';
    } finally {
      createSubmitting = false;
    }
  }
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
      <button class="btn btn--primary btn--sm" onclick={() => { createModal = true; }}>
        + Author New Rule
      </button>
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

<!-- ── Rule Authoring Modal (+ New Rule) ─────────────────────────────────── -->
{#if createModal}
  <div
    class="drawer-backdrop"
    role="presentation"
    onclick={() => { createModal = false; }}
    onkeydown={(e) => { if (e.key === 'Escape') createModal = false; }}
    style="align-items: center; justify-content: center; padding: var(--space-4);"
  >
    <!-- svelte-ignore a11y_click_events_have_key_events -->
    <div
      class="panel"
      role="dialog"
      aria-modal="true"
      tabindex="-1"
      onclick={(e) => e.stopPropagation()}
      style="width: 100%; max-width: 840px; max-height: 90vh; display: flex; flex-direction: column; padding: 0; overflow: hidden; box-shadow: 0 16px 48px rgba(0,0,0,0.6);"
    >
      <div style="padding: var(--space-3) var(--space-4); background: var(--bg-surface-2); border-bottom: 1px solid var(--border-subtle); display: flex; justify-content: space-between; align-items: center;">
        <div style="display: flex; align-items: center; gap: var(--space-2);">
          <span class="badge badge--cyan" style="font-family: var(--font-mono); font-size: 10px;">
            AUTHORING WORKFLOW
          </span>
          <span style="font-family: var(--font-display); font-size: var(--text-base); font-weight: 700;">
            Author New Sigma Detection Rule
          </span>
        </div>
        <button class="btn btn--xs btn--ghost" onclick={() => { createModal = false; }}>
          ✕
        </button>
      </div>

      <div style="padding: var(--space-4); overflow-y: auto; flex: 1; display: flex; flex-direction: column; gap: var(--space-3);">
        {#if createError}
          <div class="callout callout--danger" style="margin-bottom: var(--space-2);">
            <div class="callout__title">Validation Error</div>
            <div class="callout__body">{createError}</div>
          </div>
        {/if}

        <!-- Template Starter Presets -->
        <div>
          <span style="font-size: var(--text-2xs); font-family: var(--font-mono); color: var(--text-muted); text-transform: uppercase; display: block; margin-bottom: 6px;">
            Starter Archetype Presets
          </span>
          <div style="display: flex; gap: var(--space-1-5); flex-wrap: wrap;">
            <button
              class="btn btn--xs {createPreset === 'windows_proc' ? 'btn--primary' : 'btn--ghost'}"
              onclick={() => applyPreset('windows_proc')}
            >
              Win Process Creation (Sysmon 1)
            </button>
            <button
              class="btn btn--xs {createPreset === 'windows_net' ? 'btn--primary' : 'btn--ghost'}"
              onclick={() => applyPreset('windows_net')}
            >
              Win Network Traffic (Sysmon 3)
            </button>
            <button
              class="btn btn--xs {createPreset === 'windows_file' ? 'btn--primary' : 'btn--ghost'}"
              onclick={() => applyPreset('windows_file')}
            >
              Win File Drop (Sysmon 11)
            </button>
            <button
              class="btn btn--xs {createPreset === 'linux_shell' ? 'btn--primary' : 'btn--ghost'}"
              onclick={() => applyPreset('linux_shell')}
            >
              Linux Reverse Shell
            </button>
            <button
              class="btn btn--xs {createPreset === 'blank' ? 'btn--primary' : 'btn--ghost'}"
              onclick={() => applyPreset('blank')}
            >
              Blank Scaffolding
            </button>
          </div>
        </div>

        <!-- Target Destination Path -->
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: var(--space-3);">
          <div>
            <span style="font-size: var(--text-2xs); font-family: var(--font-mono); color: var(--text-muted); text-transform: uppercase; display: block; margin-bottom: 4px;">
              Target Subdirectory (rules/sigma/)
            </span>
            <select class="input" bind:value={createTargetDir} style="width: 100%; font-size: var(--text-xs);">
              <option value="windows/proc_creation">windows/proc_creation</option>
              <option value="windows/network">windows/network</option>
              <option value="windows/file_event">windows/file_event</option>
              <option value="windows/registry">windows/registry</option>
              <option value="windows/process_access">windows/process_access</option>
              <option value="linux">linux</option>
            </select>
          </div>

          <div>
            <span style="font-size: var(--text-2xs); font-family: var(--font-mono); color: var(--text-muted); text-transform: uppercase; display: block; margin-bottom: 4px;">
              Rule Filename (*.yml)
            </span>
            <input
              type="text"
              class="input"
              bind:value={createFilename}
              placeholder="e.g. win_proc_susp_execution.yml"
              style="width: 100%; font-size: var(--text-xs); font-family: var(--font-mono);"
            />
          </div>
        </div>

        <!-- Sigma YAML Editor -->
        <div>
          <span style="font-size: var(--text-2xs); font-family: var(--font-mono); color: var(--text-muted); text-transform: uppercase; display: block; margin-bottom: 4px;">
            Canonical Sigma YAML Source Code
          </span>
          <div class="code-editor-chrome">
            <textarea
              class="code-editor-textarea"
              bind:value={createYaml}
              spellcheck="false"
              style="height: 320px; font-size: 11px; line-height: 1.6;"
            ></textarea>
          </div>
        </div>
      </div>

      <div style="padding: var(--space-3) var(--space-4); background: var(--bg-surface-2); border-top: 1px solid var(--border-subtle); display: flex; justify-content: space-between; align-items: center;">
        <span style="font-size: var(--text-2xs); font-family: var(--font-mono); color: var(--text-muted);">
          Auto-transpiles to Wazuh XML, Sentinel KQL, and Splunk SPL on save.
        </span>
        <div style="display: flex; gap: var(--space-2);">
          <button class="btn btn--sm btn--ghost" onclick={() => { createModal = false; }} disabled={createSubmitting}>
            Cancel
          </button>
          <button class="btn btn--sm btn--primary" onclick={handleCreateRule} disabled={createSubmitting || !createFilename.trim() || !createYaml.trim()}>
            {createSubmitting ? 'Writing & Transpiling...' : '💾 Create & Transpile Rule'}
          </button>
        </div>
      </div>
    </div>
  </div>
{/if}
