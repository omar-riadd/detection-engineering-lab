<script lang="ts">
  import { rulesApi, syncApi, type Rule, type RuleConverted } from '../lib/api.ts';

  let { ruleId, onback }: { ruleId: string; onback: () => void } = $props();

  let rule = $state<Rule | null>(null);
  let converted = $state<RuleConverted | null>(null);
  let activeFormat = $state<'sigma' | 'wazuh' | 'kql' | 'splunk'>('sigma');
  let copied = $state(false);
  let syncing = $state(false);
  let syncMsg = $state<string | null>(null);
  let loading = $state(true);
  let error = $state<string | null>(null);

  // Live Rule Editor state
  let isEditing = $state(false);
  let editYaml = $state('');
  let saving = $state(false);
  let saveError = $state<string | null>(null);
  let saveSuccess = $state(false);

  // Test runner WebSocket state
  let testOutput = $state<string[]>([]);
  let testRunning = $state(false);
  let testWs: WebSocket | null = null;

  $effect(() => {
    loading = true;
    rule = null;
    converted = null;
    syncMsg = null;

    Promise.all([
      rulesApi.get(ruleId),
      rulesApi.converted(ruleId).catch(() => null)
    ])
      .then(([r, c]) => {
        rule = r;
        converted = c;
        loading = false;
      })
      .catch(e => {
        error = e.message;
        loading = false;
      });

    return () => {
      testWs?.close();
    };
  });

  async function copyActiveCode() {
    const content = converted?.formats[activeFormat]?.content || (activeFormat === 'sigma' ? rule?.raw_yaml : '');
    if (!content) return;
    try {
      await navigator.clipboard.writeText(content);
      copied = true;
      setTimeout(() => { copied = false; }, 2000);
    } catch (_) {
      // Fallback
      copied = false;
    }
  }

  async function triggerForceSync() {
    if (syncing) return;
    syncing = true;
    syncMsg = 'Re-syncing with disk...';
    try {
      const res = await syncApi.forceRule(ruleId);
      syncMsg = `[SYNCED] ${res.action.toUpperCase()} (${res.file})`;
      rule = await rulesApi.get(ruleId);
      converted = await rulesApi.converted(ruleId).catch(() => null);
    } catch (e: any) {
      syncMsg = `[ERROR] ${e.message}`;
    } finally {
      syncing = false;
      setTimeout(() => { syncMsg = null; }, 4000);
    }
  }

  function startEditing() {
    if (!rule) return;
    editYaml = rule.raw_yaml || '';
    saveError = null;
    saveSuccess = false;
    isEditing = true;
  }

  function cancelEditing() {
    isEditing = false;
    saveError = null;
  }

  async function saveRule() {
    if (saving || !rule) return;
    saving = true;
    saveError = null;
    try {
      const res = await rulesApi.save(rule.id, editYaml);
      saveSuccess = true;
      syncMsg = `[SAVED] ${res.action.toUpperCase()}: ${res.title}`;
      rule = await rulesApi.get(rule.id);
      converted = await rulesApi.converted(rule.id).catch(() => null);
      isEditing = false;
      setTimeout(() => { saveSuccess = false; syncMsg = null; }, 4000);
    } catch (e: any) {
      saveError = e.message;
    } finally {
      saving = false;
    }
  }

  function runTests() {
    if (testRunning) return;
    testOutput = [];
    testRunning = true;

    const proto = window.location.protocol === 'https:' ? 'wss' : 'ws';
    testWs = new WebSocket(`${proto}://${window.location.host}/ws/test-runner`);

    testWs.onopen = () => {
      testWs!.send(JSON.stringify({ action: 'run_tests', rule_id: ruleId }));
    };

    testWs.onmessage = (e) => {
      const msg = JSON.parse(e.data);
      if (msg.type === 'status' || msg.type === 'stdout') {
        testOutput = [...testOutput, msg.data];
        requestAnimationFrame(() => {
          const el = document.getElementById('test-terminal');
          if (el) el.scrollTop = el.scrollHeight;
        });
      }
      if (msg.type === 'exit') {
        testRunning = false;
        testOutput = [...testOutput, `\n[EXIT CODE: ${msg.code}]`];
      }
    };

    testWs.onerror = () => {
      testRunning = false;
      testOutput = [...testOutput, '[ERROR] WebSocket connection failed'];
    };
  }

  const formatList = [
    { key: 'sigma',  label: 'Sigma (YAML)',   target: 'Vendor-Neutral' },
    { key: 'wazuh',  label: 'Wazuh (XML)',    target: 'Wazuh Analysisd' },
    { key: 'kql',    label: 'Sentinel (KQL)', target: 'Microsoft Sentinel' },
    { key: 'splunk', label: 'Splunk (SPL)',   target: 'Splunk Enterprise' },
  ] as const;
</script>

<div class="page">
  <div style="display: flex; align-items: center; gap: var(--sp-3); margin-bottom: var(--sp-5);">
    <button class="btn btn--sm" onclick={onback}>← Back to Rules</button>
    <span style="color: var(--ink-3); font-size: var(--font-size-xs);">Rules / {ruleId}</span>
    
    <div style="margin-left: auto; display: flex; gap: var(--sp-2); align-items: center;">
      {#if syncMsg}
        <span style="font-size: var(--font-size-xs); color: var(--green); font-weight: 600;">{syncMsg}</span>
      {/if}
      {#if !isEditing}
        <button class="btn btn--sm" onclick={startEditing}>
          ✎ Edit YAML
        </button>
      {/if}
      <button class="btn btn--sm" onclick={triggerForceSync} disabled={syncing || isEditing}>
        {syncing ? 'Syncing...' : '↻ Force Re-sync'}
      </button>
    </div>
  </div>

  {#if loading}
    <div class="state-loading">Loading rule metadata and transpiled outputs</div>
  {:else if error}
    <div class="state-error">[ERROR] {error}</div>
  {:else if rule}

    <div class="page__header">
      <div>
        <div style="display: flex; gap: var(--sp-3); align-items: center; margin-bottom: var(--sp-2);">
          <span class="badge badge--{rule.severity}">{rule.severity}</span>
          <span class="status status--{rule.status === 'stable' ? 'stable' : 'warn'}">
            [{rule.status.toUpperCase()}]
          </span>
          <span class="status status--{rule.sync_status}">
            [SYNC: {rule.sync_status.toUpperCase()}]
          </span>
        </div>
        <h1 class="page__title" style="font-size: var(--font-size-xl);">{rule.title}</h1>
      </div>
    </div>

    <!-- ── Metadata grid ───────────────────────────────────────────── -->
    <div class="stat-grid" style="margin-bottom: var(--sp-5);">
      <div class="stat-card">
        <div class="stat-card__label">ATT&CK Techniques</div>
        <div style="font-size: var(--font-size-md); font-weight: 600; color: var(--blue);">
          {rule.techniques.length > 0 ? rule.techniques.join(', ') : '—'}
        </div>
      </div>
      <div class="stat-card">
        <div class="stat-card__label">Tactics</div>
        <div style="font-size: var(--font-size-md); font-weight: 600;">
          {rule.tactics.length > 0 ? rule.tactics.join(', ') : '—'}
        </div>
      </div>
      <div class="stat-card">
        <div class="stat-card__label">Log Source</div>
        <div style="font-size: var(--font-size-md); font-weight: 600;">
          {rule.log_source_product ?? ''}{rule.log_source_service ? ' / ' + rule.log_source_service : ''}{rule.category ? ' / ' + rule.category : ''}
          {#if !rule.log_source_product && !rule.category}—{/if}
        </div>
      </div>
      <div class="stat-card">
        <div class="stat-card__label">Source File</div>
        <div class="truncate" style="font-size: var(--font-size-xs); color: var(--ink-3);" title={rule.file_path}>
          {rule.file_path.split('/').slice(-2).join('/')}
        </div>
      </div>
    </div>

    <!-- ── Description ────────────────────────────────────────────── -->
    {#if rule.description}
      <div class="section-head">
        <span class="section-head__label">Description</span>
        <div class="section-head__line"></div>
      </div>
      <p style="font-size: var(--font-size-sm); color: var(--ink-2); margin-bottom: var(--sp-5); max-width: 820px; line-height: 1.7;">
        {rule.description}
      </p>
    {/if}

    {#if isEditing}
      <!-- ── Live Rule Editor (CQRS Write Path) ──────────────────────── -->
      <div class="section-head">
        <span class="section-head__label">Live Sigma Rule Editor (CQRS Round-Trip Write Path)</span>
        <div class="section-head__line"></div>
      </div>

      {#if saveError}
        <div class="state-error" style="margin-bottom: var(--sp-3);">
          [VALIDATION ERROR] {saveError}
        </div>
      {/if}

      <div style="border: 1px solid var(--ink-3); margin-bottom: var(--sp-5); background: var(--paper-2);">
        <div style="display: flex; background: var(--paper-1); border-bottom: 1px solid var(--ink-3); padding: var(--sp-2) var(--sp-3); align-items: center;">
          <span style="font-size: var(--font-size-xs); font-weight: 700; color: var(--amber);">
            [EDIT MODE] Editing YAML Source of Truth
          </span>
          <div style="margin-left: auto; display: flex; gap: var(--sp-2);">
            <button class="btn btn--sm" onclick={cancelEditing} disabled={saving}>
              Cancel
            </button>
            <button class="btn btn--sm btn--primary" onclick={saveRule} disabled={saving}>
              {saving ? 'Writing to Disk & Reconciling...' : '💾 Save to Disk & Reconcile'}
            </button>
          </div>
        </div>

        <textarea
          bind:value={editYaml}
          spellcheck="false"
          style="
            width: 100%;
            height: 420px;
            font-family: var(--font-mono);
            font-size: 0.76rem;
            line-height: 1.5;
            padding: var(--sp-3);
            border: none;
            outline: none;
            background: var(--paper-3);
            color: var(--ink-1);
            resize: vertical;
          "
        ></textarea>
        <div style="padding: var(--sp-2) var(--sp-3); font-size: var(--font-size-xs); color: var(--ink-3); border-top: 1px solid var(--ink-4); display: flex; justify-content: space-between;">
          <span>Lines: {editYaml.split('\n').length} | Characters: {editYaml.length}</span>
          <span>Target File: {rule.file_path.split('/').slice(-3).join('/')}</span>
        </div>
      </div>
    {:else}
      <!-- ── Multi-SIEM Transpiled Rules Viewer ───────────────────────── -->
      <div class="section-head">
        <span class="section-head__label">Multi-SIEM Detection Formats (Transpiled Outputs)</span>
        <div class="section-head__line"></div>
      </div>

      <div style="border: 1px solid var(--ink-3); margin-bottom: var(--sp-5); background: var(--paper-2);">
        <!-- Format Tabs -->
        <div style="display: flex; background: var(--paper-1); border-bottom: 1px solid var(--ink-3); align-items: center;">
          {#each formatList as fmt}
            <button
              class="btn"
              style="
                border: none;
                border-right: 1px solid var(--ink-3);
                background: {activeFormat === fmt.key ? 'var(--paper-2)' : 'transparent'};
                font-weight: {activeFormat === fmt.key ? '700' : '400'};
                color: {activeFormat === fmt.key ? 'var(--ink-1)' : 'var(--ink-3)'};
                padding: var(--sp-2) var(--sp-4);
              "
              onclick={() => { activeFormat = fmt.key; }}
            >
              {fmt.label}
            </button>
          {/each}

          <div style="margin-left: auto; padding-right: var(--sp-3); display: flex; gap: var(--sp-3); align-items: center;">
            <span style="font-size: var(--font-size-xs); color: var(--ink-3);">
              Target: <strong>{formatList.find(f => f.key === activeFormat)?.target}</strong>
            </span>
            <button class="btn btn--sm" onclick={copyActiveCode}>
              {copied ? '✓ Copied!' : 'Copy Code'}
            </button>
          </div>
        </div>

        <!-- Code Box -->
        <div class="yaml-block" style="border: none; margin: 0; min-height: 240px; max-height: 500px; overflow: auto;">
          {converted?.formats[activeFormat]?.content || (activeFormat === 'sigma' ? rule.raw_yaml : 'Format not available on disk')}
        </div>
      </div>
    {/if}

    <!-- ── Test runner ────────────────────────────────────────────── -->
    <div class="section-head">
      <span class="section-head__label">Live Detection Verification Harness</span>
      <div class="section-head__line"></div>
    </div>

    <div style="display: flex; gap: var(--sp-3); margin-bottom: var(--sp-3);">
      <button
        class="btn btn--primary"
        onclick={runTests}
        disabled={testRunning}
      >
        {testRunning ? '▶ Running pytest...' : '▶ Run Pytest Regression for this Rule'}
      </button>
    </div>

    {#if testOutput.length > 0}
      <div
        id="test-terminal"
        class="terminal"
        style="height: 320px; overflow-y: auto; font-size: 0.68rem;"
      >{testOutput.join('\n')}</div>
    {/if}

  {/if}
</div>
