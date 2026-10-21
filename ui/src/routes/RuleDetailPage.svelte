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
  let testExitCode = $state<number | null>(null);
  let testWs: WebSocket | null = null;

  $effect(() => {
    loading = true;
    rule = null;
    converted = null;
    syncMsg = null;
    testOutput = [];
    testExitCode = null;

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
    const content = activeFormat === 'sigma' ? rule?.raw_yaml : converted?.formats[activeFormat]?.content;
    if (!content) return;
    try {
      await navigator.clipboard.writeText(content);
      copied = true;
      setTimeout(() => copied = false, 1800);
    } catch (_) {}
  }

  async function triggerForceSync() {
    if (syncing) return;
    syncing = true;
    syncMsg = 'Re-syncing with disk...';
    try {
      const res = await syncApi.forceRule(ruleId);
      syncMsg = `Synced (${res.action})`;
      rule = await rulesApi.get(ruleId);
      converted = await rulesApi.converted(ruleId).catch(() => null);
    } catch (e: any) {
      syncMsg = `Sync failed: ${e.message}`;
    } finally {
      syncing = false;
      setTimeout(() => syncMsg = null, 3000);
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
      syncMsg = `Saved and reconciled: ${res.title}`;
      rule = await rulesApi.get(rule.id);
      converted = await rulesApi.converted(rule.id).catch(() => null);
      isEditing = false;
      setTimeout(() => { saveSuccess = false; syncMsg = null; }, 3500);
    } catch (e: any) {
      saveError = e.message;
    } finally {
      saving = false;
    }
  }

  function runTests() {
    if (testRunning) return;
    testOutput = [];
    testExitCode = null;
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
          const el = document.getElementById('rule-test-terminal');
          if (el) el.scrollTop = el.scrollHeight;
        });
      }
      if (msg.type === 'exit') {
        testRunning = false;
        testExitCode = msg.code;
        testOutput = [...testOutput, `\n[VERIFICATION COMPLETE] Exit code: ${msg.code}`];
      }
    };

    testWs.onerror = () => {
      testRunning = false;
      testOutput = [...testOutput, '[ERROR] WebSocket connection failed'];
    };
  }

  const formats = [
    { key: 'sigma',  label: 'Sigma YAML',    target: 'Vendor-Neutral' },
    { key: 'wazuh',  label: 'Wazuh XML',     target: 'analysisd Engine' },
    { key: 'kql',    label: 'Sentinel KQL',  target: 'Azure Log Analytics' },
    { key: 'splunk', label: 'Splunk SPL',    target: 'Enterprise Search' },
  ] as const;
</script>

<div class="view-content">
  <!-- Top Navigation & Action Header -->
  <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: var(--space-4); padding-bottom: var(--space-3); border-bottom: 1px solid var(--border-subtle);">
    <div style="display: flex; align-items: center; gap: var(--space-3);">
      <button class="btn btn--secondary btn--sm" onclick={onback}>
        ← Rules Catalog
      </button>
      <span class="badge badge--mono" style="font-size: var(--text-2xs); color: var(--text-muted);">
        {ruleId}
      </span>
      {#if syncMsg}
        <span class="status-pill status-pill--success">{syncMsg}</span>
      {/if}
    </div>

    <div style="display: flex; align-items: center; gap: var(--space-2);">
      {#if isEditing}
        <button class="btn btn--secondary btn--sm" onclick={cancelEditing} disabled={saving}>
          Cancel
        </button>
        <button class="btn btn--primary btn--sm" onclick={saveRule} disabled={saving}>
          {saving ? 'Validating & Writing...' : 'Save to Disk & Reconcile'}
        </button>
      {:else}
        <button class="btn btn--secondary btn--sm" onclick={startEditing}>
          Edit YAML
        </button>
        <button class="btn btn--secondary btn--sm" onclick={triggerForceSync} disabled={syncing}>
          {syncing ? 'Syncing...' : 'Force Sync'}
        </button>
        <button class="btn btn--primary btn--sm" onclick={runTests} disabled={testRunning}>
          {testRunning ? 'Running Tests...' : 'Run Unit Tests'}
        </button>
      {/if}
    </div>
  </div>

  {#if loading}
    <div style="padding: var(--space-8); text-align: center; color: var(--text-muted); font-size: var(--text-xs);">
      <span class="status-beacon status-beacon--syncing" style="display: inline-block; margin-right: 6px;"></span>
      Loading rule AST and transpilation artifacts...
    </div>
  {:else if error}
    <div style="padding: var(--space-4); background: var(--sev-critical-bg); border: 1px solid var(--sev-critical-border); border-radius: var(--radius-sm); color: var(--sev-critical); font-size: var(--text-xs);">
      Error: {error}
    </div>
  {:else if rule}

    <!-- ── Two-Column Workbench Layout ──────────────────────────────────── -->
    <div style="display: grid; grid-template-columns: 1fr 380px; gap: var(--space-5);">
      
      <!-- Left Column: Code Editor & Query Tabs -->
      <div style="display: flex; flex-direction: column; gap: var(--space-3);">
        <div style="display: flex; align-items: center; justify-content: space-between;">
          <div style="display: flex; align-items: center; gap: var(--space-2);">
            <span class="sev-pill sev-pill--{rule.severity}">{rule.severity}</span>
            <span class="status-pill">{rule.status}</span>
            <h2 style="font-size: var(--text-md); font-weight: 700; color: var(--text-primary);">
              {rule.title}
            </h2>
          </div>
        </div>

        {#if saveError}
          <div style="padding: var(--space-2) var(--space-3); background: var(--sev-critical-bg); border: 1px solid var(--sev-critical-border); border-radius: var(--radius-xs); color: var(--sev-critical); font-size: var(--text-xs); font-family: var(--font-mono);">
            Validation Failed: {saveError}
          </div>
        {/if}

        <!-- Multi-SIEM Format Switcher -->
        {#if !isEditing}
          <div style="display: flex; gap: 1px; background: var(--border-subtle); border-radius: var(--radius-xs); overflow: hidden;">
            {#each formats as fmt}
              <button
                class="btn btn--sm"
                style="flex: 1; border-radius: 0; background: {activeFormat === fmt.key ? 'var(--bg-elevated)' : 'var(--bg-surface)'}; color: {activeFormat === fmt.key ? 'var(--accent-primary)' : 'var(--text-muted)'}; font-weight: {activeFormat === fmt.key ? '600' : '500'};"
                onclick={() => activeFormat = fmt.key}
              >
                {fmt.label}
              </button>
            {/each}
          </div>
        {/if}

        <!-- Code Editor / Viewer Box -->
        <div class="code-editor-chrome">
          <div class="code-editor-toolbar">
            <span class="tabular-nums" style="font-family: var(--font-mono); font-size: var(--text-2xs);">
              {#if isEditing}
                EDITING: rules/sigma/ (YAML) · {editYaml.split('\n').length} lines · {editYaml.length} chars
              {:else if activeFormat === 'sigma'}
                YAML (Source of Truth) · {rule.file_path}
              {:else if activeFormat === 'wazuh'}
                Wazuh XML · Parent SID: {rule.file_path.includes('linux') ? '80700' : '60103'}
              {:else if activeFormat === 'kql'}
                Microsoft Sentinel KQL Query
              {:else if activeFormat === 'splunk'}
                Splunk Search Processing Language (SPL)
              {/if}
            </span>
            <button class="btn btn--secondary btn--sm" onclick={copyActiveCode}>
              {copied ? '✓ Copied' : 'Copy'}
            </button>
          </div>

          {#if isEditing}
            <textarea
              class="code-editor-textarea"
              bind:value={editYaml}
              spellcheck="false"
            ></textarea>
          {:else}
            <pre class="code-editor-textarea" style="overflow-y: auto; max-height: 480px; white-space: pre-wrap;">{#if activeFormat === 'sigma'}{rule.raw_yaml}{:else}{converted?.formats[activeFormat]?.content || 'Query transpilation not ready'}{/if}</pre>
          {/if}
        </div>
      </div>

      <!-- Right Column: Contextual Inspector & Test Console -->
      <div style="display: flex; flex-direction: column; gap: var(--space-4);">
        
        <!-- Inspector Details Card -->
        <div style="background: var(--bg-surface); border: 1px solid var(--border-subtle); border-radius: var(--radius-sm); padding: var(--space-4);">
          <h3 style="font-size: var(--text-xs); font-family: var(--font-mono); font-weight: 600; text-transform: uppercase; color: var(--text-muted); margin-bottom: var(--space-3);">
            Detection Context & Telemetry
          </h3>

          <div style="display: flex; flex-direction: column; gap: var(--space-3); font-size: var(--text-xs);">
            <div>
              <span style="color: var(--text-muted); display: block; font-size: var(--text-2xs); margin-bottom: 2px;">MITRE ATT&CK TECHNIQUES</span>
              <div style="display: flex; gap: 4px; flex-wrap: wrap;">
                {#each rule.techniques as t}
                  <span class="badge badge--mono" style="color: var(--accent-primary); font-size: var(--text-2xs);">
                    {t}
                  </span>
                {/each}
              </div>
            </div>

            <div>
              <span style="color: var(--text-muted); display: block; font-size: var(--text-2xs); margin-bottom: 2px;">MITRE TACTICS</span>
              <div style="color: var(--text-secondary); font-family: var(--font-mono); font-size: var(--text-2xs);">
                {rule.tactics.join(', ') || 'execution'}
              </div>
            </div>

            <div>
              <span style="color: var(--text-muted); display: block; font-size: var(--text-2xs); margin-bottom: 2px;">LOG SOURCE TELEMETRY</span>
              <div style="color: var(--text-primary); font-family: var(--font-mono); font-size: var(--text-2xs);">
                {rule.log_source_product || 'windows'} / {rule.log_source_service || rule.category || 'process_creation'}
              </div>
            </div>

            <div>
              <span style="color: var(--text-muted); display: block; font-size: var(--text-2xs); margin-bottom: 2px;">TELEMETRY RUNBOOK</span>
              <span style="color: var(--accent-primary); font-family: var(--font-mono); font-size: var(--text-2xs);">
                runbooks/{rule.techniques[0] || 'T1059'}-triage.md
              </span>
            </div>
          </div>
        </div>

        <!-- Live Unit Test Terminal -->
        <div style="background: var(--bg-surface); border: 1px solid var(--border-subtle); border-radius: var(--radius-sm); padding: var(--space-4); display: flex; flex-direction: column; flex: 1;">
          <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: var(--space-2);">
            <div style="display: flex; align-items: center; gap: var(--space-2);">
              <h3 style="font-size: var(--text-xs); font-family: var(--font-mono); font-weight: 600; text-transform: uppercase; color: var(--text-muted);">
                Test Execution Console
              </h3>
              {#if testExitCode !== null}
                <span class="sev-pill sev-pill--{testExitCode === 0 ? 'low' : 'critical'}">
                  {testExitCode === 0 ? 'PASS (0)' : `FAIL (${testExitCode})`}
                </span>
              {/if}
            </div>
            <button class="btn btn--secondary btn--sm" onclick={runTests} disabled={testRunning}>
              {testRunning ? 'Testing...' : 'Run'}
            </button>
          </div>

          <div
            id="rule-test-terminal"
            class="terminal-pane"
            style="flex: 1; min-height: 200px; max-height: 320px; font-size: var(--text-2xs);"
          >
            {#if testOutput.length === 0}
              <div style="color: var(--text-muted); font-style: italic;">
                Click "Run" or "Run Unit Tests" to execute positive and negative log fixtures against this detection rule in real time.
              </div>
            {:else}
              {#each testOutput as line}
                <div class="terminal-line" class:terminal-line--pass={line.includes('PASSED')} class:terminal-line--fail={line.includes('FAILED') || line.includes('FAIL')}>
                  {line}
                </div>
              {/each}
            {/if}
          </div>
        </div>

      </div>

    </div>

  {/if}
</div>
