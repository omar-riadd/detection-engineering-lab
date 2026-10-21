<script lang="ts">
  import { rulesApi, testRunsApi, type Rule, type TestRun } from '../lib/api.ts';

  let rules = $state<Rule[]>([]);
  let recentRuns = $state<TestRun[]>([]);
  let loading = $state(true);
  let error = $state<string | null>(null);

  // Test runner state
  let output = $state<string[]>([]);
  let running = $state(false);
  let activeRunner = $state<'replay' | 'pytest' | null>(null);
  let exitCode = $state<number | null>(null);
  let selectedRule = $state('');
  let mode = $state<'all' | 'rule'>('all');
  let ws: WebSocket | null = null;

  // Telemetry History state
  let historyStats = $state<{
    total_runs: number;
    passed: number;
    failed: number;
    pass_rate_pct: number;
    avg_duration_seconds: number;
  } | null>(null);
  let statusFilter = $state<'all' | 'pass' | 'fail'>('all');
  let selectedRun = $state<TestRun | null>(null);
  let runLogModal = $state(false);

  let filteredRuns = $derived(
    statusFilter === 'all'
      ? recentRuns
      : recentRuns.filter(r => r.status === statusFilter)
  );

  async function loadData() {
    try {
      const [r, runs, stats] = await Promise.all([
        rulesApi.list(),
        testRunsApi.list({ limit: 25 }).catch(() => []),
        testRunsApi.stats().catch(() => null)
      ]);
      rules = r;
      recentRuns = runs;
      historyStats = stats;
      loading = false;
    } catch (e: any) {
      error = e.message;
      loading = false;
    }
  }

  $effect(() => {
    loadData();
  });

  async function refreshHistory() {
    try {
      const [runs, stats] = await Promise.all([
        testRunsApi.list({ limit: 25 }),
        testRunsApi.stats().catch(() => null)
      ]);
      recentRuns = runs;
      historyStats = stats;
    } catch (_) {}
  }

  async function viewRunLog(id: number) {
    try {
      selectedRun = await testRunsApi.get(id);
      runLogModal = true;
    } catch (_) {}
  }

  function clearTerminal() {
    output = [];
    exitCode = null;
  }

  function runReplay() {
    if (running) return;
    if (ws && ws.readyState !== WebSocket.CLOSED) {
      ws.close();
      ws = null;
    }
    output = [];
    exitCode = null;
    running = true;
    activeRunner = 'replay';

    const proto = window.location.protocol === 'https:' ? 'wss' : 'ws';
    ws = new WebSocket(`${proto}://${window.location.host}/ws/replay`);

    ws.onopen = () => {
      const msg = mode === 'all'
        ? { action: 'replay_all' }
        : { action: 'replay', rule_id: selectedRule };
      ws!.send(JSON.stringify(msg));
    };

    ws.onmessage = (e) => {
      const msg = JSON.parse(e.data);
      if (msg.type === 'status' || msg.type === 'stdout') {
        output = [...output, msg.data];
        requestAnimationFrame(() => {
          const el = document.getElementById('replay-terminal');
          if (el) el.scrollTop = el.scrollHeight;
        });
      }
      if (msg.type === 'exit') {
        running = false;
        activeRunner = null;
        exitCode = msg.code;
        output = [...output, `\n[PROCESS TERMINATED] Subprocess exit code: ${msg.code}`];
        refreshHistory();
      }
    };

    ws.onerror = () => {
      running = false;
      activeRunner = null;
      output = [...output, '[ERROR] WebSocket connection failed to establish'];
    };
  }

  function runPytest() {
    if (running) return;
    if (ws && ws.readyState !== WebSocket.CLOSED) {
      ws.close();
      ws = null;
    }
    output = [];
    exitCode = null;
    running = true;
    activeRunner = 'pytest';

    const proto = window.location.protocol === 'https:' ? 'wss' : 'ws';
    ws = new WebSocket(`${proto}://${window.location.host}/ws/test-runner`);

    ws.onopen = () => {
      ws!.send(JSON.stringify({ action: 'run_all' }));
    };

    ws.onmessage = (e) => {
      const msg = JSON.parse(e.data);
      if (msg.type === 'status' || msg.type === 'stdout') {
        output = [...output, msg.data];
        requestAnimationFrame(() => {
          const el = document.getElementById('replay-terminal');
          if (el) el.scrollTop = el.scrollHeight;
        });
      }
      if (msg.type === 'exit') {
        running = false;
        activeRunner = null;
        exitCode = msg.code;
        output = [...output, `\n[PROCESS TERMINATED] Subprocess exit code: ${msg.code}`];
        refreshHistory();
      }
    };

    ws.onerror = () => {
      running = false;
      activeRunner = null;
      output = [...output, '[ERROR] WebSocket connection failed to establish'];
    };
  }

  let copySuccess = $state(false);
  function copyModalOutput() {
    if (!selectedRun?.output) return;
    navigator.clipboard.writeText(selectedRun.output);
    copySuccess = true;
    setTimeout(() => { copySuccess = false; }, 2000);
  }
</script>

<div class="view-header">
  <div class="view-header__meta">
    <span class="view-header__breadcrumb">WORKSPACE // 05</span>
    <span class="view-header__divider">/</span>
    <span class="view-header__tag">CONTINUOUS VERIFICATION</span>
  </div>
  <div class="view-header__row">
    <div>
      <h1 class="view-title">Detection Replay & Test Harness</h1>
      <p class="view-description">
        Live asynchronous WebSocket subprocess execution · Replaying Sysmon telemetry fixtures against Sigma rules with SQLite history persistence.
      </p>
    </div>
    <div style="display: flex; gap: var(--space-2); align-items: center;">
      <span class="badge" style="background: var(--bg-surface); border: 1px solid var(--border-subtle); font-family: var(--font-mono);">
        WS:// {window.location.host}/ws/*
      </span>
      <span class="badge badge--low">ASYNC SUBPROCESS ENGINE</span>
    </div>
  </div>
</div>

{#if loading}
  <div class="state-empty">
    <span class="beacon beacon--live"></span>
    <span>Connecting to test runner daemon and loading historical telemetry...</span>
  </div>
{:else if error}
  <div class="callout callout--danger">
    <div class="callout__title">Failed to load replay harness</div>
    <div class="callout__body">{error}</div>
  </div>
{:else}

  <!-- ── Dual Execution Trigger Workbench ──────────────────────────────── -->
  <div style="display: grid; grid-template-columns: 1fr 1fr; gap: var(--space-4); margin-bottom: var(--space-5);">

    <!-- Log Replay Engine Panel -->
    <div class="panel" style="display: flex; flex-direction: column; justify-content: space-between;">
      <div>
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: var(--space-2);">
          <span style="font-size: var(--text-2xs); font-family: var(--font-mono); color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.04em;">
            ENGINE 01 // EVENT REPLAY
          </span>
          <span class="badge badge--cyan" style="font-family: var(--font-mono); font-size: 10px;">
            scripts/replay_logs.py
          </span>
        </div>
        <h3 style="font-family: var(--font-display); font-size: var(--text-base); margin-bottom: var(--space-1-5);">
          Sysmon Telemetry Replay Engine
        </h3>
        <p style="font-size: var(--text-xs); color: var(--text-secondary); line-height: 1.5; margin-bottom: var(--space-3);">
          Replays synthetic Sysmon XML/JSON events across 38 positive fixtures, 27 negative fixtures (65 total), and 1,207 benign events to verify rule triggers.
        </p>

        <!-- Mode Toggle & Rule Selection -->
        <div style="margin-bottom: var(--space-3);">
          <div style="display: flex; gap: var(--space-2); margin-bottom: var(--space-2);">
            <button
              class="btn btn--xs {mode === 'all' ? 'btn--primary' : 'btn--ghost'}"
              onclick={() => { mode = 'all'; }}
            >
              Full Corpus (All Rules)
            </button>
            <button
              class="btn btn--xs {mode === 'rule' ? 'btn--primary' : 'btn--ghost'}"
              onclick={() => { mode = 'rule'; }}
            >
              Single Targeted Rule
            </button>
          </div>

          {#if mode === 'rule'}
            <select class="input" bind:value={selectedRule} style="width: 100%; font-size: var(--text-xs);">
              <option value="">— Select targeted Sigma rule ({rules.length} rules available) —</option>
              {#each rules as r}
                <option value={r.id}>
                  {r.title} ({r.techniques?.[0] || 'MITRE'})
                </option>
              {/each}
            </select>
          {/if}
        </div>
      </div>

      <div style="display: flex; justify-content: space-between; align-items: center; border-top: 1px solid var(--border-subtle); padding-top: var(--space-3); margin-top: var(--space-2);">
        <div style="font-family: var(--font-mono); font-size: 10px; color: var(--text-muted);">
          {mode === 'all' ? 'Target: 27 attack fixtures' : selectedRule ? `Target: ${selectedRule}` : 'Select a rule'}
        </div>
        <button
          class="btn btn--primary"
          onclick={runReplay}
          disabled={running || (mode === 'rule' && !selectedRule)}
        >
          {running && activeRunner === 'replay' ? '▶ Replay Running...' : '▶ Execute Log Replay'}
        </button>
      </div>
    </div>

    <!-- Pytest CI Harness Panel -->
    <div class="panel" style="display: flex; flex-direction: column; justify-content: space-between;">
      <div>
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: var(--space-2);">
          <span style="font-size: var(--text-2xs); font-family: var(--font-mono); color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.04em;">
            ENGINE 02 // CI VERIFICATION
          </span>
          <span class="badge badge--low" style="font-family: var(--font-mono); font-size: 10px;">
            pytest tests/ -v
          </span>
        </div>
        <h3 style="font-family: var(--font-display); font-size: var(--text-base); margin-bottom: var(--space-1-5);">
          Detection-as-Code Regression Suite
        </h3>
        <p style="font-size: var(--text-xs); color: var(--text-secondary); line-height: 1.5; margin-bottom: var(--space-3);">
          Executes complete pytest test matrix: 91 automated tests (77 detection assertions + 14 API integration endpoints), 0 false positive baselines, and evasion bypass checks.
        </p>

        <!-- Command terminal preview -->
        <div class="terminal-pane" style="height: 48px; padding: var(--space-2); margin-bottom: var(--space-3); border-radius: var(--radius-xs);">
          <div style="font-family: var(--font-mono); font-size: 11px; color: var(--accent-primary);">
            <span style="color: var(--text-muted);">$ </span>pytest tests/ -v --no-header --tb=short
          </div>
        </div>
      </div>

      <div style="display: flex; justify-content: space-between; align-items: center; border-top: 1px solid var(--border-subtle); padding-top: var(--space-3); margin-top: var(--space-2);">
        <div style="font-family: var(--font-mono); font-size: 10px; color: var(--text-muted);">
          Environment: Sandbox CI / venv
        </div>
        <button
          class="btn btn--primary"
          onclick={runPytest}
          disabled={running}
        >
          {running && activeRunner === 'pytest' ? '▶ Tests Running...' : '▶ Execute Full Pytest Suite'}
        </button>
      </div>
    </div>

  </div>

  <!-- ── Live Streaming Terminal Console ────────────────────────────────── -->
  <div class="panel" style="padding: 0; overflow: hidden; margin-bottom: var(--space-5);">
    <div style="padding: var(--space-2-5) var(--space-3); background: var(--bg-surface-2); border-bottom: 1px solid var(--border-subtle); display: flex; justify-content: space-between; align-items: center;">
      <div style="display: flex; align-items: center; gap: var(--space-2);">
        <span class="status-indicator {running ? 'status-indicator--active' : 'status-indicator--idle'}"></span>
        <span style="font-family: var(--font-mono); font-size: var(--text-xs); font-weight: 700; text-transform: uppercase;">
          Live Subprocess Terminal Output
        </span>
        {#if running}
          <span class="badge badge--cyan" style="font-size: 10px;">
            STREAMING ({activeRunner})
          </span>
        {/if}
        {#if exitCode !== null}
          <span class="badge {exitCode === 0 ? 'badge--low' : 'badge--high'}" style="font-size: 10px; font-family: var(--font-mono);">
            EXIT CODE: {exitCode} {exitCode === 0 ? '(PASS)' : '(FAIL)'}
          </span>
        {/if}
      </div>

      <div style="display: flex; gap: var(--space-2); align-items: center;">
        <span style="font-size: var(--text-2xs); font-family: var(--font-mono); color: var(--text-muted);">
          {output.length} lines logged
        </span>
        <button class="btn btn--xs btn--ghost" onclick={clearTerminal} disabled={running || output.length === 0}>
          Clear Console
        </button>
      </div>
    </div>

    {#if output.length > 0}
      <div
        id="replay-terminal"
        class="terminal-pane"
        style="height: 380px; overflow-y: auto; padding: var(--space-3); margin: 0; border: none; font-size: 11px; line-height: 1.6;"
      >
        {#each output as line}
          <div style="white-space: pre-wrap; font-family: var(--font-mono); color: {line.includes('PASSED') || line.includes('PASS') ? 'var(--sev-low)' : line.includes('FAILED') || line.includes('ERROR') ? 'var(--sev-critical)' : line.includes('WARNING') ? 'var(--sev-medium)' : 'var(--text-secondary)'};">
            {line}
          </div>
        {/each}
      </div>
    {:else}
      <div style="padding: var(--space-8); text-align: center; color: var(--text-muted); font-family: var(--font-mono); font-size: var(--text-xs); background: var(--bg-surface);">
        <div style="margin-bottom: var(--space-1); color: var(--text-secondary); font-weight: 600;">
          Awaiting execution trigger...
        </div>
        <div>
          Click <strong>Execute Log Replay</strong> or <strong>Execute Full Pytest Suite</strong> to initiate live bidirectional streaming.
        </div>
      </div>
    {/if}
  </div>

  <!-- ── Telemetry Run History (SQLite WAL) ─────────────────────────────── -->
  {#if recentRuns.length > 0}
    <div class="panel" style="padding: 0; overflow: hidden; margin-bottom: var(--space-6);">
      <div style="padding: var(--space-3) var(--space-4); background: var(--bg-surface); border-bottom: 1px solid var(--border-subtle); display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: var(--space-2);">
        <div style="display: flex; align-items: center; gap: var(--space-3);">
          <span style="font-family: var(--font-mono); font-size: var(--text-xs); font-weight: 700; text-transform: uppercase;">
            Historical Test Telemetry (SQLite Read-Model)
          </span>
          {#if historyStats}
            <div style="display: flex; gap: var(--space-3); font-size: var(--text-2xs); font-family: var(--font-mono); color: var(--text-muted);">
              <span>Runs: <strong style="color: var(--text-primary);">{historyStats.total_runs}</strong></span>
              <span>Pass Rate: <strong style="color: var(--sev-low);">{historyStats.pass_rate_pct}%</strong></span>
              <span>Avg Latency: <strong style="color: var(--text-primary);">{historyStats.avg_duration_seconds}s</strong></span>
            </div>
          {/if}
        </div>

        <div style="display: flex; gap: var(--space-2); align-items: center;">
          <div class="btn-group">
            <button
              class="btn btn--xs {statusFilter === 'all' ? 'btn--primary' : 'btn--ghost'}"
              onclick={() => { statusFilter = 'all'; }}
            >
              All ({recentRuns.length})
            </button>
            <button
              class="btn btn--xs {statusFilter === 'pass' ? 'btn--primary' : 'btn--ghost'}"
              onclick={() => { statusFilter = 'pass'; }}
            >
              Pass ({recentRuns.filter(r => r.status === 'pass').length})
            </button>
            <button
              class="btn btn--xs {statusFilter === 'fail' ? 'btn--primary' : 'btn--ghost'}"
              onclick={() => { statusFilter = 'fail'; }}
            >
              Fail ({recentRuns.filter(r => r.status === 'fail').length})
            </button>
          </div>

          <button class="btn btn--xs btn--ghost" onclick={refreshHistory} title="Refresh historical logs">
            ↻ Refresh
          </button>
        </div>
      </div>

      <div style="overflow-x: auto;">
        <table class="table" style="margin: 0;">
          <thead>
            <tr>
              <th style="width: 80px;">Run ID</th>
              <th style="width: 100px;">Engine</th>
              <th>Target Suite / Rule</th>
              <th style="width: 100px;">Status</th>
              <th style="width: 110px;">Duration</th>
              <th style="width: 160px;">Finished At</th>
              <th style="width: 90px; text-align: right;">Action</th>
            </tr>
          </thead>
          <tbody>
            {#each filteredRuns as tr}
              <tr>
                <td style="font-family: var(--font-mono); font-weight: 700;">
                  <button
                    class="btn btn--xs btn--ghost"
                    style="padding: 2px 4px; font-family: var(--font-mono); color: var(--accent-primary);"
                    onclick={() => viewRunLog(tr.id)}
                  >
                    #{tr.id}
                  </button>
                </td>
                <td>
                  <span class="badge" style="background: var(--bg-surface-2); border: 1px solid var(--border-subtle); font-family: var(--font-mono); font-size: 10px;">
                    {tr.run_type}
                  </span>
                </td>
                <td style="font-size: var(--text-xs); font-family: var(--font-mono);">
                  {tr.rule_id || 'All Rules (Full Suite)'}
                </td>
                <td>
                  <span class="badge {tr.status === 'pass' ? 'badge--low' : 'badge--high'}" style="font-family: var(--font-mono); font-size: 10px;">
                    [{tr.status.toUpperCase()}]
                  </span>
                </td>
                <td style="font-family: var(--font-mono); font-size: var(--text-xs);">
                  {tr.duration_seconds ?? 0}s
                </td>
                <td style="font-size: var(--text-2xs); color: var(--text-muted); font-family: var(--font-mono);">
                  {tr.finished_at ? new Date(tr.finished_at).toLocaleString() : '—'}
                </td>
                <td style="text-align: right;">
                  <button class="btn btn--xs btn--ghost" onclick={() => viewRunLog(tr.id)}>
                    View Log
                  </button>
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    </div>
  {/if}

  <!-- ── Historical Run Log Modal ──────────────────────────────────────── -->
  {#if runLogModal && selectedRun}
    <div
      class="drawer-backdrop"
      role="button"
      tabindex="0"
      onclick={(e) => { if (e.target === e.currentTarget) runLogModal = false; }}
      onkeydown={(e) => { if (e.key === 'Escape') runLogModal = false; }}
      style="align-items: center; justify-content: center; padding: var(--space-4);"
    >
      <div class="panel" style="width: 100%; max-width: 860px; max-height: 85vh; display: flex; flex-direction: column; padding: 0; overflow: hidden; box-shadow: 0 16px 48px rgba(0,0,0,0.6);">
        <div style="padding: var(--space-3) var(--space-4); background: var(--bg-surface-2); border-bottom: 1px solid var(--border-subtle); display: flex; justify-content: space-between; align-items: center;">
          <div style="display: flex; align-items: center; gap: var(--space-2);">
            <span class="badge {selectedRun.status === 'pass' ? 'badge--low' : 'badge--high'}" style="font-family: var(--font-mono);">
              #{selectedRun.id} {selectedRun.status.toUpperCase()}
            </span>
            <span style="font-family: var(--font-mono); font-size: var(--text-xs); font-weight: 600;">
              Execution Telemetry Log ({selectedRun.run_type})
            </span>
          </div>

          <div style="display: flex; gap: var(--space-2); align-items: center;">
            <button class="btn btn--xs btn--ghost" onclick={copyModalOutput}>
              {copySuccess ? '✓ Copied' : 'Copy Output'}
            </button>
            <button class="btn btn--xs btn--ghost" onclick={() => { runLogModal = false; }}>
              ✕ Close
            </button>
          </div>
        </div>

        <div class="terminal-pane" style="flex: 1; overflow-y: auto; max-height: 60vh; font-size: 11px; padding: var(--space-3); margin: 0; border: none; border-radius: 0;">
          <pre style="margin: 0; font-family: var(--font-mono); white-space: pre-wrap;">{selectedRun.output || '[NO CAPTURED CONSOLE OUTPUT]'}</pre>
        </div>

        <div style="padding: var(--space-2-5) var(--space-4); background: var(--bg-surface-2); border-top: 1px solid var(--border-subtle); display: flex; justify-content: space-between; align-items: center; font-size: var(--text-2xs); font-family: var(--font-mono); color: var(--text-muted);">
          <span>Duration: {selectedRun.duration_seconds ?? 0}s</span>
          <span>Timestamp: {selectedRun.finished_at ? new Date(selectedRun.finished_at).toLocaleString() : '—'}</span>
        </div>
      </div>
    </div>
  {/if}

{/if}
