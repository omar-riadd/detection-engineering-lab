<script lang="ts">
  import { rulesApi, testRunsApi, type Rule, type TestRun } from '../lib/api.ts';

  let rules = $state<Rule[]>([]);
  let recentRuns = $state<TestRun[]>([]);
  let loading = $state(true);
  let error = $state<string | null>(null);

  // Test runner state
  let output = $state<string[]>([]);
  let running = $state(false);
  let exitCode = $state<number | null>(null);
  let selectedRule = $state('');
  let mode = $state<'all' | 'rule'>('all');
  let ws: WebSocket | null = null;

  // Telemetry History enhancements
  let historyStats = $state<{ total_runs: number; passed: number; failed: number; pass_rate_pct: number; avg_duration_seconds: number } | null>(null);
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
        testRunsApi.list({ limit: 20 }).catch(() => []),
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
        testRunsApi.list({ limit: 20 }),
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

  function runReplay() {
    if (running) return;
    if (ws && ws.readyState !== WebSocket.CLOSED) {
      ws.close();
      ws = null;
    }
    output = [];
    exitCode = null;
    running = true;

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
        exitCode = msg.code;
        output = [...output, `\n[REPLAY COMPLETE] Exit code: ${msg.code}`];
        refreshHistory();
      }
    };

    ws.onerror = () => {
      running = false;
      output = [...output, '[ERROR] WebSocket connection failed'];
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
        exitCode = msg.code;
        output = [...output, `\n[TESTS COMPLETE] Exit code: ${msg.code}`];
        refreshHistory();
      }
    };

    ws.onerror = () => {
      running = false;
      output = [...output, '[ERROR] WebSocket connection failed'];
    };
  }
</script>

<div class="page">
  <div class="page__header">
    <div>
      <h1 class="page__title">Detection Replay & Test Harness</h1>
      <span class="page__subtitle">Live WebSocket Subprocess Streaming · Continuous Verification</span>
    </div>
  </div>

  {#if loading}
    <div class="state-loading">Loading configuration</div>
  {:else if error}
    <div class="state-error">[ERROR] {error}</div>
  {:else}

    <!-- ── Execution trigger cards ─────────────────────────────── -->
    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: var(--sp-4); margin-bottom: var(--sp-5);">

      <!-- Replay engine card -->
      <div style="padding: var(--sp-5); background: var(--paper-2); border: var(--border);">
        <h3 style="margin-bottom: var(--sp-3); font-size: var(--font-size-md);">Log Replay Engine</h3>
        <p style="font-size: var(--font-size-xs); color: var(--ink-3); margin-bottom: var(--sp-4); line-height: 1.5;">
          Executes <code>scripts/replay_logs.py --type all --verbose</code> against all 27 attack fixtures, 20 negative fixtures, and 1,200 benign baseline events.
        </p>

        <div style="display: flex; gap: var(--sp-4); margin-bottom: var(--sp-4);">
          <label style="font-size: var(--font-size-xs); display: flex; align-items: center; gap: var(--sp-2); cursor: pointer;">
            <input type="radio" bind:group={mode} value="all" />
            All Rules (Full Corpus)
          </label>
          <label style="font-size: var(--font-size-xs); display: flex; align-items: center; gap: var(--sp-2); cursor: pointer;">
            <input type="radio" bind:group={mode} value="rule" />
            Single Rule
          </label>
        </div>

        {#if mode === 'rule'}
          <select class="select" bind:value={selectedRule} style="width: 100%; margin-bottom: var(--sp-3);">
            <option value="">— Select a rule —</option>
            {#each rules as r}
              <option value={r.id}>{r.title}</option>
            {/each}
          </select>
        {/if}

        <button
          class="btn btn--primary"
          onclick={runReplay}
          disabled={running || (mode === 'rule' && !selectedRule)}
        >
          {running ? '▶ Running...' : '▶ Run Replay Engine'}
        </button>
      </div>

      <!-- pytest card -->
      <div style="padding: var(--sp-5); background: var(--paper-2); border: var(--border);">
        <h3 style="margin-bottom: var(--sp-3); font-size: var(--font-size-md);">Pytest CI Regression Harness</h3>
        <p style="font-size: var(--font-size-xs); color: var(--ink-3); margin-bottom: var(--sp-4); line-height: 1.5;">
          Executes <code>pytest tests/ -v</code> across all 65 positive and negative test cases. Mirrors GitHub Actions Detection-as-Code pipeline.
        </p>
        <div class="terminal" style="height: 52px; font-size: 0.65rem; margin-bottom: var(--sp-3); padding: var(--sp-2);">
          <span class="terminal__prompt">$ </span>pytest tests/ -v --no-header --tb=short
        </div>
        <button
          class="btn btn--primary"
          onclick={runPytest}
          disabled={running}
        >
          {running ? '▶ Running...' : '▶ Run Full Pytest Suite'}
        </button>
      </div>
    </div>

    <!-- ── Live terminal output ────────────────────────────────── -->
    <div class="section-head">
      <span class="section-head__label">Live Execution Terminal</span>
      <div class="section-head__line"></div>
      {#if exitCode !== null}
        <span class="status status--{exitCode === 0 ? 'stable' : 'fail'}">
          [EXIT: {exitCode === 0 ? 'PASS' : 'FAIL'} (CODE {exitCode})]
        </span>
      {/if}
    </div>

    {#if output.length > 0}
      <div
        id="replay-terminal"
        class="terminal"
        style="height: 380px; overflow-y: auto; font-size: 0.68rem; margin-bottom: var(--sp-5);"
      >{output.join('\n')}</div>
    {:else}
      <div class="state-empty" style="margin-bottom: var(--sp-5);">
        Press a run button above to stream live subprocess execution.<br/>
        <span style="font-size: var(--font-size-xs); color: var(--ink-3);">
          WebSocket bidirectional stream (asyncio.create_subprocess_exec + PYTHONUNBUFFERED=1)
        </span>
      </div>
    {/if}

    <!-- ── Test Run History Table ──────────────────────────────── -->
    {#if recentRuns.length > 0}
      <div class="section-head">
        <span class="section-head__label">Test Telemetry History (Persisted in SQLite)</span>
        <div class="section-head__line"></div>
        <button class="btn btn--sm" onclick={refreshHistory} style="margin-left: auto;">↻ Refresh</button>
      </div>

      <!-- Telemetry summary cards & filter -->
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: var(--sp-3); flex-wrap: wrap; gap: var(--sp-2);">
        <div style="display: flex; gap: var(--sp-3); font-size: var(--font-size-xs);">
          {#if historyStats}
            <span>Total Runs: <strong>{historyStats.total_runs}</strong></span>
            <span>Pass Rate: <strong style="color: var(--green);">{historyStats.pass_rate_pct}%</strong></span>
            <span>Avg Duration: <strong>{historyStats.avg_duration_seconds}s</strong></span>
          {/if}
        </div>

        <div style="display: flex; gap: var(--sp-1);">
          <button
            class="btn btn--sm"
            style="border-color: {statusFilter === 'all' ? 'var(--ink-1)' : 'var(--ink-4)'}; font-weight: {statusFilter === 'all' ? '700' : '400'};"
            onclick={() => { statusFilter = 'all'; }}
          >
            All ({recentRuns.length})
          </button>
          <button
            class="btn btn--sm"
            style="border-color: {statusFilter === 'pass' ? 'var(--green)' : 'var(--ink-4)'}; font-weight: {statusFilter === 'pass' ? '700' : '400'};"
            onclick={() => { statusFilter = 'pass'; }}
          >
            Pass ({recentRuns.filter(r => r.status === 'pass').length})
          </button>
          <button
            class="btn btn--sm"
            style="border-color: {statusFilter === 'fail' ? 'var(--red)' : 'var(--ink-4)'}; font-weight: {statusFilter === 'fail' ? '700' : '400'};"
            onclick={() => { statusFilter = 'fail'; }}
          >
            Fail ({recentRuns.filter(r => r.status === 'fail').length})
          </button>
        </div>
      </div>

      <table class="data-table">
        <thead>
          <tr>
            <th style="width: 80px;">Run ID</th>
            <th style="width: 100px;">Type</th>
            <th style="width: 140px;">Target</th>
            <th style="width: 100px;">Status</th>
            <th style="width: 110px;">Duration</th>
            <th>Finished At</th>
            <th style="width: 80px; text-align: right;">Action</th>
          </tr>
        </thead>
        <tbody>
          {#each filteredRuns as tr}
            <tr>
              <td style="font-weight: 700; font-family: var(--font-mono);">
                <button
                  class="btn btn--sm"
                  style="border: none; padding: 0; background: transparent; color: var(--blue); text-decoration: underline; cursor: pointer;"
                  onclick={() => viewRunLog(tr.id)}
                >
                  #{tr.id}
                </button>
              </td>
              <td>
                <span class="badge" style="background: var(--paper-1); border: 1px solid var(--ink-3);">
                  {tr.run_type}
                </span>
              </td>
              <td style="font-size: var(--font-size-xs);">{tr.rule_id || 'All Rules (Full Suite)'}</td>
              <td>
                <span class="status status--{tr.status === 'pass' ? 'stable' : 'fail'}">
                  [{tr.status.toUpperCase()}]
                </span>
              </td>
              <td style="font-size: var(--font-size-xs); font-family: var(--font-mono);">{tr.duration_seconds ?? 0}s</td>
              <td style="font-size: var(--font-size-xs); color: var(--ink-3);">
                {tr.finished_at ? new Date(tr.finished_at).toLocaleTimeString() : '—'}
              </td>
              <td style="text-align: right;">
                <button class="btn btn--sm" onclick={() => viewRunLog(tr.id)}>Log</button>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}

    <!-- ── Run Log Modal ──────────────────────────────────────── -->
    {#if runLogModal && selectedRun}
      <div style="position: fixed; inset: 0; background: rgba(0,0,0,0.5); z-index: 1000; display: flex; align-items: center; justify-content: center; padding: var(--sp-4);">
        <div style="background: var(--paper-1); border: 1px solid var(--ink-2); width: 100%; max-width: 800px; max-height: 80vh; display: flex; flex-direction: column;">
          <div style="padding: var(--sp-3); border-bottom: 1px solid var(--ink-3); display: flex; justify-content: space-between; align-items: center; background: var(--paper-2);">
            <span style="font-weight: 700; font-size: var(--font-size-sm);">
              Test Run #{selectedRun.id} Terminal Telemetry Log ({selectedRun.run_type})
            </span>
            <button class="btn btn--sm" onclick={() => { runLogModal = false; }}>✕ Close</button>
          </div>
          <div class="terminal" style="margin: 0; border: none; flex: 1; overflow-y: auto; max-height: 60vh; font-size: 0.68rem; padding: var(--sp-3);">
            {selectedRun.output || '[NO CAPTURED OUTPUT]'}
          </div>
        </div>
      </div>
    {/if}

  {/if}
</div>
