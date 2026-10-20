<script lang="ts">
  import { syncApi } from './lib/api.ts';
  import RulesPage from './routes/RulesPage.svelte';
  import RuleDetailPage from './routes/RuleDetailPage.svelte';
  import CoveragePage from './routes/CoveragePage.svelte';
  import D3fendPage from './routes/D3fendPage.svelte';
  import ReplayPage from './routes/ReplayPage.svelte';
  import PurpleTeamPage from './routes/PurpleTeamPage.svelte';
  import DashboardPage from './routes/DashboardPage.svelte';
  import ReportPage from './routes/ReportPage.svelte';

  // ── Router state (Svelte 5 runes) ─────────────────────────────────────
  type Route =
    | { name: 'dashboard' }
    | { name: 'rules' }
    | { name: 'rule-detail'; id: string }
    | { name: 'coverage' }
    | { name: 'd3fend' }
    | { name: 'replay' }
    | { name: 'purple-team' }
    | { name: 'report' };

  let route = $state<Route>({ name: 'dashboard' });
  let syncStatus = $state<{ db_healthy: boolean; rules_total: number; rules_synced: number; rules_error: number } | null>(null);
  let wsConnected = $state(false);
  let ruleChangedCount = $state(0);

  // ── Sync status polling ────────────────────────────────────────────────
  async function loadSyncStatus() {
    try {
      syncStatus = await syncApi.status();
    } catch (_) {
      syncStatus = null;
    }
  }
  $effect(() => {
    loadSyncStatus();
    const id = setInterval(loadSyncStatus, 15000);
    return () => clearInterval(id);
  });

  // ── WebSocket event bus with Auto-Reconnect (TD-07) ─────────────────────
  $effect(() => {
    let ws: WebSocket | null = null;
    let pingId: any = null;
    let reconnectTimeout: any = null;
    let backoff = 1000;
    let isDisposed = false;

    function connect() {
      if (isDisposed) return;
      const proto = window.location.protocol === 'https:' ? 'wss' : 'ws';
      ws = new WebSocket(`${proto}://${window.location.host}/ws/events`);

      ws.onopen = () => {
        wsConnected = true;
        backoff = 1000;
        loadSyncStatus();
      };

      ws.onclose = () => {
        wsConnected = false;
        if (!isDisposed) {
          reconnectTimeout = setTimeout(connect, Math.min(backoff * 1.5, 10000));
        }
      };

      ws.onerror = () => {
        wsConnected = false;
        ws?.close();
      };

      ws.onmessage = (e) => {
        try {
          const msg = JSON.parse(e.data);
          if (msg.event === 'rule_changed') {
            ruleChangedCount += 1;
            loadSyncStatus();
          }
        } catch (_) {}
      };

      if (!pingId) {
        pingId = setInterval(() => {
          if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send('ping');
          }
        }, 20000);
      }
    }

    connect();

    return () => {
      isDisposed = true;
      clearInterval(pingId);
      clearTimeout(reconnectTimeout);
      ws?.close();
    };
  });

  // ── Navigation ─────────────────────────────────────────────────────────
  function navigate(to: Route) { route = to; }

  function isActive(name: string) {
    return route.name === name || (name === 'rules' && route.name === 'rule-detail');
  }

  const navItems = [
    { name: 'dashboard',   label: 'Overview',        prefix: '01' },
    { name: 'rules',       label: 'Rules',            prefix: '02' },
    { name: 'coverage',    label: 'ATT&CK Coverage',    prefix: '03' },
    { name: 'd3fend',      label: 'D3FEND Matrix',    prefix: '04' },
    { name: 'replay',      label: 'Replay Engine',    prefix: '05' },
    { name: 'purple-team', label: 'Purple Team',      prefix: '06' },
    { name: 'report',      label: 'Executive Report', prefix: '07' },
  ] as const;
</script>

<div class="shell">
  <!-- ── Header ─────────────────────────────────────────────────────────── -->
  <header class="header">
    <button class="header__wordmark" onclick={() => navigate({ name: 'dashboard' })}>
      DE//LAB
    </button>
    <div class="header__sep"></div>
    <span class="header__meta">Detection Engineering Portfolio · v1.0</span>

    <div class="header__right">
      <!-- WebSocket connection indicator -->
      <span class="header__meta" title={wsConnected ? 'Live sync active' : 'Offline — reconnecting'}>
        {wsConnected ? '[LIVE]' : '[OFFLINE]'}
      </span>

      <!-- DB sync status -->
      {#if syncStatus}
        <div
          class="sync-dot"
          class:sync-dot--error={!syncStatus.db_healthy || (syncStatus.rules_error ?? 0) > 0}
          title={`DB: ${syncStatus.rules_synced}/${syncStatus.rules_total} rules synced`}
        ></div>
        <span class="header__meta">
          {syncStatus.rules_synced}/{syncStatus.rules_total}
        </span>
      {/if}
    </div>
  </header>

  <!-- ── Sidebar ────────────────────────────────────────────────────────── -->
  <nav class="sidebar" aria-label="Main Navigation">
    <div class="sidebar__section-label">Sections</div>
    {#each navItems as item}
      <button
        class="nav-item"
        class:nav-item--active={isActive(item.name)}
        onclick={() => navigate({ name: item.name })}
        aria-current={isActive(item.name) ? 'page' : undefined}
      >
        <span class="nav-item__prefix">{item.prefix}</span>
        {item.label}
      </button>
    {/each}

    <!-- Sigma rule sub-items (visible in rule detail) -->
    {#if ruleChangedCount > 0}
      <div style="padding: 8px 16px; font-size: 0.7rem; color: var(--amber);">
        ↻ {ruleChangedCount} rule{ruleChangedCount !== 1 ? 's' : ''} updated on disk
      </div>
    {/if}

    <div class="sidebar__section-label" style="margin-top: 16px;">Stack</div>
    <div style="padding: 4px 16px; font-size: 0.7rem; color: var(--ink-3); line-height: 1.8;">
      FastAPI 0.141<br/>
      SQLite (WAL)<br/>
      Svelte 5 (Runes)<br/>
      21 Sigma Rules<br/>
      48 Test Fixtures
    </div>
  </nav>

  <!-- ── Main content ───────────────────────────────────────────────────── -->
  <main class="main" id="main-content">
    {#if route.name === 'dashboard'}
      <DashboardPage onnavigate={navigate} />
    {:else if route.name === 'rules'}
      <RulesPage onselect={(id: string) => navigate({ name: 'rule-detail', id })} />
    {:else if route.name === 'rule-detail'}
      <RuleDetailPage
        ruleId={route.id}
        onback={() => navigate({ name: 'rules' })}
      />
    {:else if route.name === 'coverage'}
      <CoveragePage />
    {:else if route.name === 'd3fend'}
      <D3fendPage />
    {:else if route.name === 'replay'}
      <ReplayPage />
    {:else if route.name === 'purple-team'}
      <PurpleTeamPage />
    {:else if route.name === 'report'}
      <ReportPage />
    {/if}
  </main>
</div>
