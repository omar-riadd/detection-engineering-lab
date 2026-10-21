<script lang="ts">
  import { syncApi, rulesApi, type Rule } from './lib/api.ts';
  import RulesPage from './routes/RulesPage.svelte';
  import RuleDetailPage from './routes/RuleDetailPage.svelte';
  import CoveragePage from './routes/CoveragePage.svelte';
  import D3fendPage from './routes/D3fendPage.svelte';
  import ReplayPage from './routes/ReplayPage.svelte';
  import PurpleTeamPage from './routes/PurpleTeamPage.svelte';
  import DashboardPage from './routes/DashboardPage.svelte';
  import ReportPage from './routes/ReportPage.svelte';

  // ── Router state ──────────────────────────────────────────────────────────
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
  let currentTheme = $state<'dark' | 'light'>('dark');

  // Command Palette State
  let cmdOpen = $state(false);
  let cmdQuery = $state('');
  let allRules = $state<Rule[]>([]);

  // ── Sync status polling ──────────────────────────────────────────────────
  async function loadSyncStatus() {
    try {
      syncStatus = await syncApi.status();
    } catch (_) {
      syncStatus = null;
    }
  }

  $effect(() => {
    loadSyncStatus();
    rulesApi.list().then(r => allRules = r).catch(() => {});
    const id = setInterval(loadSyncStatus, 15000);
    return () => clearInterval(id);
  });

  // ── WebSocket event bus with Auto-Reconnect ──────────────────────────────
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

  // ── Theme toggle ──────────────────────────────────────────────────────────
  function toggleTheme() {
    currentTheme = currentTheme === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', currentTheme);
  }

  // ── Keyboard shortcuts (Ctrl+K, 1-7, Esc) ─────────────────────────────────
  function handleKeydown(e: KeyboardEvent) {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
      e.preventDefault();
      cmdOpen = !cmdOpen;
      cmdQuery = '';
      return;
    }
    if (e.key === 'Escape' && cmdOpen) {
      cmdOpen = false;
      return;
    }
    // Number keys when not in an input
    const tag = (e.target as HTMLElement)?.tagName?.toLowerCase();
    if (tag !== 'input' && tag !== 'textarea' && !cmdOpen) {
      if (e.key === '1') navigate({ name: 'dashboard' });
      else if (e.key === '2') navigate({ name: 'rules' });
      else if (e.key === '3') navigate({ name: 'coverage' });
      else if (e.key === '4') navigate({ name: 'd3fend' });
      else if (e.key === '5') navigate({ name: 'replay' });
      else if (e.key === '6') navigate({ name: 'purple-team' });
      else if (e.key === '7') navigate({ name: 'report' });
    }
  }

  // ── Navigation ───────────────────────────────────────────────────────────
  function navigate(to: Route) {
    route = to;
    cmdOpen = false;
  }

  function isActive(name: string) {
    return route.name === name || (name === 'rules' && route.name === 'rule-detail');
  }

  const navItems = [
    { name: 'dashboard',   label: 'Overview',     num: '1', badge: null },
    { name: 'rules',       label: 'Rules Catalog', num: '2', badge: '33' },
    { name: 'coverage',    label: 'ATT&CK Matrix', num: '3', badge: '27' },
    { name: 'd3fend',      label: 'D3FEND Matrix', num: '4', badge: '33' },
    { name: 'replay',      label: 'Replay Engine', num: '5', badge: 'LIVE' },
    { name: 'purple-team', label: 'Purple Team',   num: '6', badge: '7/7' },
    { name: 'report',      label: 'SOC Report',    num: '7', badge: null },
  ] as const;

  // Filtered command palette items
  let filteredCommands = $derived(
    cmdQuery.trim() === ''
      ? [
          { type: 'workspace', id: 'dashboard', title: '01 // System Overview', route: { name: 'dashboard' } as Route },
          { type: 'workspace', id: 'rules', title: '02 // Detection Rules Catalog', route: { name: 'rules' } as Route },
          { type: 'workspace', id: 'coverage', title: '03 // MITRE ATT&CK Matrix', route: { name: 'coverage' } as Route },
          { type: 'workspace', id: 'd3fend', title: '04 // MITRE D3FEND Countermeasures', route: { name: 'd3fend' } as Route },
          { type: 'workspace', id: 'replay', title: '05 // Subprocess Replay Engine', route: { name: 'replay' } as Route },
          { type: 'workspace', id: 'purple-team', title: '06 // Purple Team Adversarial Hardening', route: { name: 'purple-team' } as Route },
          { type: 'workspace', id: 'report', title: '07 // Executive Security Report', route: { name: 'report' } as Route },
        ]
      : [
          ...navItems
            .filter(n => n.label.toLowerCase().includes(cmdQuery.toLowerCase()))
            .map(n => ({ type: 'workspace', id: n.name, title: `Workspace: ${n.label}`, route: { name: n.name } as Route })),
          ...allRules
            .filter(r => r.title.toLowerCase().includes(cmdQuery.toLowerCase()) || r.techniques?.some(t => t.toLowerCase().includes(cmdQuery.toLowerCase())))
            .slice(0, 8)
            .map(r => ({ type: 'rule', id: r.id, title: `Rule: ${r.title}`, route: { name: 'rule-detail', id: r.id } as Route }))
        ]
  );
</script>

<svelte:window onkeydown={handleKeydown} />

<div class="app-shell">
  <!-- ── Top Command Bar ────────────────────────────────────────────────── -->
  <header class="topbar">
    <div class="topbar__left">
      <button class="topbar__brand" onclick={() => navigate({ name: 'dashboard' })}>
        <svg class="topbar__logo-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <circle cx="12" cy="12" r="10" />
          <path d="m4.93 4.93 4.24 4.24" />
          <path d="m14.83 9.17 4.24-4.24" />
          <path d="m14.83 14.83 4.24 4.24" />
          <path d="m9.17 14.83-4.24 4.24" />
          <circle cx="12" cy="12" r="3" />
        </svg>
        <span class="topbar__title">DETECTION LAB</span>
      </button>
      <span class="topbar__release-tag">v2.0</span>
      
      <div class="topbar__divider"></div>

      <nav class="topbar__breadcrumb" aria-label="Breadcrumb">
        <span>WORKBENCH</span>
        <span>/</span>
        <span class="topbar__breadcrumb-active">
          {#if route.name === 'dashboard'}01 OVERVIEW
          {:else if route.name === 'rules'}02 RULES
          {:else if route.name === 'rule-detail'}02 RULES / DETAIL
          {:else if route.name === 'coverage'}03 ATT&CK MATRIX
          {:else if route.name === 'd3fend'}04 D3FEND
          {:else if route.name === 'replay'}05 REPLAY ENGINE
          {:else if route.name === 'purple-team'}06 PURPLE TEAM
          {:else if route.name === 'report'}07 REPORT
          {/if}
        </span>
      </nav>
    </div>

    <div class="topbar__right">
      <!-- Quick search trigger -->
      <button class="topbar__search-trigger" onclick={() => { cmdOpen = true; cmdQuery = ''; }}>
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <circle cx="11" cy="11" r="8" />
          <path d="m21 21-4.3-4.3" />
        </svg>
        <span>Search workbench...</span>
        <span class="topbar__kbd">⌘K</span>
      </button>

      <div class="topbar__divider"></div>

      <!-- Live telemetry status -->
      <div class="topbar__status" title={wsConnected ? 'Connected to live event engine' : 'Reconnecting to API...'}>
        <div class="status-beacon" class:status-beacon--syncing={!wsConnected}></div>
        <span>{wsConnected ? 'LIVE' : 'SYNCING'}</span>
        {#if syncStatus}
          <span style="color: var(--text-muted);">({syncStatus.rules_synced}/{syncStatus.rules_total})</span>
        {/if}
      </div>
    </div>
  </header>

  <!-- ── Left Rail Sidebar ──────────────────────────────────────────────── -->
  <aside class="sidebar" aria-label="Workspace Navigation">
    <div class="sidebar__section-header">Operational Workspaces</div>
    <nav class="sidebar__nav">
      {#each navItems as item}
        <button
          class="sidebar__item"
          class:sidebar__item--active={isActive(item.name)}
          onclick={() => navigate({ name: item.name as any })}
        >
          <span class="sidebar__item-label">
            <span class="tabular-nums" style="opacity: 0.5; font-size: var(--text-2xs);">[{item.num}]</span>
            <span>{item.label}</span>
          </span>
          {#if item.badge}
            <span class="sidebar__item-badge">{item.badge}</span>
          {/if}
        </button>
      {/each}
    </nav>

    <div class="sidebar__footer">
      <button class="theme-toggle-btn" onclick={toggleTheme} title="Toggle theme (Light/Dark)">
        {#if currentTheme === 'dark'}
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="12" cy="12" r="5" />
            <path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42" />
          </svg>
          <span>Light</span>
        {:else}
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
          </svg>
          <span>Dark</span>
        {/if}
      </button>

      <span class="tabular-nums" style="font-size: var(--text-2xs); color: var(--text-muted);" title="Keyboard active">
        KEYS [1-7]
      </span>
    </div>
  </aside>

  <!-- ── Main Viewport ──────────────────────────────────────────────────── -->
  <main class="main-viewport">
    {#if route.name === 'dashboard'}
      <DashboardPage onnavigate={(dest) => navigate({ name: dest as any })} />
    {:else if route.name === 'rules'}
      <RulesPage onselectrule={(id) => navigate({ name: 'rule-detail', id })} />
    {:else if route.name === 'rule-detail'}
      <RuleDetailPage ruleId={route.id} onback={() => navigate({ name: 'rules' })} />
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

<!-- ── Command Palette Modal (Ctrl+K) ─────────────────────────────────── -->
{#if cmdOpen}
  <div
    class="cmd-palette-backdrop"
    role="presentation"
    onclick={() => { cmdOpen = false; }}
    onkeydown={(e) => { if (e.key === 'Escape') cmdOpen = false; }}
  >
    <!-- svelte-ignore a11y_click_events_have_key_events -->
    <div
      class="cmd-palette"
      role="dialog"
      aria-modal="true"
      tabindex="-1"
      onclick={(e) => e.stopPropagation()}
    >
      <div class="cmd-palette__input-row">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="color: var(--accent-primary);">
          <circle cx="11" cy="11" r="8" />
          <path d="m21 21-4.3-4.3" />
        </svg>
        <!-- svelte-ignore a11y_autofocus -->
        <input
          class="cmd-palette__input"
          placeholder="Search rules, tactics, workspaces... (Press Esc to close)"
          bind:value={cmdQuery}
          autofocus
        />
        <span class="topbar__kbd">ESC</span>
      </div>

      <div class="cmd-palette__list">
        {#each filteredCommands as item}
          <div
            class="cmd-palette__item"
            onclick={() => navigate(item.route)}
            role="button"
            tabindex="0"
            onkeydown={(e) => e.key === 'Enter' && navigate(item.route)}
          >
            <span>{item.title}</span>
            <span class="tabular-nums" style="font-size: var(--text-2xs); color: var(--text-muted); text-transform: uppercase;">
              {item.type}
            </span>
          </div>
        {/each}
        {#if filteredCommands.length === 0}
          <div style="padding: var(--space-4); text-align: center; color: var(--text-muted); font-size: var(--text-xs);">
            No matching rules or operational views found for "{cmdQuery}"
          </div>
        {/if}
      </div>
    </div>
  </div>
{/if}
