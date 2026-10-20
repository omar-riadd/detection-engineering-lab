/**
 * Typed API client — all REST calls to FastAPI backend.
 * All data comes from real project files via SQLite read model.
 */

export interface Rule {
  id: string;
  title: string;
  description: string | null;
  status: string;
  severity: string;
  techniques: string[];
  tactics: string[];
  category: string | null;
  log_source_product: string | null;
  log_source_service: string | null;
  file_path: string;
  sha256: string;
  sync_status: string;
  sync_error: string | null;
  synced_at: string | null;
  last_test_status: string | null;
  last_tested_at: string | null;
  fp_rate: number | null;
  raw_yaml?: string;
}

export interface RuleStats {
  total: number;
  by_severity: Record<string, number>;
  by_status: Record<string, number>;
  by_sync_status: Record<string, number>;
  unique_techniques: number;
  unique_tactics: number;
  techniques: string[];
  tactics: string[];
}

export interface AttackTechnique {
  technique_id: string;
  tactic: string;
  score: number;
  color: string;
  comment: string;
  enabled: boolean;
}

export interface AttackCoverage {
  layer_name: string;
  domain: string;
  attack_version: string;
  technique_count: number;
  gradient: Record<string, unknown>;
  legend: Array<{ label: string; color: string }>;
  techniques: AttackTechnique[];
}

export interface MttdEntry {
  rule_id: string;
  technique: string;
  mttd_seconds: number;
}

export interface MttdMetrics {
  avg_mttd_seconds: number;
  min_mttd_seconds: number;
  max_mttd_seconds: number;
  rule_count: number;
  entries: MttdEntry[];
}

export interface BypassAttempt {
  id: number;
  technique: string;
  technique_id: string | null;
  evasion_method: string;
  outcome: string;
  rule_hardened: string | null;
  notes: string | null;
}

export interface BypassStats {
  total_cases: number;
  by_outcome: Record<string, number>;
  detection_rate_pct: number;
}

export interface SyncStatus {
  db_healthy: boolean;
  rules_total: number;
  rules_synced: number;
  rules_error: number;
  bypass_entries: number;
  error?: string;
}

export interface ConvertedFormat {
  format: string;
  label: string;
  target: string;
  content: string | null;
}

export interface RuleConverted {
  rule_id: string;
  title: string;
  stem: string;
  techniques: string[];
  formats: {
    sigma: ConvertedFormat;
    wazuh: ConvertedFormat;
    kql: ConvertedFormat;
    splunk: ConvertedFormat;
  };
}

export interface TestRun {
  id: number;
  rule_id: string | null;
  run_type: string;
  status: string;
  exit_code: number | null;
  duration_seconds: number | null;
  output: string | null;
  started_at: string | null;
  finished_at: string | null;
}

export interface TestRunStats {
  total_runs: number;
  passed: number;
  failed: number;
  pass_rate_pct: number;
  avg_duration_seconds: number;
}

export interface D3fendMapping {
  technique_id: string;
  technique_name: string;
  d3fend_id: string;
  countermeasure: string;
  defense_type: string;
  runbook: string;
}

// ── Base fetch wrapper ────────────────────────────────────────────────────

async function apiFetch<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(path, options);
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`API ${path} → ${res.status}: ${text}`);
  }
  return res.json() as Promise<T>;
}

export interface RuleSaveResult {
  status: string;
  action: string;
  rule_id: string;
  title: string;
  severity: string;
  status_level: string;
  synced_at: string | null;
}

// ── Rules ─────────────────────────────────────────────────────────────────

export const rulesApi = {
  list(params?: {
    severity?: string;
    status?: string;
    technique?: string;
    tactic?: string;
    sync_status?: string;
    search?: string;
  }): Promise<Rule[]> {
    const q = new URLSearchParams();
    if (params?.severity)    q.set('severity', params.severity);
    if (params?.status)      q.set('status', params.status);
    if (params?.technique)   q.set('technique', params.technique);
    if (params?.tactic)      q.set('tactic', params.tactic);
    if (params?.sync_status) q.set('sync_status', params.sync_status);
    if (params?.search)      q.set('search', params.search);
    const qs = q.toString();
    return apiFetch<Rule[]>(`/api/rules${qs ? '?' + qs : ''}`);
  },

  stats(): Promise<RuleStats> {
    return apiFetch<RuleStats>('/api/rules/stats');
  },

  get(id: string): Promise<Rule> {
    return apiFetch<Rule>(`/api/rules/${id}`);
  },

  converted(id: string): Promise<RuleConverted> {
    return apiFetch<RuleConverted>(`/api/rules/${id}/converted`);
  },

  save(id: string, yamlContent: string): Promise<RuleSaveResult> {
    return apiFetch<RuleSaveResult>(`/api/rules/${id}/save`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ yaml_content: yamlContent }),
    });
  },
};

// ── Test Runs ─────────────────────────────────────────────────────────────

export const testRunsApi = {
  list(params?: {
    rule_id?: string;
    run_type?: string;
    status?: string;
    limit?: number;
  }): Promise<TestRun[]> {
    const q = new URLSearchParams();
    if (params?.rule_id)  q.set('rule_id', params.rule_id);
    if (params?.run_type) q.set('run_type', params.run_type);
    if (params?.status)   q.set('status', params.status);
    if (params?.limit)    q.set('limit', String(params.limit));
    const qs = q.toString();
    return apiFetch<TestRun[]>(`/api/test-runs${qs ? '?' + qs : ''}`);
  },

  stats(): Promise<TestRunStats> {
    return apiFetch<TestRunStats>('/api/test-runs/stats');
  },

  get(id: number): Promise<TestRun> {
    return apiFetch<TestRun>(`/api/test-runs/${id}`);
  },
};

// ── Coverage ──────────────────────────────────────────────────────────────

export const coverageApi = {
  attack(): Promise<AttackCoverage> {
    return apiFetch<AttackCoverage>('/api/coverage/attack');
  },
  mttd(): Promise<MttdMetrics> {
    return apiFetch<MttdMetrics>('/api/coverage/mttd');
  },
  d3fend(): Promise<{ count: number; mappings: D3fendMapping[] }> {
    return apiFetch('/api/coverage/d3fend');
  },
  fpReport(): Promise<{ overall_fp_rate: number; rule_count: number; entries: unknown[] }> {
    return apiFetch('/api/coverage/fp-report');
  },
};

// ── Bypass ────────────────────────────────────────────────────────────────

export const bypassApi = {
  list(): Promise<BypassAttempt[]> {
    return apiFetch<BypassAttempt[]>('/api/bypass');
  },
  stats(): Promise<BypassStats> {
    return apiFetch<BypassStats>('/api/bypass/stats');
  },
};

// ── Sync ──────────────────────────────────────────────────────────────────

export const syncApi = {
  status(): Promise<SyncStatus> {
    return apiFetch<SyncStatus>('/api/sync/status');
  },
  rebuild(): Promise<{ status: string; message: string }> {
    return apiFetch('/api/sync/rebuild', { method: 'POST' });
  },
  forceRule(ruleId: string): Promise<{ status: string; rule_id: string; action: string; file: string }> {
    return apiFetch(`/api/sync/force-rule/${ruleId}`, { method: 'POST' });
  },
};

// ── Health ────────────────────────────────────────────────────────────────

export const healthApi = {
  check(): Promise<{ status: string; version: string; ws_clients: number }> {
    return apiFetch('/api/health');
  },
};

// ── Reports ───────────────────────────────────────────────────────────────

export interface ExecutiveReportSummary {
  generated_at: string;
  portfolio_version: string;
  executive_summary: {
    title: string;
    overall_status: string;
    frameworks: string[];
    total_detections: number;
    unique_techniques: number;
    false_positive_rate_pct: number;
    mean_time_to_detect_seconds: number;
    adversarial_bypasses_tested: number;
    adversarial_bypasses_mitigated: number;
    bypass_mitigation_rate_pct: number;
    ci_regression_pass_rate_pct: number;
    total_test_executions: number;
  };
  severity_distribution: Record<string, number>;
  lifecycle_status: Record<string, number>;
  techniques_covered: string[];
  d3fend_countermeasures_count: number;
  recent_bypasses: Array<{
    case_id: number;
    technique: string;
    evasion_method: string;
    outcome: string;
    fix_applied: string;
  }>;
}

export const reportsApi = {
  summary(): Promise<ExecutiveReportSummary> {
    return apiFetch<ExecutiveReportSummary>('/api/reports/summary');
  },
  markdownUrl(): string {
    return '/api/reports/markdown';
  },
};

