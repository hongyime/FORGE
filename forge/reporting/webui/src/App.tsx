import { startTransition, useDeferredValue, useEffect, useState } from 'react'
import { Link, Route, Routes, useNavigate, useParams } from 'react-router-dom'
import './App.css'

type SummaryCounts = Record<string, number>
type SeveritySummary = Record<string, number>

type GraphSummary = {
  nodes: number
  edges: number
  critical_nodes: number
  critical_weight?: number
  entity_types?: Array<[string, number]>
  sample_nodes?: string[]
  source?: string
}

type Artifact = {
  name: string
  kind: string
  href: string
  path?: string
  size_label: string
  modified_at: string
}

type ReportPreview = {
  name: string
  href: string
  preview: string
}

type ReportExportArtifact = {
  artifact_name: string
  format: string
  label: string
}

type ReportSummary = {
  family_stem?: string
  artifact_name?: string
  provider?: string
  requested_provider?: string
  render_backend?: string
  upstream_provider?: string
  format?: string
  generated_at?: string
  fallback_reason?: string
  report_write_error?: string
  findings_checksum?: string
  raw_export?: boolean
  export_count?: number
  available_exports?: ReportExportArtifact[]
}

type SectionRow = Record<string, string>

type GraphNode = {
  node_id?: string
  label?: string
  node_type?: string
  entity_type?: string
  severity?: string
  source_table?: string
  source_id?: number | string
  on_critical_path?: boolean
  metadata?: Record<string, unknown>
}

type GraphEdge = {
  source_node_id?: string
  target_node_id?: string
  source?: string
  target?: string
  label?: string
  edge_type?: string
  weight?: number
  on_critical_path?: boolean
  metadata?: Record<string, unknown>
}

type GraphPayload = {
  nodes?: GraphNode[]
  edges?: GraphEdge[]
  critical_path_nodes?: string[]
  critical_path_weight?: number
  generated_at?: string
  source?: string
}

type AuditManifest = {
  present?: boolean
  verified?: boolean
  verification_status?: string
  manifest_hash?: string
  short_hash?: string
  previous_manifest_hash?: string
  generated_at?: string
  reason?: string | null
  recomputed_hash?: string
}

type RunSummary = {
  id?: number
  run_kind: string
  status: string
  seed_value: string
  seed_type: string
  seed_count: number
  max_iterations: number
  current_iteration: number
  resume_enabled: boolean
  dry_run: boolean
  attack_mode: boolean
  roe_id?: string
  roe_present?: boolean
  roe_missing?: boolean
  live_probing_allowed?: boolean
  tool_execution_allowed?: boolean
  active_recon_allowed?: boolean
  credential_validation_allowed?: boolean
  destructive_actions_allowed?: boolean
  post_exploitation_allowed?: boolean
  requires_explicit_roe?: boolean
  scope_gate?: string
  audit_manifest?: AuditManifest
  error: string
  metadata: Record<string, unknown>
  started_at: string
  completed_at: string
  updated_at: string
}

type EngagementSummary = {
  id: string
  slug: string
  name: string
  status: string
  operator: string
  tags?: string[]
  created_at: string
  updated_at: string
  latest_audit: string
  primary_seed: string
  seeds: string[]
  counts: SummaryCounts
  severity_summary: SeveritySummary
  highest_severity: string
  graph_summary: GraphSummary | null
  run_summary?: RunSummary | null
  report_count: number
  graph_count: number
  audit_count?: number
  detail_route: string
  detail_data: string
  detail_api?: string
}

type EngagementDetail = EngagementSummary & {
  path: string
  size_label: string
  scope: string[]
  sections: Record<string, SectionRow[]>
  artifacts: Artifact[]
  report_previews: ReportPreview[]
  report_summary?: ReportSummary
  report_history?: ReportSummary[]
  graph_payload?: GraphPayload
  graph_snapshot_at?: string
}

type EngagementIndex = {
  generated_at: string
  items: EngagementSummary[]
}

type SeedRecord = {
  id: number
  seed_value: string
  seed_type: string
  source: string
  status: string
  depth: number
  confidence: number
  parent_seed_id: number | null
  metadata: Record<string, unknown>
  discovered_at: string
  updated_at: string
}

type RunLog = {
  name: string
  href: string
  tail_api: string
  size_label: string
  modified_at: string
}

type RunLogTail = {
  name: string
  tail: string
  requested_lines: number
}

type KillChainLaunchPayload = {
  maxIter: number
  dryRun: boolean
  skipCloud: boolean
  skipKeyscan: boolean
  reportProvider: string
  reportMaxLoops: string
  resume?: boolean
}

type ProgressFeedEvent = {
  engagement_id: number
  message: string
  payload?: Record<string, unknown>
}

const SAMPLE_DETAIL: EngagementDetail[] = [
  {
    id: '1001',
    slug: 'engagement-1001-acme-holdings',
    name: 'Acme Holdings External Surface',
    status: 'active',
    operator: 'delta-one',
    tags: ['external', 'priority-high', 'finance'],
    created_at: '2026-07-08 22:14:09',
    updated_at: '2026-07-09 09:44:12',
    latest_audit: '2026-07-09 09:44:12',
    primary_seed: 'acme.example',
    seeds: ['acme.example', 'security@acme.example', '+15551234567'],
    counts: {
      hosts: 14,
      emails: 9,
      services: 17,
      crawl_results: 21,
      key_scanner_findings: 2,
      passive_vulns: 3,
      audit_log: 46,
    },
    severity_summary: {
      CRITICAL: 1,
      HIGH: 2,
      MEDIUM: 1,
      LOW: 3,
      INFO: 2,
    },
    highest_severity: 'CRITICAL',
    graph_summary: {
      nodes: 18,
      edges: 26,
      critical_nodes: 4,
      critical_weight: 18.6,
      entity_types: [
        ['HOST', 7],
        ['EMAIL', 4],
        ['CLOUD', 3],
        ['SERVICE', 2],
      ],
      sample_nodes: ['app.acme.example', 'storage bucket', 'admin panel', 'firebase project'],
      source: '1001_attack_graph.graphml',
    },
    run_summary: {
      run_kind: 'kill_chain',
      status: 'completed',
      seed_value: 'acme.example',
      seed_type: 'domain',
      seed_count: 3,
      max_iterations: 3,
      current_iteration: 2,
      resume_enabled: true,
      dry_run: false,
      attack_mode: false,
      error: '',
      metadata: {
        phase: 'completed',
        last_step: 'report generate',
        last_message: 'Narrative generated via deterministic fallback.',
        last_step_elapsed_seconds: 92.4,
        recent_steps: [
          { phase: 'iteration_2', step: '2.K5 findings', message: 'inserted=1 updated=0 removed=0 active=4', elapsed_seconds: 71.2 },
          { phase: 'iteration_2', step: 'report generate', message: 'Narrative generated via deterministic fallback.', elapsed_seconds: 92.4 },
        ],
      },
      started_at: '2026-07-09 09:00:00',
      completed_at: '2026-07-09 09:44:12',
      updated_at: '2026-07-09 09:44:12',
    },
    report_count: 4,
    graph_count: 3,
    audit_count: 1,
    detail_route: 'engagements/engagement-1001-acme-holdings/',
    detail_data: 'data/engagements/engagement-1001-acme-holdings.json',
    path: '.forge_data/engagements/1001.db',
    size_label: '1.2 MB',
    scope: ['acme.example', 'app.acme.example', 'mail.acme.example'],
    artifacts: [
      {
        name: 'engagement_1001_report_20260709T014412.md',
        kind: 'report',
        href: '#',
        size_label: '6.3 KB',
        modified_at: '2026-07-09 09:44:12',
      },
      {
        name: 'engagement_1001_report_20260709T014412.pdf',
        kind: 'report',
        href: '#',
        size_label: '8.1 KB',
        modified_at: '2026-07-09 09:44:12',
      },
      {
        name: 'engagement_1001_report_20260709T014412.json',
        kind: 'report',
        href: '#',
        size_label: '5.5 KB',
        modified_at: '2026-07-09 09:44:12',
      },
      {
        name: 'engagement_1001_report_20260709T014412.csv',
        kind: 'report',
        href: '#',
        size_label: '1.4 KB',
        modified_at: '2026-07-09 09:44:12',
      },
      {
        name: '1001_attack_graph.graphml',
        kind: 'graph',
        href: '#',
        size_label: '18.9 KB',
        modified_at: '2026-07-09 09:40:01',
      },
      {
        name: 'audit_1001_manifest_20260709T014413.json',
        kind: 'audit',
        href: '#',
        size_label: '2.2 KB',
        modified_at: '2026-07-09 09:44:13',
      },
    ],
    report_previews: [
      {
        name: 'engagement_1001_report_20260709T014412.md',
        href: '#',
        preview:
          '# Executive Summary\nAcme Holdings exposes a concentrated attack surface across mail, app, and storage assets. Deterministic scoring elevated two validated cloud misconfigurations and one credential exposure into executive attention items.',
      },
    ],
    report_summary: {
      artifact_name: 'engagement_1001_report_20260709T014412.json',
      provider: 'template',
      requested_provider: 'auto',
      render_backend: 'template',
      format: 'markdown',
      generated_at: '2026-07-09 09:44:12',
      fallback_reason: 'quota exceeded',
      findings_checksum: 'sha256:6fd4f11248c3f2d0b62bf951a8a9753cc7c8b5d07b3f4c489db82f6f9df54bf0',
      raw_export: false,
      export_count: 4,
      available_exports: [
        { artifact_name: 'engagement_1001_report_20260709T014412.md', format: 'markdown', label: 'Markdown' },
        { artifact_name: 'engagement_1001_report_20260709T014412.pdf', format: 'pdf', label: 'PDF' },
        { artifact_name: 'engagement_1001_report_20260709T014412.json', format: 'report_json', label: 'Report JSON' },
        { artifact_name: 'engagement_1001_report_20260709T014412.csv', format: 'csv', label: 'CSV' },
      ],
    },
    graph_payload: {
      critical_path_nodes: ['HOST::app', 'VULN::firebase', 'CLOUD::bucket'],
      critical_path_weight: 18.6,
      nodes: [
        { node_id: 'EXTERNAL::internet', node_type: 'EXTERNAL', label: 'Internet', source_table: 'engagements', source_id: 1001, metadata: { role: 'entrypoint' } },
        { node_id: 'HOST::app', node_type: 'HOST', label: 'app.acme.example', severity: 'MEDIUM', source_table: 'hosts', source_id: 1, on_critical_path: true, metadata: { os_family: 'linux', service: 'web' } },
        { node_id: 'EMAIL::security', node_type: 'CREDENTIAL', label: 'security@acme.example', severity: 'LOW', source_table: 'emails', source_id: 1, metadata: { confidence: 'high' } },
        { node_id: 'VULN::firebase', node_type: 'VULN', label: 'Validated Firebase data exposure', severity: 'HIGH', source_table: 'vulnerability_findings', source_id: 1, on_critical_path: true, metadata: { resource: 'acme-firebase-prod' } },
        { node_id: 'CLOUD::bucket', node_type: 'CLOUD', label: 'storage bucket', severity: 'HIGH', source_table: 'cloud_assets', source_id: 1, on_critical_path: true, metadata: { provider: 'firebase' } },
        { node_id: 'IMPACT::report', node_type: 'IMPACT', label: 'Executive report impact', severity: 'CRITICAL', source_table: 'reporting', source_id: 1, metadata: { audience: 'executive' } },
      ],
      edges: [
        { source_node_id: 'EXTERNAL::internet', target_node_id: 'HOST::app', edge_type: 'entry', weight: 60, on_critical_path: true },
        { source_node_id: 'HOST::app', target_node_id: 'VULN::firebase', edge_type: 'vuln_found', weight: 82, on_critical_path: true },
        {
          source_node_id: 'VULN::firebase',
          target_node_id: 'CLOUD::bucket',
          edge_type: 'cloud_misconfig',
          weight: 96,
          on_critical_path: true,
          metadata: {
            rule: 'validated_cloud_edge',
            validation_status: 'VALIDATED',
            validation_detail: 'VALIDATED:firebase_database_shallow_read:records=12',
          },
        },
        { source_node_id: 'EMAIL::security', target_node_id: 'HOST::app', edge_type: 'credential_use', weight: 30 },
        { source_node_id: 'CLOUD::bucket', target_node_id: 'IMPACT::report', edge_type: 'impact', weight: 120, on_critical_path: true },
      ],
    },
    graph_snapshot_at: '2026-07-09 09:40:01',
    sections: {
      hosts: [
        { Host: 'app.acme.example', IP: '203.0.113.10', OS: 'linux', Seen: '2026-07-09 09:11:07' },
        { Host: 'cdn.acme.example', IP: '203.0.113.22', OS: 'unknown', Seen: '2026-07-09 09:08:13' },
      ],
      emails: [
        { Email: 'security@acme.example', Domain: 'acme.example', Source: 'crawler', Seen: '2026-07-09 09:05:21' },
        { Email: 'ops@acme.example', Domain: 'acme.example', Source: 'rdap', Seen: '2026-07-09 08:58:54' },
      ],
      audit_log: [
        {
          When: '2026-07-09 09:44:12',
          Phase: 'phase6',
          Module: 'reporting',
          Action: 'report_generate',
          Target: 'engagement 1001',
          Result: 'success template fallback not required',
        },
        {
          When: '2026-07-09 09:40:01',
          Phase: 'phase4',
          Module: 'graph',
          Action: 'graph_build',
          Target: '1001_attack_graph.graphml',
          Result: '18 nodes / 26 edges',
        },
        {
          When: '2026-07-09 09:28:44',
          Phase: 'phase2',
          Module: 'crawler',
          Action: 'crawl_complete',
          Target: 'app.acme.example',
          Result: 'spa rendered',
        },
      ],
    },
  },
  {
    id: '1013',
    slug: 'engagement-1013-bryan-seah',
    name: 'Bryan Seah Identity Mapping',
    status: 'stabilized',
    operator: 'delta-one',
    tags: ['identity', 'executive', 'apac'],
    created_at: '2026-07-09 09:02:07',
    updated_at: '2026-07-09 09:43:28',
    latest_audit: '2026-07-09 09:43:28',
    primary_seed: 'bryanseah234@gmail.com',
    seeds: ['bryanseah234@gmail.com', '@bryanseah234'],
    counts: {
      hosts: 2,
      emails: 4,
      services: 1,
      crawl_results: 6,
      key_scanner_findings: 0,
      passive_vulns: 0,
      audit_log: 18,
    },
    severity_summary: {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 1,
      LOW: 2,
      INFO: 1,
    },
    highest_severity: 'MEDIUM',
    graph_summary: {
      nodes: 8,
      edges: 9,
      critical_nodes: 0,
      entity_types: [
        ['EMAIL', 3],
        ['SOCIAL', 3],
        ['HOST', 2],
      ],
      sample_nodes: ['gmail identity', 'linkedin slug', 'github profile'],
      source: '1013_attack_graph.json',
    },
    report_count: 3,
    graph_count: 1,
    audit_count: 1,
    detail_route: 'engagements/engagement-1013-bryan-seah/',
    detail_data: 'data/engagements/engagement-1013-bryan-seah.json',
    path: '.forge_data/engagements/1013.db',
    size_label: '412 KB',
    scope: ['bryanseah234@gmail.com', '@bryanseah234'],
    artifacts: [
      {
        name: 'engagement_1013_report_20260709T014328.md',
        kind: 'report',
        href: '#',
        size_label: '3.0 KB',
        modified_at: '2026-07-09 09:43:28',
      },
      {
        name: 'engagement_1013_report_20260709T014328.json',
        kind: 'report',
        href: '#',
        size_label: '2.8 KB',
        modified_at: '2026-07-09 09:43:28',
      },
      {
        name: 'engagement_1013_report_20260709T014328.csv',
        kind: 'report',
        href: '#',
        size_label: '1.0 KB',
        modified_at: '2026-07-09 09:43:28',
      },
      {
        name: 'audit_1013_manifest_20260709T014329.json',
        kind: 'audit',
        href: '#',
        size_label: '1.8 KB',
        modified_at: '2026-07-09 09:43:29',
      },
    ],
    report_previews: [
      {
        name: 'engagement_1013_report_20260709T014328.md',
        href: '#',
        preview:
          '# Executive Summary\nIdentity fan-out correlated public profiles across email and username pivots. No validated misconfigurations were observed, but cross-platform attribution confidence increased after username convergence.',
      },
    ],
    report_summary: {
      artifact_name: 'engagement_1013_report_20260709T014328.json',
      provider: 'template',
      requested_provider: 'template',
      render_backend: 'template',
      format: 'markdown',
      generated_at: '2026-07-09 09:43:28',
      findings_checksum: 'sha256:1ea5d82cc4157b90960159c54f6320a99c55435d44a4b0e6d143dddc0a4af661',
      raw_export: false,
      export_count: 3,
      available_exports: [
        { artifact_name: 'engagement_1013_report_20260709T014328.md', format: 'markdown', label: 'Markdown' },
        { artifact_name: 'engagement_1013_report_20260709T014328.json', format: 'report_json', label: 'Report JSON' },
        { artifact_name: 'engagement_1013_report_20260709T014328.csv', format: 'csv', label: 'CSV' },
      ],
    },
    graph_payload: {
      critical_path_nodes: ['EMAIL::gmail', 'SOCIAL::github'],
      critical_path_weight: 7.2,
      nodes: [
        { node_id: 'EMAIL::gmail', node_type: 'CREDENTIAL', label: 'bryanseah234@gmail.com', severity: 'LOW', source_table: 'engagement_seeds', source_id: 1, on_critical_path: true, metadata: { source: 'seed' } },
        { node_id: 'USERNAME::handle', node_type: 'EXTERNAL', label: '@bryanseah234', severity: 'LOW', source_table: 'engagement_seeds', source_id: 2, metadata: { source: 'seed' } },
        { node_id: 'SOCIAL::github', node_type: 'HOST', label: 'github profile', severity: 'MEDIUM', source_table: 'social_profiles', source_id: 1, on_critical_path: true, metadata: { platform: 'github' } },
        { node_id: 'SOCIAL::linkedin', node_type: 'HOST', label: 'linkedin slug', severity: 'LOW', source_table: 'social_profiles', source_id: 2, metadata: { platform: 'linkedin' } },
      ],
      edges: [
        { source_node_id: 'EMAIL::gmail', target_node_id: 'USERNAME::handle', edge_type: 'related_identity', weight: 22 },
        { source_node_id: 'USERNAME::handle', target_node_id: 'SOCIAL::github', edge_type: 'links_to', weight: 44, on_critical_path: true },
        { source_node_id: 'USERNAME::handle', target_node_id: 'SOCIAL::linkedin', edge_type: 'links_to', weight: 34 },
      ],
    },
    graph_snapshot_at: '2026-07-09 09:21:44',
    sections: {
      hosts: [],
      emails: [
        { Email: 'bryanseah234@gmail.com', Domain: 'gmail.com', Source: 'seed', Seen: '2026-07-09 09:02:07' },
      ],
      audit_log: [
        {
          When: '2026-07-09 09:43:28',
          Phase: 'phase6',
          Module: 'reporting',
          Action: 'report_generate',
          Target: 'engagement 1013',
          Result: 'success',
        },
        {
          When: '2026-07-09 09:21:44',
          Phase: 'phase2',
          Module: 'sherlock',
          Action: 'username_correlate',
          Target: '@bryanseah234',
          Result: '3 high-confidence matches',
        },
      ],
    },
  },
]

const SAMPLE_INDEX: EngagementIndex = {
  generated_at: '2026-07-09 09:44:12',
  items: SAMPLE_DETAIL.map((item) => ({
    id: item.id,
    slug: item.slug,
    name: item.name,
    status: item.status,
    operator: item.operator,
    tags: item.tags,
    created_at: item.created_at,
    updated_at: item.updated_at,
    latest_audit: item.latest_audit,
    primary_seed: item.primary_seed,
    seeds: item.seeds,
    counts: item.counts,
    severity_summary: item.severity_summary,
    highest_severity: item.highest_severity,
    graph_summary: item.graph_summary,
    report_count: item.report_count,
    graph_count: item.graph_count,
    audit_count: item.audit_count,
    detail_route: item.detail_route,
    detail_data: item.detail_data,
  })),
}

const SAMPLE_BY_SLUG = new Map(SAMPLE_DETAIL.map((item) => [item.slug, item]))

const SECTION_TITLES: Record<string, string> = {
  engagement_seeds: 'Seed matrix',
  seed_relations: 'Seed relations',
  seed_runs: 'Seed runs',
  engagement_runs: 'Engagement runs',
  email_intelligence: 'Email intelligence',
  services: 'Services',
  key_scanner_findings: 'Key findings',
  cloud_validation_results: 'Cloud validation',
  passive_vulns: 'Passive findings',
  vulnerability_findings: 'Validated findings',
  crawl_results: 'Web mining',
  social_profiles: 'Identity mapping',
  artifact_queue: 'Artifact queue',
  auth_test_results: 'Auth validation',
}

const BASE_PATH = import.meta.env.BASE_URL
const LIVE_TOKEN_KEY = 'forge.liveToken'
const LIVE_OPERATOR_KEY = 'forge.liveOperator'
const OVERVIEW_FILTERS_KEY = 'forge.overviewFilters'

function resolveAssetPath(path: string): string {
  return `${BASE_PATH}${path.replace(/^\/+/, '')}`
}

function canUseLiveApi(): boolean {
  return typeof window !== 'undefined' && /^https?:$/.test(window.location.protocol)
}

function resolveDownloadHref(path: string): string {
  if (!path || path === '#') {
    return '#'
  }
  if (/^(?:https?:)?\/\//.test(path) || path.startsWith('/api/')) {
    return path
  }
  return resolveAssetPath(path)
}

function apiHeaders(token: string | null | undefined): HeadersInit {
  if (!token) {
    return {}
  }
  return { Authorization: `Bearer ${token}` }
}

async function fetchJson<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, init)
  if (!response.ok) {
    throw new Error(`${path} failed: ${response.status}`)
  }
  return (await response.json()) as T
}

async function loadIndex(token?: string | null): Promise<EngagementIndex> {
  if (canUseLiveApi() && token) {
    return await fetchJson<EngagementIndex>('/api/engagements', {
      headers: apiHeaders(token),
    })
  }
  const response = await fetch(resolveAssetPath('data/engagements.json'))
  if (!response.ok) {
    throw new Error(`index fetch failed: ${response.status}`)
  }
  return (await response.json()) as EngagementIndex
}

async function loadDetail(
  slug: string,
  summaries: EngagementSummary[],
  token?: string | null,
): Promise<EngagementDetail> {
  const summary = summaries.find((item) => item.slug === slug)
  if (canUseLiveApi() && token) {
    const livePath = summary?.detail_api ?? `/api/engagements/${slug}`
    return await fetchJson<EngagementDetail>(livePath, {
      headers: apiHeaders(token),
    })
  }
  const path = summary?.detail_data ?? `data/engagements/${slug}.json`
  const response = await fetch(resolveAssetPath(path))
  if (!response.ok) {
    throw new Error(`detail fetch failed: ${response.status}`)
  }
  return (await response.json()) as EngagementDetail
}

async function loadLiveSeeds(slug: string, token: string): Promise<SeedRecord[]> {
  const payload = await fetchJson<{ items: SeedRecord[] }>(`/api/engagements/${slug}/seeds`, {
    headers: apiHeaders(token),
  })
  return payload.items
}

async function loadEngagementLogs(slug: string, token: string): Promise<RunLog[]> {
  const payload = await fetchJson<{ items: RunLog[] }>(`/api/engagements/${slug}/logs`, {
    headers: apiHeaders(token),
  })
  return payload.items
}

async function loadRunLogTail(log: RunLog, token: string, lines = 120): Promise<RunLogTail> {
  const separator = log.tail_api.includes('?') ? '&' : '?'
  return await fetchJson<RunLogTail>(`${log.tail_api}${separator}lines=${lines}`, {
    headers: apiHeaders(token),
  })
}

function progressMessageLabel(event: ProgressFeedEvent): string {
  const payload = event.payload ?? {}
  switch (event.message) {
    case 'engagement_run_started':
      return `Kill-chain launched${payload.pid ? ` · PID ${String(payload.pid)}` : ''}`
    case 'engagement_run_resumed':
      return `Kill-chain resumed${payload.pid ? ` · PID ${String(payload.pid)}` : ''}`
    case 'engagement_run_restarted':
      return `Kill-chain restarted${payload.pid ? ` · PID ${String(payload.pid)}` : ''}`
    case 'engagement_run_progress':
      return payload.last_step
        ? `${String(payload.last_step)}${payload.last_message ? ` · ${String(payload.last_message)}` : ''}`
        : 'Kill-chain progress updated'
    case 'engagement_run_pause_requested':
      return `Pause requested${payload.active_run_id ? ` · run ${String(payload.active_run_id)}` : ''}`
    case 'engagement_run_stop_requested':
      return `Stop requested${payload.active_run_id ? ` · run ${String(payload.active_run_id)}` : ''}`
    default:
      return event.message.replaceAll('_', ' ')
  }
}

function formatCount(value: number | undefined): string {
  return new Intl.NumberFormat().format(value ?? 0)
}

function statusTone(status: string): string {
  const normalized = status.trim().toLowerCase()
  if (normalized.includes('active')) {
    return 'is-live'
  }
  if (normalized.includes('stabilized') || normalized.includes('complete')) {
    return 'is-stable'
  }
  return 'is-muted'
}

function auditManifestLabel(manifest?: AuditManifest): string {
  if (!manifest) {
    return 'untracked'
  }
  if (manifest.verified) {
    return 'verified'
  }
  return manifest.verification_status || 'unknown'
}

function auditManifestHash(manifest?: AuditManifest): string {
  return manifest?.short_hash || (manifest?.manifest_hash ? manifest.manifest_hash.slice(0, 12) : '')
}

function severityTone(severity: string): string {
  const normalized = severity.trim().toUpperCase()
  if (normalized === 'CRITICAL') {
    return 'is-critical'
  }
  if (normalized === 'HIGH') {
    return 'is-high'
  }
  if (normalized === 'MEDIUM') {
    return 'is-medium'
  }
  if (normalized === 'LOW') {
    return 'is-low'
  }
  return 'is-info'
}

function severityRank(severity: string): number {
  switch (severity.trim().toUpperCase()) {
    case 'CRITICAL':
      return 5
    case 'HIGH':
      return 4
    case 'MEDIUM':
      return 3
    case 'LOW':
      return 2
    case 'INFO':
      return 1
    default:
      return 0
  }
}

function timestampValue(value: string): number {
  const normalized = value.includes('T') ? value : value.replace(' ', 'T')
  const parsed = Date.parse(normalized)
  return Number.isNaN(parsed) ? 0 : parsed
}

function matchesRecencyWindow(value: string, filter: string): boolean {
  if (filter === 'ALL') {
    return true
  }
  const updatedAt = timestampValue(value)
  const thirtyDaysMs = 30 * 24 * 60 * 60 * 1000
  if (filter === 'STALE_30D') {
    return !updatedAt || Date.now() - updatedAt > thirtyDaysMs
  }
  if (!updatedAt) {
    return false
  }
  const elapsedMs = Date.now() - updatedAt
  if (filter === '24H') {
    return elapsedMs <= 24 * 60 * 60 * 1000
  }
  if (filter === '7D') {
    return elapsedMs <= 7 * 24 * 60 * 60 * 1000
  }
  if (filter === '30D') {
    return elapsedMs <= thirtyDaysMs
  }
  return true
}

function matchesTagFilter(tags: string[], filter: string): boolean {
  if (filter === 'ALL') {
    return true
  }
  const normalizedFilter = filter.trim().toLowerCase()
  return tags.some((tag) => tag.trim().toLowerCase() === normalizedFilter)
}

function matchesDateRange(value: string, fromDate: string, toDate: string): boolean {
  if (!fromDate && !toDate) {
    return true
  }
  const updatedAt = timestampValue(value)
  if (!updatedAt) {
    return false
  }
  if (fromDate) {
    const fromMs = Date.parse(`${fromDate}T00:00:00`)
    if (Number.isNaN(fromMs) || updatedAt < fromMs) {
      return false
    }
  }
  if (toDate) {
    const toMs = Date.parse(`${toDate}T23:59:59.999`)
    if (Number.isNaN(toMs) || updatedAt > toMs) {
      return false
    }
  }
  return true
}

function engagementActivityTimestamp(item: EngagementSummary): string {
  return item.latest_audit || item.updated_at || ''
}

function splitListInput(value: string): string[] {
  return value
    .split(/\r?\n|,/)
    .map((item) => item.trim())
    .filter(Boolean)
}

type OverviewFilterState = {
  search?: string
  statusFilter?: string
  severityFilter?: string
  tagFilter?: string
  updatedAfter?: string
  updatedBefore?: string
  recencyFilter?: string
  sortBy?: string
}

function readOverviewFilters(): OverviewFilterState {
  if (typeof window === 'undefined') {
    return {}
  }
  try {
    const raw = window.localStorage.getItem(OVERVIEW_FILTERS_KEY)
    if (!raw) {
      return {}
    }
    const parsed = JSON.parse(raw) as OverviewFilterState
    return parsed && typeof parsed === 'object' ? parsed : {}
  } catch {
    return {}
  }
}

function writeOverviewFilters(state: OverviewFilterState): void {
  if (typeof window === 'undefined') {
    return
  }
  const isDefaultState =
    !state.search &&
    (state.statusFilter ?? 'ALL') === 'ALL' &&
    (state.severityFilter ?? 'ALL') === 'ALL' &&
    (state.tagFilter ?? 'ALL') === 'ALL' &&
    !state.updatedAfter &&
    !state.updatedBefore &&
    (state.recencyFilter ?? 'ALL') === 'ALL' &&
    (state.sortBy ?? 'recent') === 'recent'
  if (isDefaultState) {
    window.localStorage.removeItem(OVERVIEW_FILTERS_KEY)
    return
  }
  window.localStorage.setItem(OVERVIEW_FILTERS_KEY, JSON.stringify(state))
}

function severitySummaryText(summary: SeveritySummary): string {
  return ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
    .filter((severity) => (summary[severity] ?? 0) > 0)
    .map((severity) => `${severity[0]}:${summary[severity]}`)
    .join(' · ')
}

function engagementFindingCount(item: EngagementSummary): number {
  return (item.counts.vulnerability_findings ?? 0) + (item.counts.passive_vulns ?? 0)
}

function engagementDataPointCount(item: EngagementSummary): number {
  return (
    (item.counts.hosts ?? 0) +
    (item.counts.emails ?? 0) +
    (item.counts.services ?? 0) +
    (item.counts.social_profiles ?? 0) +
    (item.counts.crawl_results ?? 0) +
    (item.counts.subdomains ?? 0)
  )
}

function graphNodeLabels(detail: EngagementDetail): string[] {
  const labels =
    detail.graph_payload?.nodes
      ?.map((node) => node.label?.trim())
      .filter((label): label is string => Boolean(label)) ?? []
  if (labels.length) {
    return labels.slice(0, 8)
  }
  return detail.graph_summary?.sample_nodes ?? ['Awaiting graph nodes']
}

function rawDataPreview(detail: EngagementDetail): string {
  return JSON.stringify(
    {
      id: detail.id,
      slug: detail.slug,
      counts: detail.counts,
      sections: detail.sections,
      graph_payload: detail.graph_payload,
      graph_snapshot_at: detail.graph_snapshot_at,
    },
    null,
    2,
  )
}

type GraphExplorerNode = {
  id: string
  label: string
  type: string
  severity: string
  critical: boolean
  metadata: Record<string, unknown>
  sourceTable: string
  sourceId: string
  degree: number
}

type GraphExplorerEdge = {
  id: string
  source: string
  target: string
  label: string
  type: string
  weight: number
  critical: boolean
  metadata: Record<string, unknown>
}

type GraphLayout = {
  width: number
  height: number
  positions: Map<string, { x: number; y: number }>
  columns: string[]
}

function nodeTypeLabel(node: GraphNode): string {
  return String(node.node_type ?? node.entity_type ?? 'UNKNOWN').toUpperCase()
}

function normalizeGraph(detail: EngagementDetail): {
  nodes: GraphExplorerNode[]
  edges: GraphExplorerEdge[]
  nodeTypes: string[]
} {
  const payload = detail.graph_payload
  const criticalPath = new Set(payload?.critical_path_nodes ?? [])
  const rawNodes = payload?.nodes ?? []
  const nodes = rawNodes.map((node, index) => ({
    id: String(node.node_id ?? node.label ?? `node-${index}`),
    label: String(node.label ?? node.node_id ?? `Node ${index + 1}`),
    type: nodeTypeLabel(node),
    severity: String(node.severity ?? 'INFO').toUpperCase(),
    critical: Boolean(node.on_critical_path) || criticalPath.has(String(node.node_id ?? node.label ?? `node-${index}`)),
    metadata: node.metadata ?? {},
    sourceTable: String(node.source_table ?? 'unknown'),
    sourceId: String(node.source_id ?? '-'),
    degree: 0,
  }))
  const nodeMap = new Map(nodes.map((node) => [node.id, node]))
  const edges = (payload?.edges ?? [])
    .map((edge, index) => ({
      id: `edge-${index}`,
      source: String(edge.source_node_id ?? edge.source ?? ''),
      target: String(edge.target_node_id ?? edge.target ?? ''),
      label: String(edge.label ?? ''),
      type: String(edge.edge_type ?? 'relationship'),
      weight: Number(edge.weight ?? 0),
      critical: Boolean(edge.on_critical_path),
      metadata: edge.metadata ?? {},
    }))
    .filter((edge) => nodeMap.has(edge.source) && nodeMap.has(edge.target))

  const degreeByNode = new Map<string, number>()
  edges.forEach((edge) => {
    degreeByNode.set(edge.source, (degreeByNode.get(edge.source) ?? 0) + 1)
    degreeByNode.set(edge.target, (degreeByNode.get(edge.target) ?? 0) + 1)
  })
  const finalizedNodes = nodes.map((node) => ({
    ...node,
    degree: degreeByNode.get(node.id) ?? 0,
  }))

  const nodeTypes = Array.from(new Set(finalizedNodes.map((node) => node.type)))
  return { nodes: finalizedNodes, edges, nodeTypes }
}

function layoutGraph(nodes: GraphExplorerNode[]): GraphLayout {
  const preferredOrder = ['EXTERNAL', 'HOST', 'CLOUD', 'CREDENTIAL', 'APIKEY', 'VULN', 'EXPLOIT', 'IMPACT', 'UNKNOWN']
  const groups = new Map<string, GraphExplorerNode[]>()
  nodes.forEach((node) => {
    const bucket = groups.get(node.type) ?? []
    bucket.push(node)
    groups.set(node.type, bucket)
  })
  const columns = [
    ...preferredOrder.filter((type) => groups.has(type)),
    ...Array.from(groups.keys()).filter((type) => !preferredOrder.includes(type)).sort(),
  ]
  const maxRows = Math.max(1, ...Array.from(groups.values()).map((bucket) => bucket.length))
  const width = Math.max(760, columns.length * 190 + 120)
  const height = Math.max(340, maxRows * 118 + 120)
  const positions = new Map<string, { x: number; y: number }>()
  columns.forEach((type, columnIndex) => {
    const bucket = groups.get(type) ?? []
    bucket.forEach((node, rowIndex) => {
      positions.set(node.id, {
        x: 110 + columnIndex * 190,
        y: 88 + rowIndex * 110,
      })
    })
  })
  return { width, height, positions, columns }
}

function metadataEntries(metadata: Record<string, unknown>): Array<[string, string]> {
  return Object.entries(metadata).map(([key, value]) => [key, stringifyUnknown(value)])
}

function summarizeRunCounts(value: unknown): string {
  if (!value || typeof value !== 'object') {
    return ''
  }
  const counts = value as Record<string, unknown>
  const labels: Array<[string, string]> = [
    ['hosts', 'hosts'],
    ['emails', 'emails'],
    ['social_profiles', 'social'],
    ['engagement_seeds', 'seeds'],
    ['seed_relations', 'relations'],
    ['vulnerability_findings', 'findings'],
    ['cloud_assets', 'cloud'],
    ['artifact_queue', 'artifacts'],
  ]
  return labels
    .map(([key, label]) => {
      const numeric = Number(counts[key] ?? 0)
      return Number.isFinite(numeric) && numeric > 0 ? `${label} ${formatCount(numeric)}` : ''
    })
    .filter(Boolean)
    .join(' · ')
}

function summarizeRunDelta(value: unknown): string {
  if (!value || typeof value !== 'object') {
    return ''
  }
  const delta = value as Record<string, unknown>
  const labels: Array<[string, string]> = [
    ['hosts', 'hosts'],
    ['emails', 'emails'],
    ['social_profiles', 'social'],
    ['engagement_seeds', 'seeds'],
    ['seed_relations', 'relations'],
    ['crawl_results', 'crawl'],
    ['key_findings', 'keys'],
    ['github_findings', 'gh'],
  ]
  return labels
    .map(([key, label]) => {
      const numeric = Number(delta[key] ?? 0)
      return Number.isFinite(numeric) && numeric !== 0 ? `${label} ${numeric > 0 ? '+' : ''}${numeric}` : ''
    })
    .filter(Boolean)
    .join(' · ')
}

function summarizeRunQueueGroup(
  value: unknown,
  groupKey: string,
  labels: Array<[string, string]>,
): string {
  if (!value || typeof value !== 'object') {
    return ''
  }
  const groups = value as Record<string, unknown>
  const group = groups[groupKey]
  if (!group || typeof group !== 'object') {
    return ''
  }
  const counts = group as Record<string, unknown>
  return labels
    .map(([key, label]) => {
      const numeric = Number(counts[key] ?? 0)
      return Number.isFinite(numeric) && numeric > 0 ? `${label} ${formatCount(numeric)}` : ''
    })
    .filter(Boolean)
    .join(' · ')
}

function stringifyUnknown(value: unknown): string {
  if (typeof value === 'string') {
    return value
  }
  if (typeof value === 'number' || typeof value === 'boolean') {
    return String(value)
  }
  if (value == null) {
    return ''
  }
  return JSON.stringify(value)
}

function App() {
  const [liveToken, setLiveToken] = useState<string>(() =>
    typeof window === 'undefined' ? '' : window.localStorage.getItem(LIVE_TOKEN_KEY) ?? '',
  )
  const [operator, setOperator] = useState<string>(() =>
    typeof window === 'undefined' ? '' : window.localStorage.getItem(LIVE_OPERATOR_KEY) ?? '',
  )
  const [bootstrapToken, setBootstrapToken] = useState('')
  const [authBusy, setAuthBusy] = useState(false)
  const [authError, setAuthError] = useState('')
  const [index, setIndex] = useState<EngagementIndex>(SAMPLE_INDEX)
  const [loadingIndex, setLoadingIndex] = useState(true)
  const [loadError, setLoadError] = useState<string>('')

  useEffect(() => {
    if (typeof window === 'undefined') {
      return
    }
    if (liveToken) {
      window.localStorage.setItem(LIVE_TOKEN_KEY, liveToken)
    } else {
      window.localStorage.removeItem(LIVE_TOKEN_KEY)
    }
  }, [liveToken])

  useEffect(() => {
    if (typeof window === 'undefined') {
      return
    }
    if (operator) {
      window.localStorage.setItem(LIVE_OPERATOR_KEY, operator)
    } else {
      window.localStorage.removeItem(LIVE_OPERATOR_KEY)
    }
  }, [operator])

  useEffect(() => {
    let cancelled = false

    async function hydrate() {
      try {
        const payload = await loadIndex(liveToken || null)
        if (!cancelled) {
          setIndex(payload)
          setLoadError('')
        }
      } catch (error) {
        if (!cancelled) {
          setLoadError(error instanceof Error ? error.message : 'unable to load engagement index')
        }
      } finally {
        if (!cancelled) {
          setLoadingIndex(false)
        }
      }
    }

    void hydrate()
    return () => {
      cancelled = true
    }
  }, [liveToken])

  async function handleMintLiveToken(): Promise<void> {
    if (!canUseLiveApi()) {
      setAuthError('Live API bootstrap requires the dashboard to be served over HTTP(S).')
      return
    }
    if (!operator.trim() || !bootstrapToken.trim()) {
      setAuthError('Operator and bootstrap token are required.')
      return
    }
    setAuthBusy(true)
    setAuthError('')
    try {
      const response = await fetch(
        `/api/token?operator=${encodeURIComponent(operator.trim())}&bootstrap_token=${encodeURIComponent(bootstrapToken)}`,
      )
      if (!response.ok) {
        throw new Error(`token request failed: ${response.status}`)
      }
      const payload = (await response.json()) as { token: string }
      setLiveToken(payload.token)
      setBootstrapToken('')
    } catch (error) {
      setAuthError(error instanceof Error ? error.message : 'unable to mint token')
    } finally {
      setAuthBusy(false)
    }
  }

  function handleSignOut(): void {
    setLiveToken('')
    setAuthError('')
  }

  return (
    <div className="app-shell">
      <header className="masthead">
        <div>
          <p className="eyebrow">Authorized Security Assessment and Threat Intelligence Platform</p>
          <h1>FORGE Engagement Console</h1>
          <p className="lede">
            Cleaner routing at the engagement layer: overview first, then dedicated detail routes
            for report, graph, audit, and evidence context.
          </p>
        </div>
        <div className="masthead-meta">
          <div className="meta-chip">Generated {index.generated_at}</div>
          <div className="meta-chip">Active engagements {index.items.length}</div>
          <div className="meta-chip">{liveToken ? 'Live API unlocked' : canUseLiveApi() ? 'Static mode' : 'Offline static mode'}</div>
          <div className="live-auth-card">
            <label className="auth-shell">
              <span>Operator</span>
              <input value={operator} onChange={(event) => setOperator(event.target.value)} placeholder="delta-one" />
            </label>
            <label className="auth-shell">
              <span>Bootstrap</span>
              <input
                value={bootstrapToken}
                onChange={(event) => setBootstrapToken(event.target.value)}
                placeholder="FORGE_WEB_BOOTSTRAP_TOKEN"
                type="password"
              />
            </label>
            <div className="auth-actions">
              <button className="token-action" disabled={authBusy} onClick={() => void handleMintLiveToken()} type="button">
                {authBusy ? 'Unlocking…' : liveToken ? 'Refresh token' : 'Unlock live'}
              </button>
              {liveToken ? (
                <button className="token-action is-secondary" onClick={handleSignOut} type="button">
                  Sign out
                </button>
              ) : null}
            </div>
            {authError ? <span className="auth-error">{authError}</span> : null}
          </div>
        </div>
      </header>

      <Routes>
        <Route
          path="/"
          element={
            <OverviewPage
              index={index}
              loading={loadingIndex}
              loadError={loadError}
              liveToken={liveToken || null}
              onIndexRefresh={async () => setIndex(await loadIndex(liveToken || null))}
            />
          }
        />
        <Route
          path="/engagements/:slug"
          element={
            <EngagementRoute
              summaries={index.items}
              liveToken={liveToken || null}
              onIndexRefresh={async () => setIndex(await loadIndex(liveToken || null))}
            />
          }
        />
      </Routes>
    </div>
  )
}

function OverviewPage({
  index,
  loading,
  loadError,
  liveToken,
  onIndexRefresh,
}: {
  index: EngagementIndex
  loading: boolean
  loadError: string
  liveToken: string | null
  onIndexRefresh: () => Promise<void>
}) {
  const navigate = useNavigate()
  const [search, setSearch] = useState(() => readOverviewFilters().search ?? '')
  const [statusFilter, setStatusFilter] = useState(() => readOverviewFilters().statusFilter ?? 'ALL')
  const [severityFilter, setSeverityFilter] = useState(() => readOverviewFilters().severityFilter ?? 'ALL')
  const [tagFilter, setTagFilter] = useState(() => readOverviewFilters().tagFilter ?? 'ALL')
  const [updatedAfter, setUpdatedAfter] = useState(() => readOverviewFilters().updatedAfter ?? '')
  const [updatedBefore, setUpdatedBefore] = useState(() => readOverviewFilters().updatedBefore ?? '')
  const [recencyFilter, setRecencyFilter] = useState(() => readOverviewFilters().recencyFilter ?? 'ALL')
  const [sortBy, setSortBy] = useState(() => readOverviewFilters().sortBy ?? 'recent')
  const [engagementName, setEngagementName] = useState('')
  const [engagementStatus, setEngagementStatus] = useState('ACTIVE')
  const [engagementSeeds, setEngagementSeeds] = useState('')
  const [engagementTags, setEngagementTags] = useState('')
  const [engagementBusy, setEngagementBusy] = useState(false)
  const [engagementError, setEngagementError] = useState('')
  const deferredSearch = useDeferredValue(search)
  const query = deferredSearch.trim().toLowerCase()
  const statusOptions = Array.from(
    new Set(index.items.map((item) => (item.status || 'unknown').trim() || 'unknown')),
  ).sort((left, right) => left.localeCompare(right))
  const tagOptions = Array.from(new Set(index.items.flatMap((item) => item.tags ?? []))).sort((left, right) =>
    left.localeCompare(right),
  )
  const items = [...index.items]
    .filter((item) => {
      if (statusFilter !== 'ALL' && (item.status || 'unknown') !== statusFilter) {
        return false
      }
      if (severityFilter === 'CRITICAL' && (item.severity_summary.CRITICAL ?? 0) === 0) {
        return false
      }
      if (
        severityFilter === 'HIGH_PLUS' &&
        (item.severity_summary.CRITICAL ?? 0) + (item.severity_summary.HIGH ?? 0) === 0
      ) {
        return false
      }
      if (
        severityFilter === 'MEDIUM_PLUS' &&
        (item.severity_summary.CRITICAL ?? 0) +
          (item.severity_summary.HIGH ?? 0) +
          (item.severity_summary.MEDIUM ?? 0) ===
          0
      ) {
        return false
      }
      if (severityFilter === 'FINDINGS' && engagementFindingCount(item) === 0) {
        return false
      }
      if (!matchesTagFilter(item.tags ?? [], tagFilter)) {
        return false
      }
      if (!matchesDateRange(engagementActivityTimestamp(item), updatedAfter, updatedBefore)) {
        return false
      }
      if (!matchesRecencyWindow(engagementActivityTimestamp(item), recencyFilter)) {
        return false
      }
      if (!query) {
        return true
      }
      return [
        item.id,
        item.slug,
        item.name,
        item.status,
        item.operator,
        item.primary_seed,
        ...(item.tags ?? []),
        ...item.seeds,
      ]
        .join(' ')
        .toLowerCase()
        .includes(query)
    })
    .sort((left, right) => {
      if (sortBy === 'severity') {
        return severityRank(right.highest_severity) - severityRank(left.highest_severity)
      }
      if (sortBy === 'findings') {
        return engagementFindingCount(right) - engagementFindingCount(left)
      }
      if (sortBy === 'seeds') {
        return right.seeds.length - left.seeds.length
      }
      return timestampValue(engagementActivityTimestamp(right)) - timestampValue(engagementActivityTimestamp(left))
    })

  const globalTotals = index.items.reduce(
    (accumulator, item) => {
      accumulator.engagements += 1
      accumulator.critical += item.severity_summary.CRITICAL ?? 0
      accumulator.high += item.severity_summary.HIGH ?? 0
      accumulator.seeds += item.counts.engagement_seeds ?? item.seeds.length
      accumulator.dataPoints += engagementDataPointCount(item)
      return accumulator
    },
    { engagements: 0, critical: 0, high: 0, seeds: 0, dataPoints: 0 },
  )
  const visibleTotals = items.reduce(
    (accumulator, item) => {
      accumulator.engagements += 1
      accumulator.critical += item.severity_summary.CRITICAL ?? 0
      accumulator.high += item.severity_summary.HIGH ?? 0
      accumulator.seeds += item.counts.engagement_seeds ?? item.seeds.length
      accumulator.dataPoints += engagementDataPointCount(item)
      return accumulator
    },
    { engagements: 0, critical: 0, high: 0, seeds: 0, dataPoints: 0 },
  )

  useEffect(() => {
    writeOverviewFilters({
      search,
      statusFilter,
      severityFilter,
      tagFilter,
      updatedAfter,
      updatedBefore,
      recencyFilter,
      sortBy,
    })
  }, [search, statusFilter, severityFilter, tagFilter, updatedAfter, updatedBefore, recencyFilter, sortBy])

  async function handleCreateEngagement(): Promise<void> {
    if (!liveToken) {
      setEngagementError('Unlock live API access before creating engagements.')
      return
    }
    const seeds = engagementSeeds
      .split(/\r?\n|,/)
      .map((item) => item.trim())
      .filter(Boolean)
    const tags = splitListInput(engagementTags)
    if (!engagementName.trim() || seeds.length === 0) {
      setEngagementError('Name and at least one seed are required.')
      return
    }
    setEngagementBusy(true)
    setEngagementError('')
    try {
      const created = await fetchJson<EngagementDetail>('/api/engagements', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...apiHeaders(liveToken),
        },
        body: JSON.stringify({
          name: engagementName.trim(),
          status: engagementStatus,
          seeds,
          tags,
        }),
      })
      setEngagementName('')
      setEngagementStatus('ACTIVE')
      setEngagementSeeds('')
      setEngagementTags('')
      await onIndexRefresh()
      navigate(`/engagements/${created.slug}`)
    } catch (error) {
      setEngagementError(error instanceof Error ? error.message : 'unable to create engagement')
    } finally {
      setEngagementBusy(false)
    }
  }

  return (
    <main className="page-grid">
      <section className="summary-band">
        <article className="summary-card">
          <span className="summary-label">Visible engagements</span>
          <strong>{formatCount(visibleTotals.engagements)}</strong>
          <span className="card-copy">of {formatCount(globalTotals.engagements)} total</span>
        </article>
        <article className="summary-card">
          <span className="summary-label">Critical</span>
          <strong>{formatCount(visibleTotals.critical)}</strong>
        </article>
        <article className="summary-card">
          <span className="summary-label">High</span>
          <strong>{formatCount(visibleTotals.high)}</strong>
        </article>
        <article className="summary-card">
          <span className="summary-label">Tracked seeds</span>
          <strong>{formatCount(visibleTotals.seeds)}</strong>
        </article>
        <article className="summary-card">
          <span className="summary-label">Data points</span>
          <strong>{formatCount(visibleTotals.dataPoints)}</strong>
        </article>
      </section>

      <section className="workspace">
        <div className="workspace-head">
          <div>
            <p className="section-kicker">Main Dashboard</p>
            <h2>All active engagements</h2>
            <p className="card-copy">
              Filter the engagement index by operational status, severity concentration, and
              recency before routing into the per-slug detail workspace.
            </p>
          </div>
          <div className="overview-controls">
            <label className="search-shell">
              <span>Search</span>
              <input
                value={search}
                onChange={(event) => setSearch(event.target.value)}
                placeholder="Slug, seed, operator, or status"
                type="search"
              />
            </label>
            <label className="filter-shell">
              <span>Status</span>
              <select value={statusFilter} onChange={(event) => setStatusFilter(event.target.value)}>
                <option value="ALL">All statuses</option>
                {statusOptions.map((status) => (
                  <option key={status} value={status}>
                    {status}
                  </option>
                ))}
              </select>
            </label>
            <label className="filter-shell">
              <span>Severity</span>
              <select value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value)}>
                <option value="ALL">All severities</option>
                <option value="CRITICAL">Has critical</option>
                <option value="HIGH_PLUS">Has high or critical</option>
                <option value="MEDIUM_PLUS">Has medium or above</option>
                <option value="FINDINGS">Any finding rows</option>
              </select>
            </label>
            <label className="filter-shell">
              <span>Tag</span>
              <select value={tagFilter} onChange={(event) => setTagFilter(event.target.value)}>
                <option value="ALL">All tags</option>
                {tagOptions.map((tag) => (
                  <option key={tag} value={tag}>
                    {tag}
                  </option>
                ))}
              </select>
            </label>
            <label className="filter-shell">
              <span>Updated from</span>
              <input type="date" value={updatedAfter} onChange={(event) => setUpdatedAfter(event.target.value)} />
            </label>
            <label className="filter-shell">
              <span>Updated to</span>
              <input type="date" value={updatedBefore} onChange={(event) => setUpdatedBefore(event.target.value)} />
            </label>
            <label className="filter-shell">
              <span>Recency</span>
              <select value={recencyFilter} onChange={(event) => setRecencyFilter(event.target.value)}>
                <option value="ALL">Any recency</option>
                <option value="24H">Updated in 24h</option>
                <option value="7D">Updated in 7d</option>
                <option value="30D">Updated in 30d</option>
                <option value="STALE_30D">Stale over 30d</option>
              </select>
            </label>
            <label className="filter-shell">
              <span>Sort</span>
              <select value={sortBy} onChange={(event) => setSortBy(event.target.value)}>
                <option value="recent">Recently updated</option>
                <option value="severity">Highest severity</option>
                <option value="findings">Finding volume</option>
                <option value="seeds">Seed count</option>
              </select>
            </label>
          </div>
        </div>

        <section className="live-compose">
          <div>
            <p className="section-kicker">Engagement Intake</p>
            <h3>Create a multi-seed engagement</h3>
            <p className="card-copy">
              Live mode can create new engagements directly from the overview route. Enter one seed per line.
            </p>
          </div>
          <div className="compose-grid">
            <label className="search-shell">
              <span>Name</span>
              <input
                value={engagementName}
                onChange={(event) => setEngagementName(event.target.value)}
                placeholder="Acme Holdings External Surface"
              />
            </label>
            <label className="filter-shell">
              <span>Status</span>
              <select value={engagementStatus} onChange={(event) => setEngagementStatus(event.target.value)}>
                <option value="PREP">PREP</option>
                <option value="ACTIVE">ACTIVE</option>
                <option value="COMPLETE">COMPLETE</option>
                <option value="ARCHIVED">ARCHIVED</option>
              </select>
            </label>
            <label className="search-shell tags-compose-shell">
              <span>Tags</span>
              <input
                value={engagementTags}
                onChange={(event) => setEngagementTags(event.target.value)}
                placeholder="external, finance, priority-high"
              />
            </label>
            <label className="seed-compose-shell">
              <span>Seeds</span>
              <textarea
                value={engagementSeeds}
                onChange={(event) => setEngagementSeeds(event.target.value)}
                placeholder={'acme.example\nsecurity@acme.example\n+15551234567'}
                rows={4}
              />
            </label>
            <div className="compose-actions">
              <button
                className="token-action"
                disabled={!liveToken || engagementBusy}
                onClick={() => void handleCreateEngagement()}
                type="button"
              >
                {engagementBusy ? 'Creating…' : 'Create engagement'}
              </button>
              <span className="muted-copy">
                {liveToken ? 'Live API active' : 'Unlock live mode to enable creation'}
              </span>
              {engagementError ? <span className="auth-error">{engagementError}</span> : null}
            </div>
          </div>
        </section>

        {loadError ? <div className="notice">Live data unavailable: {loadError}. Showing sample payload.</div> : null}
        {loading ? <div className="notice">Loading engagement index…</div> : null}
        {!loading && items.length === 0 ? (
          <div className="notice">
            No engagements match the current filters. Relax the search or severity scope to widen the view.
          </div>
        ) : null}

        <div className="engagement-grid">
          {items.map((item) => (
            <Link className="engagement-card" key={item.slug} to={`/engagements/${item.slug}`}>
              <div className="engagement-card-head">
                <span className={`status-pill ${statusTone(item.status)}`}>{item.status || 'unknown'}</span>
                <span className="mono-tag">{item.slug}</span>
              </div>
              <div className="severity-row">
                <span className={`severity-pill ${severityTone(item.highest_severity)}`}>{item.highest_severity}</span>
                <span className="card-copy">{severitySummaryText(item.severity_summary) || 'No findings yet'}</span>
              </div>
              <h3>{item.name}</h3>
              <p className="card-copy">{item.primary_seed || 'No primary seed recorded'}</p>
              {(item.tags ?? []).length > 0 ? (
                <div className="tag-row">
                  {(item.tags ?? []).map((tag) => (
                    <span className="meta-chip" key={`${item.slug}-${tag}`}>
                      {tag}
                    </span>
                  ))}
                </div>
              ) : null}
              <div className="card-metrics">
                <span>{formatCount(item.seeds.length)} seeds</span>
                <span>{formatCount(item.counts.hosts)} hosts</span>
                <span>{formatCount(engagementFindingCount(item))} findings</span>
                <span>{formatCount(engagementDataPointCount(item))} data points</span>
              </div>
              {item.run_summary ? (
                <div className="card-metrics">
                  <span>{item.run_summary.run_kind}</span>
                  <span>{item.run_summary.status}</span>
                  <span>
                    iter {formatCount(item.run_summary.current_iteration)}/
                    {formatCount(item.run_summary.max_iterations)}
                  </span>
                  <span>
                    audit {auditManifestHash(item.run_summary.audit_manifest) || auditManifestLabel(item.run_summary.audit_manifest)}
                  </span>
                </div>
              ) : null}
              <div className="card-footer">
                <span>{item.operator || 'unassigned operator'}</span>
                <span>{engagementActivityTimestamp(item) || 'no recent audit'}</span>
                <strong>Open detail route</strong>
              </div>
            </Link>
          ))}
        </div>
      </section>
    </main>
  )
}

function EngagementRoute({
  summaries,
  liveToken,
  onIndexRefresh,
}: {
  summaries: EngagementSummary[]
  liveToken: string | null
  onIndexRefresh: () => Promise<void>
}) {
  const navigate = useNavigate()
  const { slug = '' } = useParams()
  const [detail, setDetail] = useState<EngagementDetail | null>(SAMPLE_BY_SLUG.get(slug) ?? null)
  const [liveSeeds, setLiveSeeds] = useState<SeedRecord[]>([])
  const [liveLogs, setLiveLogs] = useState<RunLog[]>([])
  const [liveLogTail, setLiveLogTail] = useState<RunLogTail | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [progressNotice, setProgressNotice] = useState('')

  async function refreshLiveSnapshot(options?: {
    refreshSeeds?: boolean
    refreshIndex?: boolean
  }): Promise<void> {
    if (!slug || !liveToken) {
      return
    }
    const refreshSeeds = Boolean(options?.refreshSeeds)
    const refreshIndex = Boolean(options?.refreshIndex)
    const [nextDetail, nextLogs, nextSeeds] = await Promise.all([
      loadDetail(slug, summaries, liveToken),
      loadEngagementLogs(slug, liveToken),
      refreshSeeds ? loadLiveSeeds(slug, liveToken) : Promise.resolve<SeedRecord[] | null>(null),
      refreshIndex ? onIndexRefresh().then(() => true) : Promise.resolve(false),
    ])
    const nextTail = nextLogs.length ? await loadRunLogTail(nextLogs[0], liveToken) : null
    startTransition(() => {
      setDetail(nextDetail)
      if (nextSeeds !== null) {
        setLiveSeeds(nextSeeds)
      }
      setLiveLogs(nextLogs)
      setLiveLogTail(nextTail)
    })
  }

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    setError('')

    async function hydrate() {
      try {
        const payload = await loadDetail(slug, summaries, liveToken)
        if (!cancelled) {
          setDetail(payload)
          if (liveToken) {
            const [seeds, logs] = await Promise.all([
              loadLiveSeeds(slug, liveToken),
              loadEngagementLogs(slug, liveToken),
            ])
            const tail = logs.length ? await loadRunLogTail(logs[0], liveToken) : null
            if (!cancelled) {
              setLiveSeeds(seeds)
              setLiveLogs(logs)
              setLiveLogTail(tail)
            }
          } else {
            setLiveSeeds([])
            setLiveLogs([])
            setLiveLogTail(null)
          }
        }
      } catch (err) {
        if (!cancelled) {
          setDetail(SAMPLE_BY_SLUG.get(slug) ?? null)
          setLiveSeeds([])
          setLiveLogs([])
          setLiveLogTail(null)
          setError(err instanceof Error ? err.message : 'unable to load engagement detail')
        }
      } finally {
        if (!cancelled) {
          setLoading(false)
        }
      }
    }

    if (slug) {
      void hydrate()
    }

    return () => {
      cancelled = true
    }
  }, [slug, summaries, liveToken])

  useEffect(() => {
    if (!liveToken || !detail || !canUseLiveApi()) {
      return
    }
    const engagementId = Number(detail.id)
    if (!Number.isFinite(engagementId) || engagementId <= 0) {
      return
    }
    let disposed = false
    let socket: WebSocket | null = null
    let reconnectTimer: number | null = null

    const connect = () => {
      if (disposed) {
        return
      }
      socket = new WebSocket(
        `${window.location.protocol === 'https:' ? 'wss://' : 'ws://'}${window.location.host}/ws/progress`,
      )
      socket.onmessage = (messageEvent) => {
        try {
          const event = JSON.parse(messageEvent.data) as ProgressFeedEvent
          if (event.engagement_id !== engagementId) {
            return
          }
          setProgressNotice(progressMessageLabel(event))
          void refreshLiveSnapshot({ refreshSeeds: true, refreshIndex: false })
        } catch {
          return
        }
      }
      socket.onclose = () => {
        if (disposed) {
          return
        }
        reconnectTimer = window.setTimeout(connect, 2000)
      }
    }

    connect()
    return () => {
      disposed = true
      if (reconnectTimer !== null) {
        window.clearTimeout(reconnectTimer)
      }
      socket?.close()
    }
  }, [detail?.id, liveToken])

  useEffect(() => {
    if (!liveToken || !detail) {
      return
    }
    const runStatus = (detail.run_summary?.status || '').toLowerCase()
    if (!['running', 'pausing', 'stopping'].includes(runStatus)) {
      return
    }
    const intervalId = window.setInterval(() => {
      void refreshLiveSnapshot({ refreshSeeds: true, refreshIndex: false })
    }, 3000)
    return () => {
      window.clearInterval(intervalId)
    }
  }, [detail?.id, detail?.run_summary?.status, liveToken])

  async function handleAddSeed(seedValue: string, seedType: string): Promise<void> {
    if (!slug || !liveToken) {
      return
    }
    await fetchJson(`/api/engagements/${slug}/seeds`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...apiHeaders(liveToken),
      },
      body: JSON.stringify({
        seed_value: seedValue,
        ...(seedType ? { seed_type: seedType } : {}),
      }),
    })
    await refreshLiveSnapshot({ refreshSeeds: true, refreshIndex: true })
  }

  async function handleDeleteSeed(seedId: number): Promise<void> {
    if (!slug || !liveToken) {
      return
    }
    await fetchJson(`/api/engagements/${slug}/seeds/${seedId}`, {
      method: 'DELETE',
      headers: apiHeaders(liveToken),
    })
    await refreshLiveSnapshot({ refreshSeeds: true, refreshIndex: true })
  }

  async function handleUpdateEngagement(payload: {
    name: string
    status: string
    operator: string
    tags: string[]
  }): Promise<void> {
    if (!slug || !liveToken) {
      return
    }
    const nextDetail = await fetchJson<EngagementDetail>(`/api/engagements/${slug}`, {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        ...apiHeaders(liveToken),
      },
      body: JSON.stringify(payload),
    })
    await onIndexRefresh()
    setDetail(nextDetail)
    const logs = await loadEngagementLogs(nextDetail.slug, liveToken)
    setLiveLogs(logs)
    setLiveLogTail(logs.length ? await loadRunLogTail(logs[0], liveToken) : null)
    if (nextDetail.slug && nextDetail.slug !== slug) {
      navigate(`/engagements/${nextDetail.slug}`, { replace: true })
    }
  }

  async function handleLaunchKillChain(
    payload: KillChainLaunchPayload,
  ): Promise<{ pid: number; log_path: string; command_preview: string }> {
    if (!slug || !liveToken) {
      throw new Error('Unlock live API access before launching the kill-chain.')
    }
    const response = await fetchJson<{ pid: number; log_path: string; command_preview: string }>(
      `/api/engagements/${slug}/runs/kill-chain`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...apiHeaders(liveToken),
        },
        body: JSON.stringify({
          max_iter: payload.maxIter,
          dry_run: payload.dryRun,
          skip_cloud: payload.skipCloud,
          skip_keyscan: payload.skipKeyscan,
          resume: payload.resume,
          ...(payload.reportProvider ? { report_provider: payload.reportProvider } : {}),
          ...(payload.reportMaxLoops.trim() ? { report_max_loops: Number(payload.reportMaxLoops) } : {}),
        }),
      },
    )
    await refreshLiveSnapshot({ refreshSeeds: true, refreshIndex: true })
    return response
  }

  async function handleRestartKillChain(
    payload: KillChainLaunchPayload,
  ): Promise<{ pid: number; log_path: string; command_preview: string }> {
    if (!slug || !liveToken) {
      throw new Error('Unlock live API access before restarting the kill-chain.')
    }
    const response = await fetchJson<{ pid: number; log_path: string; command_preview: string }>(
      `/api/engagements/${slug}/runs/restart`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...apiHeaders(liveToken),
        },
        body: JSON.stringify({
          max_iter: payload.maxIter,
          dry_run: payload.dryRun,
          skip_cloud: payload.skipCloud,
          skip_keyscan: payload.skipKeyscan,
          ...(payload.reportProvider ? { report_provider: payload.reportProvider } : {}),
          ...(payload.reportMaxLoops.trim() ? { report_max_loops: Number(payload.reportMaxLoops) } : {}),
        }),
      },
    )
    await refreshLiveSnapshot({ refreshSeeds: true, refreshIndex: true })
    return response
  }

  async function handleStopKillChain(): Promise<{ active_run_id: number | null }> {
    if (!slug || !liveToken) {
      throw new Error('Unlock live API access before stopping the kill-chain.')
    }
    const response = await fetchJson<{ active_run_id: number | null }>(
      `/api/engagements/${slug}/runs/stop`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...apiHeaders(liveToken),
        },
        body: JSON.stringify({ reason: 'operator stop requested from engagement detail' }),
      },
    )
    await refreshLiveSnapshot({ refreshSeeds: false, refreshIndex: true })
    return response
  }

  async function handlePauseKillChain(): Promise<{ active_run_id: number | null }> {
    if (!slug || !liveToken) {
      throw new Error('Unlock live API access before pausing the kill-chain.')
    }
    const response = await fetchJson<{ active_run_id: number | null }>(
      `/api/engagements/${slug}/runs/pause`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...apiHeaders(liveToken),
        },
        body: JSON.stringify({ reason: 'operator pause requested from engagement detail' }),
      },
    )
    await refreshLiveSnapshot({ refreshSeeds: false, refreshIndex: true })
    return response
  }

  async function handleResumeKillChain(
    payload: KillChainLaunchPayload,
  ): Promise<{ pid: number; log_path: string; command_preview: string }> {
    if (!slug || !liveToken) {
      throw new Error('Unlock live API access before resuming the kill-chain.')
    }
    const response = await fetchJson<{ pid: number; log_path: string; command_preview: string }>(
      `/api/engagements/${slug}/runs/resume`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...apiHeaders(liveToken),
        },
        body: JSON.stringify({
          max_iter: payload.maxIter,
          dry_run: payload.dryRun,
          skip_cloud: payload.skipCloud,
          skip_keyscan: payload.skipKeyscan,
          ...(payload.reportProvider ? { report_provider: payload.reportProvider } : {}),
          ...(payload.reportMaxLoops.trim() ? { report_max_loops: Number(payload.reportMaxLoops) } : {}),
        }),
      },
    )
    await refreshLiveSnapshot({ refreshSeeds: true, refreshIndex: true })
    return response
  }

  if (!slug) {
    return <NotFoundState />
  }

  if (!detail && !loading) {
    return <NotFoundState />
  }

  if (!detail) {
    return <section className="notice">Loading engagement detail…</section>
  }

  return (
    <DetailPage
      detail={detail}
      loading={loading}
      error={error}
      liveToken={liveToken}
      liveSeeds={liveSeeds}
      liveLogs={liveLogs}
      liveLogTail={liveLogTail}
      progressNotice={progressNotice}
      onAddSeed={handleAddSeed}
      onDeleteSeed={handleDeleteSeed}
      onUpdateEngagement={handleUpdateEngagement}
      onLaunchKillChain={handleLaunchKillChain}
      onRestartKillChain={handleRestartKillChain}
      onPauseKillChain={handlePauseKillChain}
      onStopKillChain={handleStopKillChain}
      onResumeKillChain={handleResumeKillChain}
    />
  )
}

function DetailPage({
  detail,
  loading,
  error,
  liveToken,
  liveSeeds,
  liveLogs,
  liveLogTail,
  progressNotice,
  onAddSeed,
  onDeleteSeed,
  onUpdateEngagement,
  onLaunchKillChain,
  onRestartKillChain,
  onPauseKillChain,
  onStopKillChain,
  onResumeKillChain,
}: {
  detail: EngagementDetail
  loading: boolean
  error: string
  liveToken: string | null
  liveSeeds: SeedRecord[]
  liveLogs: RunLog[]
  liveLogTail: RunLogTail | null
  progressNotice: string
  onAddSeed: (seedValue: string, seedType: string) => Promise<void>
  onDeleteSeed: (seedId: number) => Promise<void>
  onUpdateEngagement: (payload: {
    name: string
    status: string
    operator: string
    tags: string[]
  }) => Promise<void>
  onLaunchKillChain: (payload: KillChainLaunchPayload) => Promise<{ pid: number; log_path: string; command_preview: string }>
  onRestartKillChain: (payload: KillChainLaunchPayload) => Promise<{ pid: number; log_path: string; command_preview: string }>
  onPauseKillChain: () => Promise<{ active_run_id: number | null }>
  onStopKillChain: () => Promise<{ active_run_id: number | null }>
  onResumeKillChain: (payload: KillChainLaunchPayload) => Promise<{ pid: number; log_path: string; command_preview: string }>
}) {
  const [engagementName, setEngagementName] = useState(detail.name)
  const [engagementStatus, setEngagementStatus] = useState(detail.status)
  const [engagementOperator, setEngagementOperator] = useState(detail.operator)
  const [engagementTags, setEngagementTags] = useState((detail.tags ?? []).join(', '))
  const [engagementDirty, setEngagementDirty] = useState(false)
  const [engagementBusy, setEngagementBusy] = useState(false)
  const [runBusy, setRunBusy] = useState(false)
  const [runDryRun, setRunDryRun] = useState(false)
  const [runSkipCloud, setRunSkipCloud] = useState(false)
  const [runSkipKeyscan, setRunSkipKeyscan] = useState(false)
  const [runResume, setRunResume] = useState(true)
  const [runMaxIter, setRunMaxIter] = useState(3)
  const [runReportProvider, setRunReportProvider] = useState('')
  const [runReportMaxLoops, setRunReportMaxLoops] = useState('')
  const [runError, setRunError] = useState('')
  const [runMessage, setRunMessage] = useState('')
  const [newSeedValue, setNewSeedValue] = useState('')
  const [newSeedType, setNewSeedType] = useState('')
  const [seedBusy, setSeedBusy] = useState(false)
  const [seedError, setSeedError] = useState('')
  const [engagementError, setEngagementError] = useState('')
  const reportPreview = detail.report_previews[0]
  const auditRows = detail.sections.audit_log ?? []
  const hostRows = detail.sections.hosts ?? []
  const emailRows = detail.sections.emails ?? []
  const seedRows = detail.sections.engagement_seeds ?? []
  const seedRunRows = detail.sections.seed_runs ?? []
  const keyFindingRows = detail.sections.key_scanner_findings ?? []
  const cloudValidationRows = detail.sections.cloud_validation_results ?? []
  const runStatus = (detail.run_summary?.status || '').toLowerCase()
  const runIsActive = ['running', 'stopping', 'pausing'].includes(runStatus)
  const runIsPaused = runStatus === 'paused'
  const runMetadata = detail.run_summary?.metadata ?? {}
  const auditManifest = detail.run_summary?.audit_manifest
  const auditManifestStatus = auditManifestLabel(auditManifest)
  const auditManifestShortHash = auditManifestHash(auditManifest)
  const auditManifestSummary = auditManifestShortHash
    ? `${auditManifestShortHash} · ${auditManifestStatus}`
    : auditManifestStatus
  const liveExecutionPolicy =
    runMetadata.live_execution_policy &&
    typeof runMetadata.live_execution_policy === 'object' &&
    !Array.isArray(runMetadata.live_execution_policy)
      ? (runMetadata.live_execution_policy as Record<string, unknown>)
      : {}
  const runPolicyValue = (key: keyof RunSummary): unknown =>
    detail.run_summary?.[key] ?? liveExecutionPolicy[key] ?? runMetadata[key]
  const formatPolicyFlag = (value: unknown): string => {
    if (typeof value === 'boolean') {
      return value ? 'yes' : 'no'
    }
    if (value == null || value === '') {
      return '-'
    }
    return stringifyUnknown(value)
  }
  const recentRunSteps = Array.isArray(runMetadata.recent_steps)
    ? runMetadata.recent_steps.filter(
        (item): item is Record<string, unknown> => Boolean(item) && typeof item === 'object',
      )
    : []
  const recentRunStepRows: SectionRow[] = recentRunSteps
    .slice()
    .reverse()
    .map((item) => ({
      Phase: stringifyUnknown(item.phase),
      Step: stringifyUnknown(item.step),
      Message: stringifyUnknown(item.message),
      Elapsed: stringifyUnknown(item.elapsed_seconds),
    }))
  const runCountSummary = summarizeRunCounts(runMetadata.counts)
  const runDeltaSummary = summarizeRunDelta(runMetadata.last_iteration_delta)
  const runArtifactQueueSummary = summarizeRunQueueGroup(runMetadata.queue_metrics, 'artifact_queue', [
    ['queued', 'queued'],
    ['downloaded', 'downloaded'],
    ['parsed', 'parsed'],
    ['failed', 'failed'],
    ['skipped', 'skipped'],
  ])
  const runArtifactProcessorSummary = summarizeRunQueueGroup(runMetadata.queue_metrics, 'artifact_processor', [
    ['running', 'running'],
    ['pending', 'pending'],
    ['completed', 'done'],
    ['failed', 'failed'],
    ['workers', 'workers'],
    ['total', 'total'],
  ])
  const runValidationBatchSummary = summarizeRunQueueGroup(runMetadata.queue_metrics, 'validation_batch', [
    ['running', 'running'],
    ['pending', 'pending'],
    ['completed', 'done'],
    ['failed', 'failed'],
    ['workers', 'workers'],
    ['total', 'total'],
  ])
  const runFinalizationBatchSummary = summarizeRunQueueGroup(runMetadata.queue_metrics, 'finalization_batch', [
    ['running', 'running'],
    ['pending', 'pending'],
    ['completed', 'done'],
    ['failed', 'failed'],
    ['workers', 'workers'],
    ['total', 'total'],
  ])
  const runFanoutBatchSummary = summarizeRunQueueGroup(runMetadata.queue_metrics, 'fanout_batch', [
    ['running', 'running'],
    ['pending', 'pending'],
    ['completed', 'done'],
    ['failed', 'failed'],
    ['workers', 'workers'],
    ['total', 'total'],
  ])
  const runCloudValidationSummary = summarizeRunQueueGroup(runMetadata.queue_metrics, 'cloud_validation', [
    ['VALIDATED', 'validated'],
    ['ACCESSIBLE_BUT_NO_DATA', 'metadata-only'],
    ['UNVERIFIED', 'unverified'],
    ['HONEYPOT_SUSPECTED', 'honeypot'],
    ['DEAD', 'dead'],
    ['UNSUPPORTED', 'unsupported'],
    ['UNVALIDATED', 'pending'],
  ])
  const runStability =
    typeof runMetadata.last_iteration_stable === 'boolean'
      ? runMetadata.last_iteration_stable
        ? 'stable'
        : 'growing'
      : ''
  const runBatchEta =
    typeof runMetadata.active_batch_eta_seconds === 'number'
      ? `${runMetadata.active_batch_eta_seconds.toFixed(1)}s`
      : ''
  const runArtifactEta =
    typeof runMetadata.active_artifact_eta_seconds === 'number'
      ? `${runMetadata.active_artifact_eta_seconds.toFixed(1)}s`
      : ''
  const runValidationEta =
    typeof runMetadata.active_validation_eta_seconds === 'number'
      ? `${runMetadata.active_validation_eta_seconds.toFixed(1)}s`
      : ''
  const runFinalizationEta =
    typeof runMetadata.active_finalization_eta_seconds === 'number'
      ? `${runMetadata.active_finalization_eta_seconds.toFixed(1)}s`
      : ''
  const reportArtifacts = detail.artifacts.filter((artifact) => artifact.kind === 'report')
  const graphArtifacts = detail.artifacts.filter((artifact) => artifact.kind === 'graph')
  const auditArtifacts = detail.artifacts.filter((artifact) => artifact.kind === 'audit')
  const jsonExportHref = detail.detail_api ?? detail.detail_data
  const reportSummary = detail.report_summary
  const reportHistory = detail.report_history ?? (reportSummary ? [reportSummary] : [])
  const priorReportHistory = reportHistory.slice(1)
  const reportArtifactByName = new Map(reportArtifacts.map((artifact) => [artifact.name, artifact] as const))
  const resolveReportArtifactLabel = (artifactName: string) => {
    const matchedExport = reportSummary?.available_exports?.find(
      (exportArtifact) => exportArtifact.artifact_name === artifactName,
    )
    if (matchedExport?.label) {
      return matchedExport.label
    }
    const lowerName = artifactName.toLowerCase()
    if (lowerName.endsWith('.pdf')) return 'PDF'
    if (lowerName.endsWith('.csv')) return 'CSV'
    if (lowerName.endsWith('.json')) return 'Report JSON'
    return 'Markdown'
  }
  const exportLinks = [
    ...((reportSummary?.available_exports?.length
      ? reportSummary.available_exports
          .map((exportArtifact) => {
            const artifact = reportArtifactByName.get(exportArtifact.artifact_name)
            if (!artifact) return null
            return {
              label: exportArtifact.label || resolveReportArtifactLabel(artifact.name),
              href: artifact.href,
              title: artifact.name,
            }
          })
          .filter((artifact): artifact is { label: string; href: string; title: string } => Boolean(artifact))
      : reportArtifacts.map((artifact) => ({
          label: resolveReportArtifactLabel(artifact.name),
          href: artifact.href,
          title: artifact.name,
        })))),
    ...(jsonExportHref
      ? [{ label: 'Detail JSON', href: jsonExportHref, title: `${detail.slug}.json` }]
      : []),
    ...(graphArtifacts.slice(0, 1).map((artifact) => ({
      label: 'Graph',
      href: artifact.href,
      title: artifact.name,
    }))),
    ...(auditArtifacts.slice(0, 1).map((artifact) => ({
      label: 'Audit',
      href: artifact.href,
      title: artifact.name,
    }))),
  ]
  const findingRows = [
    ...(detail.sections.vulnerability_findings ?? []),
    ...(detail.sections.passive_vulns ?? []),
  ]
  const evidenceSections = Object.entries(detail.sections).filter(
    ([sectionKey, rows]) =>
      !['hosts', 'emails', 'audit_log'].includes(sectionKey) &&
      rows.length > 0 &&
      SECTION_TITLES[sectionKey],
  )

  const detailTagsText = (detail.tags ?? []).join(', ')

  useEffect(() => {
    setEngagementDirty(false)
  }, [detail.slug])

  useEffect(() => {
    if (engagementDirty) {
      return
    }
    setEngagementName(detail.name)
    setEngagementStatus(detail.status)
    setEngagementOperator(detail.operator)
    setEngagementTags(detailTagsText)
  }, [detail.name, detail.operator, detail.status, detailTagsText, engagementDirty])

  async function handleEngagementSave(): Promise<void> {
    if (!liveToken) {
      setEngagementError('Unlock live API access before editing engagement metadata.')
      return
    }
    if (!engagementName.trim()) {
      setEngagementError('Engagement name is required.')
      return
    }
    setEngagementBusy(true)
    setEngagementError('')
    try {
      await onUpdateEngagement({
        name: engagementName.trim(),
        status: engagementStatus,
        operator: engagementOperator.trim(),
        tags: splitListInput(engagementTags),
      })
      setEngagementDirty(false)
    } catch (actionError) {
      setEngagementError(actionError instanceof Error ? actionError.message : 'unable to update engagement')
    } finally {
      setEngagementBusy(false)
    }
  }

  async function handleSeedSubmit(): Promise<void> {
    if (!liveToken) {
      setSeedError('Unlock live API access before editing seeds.')
      return
    }
    if (!newSeedValue.trim()) {
      setSeedError('Seed value is required.')
      return
    }
    setSeedBusy(true)
    setSeedError('')
    try {
      await onAddSeed(newSeedValue.trim(), newSeedType)
      setNewSeedValue('')
      setNewSeedType('')
    } catch (actionError) {
      setSeedError(actionError instanceof Error ? actionError.message : 'unable to add seed')
    } finally {
      setSeedBusy(false)
    }
  }

  async function handleSeedDelete(seedId: number): Promise<void> {
    setSeedBusy(true)
    setSeedError('')
    try {
      await onDeleteSeed(seedId)
    } catch (actionError) {
      setSeedError(actionError instanceof Error ? actionError.message : 'unable to remove seed')
    } finally {
      setSeedBusy(false)
    }
  }

  async function handleLaunchSubmit(): Promise<void> {
    if (!liveToken) {
      setRunError('Unlock live API access before launching the kill-chain.')
      return
    }
    setRunBusy(true)
    setRunError('')
    setRunMessage('')
    try {
      const launch = await onLaunchKillChain({
        maxIter: Math.min(Math.max(runMaxIter, 1), 10),
        dryRun: runDryRun,
        skipCloud: runSkipCloud,
        skipKeyscan: runSkipKeyscan,
        resume: runResume,
        reportProvider: runReportProvider,
        reportMaxLoops: runReportMaxLoops,
      })
      setRunMessage(`PID ${launch.pid} · log ${launch.log_path}`)
    } catch (actionError) {
      setRunError(actionError instanceof Error ? actionError.message : 'unable to launch kill-chain')
    } finally {
      setRunBusy(false)
    }
  }

  async function handleStopSubmit(): Promise<void> {
    if (!liveToken) {
      setRunError('Unlock live API access before stopping the kill-chain.')
      return
    }
    setRunBusy(true)
    setRunError('')
    setRunMessage('')
    try {
      const stop = await onStopKillChain()
      setRunMessage(
        stop.active_run_id
          ? `Stop requested for run ${stop.active_run_id}`
          : 'Stop marker created for the next run checkpoint',
      )
    } catch (actionError) {
      setRunError(actionError instanceof Error ? actionError.message : 'unable to stop kill-chain')
    } finally {
      setRunBusy(false)
    }
  }

  async function handleRestartSubmit(): Promise<void> {
    if (!liveToken) {
      setRunError('Unlock live API access before restarting the kill-chain.')
      return
    }
    setRunBusy(true)
    setRunError('')
    setRunMessage('')
    try {
      const restarted = await onRestartKillChain({
        maxIter: Math.min(Math.max(runMaxIter, 1), 10),
        dryRun: runDryRun,
        skipCloud: runSkipCloud,
        skipKeyscan: runSkipKeyscan,
        reportProvider: runReportProvider,
        reportMaxLoops: runReportMaxLoops,
      })
      setRunMessage(`Restarted PID ${restarted.pid} · log ${restarted.log_path}`)
    } catch (actionError) {
      setRunError(actionError instanceof Error ? actionError.message : 'unable to restart kill-chain')
    } finally {
      setRunBusy(false)
    }
  }

  async function handlePauseSubmit(): Promise<void> {
    if (!liveToken) {
      setRunError('Unlock live API access before pausing the kill-chain.')
      return
    }
    setRunBusy(true)
    setRunError('')
    setRunMessage('')
    try {
      const pause = await onPauseKillChain()
      setRunMessage(
        pause.active_run_id
          ? `Pause requested for run ${pause.active_run_id}`
          : 'Pause marker created for the next run checkpoint',
      )
    } catch (actionError) {
      setRunError(actionError instanceof Error ? actionError.message : 'unable to pause kill-chain')
    } finally {
      setRunBusy(false)
    }
  }

  async function handleResumeSubmit(): Promise<void> {
    if (!liveToken) {
      setRunError('Unlock live API access before resuming the kill-chain.')
      return
    }
    setRunBusy(true)
    setRunError('')
    setRunMessage('')
    try {
      const resumed = await onResumeKillChain({
        maxIter: Math.min(Math.max(runMaxIter, 1), 10),
        dryRun: runDryRun,
        skipCloud: runSkipCloud,
        skipKeyscan: runSkipKeyscan,
        reportProvider: runReportProvider,
        reportMaxLoops: runReportMaxLoops,
      })
      setRunMessage(`Resumed PID ${resumed.pid} · log ${resumed.log_path}`)
    } catch (actionError) {
      setRunError(actionError instanceof Error ? actionError.message : 'unable to resume kill-chain')
    } finally {
      setRunBusy(false)
    }
  }

  return (
    <main className="detail-layout">
      <Link className="back-link" to="/">
        Back to dashboard
      </Link>

      <section className="detail-hero">
        <div>
          <p className="section-kicker">Engagement Detail Route</p>
          <h2>{detail.name}</h2>
          <p className="card-copy">
            Seeds, executive report, audit chronology, and graph workspace are grouped around the
            engagement slug instead of being flattened into a single dashboard.
          </p>
          {(detail.tags ?? []).length > 0 ? (
            <div className="tag-row">
              {(detail.tags ?? []).map((tag) => (
                <span className="meta-chip" key={`${detail.slug}-detail-${tag}`}>
                  {tag}
                </span>
              ))}
            </div>
          ) : null}
        </div>
        <div className="detail-hero-meta">
          <span className={`status-pill ${statusTone(detail.status)}`}>{detail.status || 'unknown'}</span>
          <span className="mono-tag">{detail.slug}</span>
          <span className="meta-chip">Latest audit {detail.latest_audit || detail.updated_at}</span>
        </div>
      </section>

      {error ? <div className="notice">Live detail unavailable: {error}. Showing fallback payload.</div> : null}
      {loading ? <div className="notice">Refreshing engagement detail…</div> : null}

      <section className="summary-band">
        <article className="summary-card">
          <span className="summary-label">Seeds</span>
          <strong>{formatCount(detail.seeds.length)}</strong>
        </article>
        <article className="summary-card">
          <span className="summary-label">Highest severity</span>
          <strong>{detail.highest_severity}</strong>
        </article>
        <article className="summary-card">
          <span className="summary-label">Critical / High</span>
          <strong>
            {formatCount(detail.severity_summary.CRITICAL ?? 0)} / {formatCount(detail.severity_summary.HIGH ?? 0)}
          </strong>
        </article>
        <article className="summary-card">
          <span className="summary-label">Audit Events</span>
          <strong>{formatCount(auditRows.length)}</strong>
        </article>
        <article className="summary-card">
          <span className="summary-label">Seed Runs</span>
          <strong>{formatCount(seedRunRows.length || detail.counts.seed_runs)}</strong>
        </article>
        <article className="summary-card">
          <span className="summary-label">Run status</span>
          <strong>{detail.run_summary?.status || 'untracked'}</strong>
        </article>
        <article className="summary-card">
          <span className="summary-label">Audit manifest</span>
          <strong>{auditManifestShortHash || auditManifestStatus}</strong>
        </article>
      </section>

      <nav className="section-nav" aria-label="Engagement sections">
        <a href="#overview">Overview</a>
        <a href="#report">Report</a>
        <a href="#seeds">Seeds</a>
        <a href="#graph">Graph</a>
        <a href="#findings">Findings</a>
        <a href="#evidence">Evidence</a>
        <a href="#audit">Audit</a>
        <a href="#raw-data">Raw data</a>
      </nav>

      <section className="detail-grid">
        <article className="panel" id="overview">
          <div className="panel-head">
            <p className="section-kicker">Overview</p>
            <strong>{detail.operator || 'unassigned operator'}</strong>
          </div>
          <div className="panel-body">
            <div className="token-wrap">
              {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map((severity) => (
                <span className={`severity-pill ${severityTone(severity)}`} key={severity}>
                  {severity}: {formatCount(detail.severity_summary[severity] ?? 0)}
                </span>
              ))}
            </div>
            <div className="mini-table">
              <div className="mini-table-row">
                <span>Created</span>
                <span>{detail.created_at || '-'}</span>
              </div>
              <div className="mini-table-row">
                <span>Updated</span>
                <span>{detail.updated_at || '-'}</span>
              </div>
              <div className="mini-table-row">
                <span>Latest audit</span>
                <span>{detail.latest_audit || '-'}</span>
              </div>
              <div className="mini-table-row">
                <span>Latest run</span>
                <span>
                  {detail.run_summary
                    ? `${detail.run_summary.run_kind} ${detail.run_summary.status} (${detail.run_summary.current_iteration}/${detail.run_summary.max_iterations})`
                    : '-'}
                </span>
              </div>
              <div className="mini-table-row">
                <span>Audit manifest</span>
                <span>{auditManifestShortHash || '-'}</span>
              </div>
              <div className="mini-table-row">
                <span>Audit verification</span>
                <span>
                  {auditManifestStatus}
                  {auditManifest?.reason ? ` · ${auditManifest.reason}` : ''}
                </span>
              </div>
              <div className="mini-table-row">
                <span>Database</span>
                <span>{detail.path}</span>
              </div>
            </div>
            <div className="scope-block">
              <span className="summary-label">Live engagement controls</span>
              <div className="seed-manager">
                <div className="seed-manager-form">
                  <label className="graph-filter">
                    <span>Name</span>
                    <input
                      value={engagementName}
                      onChange={(event) => {
                        setEngagementDirty(true)
                        setEngagementName(event.target.value)
                      }}
                      placeholder="Engagement name"
                    />
                  </label>
                  <label className="graph-filter">
                    <span>Status</span>
                    <select
                      value={engagementStatus}
                      onChange={(event) => {
                        setEngagementDirty(true)
                        setEngagementStatus(event.target.value)
                      }}
                    >
                      <option value="PREP">PREP</option>
                      <option value="ACTIVE">ACTIVE</option>
                      <option value="COMPLETE">COMPLETE</option>
                      <option value="ARCHIVED">ARCHIVED</option>
                    </select>
                  </label>
                  <button
                    className="token-action"
                    disabled={!liveToken || engagementBusy}
                    onClick={() => void handleEngagementSave()}
                    type="button"
                  >
                    {engagementBusy ? 'Saving…' : 'Save'}
                  </button>
                </div>
                <div className="seed-manager-meta">
                  <label className="graph-filter">
                    <span>Operator</span>
                    <input
                      value={engagementOperator}
                      onChange={(event) => {
                        setEngagementDirty(true)
                        setEngagementOperator(event.target.value)
                      }}
                      placeholder="operator"
                    />
                  </label>
                  <label className="graph-filter">
                    <span>Tags</span>
                    <input
                      value={engagementTags}
                      onChange={(event) => {
                        setEngagementDirty(true)
                        setEngagementTags(event.target.value)
                      }}
                      placeholder="external, finance, priority-high"
                    />
                  </label>
                </div>
                {engagementError ? <span className="auth-error">{engagementError}</span> : null}
              </div>
            </div>
            <div className="scope-block">
              <span className="summary-label">Kill-chain controls</span>
              <div className="seed-manager">
                <div className="seed-manager-form">
                  <label className="graph-filter">
                    <span>Max iterations</span>
                    <input
                      min={1}
                      max={10}
                      type="number"
                      value={runMaxIter}
                      onChange={(event) => setRunMaxIter(Number(event.target.value || 1))}
                    />
                  </label>
                  <label className="graph-filter">
                    <span>Report provider</span>
                    <select value={runReportProvider} onChange={(event) => setRunReportProvider(event.target.value)}>
                      <option value="">Env / default</option>
                      <option value="auto">auto cascade</option>
                      <option value="template">template</option>
                      <option value="llama_cpp">llama_cpp</option>
                      <option value="kiro_cli">kiro_cli</option>
                      <option value="claude_code">claude_code</option>
                      <option value="codex_cli">codex_cli</option>
                      <option value="gemini_cli">gemini_cli</option>
                      <option value="bedrock_anthropic">bedrock_anthropic</option>
                      <option value="openai_compatible">openai_compatible</option>
                    </select>
                  </label>
                  <label className="graph-filter">
                    <span>Report loops</span>
                    <input
                      min={0}
                      max={10}
                      type="number"
                      value={runReportMaxLoops}
                      onChange={(event) => setRunReportMaxLoops(event.target.value)}
                      placeholder="default"
                    />
                  </label>
                  <label className="graph-toggle">
                    <input checked={runResume} onChange={(event) => setRunResume(event.target.checked)} type="checkbox" />
                    <span>Resume</span>
                  </label>
                  <label className="graph-toggle">
                    <input checked={runDryRun} onChange={(event) => setRunDryRun(event.target.checked)} type="checkbox" />
                    <span>Dry run</span>
                  </label>
                  <label className="graph-toggle">
                    <input checked={runSkipCloud} onChange={(event) => setRunSkipCloud(event.target.checked)} type="checkbox" />
                    <span>Skip cloud</span>
                  </label>
                  <label className="graph-toggle">
                    <input
                      checked={runSkipKeyscan}
                      onChange={(event) => setRunSkipKeyscan(event.target.checked)}
                      type="checkbox"
                    />
                    <span>Skip keyscan</span>
                  </label>
                  <button
                    className="token-action"
                    disabled={!liveToken || runBusy || runIsActive}
                    onClick={() => void handleLaunchSubmit()}
                    type="button"
                  >
                    {runBusy ? 'Launching…' : 'Launch kill-chain'}
                  </button>
                  <button
                    className="token-action is-secondary"
                    disabled={!liveToken || runBusy || !runIsPaused}
                    onClick={() => void handleResumeSubmit()}
                    type="button"
                  >
                    Resume run
                  </button>
                  <button
                    className="token-action is-secondary"
                    disabled={!liveToken || runBusy || runIsActive}
                    onClick={() => void handleRestartSubmit()}
                    type="button"
                  >
                    Restart run
                  </button>
                  <button
                    className="token-action is-secondary"
                    disabled={!liveToken || runBusy || !runIsActive || runStatus !== 'running'}
                    onClick={() => void handlePauseSubmit()}
                    type="button"
                  >
                    Pause run
                  </button>
                  <button
                    className="token-action is-secondary"
                    disabled={!liveToken || runBusy || !runIsActive}
                    onClick={() => void handleStopSubmit()}
                    type="button"
                  >
                    Stop run
                  </button>
                </div>
                <div className="token-wrap">
                  {liveLogs.length ? (
                    liveLogs.slice(0, 3).map((log) => (
                      <a
                        className="token token-link"
                        href={resolveDownloadHref(log.href)}
                        key={log.name}
                        target="_blank"
                        rel="noreferrer"
                      >
                        {log.name}
                      </a>
                    ))
                  ) : (
                    <span className="muted-copy">No run logs captured yet.</span>
                  )}
                </div>
                {liveLogTail ? (
                  <div className="run-log-shell">
                    <span className="summary-label">Latest log tail · {liveLogTail.name}</span>
                    <pre className="run-log-tail">{liveLogTail.tail || 'Waiting for log output…'}</pre>
                  </div>
                ) : null}
                {detail.run_summary ? (
                  <div className="scope-block">
                    <span className="summary-label">Live run telemetry</span>
                    <div className="mini-table">
                      <div className="mini-table-row">
                        <span>Phase</span>
                        <span>{stringifyUnknown(runMetadata.phase) || detail.run_summary.status || '-'}</span>
                      </div>
                      <div className="mini-table-row">
                        <span>Audit manifest</span>
                        <span>{auditManifestSummary}</span>
                      </div>
                      <div className="mini-table-row">
                        <span>ROE reference</span>
                        <span>{stringifyUnknown(runPolicyValue('roe_id')) || '-'}</span>
                      </div>
                      <div className="mini-table-row">
                        <span>ROE missing</span>
                        <span>{formatPolicyFlag(runPolicyValue('roe_missing'))}</span>
                      </div>
                      <div className="mini-table-row">
                        <span>Scope gate</span>
                        <span>{stringifyUnknown(runPolicyValue('scope_gate')) || '-'}</span>
                      </div>
                      <div className="mini-table-row">
                        <span>Live probing</span>
                        <span>{formatPolicyFlag(runPolicyValue('live_probing_allowed'))}</span>
                      </div>
                      <div className="mini-table-row">
                        <span>Tool execution</span>
                        <span>{formatPolicyFlag(runPolicyValue('tool_execution_allowed'))}</span>
                      </div>
                      <div className="mini-table-row">
                        <span>Active recon</span>
                        <span>{formatPolicyFlag(runPolicyValue('active_recon_allowed'))}</span>
                      </div>
                      <div className="mini-table-row">
                        <span>Credential validation</span>
                        <span>{formatPolicyFlag(runPolicyValue('credential_validation_allowed'))}</span>
                      </div>
                      <div className="mini-table-row">
                        <span>Destructive actions</span>
                        <span>{formatPolicyFlag(runPolicyValue('destructive_actions_allowed'))}</span>
                      </div>
                      <div className="mini-table-row">
                        <span>Post-exploitation</span>
                        <span>{formatPolicyFlag(runPolicyValue('post_exploitation_allowed'))}</span>
                      </div>
                      <div className="mini-table-row">
                        <span>Last step</span>
                        <span>{stringifyUnknown(runMetadata.last_step) || '-'}</span>
                      </div>
                      <div className="mini-table-row">
                        <span>Last message</span>
                        <span>{stringifyUnknown(runMetadata.last_message) || '-'}</span>
                      </div>
                      <div className="mini-table-row">
                        <span>Step elapsed</span>
                        <span>{stringifyUnknown(runMetadata.last_step_elapsed_seconds) || '-'}</span>
                      </div>
                      <div className="mini-table-row">
                        <span>Tracked totals</span>
                        <span>{runCountSummary || '-'}</span>
                      </div>
                      <div className="mini-table-row">
                        <span>Last iteration delta</span>
                        <span>{runDeltaSummary || '-'}</span>
                      </div>
                      <div className="mini-table-row">
                        <span>Artifact queue</span>
                        <span>{runArtifactQueueSummary || '-'}</span>
                      </div>
                      <div className="mini-table-row">
                        <span>Artifact stage</span>
                        <span>{stringifyUnknown(runMetadata.active_artifact_stage_label) || '-'}</span>
                      </div>
                      <div className="mini-table-row">
                        <span>Artifact stage state</span>
                        <span>{runArtifactProcessorSummary || '-'}</span>
                      </div>
                      <div className="mini-table-row">
                        <span>Artifact ETA</span>
                        <span>{runArtifactEta || '-'}</span>
                      </div>
                      <div className="mini-table-row">
                        <span>Validation stage</span>
                        <span>{stringifyUnknown(runMetadata.active_validation_stage_label) || '-'}</span>
                      </div>
                      <div className="mini-table-row">
                        <span>Validation state</span>
                        <span>{runValidationBatchSummary || '-'}</span>
                      </div>
                      <div className="mini-table-row">
                        <span>Validation ETA</span>
                        <span>{runValidationEta || '-'}</span>
                      </div>
                      <div className="mini-table-row">
                        <span>Finalization stage</span>
                        <span>{stringifyUnknown(runMetadata.active_finalization_stage_label) || '-'}</span>
                      </div>
                      <div className="mini-table-row">
                        <span>Finalization state</span>
                        <span>{runFinalizationBatchSummary || '-'}</span>
                      </div>
                      <div className="mini-table-row">
                        <span>Finalization ETA</span>
                        <span>{runFinalizationEta || '-'}</span>
                      </div>
                      <div className="mini-table-row">
                        <span>Fan-out batch</span>
                        <span>{stringifyUnknown(runMetadata.active_batch_label) || '-'}</span>
                      </div>
                      <div className="mini-table-row">
                        <span>Batch state</span>
                        <span>{runFanoutBatchSummary || '-'}</span>
                      </div>
                      <div className="mini-table-row">
                        <span>Batch ETA</span>
                        <span>{runBatchEta || '-'}</span>
                      </div>
                      <div className="mini-table-row">
                        <span>Cloud validation</span>
                        <span>{runCloudValidationSummary || '-'}</span>
                      </div>
                      <div className="mini-table-row">
                        <span>Iteration state</span>
                        <span>{runStability || '-'}</span>
                      </div>
                      <div className="mini-table-row">
                        <span>Report provider</span>
                        <span>{stringifyUnknown(runMetadata.report_provider) || 'default'}</span>
                      </div>
                      <div className="mini-table-row">
                        <span>Report loops</span>
                        <span>{stringifyUnknown(runMetadata.report_max_loops) || 'default'}</span>
                      </div>
                    </div>
                    <DataList rows={recentRunStepRows} emptyText="No recent run steps recorded yet." />
                  </div>
                ) : null}
                {progressNotice ? <span className="muted-copy">{progressNotice}</span> : null}
                {runMessage ? <span className="muted-copy">{runMessage}</span> : null}
                {runError ? <span className="auth-error">{runError}</span> : null}
              </div>
            </div>
          </div>
        </article>

        <article className="panel" id="report">
          <div className="panel-head">
            <p className="section-kicker">Executive report</p>
            <strong>{reportPreview?.name ?? 'Awaiting report'}</strong>
          </div>
          <div className="panel-body">
            <div className="token-wrap">
              {exportLinks.length ? (
                exportLinks.map((exportLink) => (
                  <a
                    className="token token-link"
                    href={resolveDownloadHref(exportLink.href)}
                    key={`${exportLink.label}:${exportLink.title}`}
                    target={exportLink.href.startsWith('/api/') ? '_blank' : undefined}
                    rel={exportLink.href.startsWith('/api/') ? 'noreferrer' : undefined}
                  >
                    {exportLink.label}
                  </a>
                ))
              ) : (
                <span className="muted-copy">No report exports available yet.</span>
              )}
            </div>
            {reportSummary ? (
              <div className="scope-block">
                <span className="summary-label">Render path</span>
                <div className="token-wrap">
                  <span className="token">requested {reportSummary.requested_provider || '-'}</span>
                  <span className="token">rendered {reportSummary.render_backend || reportSummary.provider || '-'}</span>
                  <span className="token">exported {reportSummary.provider || '-'}</span>
                  <span className="token">{reportSummary.format || 'unknown format'}</span>
                  {reportSummary.raw_export ? <span className="token">raw export</span> : null}
                </div>
                <div className="mini-table">
                  <div className="mini-table-row">
                    <span>Generated</span>
                    <span>{reportSummary.generated_at || '-'}</span>
                  </div>
                  <div className="mini-table-row">
                    <span>Artifact</span>
                    <span>{reportSummary.artifact_name || '-'}</span>
                  </div>
                  <div className="mini-table-row">
                    <span>Exports</span>
                    <span>{reportSummary.export_count ?? reportSummary.available_exports?.length ?? 0}</span>
                  </div>
                </div>
                {reportSummary.available_exports?.length ? (
                  <div className="token-wrap">
                    {reportSummary.available_exports.map((exportArtifact) => (
                      <span
                        className="token"
                        key={`${exportArtifact.format}:${exportArtifact.artifact_name}`}
                        title={exportArtifact.artifact_name}
                      >
                        {exportArtifact.label}
                      </span>
                    ))}
                  </div>
                ) : null}
                {reportSummary.fallback_reason ? (
                  <p className="muted-copy">Fallback reason: {reportSummary.fallback_reason}</p>
                ) : null}
                {reportSummary.report_write_error ? (
                  <p className="muted-copy">Write degradation: {reportSummary.report_write_error}</p>
                ) : null}
                {reportSummary.findings_checksum ? (
                  <div className="token-wrap">
                    <span className="mono-tag">{reportSummary.findings_checksum}</span>
                  </div>
                ) : null}
              </div>
            ) : null}
            <pre className="report-preview">{reportPreview?.preview ?? 'No report preview available yet.'}</pre>
            {priorReportHistory.length ? (
              <div className="scope-block">
                <span className="summary-label">Prior report generations</span>
                <div className="report-history-grid">
                  {priorReportHistory.map((historyEntry) => (
                    <div className="report-history-card" key={historyEntry.family_stem || historyEntry.artifact_name || historyEntry.generated_at}>
                      <strong>{historyEntry.artifact_name || 'historic report'}</strong>
                      <div className="mini-table">
                        <div className="mini-table-row">
                          <span>Generated</span>
                          <span>{historyEntry.generated_at || '-'}</span>
                        </div>
                        <div className="mini-table-row">
                          <span>Rendered</span>
                          <span>{historyEntry.render_backend || historyEntry.provider || '-'}</span>
                        </div>
                        <div className="mini-table-row">
                          <span>Exports</span>
                          <span>{historyEntry.export_count ?? historyEntry.available_exports?.length ?? 0}</span>
                        </div>
                      </div>
                      {historyEntry.available_exports?.length ? (
                        <div className="token-wrap">
                          {historyEntry.available_exports.map((exportArtifact) => {
                            const artifact = reportArtifactByName.get(exportArtifact.artifact_name)
                            if (!artifact) {
                              return (
                                <span className="token" key={`${historyEntry.artifact_name}:${exportArtifact.artifact_name}`}>
                                  {exportArtifact.label}
                                </span>
                              )
                            }
                            return (
                              <a
                                className="token token-link"
                                href={resolveDownloadHref(artifact.href)}
                                key={`${historyEntry.artifact_name}:${exportArtifact.artifact_name}`}
                                target={artifact.href.startsWith('/api/') ? '_blank' : undefined}
                                rel={artifact.href.startsWith('/api/') ? 'noreferrer' : undefined}
                              >
                                {exportArtifact.label}
                              </a>
                            )
                          })}
                        </div>
                      ) : null}
                      {historyEntry.fallback_reason ? (
                        <p className="muted-copy">Fallback reason: {historyEntry.fallback_reason}</p>
                      ) : null}
                      {historyEntry.report_write_error ? (
                        <p className="muted-copy">Write degradation: {historyEntry.report_write_error}</p>
                      ) : null}
                      {historyEntry.findings_checksum ? (
                        <div className="token-wrap">
                          <span className="mono-tag">{historyEntry.findings_checksum}</span>
                        </div>
                      ) : null}
                    </div>
                  ))}
                </div>
              </div>
            ) : null}
          </div>
        </article>

        <article className="panel" id="seeds">
          <div className="panel-head">
            <p className="section-kicker">Input seeds</p>
            <strong>{detail.primary_seed || 'No primary seed'}</strong>
          </div>
          <div className="panel-body">
            <div className="token-wrap">
              {detail.seeds.map((seed) => (
                <span className="token" key={seed}>
                  {seed}
                </span>
              ))}
            </div>
            <div className="scope-block">
              <span className="summary-label">Scope</span>
              <div className="token-wrap">
                {detail.scope.length ? detail.scope.map((entry) => <span className="token is-scope" key={entry}>{entry}</span>) : <span className="muted-copy">No explicit scope entries recorded.</span>}
              </div>
            </div>
            <div className="scope-block">
              <span className="summary-label">Seed matrix</span>
              <DataList rows={seedRows} emptyText="No persisted seed rows captured yet." />
            </div>
            <div className="scope-block">
              <span className="summary-label">Live seed controls</span>
              <div className="seed-manager">
                <div className="seed-manager-form">
                  <label className="graph-filter">
                    <span>Seed value</span>
                    <input
                      value={newSeedValue}
                      onChange={(event) => setNewSeedValue(event.target.value)}
                      placeholder="new seed"
                    />
                  </label>
                  <label className="graph-filter">
                    <span>Type override</span>
                    <select value={newSeedType} onChange={(event) => setNewSeedType(event.target.value)}>
                      <option value="">Auto-detect</option>
                      <option value="domain">domain</option>
                      <option value="email">email</option>
                      <option value="phone">phone</option>
                      <option value="username">username</option>
                      <option value="url">url</option>
                      <option value="apk_url">apk_url</option>
                      <option value="ipv4">ipv4</option>
                      <option value="other">other</option>
                    </select>
                  </label>
                  <button
                    className="token-action"
                    disabled={!liveToken || seedBusy}
                    onClick={() => void handleSeedSubmit()}
                    type="button"
                  >
                    {seedBusy ? 'Saving…' : 'Add seed'}
                  </button>
                </div>
                <div className="seed-manager-list">
                  {liveSeeds.length ? (
                    liveSeeds.map((seed) => (
                      <div className="seed-manager-row" key={seed.id}>
                        <div>
                          <strong>{seed.seed_value}</strong>
                          <span>
                            {seed.seed_type} · {seed.status} · depth {seed.depth} · conf {seed.confidence.toFixed(2)}
                          </span>
                        </div>
                        <button
                          className="token-action is-secondary"
                          disabled={!liveToken || seedBusy}
                          onClick={() => void handleSeedDelete(seed.id)}
                          type="button"
                        >
                          Remove
                        </button>
                      </div>
                    ))
                  ) : (
                    <span className="muted-copy">
                      {liveToken ? 'No live seed rows loaded.' : 'Unlock live mode to manage seeds.'}
                    </span>
                  )}
                </div>
                {seedError ? <span className="auth-error">{seedError}</span> : null}
              </div>
            </div>
          </div>
        </article>

        <article className="panel graph-panel" id="graph">
          <div className="panel-head">
            <p className="section-kicker">Maltego graph</p>
            <strong>{detail.graph_summary?.source ?? 'Graph placeholder'}</strong>
          </div>
          <div className="panel-body">
            <GraphExplorer detail={detail} />
          </div>
        </article>

        <article className="panel" id="findings">
          <div className="panel-head">
            <p className="section-kicker">Validated findings</p>
            <strong>{formatCount(findingRows.length + keyFindingRows.length + cloudValidationRows.length)}</strong>
          </div>
          <div className="panel-body findings-stack">
            <DataList rows={keyFindingRows} emptyText="No key exposure rows captured yet." />
            <DataList rows={cloudValidationRows} emptyText="No cloud validation rows captured yet." />
            <DataList rows={findingRows} emptyText="No validated finding rows captured yet." />
          </div>
        </article>

        <article className="panel">
          <div className="panel-head">
            <p className="section-kicker">Discovered hosts</p>
            <strong>{formatCount(hostRows.length)}</strong>
          </div>
          <div className="panel-body table-shell">
            <DataList rows={hostRows} emptyText="No host rows captured yet." />
          </div>
        </article>

        <article className="panel">
          <div className="panel-head">
            <p className="section-kicker">Discovered emails</p>
            <strong>{formatCount(emailRows.length)}</strong>
          </div>
          <div className="panel-body table-shell">
            <DataList rows={emailRows} emptyText="No email rows captured yet." />
          </div>
        </article>

        <article className="panel">
          <div className="panel-head">
            <p className="section-kicker">Artifacts</p>
            <strong>{detail.size_label}</strong>
          </div>
          <div className="panel-body artifact-stack">
            {detail.artifacts.map((artifact) => (
              <div className="artifact-card" key={`${artifact.kind}:${artifact.name}`}>
                <span className="artifact-type">{artifact.kind}</span>
                <strong>
                  <a className="artifact-link" href={resolveDownloadHref(artifact.href)}>
                    {artifact.name}
                  </a>
                </strong>
                <p>{artifact.size_label}</p>
                <p>{artifact.modified_at}</p>
              </div>
            ))}
          </div>
        </article>
      </section>

      {evidenceSections.length ? (
        <section className="panel" id="evidence">
          <div className="panel-head">
            <p className="section-kicker">Evidence boards</p>
            <strong>{formatCount(evidenceSections.length)} sections</strong>
          </div>
          <div className="panel-body evidence-grid">
            {evidenceSections.map(([sectionKey, rows]) => (
              <SectionPanel
                key={sectionKey}
                title={SECTION_TITLES[sectionKey] ?? sectionKey}
                rows={rows}
              />
            ))}
          </div>
        </section>
      ) : null}

      <section className="panel" id="audit">
        <div className="panel-head">
          <p className="section-kicker">Audit timeline</p>
          <strong>{formatCount(auditRows.length)} events</strong>
        </div>
        <div className="panel-body timeline-stack">
          {auditRows.length ? (
            auditRows.map((row, index) => (
              <article className="timeline-item" key={`${row.When ?? 'unknown'}-${index}`}>
                <span className="timeline-time">{row.When ?? '-'}</span>
                <div>
                  <strong>{row.Action ?? 'event'}</strong>
                  <p>{row.Phase ?? ''} · {row.Module ?? ''}</p>
                  <p>{row.Target ?? ''}</p>
                  <p>{row.Result ?? ''}</p>
                </div>
              </article>
            ))
          ) : (
            <div className="notice">No audit timeline rows captured yet.</div>
          )}
        </div>
      </section>

      <section className="panel" id="raw-data">
        <div className="panel-head">
          <p className="section-kicker">Raw data</p>
          <strong>{detail.slug}</strong>
        </div>
        <div className="panel-body">
          <pre className="report-preview">{rawDataPreview(detail)}</pre>
        </div>
      </section>
    </main>
  )
}

function GraphExplorer({ detail }: { detail: EngagementDetail }) {
  const graph = normalizeGraph(detail)
  const [query, setQuery] = useState('')
  const [typeFilter, setTypeFilter] = useState('ALL')
  const [severityFilter, setSeverityFilter] = useState('ALL')
  const [criticalOnly, setCriticalOnly] = useState(false)
  const deferredQuery = useDeferredValue(query).trim().toLowerCase()

  const filteredNodes = graph.nodes.filter((node) => {
    if (typeFilter !== 'ALL' && node.type !== typeFilter) {
      return false
    }
    if (severityFilter !== 'ALL' && node.severity !== severityFilter) {
      return false
    }
    if (criticalOnly && !node.critical) {
      return false
    }
    if (!deferredQuery) {
      return true
    }
    return [node.label, node.id, node.type, node.severity].join(' ').toLowerCase().includes(deferredQuery)
  })
  const visibleNodeIds = new Set(filteredNodes.map((node) => node.id))
  const filteredEdges = graph.edges.filter(
    (edge) => visibleNodeIds.has(edge.source) && visibleNodeIds.has(edge.target),
  )
  const [selectedNodeId, setSelectedNodeId] = useState(filteredNodes[0]?.id ?? '')

  useEffect(() => {
    if (!filteredNodes.length) {
      setSelectedNodeId('')
      return
    }
    if (!visibleNodeIds.has(selectedNodeId)) {
      setSelectedNodeId(filteredNodes[0]?.id ?? '')
    }
  }, [filteredNodes, selectedNodeId, visibleNodeIds])

  if (!graph.nodes.length) {
    return (
      <>
        <div className="graph-stage">
          {graphNodeLabels(detail).map((node) => (
            <div className="graph-node" key={node}>
              {node}
            </div>
          ))}
        </div>
        <div className="graph-metrics">
          <span>{formatCount(detail.graph_summary?.nodes)} nodes</span>
          <span>{formatCount(detail.graph_summary?.edges)} edges</span>
          <span>{formatCount(detail.graph_summary?.critical_nodes)} critical nodes</span>
        </div>
        {detail.graph_snapshot_at ? <p className="muted-copy">Snapshot {detail.graph_snapshot_at}</p> : null}
      </>
    )
  }

  const layout = layoutGraph(filteredNodes)
  const selectedNode =
    filteredNodes.find((node) => node.id === selectedNodeId) ??
    filteredNodes[0] ??
    null
  const selectedEdges = selectedNode
    ? filteredEdges.filter((edge) => edge.source === selectedNode.id || edge.target === selectedNode.id)
    : []
  const connectedNodes = selectedNode
    ? selectedEdges
        .map((edge) => graph.nodes.find((node) => node.id === (edge.source === selectedNode.id ? edge.target : edge.source)))
        .filter((node): node is GraphExplorerNode => Boolean(node))
    : []
  const selectedEdgeRows = selectedEdges.map((edge) => ({
    Connection: `${edge.source} -> ${edge.target}`,
    Type: edge.label || edge.type,
    Weight: String(edge.weight),
    Critical: edge.critical ? 'yes' : 'no',
    Evidence:
      metadataEntries(edge.metadata)
        .map(([key, value]) => `${key}: ${value}`)
        .join(' · ') || '-',
  }))

  return (
    <>
      <div className="graph-toolbar">
        <label className="graph-filter">
          <span>Search</span>
          <input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Node label, ID, type, severity"
            type="search"
          />
        </label>
        <label className="graph-filter">
          <span>Type</span>
          <select value={typeFilter} onChange={(event) => setTypeFilter(event.target.value)}>
            <option value="ALL">All types</option>
            {graph.nodeTypes.sort().map((type) => (
              <option key={type} value={type}>
                {type}
              </option>
            ))}
          </select>
        </label>
        <label className="graph-filter">
          <span>Severity</span>
          <select value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value)}>
            <option value="ALL">All severities</option>
            {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map((severity) => (
              <option key={severity} value={severity}>
                {severity}
              </option>
            ))}
          </select>
        </label>
        <label className="graph-toggle">
          <input
            checked={criticalOnly}
            onChange={(event) => setCriticalOnly(event.target.checked)}
            type="checkbox"
          />
          <span>Critical path only</span>
        </label>
      </div>

      <div className="graph-metrics">
        <span>{formatCount(filteredNodes.length)} visible nodes</span>
        <span>{formatCount(filteredEdges.length)} visible edges</span>
        <span>{formatCount(graph.nodes.filter((node) => node.critical).length)} path nodes</span>
        {detail.graph_snapshot_at ? <span>Snapshot {detail.graph_snapshot_at}</span> : null}
      </div>

      <div className="graph-explorer">
        <div
          className="graph-stage graph-stage--interactive"
          style={{ minHeight: `${layout.height}px`, minWidth: `${layout.width}px` }}
        >
          <svg
            aria-hidden="true"
            className="graph-edges"
            viewBox={`0 0 ${layout.width} ${layout.height}`}
          >
            {filteredEdges.map((edge) => {
              const source = layout.positions.get(edge.source)
              const target = layout.positions.get(edge.target)
              if (!source || !target) {
                return null
              }
              return (
                <line
                  className={edge.critical ? 'is-critical-path' : ''}
                  key={edge.id}
                  x1={source.x}
                  x2={target.x}
                  y1={source.y}
                  y2={target.y}
                />
              )
            })}
          </svg>

          {layout.columns.map((column, columnIndex) => (
            <div
              className="graph-column-label"
              key={column}
              style={{ left: `${50 + columnIndex * 190}px` }}
            >
              {column}
            </div>
          ))}

          {filteredNodes.map((node) => {
            const position = layout.positions.get(node.id)
            if (!position) {
              return null
            }
            const selected = node.id === selectedNode?.id
            return (
              <button
                className={[
                  'graph-node-card',
                  selected ? 'is-selected' : '',
                  node.critical ? 'is-critical-path' : '',
                ]
                  .filter(Boolean)
                  .join(' ')}
                key={node.id}
                onClick={() => setSelectedNodeId(node.id)}
                style={{ left: `${position.x - 72}px`, top: `${position.y - 32}px` }}
                type="button"
              >
                <strong>{node.label}</strong>
                <span>{node.type}</span>
                <span>{node.severity}</span>
              </button>
            )
          })}
        </div>

        <aside className="graph-inspector">
          {selectedNode ? (
            <>
              <div className="panel-head">
                <p className="section-kicker">Node inspector</p>
                <strong>{selectedNode.type}</strong>
              </div>
              <div className="panel-body inspector-body">
                <h3>{selectedNode.label}</h3>
                <div className="token-wrap">
                  <span className={`severity-pill ${severityTone(selectedNode.severity)}`}>
                    {selectedNode.severity}
                  </span>
                  <span className={`severity-pill ${selectedNode.critical ? 'is-high' : 'is-info'}`}>
                    {selectedNode.critical ? 'CRITICAL PATH' : 'OBSERVED'}
                  </span>
                </div>
                <div className="mini-table">
                  <div className="mini-table-row">
                    <span>ID</span>
                    <span>{selectedNode.id}</span>
                  </div>
                  <div className="mini-table-row">
                    <span>Source</span>
                    <span>{selectedNode.sourceTable}</span>
                  </div>
                  <div className="mini-table-row">
                    <span>Source row</span>
                    <span>{selectedNode.sourceId}</span>
                  </div>
                  <div className="mini-table-row">
                    <span>Connections</span>
                    <span>{formatCount(selectedNode.degree)}</span>
                  </div>
                </div>

                <div className="scope-block">
                  <span className="summary-label">Connected nodes</span>
                  <div className="token-wrap">
                    {connectedNodes.length ? (
                      connectedNodes.map((node) => (
                        <button
                          className="token token-button"
                          key={node.id}
                          onClick={() => setSelectedNodeId(node.id)}
                          type="button"
                        >
                          {node.label}
                        </button>
                      ))
                    ) : (
                      <span className="muted-copy">No connected nodes match the current filter set.</span>
                    )}
                  </div>
                </div>

                <div className="scope-block">
                  <span className="summary-label">Edge evidence</span>
                  <DataList rows={selectedEdgeRows} emptyText="No edge metadata captured for this node." />
                </div>

                <div className="scope-block">
                  <span className="summary-label">Metadata</span>
                  {metadataEntries(selectedNode.metadata).length ? (
                    <div className="mini-table">
                      {metadataEntries(selectedNode.metadata).map(([key, value]) => (
                        <div className="mini-table-row" key={key}>
                          <span>{key}</span>
                          <span>{value}</span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <span className="muted-copy">No non-sensitive metadata captured for this node.</span>
                  )}
                </div>
              </div>
            </>
          ) : (
            <div className="panel-body">
              <div className="notice">No graph nodes match the current filters.</div>
            </div>
          )}
        </aside>
      </div>
    </>
  )
}

function SectionPanel({ title, rows }: { title: string; rows: SectionRow[] }) {
  return (
    <article className="subpanel">
      <div className="panel-head">
        <p className="section-kicker">{title}</p>
        <strong>{formatCount(rows.length)}</strong>
      </div>
      <div className="panel-body table-shell">
        <DataList rows={rows} emptyText={`No ${title.toLowerCase()} rows captured yet.`} />
      </div>
    </article>
  )
}

function DataList({ rows, emptyText }: { rows: SectionRow[]; emptyText: string }) {
  if (!rows.length) {
    return <div className="muted-copy">{emptyText}</div>
  }

  const headers = Object.keys(rows[0])
  return (
    <div className="mini-table">
      <div className="mini-table-head">
        {headers.map((header) => (
          <span key={header}>{header}</span>
        ))}
      </div>
      {rows.map((row, rowIndex) => (
        <div className="mini-table-row" key={rowIndex}>
          {headers.map((header) => (
            <span key={`${rowIndex}-${header}`}>{row[header] || '-'}</span>
          ))}
        </div>
      ))}
    </div>
  )
}

function NotFoundState() {
  return (
    <main className="not-found">
      <h2>Unknown engagement route</h2>
      <p>The requested slug is not present in the generated dashboard payload.</p>
      <Link className="back-link" to="/">
        Return to dashboard
      </Link>
    </main>
  )
}

export default App
