import { startTransition, useDeferredValue, useEffect, useMemo, useState } from 'react'
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
  rendered_provider?: string
  upstream_provider?: string
  format?: string
  generated_at?: string
  fallback_reason?: string
  report_write_error?: string
  findings_checksum?: string
  raw_export?: boolean
  export_count?: number
  available_exports?: ReportExportArtifact[]
  cloud_validation_inventory_count?: number
  cloud_asset_inventory_count?: number
  reportable_validation_count?: number
  unreportable_validation_count?: number
  validation_status_summary?: Record<string, number>
}

type SectionRow = Record<string, string>

type OperationalTimelineEvent = {
  id: string
  category: string
  time: string
  title: string
  summary: string
  method?: string
  provenance?: string
  reportability?: string
  status?: string
  severity?: string
}

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

type AssetGraphConflictOwner = {
  owner_kind?: string
  owner_ref: string
  owner_display?: string
  confidence?: number
  claim_type?: string
  source?: string
}

type AssetGraphOwnershipConflict = {
  entity_id?: number
  entity_key: string
  entity_label?: string
  entity_type?: string
  owner_count?: number
  claim_count?: number
  owners: AssetGraphConflictOwner[]
  highest_confidence?: number
}

type GraphPayload = {
  nodes?: GraphNode[]
  edges?: GraphEdge[]
  ownership_conflicts?: AssetGraphOwnershipConflict[]
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
  workspace_id?: string
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
  report_summary?: ReportSummary
  report_count: number
  graph_count: number
  audit_count?: number
  report_family_count?: number
  latest_report_family?: string
  latest_report_export_count?: number
  has_prior_report_generations?: boolean
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

const REMEDIATION_STATUSES = [
  'open',
  'assigned',
  'in_progress',
  'risk_accepted',
  'retest_pending',
  'resolved',
  'false_positive',
] as const

const REMEDIATION_RETEST_STATUSES = [
  'not_requested',
  'pending',
  'passed',
  'failed',
  'blocked',
] as const

type RemediationStatus = (typeof REMEDIATION_STATUSES)[number]

type RemediationRetestStatus = (typeof REMEDIATION_RETEST_STATUSES)[number]

type RemediationItem = {
  id: number
  engagement_id: number
  finding_table: string
  finding_id: number | null
  finding_ref: string
  title: string
  severity: string
  owner: string
  sla_due_at: string
  status: string
  risk_acceptance_reason: string
  risk_accepted_by: string
  risk_accepted_at: string
  risk_acceptance_expires_at: string
  risk_acceptance_review_status: string
  risk_acceptance_review_due: boolean
  retest_status: string
  retest_requested_at: string
  retested_at: string
  ticket_system: string
  ticket_ref: string
  ticket_url: string
  owner_approval?: {
    decision?: string
    owner?: string
    reviewed_by?: string
    reviewed_at?: string
    note?: string
  }
  metadata?: Record<string, unknown>
  created_at: string
  updated_at: string
}

type RemediationReviewQueueItem = {
  id: number
  engagement_id: number
  finding_table: string
  finding_ref: string
  title: string
  severity: string
  owner: string
  sla_due_at: string
  status: string
  risk_acceptance_expires_at: string
  risk_acceptance_review_status: string
  retest_status: string
  ticket_label: string
  latest_ticket_event?: {
    connector?: string
    destination?: string
    action?: string
    status?: string
    attempt_count?: number
    last_error?: string
    delivered_at?: string
    updated_at?: string
  } | null
  queue_reasons: string[]
  queue_reason_labels: string[]
  review_priority: number
  updated_at: string
}

type RemediationReviewQueue = {
  engagement_id: number
  generated_at: string
  summary: Record<string, number>
  items: RemediationReviewQueueItem[]
  returned_count: number
  truncated: boolean
}

type RemediationOverview = {
  items: RemediationItem[]
  summary: Record<string, number>
  review_queue?: RemediationReviewQueue
}

type RemediationUpdatePayload = {
  itemId: number
  owner: string
  status: RemediationStatus
  retestStatus: RemediationRetestStatus
  slaDueAt: string
  riskAcceptanceReason?: string
  riskAcceptanceExpiresAt?: string
  ticketSystem: string
  ticketRef: string
  ticketUrl: string
}

type RemediationSyncResult = {
  sync_count?: number
  synced_count?: number
  failure_count?: number
  failures?: Record<string, unknown>[]
  results?: Record<string, unknown>[]
}

type RemediationTicketSyncPayload = {
  force?: boolean
  webhookUrl?: string
  githubRepo?: string
  githubTokenEnv?: string
  githubApiUrl?: string
  jiraBaseUrl?: string
  jiraProjectKey?: string
  jiraIssueType?: string
  jiraEmailEnv?: string
  jiraTokenEnv?: string
  servicenowInstanceUrl?: string
  servicenowTable?: string
  servicenowUsernameEnv?: string
  servicenowPasswordEnv?: string
  servicenowTokenEnv?: string
  tinesWebhookUrl?: string
  tinesTokenEnv?: string
  splunkHecUrl?: string
  splunkHecTokenEnv?: string
  splunkIndex?: string
  splunkSource?: string
  splunkSourcetype?: string
  torqWebhookUrl?: string
  torqTokenEnv?: string
}

const DEFAULT_REMEDIATION_TICKET_SYNC: RemediationTicketSyncPayload = {
  force: true,
  githubTokenEnv: 'FORGE_GITHUB_TOKEN',
  githubApiUrl: 'https://api.github.com',
  jiraIssueType: 'Task',
  jiraEmailEnv: 'FORGE_JIRA_EMAIL',
  jiraTokenEnv: 'FORGE_JIRA_API_TOKEN',
  servicenowTable: 'incident',
  servicenowUsernameEnv: 'FORGE_SERVICENOW_USERNAME',
  servicenowPasswordEnv: 'FORGE_SERVICENOW_PASSWORD',
  tinesTokenEnv: 'FORGE_TINES_WEBHOOK_TOKEN',
  splunkHecTokenEnv: 'FORGE_SPLUNK_HEC_TOKEN',
  splunkSource: 'forge',
  splunkSourcetype: 'forge:remediation:ticket',
  torqTokenEnv: 'FORGE_TORQ_WEBHOOK_TOKEN',
}

type RemediationPropagationResult = RemediationOverview & {
  status: string
  assigned_count?: number
  unresolved_count?: number
  skipped_existing_owner_count?: number
  skipped_terminal_count?: number
  skipped_conflict_count?: number
  skipped_low_confidence_count?: number
  conflict_policy?: string
  min_confidence?: number
}

type RemediationGraphDraftResult = RemediationOverview & {
  status: string
  candidate_count?: number
  drafted_count?: number
}

type RemediationOwnerReviewResult = RemediationOverview & {
  status: string
  decision: string
  item: RemediationItem
}

type AssetGraphConflictResolutionResult = {
  status: string
  selected_owner?: string
  selected_claim_id?: number
  superseded_claim_ids?: number[]
  asset_graph?: GraphPayload
}

type RetentionPolicy = {
  id?: number | null
  engagement_id?: number
  name: string
  enabled: boolean
  audit_review_days: number | null
  monitoring_days: number | null
  remediation_event_days: number | null
  retention_run_days: number | null
  legal_hold_override: boolean
  metadata?: Record<string, unknown>
  created_at?: string
  updated_at?: string
}

type RetentionRunItem = {
  engagement_id?: number
  category: string
  table_name: string
  retention_days: number | null
  cutoff_at: string
  eligible_count: number
  deleted_count: number
  skipped_count: number
  reason: string
  created_at?: string
}

type RetentionRun = {
  id: number
  engagement_id?: number
  policy_id?: number | null
  policy_name: string
  mode: string
  status: string
  operator: string
  summary?: Record<string, unknown>
  items?: RetentionRunItem[]
  created_at: string
}

type RetentionOverview = {
  schema?: string
  engagement_id?: number
  policy: RetentionPolicy
  legal_hold: boolean
  runs: RetentionRun[]
  summary?: Record<string, unknown>
}

type RetentionRunResult = {
  schema?: string
  mode: string
  status: string
  engagement_id?: number
  policy?: RetentionPolicy
  legal_hold?: boolean
  summary?: Record<string, unknown>
  items?: RetentionRunItem[]
  retention_run_id?: number | null
}

type ConnectorSecret = {
  id: number
  engagement_id: number
  connector_id: string
  secret_name: string
  secret_ref: string
  key_hint: string
  metadata?: Record<string, unknown>
  created_by: string
  updated_by: string
  created_at: string
  updated_at: string
  secret_material_policy: string
}

type ConnectorSecretsSummary = {
  count: number
  connectors: string[]
  secret_material_policy: string
}

type ConnectorSecretsOverview = {
  items: ConnectorSecret[]
  summary: ConnectorSecretsSummary
}

type WorkspaceAuditEvent = {
  id: number
  event_type: string
  workspace_id: string
  actor_subject: string
  subject: string
  source: string
  payload: Record<string, unknown>
  previous_hash: string
  event_hash: string
  created_at: string
}

type WorkspaceAuditOverview = {
  workspace_id: string
  items: WorkspaceAuditEvent[]
}

type WorkspaceRecord = {
  workspace_id: string
  name: string
  metadata: Record<string, unknown>
  member_count: number
  engagement_count: number
  created_at: string
  updated_at: string
}

type WorkspaceIndex = {
  generated_at: string
  items: WorkspaceRecord[]
}

type WorkspaceMember = {
  workspace_id: string
  subject: string
  role: string
  permissions: string[]
  created_at: string
  updated_at: string
}

type WorkspaceMembersOverview = {
  workspace_id: string
  items: WorkspaceMember[]
}

type WorkspaceUpsertPayload = {
  workspaceId: string
  name: string
  metadata: Record<string, unknown>
}

type WorkspaceMemberUpsertPayload = {
  workspaceId: string
  subject: string
  role: string
  permissions?: string[]
}

type ConnectorCatalogItem = {
  id: string
  label: string
  domain: string
  cost_profile: string
  safety: string
  description: string
  capabilities: string[]
  outputs: string[]
  input_formats: string[]
  local_binaries: string[]
  missing_binaries: string[]
  env_options: string[][]
  env_configured: boolean
  secret_store_configured: boolean
  secret_store_readiness: string
  stored_secret_names: string[]
  stored_secret_statuses: { name: string; status: string }[]
  required_gates: string[]
  implementation_status: string
  readiness: string
  source?: string
  execution_status?: string
  runner_supported?: boolean
  manifest_path?: string
}

const EMPTY_CONNECTOR_CATALOG: ConnectorCatalogItem[] = []

type ConnectorCatalogSummary = {
  connector_count: number
  free_first_count: number
  optional_paid_count: number
  configured_count: number
  cost_profiles: Record<string, number>
  readiness: Record<string, number>
  domains: Record<string, number>
  sources?: Record<string, number>
  execution?: Record<string, number>
  plugin_manifest_count?: number
  active_validation_plugin_manifest_count?: number
  runner_supported_count?: number
  plugin_manifest_catalog_count?: number
  engagement_id?: number
  secret_store_connector_count?: number
  secret_material_policy: string
}

type ConnectorCatalogOverview = {
  connectors: ConnectorCatalogItem[]
  summary: ConnectorCatalogSummary
}

type ConnectorSecretStorePayload = {
  connectorId: string
  secretName: string
  secretValue: string
  secretRef: string
  owner: string
}

type ConnectorSecretStoreResult = {
  status: string
  item: ConnectorSecret
  summary: ConnectorSecretsSummary
}

const ACTIVE_VALIDATION_MODES = ['dry_run', 'lab', 'read_only_live'] as const
const ACTIVE_VALIDATION_TARGET_KINDS = [
  'asset',
  'host',
  'service',
  'cloud',
  'identity',
  'finding',
  'remediation',
  'fixture',
  'other',
] as const
const ACTIVE_VALIDATION_METHOD_IDS = [
  'fixture_replay',
  'control_simulation',
  'http_reachability',
  'http_security_headers',
  'fix_verification',
] as const

type ActiveValidationMode = (typeof ACTIVE_VALIDATION_MODES)[number]

type ActiveValidationTargetKind = (typeof ACTIVE_VALIDATION_TARGET_KINDS)[number]

type ActiveValidationMethodId = (typeof ACTIVE_VALIDATION_METHOD_IDS)[number]

type ActiveValidationMethod = {
  id: string
  label: string
  category: string
  description: string
  supported_modes: string[]
  implemented_modes: string[]
  safety_profile: string
  proof_kind: string
  implementation_status: string
  attack_mappings: string[]
  control_families: string[]
  required_gates: string[]
  free_local_dependencies?: string[]
}

type ActiveValidationJob = {
  id: number
  engagement_id: number
  target_ref: string
  target_kind: string
  method: string
  method_config?: ActiveValidationMethod
  mode: string
  status: string
  approved: boolean
  roe_id: string
  scope_manifest_ref: string
  scope_manifest_hash: string
  safe_profile: string
  max_steps: number
  requested_by: string
  approved_by: string
  approval_note: string
  metadata?: Record<string, unknown>
  created_at: string
  approved_at: string
  updated_at: string
}

type ActiveValidationRun = {
  id: number
  engagement_id: number
  job_id: number
  status: string
  result: string
  operator: string
  evidence?: Record<string, unknown>
  error: string
  started_at: string
  completed_at: string
  created_at: string
  job?: ActiveValidationJob
}

type ActiveValidationCoverageStates = Record<string, number>

type ActiveValidationCoverageBucket = {
  id: string
  label: string
  job_count: number
  run_count: number
  states: ActiveValidationCoverageStates
  methods?: string[]
  latest_job_ids?: number[]
  category?: string
  implementation_status?: string
}

type ActiveValidationCoverage = {
  schema: string
  engagement_id: number
  summary: {
    job_count: number
    run_count: number
    mapped_job_count: number
    attack_mapping_count: number
    control_family_count: number
    states: ActiveValidationCoverageStates
    method_count: number
  }
  attack_mappings: ActiveValidationCoverageBucket[]
  control_families: ActiveValidationCoverageBucket[]
  methods: ActiveValidationCoverageBucket[]
}

type ActiveValidationGraphScenario = {
  title: string
  target_ref: string
  target_kind: string
  method: string
  mode: string
  safe_profile: string
  max_steps: number
  approved: boolean
  approval_required: boolean
  network_execution: boolean
  expected_result: string
  reason: string
  risk_tags: string[]
  metadata?: Record<string, unknown>
}

type ActiveValidationSnapshot = {
  engagement_id: number
  jobs: ActiveValidationJob[]
  runs: ActiveValidationRun[]
  methods: ActiveValidationMethod[]
  coverage?: ActiveValidationCoverage
  graph_scenarios?: ActiveValidationGraphScenario[]
  summary: {
    job_count: number
    run_count: number
    graph_scenario_count?: number
    blocked_run_count: number
    completed_run_count: number
    coverage_states?: ActiveValidationCoverageStates
    attack_mapping_count?: number
    control_family_count?: number
  }
}

type ActiveValidationCreatePayload = {
  targetRef: string
  targetKind: ActiveValidationTargetKind
  method: ActiveValidationMethodId | string
  mode: ActiveValidationMode
  roeId: string
  scopeManifest: string
  maxSteps: number
  metadata?: Record<string, unknown>
}

type ActiveValidationApprovalPayload = {
  jobId: number
  roeId: string
  scopeManifest: string
  approvalNote: string
}

type RemediationRetestRequestPayload = {
  itemId: number
  targetRef: string
  targetKind: ActiveValidationTargetKind | string
  method: ActiveValidationMethodId | string
  mode: ActiveValidationMode
  approve: boolean
  roeId: string
  scopeManifest: string
  approvalNote: string
  expectedResult: string
}

type RemediationRetestRequestResult = {
  status: string
  remediation_item: RemediationItem
  active_validation_job: ActiveValidationJob
}

const FALLBACK_ACTIVE_VALIDATION_METHODS: ActiveValidationMethod[] = [
  {
    id: 'fixture_replay',
    label: 'Fixture Replay',
    category: 'lab_replay',
    description: 'Replay stored proof-pack fixtures without touching a live target.',
    supported_modes: ['dry_run', 'lab'],
    implemented_modes: ['dry_run', 'lab'],
    safety_profile: 'non_destructive',
    proof_kind: 'fixture_evidence',
    implementation_status: 'implemented_offline',
    attack_mappings: ['TA0043', 'TA0007'],
    control_families: ['BAS fixture replay', 'NIST CSF DE.CM'],
    required_gates: ['offline_fixture'],
  },
  {
    id: 'control_simulation',
    label: 'Control Simulation',
    category: 'control_validation',
    description: 'Simulate a detection/control outcome against local fixture evidence.',
    supported_modes: ['dry_run', 'lab'],
    implemented_modes: ['dry_run', 'lab'],
    safety_profile: 'non_destructive',
    proof_kind: 'control_simulation',
    implementation_status: 'implemented_offline',
    attack_mappings: ['TA0005', 'TA0007'],
    control_families: ['MITRE ATT&CK control coverage', 'NIST CSF DE.CM'],
    required_gates: ['offline_fixture'],
  },
  {
    id: 'http_reachability',
    label: 'HTTP Reachability',
    category: 'read_only_probe',
    description: 'Plan or validate whether an approved HTTP endpoint is reachable.',
    supported_modes: ['dry_run', 'lab', 'read_only_live'],
    implemented_modes: ['dry_run', 'lab', 'read_only_live'],
    safety_profile: 'non_destructive',
    proof_kind: 'reachability_observation',
    implementation_status: 'implemented_read_only_live',
    attack_mappings: ['TA0043', 'TA0001'],
    control_families: ['ASM exposure validation', 'NIST CSF ID.AM'],
    required_gates: ['approval', 'roe_id', 'scope_manifest', 'live_gate'],
    free_local_dependencies: ['curl', 'python_http_client'],
  },
  {
    id: 'http_security_headers',
    label: 'HTTP Security Headers',
    category: 'read_only_probe',
    description: 'Observe security-relevant HTTP response headers on an approved endpoint without capturing a response body.',
    supported_modes: ['dry_run', 'lab', 'read_only_live'],
    implemented_modes: ['dry_run', 'lab', 'read_only_live'],
    safety_profile: 'non_destructive',
    proof_kind: 'security_header_observation',
    implementation_status: 'implemented_read_only_live',
    attack_mappings: ['TA0043', 'TA0001'],
    control_families: ['HTTP security headers', 'OWASP Secure Headers', 'NIST CSF PR.PT'],
    required_gates: ['approval', 'roe_id', 'scope_manifest', 'live_gate'],
    free_local_dependencies: ['curl', 'python_http_client'],
  },
  {
    id: 'fix_verification',
    label: 'Fix Verification',
    category: 'retest',
    description:
      'Replay a previous safe proof plan, fixture, or approved read-only retest after remediation.',
    supported_modes: ['dry_run', 'lab', 'read_only_live'],
    implemented_modes: ['dry_run', 'lab', 'read_only_live'],
    safety_profile: 'non_destructive',
    proof_kind: 'retest_evidence',
    implementation_status: 'implemented_read_only_live',
    attack_mappings: ['TA0043', 'TA0001'],
    control_families: ['Remediation retest', 'NIST CSF RS.MI'],
    required_gates: ['approval', 'roe_id', 'scope_manifest', 'live_gate'],
    free_local_dependencies: ['curl', 'python_http_client'],
  },
]

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
      secret_lifecycle_items: 1,
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
      cloud_validation_inventory_count: 2,
      cloud_asset_inventory_count: 2,
      reportable_validation_count: 1,
      unreportable_validation_count: 1,
      validation_status_summary: { VALIDATED: 1, UNVERIFIED: 1 },
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
      secret_lifecycle_items: [
        {
          Key: '42',
          Service: 'github',
          Pattern: 'github_pat',
          Lifecycle: 'owner_routed',
          Owner: 'appsec@example.com',
          'Owner Source': 'validation_claims',
          Suppressed: 'no',
          Suppression: '-',
          Remediation: '#7 assigned',
          Source: 'https://github.com/acme/mobile/blob/main/config.js',
          Repository: 'acme/mobile',
          Guidance: 'Revoke the exposed token, rotate dependent deployments, and rerun Forge validation.',
          Prevention: 'gitleaks:pre-commit (free/local), trufflehog:pr (free/local)',
          Meta: 'key_redacted, repo_name, source_backend, validation_state',
          Updated: '2026-07-09 09:31:12',
        },
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
    name: 'FORGE Operator Identity Mapping',
    status: 'stabilized',
    operator: 'delta-one',
    tags: ['identity', 'executive', 'apac'],
    created_at: '2026-07-09 09:02:07',
    updated_at: '2026-07-09 09:43:28',
    latest_audit: '2026-07-09 09:43:28',
    primary_seed: 'user@company.com',
    seeds: ['user@company.com', '@operator'],
    counts: {
      hosts: 2,
      emails: 4,
      services: 1,
      crawl_results: 6,
      key_scanner_findings: 0,
      secret_lifecycle_items: 0,
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
    scope: ['user@company.com', '@operator'],
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
      cloud_validation_inventory_count: 1,
      cloud_asset_inventory_count: 1,
      reportable_validation_count: 0,
      unreportable_validation_count: 1,
      validation_status_summary: { UNVERIFIED: 1 },
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
        { node_id: 'EMAIL::gmail', node_type: 'CREDENTIAL', label: 'user@company.com', severity: 'LOW', source_table: 'engagement_seeds', source_id: 1, on_critical_path: true, metadata: { source: 'seed' } },
        { node_id: 'USERNAME::handle', node_type: 'EXTERNAL', label: '@operator', severity: 'LOW', source_table: 'engagement_seeds', source_id: 2, metadata: { source: 'seed' } },
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
        { Email: 'user@company.com', Domain: 'gmail.com', Source: 'seed', Seen: '2026-07-09 09:02:07' },
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
          Target: '@operator',
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
    report_summary: item.report_summary,
    report_count: item.report_count,
    graph_count: item.graph_count,
    audit_count: item.audit_count,
    report_family_count: item.report_family_count,
    latest_report_family: item.latest_report_family,
    latest_report_export_count: item.latest_report_export_count,
    has_prior_report_generations: item.has_prior_report_generations,
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
  distributed_tasks: 'Distributed tasks',
  email_intelligence: 'Email intelligence',
  services: 'Services',
  key_scanner_findings: 'Key findings',
  secret_lifecycle_items: 'Secret lifecycle',
  cloud_validation_results: 'Cloud validation',
  passive_vulns: 'Passive findings',
  vulnerability_findings: 'Validated findings',
  crawl_results: 'Web mining',
  social_profiles: 'Identity mapping',
  artifact_queue: 'Artifact queue',
  auth_test_results: 'Auth validation',
  active_validation_jobs: 'Active validation jobs',
  active_validation_runs: 'Active validation runs',
  active_validation_coverage: 'Active Validation Coverage',
  remediation_items: 'Remediation workflow',
  remediation_review_queue: 'Remediation Review Queue',
  retention_policies: 'Retention Policies',
  retention_runs: 'Retention Runs',
  retention_run_items: 'Retention Run Items',
  scope_denials: 'Scheduled scope denials',
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

function apiJsonHeaders(token: string | null | undefined): HeadersInit {
  return token
    ? { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }
    : { 'Content-Type': 'application/json' }
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

async function loadWorkspaces(token: string): Promise<WorkspaceIndex> {
  return await fetchJson<WorkspaceIndex>('/api/workspaces', {
    headers: apiHeaders(token),
  })
}

async function loadWorkspaceMembers(
  workspaceId: string,
  token: string,
): Promise<WorkspaceMembersOverview> {
  return await fetchJson<WorkspaceMembersOverview>(
    `/api/workspaces/${encodeURIComponent(workspaceId || 'default')}/members`,
    {
      headers: apiHeaders(token),
    },
  )
}

async function requestWorkspaceUpsert(
  token: string,
  payload: WorkspaceUpsertPayload,
): Promise<{ status: string; item: WorkspaceRecord }> {
  return await fetchJson<{ status: string; item: WorkspaceRecord }>('/api/workspaces', {
    body: JSON.stringify({
      workspace_id: payload.workspaceId,
      name: payload.name,
      metadata: payload.metadata,
    }),
    headers: apiJsonHeaders(token),
    method: 'POST',
  })
}

async function requestWorkspaceMemberUpsert(
  token: string,
  payload: WorkspaceMemberUpsertPayload,
): Promise<{ status: string; item: WorkspaceMember | null }> {
  return await fetchJson<{ status: string; item: WorkspaceMember | null }>(
    `/api/workspaces/${encodeURIComponent(payload.workspaceId || 'default')}/members/${encodeURIComponent(
      payload.subject,
    )}`,
    {
      body: JSON.stringify({
        role: payload.role,
        ...(payload.permissions?.length ? { permissions: payload.permissions } : {}),
      }),
      headers: apiJsonHeaders(token),
      method: 'PUT',
    },
  )
}

async function requestWorkspaceMemberDelete(
  token: string,
  workspaceId: string,
  subject: string,
): Promise<{ status: string; workspace_id: string; subject: string }> {
  return await fetchJson<{ status: string; workspace_id: string; subject: string }>(
    `/api/workspaces/${encodeURIComponent(workspaceId || 'default')}/members/${encodeURIComponent(subject)}`,
    {
      headers: apiHeaders(token),
      method: 'DELETE',
    },
  )
}

async function loadWorkspaceAudit(
  workspaceId: string,
  token: string,
): Promise<WorkspaceAuditOverview> {
  return await fetchJson<WorkspaceAuditOverview>(
    `/api/workspaces/${encodeURIComponent(workspaceId || 'default')}/audit`,
    {
      headers: apiHeaders(token),
    },
  )
}

async function loadWorkspaceAuditForPanel(
  workspaceId: string,
  token: string,
): Promise<{ overview: WorkspaceAuditOverview | null; error: string }> {
  try {
    return { overview: await loadWorkspaceAudit(workspaceId, token), error: '' }
  } catch (error) {
    return {
      overview: null,
      error: error instanceof Error ? error.message : 'workspace audit unavailable',
    }
  }
}

async function loadRetention(slug: string, token: string): Promise<RetentionOverview> {
  return await fetchJson<RetentionOverview>(`/api/engagements/${slug}/retention`, {
    headers: apiHeaders(token),
  })
}

async function loadRetentionForPanel(
  slug: string,
  token: string,
): Promise<{ overview: RetentionOverview | null; error: string }> {
  try {
    return { overview: await loadRetention(slug, token), error: '' }
  } catch (error) {
    return {
      overview: null,
      error: error instanceof Error ? error.message : 'retention unavailable',
    }
  }
}

async function requestRetentionPreview(slug: string, token: string): Promise<RetentionRunResult> {
  return await fetchJson<RetentionRunResult>(`/api/engagements/${slug}/retention/preview`, {
    body: JSON.stringify({ policy_name: 'default' }),
    headers: apiJsonHeaders(token),
    method: 'POST',
  })
}

async function requestRetentionApply(slug: string, token: string): Promise<RetentionRunResult> {
  return await fetchJson<RetentionRunResult>(`/api/engagements/${slug}/retention/apply`, {
    body: JSON.stringify({ policy_name: 'default', confirm: true }),
    headers: apiJsonHeaders(token),
    method: 'POST',
  })
}

async function loadConnectorCatalog(slug: string, token: string): Promise<ConnectorCatalogOverview> {
  return await fetchJson<ConnectorCatalogOverview>(`/api/engagements/${slug}/connectors`, {
    headers: apiHeaders(token),
  })
}

async function loadConnectorCatalogForPanel(
  slug: string,
  token: string,
): Promise<{ overview: ConnectorCatalogOverview | null; error: string }> {
  try {
    return { overview: await loadConnectorCatalog(slug, token), error: '' }
  } catch (error) {
    return {
      overview: null,
      error: error instanceof Error ? error.message : 'connector catalog unavailable',
    }
  }
}

async function loadConnectorSecrets(slug: string, token: string): Promise<ConnectorSecretsOverview> {
  return await fetchJson<ConnectorSecretsOverview>(`/api/engagements/${slug}/connector-secrets`, {
    headers: apiHeaders(token),
  })
}

async function loadConnectorSecretsForPanel(
  slug: string,
  token: string,
): Promise<{ overview: ConnectorSecretsOverview | null; error: string }> {
  try {
    return { overview: await loadConnectorSecrets(slug, token), error: '' }
  } catch (error) {
    return {
      overview: null,
      error: error instanceof Error ? error.message : 'connector secrets unavailable',
    }
  }
}

async function requestConnectorSecretStore(
  slug: string,
  token: string,
  payload: ConnectorSecretStorePayload,
): Promise<ConnectorSecretStoreResult> {
  return await fetchJson<ConnectorSecretStoreResult>(`/api/engagements/${slug}/connector-secrets`, {
    body: JSON.stringify({
      connector_id: payload.connectorId,
      secret_name: payload.secretName,
      secret_value: payload.secretValue,
      secret_ref: payload.secretRef,
      metadata: {
        ...(payload.owner ? { owner: payload.owner } : {}),
      },
    }),
    headers: apiJsonHeaders(token),
    method: 'POST',
  })
}

async function loadActiveValidation(slug: string, token: string): Promise<ActiveValidationSnapshot> {
  return await fetchJson<ActiveValidationSnapshot>(`/api/engagements/${slug}/active-validation`, {
    headers: apiHeaders(token),
  })
}

async function loadActiveValidationForPanel(
  slug: string,
  token: string,
): Promise<{ snapshot: ActiveValidationSnapshot | null; error: string }> {
  try {
    return { snapshot: await loadActiveValidation(slug, token), error: '' }
  } catch (error) {
    return {
      snapshot: null,
      error: error instanceof Error ? error.message : 'active validation unavailable',
    }
  }
}

async function requestActiveValidationCreate(
  slug: string,
  token: string,
  payload: ActiveValidationCreatePayload,
): Promise<ActiveValidationJob> {
  const response = await fetchJson<{ status: string; job: ActiveValidationJob }>(
    `/api/engagements/${slug}/active-validation/jobs`,
    {
      body: JSON.stringify({
        target_ref: payload.targetRef,
        target_kind: payload.targetKind,
        method: payload.method,
        mode: payload.mode,
        max_steps: payload.maxSteps,
        ...(payload.metadata ? { metadata: payload.metadata } : {}),
        ...(payload.roeId ? { roe_id: payload.roeId } : {}),
        ...(payload.scopeManifest ? { scope_manifest: payload.scopeManifest } : {}),
      }),
      headers: apiJsonHeaders(token),
      method: 'POST',
    },
  )
  return response.job
}

async function requestActiveValidationApprove(
  slug: string,
  token: string,
  payload: ActiveValidationApprovalPayload,
): Promise<ActiveValidationJob> {
  const response = await fetchJson<{ status: string; job: ActiveValidationJob }>(
    `/api/engagements/${slug}/active-validation/jobs/${payload.jobId}/approve`,
    {
      body: JSON.stringify({
        ...(payload.roeId ? { roe_id: payload.roeId } : {}),
        ...(payload.scopeManifest ? { scope_manifest: payload.scopeManifest } : {}),
        ...(payload.approvalNote ? { approval_note: payload.approvalNote } : {}),
      }),
      headers: apiJsonHeaders(token),
      method: 'POST',
    },
  )
  return response.job
}

async function requestActiveValidationRun(
  slug: string,
  token: string,
  jobId: number,
  allowLive: boolean,
): Promise<ActiveValidationRun> {
  const response = await fetchJson<{ status: string; run: ActiveValidationRun }>(
    `/api/engagements/${slug}/active-validation/jobs/${jobId}/run`,
    {
      body: JSON.stringify({ allow_live: allowLive }),
      headers: apiJsonHeaders(token),
      method: 'POST',
    },
  )
  return response.run
}

async function loadRemediation(slug: string, token: string): Promise<RemediationOverview> {
  return await fetchJson<RemediationOverview>(`/api/engagements/${slug}/remediation`, {
    headers: apiHeaders(token),
  })
}

async function loadRemediationForPanel(
  slug: string,
  token: string,
): Promise<{ overview: RemediationOverview | null; error: string }> {
  try {
    return { overview: await loadRemediation(slug, token), error: '' }
  } catch (error) {
    return {
      overview: null,
      error: error instanceof Error ? error.message : 'remediation unavailable',
    }
  }
}

async function requestRemediationUpdate(
  slug: string,
  token: string,
  payload: RemediationUpdatePayload,
): Promise<RemediationItem> {
  const body: Record<string, string> = {
    owner: payload.owner,
    sla_due_at: payload.slaDueAt,
    status: payload.status,
    retest_status: payload.retestStatus,
    ticket_system: payload.ticketSystem,
    ticket_ref: payload.ticketRef,
    ticket_url: payload.ticketUrl,
  }
  if (payload.riskAcceptanceReason !== undefined) {
    body.risk_acceptance_reason = payload.riskAcceptanceReason
  }
  if (payload.riskAcceptanceExpiresAt !== undefined) {
    body.risk_acceptance_expires_at = payload.riskAcceptanceExpiresAt
  }
  const response = await fetchJson<{ status: string; item: RemediationItem }>(
    `/api/engagements/${slug}/remediation/${payload.itemId}`,
    {
      body: JSON.stringify(body),
      headers: apiJsonHeaders(token),
      method: 'PATCH',
    },
  )
  return response.item
}

function remediationTicketSyncBody(
  payload: RemediationTicketSyncPayload,
): Record<string, string | boolean | string[]> {
  const connectors = ['jsonl']
  const body: Record<string, string | boolean | string[]> = {
    connectors,
    force: payload.force ?? true,
  }
  const setText = (key: string, value: string | undefined): boolean => {
    const trimmed = (value ?? '').trim()
    if (!trimmed) {
      return false
    }
    body[key] = trimmed
    return true
  }

  if (setText('webhook_url', payload.webhookUrl)) {
    connectors.push('webhook')
  }
  if (setText('github_repo', payload.githubRepo)) {
    connectors.push('github_issues')
  }
  setText('github_token_env', payload.githubTokenEnv)
  setText('github_api_url', payload.githubApiUrl)
  const hasJiraBase = setText('jira_base_url', payload.jiraBaseUrl)
  const hasJiraProject = setText('jira_project_key', payload.jiraProjectKey)
  if (hasJiraBase || hasJiraProject) {
    connectors.push('jira')
  }
  setText('jira_issue_type', payload.jiraIssueType)
  setText('jira_email_env', payload.jiraEmailEnv)
  setText('jira_token_env', payload.jiraTokenEnv)
  if (setText('servicenow_instance_url', payload.servicenowInstanceUrl)) {
    connectors.push('servicenow')
  }
  setText('servicenow_table', payload.servicenowTable)
  setText('servicenow_username_env', payload.servicenowUsernameEnv)
  setText('servicenow_password_env', payload.servicenowPasswordEnv)
  setText('servicenow_token_env', payload.servicenowTokenEnv)
  if (setText('tines_webhook_url', payload.tinesWebhookUrl)) {
    connectors.push('tines')
  }
  setText('tines_token_env', payload.tinesTokenEnv)
  if (setText('splunk_hec_url', payload.splunkHecUrl)) {
    connectors.push('splunk_hec')
  }
  setText('splunk_hec_token_env', payload.splunkHecTokenEnv)
  setText('splunk_index', payload.splunkIndex)
  setText('splunk_source', payload.splunkSource)
  setText('splunk_sourcetype', payload.splunkSourcetype)
  if (setText('torq_webhook_url', payload.torqWebhookUrl)) {
    connectors.push('torq')
  }
  setText('torq_token_env', payload.torqTokenEnv)
  return body
}

async function requestRemediationTicketSync(
  slug: string,
  token: string,
  itemId: number,
  payload: RemediationTicketSyncPayload,
): Promise<RemediationSyncResult> {
  return await fetchJson<RemediationSyncResult>(
    `/api/engagements/${slug}/remediation/${itemId}/sync-ticket`,
    {
      body: JSON.stringify(remediationTicketSyncBody(payload)),
      headers: apiJsonHeaders(token),
      method: 'POST',
    },
  )
}

async function requestRemediationOwnerPropagation(
  slug: string,
  token: string,
  overwrite: boolean,
  conflictPolicy = 'highest_confidence',
  minConfidence = 0,
): Promise<RemediationPropagationResult> {
  return await fetchJson<RemediationPropagationResult>(
    `/api/engagements/${slug}/remediation/propagate-owners`,
    {
      body: JSON.stringify({
        overwrite,
        conflict_policy: conflictPolicy,
        min_confidence: minConfidence,
      }),
      headers: apiJsonHeaders(token),
      method: 'POST',
    },
  )
}

async function requestRemediationGraphDraft(
  slug: string,
  token: string,
  limit = 10,
): Promise<RemediationGraphDraftResult> {
  return await fetchJson<RemediationGraphDraftResult>(
    `/api/engagements/${slug}/remediation/draft-from-asset-graph`,
    {
      body: JSON.stringify({ limit }),
      headers: apiJsonHeaders(token),
      method: 'POST',
    },
  )
}

async function requestRemediationOwnerReview(
  slug: string,
  token: string,
  itemId: number,
  decision: string,
  note = '',
): Promise<RemediationOwnerReviewResult> {
  return await fetchJson<RemediationOwnerReviewResult>(
    `/api/engagements/${slug}/remediation/${itemId}/review-owner`,
    {
      body: JSON.stringify({ decision, note }),
      headers: apiJsonHeaders(token),
      method: 'POST',
    },
  )
}

async function requestAssetGraphConflictResolution(
  slug: string,
  token: string,
  conflict: AssetGraphOwnershipConflict,
  owner: AssetGraphConflictOwner,
): Promise<AssetGraphConflictResolutionResult> {
  return await fetchJson<AssetGraphConflictResolutionResult>(
    `/api/engagements/${slug}/asset-graph/ownership-conflicts/resolve`,
    {
      body: JSON.stringify({
        entity_key: conflict.entity_key,
        owner_ref: owner.owner_ref,
        owner_kind: owner.owner_kind ?? '',
        reason: 'operator selected owner from live dashboard',
      }),
      headers: apiJsonHeaders(token),
      method: 'POST',
    },
  )
}

async function requestRemediationRetest(
  slug: string,
  token: string,
  payload: RemediationRetestRequestPayload,
): Promise<RemediationRetestRequestResult> {
  return await fetchJson<RemediationRetestRequestResult>(
    `/api/engagements/${slug}/remediation/${payload.itemId}/request-retest`,
    {
      body: JSON.stringify({
        ...(payload.targetRef ? { target_ref: payload.targetRef } : {}),
        ...(payload.targetKind ? { target_kind: payload.targetKind } : {}),
        method: payload.method,
        mode: payload.mode,
        approve: payload.approve,
        ...(payload.roeId ? { roe_id: payload.roeId } : {}),
        ...(payload.scopeManifest ? { scope_manifest: payload.scopeManifest } : {}),
        ...(payload.approvalNote ? { approval_note: payload.approvalNote } : {}),
        ...(payload.expectedResult ? { expected_result: payload.expectedResult } : {}),
      }),
      headers: apiJsonHeaders(token),
      method: 'POST',
    },
  )
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

function numericValue(value: unknown): number {
  const numeric = Number(value ?? 0)
  return Number.isFinite(numeric) ? numeric : 0
}

function retentionDaysLabel(value: number | null | undefined): string {
  if (value === null || value === undefined) {
    return 'never'
  }
  return `${formatCount(value)}d`
}

function retentionSummaryNumber(summary: Record<string, unknown> | undefined, key: string): number {
  return numericValue(summary?.[key])
}

function retentionPolicyRow(policy: RetentionPolicy): SectionRow {
  return {
    Name: policy.name || 'default',
    Enabled: policy.enabled ? 'yes' : 'no',
    Audit: retentionDaysLabel(policy.audit_review_days),
    Monitoring: retentionDaysLabel(policy.monitoring_days),
    Remediation: retentionDaysLabel(policy.remediation_event_days),
    'Retention Runs': retentionDaysLabel(policy.retention_run_days),
    'Legal Hold': policy.legal_hold_override ? 'override' : 'no',
    Updated: policy.updated_at || '-',
  }
}

function retentionRunRow(run: RetentionRun): SectionRow {
  return {
    Run: String(run.id),
    Policy: run.policy_name || 'default',
    Mode: run.mode || '-',
    Status: run.status || '-',
    Operator: run.operator || '-',
    Eligible: formatCount(retentionSummaryNumber(run.summary, 'eligible_count')),
    Deleted: formatCount(retentionSummaryNumber(run.summary, 'deleted_count')),
    Skipped: formatCount(retentionSummaryNumber(run.summary, 'skipped_count')),
    Items: formatCount(retentionSummaryNumber(run.summary, 'item_count') || (run.items?.length ?? 0)),
    Created: run.created_at || '-',
  }
}

function retentionRunItemRow(run: RetentionRun, item: RetentionRunItem): SectionRow {
  return {
    Run: String(run.id),
    Category: item.category || '-',
    Table: item.table_name || '-',
    Retention: retentionDaysLabel(item.retention_days),
    Cutoff: item.cutoff_at || '-',
    Eligible: formatCount(item.eligible_count),
    Deleted: formatCount(item.deleted_count),
    Skipped: formatCount(item.skipped_count),
    Reason: item.reason || '-',
  }
}

function connectorSecretRow(secret: ConnectorSecret): SectionRow {
  return {
    Connector: secret.connector_id || '-',
    Name: secret.secret_name || '-',
    Source: secret.secret_ref || '-',
    Key: secret.key_hint || '-',
    Owner: stringifyUnknown(secret.metadata?.owner) || '-',
    Updated: secret.updated_at || '-',
    Operator: secret.updated_by || secret.created_by || '-',
  }
}

function workspaceRecordRow(workspace: WorkspaceRecord): SectionRow {
  return {
    Workspace: workspace.workspace_id || 'default',
    Name: workspace.name || '-',
    Members: formatCount(workspace.member_count),
    Engagements: formatCount(workspace.engagement_count),
    Metadata: redactDashboardText(workspace.metadata),
    Updated: workspace.updated_at || '-',
  }
}

function workspaceMemberRow(member: WorkspaceMember): SectionRow {
  return {
    Subject: member.subject || '-',
    Role: member.role || '-',
    Permissions: member.permissions.join(', ') || '-',
    Updated: member.updated_at || '-',
  }
}

function parseWorkspaceMetadata(value: string): Record<string, unknown> {
  const trimmed = value.trim()
  if (!trimmed) {
    return {}
  }
  const parsed = JSON.parse(trimmed) as unknown
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('Workspace metadata must be a JSON object.')
  }
  return parsed as Record<string, unknown>
}

function shortAuditHash(value: string | undefined): string {
  const text = String(value || '').trim()
  return text ? text.slice(0, 12) : '-'
}

function workspaceAuditPayloadPreview(payload: Record<string, unknown>): string {
  const redacted = redactDashboardText(payload)
  return redacted.length > 180 ? `${redacted.slice(0, 177)}...` : redacted || '-'
}

function workspaceAuditEventRow(event: WorkspaceAuditEvent): SectionRow {
  return {
    When: event.created_at || '-',
    Event: event.event_type || '-',
    Actor: event.actor_subject || '-',
    Subject: event.subject || '-',
    Source: event.source || '-',
    Payload: workspaceAuditPayloadPreview(event.payload),
    Hash: shortAuditHash(event.event_hash),
    Previous: shortAuditHash(event.previous_hash),
  }
}

function connectorCredentialNames(connector: ConnectorCatalogItem | null | undefined): string[] {
  if (!connector) {
    return []
  }
  return Array.from(new Set(connector.env_options.flat().filter(Boolean))).sort()
}

function connectorStoredSecretStatusLabel(connector: ConnectorCatalogItem): string {
  const rows = connector.stored_secret_statuses ?? []
  if (rows.length) {
    return rows.map((row) => `${row.name}:${row.status}`).join(', ')
  }
  return connector.secret_store_readiness || '-'
}

function connectorCatalogRow(connector: ConnectorCatalogItem): SectionRow {
  const credentialSource = connector.env_configured
    ? 'env'
    : connector.secret_store_configured
      ? 'secret-store'
      : connector.secret_store_readiness === 'stored_decrypt_failed' ||
          connector.secret_store_readiness === 'stored_key_missing'
        ? connector.secret_store_readiness
        : connector.env_options.length
          ? 'unset'
          : '-'
  return {
    Connector: connector.id,
    Domain: connector.domain || '-',
    Cost: connector.cost_profile || '-',
    Readiness: connector.readiness || '-',
    Source: connector.source || 'built_in',
    Execution: connector.execution_status || '-',
    Runner: connector.runner_supported ? 'yes' : 'no',
    Credentials: credentialSource,
    'Stored names': connector.stored_secret_names.join(', ') || '-',
    'Store status': connectorStoredSecretStatusLabel(connector),
    Missing: connector.missing_binaries.join(', ') || '-',
    Gates: connector.required_gates.join(', ') || '-',
    Status: connector.implementation_status || '-',
  }
}

function retentionResultMessage(action: string, result: RetentionRunResult): string {
  const summary = result.summary ?? {}
  return `${action} ${result.status}: ${formatCount(retentionSummaryNumber(summary, 'eligible_count'))} eligible, ${formatCount(
    retentionSummaryNumber(summary, 'deleted_count'),
  )} deleted.`
}

function normalizeRemediationStatus(value: string | undefined): RemediationStatus {
  const normalized = (value || 'open').trim().toLowerCase()
  return REMEDIATION_STATUSES.find((status) => status === normalized) ?? 'open'
}

function normalizeRemediationRetestStatus(value: string | undefined): RemediationRetestStatus {
  const normalized = (value || 'not_requested').trim().toLowerCase()
  return REMEDIATION_RETEST_STATUSES.find((status) => status === normalized) ?? 'not_requested'
}

function remediationTicketLabel(item: RemediationItem): string {
  const ticketLabel = [item.ticket_system, item.ticket_ref].filter(Boolean).join(': ')
  return ticketLabel || item.ticket_url || '-'
}

function remediationItemRow(item: RemediationItem): SectionRow {
  const findingRef = item.finding_ref || (item.finding_id !== null ? String(item.finding_id) : String(item.id))
  return {
    Item: String(item.id),
    Severity: item.severity || '-',
    Status: item.status || '-',
    Owner: item.owner || '-',
    SLA: item.sla_due_at || '-',
    Finding: `${item.finding_table || 'manual'}:${findingRef}`,
    Title: item.title || '-',
    Retest: item.retest_status || '-',
    Ticket: remediationTicketLabel(item),
    Risk: item.risk_acceptance_reason || '-',
    'Risk expiry': item.risk_acceptance_expires_at || '-',
    'Risk review': item.risk_acceptance_review_status || '-',
    Updated: item.updated_at || '-',
  }
}

function remediationReviewQueueRow(item: RemediationReviewQueueItem): SectionRow {
  const finding = `${item.finding_table || 'manual'}:${item.finding_ref || item.id}`
  const ticketEvent = item.latest_ticket_event
  const ticketSync = ticketEvent
    ? [ticketEvent.connector, ticketEvent.status].filter(Boolean).join(' ')
    : ''
  return {
    Priority: String(item.review_priority),
    Reason: item.queue_reason_labels.join(', ') || '-',
    Severity: item.severity || '-',
    Status: item.status || '-',
    Owner: item.owner || '-',
    SLA: item.sla_due_at || '-',
    Retest: item.retest_status || '-',
    Ticket: item.ticket_label || '-',
    'Ticket Sync': ticketSync || '-',
    'Sync Attempts': ticketEvent?.attempt_count ? String(ticketEvent.attempt_count) : '-',
    'Sync Error': ticketEvent?.last_error || '-',
    Finding: finding,
    Title: item.title || '-',
    Updated: item.updated_at || '-',
  }
}

function summarizeRemediationReviewQueueRows(rows: SectionRow[]): Record<string, number> {
  const summary: Record<string, number> = {
    attention_required: rows.length,
    missing_owner: 0,
    missing_ticket: 0,
    sla_overdue: 0,
    risk_acceptance_review_due: 0,
    retest_pending: 0,
    retest_blocked: 0,
    ticket_sync_failed: 0,
  }
  rows.forEach((row) => {
    const reason = (row.Reason || '').toLowerCase()
    if (reason.includes('missing owner')) {
      summary.missing_owner += 1
    }
    if (reason.includes('missing ticket')) {
      summary.missing_ticket += 1
    }
    if (reason.includes('sla overdue')) {
      summary.sla_overdue += 1
    }
    if (reason.includes('risk acceptance')) {
      summary.risk_acceptance_review_due += 1
    }
    if (reason.includes('retest pending')) {
      summary.retest_pending += 1
    }
    if (reason.includes('retest blocked')) {
      summary.retest_blocked += 1
    }
    if (reason.includes('ticket sync failed')) {
      summary.ticket_sync_failed += 1
    }
  })
  return summary
}

function summarizeRemediationRows(rows: SectionRow[]): Record<string, number> {
  const summary: Record<string, number> = {
    total: rows.length,
    open: 0,
    assigned: 0,
    in_progress: 0,
    risk_accepted: 0,
    retest_pending: 0,
    resolved: 0,
    false_positive: 0,
    with_ticket: 0,
    with_owner: 0,
    with_sla: 0,
    risk_acceptance_review_due: 0,
    risk_acceptance_expired: 0,
    risk_acceptance_expiring_soon: 0,
    risk_acceptance_missing_expiry: 0,
    risk_acceptance_invalid_expiry: 0,
  }
  rows.forEach((row) => {
    const status = (row.Status || '').trim().toLowerCase().replaceAll(' ', '_')
    if (status && Object.prototype.hasOwnProperty.call(summary, status)) {
      summary[status] += 1
    }
    if (row.Ticket && row.Ticket !== '-') {
      summary.with_ticket += 1
    }
    if (row.Owner && row.Owner !== '-') {
      summary.with_owner += 1
    }
    const slaLabel = row.SLA || row['SLA Due'] || ''
    if (slaLabel && slaLabel !== '-') {
      summary.with_sla += 1
    }
    const riskReview = (row['Risk review'] || row['Risk Review'] || '').trim().toLowerCase().replaceAll(' ', '_')
    if (riskReview === 'expired') {
      summary.risk_acceptance_expired += 1
    } else if (riskReview === 'expiring_soon') {
      summary.risk_acceptance_expiring_soon += 1
    } else if (riskReview === 'missing_expiry') {
      summary.risk_acceptance_missing_expiry += 1
    } else if (riskReview === 'invalid_expiry') {
      summary.risk_acceptance_invalid_expiry += 1
    }
    if (['expired', 'expiring_soon', 'missing_expiry', 'invalid_expiry'].includes(riskReview)) {
      summary.risk_acceptance_review_due += 1
    }
  })
  return summary
}

function remediationSummaryCount(summary: Record<string, number>, key: string): number {
  return numericValue(summary[key])
}

function normalizeActiveValidationMode(value: string | undefined): ActiveValidationMode {
  const normalized = (value || 'dry_run').trim().toLowerCase()
  return ACTIVE_VALIDATION_MODES.find((mode) => mode === normalized) ?? 'dry_run'
}

function normalizeActiveValidationTargetKind(value: string | undefined): ActiveValidationTargetKind {
  const normalized = (value || 'host').trim().toLowerCase()
  return ACTIVE_VALIDATION_TARGET_KINDS.find((kind) => kind === normalized) ?? 'host'
}

function normalizeActiveValidationMethodId(value: string | undefined): ActiveValidationMethodId | string {
  const normalized = (value || 'http_reachability').trim().toLowerCase()
  return ACTIVE_VALIDATION_METHOD_IDS.find((method) => method === normalized) ?? normalized
}

function activeValidationMethodCoverage(method: ActiveValidationMethod | undefined): string {
  const mappings = method?.attack_mappings ?? []
  const controls = method?.control_families ?? []
  return [...mappings, ...controls].join(', ') || '-'
}

function activeValidationMethodFromEvidence(
  evidence: Record<string, unknown> | undefined,
): ActiveValidationMethod | undefined {
  const method = evidence?.method
  if (method && typeof method === 'object' && !Array.isArray(method)) {
    return method as ActiveValidationMethod
  }
  return undefined
}

function activeValidationSafetyLabel(evidence: Record<string, unknown> | undefined): string {
  const payload = evidence ?? {}
  return [
    ['net', 'network_execution'],
    ['destructive', 'destructive_actions'],
    ['lateral', 'lateral_movement'],
    ['post-ex', 'post_exploitation'],
  ]
    .map(([label, key]) => `${label}=${payload[key] ? 'yes' : 'no'}`)
    .join(', ')
}

function activeValidationJobRow(job: ActiveValidationJob): SectionRow {
  const method = job.method_config
  return {
    Job: String(job.id),
    Target: job.target_ref,
    Kind: job.target_kind,
    Method: job.method,
    'Method Status': method?.implementation_status ?? '-',
    Mode: job.mode,
    Status: job.status,
    Approved: job.approved ? 'yes' : 'no',
    ROE: job.roe_id || '-',
    Scope: job.scope_manifest_ref || (job.scope_manifest_hash ? 'stored' : 'no'),
    Proof: method?.proof_kind ?? '-',
    Coverage: activeValidationMethodCoverage(method),
    Updated: job.updated_at || '-',
  }
}

function activeValidationCoverageStateLabel(states: ActiveValidationCoverageStates | undefined): string {
  const entries = Object.entries(states ?? {}).filter(([, count]) => count > 0)
  return entries.length
    ? entries
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([state, count]) => `${state}=${formatCount(count)}`)
        .join(', ')
    : '-'
}

function activeValidationCoverageRows(coverage: ActiveValidationCoverage | undefined): SectionRow[] {
  if (!coverage) {
    return []
  }
  const groups: Array<{
    label: string
    rows: ActiveValidationCoverageBucket[]
  }> = [
    { label: 'ATT&CK', rows: coverage.attack_mappings },
    { label: 'Control', rows: coverage.control_families },
    { label: 'Method', rows: coverage.methods },
  ]
  return groups.flatMap((group) =>
    group.rows.map((row) => ({
      Type: group.label,
      Coverage: row.label || row.id,
      Jobs: formatCount(row.job_count),
      Runs: formatCount(row.run_count),
      States: activeValidationCoverageStateLabel(row.states),
      Methods: (row.methods?.length ? row.methods : [row.id]).join(', ') || '-',
      'Latest Jobs': row.latest_job_ids?.length ? row.latest_job_ids.map(String).join(', ') : '-',
    })),
  )
}

const DASHBOARD_REDACTION_PATTERNS: Array<[RegExp, string]> = [
  [/("(?:api[_-]?key|access[_-]?token|token|secret|password|authorization|private[_-]?key)"\s*:\s*")[^"]+(")/gi, '$1[redacted]$2'],
  [/(\b(?:api[_-]?key|access[_-]?token|token|secret|password|authorization|bearer)\b\s*[:=]\s*["']?)[^"',;\s]{8,}/gi, '$1[redacted]'],
  [/([?&](?:api[_-]?key|access[_-]?token|token|secret|signature|password)=)[^&\s"']+/gi, '$1[redacted]'],
  [/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g, '[redacted]'],
  [/\b(?:ghp|github_pat|glpat|xox[baprs]|sk)-?[A-Za-z0-9_./+=-]{16,}\b/g, '[redacted]'],
  [/\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\b/g, '[redacted]'],
]

function redactDashboardText(value: unknown): string {
  return DASHBOARD_REDACTION_PATTERNS.reduce(
    (text, [pattern, replacement]) => text.replace(pattern, replacement),
    stringifyUnknown(value),
  )
}

function activeValidationRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value) ? (value as Record<string, unknown>) : {}
}

function activeValidationShortText(value: unknown, limit = 180): string {
  return redactDashboardText(value).replace(/\s+/g, ' ').trim().slice(0, limit)
}

function activeValidationBoolLabel(value: unknown): string {
  return value ? 'yes' : 'no'
}

function activeValidationHttpProofLabel(payload: Record<string, unknown>): string {
  const request = activeValidationRecord(payload.request)
  const response = activeValidationRecord(payload.response)
  const networkError = activeValidationRecord(payload.network_error)
  let method = activeValidationShortText(request.method, 20)
  const allowedMethods = request.allowed_methods
  if (!method && Array.isArray(allowedMethods) && allowedMethods.length > 0) {
    method = activeValidationShortText(allowedMethods[0], 20)
  }
  const statusCode = response.status_code
  const parts: string[] = []
  if (statusCode !== undefined && statusCode !== null && String(statusCode) !== '') {
    parts.push(`${method || 'HTTP'} ${activeValidationShortText(statusCode, 20)}`)
  } else if (Object.keys(networkError).length > 0) {
    const errorType = activeValidationShortText(networkError.type || 'error', 80)
    parts.push(`${method || 'HTTP'} network_error=${errorType}`)
  } else {
    const reason = activeValidationShortText(payload.reason, 80)
    if (reason) {
      parts.push(`blocked reason=${reason}`)
    } else if (Object.keys(payload).length > 0) {
      parts.push('live evidence recorded')
    }
  }
  const redirect = activeValidationShortText(response.redirect_location, 120)
  if (redirect) {
    parts.push(`redirect=${redirect}`)
  }
  if (Object.prototype.hasOwnProperty.call(payload, 'body_captured')) {
    parts.push(`body=${activeValidationBoolLabel(payload.body_captured)}`)
  }
  return parts.join(' ')
}

function activeValidationStringList(value: unknown, limit = 6): string {
  if (!Array.isArray(value)) {
    return ''
  }
  return value
    .slice(0, limit)
    .map((item) => activeValidationShortText(item, 60))
    .filter(Boolean)
    .join(', ')
}

function activeValidationSecurityHeadersProofLabel(payload: Record<string, unknown>): string {
  const networkError = activeValidationRecord(payload.network_error)
  if (Object.keys(networkError).length > 0) {
    return activeValidationHttpProofLabel(payload)
  }
  const request = activeValidationRecord(payload.request)
  const response = activeValidationRecord(payload.response)
  const headers = activeValidationRecord(payload.security_headers)
  const observed = activeValidationRecord(headers.observed)
  const method = activeValidationShortText(request.method, 20) || 'HTTP'
  const statusCode = activeValidationShortText(response.status_code, 20)
  const parts = [`${method} ${statusCode}`.trim(), `headers observed=${Object.keys(observed).length}`]
  const missing = activeValidationStringList(headers.missing)
  const weak = activeValidationStringList(headers.weak)
  if (missing) {
    parts.push(`missing=${missing}`)
  }
  if (weak) {
    parts.push(`weak=${weak}`)
  }
  if (Object.prototype.hasOwnProperty.call(payload, 'body_captured')) {
    parts.push(`body=${activeValidationBoolLabel(payload.body_captured)}`)
  }
  return parts.filter(Boolean).join(' ')
}

function activeValidationFixMatchLabel(liveValidation: Record<string, unknown>): string {
  const fix = activeValidationRecord(liveValidation.fix_verification)
  if (Object.keys(fix).length === 0) {
    return ''
  }
  const expected = activeValidationShortText(fix.expected_result, 80) || '-'
  const observed = activeValidationShortText(fix.observed_result, 80) || '-'
  return `expected=${expected} observed=${observed} matched=${activeValidationBoolLabel(fix.matched)}`
}

type ActiveValidationProofSummary = {
  Evidence: string
  'Live Proof': string
  'Fix Match': string
}

function activeValidationProofSummary(
  evidence: Record<string, unknown> | undefined,
): ActiveValidationProofSummary {
  const payload = evidence ?? {}
  const existing = activeValidationRecord(payload.proof_summary)
  const existingEvidence = activeValidationShortText(existing.evidence)
  const existingLiveProof = activeValidationShortText(existing.live_proof)
  const existingFixMatch = activeValidationShortText(existing.fix_match)
  if (existingEvidence || existingLiveProof || existingFixMatch) {
    return {
      Evidence: existingEvidence || '-',
      'Live Proof': existingLiveProof || '-',
      'Fix Match': existingFixMatch || '-',
    }
  }

  const liveValidation = activeValidationRecord(payload.live_validation)
  let liveProof = ''
  let fixMatch = ''
  if (Object.keys(liveValidation).length > 0) {
    fixMatch = activeValidationFixMatchLabel(liveValidation)
    const securityHeaders = activeValidationRecord(liveValidation.security_headers)
    if (Object.keys(securityHeaders).length > 0) {
      liveProof = activeValidationSecurityHeadersProofLabel(liveValidation)
    } else {
      const httpPayload = activeValidationRecord(liveValidation.http_reachability)
      liveProof = activeValidationHttpProofLabel(
        Object.keys(httpPayload).length > 0 ? httpPayload : liveValidation,
      )
    }
  }

  let evidenceLabel = ''
  if (fixMatch && liveProof) {
    evidenceLabel = `${fixMatch}; ${liveProof}`
  } else if (fixMatch) {
    evidenceLabel = fixMatch
  } else if (liveProof) {
    evidenceLabel = liveProof
  } else if (Array.isArray(payload.planned_steps) && payload.planned_steps.length > 0) {
    const step = activeValidationRecord(payload.planned_steps[0])
    const method = activeValidationShortText(step.method, 80) || 'planned'
    const effect = activeValidationShortText(step.effect, 80)
    evidenceLabel = effect ? `${method} effect=${effect}` : method
  } else {
    const fixture = activeValidationRecord(payload.fixture)
    if (Object.keys(fixture).length > 0) {
      const method = activeValidationShortText(fixture.method, 80) || 'fixture'
      const result = activeValidationShortText(fixture.result, 80)
      evidenceLabel = result ? `${method} result=${result}` : method
    }
  }

  return {
    Evidence: evidenceLabel || '-',
    'Live Proof': liveProof || '-',
    'Fix Match': fixMatch || '-',
  }
}

function activeValidationRunRow(run: ActiveValidationRun): SectionRow {
  const method = run.job?.method_config ?? activeValidationMethodFromEvidence(run.evidence)
  const proofSummary = activeValidationProofSummary(run.evidence)
  return {
    Run: String(run.id),
    Job: String(run.job_id),
    Target: run.job?.target_ref ?? stringifyUnknown(run.evidence?.job),
    Mode: run.job?.mode ?? stringifyUnknown(run.evidence?.mode),
    Method: run.job?.method ?? method?.id ?? '',
    Status: run.status,
    Result: run.result,
    Proof: method?.proof_kind ?? '-',
    Coverage: activeValidationMethodCoverage(method),
    Evidence: proofSummary.Evidence,
    'Live Proof': proofSummary['Live Proof'],
    'Fix Match': proofSummary['Fix Match'],
    Safety: activeValidationSafetyLabel(run.evidence),
    Operator: run.operator || '-',
    Completed: run.completed_at || '-',
    Error: run.error ? redactDashboardText(run.error) : '-',
  }
}

function sectionRowTime(row: SectionRow, keys: string[]): string {
  for (const key of keys) {
    const value = row[key]
    if (value && value !== '-') {
      return value
    }
  }
  return ''
}

function validationReportabilityLabel(status?: string): string | undefined {
  const normalized = (status || '').trim().toUpperCase()
  if (!normalized) {
    return undefined
  }
  if (['VALIDATED', 'VERIFIED', 'YES', 'TRUE'].includes(normalized)) {
    return 'reportable validated'
  }
  if (['NO', 'FALSE', 'INVALID', 'UNVERIFIED', 'FAILED', 'ERROR', 'BLOCKED'].includes(normalized)) {
    return `non-reportable ${normalized.toLowerCase()}`
  }
  return 'non-reportable inventory held'
}

function cloudReportabilityLabel(reportable?: string): string | undefined {
  const normalized = (reportable || '').trim().toLowerCase()
  if (!normalized) {
    return undefined
  }
  return ['yes', 'true', '1'].includes(normalized) ? 'reportable yes' : `non-reportable ${normalized}`
}

function redactOperationalTimelineEvent(event: OperationalTimelineEvent): OperationalTimelineEvent {
  return {
    ...event,
    time: redactDashboardText(event.time),
    title: redactDashboardText(event.title),
    summary: redactDashboardText(event.summary),
    method: event.method ? redactDashboardText(event.method) : undefined,
    provenance: event.provenance ? redactDashboardText(event.provenance) : undefined,
    reportability: event.reportability ? redactDashboardText(event.reportability) : undefined,
    status: event.status ? redactDashboardText(event.status) : undefined,
    severity: event.severity ? redactDashboardText(event.severity) : undefined,
  }
}

function operationalTimelineEvents(
  detail: EngagementDetail,
  activeValidationRuns: ActiveValidationRun[],
  activeValidationRunRows: SectionRow[],
  remediationRows: SectionRow[],
): OperationalTimelineEvent[] {
  const events: OperationalTimelineEvent[] = []
  const auditRows = detail.sections.audit_log ?? []
  const monitoringTrendRows = detail.sections.monitoring_trend_points ?? []
  const monitoringChangeRows = detail.sections.monitoring_changes ?? []
  const monitoringAlertRows = detail.sections.monitoring_alerts ?? []
  const cloudValidationRows = detail.sections.cloud_validation_results ?? []
  const keyFindingRows = detail.sections.key_scanner_findings ?? []
  const secretLifecycleRows = detail.sections.secret_lifecycle_items ?? []
  const reportableFindingRows = [
    ...(detail.sections.vulnerability_findings ?? []),
    ...(detail.sections.passive_vulns ?? []),
  ]
  const reportHistory = detail.report_history ?? (detail.report_summary ? [detail.report_summary] : [])

  auditRows.slice(0, 8).forEach((row, index) => {
    events.push({
      id: `audit-${index}`,
      category: 'Audit',
      time: sectionRowTime(row, ['When', 'Created', 'Updated']),
      title: row.Action || 'Audit event',
      summary: [row.Phase, row.Module, row.Target, row.Result].filter(Boolean).join(' · '),
      provenance: row.Module || row.Phase || 'audit_log',
      status: row.Result,
    })
  })

  monitoringTrendRows.slice(0, 4).forEach((row, index) => {
    events.push({
      id: `monitoring-trend-${index}`,
      category: 'Monitoring',
      time: sectionRowTime(row, ['Observed']),
      title: `Snapshot ${row.Snapshot || '-'}`,
      summary: `assets ${row.Assets || '0'} · findings ${row.Findings || '0'} · changes +${row.Added || '0'}/-${row.Removed || '0'}/${row.Changed || '0'}`,
      provenance: 'monitoring_trend_points',
      status: `alerts ${row.Alerts || '0'} open ${row['Open Alerts'] || '0'}`,
    })
  })

  monitoringChangeRows.slice(0, 6).forEach((row, index) => {
    events.push({
      id: `monitoring-change-${index}`,
      category: 'Monitoring change',
      time: sectionRowTime(row, ['Seen', 'Observed', 'Created', 'Updated']),
      title: [row.Change, row.Entity].filter(Boolean).join(' ') || 'Monitoring change',
      summary: [
        row.Before ? `before ${row.Before}` : '',
        row.After ? `after ${row.After}` : '',
        row.Snapshot ? `snapshot ${row.Snapshot}` : '',
      ]
        .filter(Boolean)
        .join(' · '),
      provenance: 'monitoring_changes',
      status: row.Change,
      severity: row.Severity,
    })
  })

  monitoringAlertRows.slice(0, 5).forEach((row, index) => {
    events.push({
      id: `monitoring-alert-${index}`,
      category: 'Monitoring alert',
      time: sectionRowTime(row, ['Updated', 'Created']),
      title: row.Title || row.Type || 'Monitoring alert',
      summary: [row.Entity, row.Type, row.Snapshot ? `snapshot ${row.Snapshot}` : ''].filter(Boolean).join(' · '),
      provenance: 'monitoring_alerts',
      status: row.Status,
      severity: row.Severity,
    })
  })

  cloudValidationRows.slice(0, 5).forEach((row, index) => {
    events.push({
      id: `cloud-validation-${index}`,
      category: 'Cloud validation',
      time: sectionRowTime(row, ['Checked', 'Updated']),
      title: row.Asset || 'Cloud asset',
      summary: [row.Status, row.Evidence, row.Notes].filter(Boolean).join(' · '),
      method: row.Method,
      provenance: row.Type || 'cloud_validation_results',
      reportability: cloudReportabilityLabel(row.Reportable),
      status: row.Status,
    })
  })

  keyFindingRows.slice(0, 5).forEach((row, index) => {
    events.push({
      id: `key-validation-${index}`,
      category: 'Secret validation',
      time: sectionRowTime(row, ['Validated', 'Seen']),
      title: [row.Service, row.Pattern].filter(Boolean).join(' / ') || 'Secret finding',
      summary: [row['Validation Status'], row['Validation Proof'], row.Repository].filter(Boolean).join(' · '),
      method: row['Validation Method'],
      provenance: row.Backend || row.Source || 'key_scanner_findings',
      reportability: validationReportabilityLabel(row['Validation Status']),
      status: row.State || row['Validation Status'],
    })
  })

  secretLifecycleRows.slice(0, 5).forEach((row, index) => {
    events.push({
      id: `secret-lifecycle-${index}`,
      category: 'Secret lifecycle',
      time: sectionRowTime(row, ['Updated']),
      title: [row.Service, row.Pattern].filter(Boolean).join(' / ') || `Key ${row.Key || '-'}`,
      summary: [
        row.Owner && row.Owner !== '-' ? `owner ${row.Owner}` : '',
        row.Remediation && row.Remediation !== '-' ? `remediation ${row.Remediation}` : '',
        row.Suppressed === 'yes' ? 'suppressed' : '',
      ]
        .filter(Boolean)
        .join(' · '),
      method: row['Owner Source'],
      provenance: 'secret_lifecycle_items',
      reportability: row.Lifecycle,
      status: row.Lifecycle,
    })
  })

  reportableFindingRows.slice(0, 6).forEach((row, index) => {
    const isFalsePositive = (row['False+'] || '').trim().toLowerCase() === 'yes'
    events.push({
      id: `reportable-finding-${index}`,
      category: 'Reportable finding',
      time: sectionRowTime(row, ['Seen', 'Found', 'Created', 'Updated']),
      title: row.Title || row.Vuln || row.Plugin || row.Type || 'Finding',
      summary: [
        row.Target || row.URL,
        row['Validation Proof'] || row['Validation Notes'],
        row.Verified ? `verified ${row.Verified}` : '',
      ]
        .filter(Boolean)
        .join(' · '),
      method: row['Validation Method'] || (row.Plugin ? 'passive scanner' : undefined),
      provenance: row.Type || row.Plugin || 'vulnerability_findings',
      reportability: isFalsePositive ? 'non-reportable false positive' : 'reportable finding',
      status: row['Validation Status'] || row.Verified || row.Type,
      severity: row.Severity,
    })
  })

  const activeValidationSourceRows = activeValidationRuns.length
    ? activeValidationRuns.map(activeValidationRunRow)
    : activeValidationRunRows
  activeValidationSourceRows.slice(0, 5).forEach((row, index) => {
    events.push({
      id: `active-validation-${index}`,
      category: 'Active validation',
      time: sectionRowTime(row, ['Completed', 'Updated']),
      title: row.Target || `Run ${row.Run || index + 1}`,
      summary: [row.Result, row.Safety, row.Error && row.Error !== '-' ? row.Error : ''].filter(Boolean).join(' · '),
      method: row.Method,
      provenance: row.Proof || 'active_validation_runs',
      reportability: row.Coverage ? `coverage ${row.Coverage}` : undefined,
      status: row.Status,
    })
  })

  remediationRows.slice(0, 5).forEach((row, index) => {
    events.push({
      id: `remediation-${index}`,
      category: 'Remediation',
      time: sectionRowTime(row, ['Updated', 'SLA']),
      title: row.Title || row.Finding || 'Remediation item',
      summary: [row.Owner ? `owner ${row.Owner}` : '', row.Retest ? `retest ${row.Retest}` : '', row.Ticket ? `ticket ${row.Ticket}` : '']
        .filter(Boolean)
        .join(' · '),
      provenance: row.Finding || 'remediation_items',
      reportability: row.Status === 'risk_accepted' ? 'risk accepted' : undefined,
      status: row.Status,
      severity: row.Severity,
    })
  })

  reportHistory.slice(0, 3).forEach((report, index) => {
    events.push({
      id: `report-${index}`,
      category: 'Report',
      time: report.generated_at || '',
      title: report.artifact_name || report.family_stem || 'Report generated',
      summary: [
        report.rendered_provider || report.provider || report.render_backend,
        report.export_count !== undefined ? `${report.export_count} exports` : '',
        report.findings_checksum ? `checksum ${report.findings_checksum}` : '',
      ]
        .filter(Boolean)
        .join(' · '),
      provenance: report.raw_export ? 'raw export fallback' : 'report family',
      reportability:
        report.reportable_validation_count !== undefined
          ? `${report.reportable_validation_count} reportable / ${report.unreportable_validation_count ?? 0} inventory`
          : undefined,
      status: report.fallback_reason || report.report_write_error || report.format,
    })
  })

  return events
    .map(redactOperationalTimelineEvent)
    .filter((event) => event.time || event.title || event.summary)
    .sort((left, right) => timestampValue(right.time) - timestampValue(left.time))
    .slice(0, 18)
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

function riskReviewLabel(status: string): string {
  return status.trim().toLowerCase().replaceAll('_', ' ') || 'not accepted'
}

function riskReviewTone(status: string): string {
  const normalized = status.trim().toLowerCase()
  if (normalized === 'current') {
    return 'is-live'
  }
  if (normalized === 'expiring_soon') {
    return 'is-stable'
  }
  if (['expired', 'missing_expiry', 'invalid_expiry'].includes(normalized)) {
    return 'is-danger'
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

function matchesReportState(item: EngagementSummary, filter: string): boolean {
  if (filter === 'ALL') {
    return true
  }
  if (filter === 'PRIOR') {
    return Boolean(item.has_prior_report_generations)
  }
  if (filter === 'RAW_EXPORT') {
    return item.report_summary?.raw_export === true
  }
  if (filter === 'FALLBACK') {
    return Boolean(item.report_summary?.fallback_reason)
  }
  if (filter === 'DEGRADED') {
    return Boolean(item.report_summary?.report_write_error)
  }
  return true
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
  reportStateFilter?: string
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
    (state.reportStateFilter ?? 'ALL') === 'ALL' &&
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
  return redactDashboardText(JSON.stringify(
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
  ))
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
  return Object.entries(metadata).map(([key, value]) => [key, redactDashboardText(value)])
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
  const [reportStateFilter, setReportStateFilter] = useState(() => readOverviewFilters().reportStateFilter ?? 'ALL')
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
  const [workspaceIndex, setWorkspaceIndex] = useState<WorkspaceIndex | null>(null)
  const [workspaceMembers, setWorkspaceMembers] = useState<WorkspaceMembersOverview | null>(null)
  const [workspaceLoadError, setWorkspaceLoadError] = useState('')
  const [selectedWorkspaceId, setSelectedWorkspaceId] = useState('')
  const [workspaceEditId, setWorkspaceEditId] = useState('')
  const [workspaceName, setWorkspaceName] = useState('')
  const [workspaceMetadata, setWorkspaceMetadata] = useState('')
  const [workspaceMemberSubject, setWorkspaceMemberSubject] = useState('')
  const [workspaceMemberRole, setWorkspaceMemberRole] = useState('operator')
  const [workspaceMemberPermissions, setWorkspaceMemberPermissions] = useState('')
  const [workspaceBusy, setWorkspaceBusy] = useState(false)
  const [workspaceMessage, setWorkspaceMessage] = useState('')
  const [workspaceError, setWorkspaceError] = useState('')
  const deferredSearch = useDeferredValue(search)
  const query = deferredSearch.trim().toLowerCase()
  const workspaceRows = workspaceIndex?.items.map(workspaceRecordRow) ?? []
  const selectedWorkspace =
    workspaceIndex?.items.find((workspace) => workspace.workspace_id === selectedWorkspaceId) ??
    workspaceIndex?.items[0] ??
    null
  const workspaceMemberRows = workspaceMembers?.items.map(workspaceMemberRow) ?? []
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
      if (!matchesReportState(item, reportStateFilter)) {
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
      reportStateFilter,
      updatedAfter,
      updatedBefore,
      recencyFilter,
      sortBy,
    })
  }, [search, statusFilter, severityFilter, tagFilter, reportStateFilter, updatedAfter, updatedBefore, recencyFilter, sortBy])

  useEffect(() => {
    let cancelled = false
    if (!liveToken) {
      setWorkspaceIndex(null)
      setWorkspaceMembers(null)
      setWorkspaceLoadError('')
      setSelectedWorkspaceId('')
      return
    }
    const token = liveToken

    async function hydrateWorkspaces() {
      try {
        const nextWorkspaces = await loadWorkspaces(token)
        if (cancelled) {
          return
        }
        setWorkspaceIndex(nextWorkspaces)
        setWorkspaceLoadError('')
        const nextWorkspaceId =
          selectedWorkspaceId && nextWorkspaces.items.some((item) => item.workspace_id === selectedWorkspaceId)
            ? selectedWorkspaceId
            : nextWorkspaces.items[0]?.workspace_id || ''
        setSelectedWorkspaceId(nextWorkspaceId)
      } catch (error) {
        if (!cancelled) {
          setWorkspaceIndex(null)
          setWorkspaceMembers(null)
          setWorkspaceLoadError(error instanceof Error ? error.message : 'unable to load workspaces')
        }
      }
    }

    void hydrateWorkspaces()
    return () => {
      cancelled = true
    }
  }, [liveToken, selectedWorkspaceId])

  useEffect(() => {
    setWorkspaceEditId(selectedWorkspace?.workspace_id ?? '')
    setWorkspaceName(selectedWorkspace?.name ?? '')
    setWorkspaceMetadata(
      selectedWorkspace ? JSON.stringify(selectedWorkspace.metadata ?? {}, null, 2) : '',
    )
  }, [selectedWorkspace])

  useEffect(() => {
    let cancelled = false
    if (!liveToken || !selectedWorkspaceId) {
      setWorkspaceMembers(null)
      return
    }
    const token = liveToken

    async function hydrateMembers() {
      try {
        const nextMembers = await loadWorkspaceMembers(selectedWorkspaceId, token)
        if (!cancelled) {
          setWorkspaceMembers(nextMembers)
          setWorkspaceLoadError('')
        }
      } catch (error) {
        if (!cancelled) {
          setWorkspaceMembers(null)
          setWorkspaceLoadError(error instanceof Error ? error.message : 'unable to load workspace members')
        }
      }
    }

    void hydrateMembers()
    return () => {
      cancelled = true
    }
  }, [liveToken, selectedWorkspaceId])

  async function refreshWorkspaceAdmin(workspaceId?: string): Promise<void> {
    if (!liveToken) {
      return
    }
    const nextWorkspaces = await loadWorkspaces(liveToken)
    const nextWorkspaceId =
      workspaceId && nextWorkspaces.items.some((item) => item.workspace_id === workspaceId)
        ? workspaceId
        : selectedWorkspaceId && nextWorkspaces.items.some((item) => item.workspace_id === selectedWorkspaceId)
          ? selectedWorkspaceId
          : nextWorkspaces.items[0]?.workspace_id || ''
    const nextMembers = nextWorkspaceId ? await loadWorkspaceMembers(nextWorkspaceId, liveToken) : null
    setWorkspaceIndex(nextWorkspaces)
    setSelectedWorkspaceId(nextWorkspaceId)
    setWorkspaceMembers(nextMembers)
    setWorkspaceLoadError('')
  }

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
          ...(selectedWorkspaceId ? { workspace_id: selectedWorkspaceId } : {}),
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

  async function handleWorkspaceUpsert(): Promise<void> {
    if (!liveToken) {
      setWorkspaceError('Unlock live API access before managing workspaces.')
      return
    }
    const workspaceId = workspaceEditId.trim()
    if (!workspaceId) {
      setWorkspaceError('Workspace ID is required.')
      return
    }
    setWorkspaceBusy(true)
    setWorkspaceError('')
    setWorkspaceMessage('')
    try {
      await requestWorkspaceUpsert(liveToken, {
        workspaceId,
        name: workspaceName.trim(),
        metadata: parseWorkspaceMetadata(workspaceMetadata),
      })
      await refreshWorkspaceAdmin(workspaceId)
      setWorkspaceMessage(`${workspaceId} saved.`)
    } catch (error) {
      setWorkspaceError(error instanceof Error ? error.message : 'unable to save workspace')
    } finally {
      setWorkspaceBusy(false)
    }
  }

  async function handleWorkspaceMemberUpsert(): Promise<void> {
    if (!liveToken) {
      setWorkspaceError('Unlock live API access before managing workspace members.')
      return
    }
    const workspaceId = selectedWorkspaceId.trim()
    const subject = workspaceMemberSubject.trim()
    if (!workspaceId || !subject) {
      setWorkspaceError('Workspace and subject are required.')
      return
    }
    setWorkspaceBusy(true)
    setWorkspaceError('')
    setWorkspaceMessage('')
    try {
      const customPermissions = splitListInput(workspaceMemberPermissions)
      await requestWorkspaceMemberUpsert(liveToken, {
        workspaceId,
        subject,
        role: workspaceMemberRole,
        ...(customPermissions.length ? { permissions: customPermissions } : {}),
      })
      await refreshWorkspaceAdmin(workspaceId)
      setWorkspaceMemberSubject('')
      setWorkspaceMemberPermissions('')
      setWorkspaceMessage(`${subject} saved.`)
    } catch (error) {
      setWorkspaceError(error instanceof Error ? error.message : 'unable to save workspace member')
    } finally {
      setWorkspaceBusy(false)
    }
  }

  async function handleWorkspaceMemberDelete(subject: string): Promise<void> {
    if (!liveToken || !selectedWorkspaceId) {
      setWorkspaceError('Unlock live API access before managing workspace members.')
      return
    }
    setWorkspaceBusy(true)
    setWorkspaceError('')
    setWorkspaceMessage('')
    try {
      const result = await requestWorkspaceMemberDelete(liveToken, selectedWorkspaceId, subject)
      await refreshWorkspaceAdmin(selectedWorkspaceId)
      setWorkspaceMessage(`${subject} ${result.status}.`)
    } catch (error) {
      setWorkspaceError(error instanceof Error ? error.message : 'unable to delete workspace member')
    } finally {
      setWorkspaceBusy(false)
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
              <span>Report state</span>
              <select value={reportStateFilter} onChange={(event) => setReportStateFilter(event.target.value)}>
                <option value="ALL">All report states</option>
                <option value="PRIOR">Has prior reports</option>
                <option value="RAW_EXPORT">Raw export fallback</option>
                <option value="FALLBACK">Fallback reason</option>
                <option value="DEGRADED">Write degraded</option>
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
            <label className="filter-shell">
              <span>Workspace</span>
              <select
                value={selectedWorkspaceId}
                onChange={(event) => setSelectedWorkspaceId(event.target.value)}
              >
                {workspaceIndex?.items.length ? (
                  workspaceIndex.items.map((workspace) => (
                    <option key={workspace.workspace_id} value={workspace.workspace_id}>
                      {workspace.workspace_id}
                    </option>
                  ))
                ) : (
                  <option value="">default</option>
                )}
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

        <section className="live-compose" id="workspace-admin">
          <div>
            <p className="section-kicker">Workspace Administration</p>
            <h3>Workspaces and members</h3>
            <p className="card-copy">{workspaceIndex?.generated_at || 'Live workspace data'}</p>
          </div>
          <div className="compose-grid">
            <label className="filter-shell">
              <span>Active workspace</span>
              <select
                value={selectedWorkspaceId}
                onChange={(event) => setSelectedWorkspaceId(event.target.value)}
                disabled={!liveToken || workspaceBusy}
              >
                {workspaceIndex?.items.length ? (
                  workspaceIndex.items.map((workspace) => (
                    <option key={workspace.workspace_id} value={workspace.workspace_id}>
                      {workspace.workspace_id}
                    </option>
                  ))
                ) : (
                  <option value="">No workspace</option>
                )}
              </select>
            </label>
            <label className="search-shell">
              <span>Workspace ID</span>
              <input
                value={workspaceEditId}
                onChange={(event) => setWorkspaceEditId(event.target.value)}
                placeholder="default"
              />
            </label>
            <label className="search-shell">
              <span>Name</span>
              <input
                value={workspaceName}
                onChange={(event) => setWorkspaceName(event.target.value)}
                placeholder="Default Workspace"
              />
            </label>
            <label className="seed-compose-shell">
              <span>Metadata JSON</span>
              <textarea
                value={workspaceMetadata}
                onChange={(event) => setWorkspaceMetadata(event.target.value)}
                placeholder='{"owner":"security"}'
                rows={4}
              />
            </label>
            <div className="compose-actions">
              <button
                className="token-action"
                disabled={!liveToken || workspaceBusy}
                onClick={() => void handleWorkspaceUpsert()}
                type="button"
              >
                {workspaceBusy ? 'Saving...' : 'Save workspace'}
              </button>
              <span className="muted-copy">{liveToken ? 'Live API active' : 'Unlock live mode'}</span>
            </div>
            <div className="table-shell workspace-admin-table">
              <DataList rows={workspaceRows} emptyText="No workspace rows loaded." />
            </div>
            <label className="search-shell">
              <span>Subject</span>
              <input
                value={workspaceMemberSubject}
                onChange={(event) => setWorkspaceMemberSubject(event.target.value)}
                placeholder="operator@example.com"
              />
            </label>
            <label className="filter-shell">
              <span>Role</span>
              <select
                value={workspaceMemberRole}
                onChange={(event) => setWorkspaceMemberRole(event.target.value)}
              >
                <option value="owner">owner</option>
                <option value="admin">admin</option>
                <option value="operator">operator</option>
                <option value="viewer">viewer</option>
              </select>
            </label>
            <label className="search-shell tags-compose-shell">
              <span>Custom permissions</span>
              <input
                value={workspaceMemberPermissions}
                onChange={(event) => setWorkspaceMemberPermissions(event.target.value)}
                placeholder="workspaces:read, workspaces:members:write"
              />
            </label>
            <div className="compose-actions">
              <button
                className="token-action"
                disabled={!liveToken || workspaceBusy || !selectedWorkspaceId}
                onClick={() => void handleWorkspaceMemberUpsert()}
                type="button"
              >
                {workspaceBusy ? 'Saving...' : 'Save member'}
              </button>
              {workspaceMessage ? <span className="muted-copy">{workspaceMessage}</span> : null}
              {workspaceError || workspaceLoadError ? (
                <span className="auth-error">{workspaceError || workspaceLoadError}</span>
              ) : null}
            </div>
            <div className="table-shell workspace-admin-table">
              {workspaceMembers?.items.length ? (
                <div className="mini-table">
                  <div className="mini-table-head">
                    <span>Subject</span>
                    <span>Role</span>
                    <span>Permissions</span>
                    <span>Updated</span>
                    <span>Action</span>
                  </div>
                  {workspaceMembers.items.map((member) => (
                    <div className="mini-table-row" key={`${member.workspace_id}:${member.subject}`}>
                      <span>{member.subject || '-'}</span>
                      <span>{member.role || '-'}</span>
                      <span>{member.permissions.join(', ') || '-'}</span>
                      <span>{member.updated_at || '-'}</span>
                      <span>
                        <button
                          className="token-action is-secondary"
                          disabled={!liveToken || workspaceBusy}
                          onClick={() => void handleWorkspaceMemberDelete(member.subject)}
                          type="button"
                        >
                          Remove
                        </button>
                      </span>
                    </div>
                  ))}
                </div>
              ) : (
                <DataList rows={workspaceMemberRows} emptyText="No workspace members loaded." />
              )}
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
              {item.report_summary ? (
                <div className="card-metrics">
                  <span>
                    report{' '}
                    {item.report_summary.rendered_provider
                      || item.report_summary.provider
                      || item.report_summary.render_backend
                      || '-'}
                  </span>
                  {item.report_summary.render_backend
                  && item.report_summary.render_backend !== (
                    item.report_summary.rendered_provider || item.report_summary.provider
                  ) ? (
                    <span>backend {item.report_summary.render_backend}</span>
                  ) : null}
                  <span>
                    {formatCount(
                      item.report_summary.export_count ?? item.report_summary.available_exports?.length,
                    )}{' '}
                    exports
                  </span>
                  {item.report_family_count && item.report_family_count > 1 ? (
                    <span>{formatCount(item.report_family_count)} families</span>
                  ) : null}
                  {item.report_summary.raw_export ? <span>raw export</span> : null}
                  {item.report_summary.fallback_reason ? <span>fallback</span> : null}
                </div>
              ) : null}
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
  const [activeValidation, setActiveValidation] = useState<ActiveValidationSnapshot | null>(null)
  const [activeValidationLoadError, setActiveValidationLoadError] = useState('')
  const [remediationOverview, setRemediationOverview] = useState<RemediationOverview | null>(null)
  const [remediationLoadError, setRemediationLoadError] = useState('')
  const [retentionOverview, setRetentionOverview] = useState<RetentionOverview | null>(null)
  const [retentionLoadError, setRetentionLoadError] = useState('')
  const [connectorCatalogOverview, setConnectorCatalogOverview] = useState<ConnectorCatalogOverview | null>(null)
  const [connectorCatalogLoadError, setConnectorCatalogLoadError] = useState('')
  const [connectorSecretsOverview, setConnectorSecretsOverview] = useState<ConnectorSecretsOverview | null>(null)
  const [connectorSecretsLoadError, setConnectorSecretsLoadError] = useState('')
  const [workspaceAuditOverview, setWorkspaceAuditOverview] = useState<WorkspaceAuditOverview | null>(null)
  const [workspaceAuditLoadError, setWorkspaceAuditLoadError] = useState('')
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
    const [
      nextDetail,
      nextLogs,
      nextSeeds,
      nextActiveValidation,
      nextRemediation,
      nextRetention,
      nextConnectorCatalog,
      nextConnectorSecrets,
    ] = await Promise.all([
      loadDetail(slug, summaries, liveToken),
      loadEngagementLogs(slug, liveToken),
      refreshSeeds ? loadLiveSeeds(slug, liveToken) : Promise.resolve<SeedRecord[] | null>(null),
      loadActiveValidationForPanel(slug, liveToken),
      loadRemediationForPanel(slug, liveToken),
      loadRetentionForPanel(slug, liveToken),
      loadConnectorCatalogForPanel(slug, liveToken),
      loadConnectorSecretsForPanel(slug, liveToken),
      refreshIndex ? onIndexRefresh().then(() => true) : Promise.resolve(false),
    ])
    const nextWorkspaceAudit = await loadWorkspaceAuditForPanel(nextDetail.workspace_id || 'default', liveToken)
    const nextTail = nextLogs.length ? await loadRunLogTail(nextLogs[0], liveToken) : null
    startTransition(() => {
      setDetail(nextDetail)
      if (nextSeeds !== null) {
        setLiveSeeds(nextSeeds)
      }
      setLiveLogs(nextLogs)
      setLiveLogTail(nextTail)
      setActiveValidation(nextActiveValidation.snapshot)
      setActiveValidationLoadError(nextActiveValidation.error)
      setRemediationOverview(nextRemediation.overview)
      setRemediationLoadError(nextRemediation.error)
      setRetentionOverview(nextRetention.overview)
      setRetentionLoadError(nextRetention.error)
      setConnectorCatalogOverview(nextConnectorCatalog.overview)
      setConnectorCatalogLoadError(nextConnectorCatalog.error)
      setConnectorSecretsOverview(nextConnectorSecrets.overview)
      setConnectorSecretsLoadError(nextConnectorSecrets.error)
      setWorkspaceAuditOverview(nextWorkspaceAudit.overview)
      setWorkspaceAuditLoadError(nextWorkspaceAudit.error)
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
            const [
              seeds,
              logs,
              activeValidationSnapshot,
              remediationSnapshot,
              retentionSnapshot,
              connectorCatalogSnapshot,
              connectorSecretsSnapshot,
              workspaceAuditSnapshot,
            ] = await Promise.all([
              loadLiveSeeds(slug, liveToken),
              loadEngagementLogs(slug, liveToken),
              loadActiveValidationForPanel(slug, liveToken),
              loadRemediationForPanel(slug, liveToken),
              loadRetentionForPanel(slug, liveToken),
              loadConnectorCatalogForPanel(slug, liveToken),
              loadConnectorSecretsForPanel(slug, liveToken),
              loadWorkspaceAuditForPanel(payload.workspace_id || 'default', liveToken),
            ])
            const tail = logs.length ? await loadRunLogTail(logs[0], liveToken) : null
            if (!cancelled) {
              setLiveSeeds(seeds)
              setLiveLogs(logs)
              setLiveLogTail(tail)
              setActiveValidation(activeValidationSnapshot.snapshot)
              setActiveValidationLoadError(activeValidationSnapshot.error)
              setRemediationOverview(remediationSnapshot.overview)
              setRemediationLoadError(remediationSnapshot.error)
              setRetentionOverview(retentionSnapshot.overview)
              setRetentionLoadError(retentionSnapshot.error)
              setConnectorCatalogOverview(connectorCatalogSnapshot.overview)
              setConnectorCatalogLoadError(connectorCatalogSnapshot.error)
              setConnectorSecretsOverview(connectorSecretsSnapshot.overview)
              setConnectorSecretsLoadError(connectorSecretsSnapshot.error)
              setWorkspaceAuditOverview(workspaceAuditSnapshot.overview)
              setWorkspaceAuditLoadError(workspaceAuditSnapshot.error)
            }
          } else {
            setLiveSeeds([])
            setLiveLogs([])
            setLiveLogTail(null)
            setActiveValidation(null)
            setActiveValidationLoadError('')
            setRemediationOverview(null)
            setRemediationLoadError('')
            setRetentionOverview(null)
            setRetentionLoadError('')
            setConnectorCatalogOverview(null)
            setConnectorCatalogLoadError('')
            setConnectorSecretsOverview(null)
            setConnectorSecretsLoadError('')
            setWorkspaceAuditOverview(null)
            setWorkspaceAuditLoadError('')
          }
        }
      } catch (err) {
        if (!cancelled) {
          setDetail(SAMPLE_BY_SLUG.get(slug) ?? null)
          setLiveSeeds([])
          setLiveLogs([])
          setLiveLogTail(null)
          setActiveValidation(null)
          setActiveValidationLoadError('')
          setRemediationOverview(null)
          setRemediationLoadError('')
          setRetentionOverview(null)
          setRetentionLoadError('')
          setConnectorCatalogOverview(null)
          setConnectorCatalogLoadError('')
          setConnectorSecretsOverview(null)
          setConnectorSecretsLoadError('')
          setWorkspaceAuditOverview(null)
          setWorkspaceAuditLoadError('')
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
        `${window.location.protocol === 'https:' ? 'wss://' : 'ws://'}${window.location.host}/ws/progress?engagement_id=${encodeURIComponent(
          String(engagementId),
        )}`,
        ['forge-progress', liveToken],
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

  async function handleUpdateRemediation(payload: RemediationUpdatePayload): Promise<void> {
    if (!slug || !liveToken) {
      throw new Error('Unlock live API access before updating remediation.')
    }
    await requestRemediationUpdate(slug, liveToken, payload)
    await refreshLiveSnapshot({ refreshSeeds: false, refreshIndex: true })
  }

  async function handleSyncRemediationTicket(
    itemId: number,
    payload: RemediationTicketSyncPayload,
  ): Promise<RemediationSyncResult> {
    if (!slug || !liveToken) {
      throw new Error('Unlock live API access before syncing remediation tickets.')
    }
    const result = await requestRemediationTicketSync(slug, liveToken, itemId, payload)
    await refreshLiveSnapshot({ refreshSeeds: false, refreshIndex: true })
    return result
  }

  async function handlePropagateRemediationOwners(
    overwrite: boolean,
    conflictPolicy: string,
    minConfidence: number,
  ): Promise<RemediationPropagationResult> {
    if (!slug || !liveToken) {
      throw new Error('Unlock live API access before propagating remediation owners.')
    }
    const result = await requestRemediationOwnerPropagation(
      slug,
      liveToken,
      overwrite,
      conflictPolicy,
      minConfidence,
    )
    await refreshLiveSnapshot({ refreshSeeds: false, refreshIndex: true })
    return result
  }

  async function handleDraftRemediationFromGraph(): Promise<RemediationGraphDraftResult> {
    if (!slug || !liveToken) {
      throw new Error('Unlock live API access before drafting graph remediation.')
    }
    const result = await requestRemediationGraphDraft(slug, liveToken)
    await refreshLiveSnapshot({ refreshSeeds: false, refreshIndex: true })
    return result
  }

  async function handleReviewRemediationOwner(
    itemId: number,
    decision: string,
    note = '',
  ): Promise<RemediationOwnerReviewResult> {
    if (!slug || !liveToken) {
      throw new Error('Unlock live API access before reviewing remediation owners.')
    }
    const result = await requestRemediationOwnerReview(slug, liveToken, itemId, decision, note)
    await refreshLiveSnapshot({ refreshSeeds: false, refreshIndex: true })
    return result
  }

  async function handleResolveAssetGraphConflict(
    conflict: AssetGraphOwnershipConflict,
    owner: AssetGraphConflictOwner,
  ): Promise<AssetGraphConflictResolutionResult> {
    if (!slug || !liveToken) {
      throw new Error('Unlock live API access before resolving asset ownership conflicts.')
    }
    const result = await requestAssetGraphConflictResolution(slug, liveToken, conflict, owner)
    await refreshLiveSnapshot({ refreshSeeds: false, refreshIndex: true })
    return result
  }

  async function handleRequestRemediationRetest(
    payload: RemediationRetestRequestPayload,
  ): Promise<RemediationRetestRequestResult> {
    if (!slug || !liveToken) {
      throw new Error('Unlock live API access before requesting remediation retest.')
    }
    const result = await requestRemediationRetest(slug, liveToken, payload)
    await refreshLiveSnapshot({ refreshSeeds: false, refreshIndex: true })
    return result
  }

  async function handleRetentionPreview(): Promise<RetentionRunResult> {
    if (!slug || !liveToken) {
      throw new Error('Unlock live API access before previewing retention.')
    }
    const result = await requestRetentionPreview(slug, liveToken)
    await refreshLiveSnapshot({ refreshSeeds: false, refreshIndex: true })
    return result
  }

  async function handleRetentionApply(): Promise<RetentionRunResult> {
    if (!slug || !liveToken) {
      throw new Error('Unlock live API access before applying retention.')
    }
    const result = await requestRetentionApply(slug, liveToken)
    await refreshLiveSnapshot({ refreshSeeds: false, refreshIndex: true })
    return result
  }

  async function handleConnectorSecretStore(payload: ConnectorSecretStorePayload): Promise<void> {
    if (!slug || !liveToken) {
      throw new Error('Unlock live API access before storing connector secrets.')
    }
    await requestConnectorSecretStore(slug, liveToken, payload)
    await refreshLiveSnapshot({ refreshSeeds: false, refreshIndex: true })
  }

  async function handleCreateActiveValidation(payload: ActiveValidationCreatePayload): Promise<void> {
    if (!slug || !liveToken) {
      throw new Error('Unlock live API access before creating active-validation jobs.')
    }
    await requestActiveValidationCreate(slug, liveToken, payload)
    await refreshLiveSnapshot({ refreshSeeds: false, refreshIndex: true })
  }

  async function handleApproveActiveValidation(payload: ActiveValidationApprovalPayload): Promise<void> {
    if (!slug || !liveToken) {
      throw new Error('Unlock live API access before approving active-validation jobs.')
    }
    await requestActiveValidationApprove(slug, liveToken, payload)
    await refreshLiveSnapshot({ refreshSeeds: false, refreshIndex: true })
  }

  async function handleRunActiveValidation(jobId: number, allowLive: boolean): Promise<void> {
    if (!slug || !liveToken) {
      throw new Error('Unlock live API access before running active-validation jobs.')
    }
    await requestActiveValidationRun(slug, liveToken, jobId, allowLive)
    await refreshLiveSnapshot({ refreshSeeds: false, refreshIndex: true })
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
      activeValidation={activeValidation}
      activeValidationLoadError={activeValidationLoadError}
      remediationOverview={remediationOverview}
      remediationLoadError={remediationLoadError}
      retentionOverview={retentionOverview}
      retentionLoadError={retentionLoadError}
      connectorCatalogOverview={connectorCatalogOverview}
      connectorCatalogLoadError={connectorCatalogLoadError}
      connectorSecretsOverview={connectorSecretsOverview}
      connectorSecretsLoadError={connectorSecretsLoadError}
      workspaceAuditOverview={workspaceAuditOverview}
      workspaceAuditLoadError={workspaceAuditLoadError}
      progressNotice={progressNotice}
      onAddSeed={handleAddSeed}
      onDeleteSeed={handleDeleteSeed}
      onUpdateEngagement={handleUpdateEngagement}
      onLaunchKillChain={handleLaunchKillChain}
      onRestartKillChain={handleRestartKillChain}
      onPauseKillChain={handlePauseKillChain}
      onStopKillChain={handleStopKillChain}
      onResumeKillChain={handleResumeKillChain}
      onUpdateRemediation={handleUpdateRemediation}
      onSyncRemediationTicket={handleSyncRemediationTicket}
      onPropagateRemediationOwners={handlePropagateRemediationOwners}
      onDraftRemediationFromGraph={handleDraftRemediationFromGraph}
      onReviewRemediationOwner={handleReviewRemediationOwner}
      onResolveAssetGraphConflict={handleResolveAssetGraphConflict}
      onRequestRemediationRetest={handleRequestRemediationRetest}
      onPreviewRetention={handleRetentionPreview}
      onApplyRetention={handleRetentionApply}
      onStoreConnectorSecret={handleConnectorSecretStore}
      onCreateActiveValidation={handleCreateActiveValidation}
      onApproveActiveValidation={handleApproveActiveValidation}
      onRunActiveValidation={handleRunActiveValidation}
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
  activeValidation,
  activeValidationLoadError,
  remediationOverview,
  remediationLoadError,
  retentionOverview,
  retentionLoadError,
  connectorCatalogOverview,
  connectorCatalogLoadError,
  connectorSecretsOverview,
  connectorSecretsLoadError,
  workspaceAuditOverview,
  workspaceAuditLoadError,
  progressNotice,
  onAddSeed,
  onDeleteSeed,
  onUpdateEngagement,
  onLaunchKillChain,
  onRestartKillChain,
  onPauseKillChain,
  onStopKillChain,
  onResumeKillChain,
  onUpdateRemediation,
  onSyncRemediationTicket,
  onPropagateRemediationOwners,
  onDraftRemediationFromGraph,
  onReviewRemediationOwner,
  onResolveAssetGraphConflict,
  onRequestRemediationRetest,
  onPreviewRetention,
  onApplyRetention,
  onStoreConnectorSecret,
  onCreateActiveValidation,
  onApproveActiveValidation,
  onRunActiveValidation,
}: {
  detail: EngagementDetail
  loading: boolean
  error: string
  liveToken: string | null
  liveSeeds: SeedRecord[]
  liveLogs: RunLog[]
  liveLogTail: RunLogTail | null
  activeValidation: ActiveValidationSnapshot | null
  activeValidationLoadError: string
  remediationOverview: RemediationOverview | null
  remediationLoadError: string
  retentionOverview: RetentionOverview | null
  retentionLoadError: string
  connectorCatalogOverview: ConnectorCatalogOverview | null
  connectorCatalogLoadError: string
  connectorSecretsOverview: ConnectorSecretsOverview | null
  connectorSecretsLoadError: string
  workspaceAuditOverview: WorkspaceAuditOverview | null
  workspaceAuditLoadError: string
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
  onUpdateRemediation: (payload: RemediationUpdatePayload) => Promise<void>
  onSyncRemediationTicket: (
    itemId: number,
    payload: RemediationTicketSyncPayload,
  ) => Promise<RemediationSyncResult>
  onPropagateRemediationOwners: (
    overwrite: boolean,
    conflictPolicy: string,
    minConfidence: number,
  ) => Promise<RemediationPropagationResult>
  onDraftRemediationFromGraph: () => Promise<RemediationGraphDraftResult>
  onReviewRemediationOwner: (
    itemId: number,
    decision: string,
    note?: string,
  ) => Promise<RemediationOwnerReviewResult>
  onResolveAssetGraphConflict: (
    conflict: AssetGraphOwnershipConflict,
    owner: AssetGraphConflictOwner,
  ) => Promise<AssetGraphConflictResolutionResult>
  onRequestRemediationRetest: (
    payload: RemediationRetestRequestPayload,
  ) => Promise<RemediationRetestRequestResult>
  onPreviewRetention: () => Promise<RetentionRunResult>
  onApplyRetention: () => Promise<RetentionRunResult>
  onStoreConnectorSecret: (payload: ConnectorSecretStorePayload) => Promise<void>
  onCreateActiveValidation: (payload: ActiveValidationCreatePayload) => Promise<void>
  onApproveActiveValidation: (payload: ActiveValidationApprovalPayload) => Promise<void>
  onRunActiveValidation: (jobId: number, allowLive: boolean) => Promise<void>
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
  const [activeValidationTarget, setActiveValidationTarget] = useState(detail.primary_seed)
  const [activeValidationTargetKind, setActiveValidationTargetKind] =
    useState<ActiveValidationTargetKind>('host')
  const [activeValidationMethod, setActiveValidationMethod] =
    useState<ActiveValidationMethodId | string>('http_reachability')
  const [activeValidationMode, setActiveValidationMode] = useState<ActiveValidationMode>('dry_run')
  const [activeValidationRoe, setActiveValidationRoe] = useState('')
  const [activeValidationScope, setActiveValidationScope] = useState('')
  const [activeValidationApprovalNote, setActiveValidationApprovalNote] = useState('')
  const [activeValidationMaxSteps, setActiveValidationMaxSteps] = useState(1)
  const [activeValidationAllowLive, setActiveValidationAllowLive] = useState(false)
  const [activeValidationBusy, setActiveValidationBusy] = useState(false)
  const [activeValidationError, setActiveValidationError] = useState('')
  const [activeValidationMessage, setActiveValidationMessage] = useState('')
  const [selectedActiveValidationGraphScenario, setSelectedActiveValidationGraphScenario] =
    useState<ActiveValidationGraphScenario | null>(null)
  const [selectedRemediationId, setSelectedRemediationId] = useState<number | null>(null)
  const [remediationOwner, setRemediationOwner] = useState('')
  const [remediationStatus, setRemediationStatus] = useState<RemediationStatus>('open')
  const [remediationRetestStatus, setRemediationRetestStatus] =
    useState<RemediationRetestStatus>('not_requested')
  const [remediationSlaDueAt, setRemediationSlaDueAt] = useState('')
  const [remediationRiskReason, setRemediationRiskReason] = useState('')
  const [remediationRiskExpiresAt, setRemediationRiskExpiresAt] = useState('')
  const [remediationTicketSystem, setRemediationTicketSystem] = useState('')
  const [remediationTicketRef, setRemediationTicketRef] = useState('')
  const [remediationTicketUrl, setRemediationTicketUrl] = useState('')
  const [remediationTicketSync, setRemediationTicketSync] =
    useState<RemediationTicketSyncPayload>(DEFAULT_REMEDIATION_TICKET_SYNC)
  const [remediationOwnerOverwrite, setRemediationOwnerOverwrite] = useState(false)
  const [remediationOwnerConflictPolicy, setRemediationOwnerConflictPolicy] = useState('highest_confidence')
  const [remediationOwnerMinConfidence, setRemediationOwnerMinConfidence] = useState('0')
  const [remediationRetestTarget, setRemediationRetestTarget] = useState('')
  const [remediationRetestTargetKind, setRemediationRetestTargetKind] =
    useState<ActiveValidationTargetKind>('fixture')
  const [remediationRetestMethod, setRemediationRetestMethod] =
    useState<ActiveValidationMethodId | string>('fix_verification')
  const [remediationRetestMode, setRemediationRetestMode] = useState<ActiveValidationMode>('dry_run')
  const [remediationRetestApprove, setRemediationRetestApprove] = useState(false)
  const [remediationRetestExpectedResult, setRemediationRetestExpectedResult] = useState('')
  const [remediationBusy, setRemediationBusy] = useState(false)
  const [remediationError, setRemediationError] = useState('')
  const [remediationMessage, setRemediationMessage] = useState('')
  const [graphConflictBusyKey, setGraphConflictBusyKey] = useState('')
  const [graphConflictError, setGraphConflictError] = useState('')
  const [graphConflictMessage, setGraphConflictMessage] = useState('')
  const [retentionConfirmApply, setRetentionConfirmApply] = useState(false)
  const [retentionBusy, setRetentionBusy] = useState(false)
  const [retentionError, setRetentionError] = useState('')
  const [retentionMessage, setRetentionMessage] = useState('')
  const [connectorSecretConnectorId, setConnectorSecretConnectorId] = useState('shodan_host_lookup')
  const [connectorSecretName, setConnectorSecretName] = useState('FORGE_SHODAN_API_KEY')
  const [connectorSecretValue, setConnectorSecretValue] = useState('')
  const [connectorSecretRef, setConnectorSecretRef] = useState('')
  const [connectorSecretOwner, setConnectorSecretOwner] = useState('')
  const [connectorSecretBusy, setConnectorSecretBusy] = useState(false)
  const [connectorSecretError, setConnectorSecretError] = useState('')
  const [connectorSecretMessage, setConnectorSecretMessage] = useState('')
  const reportPreview = detail.report_previews[0]
  const assetGraphConflicts = detail.graph_payload?.ownership_conflicts ?? []
  const auditRows = detail.sections.audit_log ?? []
  const workspaceAuditWorkspaceId = workspaceAuditOverview?.workspace_id || detail.workspace_id || 'default'
  const workspaceAuditEvents = workspaceAuditOverview?.items ?? []
  const workspaceAuditRows = workspaceAuditEvents.map(workspaceAuditEventRow)
  const hostRows = detail.sections.hosts ?? []
  const emailRows = detail.sections.emails ?? []
  const seedRows = detail.sections.engagement_seeds ?? []
  const seedRunRows = detail.sections.seed_runs ?? []
  const keyFindingRows = detail.sections.key_scanner_findings ?? []
  const secretLifecycleRows = detail.sections.secret_lifecycle_items ?? []
  const cloudValidationRows = detail.sections.cloud_validation_results ?? []
  const staticActiveValidationJobRows = detail.sections.active_validation_jobs ?? []
  const staticActiveValidationRunRows = detail.sections.active_validation_runs ?? []
  const staticActiveValidationCoverageRows = detail.sections.active_validation_coverage ?? []
  const activeValidationJobs = activeValidation?.jobs ?? []
  const activeValidationRuns = activeValidation?.runs ?? []
  const activeValidationCoverage = activeValidation?.coverage
  const activeValidationMethods = activeValidation?.methods?.length
    ? activeValidation.methods
    : FALLBACK_ACTIVE_VALIDATION_METHODS
  const activeValidationGraphScenarios = activeValidation?.graph_scenarios ?? []
  const activeValidationJobRows = activeValidation
    ? activeValidationJobs.map(activeValidationJobRow)
    : staticActiveValidationJobRows
  const activeValidationRunRows = activeValidation
    ? activeValidationRuns.map(activeValidationRunRow)
    : staticActiveValidationRunRows
  const activeValidationCoverageRowsForDisplay = activeValidation
    ? activeValidationCoverageRows(activeValidationCoverage)
    : staticActiveValidationCoverageRows
  const activeValidationJobCount = activeValidation?.summary.job_count ?? staticActiveValidationJobRows.length
  const activeValidationRunCount = activeValidation?.summary.run_count ?? staticActiveValidationRunRows.length
  const activeValidationCoverageStates =
    activeValidation?.summary.coverage_states ?? activeValidationCoverage?.summary.states
  const activeValidationBlockedRunCount =
    activeValidation?.summary.blocked_run_count ??
    activeValidationRunRows.filter((row) => (row.Status || '').toLowerCase() === 'blocked').length
  const activeValidationCompletedRunCount =
    activeValidation?.summary.completed_run_count ??
    activeValidationRunRows.filter((row) => (row.Status || '').toLowerCase() === 'completed').length
  const activeValidationApprovedJobCount =
    activeValidationJobs.filter((job) => job.approved).length ||
    activeValidationJobRows.filter((row) => (row.Approved || '').toLowerCase() === 'yes').length
  const activeValidationAttackMappingCount =
    activeValidation?.summary.attack_mapping_count ??
    activeValidationCoverage?.summary.attack_mapping_count ??
    staticActiveValidationCoverageRows.filter((row) => row.Type === 'ATT&CK').length
  const activeValidationControlFamilyCount =
    activeValidation?.summary.control_family_count ??
    activeValidationCoverage?.summary.control_family_count ??
    staticActiveValidationCoverageRows.filter((row) => row.Type === 'Control').length
  const activeValidationMethodCoverageCount =
    activeValidationCoverage?.summary.method_count ??
    staticActiveValidationCoverageRows.filter((row) => row.Type === 'Method').length
  const activeValidationGraphScenarioCount =
    activeValidation?.summary.graph_scenario_count ?? activeValidationGraphScenarios.length
  const staticRemediationRows = detail.sections.remediation_items ?? []
  const remediationItems = remediationOverview?.items ?? []
  const remediationRows = remediationOverview
    ? remediationItems.map(remediationItemRow)
    : staticRemediationRows
  const remediationSummary = remediationOverview?.summary ?? summarizeRemediationRows(staticRemediationRows)
  const staticRemediationReviewQueueRows = detail.sections.remediation_review_queue ?? []
  const remediationReviewQueue = remediationOverview?.review_queue ?? null
  const remediationReviewQueueRows = remediationReviewQueue
    ? remediationReviewQueue.items.map(remediationReviewQueueRow)
    : staticRemediationReviewQueueRows
  const remediationReviewQueueSummary =
    remediationReviewQueue?.summary ?? summarizeRemediationReviewQueueRows(staticRemediationReviewQueueRows)
  const remediationReviewQueueCount = remediationSummaryCount(
    remediationReviewQueueSummary,
    'attention_required',
  )
  const remediationSlaOverdueCount = remediationSummaryCount(remediationReviewQueueSummary, 'sla_overdue')
  const remediationMissingTicketCount = remediationSummaryCount(remediationReviewQueueSummary, 'missing_ticket')
  const remediationRetestBlockedCount = remediationSummaryCount(remediationReviewQueueSummary, 'retest_blocked')
  const remediationTicketSyncFailedCount = remediationSummaryCount(
    remediationReviewQueueSummary,
    'ticket_sync_failed',
  )
  const remediationOpenCount =
    remediationItems.length > 0
      ? remediationItems.filter((item) =>
          ['open', 'assigned', 'in_progress', 'retest_pending'].includes(item.status),
        ).length
      : ['open', 'assigned', 'in_progress', 'retest_pending'].reduce(
          (total, status) => total + remediationSummaryCount(remediationSummary, status),
          0,
        )
  const remediationRiskAcceptedCount = remediationSummaryCount(remediationSummary, 'risk_accepted')
  const remediationRetestPendingCount = remediationSummaryCount(remediationSummary, 'retest_pending')
  const remediationWithTicketCount = remediationSummaryCount(remediationSummary, 'with_ticket')
  const remediationWithOwnerCount = remediationSummaryCount(remediationSummary, 'with_owner')
  const remediationWithSlaCount = remediationSummaryCount(remediationSummary, 'with_sla')
  const remediationRiskReviewDueCount = remediationSummaryCount(remediationSummary, 'risk_acceptance_review_due')
  const remediationRiskExpiredCount = remediationSummaryCount(remediationSummary, 'risk_acceptance_expired')
  const remediationRiskExpiringSoonCount = remediationSummaryCount(
    remediationSummary,
    'risk_acceptance_expiring_soon',
  )
  const remediationUnownedCount = Math.max(0, remediationRows.length - remediationWithOwnerCount)
  const selectedRemediationItem =
    remediationItems.find((item) => item.id === selectedRemediationId) ?? remediationItems[0] ?? null
  const staticRetentionPolicyRows = detail.sections.retention_policies ?? []
  const staticRetentionRunRows = detail.sections.retention_runs ?? []
  const staticRetentionRunItemRows = detail.sections.retention_run_items ?? []
  const retentionPolicy = retentionOverview?.policy ?? null
  const retentionRuns = retentionOverview?.runs ?? []
  const retentionPolicyRows = retentionOverview
    ? [retentionPolicyRow(retentionOverview.policy)]
    : staticRetentionPolicyRows
  const retentionRunRows = retentionOverview
    ? retentionRuns.map(retentionRunRow)
    : staticRetentionRunRows
  const retentionRunItemRows = retentionOverview
    ? retentionRuns.flatMap((run) => (run.items ?? []).map((item) => retentionRunItemRow(run, item)))
    : staticRetentionRunItemRows
  const latestRetentionRun = retentionRuns[0] ?? null
  const latestRetentionSummary = latestRetentionRun?.summary ?? {}
  const retentionPolicyName = retentionPolicy?.name || staticRetentionPolicyRows[0]?.Name || 'default'
  const retentionEnabledLabel = retentionPolicy
    ? retentionPolicy.enabled
      ? 'enabled'
      : 'disabled'
    : staticRetentionPolicyRows[0]?.Enabled || '-'
  const retentionLegalHoldLabel =
    retentionOverview?.legal_hold === true
      ? 'active'
      : retentionOverview?.legal_hold === false
        ? 'clear'
        : staticRetentionPolicyRows[0]?.['Legal Hold'] || '-'
  const retentionLatestRunLabel = latestRetentionRun
    ? `${latestRetentionRun.mode || 'run'} ${latestRetentionRun.status || 'unknown'}`
    : staticRetentionRunRows[0]
      ? `${staticRetentionRunRows[0].Mode || 'run'} ${staticRetentionRunRows[0].Status || 'unknown'}`
      : 'none'
  const retentionRunCount = retentionOverview ? retentionRuns.length : staticRetentionRunRows.length
  const retentionEligibleCount = latestRetentionRun
    ? retentionSummaryNumber(latestRetentionSummary, 'eligible_count')
    : numericValue(staticRetentionRunRows[0]?.Eligible)
  const retentionDeletedCount = latestRetentionRun
    ? retentionSummaryNumber(latestRetentionSummary, 'deleted_count')
    : numericValue(staticRetentionRunRows[0]?.Deleted)
  const connectorCatalog = connectorCatalogOverview?.connectors ?? EMPTY_CONNECTOR_CATALOG
  const connectorCatalogRows = connectorCatalog.map(connectorCatalogRow)
  const connectorCatalogSummary = connectorCatalogOverview?.summary ?? null
  const connectorCatalogConfiguredCount = connectorCatalogSummary?.configured_count ?? 0
  const connectorCatalogFreeFirstCount = connectorCatalogSummary?.free_first_count ?? 0
  const connectorCatalogMissingBinaryCount = connectorCatalogSummary?.readiness.missing_binary ?? 0
  const connectorCatalogOptionalKeyCount = connectorCatalogSummary?.readiness.not_configured_optional_key ?? 0
  const connectorCatalogSecretStoreCount = connectorCatalogSummary?.secret_store_connector_count ?? 0
  const connectorCatalogPluginManifestCount = connectorCatalogSummary?.plugin_manifest_count ?? 0
  const connectorCatalogActiveValidationPluginManifestCount =
    connectorCatalogSummary?.active_validation_plugin_manifest_count ?? 0
  const connectorCatalogPluginManifestCatalogCount =
    connectorCatalogSummary?.plugin_manifest_catalog_count ?? 0
  const connectorCatalogRunnerSupportedCount =
    connectorCatalogSummary?.runner_supported_count ?? 0
  const connectorCatalogDecryptFailureCount =
    connectorCatalogSummary?.readiness.stored_decrypt_failed ?? 0
  const connectorCatalogStoredKeyMissingCount =
    connectorCatalogSummary?.readiness.stored_key_missing ?? 0
  const connectorSecretConnectorOptions = useMemo(
    () => connectorCatalog.filter((connector) => connectorCredentialNames(connector).length > 0),
    [connectorCatalog],
  )
  const selectedConnectorSecretConnector =
    connectorSecretConnectorOptions.find((connector) => connector.id === connectorSecretConnectorId) ??
    connectorSecretConnectorOptions[0] ??
    null
  const connectorSecretNameOptions = useMemo(
    () => connectorCredentialNames(selectedConnectorSecretConnector),
    [selectedConnectorSecretConnector],
  )
  const connectorSecrets = connectorSecretsOverview?.items ?? []
  const connectorSecretRows = connectorSecrets.map(connectorSecretRow)
  const connectorSecretCount = connectorSecretsOverview?.summary.count ?? connectorSecrets.length
  const connectorSecretConnectors = connectorSecretsOverview?.summary.connectors ?? []
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
  const validationStatusSummary = reportSummary?.validation_status_summary
    ? Object.entries(reportSummary.validation_status_summary)
        .map(([status, count]) => `${status.toLowerCase()}: ${count}`)
        .join(', ')
    : ''
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
      ![
        'hosts',
        'emails',
        'audit_log',
        'active_validation_jobs',
        'active_validation_runs',
        'active_validation_coverage',
        'remediation_items',
        'remediation_review_queue',
        'retention_policies',
        'retention_runs',
        'retention_run_items',
        'connector_secrets',
        'monitoring_policies',
        'monitoring_snapshots',
        'monitoring_trend_points',
        'monitoring_changes',
        'monitoring_alerts',
        'monitoring_alert_routes',
        'monitoring_alert_suppressions',
      ].includes(sectionKey) &&
      rows.length > 0 &&
      SECTION_TITLES[sectionKey],
  )
  const operationalEvents = operationalTimelineEvents(
    detail,
    activeValidationRuns,
    activeValidationRunRows,
    remediationRows,
  )

  const detailTagsText = (detail.tags ?? []).join(', ')

  useEffect(() => {
    setEngagementDirty(false)
    setActiveValidationTarget(detail.primary_seed)
    setActiveValidationTargetKind('host')
    setActiveValidationMethod('http_reachability')
    setActiveValidationMode('dry_run')
    setActiveValidationRoe('')
    setActiveValidationScope('')
    setActiveValidationApprovalNote('')
    setActiveValidationMaxSteps(1)
    setActiveValidationAllowLive(false)
    setActiveValidationError('')
    setActiveValidationMessage('')
    setSelectedRemediationId(null)
    setRemediationError('')
    setRemediationMessage('')
    setRemediationTicketSync({ ...DEFAULT_REMEDIATION_TICKET_SYNC })
    setRemediationOwnerOverwrite(false)
    setRemediationRetestTarget('')
    setRemediationRetestTargetKind('fixture')
    setRemediationRetestMethod('fix_verification')
    setRemediationRetestMode('dry_run')
    setRemediationRetestApprove(false)
    setRemediationRetestExpectedResult('')
    setRetentionConfirmApply(false)
    setRetentionError('')
    setRetentionMessage('')
    setConnectorSecretValue('')
    setConnectorSecretRef('')
    setConnectorSecretError('')
    setConnectorSecretMessage('')
  }, [detail.primary_seed, detail.slug])

  useEffect(() => {
    if (!connectorSecretConnectorOptions.length) {
      return
    }
    const nextConnector =
      connectorSecretConnectorOptions.find((connector) => connector.id === connectorSecretConnectorId) ??
      connectorSecretConnectorOptions[0]
    if (nextConnector.id !== connectorSecretConnectorId) {
      setConnectorSecretConnectorId(nextConnector.id)
    }
    const nextNames = connectorCredentialNames(nextConnector)
    const nextName = nextNames.includes(connectorSecretName) ? connectorSecretName : nextNames[0] || ''
    if (nextName && nextName !== connectorSecretName) {
      setConnectorSecretName(nextName)
    }
    if (nextName && (!connectorSecretRef.trim() || connectorSecretRef.startsWith('env:'))) {
      const nextRef = `env:${nextName}`
      if (connectorSecretRef !== nextRef) {
        setConnectorSecretRef(nextRef)
      }
    }
  }, [
    connectorSecretConnectorId,
    connectorSecretConnectorOptions,
    connectorSecretName,
    connectorSecretRef,
  ])

  useEffect(() => {
    if (!selectedRemediationItem) {
      setRemediationOwner('')
      setRemediationStatus('open')
      setRemediationRetestStatus('not_requested')
      setRemediationSlaDueAt('')
      setRemediationRiskReason('')
      setRemediationRiskExpiresAt('')
      setRemediationTicketSystem('')
      setRemediationTicketRef('')
      setRemediationTicketUrl('')
      return
    }
    setRemediationOwner(selectedRemediationItem.owner || '')
    setRemediationStatus(normalizeRemediationStatus(selectedRemediationItem.status))
    setRemediationRetestStatus(normalizeRemediationRetestStatus(selectedRemediationItem.retest_status))
    setRemediationSlaDueAt(selectedRemediationItem.sla_due_at || '')
    setRemediationRiskReason(selectedRemediationItem.risk_acceptance_reason || '')
    setRemediationRiskExpiresAt(selectedRemediationItem.risk_acceptance_expires_at || '')
    setRemediationTicketSystem(selectedRemediationItem.ticket_system || '')
    setRemediationTicketRef(selectedRemediationItem.ticket_ref || '')
    setRemediationTicketUrl(selectedRemediationItem.ticket_url || '')
  }, [selectedRemediationItem])

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

  function setRemediationTicketSyncValue<K extends keyof RemediationTicketSyncPayload>(
    key: K,
    value: RemediationTicketSyncPayload[K],
  ): void {
    setRemediationTicketSync((current) => ({ ...current, [key]: value }))
  }

  async function handleRemediationSave(): Promise<void> {
    if (!liveToken) {
      setRemediationError('Unlock live API access before updating remediation.')
      return
    }
    if (!selectedRemediationItem) {
      setRemediationError('Select a remediation item first.')
      return
    }
    if (remediationStatus === 'risk_accepted' && !remediationRiskReason.trim()) {
      setRemediationError('Risk acceptance requires a reason.')
      return
    }
    if (remediationStatus === 'risk_accepted' && !remediationRiskExpiresAt.trim()) {
      setRemediationError('Risk acceptance requires an expiry.')
      return
    }
    setRemediationBusy(true)
    setRemediationError('')
    setRemediationMessage('')
    try {
      await onUpdateRemediation({
        itemId: selectedRemediationItem.id,
        owner: remediationOwner.trim(),
        slaDueAt: remediationSlaDueAt.trim(),
        status: remediationStatus,
        retestStatus: remediationRetestStatus,
        riskAcceptanceReason:
          remediationStatus === 'risk_accepted' ? remediationRiskReason.trim() : undefined,
        riskAcceptanceExpiresAt:
          remediationStatus === 'risk_accepted' ? remediationRiskExpiresAt.trim() : undefined,
        ticketSystem: remediationTicketSystem.trim(),
        ticketRef: remediationTicketRef.trim(),
        ticketUrl: remediationTicketUrl.trim(),
      })
      setRemediationMessage(`Remediation item ${selectedRemediationItem.id} updated.`)
    } catch (actionError) {
      setRemediationError(actionError instanceof Error ? actionError.message : 'unable to update remediation')
    } finally {
      setRemediationBusy(false)
    }
  }

  async function handleRemediationTicketSync(): Promise<void> {
    if (!liveToken) {
      setRemediationError('Unlock live API access before syncing remediation tickets.')
      return
    }
    if (!selectedRemediationItem) {
      setRemediationError('Select a remediation item first.')
      return
    }
    setRemediationBusy(true)
    setRemediationError('')
    setRemediationMessage('')
    try {
      const result = await onSyncRemediationTicket(selectedRemediationItem.id, remediationTicketSync)
      const synced = numericValue(result.sync_count ?? result.synced_count)
      const failed = numericValue(result.failure_count)
      setRemediationMessage(`Ticket sync complete: ${formatCount(synced)} synced, ${formatCount(failed)} failed.`)
    } catch (actionError) {
      setRemediationError(actionError instanceof Error ? actionError.message : 'unable to sync remediation ticket')
    } finally {
      setRemediationBusy(false)
    }
  }

  async function handleRemediationOwnerPropagation(): Promise<void> {
    if (!liveToken) {
      setRemediationError('Unlock live API access before propagating remediation owners.')
      return
    }
    setRemediationBusy(true)
    setRemediationError('')
    setRemediationMessage('')
    try {
      const confidenceFloor = Math.max(0, Math.min(1, Number(remediationOwnerMinConfidence) || 0))
      const result = await onPropagateRemediationOwners(
        remediationOwnerOverwrite,
        remediationOwnerConflictPolicy,
        confidenceFloor,
      )
      const assigned = numericValue(result.assigned_count)
      const unresolved = numericValue(result.unresolved_count)
      const skipped = numericValue(result.skipped_existing_owner_count)
      const skippedConflict = numericValue(result.skipped_conflict_count)
      const skippedLowConfidence = numericValue(result.skipped_low_confidence_count)
      setRemediationMessage(
        `Owner propagation complete: ${formatCount(assigned)} assigned, ${formatCount(unresolved)} unresolved, ${formatCount(skipped)} explicit owners kept, ${formatCount(skippedConflict)} conflicts skipped, ${formatCount(skippedLowConfidence)} below confidence floor.`,
      )
    } catch (actionError) {
      setRemediationError(
        actionError instanceof Error ? actionError.message : 'unable to propagate remediation owners',
      )
    } finally {
      setRemediationBusy(false)
    }
  }

  async function handleRemediationGraphDraft(): Promise<void> {
    if (!liveToken) {
      setRemediationError('Unlock live API access before drafting graph remediation.')
      return
    }
    setRemediationBusy(true)
    setRemediationError('')
    setRemediationMessage('')
    try {
      const result = await onDraftRemediationFromGraph()
      const candidates = numericValue(result.candidate_count)
      const drafted = numericValue(result.drafted_count)
      setRemediationMessage(
        `Graph remediation draft complete: ${formatCount(drafted)} drafted from ${formatCount(candidates)} candidates.`,
      )
    } catch (actionError) {
      setRemediationError(
        actionError instanceof Error ? actionError.message : 'unable to draft graph remediation',
      )
    } finally {
      setRemediationBusy(false)
    }
  }

  async function handleRemediationOwnerReview(decision: string): Promise<void> {
    if (!liveToken) {
      setRemediationError('Unlock live API access before reviewing remediation owners.')
      return
    }
    if (!selectedRemediationItem) {
      setRemediationError('Select a remediation item first.')
      return
    }
    setRemediationBusy(true)
    setRemediationError('')
    setRemediationMessage('')
    try {
      const result = await onReviewRemediationOwner(selectedRemediationItem.id, decision)
      setRemediationMessage(`Owner review complete: ${result.decision} for item ${selectedRemediationItem.id}.`)
    } catch (actionError) {
      setRemediationError(
        actionError instanceof Error ? actionError.message : 'unable to review remediation owner',
      )
    } finally {
      setRemediationBusy(false)
    }
  }

  async function handleGraphConflictResolve(
    conflict: AssetGraphOwnershipConflict,
    owner: AssetGraphConflictOwner,
  ): Promise<void> {
    if (!liveToken) {
      setGraphConflictError('Unlock live API access before resolving ownership conflicts.')
      return
    }
    if (!conflict.entity_key || !owner.owner_ref) {
      setGraphConflictError('Conflict entity and owner are required.')
      return
    }
    const busyKey = `${conflict.entity_key}:${owner.owner_kind ?? ''}:${owner.owner_ref}`
    setGraphConflictBusyKey(busyKey)
    setGraphConflictError('')
    setGraphConflictMessage('')
    try {
      const result = await onResolveAssetGraphConflict(conflict, owner)
      setGraphConflictMessage(
        `Resolved ${conflict.entity_label || conflict.entity_key} to ${
          owner.owner_display || result.selected_owner || owner.owner_ref
        }; ${formatCount(result.superseded_claim_ids?.length ?? 0)} competing claims superseded.`,
      )
    } catch (actionError) {
      setGraphConflictError(
        actionError instanceof Error ? actionError.message : 'unable to resolve ownership conflict',
      )
    } finally {
      setGraphConflictBusyKey('')
    }
  }

  async function handleRemediationRetestRequest(): Promise<void> {
    if (!liveToken) {
      setRemediationError('Unlock live API access before requesting remediation retest.')
      return
    }
    if (!selectedRemediationItem) {
      setRemediationError('Select a remediation item first.')
      return
    }
    setRemediationBusy(true)
    setRemediationError('')
    setRemediationMessage('')
    try {
      const result = await onRequestRemediationRetest({
        itemId: selectedRemediationItem.id,
        targetRef: remediationRetestTarget.trim(),
        targetKind: remediationRetestTargetKind,
        method: remediationRetestMethod,
        mode: remediationRetestMode,
        approve: remediationRetestApprove,
        roeId: activeValidationRoe.trim(),
        scopeManifest: activeValidationScope.trim(),
        approvalNote: activeValidationApprovalNote.trim(),
        expectedResult: remediationRetestExpectedResult.trim(),
      })
      setRemediationMessage(
        `Retest job ${result.active_validation_job.id} requested for item ${selectedRemediationItem.id}.`,
      )
    } catch (actionError) {
      setRemediationError(actionError instanceof Error ? actionError.message : 'unable to request remediation retest')
    } finally {
      setRemediationBusy(false)
    }
  }

  async function handleRetentionPreview(): Promise<void> {
    if (!liveToken) {
      setRetentionError('Unlock live API access before previewing retention.')
      return
    }
    setRetentionBusy(true)
    setRetentionError('')
    setRetentionMessage('')
    try {
      const result = await onPreviewRetention()
      setRetentionMessage(retentionResultMessage('Preview', result))
    } catch (actionError) {
      setRetentionError(actionError instanceof Error ? actionError.message : 'unable to preview retention')
    } finally {
      setRetentionBusy(false)
    }
  }

  async function handleRetentionApply(): Promise<void> {
    if (!liveToken) {
      setRetentionError('Unlock live API access before applying retention.')
      return
    }
    if (!retentionConfirmApply) {
      setRetentionError('Confirm apply before running destructive retention cleanup.')
      return
    }
    setRetentionBusy(true)
    setRetentionError('')
    setRetentionMessage('')
    try {
      const result = await onApplyRetention()
      setRetentionMessage(retentionResultMessage('Apply', result))
      setRetentionConfirmApply(false)
    } catch (actionError) {
      setRetentionError(actionError instanceof Error ? actionError.message : 'unable to apply retention')
    } finally {
      setRetentionBusy(false)
    }
  }

  async function handleConnectorSecretStore(): Promise<void> {
    if (!liveToken) {
      setConnectorSecretError('Unlock live API access before storing connector secrets.')
      return
    }
    if (!connectorSecretConnectorId.trim()) {
      setConnectorSecretError('Connector ID is required.')
      return
    }
    if (!selectedConnectorSecretConnector) {
      setConnectorSecretError('Choose a connector that declares stored credential names.')
      return
    }
    if (!connectorSecretName.trim()) {
      setConnectorSecretError('Secret name is required.')
      return
    }
    if (!connectorSecretNameOptions.includes(connectorSecretName.trim())) {
      setConnectorSecretError('Choose a declared secret name for this connector.')
      return
    }
    if (!connectorSecretValue.trim()) {
      setConnectorSecretError('Secret value is required.')
      return
    }
    setConnectorSecretBusy(true)
    setConnectorSecretError('')
    setConnectorSecretMessage('')
    try {
      const secretName = connectorSecretName.trim()
      await onStoreConnectorSecret({
        connectorId: connectorSecretConnectorId.trim(),
        secretName,
        secretValue: connectorSecretValue,
        secretRef: connectorSecretRef.trim(),
        owner: connectorSecretOwner.trim(),
      })
      setConnectorSecretValue('')
      setConnectorSecretMessage(`${secretName} stored.`)
    } catch (actionError) {
      setConnectorSecretError(
        actionError instanceof Error ? actionError.message : 'unable to store connector secret',
      )
    } finally {
      setConnectorSecretBusy(false)
    }
  }

  async function handleActiveValidationCreate(): Promise<void> {
    if (!liveToken) {
      setActiveValidationError('Unlock live API access before creating active-validation jobs.')
      return
    }
    if (!activeValidationTarget.trim()) {
      setActiveValidationError('Target is required.')
      return
    }
    setActiveValidationBusy(true)
    setActiveValidationError('')
    setActiveValidationMessage('')
    try {
      await onCreateActiveValidation({
        targetRef: activeValidationTarget.trim(),
        targetKind: activeValidationTargetKind,
        method: activeValidationMethod,
        mode: activeValidationMode,
        roeId: activeValidationRoe.trim(),
        scopeManifest: activeValidationScope.trim(),
        maxSteps: Math.min(Math.max(Math.round(activeValidationMaxSteps || 1), 1), 50),
        metadata: selectedActiveValidationGraphScenario?.metadata,
      })
      setActiveValidationMessage('Active-validation job queued.')
      setSelectedActiveValidationGraphScenario(null)
    } catch (actionError) {
      setActiveValidationError(actionError instanceof Error ? actionError.message : 'unable to create active-validation job')
    } finally {
      setActiveValidationBusy(false)
    }
  }

  function handleUseActiveValidationGraphScenario(scenario: ActiveValidationGraphScenario): void {
    setActiveValidationTarget(scenario.target_ref || '')
    setActiveValidationTargetKind(normalizeActiveValidationTargetKind(scenario.target_kind))
    setActiveValidationMethod(normalizeActiveValidationMethodId(scenario.method))
    setActiveValidationMode(normalizeActiveValidationMode(scenario.mode))
    setActiveValidationMaxSteps(Math.min(Math.max(Math.round(scenario.max_steps || 1), 1), 50))
    setSelectedActiveValidationGraphScenario(scenario)
    setActiveValidationError('')
    setActiveValidationMessage(`Loaded graph recommendation for ${scenario.target_ref || 'target'}.`)
  }

  function clearActiveValidationGraphScenario(): void {
    setSelectedActiveValidationGraphScenario(null)
  }

  async function handleActiveValidationApprove(job: ActiveValidationJob): Promise<void> {
    if (!liveToken) {
      setActiveValidationError('Unlock live API access before approving active-validation jobs.')
      return
    }
    setActiveValidationBusy(true)
    setActiveValidationError('')
    setActiveValidationMessage('')
    try {
      await onApproveActiveValidation({
        jobId: job.id,
        roeId: activeValidationRoe.trim(),
        scopeManifest: activeValidationScope.trim(),
        approvalNote: activeValidationApprovalNote.trim(),
      })
      setActiveValidationMessage(`Job ${job.id} approved.`)
    } catch (actionError) {
      setActiveValidationError(actionError instanceof Error ? actionError.message : 'unable to approve active-validation job')
    } finally {
      setActiveValidationBusy(false)
    }
  }

  async function handleActiveValidationRun(job: ActiveValidationJob, allowLive: boolean): Promise<void> {
    if (!liveToken) {
      setActiveValidationError('Unlock live API access before running active-validation jobs.')
      return
    }
    setActiveValidationBusy(true)
    setActiveValidationError('')
    setActiveValidationMessage('')
    try {
      await onRunActiveValidation(job.id, allowLive)
      setActiveValidationMessage(`Job ${job.id} run requested.`)
    } catch (actionError) {
      setActiveValidationError(actionError instanceof Error ? actionError.message : 'unable to run active-validation job')
    } finally {
      setActiveValidationBusy(false)
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
        <article className="summary-card">
          <span className="summary-label">Active validation</span>
          <strong>{formatCount(activeValidationJobCount)}</strong>
          <span className="card-copy">
            {formatCount(activeValidationRunCount)} runs · {formatCount(activeValidationBlockedRunCount)} blocked
          </span>
        </article>
        <article className="summary-card">
          <span className="summary-label">Remediation</span>
          <strong>{formatCount(remediationOpenCount)}</strong>
          <span className="card-copy">
            {formatCount(remediationWithTicketCount)} ticketed · {formatCount(remediationRetestPendingCount)} retest
          </span>
        </article>
        <article className="summary-card">
          <span className="summary-label">Retention</span>
          <strong>{retentionPolicyName}</strong>
          <span className="card-copy">
            {retentionLatestRunLabel} · {formatCount(retentionEligibleCount)} eligible
          </span>
        </article>
        <article className="summary-card">
          <span className="summary-label">Connectors</span>
          <strong>{formatCount(connectorCatalogConfiguredCount)}</strong>
          <span className="card-copy">{formatCount(connectorCatalogFreeFirstCount)} free-first</span>
        </article>
        <article className="summary-card">
          <span className="summary-label">Connector secrets</span>
          <strong>{formatCount(connectorSecretCount)}</strong>
          <span className="card-copy">{formatCount(connectorSecretConnectors.length)} connectors</span>
        </article>
        <article className="summary-card">
          <span className="summary-label">Workspace audit</span>
          <strong>{formatCount(workspaceAuditRows.length)}</strong>
          <span className="card-copy">{workspaceAuditWorkspaceId}</span>
        </article>
      </section>

      <nav className="section-nav" aria-label="Engagement sections">
        <a href="#overview">Overview</a>
        <a href="#report">Report</a>
        <a href="#seeds">Seeds</a>
        <a href="#graph">Graph</a>
        <a href="#findings">Findings</a>
        <a href="#active-validation">Active validation</a>
        <a href="#remediation">Remediation</a>
        <a href="#retention">Retention</a>
        <a href="#connector-catalog">Connectors</a>
        <a href="#connector-secrets">Connector secrets</a>
        <a href="#operational-timeline">Timeline</a>
        <a href="#evidence">Evidence</a>
        <a href="#audit">Audit</a>
        <a href="#workspace-audit">Workspace audit</a>
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
                  <span className="token">
                    rendered {reportSummary.rendered_provider || reportSummary.provider || reportSummary.render_backend || '-'}
                  </span>
                  <span className="token">backend {reportSummary.render_backend || '-'}</span>
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
                  <div className="mini-table-row">
                    <span>Report generations</span>
                    <span>{detail.report_family_count ?? reportHistory.length}</span>
                  </div>
                  {detail.latest_report_family ? (
                    <div className="mini-table-row">
                      <span>Latest family</span>
                      <span>{detail.latest_report_family}</span>
                    </div>
                  ) : null}
                  <div className="mini-table-row">
                    <span>Validation inventory</span>
                    <span>{reportSummary.cloud_validation_inventory_count ?? 0}</span>
                  </div>
                  <div className="mini-table-row">
                    <span>Reportable validations</span>
                    <span>
                      {reportSummary.reportable_validation_count ?? 0}
                      {' / '}
                      {reportSummary.unreportable_validation_count ?? 0} held
                    </span>
                  </div>
                  <div className="mini-table-row">
                    <span>Cloud assets</span>
                    <span>{reportSummary.cloud_asset_inventory_count ?? 0}</span>
                  </div>
                  {validationStatusSummary ? (
                    <div className="mini-table-row">
                      <span>Validation status</span>
                      <span>{validationStatusSummary}</span>
                    </div>
                  ) : null}
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
                          <span>{historyEntry.rendered_provider || historyEntry.provider || historyEntry.render_backend || '-'}</span>
                        </div>
                        <div className="mini-table-row">
                          <span>Backend</span>
                          <span>{historyEntry.render_backend || '-'}</span>
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
            <div className="scope-block">
              <span className="summary-label">Asset ownership conflicts</span>
              <div className="token-wrap">
                <span className="token">conflicts {formatCount(assetGraphConflicts.length)}</span>
                <span className="token">live resolution {liveToken ? 'enabled' : 'locked'}</span>
              </div>
              {assetGraphConflicts.length ? (
                <div className="remediation-card-list">
                  {assetGraphConflicts.slice(0, 6).map((conflict) => (
                    <article className="remediation-card" key={conflict.entity_key}>
                      <div className="remediation-card-head">
                        <div>
                          <strong>{conflict.entity_label || conflict.entity_key}</strong>
                          <span>
                            {conflict.entity_type || 'asset'} · {formatCount(conflict.owner_count)} owners ·{' '}
                            {formatCount(conflict.claim_count)} claims
                          </span>
                        </div>
                        <span className="severity-pill is-medium">
                          conf {formatCount(Math.round(numericValue(conflict.highest_confidence) * 100))}%
                        </span>
                      </div>
                      <div className="token-wrap">
                        {conflict.owners.map((owner) => {
                          const ownerBusyKey = `${conflict.entity_key}:${owner.owner_kind ?? ''}:${owner.owner_ref}`
                          return (
                            <button
                              className="token token-button"
                              disabled={!liveToken || graphConflictBusyKey === ownerBusyKey}
                              key={`${owner.owner_kind ?? 'owner'}:${owner.owner_ref}`}
                              onClick={() => void handleGraphConflictResolve(conflict, owner)}
                              title={`${owner.owner_kind || 'owner'} · ${owner.source || 'unknown source'}`}
                              type="button"
                            >
                              Resolve to {owner.owner_display || owner.owner_ref}
                            </button>
                          )
                        })}
                      </div>
                    </article>
                  ))}
                </div>
              ) : (
                <span className="muted-copy">No active ownership conflicts in the current graph snapshot.</span>
              )}
              {graphConflictMessage ? <span className="muted-copy">{graphConflictMessage}</span> : null}
              {graphConflictError ? <span className="auth-error">{graphConflictError}</span> : null}
            </div>
            <GraphExplorer detail={detail} />
          </div>
        </article>

        <article className="panel" id="findings">
          <div className="panel-head">
            <p className="section-kicker">Reportable validated findings</p>
            <strong>{formatCount(findingRows.length)}</strong>
          </div>
          <div className="panel-body findings-stack">
            <DataList rows={findingRows} emptyText="No validated finding rows captured yet." />
          </div>
        </article>

        <article className="panel" id="validation-inventory">
          <div className="panel-head">
            <p className="section-kicker">Validation inventory</p>
            <strong>{formatCount(keyFindingRows.length + secretLifecycleRows.length + cloudValidationRows.length)}</strong>
          </div>
          <div className="panel-body findings-stack">
            <DataList rows={keyFindingRows} emptyText="No key validation inventory rows captured yet." />
            <DataList rows={secretLifecycleRows} emptyText="No secret lifecycle rows captured yet." />
            <DataList rows={cloudValidationRows} emptyText="No cloud validation inventory rows captured yet." />
          </div>
        </article>

        <article className="panel" id="active-validation">
          <div className="panel-head">
            <p className="section-kicker">Active validation</p>
            <strong>
              {formatCount(activeValidationJobCount)} jobs / {formatCount(activeValidationRunCount)} runs
            </strong>
          </div>
          <div className="panel-body findings-stack">
            <div className="token-wrap">
              <span className="token">approved {formatCount(activeValidationApprovedJobCount)}</span>
              <span className="token">completed {formatCount(activeValidationCompletedRunCount)}</span>
              <span className="token">blocked {formatCount(activeValidationBlockedRunCount)}</span>
              <span className="token">ATT&CK {formatCount(activeValidationAttackMappingCount)}</span>
              <span className="token">controls {formatCount(activeValidationControlFamilyCount)}</span>
              <span className="token">methods {formatCount(activeValidationMethodCoverageCount)}</span>
              <span className="token">graph drafts {formatCount(activeValidationGraphScenarioCount)}</span>
              <span className="token">coverage {activeValidationCoverageStateLabel(activeValidationCoverageStates)}</span>
              <span className="token">live {activeValidationAllowLive ? 'armed' : 'off'}</span>
              <span className="token">read_only_live http + headers + fix: gated</span>
              {activeValidationLoadError ? <span className="auth-error">{activeValidationLoadError}</span> : null}
            </div>

            <div className="scope-block">
              <span className="summary-label">Graph recommendations</span>
              {activeValidationGraphScenarios.length ? (
                <div className="active-validation-card-grid">
                  {activeValidationGraphScenarios.slice(0, 6).map((scenario, index) => (
                    <article className="active-validation-card" key={`${scenario.target_ref}-${scenario.method}-${index}`}>
                      <div className="active-validation-card-head">
                        <strong>{scenario.title || scenario.target_ref || `graph draft ${index + 1}`}</strong>
                        <span className="status-pill is-muted">{scenario.mode || 'dry_run'}</span>
                      </div>
                      <div className="token-wrap">
                        <span className="token">{scenario.method || '-'}</span>
                        <span className="token">{scenario.target_kind || '-'}</span>
                        <span className="token">network {scenario.network_execution ? 'yes' : 'no'}</span>
                        <span className="token">approved {scenario.approved ? 'yes' : 'no'}</span>
                        {(scenario.risk_tags ?? []).slice(0, 3).map((tag) => (
                          <span className="token" key={tag}>{tag}</span>
                        ))}
                      </div>
                      <div className="mini-table">
                        <div className="mini-table-row">
                          <span>{scenario.target_ref || '-'}</span>
                          <span>{scenario.reason || '-'}</span>
                          <span>{scenario.expected_result || '-'}</span>
                        </div>
                      </div>
                      <div className="token-wrap">
                        <button
                          className="token-action is-secondary"
                          disabled={activeValidationBusy}
                          onClick={() => handleUseActiveValidationGraphScenario(scenario)}
                          type="button"
                        >
                          Use draft
                        </button>
                      </div>
                    </article>
                  ))}
                </div>
              ) : (
                <span className="muted-copy">No graph-recommended validation drafts captured yet.</span>
              )}
            </div>

            <div className="scope-block">
              <span className="summary-label">Create job</span>
              <div className="active-validation-form">
                <label className="graph-filter">
                  <span>Target</span>
                  <input
                    value={activeValidationTarget}
                    onChange={(event) => {
                      clearActiveValidationGraphScenario()
                      setActiveValidationTarget(event.target.value)
                    }}
                    placeholder="host:app.acme.example"
                  />
                </label>
                <label className="graph-filter">
                  <span>Kind</span>
                  <select
                    value={activeValidationTargetKind}
                    onChange={(event) => {
                      clearActiveValidationGraphScenario()
                      setActiveValidationTargetKind(normalizeActiveValidationTargetKind(event.target.value))
                    }}
                  >
                    {ACTIVE_VALIDATION_TARGET_KINDS.map((kind) => (
                      <option key={kind} value={kind}>
                        {kind}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="graph-filter">
                  <span>Method</span>
                  <select
                    value={activeValidationMethod}
                    onChange={(event) => {
                      clearActiveValidationGraphScenario()
                      setActiveValidationMethod(normalizeActiveValidationMethodId(event.target.value))
                    }}
                  >
                    {activeValidationMethods.map((method) => (
                      <option key={method.id} value={method.id}>
                        {method.id}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="graph-filter">
                  <span>Mode</span>
                  <select
                    value={activeValidationMode}
                    onChange={(event) => {
                      clearActiveValidationGraphScenario()
                      setActiveValidationMode(normalizeActiveValidationMode(event.target.value))
                    }}
                  >
                    {ACTIVE_VALIDATION_MODES.map((mode) => (
                      <option key={mode} value={mode}>
                        {mode}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="graph-filter">
                  <span>Steps</span>
                  <input
                    min="1"
                    max="50"
                    type="number"
                    value={activeValidationMaxSteps}
                    onChange={(event) => setActiveValidationMaxSteps(Number(event.target.value || 1))}
                  />
                </label>
                <button
                  className="token-action"
                  disabled={!liveToken || activeValidationBusy}
                  onClick={() => void handleActiveValidationCreate()}
                  type="button"
                >
                  {activeValidationBusy ? 'Working...' : 'Create job'}
                </button>
              </div>
              {selectedActiveValidationGraphScenario ? (
                <div className="token-wrap">
                  <span className="token">graph lineage attached</span>
                  <span className="token">
                    {selectedActiveValidationGraphScenario.reason || 'asset_graph'}
                  </span>
                  <span className="token">
                    {selectedActiveValidationGraphScenario.expected_result || 'validation draft'}
                  </span>
                  <button
                    className="token-action is-secondary"
                    disabled={activeValidationBusy}
                    onClick={clearActiveValidationGraphScenario}
                    type="button"
                  >
                    Clear graph draft
                  </button>
                </div>
              ) : null}
            </div>

            <div className="scope-block">
              <span className="summary-label">Approval context</span>
              <div className="active-validation-approval-grid">
                <label className="graph-filter">
                  <span>ROE</span>
                  <input
                    value={activeValidationRoe}
                    onChange={(event) => setActiveValidationRoe(event.target.value)}
                    placeholder="ROE-1001"
                  />
                </label>
                <label className="graph-filter">
                  <span>Approval note</span>
                  <input
                    value={activeValidationApprovalNote}
                    onChange={(event) => setActiveValidationApprovalNote(event.target.value)}
                    placeholder="read-only proof approved"
                  />
                </label>
                <label className="graph-toggle">
                  <input
                    checked={activeValidationAllowLive}
                    onChange={(event) => setActiveValidationAllowLive(event.target.checked)}
                    type="checkbox"
                  />
                  <span>Allow live run</span>
                </label>
                <label className="graph-filter active-validation-scope-field">
                  <span>Scope manifest</span>
                  <textarea
                    value={activeValidationScope}
                    onChange={(event) => setActiveValidationScope(event.target.value)}
                    placeholder='{"roe_id":"ROE-1001","authorized_seeds":["https://app.acme.example/health"]}'
                    rows={4}
                  />
                </label>
              </div>
            </div>

            <div className="scope-block">
              <span className="summary-label">Methods</span>
              <div className="active-validation-card-grid">
                {activeValidationMethods.map((method) => (
                  <article className="active-validation-card" key={method.id}>
                    <div className="active-validation-card-head">
                      <strong>{method.label || method.id}</strong>
                      <span className="status-pill is-muted">{method.implementation_status || 'catalog'}</span>
                    </div>
                    <div className="token-wrap">
                      <span className="token">{method.proof_kind || '-'}</span>
                      <span className="token">{method.safety_profile || '-'}</span>
                      <span className="token">{method.supported_modes.join(', ') || '-'}</span>
                    </div>
                    <p className="card-copy">{method.description || activeValidationMethodCoverage(method)}</p>
                  </article>
                ))}
              </div>
            </div>

            <div className="scope-block">
              <span className="summary-label">Coverage</span>
              <DataList
                rows={activeValidationCoverageRowsForDisplay}
                emptyText="No active-validation coverage captured yet."
              />
            </div>

            <div className="scope-block">
              <span className="summary-label">Jobs</span>
              {activeValidationJobs.length ? (
                <div className="active-validation-card-grid">
                  {activeValidationJobs.map((job) => {
                    const method = job.method_config
                    return (
                      <article className="active-validation-card" key={job.id}>
                        <div className="active-validation-card-head">
                          <strong>{job.target_ref || `job ${job.id}`}</strong>
                          <span className={`status-pill ${statusTone(job.status)}`}>
                            {job.status || 'queued'}
                          </span>
                        </div>
                        <div className="token-wrap">
                          <span className="token">{job.method || '-'}</span>
                          <span className="token">{job.mode || '-'}</span>
                          <span className="token">approved {job.approved ? 'yes' : 'no'}</span>
                          <span className="token">proof {method?.proof_kind ?? '-'}</span>
                        </div>
                        <div className="mini-table">
                          <div className="mini-table-row">
                            <span>ROE {job.roe_id || '-'}</span>
                            <span>Scope {job.scope_manifest_ref || (job.scope_manifest_hash ? 'stored' : '-')}</span>
                            <span>{activeValidationMethodCoverage(method)}</span>
                            <span>updated {job.updated_at || '-'}</span>
                          </div>
                        </div>
                        <div className="token-wrap">
                          <button
                            className="token-action is-secondary"
                            disabled={!liveToken || activeValidationBusy || job.approved}
                            onClick={() => void handleActiveValidationApprove(job)}
                            type="button"
                          >
                            Approve
                          </button>
                          <button
                            className="token-action"
                            disabled={!liveToken || activeValidationBusy}
                            onClick={() => void handleActiveValidationRun(job, false)}
                            type="button"
                          >
                            Run
                          </button>
                          <button
                            className="token-action is-secondary"
                            disabled={!liveToken || activeValidationBusy || !activeValidationAllowLive}
                            onClick={() => void handleActiveValidationRun(job, true)}
                            type="button"
                          >
                            Run live gate
                          </button>
                        </div>
                      </article>
                    )
                  })}
                </div>
              ) : (
                <DataList rows={activeValidationJobRows} emptyText="No active-validation jobs captured yet." />
              )}
            </div>

            <div className="scope-block">
              <span className="summary-label">Runs</span>
              <DataList rows={activeValidationRunRows} emptyText="No active-validation runs captured yet." />
            </div>

            {activeValidationMessage ? <span className="muted-copy">{activeValidationMessage}</span> : null}
            {activeValidationError ? <span className="auth-error">{activeValidationError}</span> : null}
          </div>
        </article>

        <article className="panel" id="remediation">
          <div className="panel-head">
            <p className="section-kicker">Remediation workflow</p>
            <strong>
              {formatCount(remediationRows.length)} items / {formatCount(remediationOpenCount)} active
            </strong>
          </div>
          <div className="panel-body findings-stack">
            <div className="token-wrap">
              <span className="token">owners {formatCount(remediationWithOwnerCount)}</span>
              <span className="token">SLA {formatCount(remediationWithSlaCount)}</span>
              <span className="token">tickets {formatCount(remediationWithTicketCount)}</span>
              <span className="token">risk accepted {formatCount(remediationRiskAcceptedCount)}</span>
              <span className="token">risk review due {formatCount(remediationRiskReviewDueCount)}</span>
              <span className="token">expired {formatCount(remediationRiskExpiredCount)}</span>
              <span className="token">expiring {formatCount(remediationRiskExpiringSoonCount)}</span>
              <span className="token">retest pending {formatCount(remediationRetestPendingCount)}</span>
              <span className="token">review queue {formatCount(remediationReviewQueueCount)}</span>
              <span className="token">SLA overdue {formatCount(remediationSlaOverdueCount)}</span>
              <span className="token">retest blocked {formatCount(remediationRetestBlockedCount)}</span>
              <span className="token">missing tickets {formatCount(remediationMissingTicketCount)}</span>
              <span className="token">ticket sync failed {formatCount(remediationTicketSyncFailedCount)}</span>
              {remediationLoadError ? <span className="auth-error">{remediationLoadError}</span> : null}
              <a
                className="token token-link"
                href={`/api/engagements/${detail.slug}/remediation/export?format=json`}
                target="_blank"
                rel="noreferrer"
              >
                Export JSON
              </a>
              <a
                className="token token-link"
                href={`/api/engagements/${detail.slug}/remediation/export?format=csv`}
                target="_blank"
                rel="noreferrer"
              >
                Export CSV
              </a>
            </div>

            <div className="remediation-command-strip">
              <div className="remediation-command-card">
                <span className="summary-label">Selected item</span>
                <strong>{selectedRemediationItem?.title || 'No item selected'}</strong>
                <div className="token-wrap">
                  <span className={`status-pill ${statusTone(selectedRemediationItem?.status || 'open')}`}>
                    {selectedRemediationItem?.status || '-'}
                  </span>
                  <span className="token">owner {selectedRemediationItem?.owner || '-'}</span>
                  <span className="token">
                    owner review {selectedRemediationItem?.owner_approval?.decision || 'unreviewed'}
                  </span>
                  <span className="token">ticket {selectedRemediationItem ? remediationTicketLabel(selectedRemediationItem) : '-'}</span>
                  <button
                    className="token-action"
                    disabled={!liveToken || remediationBusy || !selectedRemediationItem || !selectedRemediationItem.owner}
                    onClick={() => void handleRemediationOwnerReview('approved')}
                    type="button"
                  >
                    Approve owner
                  </button>
                  <button
                    className="token-action is-secondary"
                    disabled={!liveToken || remediationBusy || !selectedRemediationItem}
                    onClick={() => void handleRemediationOwnerReview('rejected')}
                    type="button"
                  >
                    Reject owner
                  </button>
                  <button
                    className="token-action is-secondary"
                    disabled={!liveToken || remediationBusy || !selectedRemediationItem}
                    onClick={() => void handleRemediationOwnerReview('needs_review')}
                    type="button"
                  >
                    Needs review
                  </button>
                </div>
              </div>
              <div className="remediation-command-card">
                <span className="summary-label">Queue health</span>
                <strong>{formatCount(remediationReviewQueueCount)} need attention</strong>
                <div className="token-wrap">
                  <span className="token">SLA overdue {formatCount(remediationSlaOverdueCount)}</span>
                  <span className="token">missing tickets {formatCount(remediationMissingTicketCount)}</span>
                  <span className="token">blocked retests {formatCount(remediationRetestBlockedCount)}</span>
                </div>
              </div>
              <div className="remediation-command-card">
                <span className="summary-label">Action readiness</span>
                <strong>{liveToken ? 'Live API unlocked' : 'Live API locked'}</strong>
                <div className="token-wrap">
                  <span className="token">graph owners {formatCount(remediationWithOwnerCount)}</span>
                  <span className="token">retests {formatCount(remediationRetestPendingCount)}</span>
                  <span className="token">sync failures {formatCount(remediationTicketSyncFailedCount)}</span>
                </div>
              </div>
            </div>

            <div className="scope-block">
              <span className="summary-label">Items</span>
              {remediationItems.length ? (
                <div className="active-validation-card-grid">
                  {remediationItems.map((item) => (
                    <article className="active-validation-card" key={item.id}>
                      <div className="active-validation-card-head">
                        <strong>{item.title || `item ${item.id}`}</strong>
                        <span className={`severity-pill ${severityTone(item.severity)}`}>
                          {item.severity || 'INFO'}
                        </span>
                      </div>
                      <div className="token-wrap">
                        <span className={`status-pill ${statusTone(item.status)}`}>{item.status || 'open'}</span>
                        <span className="token">owner {item.owner || '-'}</span>
                        <span className="token">retest {item.retest_status || '-'}</span>
                        <span className="token">ticket {remediationTicketLabel(item)}</span>
                        {item.risk_acceptance_review_status ? (
                          <span
                            className={`status-pill ${riskReviewTone(item.risk_acceptance_review_status)}`}
                          >
                            risk {riskReviewLabel(item.risk_acceptance_review_status)}
                          </span>
                        ) : null}
                      </div>
                      <div className="mini-table">
                        <div className="mini-table-row">
                          <span>{item.finding_table || 'manual'}</span>
                          <span>{item.finding_ref || item.finding_id || item.id}</span>
                          <span>SLA {item.sla_due_at || '-'}</span>
                          <span>updated {item.updated_at || '-'}</span>
                        </div>
                      </div>
                      <button
                        className="token-action is-secondary"
                        onClick={() => setSelectedRemediationId(item.id)}
                        type="button"
                      >
                        {selectedRemediationItem?.id === item.id ? 'Selected' : 'Select'}
                      </button>
                    </article>
                  ))}
                </div>
              ) : (
                <DataList rows={remediationRows} emptyText="No remediation workflow rows captured yet." />
              )}
            </div>

            <div className="scope-block">
              <span className="summary-label">Review queue</span>
              <div className="token-wrap">
                <span className="token">attention {formatCount(remediationReviewQueueCount)}</span>
                <span className="token">unowned {formatCount(remediationUnownedCount)}</span>
                <span className="token">missing tickets {formatCount(remediationMissingTicketCount)}</span>
                <span className="token">SLA overdue {formatCount(remediationSlaOverdueCount)}</span>
                <span className="token">blocked retests {formatCount(remediationRetestBlockedCount)}</span>
                <span className="token">ticket sync failed {formatCount(remediationTicketSyncFailedCount)}</span>
                {remediationReviewQueue?.truncated ? <span className="token">truncated</span> : null}
              </div>
              <DataList rows={remediationReviewQueueRows} emptyText="No remediation review-queue rows captured yet." />
            </div>

            <div className="scope-block">
              <span className="summary-label">Ownership routing</span>
              <div className="token-wrap">
                <span className="token">unowned {formatCount(remediationUnownedCount)}</span>
                <span className="token">owned {formatCount(remediationWithOwnerCount)}</span>
              </div>
              <div className="active-validation-form">
                <label className="graph-toggle">
                  <input
                    checked={remediationOwnerOverwrite}
                    disabled={!liveToken || remediationBusy}
                    onChange={(event) => setRemediationOwnerOverwrite(event.target.checked)}
                    type="checkbox"
                  />
                  <span>Overwrite explicit owners</span>
                </label>
                <label className="graph-filter">
                  <span>Conflict policy</span>
                  <select
                    disabled={!liveToken || remediationBusy}
                    value={remediationOwnerConflictPolicy}
                    onChange={(event) => setRemediationOwnerConflictPolicy(event.target.value)}
                  >
                    <option value="highest_confidence">Highest confidence</option>
                    <option value="skip_conflicts">Skip conflicts</option>
                  </select>
                </label>
                <label className="graph-filter">
                  <span>Min confidence</span>
                  <input
                    disabled={!liveToken || remediationBusy}
                    max="1"
                    min="0"
                    onChange={(event) => setRemediationOwnerMinConfidence(event.target.value)}
                    step="0.05"
                    type="number"
                    value={remediationOwnerMinConfidence}
                  />
                </label>
                <button
                  className="token-action"
                  disabled={!liveToken || remediationBusy || remediationRows.length === 0}
                  onClick={() => void handleRemediationOwnerPropagation()}
                  type="button"
                >
                  {remediationBusy ? 'Working...' : 'Apply graph owners'}
                </button>
                <button
                  className="token-action"
                  disabled={!liveToken || remediationBusy}
                  onClick={() => void handleRemediationGraphDraft()}
                  type="button"
                >
                  {remediationBusy ? 'Working...' : 'Draft graph fixes'}
                </button>
              </div>
            </div>

            <div className="scope-block">
              <span className="summary-label">Live controls</span>
              <div className="active-validation-form">
                <label className="graph-filter">
                  <span>Owner</span>
                  <input
                    value={remediationOwner}
                    onChange={(event) => setRemediationOwner(event.target.value)}
                    placeholder="appsec"
                  />
                </label>
                <label className="graph-filter">
                  <span>Status</span>
                  <select
                    value={remediationStatus}
                    onChange={(event) => setRemediationStatus(normalizeRemediationStatus(event.target.value))}
                  >
                    {REMEDIATION_STATUSES.map((status) => (
                      <option key={status} value={status}>
                        {status}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="graph-filter">
                  <span>Retest</span>
                  <select
                    value={remediationRetestStatus}
                    onChange={(event) =>
                      setRemediationRetestStatus(normalizeRemediationRetestStatus(event.target.value))
                    }
                  >
                    {REMEDIATION_RETEST_STATUSES.map((status) => (
                      <option key={status} value={status}>
                        {status}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="graph-filter">
                  <span>SLA</span>
                  <input
                    value={remediationSlaDueAt}
                    onChange={(event) => setRemediationSlaDueAt(event.target.value)}
                    placeholder="2026-08-31"
                  />
                </label>
                <label className="graph-filter">
                  <span>Ticket system</span>
                  <input
                    value={remediationTicketSystem}
                    onChange={(event) => setRemediationTicketSystem(event.target.value)}
                    placeholder="github_issues"
                  />
                </label>
                <label className="graph-filter">
                  <span>Ticket ref</span>
                  <input
                    value={remediationTicketRef}
                    onChange={(event) => setRemediationTicketRef(event.target.value)}
                    placeholder="SEC-1001"
                  />
                </label>
                <label className="graph-filter">
                  <span>Ticket URL</span>
                  <input
                    value={remediationTicketUrl}
                    onChange={(event) => setRemediationTicketUrl(event.target.value)}
                    placeholder="https://tracker.example/SEC-1001"
                  />
                </label>
                <label className="graph-filter remediation-risk-field">
                  <span>Risk acceptance</span>
                  <textarea
                    value={remediationRiskReason}
                    onChange={(event) => setRemediationRiskReason(event.target.value)}
                    placeholder="business exception and approver"
                    rows={3}
                  />
                </label>
                <label className="graph-filter">
                  <span>Risk expiry</span>
                  <input
                    value={remediationRiskExpiresAt}
                    onChange={(event) => setRemediationRiskExpiresAt(event.target.value)}
                    placeholder="2026-12-31T00:00:00Z"
                  />
                </label>
                <button
                  className="token-action"
                  disabled={!liveToken || remediationBusy || !selectedRemediationItem}
                  onClick={() => void handleRemediationSave()}
                  type="button"
                >
                  {remediationBusy ? 'Working...' : 'Save'}
                </button>
              </div>
            </div>

            <div className="scope-block">
              <span className="summary-label">Ticket destinations</span>
              <div className="active-validation-form">
                <label className="graph-toggle">
                  <input
                    checked={remediationTicketSync.force ?? true}
                    disabled={!liveToken || remediationBusy}
                    onChange={(event) => setRemediationTicketSyncValue('force', event.target.checked)}
                    type="checkbox"
                  />
                  <span>Force sync</span>
                </label>
                <label className="graph-filter">
                  <span>Webhook URL</span>
                  <input
                    value={remediationTicketSync.webhookUrl ?? ''}
                    onChange={(event) => setRemediationTicketSyncValue('webhookUrl', event.target.value)}
                    placeholder="https://hooks.example/forge"
                  />
                </label>
                <label className="graph-filter">
                  <span>GitHub repo</span>
                  <input
                    value={remediationTicketSync.githubRepo ?? ''}
                    onChange={(event) => setRemediationTicketSyncValue('githubRepo', event.target.value)}
                    placeholder="owner/repo"
                  />
                </label>
                <label className="graph-filter">
                  <span>GitHub token env</span>
                  <input
                    value={remediationTicketSync.githubTokenEnv ?? ''}
                    onChange={(event) => setRemediationTicketSyncValue('githubTokenEnv', event.target.value)}
                    placeholder="FORGE_GITHUB_TOKEN"
                  />
                </label>
                <label className="graph-filter">
                  <span>Jira URL</span>
                  <input
                    value={remediationTicketSync.jiraBaseUrl ?? ''}
                    onChange={(event) => setRemediationTicketSyncValue('jiraBaseUrl', event.target.value)}
                    placeholder="https://acme.atlassian.net"
                  />
                </label>
                <label className="graph-filter">
                  <span>Jira project</span>
                  <input
                    value={remediationTicketSync.jiraProjectKey ?? ''}
                    onChange={(event) => setRemediationTicketSyncValue('jiraProjectKey', event.target.value)}
                    placeholder="SEC"
                  />
                </label>
                <label className="graph-filter">
                  <span>Jira token env</span>
                  <input
                    value={remediationTicketSync.jiraTokenEnv ?? ''}
                    onChange={(event) => setRemediationTicketSyncValue('jiraTokenEnv', event.target.value)}
                    placeholder="FORGE_JIRA_API_TOKEN"
                  />
                </label>
                <label className="graph-filter">
                  <span>ServiceNow URL</span>
                  <input
                    value={remediationTicketSync.servicenowInstanceUrl ?? ''}
                    onChange={(event) =>
                      setRemediationTicketSyncValue('servicenowInstanceUrl', event.target.value)
                    }
                    placeholder="https://acme.service-now.com"
                  />
                </label>
                <label className="graph-filter">
                  <span>ServiceNow token env</span>
                  <input
                    value={remediationTicketSync.servicenowTokenEnv ?? ''}
                    onChange={(event) => setRemediationTicketSyncValue('servicenowTokenEnv', event.target.value)}
                    placeholder="FORGE_SERVICENOW_TOKEN"
                  />
                </label>
                <label className="graph-filter">
                  <span>Tines webhook</span>
                  <input
                    value={remediationTicketSync.tinesWebhookUrl ?? ''}
                    onChange={(event) => setRemediationTicketSyncValue('tinesWebhookUrl', event.target.value)}
                    placeholder="https://tenant.tines.com/webhook/..."
                  />
                </label>
                <label className="graph-filter">
                  <span>Tines token env</span>
                  <input
                    value={remediationTicketSync.tinesTokenEnv ?? ''}
                    onChange={(event) => setRemediationTicketSyncValue('tinesTokenEnv', event.target.value)}
                    placeholder="FORGE_TINES_WEBHOOK_TOKEN"
                  />
                </label>
                <label className="graph-filter">
                  <span>Splunk HEC URL</span>
                  <input
                    value={remediationTicketSync.splunkHecUrl ?? ''}
                    onChange={(event) => setRemediationTicketSyncValue('splunkHecUrl', event.target.value)}
                    placeholder="https://splunk.example:8088/services/collector/event"
                  />
                </label>
                <label className="graph-filter">
                  <span>Splunk token env</span>
                  <input
                    value={remediationTicketSync.splunkHecTokenEnv ?? ''}
                    onChange={(event) => setRemediationTicketSyncValue('splunkHecTokenEnv', event.target.value)}
                    placeholder="FORGE_SPLUNK_HEC_TOKEN"
                  />
                </label>
                <label className="graph-filter">
                  <span>Splunk index</span>
                  <input
                    value={remediationTicketSync.splunkIndex ?? ''}
                    onChange={(event) => setRemediationTicketSyncValue('splunkIndex', event.target.value)}
                    placeholder="security"
                  />
                </label>
                <label className="graph-filter">
                  <span>Splunk source</span>
                  <input
                    value={remediationTicketSync.splunkSource ?? ''}
                    onChange={(event) => setRemediationTicketSyncValue('splunkSource', event.target.value)}
                    placeholder="forge"
                  />
                </label>
                <label className="graph-filter">
                  <span>Torq webhook</span>
                  <input
                    value={remediationTicketSync.torqWebhookUrl ?? ''}
                    onChange={(event) => setRemediationTicketSyncValue('torqWebhookUrl', event.target.value)}
                    placeholder="https://hooks.torq.io/v1/webhooks/..."
                  />
                </label>
                <label className="graph-filter">
                  <span>Torq token env</span>
                  <input
                    value={remediationTicketSync.torqTokenEnv ?? ''}
                    onChange={(event) => setRemediationTicketSyncValue('torqTokenEnv', event.target.value)}
                    placeholder="FORGE_TORQ_WEBHOOK_TOKEN"
                  />
                </label>
                <button
                  className="token-action is-secondary"
                  disabled={!liveToken || remediationBusy || !selectedRemediationItem}
                  onClick={() => void handleRemediationTicketSync()}
                  type="button"
                >
                  Sync ticket
                </button>
              </div>
            </div>

            <div className="scope-block">
              <span className="summary-label">Validation retest</span>
              <div className="active-validation-form">
                <label className="graph-filter">
                  <span>Target override</span>
                  <input
                    value={remediationRetestTarget}
                    onChange={(event) => setRemediationRetestTarget(event.target.value)}
                    placeholder="fixture://proof-packs/fixed"
                  />
                </label>
                <label className="graph-filter">
                  <span>Target kind</span>
                  <select
                    value={remediationRetestTargetKind}
                    onChange={(event) =>
                      setRemediationRetestTargetKind(normalizeActiveValidationTargetKind(event.target.value))
                    }
                  >
                    {ACTIVE_VALIDATION_TARGET_KINDS.map((kind) => (
                      <option key={kind} value={kind}>
                        {kind}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="graph-filter">
                  <span>Method</span>
                  <select
                    value={remediationRetestMethod}
                    onChange={(event) => setRemediationRetestMethod(normalizeActiveValidationMethodId(event.target.value))}
                  >
                    {activeValidationMethods.map((method) => (
                      <option key={method.id} value={method.id}>
                        {method.label || method.id}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="graph-filter">
                  <span>Mode</span>
                  <select
                    value={remediationRetestMode}
                    onChange={(event) => setRemediationRetestMode(normalizeActiveValidationMode(event.target.value))}
                  >
                    {ACTIVE_VALIDATION_MODES.map((mode) => (
                      <option key={mode} value={mode}>
                        {mode}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="graph-filter">
                  <span>Expected result</span>
                  <input
                    value={remediationRetestExpectedResult}
                    onChange={(event) => setRemediationRetestExpectedResult(event.target.value)}
                    placeholder="not_reachable"
                  />
                </label>
                <label className="graph-filter">
                  <span>ROE</span>
                  <input
                    value={activeValidationRoe}
                    onChange={(event) => setActiveValidationRoe(event.target.value)}
                    placeholder="ROE-1001"
                  />
                </label>
                <label className="graph-filter">
                  <span>Approval note</span>
                  <input
                    value={activeValidationApprovalNote}
                    onChange={(event) => setActiveValidationApprovalNote(event.target.value)}
                    placeholder="read-only retest approved"
                  />
                </label>
                <label className="graph-toggle">
                  <input
                    checked={remediationRetestApprove}
                    onChange={(event) => setRemediationRetestApprove(event.target.checked)}
                    type="checkbox"
                  />
                  <span>Pre-approve job</span>
                </label>
                <label className="graph-filter active-validation-scope-field">
                  <span>Scope manifest</span>
                  <textarea
                    value={activeValidationScope}
                    onChange={(event) => setActiveValidationScope(event.target.value)}
                    placeholder='{"roe_id":"ROE-1001","authorized_seeds":["https://app.acme.example/health"]}'
                    rows={4}
                  />
                </label>
                <button
                  className="token-action"
                  disabled={!liveToken || remediationBusy || !selectedRemediationItem}
                  onClick={() => void handleRemediationRetestRequest()}
                  type="button"
                >
                  {remediationBusy ? 'Working...' : 'Request retest'}
                </button>
              </div>
              {remediationMessage ? <span className="muted-copy">{remediationMessage}</span> : null}
              {remediationError ? <span className="auth-error">{remediationError}</span> : null}
            </div>
          </div>
        </article>

        <article className="panel" id="retention">
          <div className="panel-head">
            <p className="section-kicker">Retention</p>
            <strong>
              {retentionPolicyName} / {retentionEnabledLabel}
            </strong>
          </div>
          <div className="panel-body findings-stack">
            <div className="token-wrap">
              <span className="token">legal hold {retentionLegalHoldLabel}</span>
              <span className="token">runs {formatCount(retentionRunCount)}</span>
              <span className="token">eligible {formatCount(retentionEligibleCount)}</span>
              <span className="token">deleted {formatCount(retentionDeletedCount)}</span>
              <span className="token">latest {retentionLatestRunLabel}</span>
              {retentionLoadError ? <span className="auth-error">{retentionLoadError}</span> : null}
            </div>

            <div className="scope-block">
              <span className="summary-label">Current policy</span>
              <DataList rows={retentionPolicyRows} emptyText="No retention policy rows captured yet." />
            </div>

            <div className="scope-block">
              <span className="summary-label">Live controls</span>
              <div className="active-validation-form">
                <button
                  className="token-action"
                  disabled={!liveToken || retentionBusy}
                  onClick={() => void handleRetentionPreview()}
                  type="button"
                >
                  {retentionBusy ? 'Working...' : 'Preview'}
                </button>
                <label className="graph-toggle">
                  <input
                    checked={retentionConfirmApply}
                    disabled={!liveToken || retentionBusy}
                    onChange={(event) => setRetentionConfirmApply(event.target.checked)}
                    type="checkbox"
                  />
                  <span>Confirm apply</span>
                </label>
                <button
                  className="token-action is-secondary"
                  disabled={!liveToken || retentionBusy || !retentionConfirmApply}
                  onClick={() => void handleRetentionApply()}
                  type="button"
                >
                  Apply
                </button>
              </div>
              {retentionMessage ? <span className="muted-copy">{retentionMessage}</span> : null}
              {retentionError ? <span className="auth-error">{retentionError}</span> : null}
            </div>

            <div className="scope-block">
              <span className="summary-label">Recent runs</span>
              <DataList rows={retentionRunRows} emptyText="No retention runs captured yet." />
            </div>

            <div className="scope-block">
              <span className="summary-label">Run items</span>
              <DataList rows={retentionRunItemRows} emptyText="No retention run items captured yet." />
            </div>
          </div>
        </article>

        <article className="panel" id="connector-catalog">
          <div className="panel-head">
            <p className="section-kicker">Connector catalog</p>
            <strong>
              {formatCount(connectorCatalogConfiguredCount)} / {formatCount(connectorCatalog.length)} ready
            </strong>
          </div>
          <div className="panel-body findings-stack">
            <div className="token-wrap">
              <span className="token">free-first {formatCount(connectorCatalogFreeFirstCount)}</span>
              <span className="token">secret-store {formatCount(connectorCatalogSecretStoreCount)}</span>
              <span className="token">plugin manifests {formatCount(connectorCatalogPluginManifestCount)}</span>
              <span className="token">
                active-validation plugins {formatCount(connectorCatalogActiveValidationPluginManifestCount)}
              </span>
              <span className="token">plugin catalog {formatCount(connectorCatalogPluginManifestCatalogCount)}</span>
              <span className="token">runner paths {formatCount(connectorCatalogRunnerSupportedCount)}</span>
              <span className="token">missing binaries {formatCount(connectorCatalogMissingBinaryCount)}</span>
              <span className="token">optional keys {formatCount(connectorCatalogOptionalKeyCount)}</span>
              <span className="token">decrypt failed {formatCount(connectorCatalogDecryptFailureCount)}</span>
              <span className="token">partial keys {formatCount(connectorCatalogStoredKeyMissingCount)}</span>
              {connectorCatalogLoadError ? <span className="auth-error">{connectorCatalogLoadError}</span> : null}
            </div>
            <div className="scope-block">
              <span className="summary-label">Readiness matrix</span>
              <DataList rows={connectorCatalogRows} emptyText="Unlock live API access to load connector readiness." />
            </div>
          </div>
        </article>

        <article className="panel" id="connector-secrets">
          <div className="panel-head">
            <p className="section-kicker">Connector secrets</p>
            <strong>{formatCount(connectorSecretCount)} stored</strong>
          </div>
          <div className="panel-body findings-stack">
            <div className="token-wrap">
              <span className="token">connectors {formatCount(connectorSecretConnectors.length)}</span>
              <span className="token">encrypted</span>
              {connectorSecretsLoadError ? <span className="auth-error">{connectorSecretsLoadError}</span> : null}
            </div>

            <div className="scope-block">
              <span className="summary-label">Stored credentials</span>
              <DataList rows={connectorSecretRows} emptyText="No connector secrets stored yet." />
            </div>

            <div className="scope-block">
              <span className="summary-label">Live controls</span>
              <div className="active-validation-form connector-secret-form">
                <label className="graph-filter">
                  <span>Connector</span>
                  <select
                    value={connectorSecretConnectorId}
                    onChange={(event) => {
                      const nextConnectorId = event.target.value
                      setConnectorSecretConnectorId(nextConnectorId)
                      const nextConnector = connectorSecretConnectorOptions.find(
                        (connector) => connector.id === nextConnectorId,
                      )
                      const nextName = connectorCredentialNames(nextConnector)[0] || ''
                      setConnectorSecretName(nextName)
                      if (nextName) {
                        setConnectorSecretRef(`env:${nextName}`)
                      }
                    }}
                  >
                    {connectorSecretConnectorOptions.length ? null : (
                      <option value="">No credentialed connectors</option>
                    )}
                    {connectorSecretConnectorOptions.map((connector) => (
                      <option key={connector.id} value={connector.id}>
                        {connector.label} ({connector.cost_profile})
                      </option>
                    ))}
                  </select>
                </label>
                <label className="graph-filter">
                  <span>Name</span>
                  <select
                    value={connectorSecretName}
                    onChange={(event) => {
                      const nextName = event.target.value
                      setConnectorSecretName(nextName)
                      if (!connectorSecretRef.trim() || connectorSecretRef.startsWith('env:')) {
                        setConnectorSecretRef(`env:${nextName}`)
                      }
                    }}
                  >
                    {connectorSecretNameOptions.length ? null : <option value="">No declared names</option>}
                    {connectorSecretNameOptions.map((name) => (
                      <option key={name} value={name}>
                        {name}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="graph-filter">
                  <span>Source ref</span>
                  <input
                    value={connectorSecretRef}
                    onChange={(event) => setConnectorSecretRef(event.target.value)}
                    placeholder="env:FORGE_SHODAN_API_KEY"
                  />
                </label>
                <label className="graph-filter">
                  <span>Owner</span>
                  <input
                    value={connectorSecretOwner}
                    onChange={(event) => setConnectorSecretOwner(event.target.value)}
                    placeholder="secops"
                  />
                </label>
                <label className="graph-filter connector-secret-value-field">
                  <span>Value</span>
                  <input
                    autoComplete="new-password"
                    value={connectorSecretValue}
                    onChange={(event) => setConnectorSecretValue(event.target.value)}
                    placeholder="Paste secret value"
                    type="password"
                  />
                </label>
                <button
                  className="token-action"
                  disabled={
                    !liveToken ||
                    connectorSecretBusy ||
                    !selectedConnectorSecretConnector ||
                    !connectorSecretNameOptions.length
                  }
                  onClick={() => void handleConnectorSecretStore()}
                  type="button"
                >
                  {connectorSecretBusy ? 'Storing...' : 'Store'}
                </button>
              </div>
              {connectorSecretMessage ? <span className="muted-copy">{connectorSecretMessage}</span> : null}
              {connectorSecretError ? <span className="auth-error">{connectorSecretError}</span> : null}
            </div>
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

      <section className="panel" id="operational-timeline">
        <div className="panel-head">
          <p className="section-kicker">Operational timeline</p>
          <strong>{formatCount(operationalEvents.length)} signals</strong>
        </div>
        <div className="panel-body timeline-stack operational-timeline">
          {operationalEvents.length ? (
            operationalEvents.map((event) => (
              <article className="timeline-item operational-timeline-item" key={event.id}>
                <span className="timeline-time">{event.time || '-'}</span>
                <div>
                  <strong>{event.title || event.category}</strong>
                  <div className="token-wrap">
                    <span className="token">{event.category}</span>
                    {event.status ? (
                      <span className={`status-pill ${statusTone(event.status)}`}>{event.status}</span>
                    ) : null}
                    {event.severity ? (
                      <span className={`severity-pill ${severityTone(event.severity)}`}>{event.severity}</span>
                    ) : null}
                    {event.method ? <span className="token">method {event.method}</span> : null}
                    {event.reportability ? (
                      <span className="token">reportability {event.reportability}</span>
                    ) : null}
                    {event.provenance ? <span className="token">source {event.provenance}</span> : null}
                  </div>
                  <p>{event.summary || '-'}</p>
                </div>
              </article>
            ))
          ) : (
            <div className="notice">No operational timeline signals captured yet.</div>
          )}
        </div>
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

      <section className="panel" id="workspace-audit">
        <div className="panel-head">
          <p className="section-kicker">Workspace audit</p>
          <strong>{workspaceAuditWorkspaceId} · {formatCount(workspaceAuditRows.length)} events</strong>
        </div>
        <div className="panel-body findings-stack">
          {workspaceAuditLoadError ? (
            <div className="notice">Workspace audit unavailable: {workspaceAuditLoadError}</div>
          ) : null}
          <DataList
            rows={workspaceAuditRows}
            emptyText={liveToken ? 'No workspace audit events captured yet.' : 'Unlock live mode to review workspace audit events.'}
          />
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
