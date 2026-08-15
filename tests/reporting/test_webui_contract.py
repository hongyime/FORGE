from pathlib import Path


WEBUI_APP = Path("forge/reporting/webui/src/App.tsx")


def _app_source() -> str:
    return WEBUI_APP.read_text(encoding="utf-8")


def test_webui_graph_explorer_surfaces_edge_metadata() -> None:
    source = _app_source()

    assert "metadata?: Record<string, unknown>" in source
    assert "metadata: edge.metadata ?? {}" in source
    assert "Edge evidence" in source
    assert "metadataEntries(edge.metadata)" in source


def test_webui_surfaces_asset_graph_ownership_conflict_resolution() -> None:
    source = _app_source()

    assert "type AssetGraphOwnershipConflict =" in source
    assert "type AssetGraphConflictOwner =" in source
    assert "ownership_conflicts?: AssetGraphOwnershipConflict[]" in source
    assert "requestAssetGraphConflictResolution" in source
    assert "/asset-graph/ownership-conflicts/resolve" in source
    assert "onResolveAssetGraphConflict" in source
    assert "Asset ownership conflicts" in source
    assert "Resolve to {owner.owner_display || owner.owner_ref}" in source
    assert "Resolved ${conflict.entity_label || conflict.entity_key}" in source
    assert "competing claims superseded" in source


def test_webui_fallback_samples_include_csv_report_exports() -> None:
    source = _app_source()

    assert "engagement_1001_report_20260709T014412.csv" in source
    assert "engagement_1013_report_20260709T014328.csv" in source
    assert source.count("format: 'csv', label: 'CSV'") >= 2


def test_webui_fallback_samples_include_audit_artifact_contract() -> None:
    source = _app_source()

    assert "audit_count: item.audit_count" in source
    assert "const auditArtifacts = detail.artifacts.filter((artifact) => artifact.kind === 'audit')" in source
    assert "audit_1001_manifest_20260709T014413.json" in source
    assert "kind: 'audit'" in source
    assert "label: 'Audit'" in source


def test_webui_prior_report_history_surfaces_degraded_lineage() -> None:
    source = _app_source()

    assert "historyEntry.report_write_error" in source
    assert "Write degradation: {historyEntry.report_write_error}" in source
    assert "historyEntry.findings_checksum" in source
    assert "<span className=\"mono-tag\">{historyEntry.findings_checksum}</span>" in source
    assert "report_family_count?: number" in source
    assert "Report generations" in source
    assert "item.report_family_count" in source
    assert "reportStateFilter?: string" in source
    assert "matchesReportState(item, reportStateFilter)" in source
    assert "<span>Report state</span>" in source
    assert "Raw export fallback" in source


def test_webui_separates_reportable_findings_from_validation_inventory() -> None:
    source = _app_source()

    assert "Reportable validated findings" in source
    assert "<strong>{formatCount(findingRows.length)}</strong>" in source
    assert "findingRows.length + keyFindingRows.length + cloudValidationRows.length" not in source
    assert "Validation inventory" in source
    assert "id=\"validation-inventory\"" in source
    assert (
        "<strong>{formatCount(keyFindingRows.length + secretLifecycleRows.length + cloudValidationRows.length)}</strong>"
        in source
    )
    assert "No key validation inventory rows captured yet." in source
    assert "No secret lifecycle rows captured yet." in source
    assert "No cloud validation inventory rows captured yet." in source


def test_webui_surfaces_remediation_workflow_contract() -> None:
    source = _app_source()

    assert "type RemediationItem =" in source
    assert "type RemediationReviewQueue =" in source
    assert "type RemediationOverview =" in source
    assert "type RemediationTicketSyncPayload =" in source
    assert "DEFAULT_REMEDIATION_TICKET_SYNC" in source
    assert "function remediationReviewQueueRow(" in source
    assert "function remediationTicketSyncBody(" in source
    assert "/api/engagements/${slug}/remediation" in source
    assert "review_queue?: RemediationReviewQueue" in source
    assert "remediation_review_queue" in source
    assert "/remediation/propagate-owners" in source
    assert "/remediation/draft-from-asset-graph" in source
    assert "/remediation/${itemId}/review-owner" in source
    assert "/remediation/${payload.itemId}" in source
    assert "/remediation/${itemId}/sync-ticket" in source
    assert "/remediation/export?format=json" in source
    assert "/remediation/export?format=csv" in source
    assert "type RemediationPropagationResult =" in source
    assert "type RemediationGraphDraftResult =" in source
    assert "type RemediationOwnerReviewResult =" in source
    assert "owner_approval?:" in source
    assert "Apply graph owners" in source
    assert "Conflict policy" in source
    assert "Min confidence" in source
    assert "skip_conflicts" in source
    assert "skipped_conflict_count?: number" in source
    assert "skipped_low_confidence_count?: number" in source
    assert "conflict_policy: conflictPolicy" in source
    assert "min_confidence: minConfidence" in source
    assert "below confidence floor" in source
    assert "Draft graph fixes" in source
    assert "Graph remediation draft complete" in source
    assert "Overwrite explicit owners" in source
    assert "Risk acceptance" in source
    assert "risk_acceptance_expires_at" in source
    assert "risk_acceptance_review_status" in source
    assert "risk_acceptance_review_due" in source
    assert "risk review due" in source
    assert "Review queue" in source
    assert "Selected item" in source
    assert "Queue health" in source
    assert "Action readiness" in source
    assert "Live API unlocked" in source
    assert "owner review" in source
    assert "Approve owner" in source
    assert "Reject owner" in source
    assert "Needs review" in source
    assert "Owner review complete" in source
    assert "SLA overdue" in source
    assert "retest blocked" in source
    assert "missing tickets" in source
    assert "Risk expiry" in source
    assert "Risk review" in source
    assert "Ticket destinations" in source
    assert "Force sync" in source
    assert "tines_webhook_url" in source
    assert "splunk_hec_url" in source
    assert "torq_webhook_url" in source
    assert "FORGE_TINES_WEBHOOK_TOKEN" in source
    assert "FORGE_SPLUNK_HEC_TOKEN" in source
    assert "FORGE_TORQ_WEBHOOK_TOKEN" in source
    assert "connectors.push('tines')" in source
    assert "connectors.push('splunk_hec')" in source
    assert "connectors.push('torq')" in source
    assert "Retest" in source
    assert "Sync ticket" in source
    assert "Export JSON" in source
    assert "Export CSV" in source
    for literal in (
        "risk_accepted",
        "retest_pending",
        "false_positive",
        "not_requested",
        "passed",
        "blocked",
    ):
        assert literal in source


def test_webui_surfaces_connector_plugin_catalog_contract() -> None:
    source = _app_source()

    assert "source?: string" in source
    assert "execution_status?: string" in source
    assert "runner_supported?: boolean" in source
    assert "plugin_manifest_count?: number" in source
    assert "active_validation_plugin_manifest_count?: number" in source
    assert "plugin_manifest_catalog_count?: number" in source
    assert "connectorCatalogPluginManifestCount" in source
    assert "connectorCatalogActiveValidationPluginManifestCount" in source
    assert "Source: connector.source || 'built_in'" in source
    assert "Execution: connector.execution_status || '-'" in source
    assert "Runner: connector.runner_supported ? 'yes' : 'no'" in source
    assert "plugin manifests {formatCount(connectorCatalogPluginManifestCount)}" in source
    assert (
        "active-validation plugins {formatCount(connectorCatalogActiveValidationPluginManifestCount)}"
        in source
    )
    assert "plugin catalog {formatCount(connectorCatalogPluginManifestCatalogCount)}" in source
    assert "runner paths {formatCount(connectorCatalogRunnerSupportedCount)}" in source


def test_webui_surfaces_retention_policy_contract() -> None:
    source = _app_source()

    assert "type RetentionPolicy =" in source
    assert "type RetentionOverview =" in source
    assert "type RetentionRunResult =" in source
    assert "/api/engagements/${slug}/retention" in source
    assert "/retention/preview" in source
    assert "/retention/apply" in source
    assert "policy_name: 'default'" in source
    assert "confirm: true" in source
    assert "Confirm apply" in source
    assert "Preview" in source
    assert "Run items" in source
    assert "legal hold" in source
    for literal in (
        "retention_policies",
        "retention_runs",
        "retention_run_items",
        "Retention Policies",
        "Retention Runs",
        "Retention Run Items",
    ):
        assert literal in source


def test_webui_surfaces_workspace_control_audit_contract() -> None:
    source = _app_source()

    assert "workspace_id?: string" in source
    assert "type WorkspaceAuditEvent =" in source
    assert "type WorkspaceAuditOverview =" in source
    assert "event_hash: string" in source
    assert "previous_hash: string" in source
    assert "`/api/workspaces/${encodeURIComponent(workspaceId || 'default')}/audit`" in source
    assert "function loadWorkspaceAuditForPanel(" in source
    assert "function workspaceAuditEventRow(" in source
    assert "redactDashboardText(payload)" in source
    assert "workspaceAuditOverview={workspaceAuditOverview}" in source
    assert "id=\"workspace-audit\"" in source
    assert "Workspace audit" in source
    assert "Workspace audit unavailable" in source
    assert "Unlock live mode to review workspace audit events." in source


def test_webui_surfaces_workspace_admin_contract() -> None:
    source = _app_source()

    assert "type WorkspaceRecord =" in source
    assert "type WorkspaceMember =" in source
    assert "type WorkspaceMembersOverview =" in source
    assert "type WorkspaceUpsertPayload =" in source
    assert "type WorkspaceMemberUpsertPayload =" in source
    assert "async function loadWorkspaces(" in source
    assert "async function loadWorkspaceMembers(" in source
    assert "async function requestWorkspaceUpsert(" in source
    assert "async function requestWorkspaceMemberUpsert(" in source
    assert "async function requestWorkspaceMemberDelete(" in source
    assert "'/api/workspaces'" in source
    assert "/members/${encodeURIComponent(" in source
    assert "workspace_id: payload.workspaceId" in source
    assert "function workspaceRecordRow(" in source
    assert "function workspaceMemberRow(" in source
    assert "function parseWorkspaceMetadata(" in source
    assert "id=\"workspace-admin\"" in source
    assert "Workspace Administration" in source
    assert "Save workspace" in source
    assert "Save member" in source
    assert "Remove" in source
    assert "...(selectedWorkspaceId ? { workspace_id: selectedWorkspaceId } : {})" in source


def test_webui_surfaces_active_validation_workflow_contract() -> None:
    source = _app_source()

    assert "type ActiveValidationJob =" in source
    assert "type ActiveValidationRun =" in source
    assert "type ActiveValidationMethod =" in source
    assert "type ActiveValidationCoverage =" in source
    assert "type ActiveValidationGraphScenario =" in source
    assert "type ActiveValidationSnapshot =" in source
    assert "coverage?: ActiveValidationCoverage" in source
    assert "graph_scenarios?: ActiveValidationGraphScenario[]" in source
    assert "graph_scenario_count?: number" in source
    assert "coverage_states?: ActiveValidationCoverageStates" in source
    assert "metadata?: Record<string, unknown>" in source
    assert "/api/engagements/${slug}/active-validation" in source
    assert "/active-validation/jobs" in source
    assert "/active-validation/jobs/${payload.jobId}/approve" in source
    assert "/active-validation/jobs/${jobId}/run" in source
    assert "allow_live" in source
    assert "Active validation" in source
    assert "Active Validation Coverage" in source
    assert "active_validation_coverage" in source
    assert "activeValidationCoverageRowsForDisplay" in source
    assert "Create job" in source
    assert "Graph recommendations" in source
    assert "activeValidationGraphScenarios" in source
    assert "handleUseActiveValidationGraphScenario" in source
    assert "selectedActiveValidationGraphScenario" in source
    assert "clearActiveValidationGraphScenario" in source
    assert "Use draft" in source
    assert "graph lineage attached" in source
    assert "Clear graph draft" in source
    assert "...(payload.metadata ? { metadata: payload.metadata } : {})" in source
    assert "metadata: selectedActiveValidationGraphScenario?.metadata" in source
    assert "No graph-recommended validation drafts captured yet." in source
    assert "Approval context" in source
    assert "No active-validation coverage captured yet." in source
    assert "Allow live run" in source
    assert "Run live gate" in source
    for literal in (
        "fixture_replay",
        "control_simulation",
        "http_reachability",
        "http_security_headers",
        "fix_verification",
        "dry_run",
        "lab",
        "read_only_live",
        "implemented_read_only_live",
        "python_http_client",
        "security_header_observation",
        "read_only_live http + headers + fix: gated",
        "function activeValidationProofSummary(",
        "activeValidationHttpProofLabel",
        "activeValidationSecurityHeadersProofLabel",
        "proof_summary",
        "'Live Proof'",
        "'Fix Match'",
        "network_error",
        "'cloud'",
        "'identity'",
        "'finding'",
        "'remediation'",
        "'other'",
    ):
        assert literal in source


def test_webui_surfaces_operational_timeline_contract() -> None:
    source = _app_source()

    assert "type OperationalTimelineEvent =" in source
    assert "function operationalTimelineEvents(" in source
    assert "const operationalEvents = operationalTimelineEvents(" in source
    assert "id=\"operational-timeline\"" in source
    assert "Operational timeline" in source
    assert "operationalEvents.map((event)" in source
    assert "event.provenance" in source
    assert "event.method" in source
    assert "event.reportability" in source
    assert "No operational timeline signals captured yet." in source
    assert "const monitoringChangeRows = detail.sections.monitoring_changes ?? []" in source
    assert "category: 'Monitoring change'" in source
    assert "category: 'Reportable finding'" in source
    assert "detail.sections.vulnerability_findings" in source
    assert "detail.sections.passive_vulns" in source
    assert "monitoring_trend_points" in source
    assert "monitoring_changes" in source
    assert "monitoring_alerts" in source
    assert "cloud_validation_results" in source
    assert "key_scanner_findings" in source
    assert "secret_lifecycle_items" in source
    assert "category: 'Secret lifecycle'" in source
    assert "active_validation_runs" in source
    assert "remediation_items" in source
    assert "reportable_validation_count" in source
    assert "reportability {event.reportability}" in source
    assert "source {event.provenance}" in source
    assert "method {event.method}" in source
    assert "validationReportabilityLabel(row['Validation Status'])" in source
    assert "cloudReportabilityLabel(row.Reportable)" in source
    assert "non-reportable inventory held" in source
    assert "reportable finding" in source
    assert "'monitoring_trend_points'," in source
    assert "'monitoring_alerts'," in source
    assert "redactDashboardText" in source
    assert "Error: run.error ? redactDashboardText(run.error) : '-'" in source
    assert "return redactDashboardText(JSON.stringify(" in source
