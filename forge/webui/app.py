from __future__ import annotations

import asyncio
import os
import sqlite3
import subprocess
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from forge.audit.manifest import summarize_run_audit_manifest
from forge.audit.review import audit_review_summary
from forge.config import ForgeConfig
from forge.db.control import (
    connect_control_db,
)
from forge.db.session import get_engagement_db
from forge.distributed.coordinator import QueueCoordinator
from forge.engagement_ids import allocate_engagement_id, numeric_engagement_db_files
from forge.opsec.scope_gate import scope_entries_from_payload
from forge.reporting.dashboard import (
    _engagement_tags,
    _format_dt,
    _format_size,
    _graph_files,
    _safe_json_loads,
    _slugify,
    _table_columns,
    _table_exists,
)
from forge.reporting.audit_manifest_artifacts import materialize_audit_manifest_artifacts
from forge.reporting.report_history import (
    report_history_payload,
    report_review_counts,
)
from forge.security_headers import install_security_headers
from forge.webui.auth import Principal, mint_token, validate_jwt_secret
from forge.webui.auth_dependencies import (
    build_auth_principal_dependency,
    build_bootstrap_secret_provider,
    build_principal_permission_guard,
    websocket_principal,
)
from forge.webui.db import open_workflow_db
from forge.webui.artifacts import (
    ArtifactRouteNotFound,
    artifact_payloads as build_artifact_payloads,
    audit_artifact_payloads as build_audit_artifact_payloads,
    build_audit_files_provider,
    build_report_files_provider,
    build_reports_dir_provider,
    engagement_artifact_files as webui_engagement_artifact_files,
    engagement_artifact_route_file,
    report_preview_payload as build_report_preview_payload,
)
from forge.webui.engagement_payloads import (
    engagement_detail_payload as build_engagement_detail_payload,
    engagement_summary_payload as build_engagement_summary_payload,
)
from forge.webui.audit_review_routes import (
    AuditReviewRouteError,
    AuditReviewRouteNotFound,
    audit_review_list_payload,
    record_audit_review_payload,
)
from forge.webui.asset_graph_routes import (
    AssetGraphRouteError,
    AssetGraphRouteNotFound,
    asset_graph_payload,
    import_asset_attribution_payload,
    rebuild_asset_graph_payload,
    resolve_ownership_conflict_payload,
    upsert_ownership_claim_payload,
)
from forge.webui.logs import build_logs_dir_provider
from forge.webui.kill_chain_launch import (
    KillChainLaunchConflict,
    KillChainLaunchNoSeeds,
    KillChainLaunchOptionError,
    launch_kill_chain_run_payload,
)
from forge.webui.monitoring_routes import (
    MonitoringRouteError,
    add_monitoring_alert_suppression_route_payload,
    create_monitoring_snapshot_route_payload,
    escalate_monitoring_alert_to_remediation_route_payload,
    monitoring_overview_route_payload,
    run_due_monitoring_policies_route_payload,
    update_monitoring_alert_route_payload,
    upsert_monitoring_alert_route_dispatch_payload,
    upsert_monitoring_policy_route_payload,
)
from forge.webui.middleware import (
    install_webui_internal_error_handler,
    install_webui_rate_limit_middleware,
)
from forge.webui.remediation_routes import (
    RemediationRouteError,
    RemediationRouteNotFound,
    create_remediation_route_payload,
    draft_asset_graph_remediation_route_payload,
    list_remediation_route_payload,
    propagate_remediation_owners_route_payload,
    remediation_draft_from_graph_permissions,
    remediation_export_route_payload,
    remediation_propagate_permissions,
    remediation_retest_permissions,
    remediation_review_queue_route_payload,
    review_remediation_owner_route_payload,
    request_remediation_retest_route_payload,
    sync_remediation_ticket_route_payload,
    update_remediation_route_payload,
)
from forge.webui.retention_routes import (
    RetentionRouteError,
    retention_apply_payload,
    retention_overview_payload,
    retention_preview_payload,
    upsert_retention_policy_payload,
)
from forge.webui.engagement_lifecycle import (
    create_engagement_route_payload,
    engagement_row as webui_engagement_row,
    engagement_rows as webui_engagement_rows,
    normalize_create_engagement_request,
    update_engagement_route_payload,
)
from forge.webui.engagement_discovery import (
    EngagementDiscoveryContext,
    find_engagement_artifact as find_engagement_artifact_file,
    find_engagement_detail as find_engagement_detail_payload,
    iter_engagement_payloads as iter_discovered_engagement_payloads,
    iter_missing_engagement_index_payloads as iter_missing_index_payloads,
    resolve_engagement_db as resolve_engagement_db_path,
)
from forge.webui.automation_routes import (
    AutomationRouteError,
    automation_playbook_route_payload,
    automation_suggestions_route_payload,
    execute_automation_route_payload,
    parse_automation_action_request,
    parse_automation_playbook_request,
)
from forge.webui.active_validation_routes import (
    ActiveValidationRouteError,
    active_validation_list_route_payload,
    active_validation_run_permissions,
    active_validation_write_permissions,
    approve_active_validation_route_payload,
    create_active_validation_route_payload,
    preview_active_validation_route_payload,
    run_active_validation_route_payload,
)
from forge.webui.command_center_routes import (
    CommandCenterRouteError,
    approve_action_route_payload,
    command_body_engagement_id,
    command_center_service as build_command_center_service,
    emergency_stop_route_payload,
    execute_action_route_payload,
    host_actions_route_payload,
    host_context_route_payload,
    publish_command_progress_event,
    timeline_route_payload,
    toggle_sentry_route_payload,
)
from forge.webui.connector_routes import (
    ConnectorRouteError,
    ConnectorRouteNotFound,
    connector_catalog_payload,
    connector_secrets_payload,
    store_connector_secret_payload,
)
from forge.webui.engagement_data import (
    asset_tree_route_payload,
    engagement_assets_route_payload,
    vulnerability_summary_route_payload,
)
from forge.webui.engagement_index_routes import (
    EngagementIndexRouteNotFound,
    engagement_collection_payload,
    engagement_collection_route_payload,
    engagement_detail_route_payload,
    engagement_tombstones_route_payload,
)
from forge.webui.htmx_routes import (
    HtmxRouteNotFound,
    htmx_shell_response,
    htmx_tab_response,
    htmx_templates_dir,
)
from forge.webui.rbac import ROLE_PERMISSIONS
from forge.webui.route_authorization import AuthorizedEngagementResolver
from forge.webui.run_control import (
    build_run_control_marker_clearer,
    open_launch_log as open_launch_log_file,
)
from forge.webui.run_log_routes import (
    RunLogRouteError,
    RunLogRouteNotFound,
    engagement_log_route_file,
    engagement_log_tail_route_payload,
    engagement_logs_route_payload,
    engagement_runs_route_payload,
    run_control_route_payload,
)
from forge.webui.run_status import (
    annotate_run_audit_review as annotate_run_audit_review_payload,
    iter_live_run_progress_snapshots,
)
from forge.webui.shell_routes import (
    ShellRouteNotFound,
    frontend_asset_response,
    frontend_entry_response,
    generated_dashboard_data_response,
)
from forge.webui.seed_routes import (
    create_seed_route_payload,
    delete_seed_route_payload,
    engagement_seed_list_payload,
    update_seed_route_payload,
)
from forge.webui.task_routes import (
    TaskRouteError,
    parse_task_enqueue_request,
    queue_metrics_route_payload,
    scan_progress_route_payload,
    scan_start_route_payload,
    task_enqueue_route_payload,
    task_list_route_payload,
    worker_list_route_payload,
)
from forge.webui.workspace_routes import (
    WorkspaceAccessError,
    WorkspaceRouteError,
    delete_workspace_member_route_payload,
    list_workspace_audit_route_payload,
    list_workspace_members_route_payload,
    list_workspaces_route_payload,
    upsert_workspace_member_route_payload,
    upsert_workspace_route_payload,
)
from forge.webui.workspace_access import (
    ensure_workspace_rbac_foundation,
    principal_can_access_engagement_row,
    principal_can_access_workspace,
)
from forge.webui.state import (
    build_progress_publisher,
    engagement_run_progress_event,
    broker,
    progress_event_websocket_text,
    progress_websocket_subprotocol,
    queued_progress_event,
)
from forge.db.direct_connect import direct_connect  # noqa: E402  # PRAGMA-configured wrapper for bare sqlite3.connect


def create_app() -> Any:
    try:
        from fastapi import Depends, FastAPI, Header, HTTPException, Request, WebSocket
        from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
        from fastapi.security import HTTPBearer
        from fastapi.staticfiles import StaticFiles
        from fastapi.templating import Jinja2Templates
    except ImportError as exc:
        raise RuntimeError("FastAPI is required for web interface support.") from exc
    globals()["WebSocket"] = WebSocket

    _is_dev = os.environ.get("FORGE_ENV", "").lower() in ("dev", "development")
    cfg = ForgeConfig.load()
    coordinator = QueueCoordinator(redis_url=cfg.redis_url)
    event_bridge_task: asyncio.Task[None] | None = None
    run_progress_bridge_task: asyncio.Task[None] | None = None
    event_bridge_stop = asyncio.Event()
    run_progress_poll_interval = max(
        0.1,
        float(os.environ.get("FORGE_WEB_PROGRESS_POLL_INTERVAL", "0.75") or 0.75),
    )
    frontend_dist_dir = Path(__file__).resolve().parents[1] / "reporting" / "webui" / "dist"
    frontend_index_path = frontend_dist_dir / "index.html"
    frontend_assets_dir = frontend_dist_dir / "assets"
    legacy_template_path = Path(__file__).parent / "templates" / "dashboard.html"
    generated_dashboard_dir = Path.cwd() / "reports" / "dashboard"
    generated_dashboard_data_dir = generated_dashboard_dir / "data"

    @asynccontextmanager
    async def _lifespan(_app: Any):
        nonlocal event_bridge_task, run_progress_bridge_task
        event_bridge_stop.clear()
        event_bridge_task = asyncio.create_task(_queue_event_bridge())
        run_progress_bridge_task = asyncio.create_task(_run_progress_bridge())
        try:
            yield
        finally:
            event_bridge_stop.set()
            if event_bridge_task is not None:
                await event_bridge_task
            if run_progress_bridge_task is not None:
                await run_progress_bridge_task
            event_bridge_task = None
            run_progress_bridge_task = None

    app = FastAPI(title="FORGE Web Interface", version="0.1.0", debug=_is_dev, lifespan=_lifespan)
    install_security_headers(app, surface="webui")
    if frontend_assets_dir.is_dir():
        app.mount("/assets", StaticFiles(directory=frontend_assets_dir), name="frontend-assets")
    auth_scheme = HTTPBearer(auto_error=False)
    if cfg.web_auth.lower() == "jwt":
        validate_jwt_secret()

    install_webui_rate_limit_middleware(
        app,
        request_type=Request,
        json_response=JSONResponse,
    )
    install_webui_internal_error_handler(
        app,
        request_type=Request,
        json_response=JSONResponse,
        enabled=not _is_dev,
    )
    _auth_principal = build_auth_principal_dependency(
        auth_scheme=auth_scheme,
        depends=Depends,
        http_exception=HTTPException,
    )
    _bootstrap_secret = build_bootstrap_secret_provider(http_exception=HTTPException)
    _require_principal_permission = build_principal_permission_guard(http_exception=HTTPException)

    _publish_progress_sync = build_progress_publisher(broker.publish_sync)

    async def _queue_event_bridge() -> None:
        while not event_bridge_stop.is_set():
            msg = await asyncio.to_thread(
                coordinator.consume_topic,
                "forge.events",
                0.75,
            )
            if msg is None:
                continue
            event = queued_progress_event(msg.payload)
            if event is None:
                continue
            await broker.publish(event)

    def _iter_live_run_progress_snapshots() -> list[tuple[int, str, dict[str, Any]]]:
        return iter_live_run_progress_snapshots(
            cfg.data_dir,
            numeric_db_files=numeric_engagement_db_files,
            table_exists=_table_exists,
            connect=direct_connect,
        )

    async def _run_progress_bridge() -> None:
        last_seen: dict[int, str] = {}
        while not event_bridge_stop.is_set():
            active_engagements: set[int] = set()
            for engagement_id, fingerprint, payload in _iter_live_run_progress_snapshots():
                active_engagements.add(engagement_id)
                if last_seen.get(engagement_id) == fingerprint:
                    continue
                last_seen[engagement_id] = fingerprint
                await broker.publish(engagement_run_progress_event(engagement_id, payload))
            stale_engagements = set(last_seen) - active_engagements
            for engagement_id in stale_engagements:
                del last_seen[engagement_id]
            try:
                await asyncio.wait_for(
                    event_bridge_stop.wait(),
                    timeout=run_progress_poll_interval,
                )
            except asyncio.TimeoutError:
                continue

    _reports_dir = build_reports_dir_provider()

    def _frontend_entry_response() -> Any:
        return frontend_entry_response(
            frontend_index_path=frontend_index_path,
            legacy_template_path=legacy_template_path,
            file_response=FileResponse,
        )

    def _principal_can_access_workspace(
        principal: Principal | None,
        workspace_id: str,
        *,
        con: sqlite3.Connection | None = None,
        allow_bootstrap: bool = False,
    ) -> bool:
        return principal_can_access_workspace(
            principal,
            workspace_id,
            con=con,
            allow_bootstrap=allow_bootstrap,
        )

    def _principal_can_access_engagement_row(
        con: sqlite3.Connection,
        principal: Principal | None,
        row: sqlite3.Row,
    ) -> bool:
        return principal_can_access_engagement_row(con, principal, row)

    def _workspace_access_checker(
        principal: Principal,
        workspace_id: str,
        con: sqlite3.Connection,
    ) -> bool:
        return _principal_can_access_workspace(principal, workspace_id, con=con)

    def _annotate_run_audit_review(
        con: sqlite3.Connection,
        run_summary: dict[str, Any] | None,
        engagement_id: int,
    ) -> dict[str, Any] | None:
        return annotate_run_audit_review_payload(
            con,
            run_summary,
            engagement_id=engagement_id,
        )

    _clear_run_control_markers = build_run_control_marker_clearer(cfg.data_dir)

    _logs_dir = build_logs_dir_provider(cfg.data_dir)

    _report_files = build_report_files_provider(_reports_dir)
    _audit_files = build_audit_files_provider(_reports_dir)

    def _engagement_summary_payload(
        db_file: Path,
        con: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> dict[str, Any]:
        return build_engagement_summary_payload(
            db_file,
            con,
            row,
            reports_root=_reports_dir(),
            format_dt=_format_dt,
            format_size=_format_size,
        )

    def _engagement_detail_payload(
        db_file: Path,
        con: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> dict[str, Any]:
        return build_engagement_detail_payload(
            db_file,
            con,
            row,
            reports_root=_reports_dir(),
            format_dt=_format_dt,
            format_size=_format_size,
        )

    def _open_workflow_db(db_path: Path) -> sqlite3.Connection:
        return open_workflow_db(db_path)

    def _engagement_artifact_files(
        con: sqlite3.Connection,
        db_file: Path,
        engagement_id: int,
        _summary: dict[str, Any],
    ) -> list[Path]:
        return webui_engagement_artifact_files(
            con,
            db_path=db_file,
            reports_root=_reports_dir(),
            engagement_id=engagement_id,
        )

    def _discovery_context() -> EngagementDiscoveryContext:
        return EngagementDiscoveryContext(
            data_dir=cfg.data_dir,
            ensure_workspace_rbac_foundation=ensure_workspace_rbac_foundation,
            engagement_rows=webui_engagement_rows,
            engagement_row=webui_engagement_row,
            summary_payload=_engagement_summary_payload,
            detail_payload=_engagement_detail_payload,
            can_access_workspace=(
                lambda principal, workspace_id, con: _principal_can_access_workspace(
                    principal,
                    workspace_id,
                    con=con,
                )
            ),
            can_access_engagement_row=_principal_can_access_engagement_row,
            artifact_files=_engagement_artifact_files,
            tombstone_retention_days=os.environ.get(
                "FORGE_CONTROL_TOMBSTONE_RETENTION_DAYS",
                "30",
            ),
        )

    def _iter_engagement_payloads(principal: Principal | None = None) -> list[dict[str, Any]]:
        return iter_discovered_engagement_payloads(_discovery_context(), principal)

    def _iter_missing_engagement_index_payloads(
        principal: Principal | None = None,
    ) -> list[dict[str, Any]]:
        return iter_missing_index_payloads(_discovery_context(), principal)

    def _find_engagement_detail(
        engagement_ref: str,
        principal: Principal | None = None,
    ) -> dict[str, Any] | None:
        return find_engagement_detail_payload(_discovery_context(), engagement_ref, principal)

    def _find_engagement_artifact(
        engagement_ref: str,
        artifact_name: str,
        principal: Principal | None = None,
    ) -> Path | None:
        return find_engagement_artifact_file(
            _discovery_context(),
            engagement_ref,
            artifact_name,
            principal,
        )

    def _resolve_engagement_db(
        engagement_ref: str,
        principal: Principal | None = None,
    ) -> tuple[Path, int] | None:
        return resolve_engagement_db_path(_discovery_context(), engagement_ref, principal)

    authorized_engagements = AuthorizedEngagementResolver(_discovery_context)

    @app.get("/api/token")
    def get_token(
        operator: str,
        bootstrap_token: str | None = None,
        role: str = "operator",
        workspace_id: str = "default",
    ) -> dict[str, str]:
        if not operator.strip():
            raise HTTPException(status_code=400, detail="operator is required.")
        if bootstrap_token is None or not bootstrap_token.strip():
            raise HTTPException(status_code=401, detail="Missing bootstrap credential.")
        if bootstrap_token != _bootstrap_secret():
            raise HTTPException(status_code=401, detail="Invalid bootstrap credential.")
        normalized_role = str(role or "operator").strip().lower() or "operator"
        if normalized_role not in ROLE_PERMISSIONS:
            raise HTTPException(status_code=400, detail=f"Unsupported token role: {normalized_role}")
        normalized_workspace = str(workspace_id or "default").strip() or "default"
        return {
            "token": mint_token(
                operator.strip(),
                workspace_id=normalized_workspace,
                roles=(normalized_role,),
            ),
            "role": normalized_role,
            "workspace_id": normalized_workspace,
        }

    @app.get("/api/automation/suggestions")
    def get_automation_suggestions(
        engagement_id: int,
        principal: Principal = Depends(_auth_principal),
    ) -> dict[str, Any]:
        authorized_engagements.db_path(engagement_id, principal)
        _require_principal_permission(principal, "automation:read")
        return automation_suggestions_route_payload(engagement_id)

    @app.post("/api/automation/execute")
    async def execute_suggestion(
        body: dict[str, Any],
        principal: Principal = Depends(_auth_principal),
    ) -> dict[str, str]:
        try:
            request = parse_automation_action_request(body)
        except AutomationRouteError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        db_path = authorized_engagements.db_path(int(request.engagement_id), principal)
        _require_principal_permission(principal, "automation:execute")
        try:
            return execute_automation_route_payload(
                request,
                db_path=db_path,
                queue=coordinator,
                event_publisher=_publish_progress_sync,
            )
        except AutomationRouteError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/automation/playbook")
    async def run_playbook(
        body: dict[str, Any],
        principal: Principal = Depends(_auth_principal),
    ) -> dict[str, str]:
        try:
            request = parse_automation_playbook_request(body)
        except AutomationRouteError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        db_path = authorized_engagements.db_path(int(request.engagement_id), principal)
        _require_principal_permission(principal, "automation:execute")
        try:
            return automation_playbook_route_payload(
                request,
                db_path=db_path,
                queue=coordinator,
                event_publisher=_publish_progress_sync,
            )
        except AutomationRouteError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/")
    def dashboard() -> Any:
        return _frontend_entry_response()

    # ---------------------------------------------------------------- HTMX tabs
    # Task 23: server-rendered engagement detail tabs. Runs in parallel to
    # the React SPA (which stays as /engagements/{ref}). New URL prefix is
    # /engagements/{ref}/htmx and /engagements/{ref}/tab/{name} so the SPA
    # catch-all below still serves everything else.

    _htmx_templates = Jinja2Templates(directory=htmx_templates_dir())

    @app.get("/engagements/{engagement_ref}/htmx", response_class=HTMLResponse)
    def engagement_htmx_shell(
        engagement_ref: str,
        principal: Principal = Depends(_auth_principal),
    ) -> Any:
        """Base HTMX shell with the default 'overview' tab pre-rendered."""
        _require_principal_permission(principal, "engagements:read")
        try:
            return htmx_shell_response(
                detail=_find_engagement_detail(engagement_ref, principal),
                templates=_htmx_templates,
                response_class=HTMLResponse,
            )
        except HtmxRouteNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.get(
        "/engagements/{engagement_ref}/tab/{tab_name}",
        response_class=HTMLResponse,
    )
    def engagement_htmx_tab(
        engagement_ref: str,
        tab_name: str,
        hx_request: str = Header(default=""),
        principal: Principal = Depends(_auth_principal),
    ) -> Any:
        _require_principal_permission(principal, "engagements:read")
        try:
            return htmx_tab_response(
                detail=_find_engagement_detail(engagement_ref, principal),
                tab_name=tab_name,
                hx_request=hx_request,
                templates=_htmx_templates,
                response_class=HTMLResponse,
            )
        except HtmxRouteNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.get("/engagements/{engagement_path:path}")
    def engagement_spa_route(engagement_path: str) -> Any:
        return _frontend_entry_response()

    @app.get("/command-center")
    def legacy_command_center() -> Any:
        return FileResponse(legacy_template_path)

    @app.get("/favicon.svg")
    def frontend_favicon() -> Any:
        try:
            return frontend_asset_response(
                frontend_dist_dir=frontend_dist_dir,
                asset_name="favicon.svg",
                missing_detail="favicon not found.",
                file_response=FileResponse,
            )
        except ShellRouteNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.get("/icons.svg")
    def frontend_icons() -> Any:
        try:
            return frontend_asset_response(
                frontend_dist_dir=frontend_dist_dir,
                asset_name="icons.svg",
                missing_detail="icons not found.",
                file_response=FileResponse,
            )
        except ShellRouteNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.get("/data/{resource_path:path}")
    def generated_dashboard_data(
        resource_path: str,
        principal: Principal = Depends(_auth_principal),
    ) -> Any:
        try:
            return generated_dashboard_data_response(
                resource_path=resource_path,
                principal=principal,
                generated_dashboard_data_dir=generated_dashboard_data_dir,
                generated_at=_format_dt(
                    time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime())
                ),
                iter_engagement_payloads=_iter_engagement_payloads,
                find_engagement_detail=_find_engagement_detail,
                require_permission=_require_principal_permission,
                json_response=JSONResponse,
                file_response=FileResponse,
            )
        except (EngagementIndexRouteNotFound, ShellRouteNotFound) as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.get("/api/engagements")
    def list_engagements(principal: Principal = Depends(_auth_principal)) -> dict[str, Any]:
        _require_principal_permission(principal, "engagements:read")
        return engagement_collection_route_payload(
            generated_at=_format_dt(time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime())),
            principal=principal,
            iter_engagement_payloads=_iter_engagement_payloads,
        )

    @app.get("/api/engagements/index/tombstones")
    def list_engagement_index_tombstones(
        principal: Principal = Depends(_auth_principal),
    ) -> dict[str, Any]:
        _require_principal_permission(principal, "engagements:read")
        return engagement_tombstones_route_payload(
            generated_at=_format_dt(time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime())),
            retention_days=os.environ.get("FORGE_CONTROL_TOMBSTONE_RETENTION_DAYS", "30"),
            principal=principal,
            iter_missing_engagement_index_payloads=_iter_missing_engagement_index_payloads,
        )

    @app.get("/api/workspaces")
    def list_control_workspaces(
        principal: Principal = Depends(_auth_principal),
    ) -> dict[str, Any]:
        _require_principal_permission(principal, "workspaces:read")
        control_con = connect_control_db(cfg.data_dir)
        try:
            return list_workspaces_route_payload(
                control_con,
                principal=principal,
                can_access_workspace=_workspace_access_checker,
                generated_at=_format_dt(time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime())),
            )
        except WorkspaceAccessError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        finally:
            control_con.close()

    @app.post("/api/workspaces")
    def upsert_control_workspace(
        body: dict[str, Any],
        principal: Principal = Depends(_auth_principal),
    ) -> dict[str, Any]:
        _require_principal_permission(principal, "workspaces:write")
        control_con = connect_control_db(cfg.data_dir)
        try:
            return upsert_workspace_route_payload(
                control_con,
                principal=principal,
                body=body,
            )
        except WorkspaceRouteError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except WorkspaceAccessError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        finally:
            control_con.close()

    @app.get("/api/workspaces/{workspace_id}/members")
    def list_control_workspace_members(
        workspace_id: str,
        principal: Principal = Depends(_auth_principal),
    ) -> dict[str, Any]:
        _require_principal_permission(principal, "workspaces:read")
        control_con = connect_control_db(cfg.data_dir)
        try:
            return list_workspace_members_route_payload(
                control_con,
                workspace_id=workspace_id,
                principal=principal,
                can_access_workspace=_workspace_access_checker,
            )
        except WorkspaceRouteError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except WorkspaceAccessError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        finally:
            control_con.close()

    @app.get("/api/workspaces/{workspace_id}/audit")
    def list_control_workspace_audit(
        workspace_id: str,
        limit: int = 100,
        principal: Principal = Depends(_auth_principal),
    ) -> dict[str, Any]:
        _require_principal_permission(principal, "workspaces:read")
        control_con = connect_control_db(cfg.data_dir)
        try:
            return list_workspace_audit_route_payload(
                control_con,
                workspace_id=workspace_id,
                limit=limit,
                principal=principal,
                can_access_workspace=_workspace_access_checker,
            )
        except WorkspaceRouteError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except WorkspaceAccessError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        finally:
            control_con.close()

    @app.put("/api/workspaces/{workspace_id}/members/{subject}")
    def upsert_control_workspace_member(
        workspace_id: str,
        subject: str,
        body: dict[str, Any],
        principal: Principal = Depends(_auth_principal),
    ) -> dict[str, Any]:
        _require_principal_permission(principal, "workspaces:members:write")
        control_con = connect_control_db(cfg.data_dir)
        try:
            return upsert_workspace_member_route_payload(
                control_con,
                subject=subject,
                workspace_id=workspace_id,
                body=body,
                principal=principal,
                can_access_workspace=_workspace_access_checker,
            )
        except WorkspaceRouteError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except WorkspaceAccessError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        finally:
            control_con.close()

    @app.delete("/api/workspaces/{workspace_id}/members/{subject}")
    def delete_control_workspace_member(
        workspace_id: str,
        subject: str,
        principal: Principal = Depends(_auth_principal),
    ) -> dict[str, Any]:
        _require_principal_permission(principal, "workspaces:members:write")
        control_con = connect_control_db(cfg.data_dir)
        try:
            return delete_workspace_member_route_payload(
                control_con,
                workspace_id=workspace_id,
                subject=subject,
                principal=principal,
                can_access_workspace=_workspace_access_checker,
            )
        except WorkspaceRouteError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except WorkspaceAccessError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        finally:
            control_con.close()

    @app.post("/api/engagements")
    def create_engagement(
        body: dict[str, Any],
        principal: Principal = Depends(_auth_principal),
    ) -> dict[str, Any]:
        try:
            request = normalize_create_engagement_request(
                body,
                principal_subject=principal.subject,
                principal_workspace_id=principal.workspace_id,
                default_operator=cfg.operator,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        _require_principal_permission(principal, "engagements:create")
        if not _principal_can_access_workspace(principal, request.workspace_id, allow_bootstrap=True):
            raise HTTPException(status_code=403, detail="Workspace access denied.")

        engagement_id = allocate_engagement_id(cfg.data_dir)
        db_path = cfg.engagement_db_path(str(engagement_id))
        con = direct_connect(db_path)
        con.row_factory = sqlite3.Row
        try:
            try:
                return create_engagement_route_payload(
                    con,
                    data_dir=cfg.data_dir,
                    db_path=db_path,
                    engagement_id=engagement_id,
                    request=request,
                    member_subject=principal.subject,
                    detail_payload_builder=_engagement_detail_payload,
                )
            except RuntimeError as exc:
                raise HTTPException(status_code=500, detail=str(exc)) from exc
        finally:
            con.close()

    @app.get("/api/engagements/{engagement_ref}")
    def get_engagement_detail(
        engagement_ref: str,
        principal: Principal = Depends(_auth_principal),
    ) -> dict[str, Any]:
        _require_principal_permission(principal, "engagements:read")
        try:
            return engagement_detail_route_payload(
                engagement_ref,
                principal=principal,
                find_engagement_detail=_find_engagement_detail,
            )
        except EngagementIndexRouteNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.get("/api/engagements/{engagement_ref}/audit-reviews")
    def get_engagement_audit_reviews(
        engagement_ref: str,
        run_id: int | None = None,
        manifest_hash: str | None = None,
        limit: int = 50,
        principal: Principal = Depends(_auth_principal),
    ) -> dict[str, Any]:
        _require_principal_permission(principal, "audit:read")
        resolved = _resolve_engagement_db(engagement_ref, principal)
        if resolved is None:
            raise HTTPException(status_code=404, detail="Engagement not found.")
        db_path, engagement_id = resolved
        con = _open_workflow_db(db_path)
        try:
            return audit_review_list_payload(
                con,
                engagement_id=engagement_id,
                run_id=run_id,
                manifest_hash=manifest_hash,
                limit=limit,
            )
        finally:
            con.close()

    @app.post("/api/engagements/{engagement_ref}/audit-reviews")
    def post_engagement_audit_review(
        engagement_ref: str,
        body: dict[str, Any] | None = None,
        principal: Principal = Depends(_auth_principal),
    ) -> dict[str, Any]:
        _require_principal_permission(principal, "audit:review")
        resolved = _resolve_engagement_db(engagement_ref, principal)
        if resolved is None:
            raise HTTPException(status_code=404, detail="Engagement not found.")
        db_path, engagement_id = resolved
        con = _open_workflow_db(db_path)
        try:
            return record_audit_review_payload(
                con,
                engagement_id=engagement_id,
                body=body,
                reviewer=principal.subject,
            )
        except AuditReviewRouteNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except AuditReviewRouteError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        finally:
            con.close()

    @app.get("/api/engagements/{engagement_ref}/connectors")
    def get_engagement_connectors(
        engagement_ref: str,
        domain: str = "",
        include_paid: bool = False,
        principal: Principal = Depends(_auth_principal),
    ) -> dict[str, Any]:
        _require_principal_permission(principal, "connectors:read")
        resolved = _resolve_engagement_db(engagement_ref, principal)
        if resolved is None:
            raise HTTPException(status_code=404, detail="Engagement not found.")
        db_path, engagement_id = resolved
        con = _open_workflow_db(db_path)
        try:
            return connector_catalog_payload(
                con,
                engagement_id=engagement_id,
                data_dir=cfg.data_dir,
                domain=domain,
                include_paid=include_paid,
            )
        except ConnectorRouteError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        finally:
            con.close()

    @app.get("/api/engagements/{engagement_ref}/connector-secrets")
    def get_engagement_connector_secrets(
        engagement_ref: str,
        connector: str = "",
        principal: Principal = Depends(_auth_principal),
    ) -> dict[str, Any]:
        _require_principal_permission(principal, "connectors:read")
        resolved = _resolve_engagement_db(engagement_ref, principal)
        if resolved is None:
            raise HTTPException(status_code=404, detail="Engagement not found.")
        db_path, engagement_id = resolved
        con = _open_workflow_db(db_path)
        try:
            return connector_secrets_payload(
                con,
                engagement_id=engagement_id,
                connector=connector,
            )
        except ConnectorRouteError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        finally:
            con.close()

    @app.post("/api/engagements/{engagement_ref}/connector-secrets")
    def post_engagement_connector_secret(
        engagement_ref: str,
        body: dict[str, Any] | None = None,
        principal: Principal = Depends(_auth_principal),
    ) -> dict[str, Any]:
        _require_principal_permission(principal, "connectors:write")
        resolved = _resolve_engagement_db(engagement_ref, principal)
        if resolved is None:
            raise HTTPException(status_code=404, detail="Engagement not found.")
        db_path, engagement_id = resolved
        con = _open_workflow_db(db_path)
        try:
            return store_connector_secret_payload(
                con,
                engagement_id=engagement_id,
                body=body,
                operator=principal.subject,
            )
        except ConnectorRouteNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ConnectorRouteError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        finally:
            con.close()

    @app.get("/api/engagements/{engagement_ref}/retention")
    def get_engagement_retention(
        engagement_ref: str,
        policy: str = "default",
        limit: int = 20,
        principal: Principal = Depends(_auth_principal),
    ) -> dict[str, Any]:
        _require_principal_permission(principal, "retention:read")
        resolved = _resolve_engagement_db(engagement_ref, principal)
        if resolved is None:
            raise HTTPException(status_code=404, detail="Engagement not found.")
        db_path, engagement_id = resolved
        con = _open_workflow_db(db_path)
        try:
            return retention_overview_payload(
                con,
                engagement_id=engagement_id,
                policy=policy,
                limit=limit,
            )
        except RetentionRouteError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        finally:
            con.close()

    @app.post("/api/engagements/{engagement_ref}/retention/policy")
    def post_engagement_retention_policy(
        engagement_ref: str,
        body: dict[str, Any] | None = None,
        principal: Principal = Depends(_auth_principal),
    ) -> dict[str, Any]:
        _require_principal_permission(principal, "retention:write")
        resolved = _resolve_engagement_db(engagement_ref, principal)
        if resolved is None:
            raise HTTPException(status_code=404, detail="Engagement not found.")
        db_path, engagement_id = resolved
        con = _open_workflow_db(db_path)
        try:
            return upsert_retention_policy_payload(
                con,
                engagement_id=engagement_id,
                body=body,
            )
        except RetentionRouteError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        finally:
            con.close()

    @app.post("/api/engagements/{engagement_ref}/retention/preview")
    def post_engagement_retention_preview(
        engagement_ref: str,
        body: dict[str, Any] | None = None,
        principal: Principal = Depends(_auth_principal),
    ) -> dict[str, Any]:
        _require_principal_permission(principal, "retention:write")
        resolved = _resolve_engagement_db(engagement_ref, principal)
        if resolved is None:
            raise HTTPException(status_code=404, detail="Engagement not found.")
        db_path, engagement_id = resolved
        con = _open_workflow_db(db_path)
        try:
            return retention_preview_payload(
                con,
                engagement_id=engagement_id,
                body=body,
                operator=principal.subject,
            )
        except RetentionRouteError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        finally:
            con.close()

    @app.post("/api/engagements/{engagement_ref}/retention/apply")
    def post_engagement_retention_apply(
        engagement_ref: str,
        body: dict[str, Any] | None = None,
        principal: Principal = Depends(_auth_principal),
    ) -> dict[str, Any]:
        _require_principal_permission(principal, "retention:write")
        resolved = _resolve_engagement_db(engagement_ref, principal)
        if resolved is None:
            raise HTTPException(status_code=404, detail="Engagement not found.")
        db_path, engagement_id = resolved
        con = _open_workflow_db(db_path)
        try:
            return retention_apply_payload(
                con,
                engagement_id=engagement_id,
                body=body,
                operator=principal.subject,
            )
        except RetentionRouteError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        finally:
            con.close()

    @app.get("/api/engagements/{engagement_ref}/asset-graph")
    def get_engagement_asset_graph(
        engagement_ref: str,
        entity_key: str | None = None,
        limit: int = 100,
        principal: Principal = Depends(_auth_principal),
    ) -> dict[str, Any]:
        resolved = _resolve_engagement_db(engagement_ref, principal)
        if resolved is None:
            raise HTTPException(status_code=404, detail="Engagement not found.")
        _require_principal_permission(principal, "assets:read")
        db_path, engagement_id = resolved
        con = _open_workflow_db(db_path)
        try:
            return asset_graph_payload(
                con,
                engagement_id=engagement_id,
                entity_key=entity_key,
                limit=limit,
            )
        finally:
            con.close()

    @app.post("/api/engagements/{engagement_ref}/asset-graph/rebuild")
    def rebuild_engagement_asset_graph(
        engagement_ref: str,
        principal: Principal = Depends(_auth_principal),
    ) -> dict[str, Any]:
        resolved = _resolve_engagement_db(engagement_ref, principal)
        if resolved is None:
            raise HTTPException(status_code=404, detail="Engagement not found.")
        _require_principal_permission(principal, "assets:write")
        db_path, engagement_id = resolved
        con = _open_workflow_db(db_path)
        try:
            return rebuild_asset_graph_payload(
                con,
                engagement_id=engagement_id,
                operator=principal.subject,
            )
        finally:
            con.close()

    @app.post("/api/engagements/{engagement_ref}/asset-graph/ownership-claims")
    def create_engagement_asset_ownership_claim(
        engagement_ref: str,
        body: dict[str, Any],
        principal: Principal = Depends(_auth_principal),
    ) -> dict[str, Any]:
        resolved = _resolve_engagement_db(engagement_ref, principal)
        if resolved is None:
            raise HTTPException(status_code=404, detail="Engagement not found.")
        _require_principal_permission(principal, "assets:write")
        db_path, engagement_id = resolved
        con = _open_workflow_db(db_path)
        try:
            return upsert_ownership_claim_payload(
                con,
                engagement_id=engagement_id,
                body=body,
                operator=principal.subject,
            )
        except AssetGraphRouteError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        finally:
            con.close()

    @app.post("/api/engagements/{engagement_ref}/asset-graph/attribution")
    def import_engagement_asset_attribution(
        engagement_ref: str,
        body: dict[str, Any],
        principal: Principal = Depends(_auth_principal),
    ) -> dict[str, Any]:
        resolved = _resolve_engagement_db(engagement_ref, principal)
        if resolved is None:
            raise HTTPException(status_code=404, detail="Engagement not found.")
        _require_principal_permission(principal, "assets:write")
        db_path, engagement_id = resolved
        con = _open_workflow_db(db_path)
        try:
            return import_asset_attribution_payload(
                con,
                engagement_id=engagement_id,
                body=body,
                operator=principal.subject,
            )
        except AssetGraphRouteError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        finally:
            con.close()

    @app.post("/api/engagements/{engagement_ref}/asset-graph/ownership-conflicts/resolve")
    def resolve_engagement_asset_ownership_conflict(
        engagement_ref: str,
        body: dict[str, Any],
        principal: Principal = Depends(_auth_principal),
    ) -> dict[str, Any]:
        resolved = _resolve_engagement_db(engagement_ref, principal)
        if resolved is None:
            raise HTTPException(status_code=404, detail="Engagement not found.")
        _require_principal_permission(principal, "assets:write")
        db_path, engagement_id = resolved
        con = _open_workflow_db(db_path)
        try:
            return resolve_ownership_conflict_payload(
                con,
                engagement_id=engagement_id,
                body=body,
                operator=principal.subject,
            )
        except AssetGraphRouteNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except AssetGraphRouteError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        finally:
            con.close()

    @app.get("/api/engagements/{engagement_ref}/active-validation")
    def list_engagement_active_validation(
        engagement_ref: str,
        status: str | None = None,
        job_id: int | None = None,
        limit: int = 100,
        principal: Principal = Depends(_auth_principal),
    ) -> dict[str, Any]:
        resolved = _resolve_engagement_db(engagement_ref, principal)
        if resolved is None:
            raise HTTPException(status_code=404, detail="Engagement not found.")
        _require_principal_permission(principal, "active_validation:read")
        db_path, engagement_id = resolved
        con = _open_workflow_db(db_path)
        try:
            return active_validation_list_route_payload(
                con,
                engagement_id=engagement_id,
                status=status,
                job_id=job_id,
                limit=limit,
            )
        finally:
            con.close()

    @app.post("/api/engagements/{engagement_ref}/active-validation/preview")
    def preview_engagement_active_validation_job(
        engagement_ref: str,
        body: dict[str, Any],
        principal: Principal = Depends(_auth_principal),
    ) -> dict[str, Any]:
        resolved = _resolve_engagement_db(engagement_ref, principal)
        if resolved is None:
            raise HTTPException(status_code=404, detail="Engagement not found.")
        for permission in active_validation_write_permissions(body):
            _require_principal_permission(principal, permission)
        _, engagement_id = resolved
        try:
            return preview_active_validation_route_payload(
                engagement_id=engagement_id,
                body=body,
                requested_by=principal.subject,
            )
        except ActiveValidationRouteError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/engagements/{engagement_ref}/active-validation/jobs")
    def create_engagement_active_validation_job(
        engagement_ref: str,
        body: dict[str, Any],
        principal: Principal = Depends(_auth_principal),
    ) -> dict[str, Any]:
        resolved = _resolve_engagement_db(engagement_ref, principal)
        if resolved is None:
            raise HTTPException(status_code=404, detail="Engagement not found.")
        for permission in active_validation_write_permissions(body):
            _require_principal_permission(principal, permission)
        db_path, engagement_id = resolved
        con = _open_workflow_db(db_path)
        try:
            try:
                return create_active_validation_route_payload(
                    con,
                    engagement_id=engagement_id,
                    body=body,
                    requested_by=principal.subject,
                )
            except ActiveValidationRouteError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
        finally:
            con.close()

    @app.post("/api/engagements/{engagement_ref}/active-validation/jobs/{job_id}/approve")
    def approve_engagement_active_validation_job(
        engagement_ref: str,
        job_id: int,
        body: dict[str, Any] | None = None,
        principal: Principal = Depends(_auth_principal),
    ) -> dict[str, Any]:
        resolved = _resolve_engagement_db(engagement_ref, principal)
        if resolved is None:
            raise HTTPException(status_code=404, detail="Engagement not found.")
        _require_principal_permission(principal, "active_validation:approve")
        db_path, engagement_id = resolved
        con = _open_workflow_db(db_path)
        try:
            try:
                return approve_active_validation_route_payload(
                    con,
                    engagement_id=engagement_id,
                    job_id=job_id,
                    body=body,
                    approved_by=principal.subject,
                )
            except LookupError as exc:
                raise HTTPException(status_code=404, detail=str(exc)) from exc
            except ActiveValidationRouteError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
        finally:
            con.close()

    @app.post("/api/engagements/{engagement_ref}/active-validation/jobs/{job_id}/run")
    def run_engagement_active_validation_job(
        engagement_ref: str,
        job_id: int,
        body: dict[str, Any] | None = None,
        principal: Principal = Depends(_auth_principal),
    ) -> dict[str, Any]:
        resolved = _resolve_engagement_db(engagement_ref, principal)
        if resolved is None:
            raise HTTPException(status_code=404, detail="Engagement not found.")
        for permission in active_validation_run_permissions(body):
            _require_principal_permission(principal, permission)
        db_path, engagement_id = resolved
        con = _open_workflow_db(db_path)
        try:
            try:
                return run_active_validation_route_payload(
                    con,
                    engagement_id=engagement_id,
                    job_id=job_id,
                    operator=principal.subject,
                    body=body,
                )
            except LookupError as exc:
                raise HTTPException(status_code=404, detail=str(exc)) from exc
        finally:
            con.close()

    @app.get("/api/engagements/{engagement_ref}/remediation")
    def list_engagement_remediation(
        engagement_ref: str,
        principal: Principal = Depends(_auth_principal),
    ) -> dict[str, Any]:
        resolved = _resolve_engagement_db(engagement_ref, principal)
        if resolved is None:
            raise HTTPException(status_code=404, detail="Engagement not found.")
        _require_principal_permission(principal, "remediation:read")
        db_path, engagement_id = resolved
        con = _open_workflow_db(db_path)
        try:
            return list_remediation_route_payload(con, engagement_id=engagement_id)
        finally:
            con.close()

    @app.get("/api/engagements/{engagement_ref}/remediation/review-queue")
    def get_engagement_remediation_review_queue(
        engagement_ref: str,
        limit: int = 100,
        principal: Principal = Depends(_auth_principal),
    ) -> dict[str, Any]:
        resolved = _resolve_engagement_db(engagement_ref, principal)
        if resolved is None:
            raise HTTPException(status_code=404, detail="Engagement not found.")
        _require_principal_permission(principal, "remediation:read")
        db_path, engagement_id = resolved
        con = _open_workflow_db(db_path)
        try:
            try:
                return remediation_review_queue_route_payload(
                    con,
                    engagement_id=engagement_id,
                    limit=limit,
                )
            except RemediationRouteError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
        finally:
            con.close()

    @app.get("/api/engagements/{engagement_ref}/remediation/export")
    def export_engagement_remediation(
        engagement_ref: str,
        format: str = "json",
        principal: Principal = Depends(_auth_principal),
    ) -> Any:
        resolved = _resolve_engagement_db(engagement_ref, principal)
        if resolved is None:
            raise HTTPException(status_code=404, detail="Engagement not found.")
        _require_principal_permission(principal, "remediation:export")
        db_path, engagement_id = resolved
        con = _open_workflow_db(db_path)
        try:
            try:
                export_payload = remediation_export_route_payload(
                    con,
                    engagement_id=engagement_id,
                    export_format=format,
                    operator=principal.subject,
                )
            except RemediationRouteError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
        finally:
            con.close()

        filename = str(export_payload["filename"])
        headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
        if export_payload["format"] == "csv":
            return Response(
                content=str(export_payload["content"]),
                media_type="text/csv; charset=utf-8",
                headers=headers,
            )
        return JSONResponse(
            content=export_payload["content"],
            headers=headers,
        )

    @app.post("/api/engagements/{engagement_ref}/remediation/propagate-owners")
    def propagate_engagement_remediation_owners(
        engagement_ref: str,
        body: dict[str, Any] | None = None,
        principal: Principal = Depends(_auth_principal),
    ) -> dict[str, Any]:
        resolved = _resolve_engagement_db(engagement_ref, principal)
        if resolved is None:
            raise HTTPException(status_code=404, detail="Engagement not found.")
        for permission in remediation_propagate_permissions():
            _require_principal_permission(principal, permission)
        db_path, engagement_id = resolved
        con = _open_workflow_db(db_path)
        try:
            try:
                return propagate_remediation_owners_route_payload(
                    con,
                    engagement_id=engagement_id,
                    body=body,
                    operator=principal.subject,
                )
            except RemediationRouteError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
        finally:
            con.close()

    @app.post("/api/engagements/{engagement_ref}/remediation/draft-from-asset-graph")
    def draft_engagement_remediation_from_asset_graph(
        engagement_ref: str,
        body: dict[str, Any] | None = None,
        principal: Principal = Depends(_auth_principal),
    ) -> dict[str, Any]:
        resolved = _resolve_engagement_db(engagement_ref, principal)
        if resolved is None:
            raise HTTPException(status_code=404, detail="Engagement not found.")
        for permission in remediation_draft_from_graph_permissions():
            _require_principal_permission(principal, permission)
        db_path, engagement_id = resolved
        con = _open_workflow_db(db_path)
        try:
            try:
                return draft_asset_graph_remediation_route_payload(
                    con,
                    engagement_id=engagement_id,
                    body=body,
                    operator=principal.subject,
                )
            except RemediationRouteError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
        finally:
            con.close()

    @app.post("/api/engagements/{engagement_ref}/remediation")
    def create_engagement_remediation(
        engagement_ref: str,
        body: dict[str, Any],
        principal: Principal = Depends(_auth_principal),
    ) -> dict[str, Any]:
        resolved = _resolve_engagement_db(engagement_ref, principal)
        if resolved is None:
            raise HTTPException(status_code=404, detail="Engagement not found.")
        _require_principal_permission(principal, "remediation:write")
        db_path, engagement_id = resolved
        con = _open_workflow_db(db_path)
        try:
            try:
                return create_remediation_route_payload(
                    con,
                    engagement_id=engagement_id,
                    body=body,
                    operator=principal.subject,
                    require_permission=lambda permission: _require_principal_permission(
                        principal,
                        permission,
                    ),
                )
            except RemediationRouteNotFound as exc:
                raise HTTPException(status_code=404, detail=str(exc)) from exc
            except RemediationRouteError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
        finally:
            con.close()

    @app.patch("/api/engagements/{engagement_ref}/remediation/{item_id}")
    def update_engagement_remediation(
        engagement_ref: str,
        item_id: int,
        body: dict[str, Any],
        principal: Principal = Depends(_auth_principal),
    ) -> dict[str, Any]:
        resolved = _resolve_engagement_db(engagement_ref, principal)
        if resolved is None:
            raise HTTPException(status_code=404, detail="Engagement not found.")
        _require_principal_permission(principal, "remediation:write")
        db_path, engagement_id = resolved
        con = _open_workflow_db(db_path)
        try:
            try:
                return update_remediation_route_payload(
                    con,
                    engagement_id=engagement_id,
                    item_id=item_id,
                    body=body,
                    operator=principal.subject,
                    require_permission=lambda permission: _require_principal_permission(
                        principal,
                        permission,
                    ),
                )
            except RemediationRouteNotFound as exc:
                raise HTTPException(status_code=404, detail=str(exc)) from exc
            except RemediationRouteError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
        finally:
            con.close()

    @app.post("/api/engagements/{engagement_ref}/remediation/{item_id}/review-owner")
    def review_engagement_remediation_owner(
        engagement_ref: str,
        item_id: int,
        body: dict[str, Any] | None = None,
        principal: Principal = Depends(_auth_principal),
    ) -> dict[str, Any]:
        resolved = _resolve_engagement_db(engagement_ref, principal)
        if resolved is None:
            raise HTTPException(status_code=404, detail="Engagement not found.")
        _require_principal_permission(principal, "remediation:write")
        db_path, engagement_id = resolved
        con = _open_workflow_db(db_path)
        try:
            try:
                return review_remediation_owner_route_payload(
                    con,
                    engagement_id=engagement_id,
                    item_id=item_id,
                    body=body,
                    operator=principal.subject,
                )
            except LookupError as exc:
                raise HTTPException(status_code=404, detail=str(exc)) from exc
            except RemediationRouteError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
        finally:
            con.close()

    @app.post("/api/engagements/{engagement_ref}/remediation/{item_id}/request-retest")
    def request_engagement_remediation_retest(
        engagement_ref: str,
        item_id: int,
        body: dict[str, Any] | None = None,
        principal: Principal = Depends(_auth_principal),
    ) -> dict[str, Any]:
        resolved = _resolve_engagement_db(engagement_ref, principal)
        if resolved is None:
            raise HTTPException(status_code=404, detail="Engagement not found.")
        for permission in remediation_retest_permissions():
            _require_principal_permission(principal, permission)
        db_path, engagement_id = resolved
        con = _open_workflow_db(db_path)
        try:
            try:
                return request_remediation_retest_route_payload(
                    con,
                    engagement_id=engagement_id,
                    item_id=item_id,
                    body=body,
                    operator=principal.subject,
                    require_permission=lambda permission: _require_principal_permission(
                        principal,
                        permission,
                    ),
                )
            except LookupError as exc:
                raise HTTPException(status_code=404, detail=str(exc)) from exc
            except RemediationRouteError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
        finally:
            con.close()

    @app.post("/api/engagements/{engagement_ref}/remediation/{item_id}/sync-ticket")
    def sync_engagement_remediation_ticket(
        engagement_ref: str,
        item_id: int,
        body: dict[str, Any] | None = None,
        principal: Principal = Depends(_auth_principal),
    ) -> dict[str, Any]:
        resolved = _resolve_engagement_db(engagement_ref, principal)
        if resolved is None:
            raise HTTPException(status_code=404, detail="Engagement not found.")
        _require_principal_permission(principal, "remediation:write")
        db_path, engagement_id = resolved
        con = _open_workflow_db(db_path)
        try:
            try:
                return sync_remediation_ticket_route_payload(
                    con,
                    engagement_id=engagement_id,
                    item_id=item_id,
                    body=body,
                    operator=principal.subject,
                    data_dir=cfg.data_dir,
                    db_path=db_path,
                )
            except RemediationRouteNotFound as exc:
                raise HTTPException(status_code=404, detail=str(exc)) from exc
            except RemediationRouteError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
        finally:
            con.close()

    @app.get("/api/engagements/{engagement_ref}/monitoring")
    def get_engagement_monitoring(
        engagement_ref: str,
        principal: Principal = Depends(_auth_principal),
    ) -> dict[str, Any]:
        resolved = _resolve_engagement_db(engagement_ref, principal)
        if resolved is None:
            raise HTTPException(status_code=404, detail="Engagement not found.")
        _require_principal_permission(principal, "monitoring:read")
        db_path, engagement_id = resolved
        con = _open_workflow_db(db_path)
        try:
            return monitoring_overview_route_payload(
                con,
                engagement_id=engagement_id,
            )
        finally:
            con.close()

    @app.post("/api/engagements/{engagement_ref}/monitoring/policies")
    def upsert_engagement_monitoring_policy(
        engagement_ref: str,
        body: dict[str, Any],
        principal: Principal = Depends(_auth_principal),
    ) -> dict[str, Any]:
        resolved = _resolve_engagement_db(engagement_ref, principal)
        if resolved is None:
            raise HTTPException(status_code=404, detail="Engagement not found.")
        _require_principal_permission(principal, "monitoring:write")
        db_path, engagement_id = resolved
        con = _open_workflow_db(db_path)
        try:
            try:
                return upsert_monitoring_policy_route_payload(
                    con,
                    engagement_id=engagement_id,
                    body=body,
                    operator=principal.subject,
                )
            except MonitoringRouteError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
        finally:
            con.close()

    @app.post("/api/engagements/{engagement_ref}/monitoring/routes")
    def upsert_engagement_monitoring_alert_route(
        engagement_ref: str,
        body: dict[str, Any],
        principal: Principal = Depends(_auth_principal),
    ) -> dict[str, Any]:
        resolved = _resolve_engagement_db(engagement_ref, principal)
        if resolved is None:
            raise HTTPException(status_code=404, detail="Engagement not found.")
        _require_principal_permission(principal, "monitoring:write")
        db_path, engagement_id = resolved
        con = _open_workflow_db(db_path)
        try:
            try:
                return upsert_monitoring_alert_route_dispatch_payload(
                    con,
                    engagement_id=engagement_id,
                    body=body,
                    operator=principal.subject,
                )
            except MonitoringRouteError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
        finally:
            con.close()

    @app.post("/api/engagements/{engagement_ref}/monitoring/suppressions")
    def add_engagement_monitoring_alert_suppression(
        engagement_ref: str,
        body: dict[str, Any],
        principal: Principal = Depends(_auth_principal),
    ) -> dict[str, Any]:
        resolved = _resolve_engagement_db(engagement_ref, principal)
        if resolved is None:
            raise HTTPException(status_code=404, detail="Engagement not found.")
        _require_principal_permission(principal, "monitoring:write")
        db_path, engagement_id = resolved
        con = _open_workflow_db(db_path)
        try:
            try:
                return add_monitoring_alert_suppression_route_payload(
                    con,
                    engagement_id=engagement_id,
                    body=body,
                    operator=principal.subject,
                )
            except MonitoringRouteError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
        finally:
            con.close()

    @app.post("/api/engagements/{engagement_ref}/monitoring/snapshots")
    def create_engagement_monitoring_snapshot(
        engagement_ref: str,
        body: dict[str, Any] | None = None,
        principal: Principal = Depends(_auth_principal),
    ) -> dict[str, Any]:
        resolved = _resolve_engagement_db(engagement_ref, principal)
        if resolved is None:
            raise HTTPException(status_code=404, detail="Engagement not found.")
        _require_principal_permission(principal, "monitoring:write")
        db_path, engagement_id = resolved
        con = _open_workflow_db(db_path)
        try:
            try:
                return create_monitoring_snapshot_route_payload(
                    con,
                    engagement_id=engagement_id,
                    body=body,
                    operator=principal.subject,
                )
            except MonitoringRouteError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
        finally:
            con.close()

    @app.post("/api/engagements/{engagement_ref}/monitoring/run-due")
    def run_due_engagement_monitoring_policies(
        engagement_ref: str,
        body: dict[str, Any] | None = None,
        principal: Principal = Depends(_auth_principal),
    ) -> dict[str, Any]:
        resolved = _resolve_engagement_db(engagement_ref, principal)
        if resolved is None:
            raise HTTPException(status_code=404, detail="Engagement not found.")
        _require_principal_permission(principal, "monitoring:write")
        db_path, engagement_id = resolved
        con = _open_workflow_db(db_path)
        try:
            return run_due_monitoring_policies_route_payload(
                con,
                engagement_id=engagement_id,
                operator=principal.subject,
                body=body,
            )
        finally:
            con.close()

    @app.patch("/api/engagements/{engagement_ref}/monitoring/alerts/{alert_id}")
    def update_engagement_monitoring_alert(
        engagement_ref: str,
        alert_id: int,
        body: dict[str, Any],
        principal: Principal = Depends(_auth_principal),
    ) -> dict[str, Any]:
        resolved = _resolve_engagement_db(engagement_ref, principal)
        if resolved is None:
            raise HTTPException(status_code=404, detail="Engagement not found.")
        _require_principal_permission(principal, "monitoring:write")
        db_path, engagement_id = resolved
        con = _open_workflow_db(db_path)
        try:
            try:
                return update_monitoring_alert_route_payload(
                    con,
                    engagement_id=engagement_id,
                    alert_id=alert_id,
                    body=body,
                    operator=principal.subject,
                )
            except LookupError as exc:
                raise HTTPException(status_code=404, detail=str(exc)) from exc
            except MonitoringRouteError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
        finally:
            con.close()

    @app.post("/api/engagements/{engagement_ref}/monitoring/alerts/{alert_id}/remediation")
    def escalate_engagement_monitoring_alert_to_remediation(
        engagement_ref: str,
        alert_id: int,
        body: dict[str, Any] | None = None,
        principal: Principal = Depends(_auth_principal),
    ) -> dict[str, Any]:
        resolved = _resolve_engagement_db(engagement_ref, principal)
        if resolved is None:
            raise HTTPException(status_code=404, detail="Engagement not found.")
        _require_principal_permission(principal, "monitoring:write")
        _require_principal_permission(principal, "remediation:write")
        db_path, engagement_id = resolved
        con = _open_workflow_db(db_path)
        try:
            try:
                return escalate_monitoring_alert_to_remediation_route_payload(
                    con,
                    engagement_id=engagement_id,
                    alert_id=alert_id,
                    operator=principal.subject,
                    body=body,
                )
            except LookupError as exc:
                raise HTTPException(status_code=404, detail=str(exc)) from exc
            except MonitoringRouteError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
        finally:
            con.close()

    @app.patch("/api/engagements/{engagement_ref}")
    def update_engagement(
        engagement_ref: str,
        body: dict[str, Any],
        principal: Principal = Depends(_auth_principal),
    ) -> dict[str, Any]:
        resolved = _resolve_engagement_db(engagement_ref, principal)
        if resolved is None:
            raise HTTPException(status_code=404, detail="Engagement not found.")
        _require_principal_permission(principal, "engagements:write")
        db_path, engagement_id = resolved
        con = direct_connect(db_path)
        con.row_factory = sqlite3.Row
        try:
            try:
                return update_engagement_route_payload(
                    con,
                    data_dir=cfg.data_dir,
                    db_path=db_path,
                    engagement_id=engagement_id,
                    body=body,
                    detail_payload_builder=_engagement_detail_payload,
                )
            except LookupError as exc:
                raise HTTPException(status_code=404, detail=str(exc)) from exc
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
            except RuntimeError as exc:
                raise HTTPException(status_code=500, detail=str(exc)) from exc
        finally:
            con.close()

    @app.get("/api/engagements/{engagement_ref}/seeds")
    def list_engagement_seeds(
        engagement_ref: str,
        principal: Principal = Depends(_auth_principal),
    ) -> dict[str, list[dict[str, Any]]]:
        resolved = _resolve_engagement_db(engagement_ref, principal)
        if resolved is None:
            raise HTTPException(status_code=404, detail="Engagement not found.")
        _require_principal_permission(principal, "engagements:read")
        db_path, engagement_id = resolved
        con = direct_connect(db_path)
        con.row_factory = sqlite3.Row
        try:
            return engagement_seed_list_payload(con, engagement_id, format_dt=_format_dt)
        finally:
            con.close()

    @app.post("/api/engagements/{engagement_ref}/seeds")
    def create_engagement_seed(
        engagement_ref: str,
        body: dict[str, Any],
        principal: Principal = Depends(_auth_principal),
    ) -> dict[str, Any]:
        resolved = _resolve_engagement_db(engagement_ref, principal)
        if resolved is None:
            raise HTTPException(status_code=404, detail="Engagement not found.")
        _require_principal_permission(principal, "engagements:write")
        db_path, engagement_id = resolved
        con = direct_connect(db_path)
        con.row_factory = sqlite3.Row
        try:
            try:
                return create_seed_route_payload(
                    con,
                    engagement_id,
                    body,
                    format_dt=_format_dt,
                )
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
            except sqlite3.IntegrityError as exc:
                raise HTTPException(status_code=409, detail=str(exc)) from exc
            except RuntimeError as exc:
                raise HTTPException(status_code=500, detail=str(exc)) from exc
        finally:
            con.close()

    @app.patch("/api/engagements/{engagement_ref}/seeds/{seed_id}")
    def update_engagement_seed(
        engagement_ref: str,
        seed_id: int,
        body: dict[str, Any],
        principal: Principal = Depends(_auth_principal),
    ) -> dict[str, Any]:
        resolved = _resolve_engagement_db(engagement_ref, principal)
        if resolved is None:
            raise HTTPException(status_code=404, detail="Engagement not found.")
        _require_principal_permission(principal, "engagements:write")
        db_path, engagement_id = resolved
        con = direct_connect(db_path)
        con.row_factory = sqlite3.Row
        try:
            try:
                return update_seed_route_payload(
                    con,
                    engagement_id,
                    seed_id,
                    body,
                    format_dt=_format_dt,
                )
            except LookupError as exc:
                raise HTTPException(status_code=404, detail=str(exc)) from exc
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
            except sqlite3.IntegrityError as exc:
                raise HTTPException(status_code=409, detail=str(exc)) from exc
        finally:
            con.close()

    @app.delete("/api/engagements/{engagement_ref}/seeds/{seed_id}")
    def delete_engagement_seed(
        engagement_ref: str,
        seed_id: int,
        principal: Principal = Depends(_auth_principal),
    ) -> dict[str, Any]:
        resolved = _resolve_engagement_db(engagement_ref, principal)
        if resolved is None:
            raise HTTPException(status_code=404, detail="Engagement not found.")
        _require_principal_permission(principal, "engagements:write")
        db_path, engagement_id = resolved
        con = direct_connect(db_path)
        con.row_factory = sqlite3.Row
        try:
            try:
                return delete_seed_route_payload(
                    con,
                    engagement_id,
                    seed_id,
                    format_dt=_format_dt,
                )
            except LookupError as exc:
                raise HTTPException(status_code=404, detail=str(exc)) from exc
        finally:
            con.close()

    @app.post("/api/engagements/{engagement_ref}/runs/kill-chain")
    def launch_engagement_kill_chain(
        engagement_ref: str,
        body: dict[str, Any] | None = None,
        principal: Principal = Depends(_auth_principal),
    ) -> dict[str, Any]:
        return _launch_engagement_run_process(
            engagement_ref,
            body,
            principal=principal,
            force_resume=None,
            launch_status="started",
        )

    @app.post("/api/engagements/{engagement_ref}/runs/resume")
    def resume_engagement_kill_chain(
        engagement_ref: str,
        body: dict[str, Any] | None = None,
        principal: Principal = Depends(_auth_principal),
    ) -> dict[str, Any]:
        return _launch_engagement_run_process(
            engagement_ref,
            body,
            principal=principal,
            force_resume=True,
            launch_status="resumed",
        )

    @app.post("/api/engagements/{engagement_ref}/runs/restart")
    def restart_engagement_kill_chain(
        engagement_ref: str,
        body: dict[str, Any] | None = None,
        principal: Principal = Depends(_auth_principal),
    ) -> dict[str, Any]:
        return _launch_engagement_run_process(
            engagement_ref,
            body,
            principal=principal,
            force_resume=False,
            launch_status="restarted",
        )

    @app.post("/api/engagements/{engagement_ref}/runs/rerun")
    def rerun_engagement_kill_chain(
        engagement_ref: str,
        body: dict[str, Any] | None = None,
        principal: Principal = Depends(_auth_principal),
    ) -> dict[str, Any]:
        return _launch_engagement_run_process(
            engagement_ref,
            body,
            principal=principal,
            force_resume=False,
            launch_status="restarted",
        )

    def _launch_engagement_run_process(
        engagement_ref: str,
        body: dict[str, Any] | None,
        *,
        principal: Principal,
        force_resume: bool | None,
        launch_status: str,
    ) -> dict[str, Any]:
        subject = principal.subject
        resolved = _resolve_engagement_db(engagement_ref, principal)
        if resolved is None:
            raise HTTPException(status_code=404, detail="Engagement not found.")
        _require_principal_permission(principal, "runs:execute")
        db_path, engagement_id = resolved
        con = direct_connect(db_path)
        con.row_factory = sqlite3.Row
        try:
            return launch_kill_chain_run_payload(
                con=con,
                engagement_id=engagement_id,
                operator=subject,
                body=body,
                force_resume=force_resume,
                launch_status=launch_status,
                logs_root=_logs_dir(),
                clear_control_markers=_clear_run_control_markers,
                open_launch_log=open_launch_log_file,
                publish_sync=_publish_progress_sync,
                env=os.environ,
                cwd=Path.cwd(),
                popen_factory=subprocess.Popen,
            )
        except KillChainLaunchConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except (KillChainLaunchNoSeeds, KillChainLaunchOptionError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        finally:
            con.close()

    @app.get("/api/engagements/{engagement_ref}/runs")
    def list_engagement_runs(
        engagement_ref: str,
        verify_manifests: bool = True,
        principal: Principal = Depends(_auth_principal),
    ) -> dict[str, list[dict[str, Any]]]:
        resolved = _resolve_engagement_db(engagement_ref, principal)
        if resolved is None:
            raise HTTPException(status_code=404, detail="Engagement not found.")
        _require_principal_permission(principal, "runs:read")
        db_path, engagement_id = resolved
        con = direct_connect(db_path)
        con.row_factory = sqlite3.Row
        try:
            return engagement_runs_route_payload(
                con,
                engagement_id=engagement_id,
                db_path=db_path,
                verify_manifests=verify_manifests,
                format_dt=_format_dt,
                summarize_run_audit_manifest=summarize_run_audit_manifest,
                audit_review_summary=audit_review_summary,
            )
        finally:
            con.close()

    @app.post("/api/engagements/{engagement_ref}/runs/stop")
    def stop_engagement_kill_chain(
        engagement_ref: str,
        body: dict[str, Any] | None = None,
        principal: Principal = Depends(_auth_principal),
    ) -> dict[str, Any]:
        return _request_engagement_run_control(
            engagement_ref,
            body,
            principal=principal,
            control_kind="stop",
        )

    @app.post("/api/engagements/{engagement_ref}/runs/pause")
    def pause_engagement_kill_chain(
        engagement_ref: str,
        body: dict[str, Any] | None = None,
        principal: Principal = Depends(_auth_principal),
    ) -> dict[str, Any]:
        return _request_engagement_run_control(
            engagement_ref,
            body,
            principal=principal,
            control_kind="pause",
        )

    def _request_engagement_run_control(
        engagement_ref: str,
        body: dict[str, Any] | None,
        *,
        principal: Principal,
        control_kind: str,
    ) -> dict[str, Any]:
        subject = principal.subject
        resolved = _resolve_engagement_db(engagement_ref, principal)
        if resolved is None:
            raise HTTPException(status_code=404, detail="Engagement not found.")
        _require_principal_permission(principal, "runs:control")
        db_path, engagement_id = resolved
        con = direct_connect(db_path)
        con.row_factory = sqlite3.Row
        try:
            return run_control_route_payload(
                con,
                data_dir=cfg.data_dir,
                engagement_id=engagement_id,
                control_kind=control_kind,
                requested_by=subject,
                body=body,
                publish_sync=_publish_progress_sync,
                format_dt=_format_dt,
            )
        except RunLogRouteError as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc
        finally:
            con.close()

    @app.get("/api/engagements/{engagement_ref}/logs")
    def list_engagement_logs(
        engagement_ref: str,
        principal: Principal = Depends(_auth_principal),
    ) -> dict[str, list[dict[str, Any]]]:
        resolved = _resolve_engagement_db(engagement_ref, principal)
        if resolved is None:
            raise HTTPException(status_code=404, detail="Engagement not found.")
        _require_principal_permission(principal, "logs:read")
        _db_path, engagement_id = resolved
        return engagement_logs_route_payload(
            logs_root=_logs_dir(),
            engagement_ref=engagement_ref,
            engagement_id=engagement_id,
            format_size=_format_size,
            format_dt=_format_dt,
        )

    @app.get("/api/engagements/{engagement_ref}/logs/{log_name}")
    def download_engagement_log(
        engagement_ref: str,
        log_name: str,
        principal: Principal = Depends(_auth_principal),
    ) -> Any:
        resolved = _resolve_engagement_db(engagement_ref, principal)
        if resolved is None:
            raise HTTPException(status_code=404, detail="Engagement not found.")
        _require_principal_permission(principal, "logs:read")
        _db_path, engagement_id = resolved
        try:
            artifact = engagement_log_route_file(
                logs_root=_logs_dir(),
                engagement_id=engagement_id,
                log_name=log_name,
            )
        except RunLogRouteNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return FileResponse(path=artifact, filename=artifact.name)

    @app.get("/api/engagements/{engagement_ref}/logs/{log_name}/tail")
    def tail_engagement_log(
        engagement_ref: str,
        log_name: str,
        lines: int = 120,
        principal: Principal = Depends(_auth_principal),
    ) -> dict[str, Any]:
        resolved = _resolve_engagement_db(engagement_ref, principal)
        if resolved is None:
            raise HTTPException(status_code=404, detail="Engagement not found.")
        _require_principal_permission(principal, "logs:read")
        _db_path, engagement_id = resolved
        try:
            return engagement_log_tail_route_payload(
                logs_root=_logs_dir(),
                engagement_id=engagement_id,
                log_name=log_name,
                lines=lines,
            )
        except RunLogRouteNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.get("/api/engagements/{engagement_ref}/artifacts/{artifact_name}")
    def download_engagement_artifact(
        engagement_ref: str,
        artifact_name: str,
        principal: Principal = Depends(_auth_principal),
    ) -> Any:
        _require_principal_permission(principal, "artifacts:read")
        try:
            artifact = engagement_artifact_route_file(
                engagement_ref=engagement_ref,
                artifact_name=artifact_name,
                principal=principal,
                find_artifact=_find_engagement_artifact,
            )
        except ArtifactRouteNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return FileResponse(path=artifact, filename=artifact.name)

    @app.post("/api/scans/start")
    async def start_scan(
        engagement_id: int,
        task_key: str,
        principal: Principal = Depends(_auth_principal),
    ) -> dict[str, str]:
        db_path = authorized_engagements.db_path(engagement_id, principal)
        _require_principal_permission(principal, "scans:write")
        con = get_engagement_db(db_path)
        try:
            response, event = scan_start_route_payload(
                con,
                engagement_id=engagement_id,
                task_key=task_key,
            )
        finally:
            con.close()
        await broker.publish(event)
        return response

    @app.post("/api/tasks/enqueue")
    async def enqueue_task(
        body: dict[str, Any],
        principal: Principal = Depends(_auth_principal),
    ) -> dict[str, str]:
        try:
            request = parse_task_enqueue_request(body)
        except TaskRouteError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        db_path = authorized_engagements.db_path(request.engagement_id, principal)
        _require_principal_permission(principal, "tasks:write")
        try:
            response, event = task_enqueue_route_payload(
                request,
                db_path=db_path,
                queue=coordinator,
                event_publisher=_publish_progress_sync,
            )
        except TaskRouteError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        await broker.publish(event)
        return response

    @app.get("/api/tasks")
    def list_tasks(
        engagement_id: int,
        principal: Principal = Depends(_auth_principal),
    ) -> dict[str, list[dict[str, Any]]]:
        db_path = authorized_engagements.db_path(engagement_id, principal)
        _require_principal_permission(principal, "tasks:read")
        con = get_engagement_db(db_path)
        try:
            return task_list_route_payload(con, engagement_id)
        finally:
            con.close()

    @app.get("/api/workers")
    def list_workers(
        engagement_id: int,
        principal: Principal = Depends(_auth_principal),
    ) -> dict[str, list[dict[str, Any]]]:
        db_path = authorized_engagements.db_path(engagement_id, principal)
        _require_principal_permission(principal, "workers:read")
        con = get_engagement_db(db_path)
        try:
            return worker_list_route_payload(con, engagement_id)
        finally:
            con.close()

    @app.get("/api/queue/metrics")
    def queue_metrics(
        engagement_id: int,
        limit: int = 50,
        principal: Principal = Depends(_auth_principal),
    ) -> dict[str, Any]:
        db_path = authorized_engagements.db_path(engagement_id, principal)
        _require_principal_permission(principal, "queue:read")
        con = get_engagement_db(db_path)
        try:
            return queue_metrics_route_payload(con, engagement_id, limit=limit)
        finally:
            con.close()

    @app.get("/api/scans/{engagement_id}/progress")
    def scan_progress(
        engagement_id: int, principal: Principal = Depends(_auth_principal)
    ) -> dict[str, list[dict[str, Any]]]:
        db_path = authorized_engagements.db_path(engagement_id, principal)
        _require_principal_permission(principal, "scans:read")
        con = get_engagement_db(db_path)
        try:
            return scan_progress_route_payload(con, engagement_id)
        finally:
            con.close()

    @app.get("/api/engagements/{engagement_id}/assets")
    def engagement_assets(
        engagement_id: int, principal: Principal = Depends(_auth_principal)
    ) -> dict[str, Any]:
        db_path = authorized_engagements.db_path(engagement_id, principal)
        _require_principal_permission(principal, "assets:read")
        con = get_engagement_db(db_path)
        try:
            return engagement_assets_route_payload(con, engagement_id)
        finally:
            con.close()

    @app.get("/api/engagements/{engagement_id}/vuln-summary")
    def vuln_summary(
        engagement_id: int,
        principal: Principal = Depends(_auth_principal),
    ) -> dict[str, Any]:
        db_path = authorized_engagements.db_path(engagement_id, principal)
        _require_principal_permission(principal, "findings:read")
        con = get_engagement_db(db_path)
        try:
            return vulnerability_summary_route_payload(con, engagement_id)
        finally:
            con.close()

    @app.get("/api/engagements/{engagement_id}/asset-tree")
    def asset_tree(
        engagement_id: int, principal: Principal = Depends(_auth_principal)
    ) -> dict[str, list[dict[str, Any]]]:
        db_path = authorized_engagements.db_path(engagement_id, principal)
        _require_principal_permission(principal, "assets:read")
        con = get_engagement_db(db_path)
        try:
            return asset_tree_route_payload(con, engagement_id)
        finally:
            con.close()

    def _publish_command_event(event: Any) -> None:
        publish_command_progress_event(broker.publish_sync, event)

    def get_command_center(engagement_id: Any) -> Any:
        return build_command_center_service(
            engagement_id=engagement_id,
            config=cfg,
            coordinator=coordinator,
            publish_event=_publish_command_event,
        )

    def _command_body_engagement_id(body: dict[str, Any]) -> Any:
        try:
            return command_body_engagement_id(body)
        except CommandCenterRouteError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/api/assets/{host}/context")
    def get_host_context_api(
        host: str,
        engagement_id: int,
        principal: Principal = Depends(_auth_principal),
    ) -> dict[str, Any]:
        authorized_engagements.db_path(engagement_id, principal)
        _require_principal_permission(principal, "assets:read")
        return host_context_route_payload(get_command_center(engagement_id), host)

    @app.get("/api/assets/{host}/actions")
    def get_host_actions_api(
        host: str,
        engagement_id: int,
        principal: Principal = Depends(_auth_principal),
    ) -> dict[str, Any]:
        authorized_engagements.db_path(engagement_id, principal)
        _require_principal_permission(principal, "actions:read")
        return host_actions_route_payload(get_command_center(engagement_id), host)

    @app.post("/api/actions/{action_id}/execute")
    def execute_action_api(
        action_id: str,
        body: dict[str, Any],
        principal: Principal = Depends(_auth_principal),
    ) -> dict[str, Any]:
        engagement_id = _command_body_engagement_id(body)
        authorized_engagements.db_path(int(engagement_id), principal)
        _require_principal_permission(principal, "actions:execute")
        try:
            return execute_action_route_payload(get_command_center(engagement_id), action_id, body)
        except CommandCenterRouteError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/actions/{action_id}/approve")
    def approve_action_api(
        action_id: str,
        body: dict[str, Any],
        principal: Principal = Depends(_auth_principal),
    ) -> dict[str, Any]:
        engagement_id = _command_body_engagement_id(body)
        authorized_engagements.db_path(int(engagement_id), principal)
        _require_principal_permission(principal, "actions:approve")
        try:
            return approve_action_route_payload(get_command_center(engagement_id), action_id, body)
        except CommandCenterRouteError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/sentry/toggle")
    def toggle_sentry_api(
        body: dict[str, Any],
        principal: Principal = Depends(_auth_principal),
    ) -> dict[str, Any]:
        engagement_id = _command_body_engagement_id(body)
        authorized_engagements.db_path(int(engagement_id), principal)
        _require_principal_permission(principal, "sentry:write")
        return toggle_sentry_route_payload(get_command_center(engagement_id), body)

    @app.post("/api/sentry/emergency-stop")
    def emergency_stop_api(
        body: dict[str, Any],
        principal: Principal = Depends(_auth_principal),
    ) -> dict[str, Any]:
        engagement_id = _command_body_engagement_id(body)
        authorized_engagements.db_path(int(engagement_id), principal)
        _require_principal_permission(principal, "sentry:emergency_stop")
        return emergency_stop_route_payload(get_command_center(engagement_id))

    @app.get("/api/timeline")
    def get_timeline_api(
        engagement_id: int,
        principal: Principal = Depends(_auth_principal),
    ) -> dict[str, Any]:
        authorized_engagements.db_path(engagement_id, principal)
        _require_principal_permission(principal, "timeline:read")
        return timeline_route_payload(get_command_center(engagement_id))

    @app.websocket("/ws/progress")
    async def progress_ws(websocket: WebSocket) -> None:
        principal = websocket_principal(websocket)
        if principal is None:
            await websocket.close(code=1008)
            return
        try:
            engagement_id = int(str(websocket.query_params.get("engagement_id") or ""))
        except ValueError:
            await websocket.close(code=1008)
            return
        try:
            authorized_engagements.db_path(engagement_id, principal)
        except HTTPException:
            await websocket.close(code=1008)
            return
        await websocket.accept(
            subprotocol=progress_websocket_subprotocol(
                str(websocket.headers.get("sec-websocket-protocol") or "")
            )
        )
        queue = broker.subscribe()
        try:
            while True:
                event = await queue.get()
                if event.engagement_id != engagement_id:
                    continue
                await websocket.send_text(progress_event_websocket_text(event))
        except Exception:
            await asyncio.sleep(0)
        finally:
            broker.unsubscribe(queue)

    @app.get("/health")
    async def health() -> dict:
        return {"status": "ok", "version": "7.2.0"}

    return app


def create_server(host: str = "127.0.0.1", port: int = 8080) -> Any:
    app = create_app()
    try:
        import uvicorn
    except ImportError as exc:
        raise RuntimeError("uvicorn is required to run the web interface.") from exc
    return uvicorn.Server(uvicorn.Config(app=app, host=host, port=port, log_level="info"))
