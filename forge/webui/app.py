from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import re
import sqlite3
import subprocess
import sys
import time
from collections import defaultdict
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlparse, urlsplit, urlunsplit

from forge.audit.manifest import summarize_run_audit_manifest
from forge.config import ForgeConfig
from forge.db.session import get_engagement_db
from forge.distributed.coordinator import QueueCoordinator
from forge.distributed.scheduler import ScheduledTask, TaskScheduler
from forge.engagement_ids import allocate_engagement_id, engagement_db_root, numeric_engagement_db_files
from forge.models.pydantic_models import CommandEvent
from forge.reporting.dashboard import (
    _annotate_audit_manifest_bundle,
    _engagement_metadata,
    _engagement_tags,
    _detail_sections,
    _format_dt,
    _format_size,
    _graph_files,
    _graph_state_for_engagement,
    _highest_severity,
    _latest_report_family_files,
    _latest_engagement_run,
    _materialize_audit_manifest_artifacts,
    _normalize_engagement_tags,
    _report_history_payload,
    _reportable_vulnerability_rows,
    _report_summary_payload,
    _run_policy_summary,
    _safe_json_loads,
    _seed_list,
    _seed_graph_summary,
    _slugify,
    _severity_summary,
    _summary_counts,
    _table_columns,
    _table_exists,
)
from forge.utils.automation import AutomationEngine, EXECUTABLE_AUTOMATION_ACTIONS
from forge.utils.kill_chain_options import normalize_kill_chain_max_iter
from forge.utils.playbooks import PlaybookEngine
from forge.webui.auth import mint_token, validate_jwt_secret, verify_token
from forge.webui.command_center import CommandCenterService
from forge.webui.state import ProgressEvent, broker

_VALID_ENGAGEMENT_STATUSES = {"PREP", "ACTIVE", "COMPLETE", "ARCHIVED"}
_VALID_SEED_STATUSES = {"pending", "running", "completed", "failed", "ignored"}
_VALID_SEED_SOURCES = {"operator", "scope", "discovered", "artifact", "cross_reference"}
_VALID_REPORT_PROVIDERS = {
    "auto",
    "template",
    "llama_cpp",
    "kiro_cli",
    "claude_code",
    "codex_cli",
    "gemini_cli",
    "bedrock_anthropic",
    "openai_compatible",
}
_COMPANY_SUFFIXES = {
    "co",
    "company",
    "corp",
    "corporation",
    "group",
    "holdings",
    "inc",
    "incorporated",
    "llc",
    "limited",
    "ltd",
    "plc",
    "pte",
    "pty",
}
_MOBILE_BUNDLE_SEED_SUFFIXES = (".apk", ".ipa", ".aab", ".apkm", ".apks", ".xapk")


def create_app() -> Any:
    try:
        from fastapi import Depends, FastAPI, HTTPException, Request, WebSocket
        from fastapi.responses import FileResponse, JSONResponse
        from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
        from fastapi.staticfiles import StaticFiles
    except ImportError as exc:
        raise RuntimeError("FastAPI is required for web interface support.") from exc

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
    if frontend_assets_dir.is_dir():
        app.mount("/assets", StaticFiles(directory=frontend_assets_dir), name="frontend-assets")
    auth_scheme = HTTPBearer(auto_error=False)
    if cfg.web_auth.lower() == "jwt":
        validate_jwt_secret()

    # --- Rate limiting (60 req/min per IP, in-process) ---
    _rate_window: dict[str, list[float]] = defaultdict(list)

    @app.middleware("http")
    async def _rate_limit(request: Request, call_next):
        if request.url.path == "/health":
            return await call_next(request)
        client_ip = request.client.host if request.client else "unknown"
        now = time.monotonic()
        window = _rate_window[client_ip]
        window[:] = [t for t in window if now - t < 60.0]
        if len(window) >= 60:
            return JSONResponse(status_code=429, content={"error": "rate limit exceeded"})
        window.append(now)
        return await call_next(request)

    # --- Production 500 handler (no traceback leakage) ---
    if not _is_dev:
        @app.exception_handler(Exception)
        async def _internal_error(request: Request, exc: Exception) -> JSONResponse:
            return JSONResponse(status_code=500, content={"error": "internal error"})
    def _auth_subject(
        creds: HTTPAuthorizationCredentials | None = Depends(auth_scheme),
    ) -> str:
        if creds is None:
            raise HTTPException(status_code=401, detail="Missing authorization token.")
        subject = verify_token(creds.credentials)
        if subject is None:
            raise HTTPException(status_code=401, detail="Invalid authorization token.")
        return subject

    def _bootstrap_secret() -> str:
        secret = os.environ.get("FORGE_WEB_BOOTSTRAP_TOKEN", "").strip()
        if not secret:
            raise HTTPException(
                status_code=503,
                detail="Token issuance is disabled until FORGE_WEB_BOOTSTRAP_TOKEN is configured.",
            )
        return secret

    def _publish_progress_sync(engagement_id: int, message: str, payload: dict[str, Any]) -> None:
        broker.publish_sync(
            ProgressEvent(
                engagement_id=engagement_id,
                message=message,
                payload=payload,
            )
        )

    def _engagement_db_root() -> Path:
        return engagement_db_root(cfg.data_dir)

    def _numeric_engagement_db_files() -> list[Path]:
        return numeric_engagement_db_files(cfg.data_dir)

    def _allocate_engagement_id() -> int:
        return allocate_engagement_id(cfg.data_dir)

    async def _queue_event_bridge() -> None:
        while not event_bridge_stop.is_set():
            msg = await asyncio.to_thread(
                coordinator.consume_topic,
                "forge.events",
                0.75,
            )
            if msg is None:
                continue
            engagement_id_raw = msg.payload.get("engagement_id")
            message_raw = msg.payload.get("message")
            payload_raw = msg.payload.get("payload")
            if not isinstance(engagement_id_raw, int) or engagement_id_raw <= 0:
                continue
            if not isinstance(message_raw, str) or not message_raw:
                continue
            payload = payload_raw if isinstance(payload_raw, dict) else {}
            await broker.publish(
                ProgressEvent(
                    engagement_id=engagement_id_raw,
                    message=message_raw,
                    payload=payload,
                )
            )

    def _iter_live_run_progress_snapshots() -> list[tuple[int, str, dict[str, Any]]]:
        db_root = cfg.data_dir / "engagements"
        if not db_root.exists():
            return []
        snapshots: list[tuple[int, str, dict[str, Any]]] = []
        for db_file in _numeric_engagement_db_files():
            con = sqlite3.connect(db_file)
            con.row_factory = sqlite3.Row
            try:
                if not _table_exists(con, "engagement_runs"):
                    continue
                rows = con.execute(
                    """
                    SELECT id,
                           engagement_id,
                           status,
                           current_iteration,
                           max_iterations,
                           metadata_json
                    FROM engagement_runs
                    ORDER BY engagement_id ASC, updated_at DESC, id DESC
                    """
                ).fetchall()
            except sqlite3.OperationalError:
                continue
            finally:
                con.close()
            seen_engagements: set[int] = set()
            for row in rows:
                engagement_id = int(row["engagement_id"] or 0)
                if engagement_id <= 0 or engagement_id in seen_engagements:
                    continue
                seen_engagements.add(engagement_id)
                metadata = _safe_json_loads(str(row["metadata_json"] or "{}"))
                effective_status = _effective_run_status(str(row["status"] or ""), metadata)
                if effective_status not in {"running", "pausing", "stopping"}:
                    continue
                last_step = str(metadata.get("last_step") or "").strip()
                last_message = str(metadata.get("last_message") or "").strip()
                last_step_at = str(metadata.get("last_step_at") or "").strip()
                if not last_step and not last_step_at:
                    continue
                payload = {
                    "run_id": int(row["id"]),
                    "status": effective_status,
                    "phase": str(metadata.get("phase") or ""),
                    "last_step": last_step,
                    "last_message": last_message,
                    "last_step_elapsed_seconds": float(
                        metadata.get("last_step_elapsed_seconds") or 0.0
                    ),
                    "last_step_at": last_step_at,
                    "current_iteration": int(row["current_iteration"] or 0),
                    "max_iterations": int(row["max_iterations"] or 0),
                    "run_kind": "kill_chain",
                    "counts": metadata.get("counts") if isinstance(metadata.get("counts"), dict) else {},
                    "queue_metrics": (
                        metadata.get("queue_metrics")
                        if isinstance(metadata.get("queue_metrics"), dict)
                        else {}
                    ),
                    "last_iteration_delta": (
                        metadata.get("last_iteration_delta")
                        if isinstance(metadata.get("last_iteration_delta"), dict)
                        else {}
                    ),
                    "last_iteration_stable": (
                        metadata.get("last_iteration_stable")
                        if isinstance(metadata.get("last_iteration_stable"), bool)
                        else None
                    ),
                    "active_batch_label": str(metadata.get("active_batch_label") or ""),
                    "active_batch_eta_seconds": (
                        float(metadata.get("active_batch_eta_seconds"))
                        if isinstance(metadata.get("active_batch_eta_seconds"), (int, float))
                        and not isinstance(metadata.get("active_batch_eta_seconds"), bool)
                        else None
                    ),
                    "active_artifact_stage_label": str(
                        metadata.get("active_artifact_stage_label") or ""
                    ),
                    "active_artifact_eta_seconds": (
                        float(metadata.get("active_artifact_eta_seconds"))
                        if isinstance(metadata.get("active_artifact_eta_seconds"), (int, float))
                        and not isinstance(metadata.get("active_artifact_eta_seconds"), bool)
                        else None
                    ),
                    "active_validation_stage_label": str(
                        metadata.get("active_validation_stage_label") or ""
                    ),
                    "active_validation_eta_seconds": (
                        float(metadata.get("active_validation_eta_seconds"))
                        if isinstance(metadata.get("active_validation_eta_seconds"), (int, float))
                        and not isinstance(metadata.get("active_validation_eta_seconds"), bool)
                        else None
                    ),
                    "active_finalization_stage_label": str(
                        metadata.get("active_finalization_stage_label") or ""
                    ),
                    "active_finalization_eta_seconds": (
                        float(metadata.get("active_finalization_eta_seconds"))
                        if isinstance(metadata.get("active_finalization_eta_seconds"), (int, float))
                        and not isinstance(metadata.get("active_finalization_eta_seconds"), bool)
                        else None
                    ),
                }
                fingerprint = json.dumps(
                    {
                        "run_id": payload["run_id"],
                        "status": payload["status"],
                        "phase": payload["phase"],
                        "last_step": payload["last_step"],
                        "last_message": payload["last_message"],
                        "last_step_elapsed_seconds": payload["last_step_elapsed_seconds"],
                        "last_step_at": payload["last_step_at"],
                        "current_iteration": payload["current_iteration"],
                        "counts": payload["counts"],
                        "queue_metrics": payload["queue_metrics"],
                        "last_iteration_delta": payload["last_iteration_delta"],
                        "last_iteration_stable": payload["last_iteration_stable"],
                        "active_batch_label": payload["active_batch_label"],
                        "active_batch_eta_seconds": payload["active_batch_eta_seconds"],
                        "active_artifact_stage_label": payload["active_artifact_stage_label"],
                        "active_artifact_eta_seconds": payload["active_artifact_eta_seconds"],
                        "active_validation_stage_label": payload["active_validation_stage_label"],
                        "active_validation_eta_seconds": payload["active_validation_eta_seconds"],
                        "active_finalization_stage_label": payload["active_finalization_stage_label"],
                        "active_finalization_eta_seconds": payload["active_finalization_eta_seconds"],
                    },
                    sort_keys=True,
                )
                snapshots.append((engagement_id, fingerprint, payload))
        return snapshots

    async def _run_progress_bridge() -> None:
        last_seen: dict[int, str] = {}
        while not event_bridge_stop.is_set():
            active_engagements: set[int] = set()
            for engagement_id, fingerprint, payload in _iter_live_run_progress_snapshots():
                active_engagements.add(engagement_id)
                if last_seen.get(engagement_id) == fingerprint:
                    continue
                last_seen[engagement_id] = fingerprint
                await broker.publish(
                    ProgressEvent(
                        engagement_id=engagement_id,
                        message="engagement_run_progress",
                        payload=payload,
                    )
                )
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

    def _reports_dir() -> Path:
        return Path.cwd() / "reports"

    def _frontend_entry_response() -> Any:
        if frontend_index_path.is_file():
            return FileResponse(frontend_index_path)
        return FileResponse(legacy_template_path)

    def _looks_like_person_name(value: str) -> bool:
        tokens = [token for token in re.split(r"\s+", value.strip()) if token]
        if len(tokens) < 2 or len(tokens) > 4:
            return False
        if any(token.lower().strip(".,") in _COMPANY_SUFFIXES for token in tokens):
            return False
        return all(re.match(r"^[A-Za-z][A-Za-z'\-]*$", token) for token in tokens)

    def _looks_like_company_name(value: str) -> bool:
        tokens = [token.strip(".,") for token in re.split(r"\s+", value.strip()) if token]
        if len(tokens) < 2:
            return False
        return any(token.lower() in _COMPANY_SUFFIXES for token in tokens)

    def _classify_seed_value(value: str) -> str:
        text = value.strip()
        if not text:
            return "other"
        lowered = text.lower()
        if re.match(r"^\+\d{6,15}$", text):
            return "phone"
        if re.match(r"^@[a-z0-9_.\-]{2,32}$", lowered):
            return "username"
        try:
            parsed_ip = ipaddress.ip_address(text)
            return "ipv6" if parsed_ip.version == 6 else "ipv4"
        except ValueError:
            pass
        parsed = urlparse(text)
        if parsed.scheme in {"http", "https"} and parsed.netloc:
            if parsed.path.lower().endswith(_MOBILE_BUNDLE_SEED_SUFFIXES):
                return "apk_url"
            return "url"
        if re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", text):
            return "email"
        if lowered.startswith("*."):
            lowered = lowered[2:]
        if re.match(
            r"^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(?:\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)+$",
            lowered,
        ):
            return "domain"
        if _looks_like_company_name(text):
            return "company"
        if _looks_like_person_name(text):
            return "name"
        return "other"

    def _canonical_http_url_value(value: str) -> str | None:
        try:
            parsed = urlsplit(str(value or "").strip())
        except ValueError:
            return None
        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https"}:
            return None
        host = (parsed.hostname or "").strip().lower()
        if not host:
            return None
        try:
            port = parsed.port
        except ValueError:
            return None
        host_part = f"[{host}]" if ":" in host and not host.startswith("[") else host
        default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
        netloc = f"{host_part}:{port}" if port is not None and not default_port else host_part
        return urlunsplit((scheme, netloc, parsed.path or "/", parsed.query, ""))

    def _canonical_seed_value(seed_value: str, seed_type: str) -> str:
        value = str(seed_value or "").strip()
        if str(seed_type or "").strip().lower() in {"url", "apk_url"}:
            return _canonical_http_url_value(value) or value
        return value

    def _scope_entries_for_seed(seed_value: str, seed_type: str) -> list[str]:
        entries = [seed_value]
        if seed_type == "domain":
            entries.append(f"*.{seed_value.lstrip('*.')}")
        return entries

    def _effective_run_status(status: str, metadata: Any) -> str:
        normalized = str(status or "").strip().lower()
        metadata_dict = metadata if isinstance(metadata, dict) else {}
        if normalized == "running":
            if metadata_dict.get("pause_requested"):
                return "pausing"
            if metadata_dict.get("stop_requested"):
                return "stopping"
            return normalized
        if normalized == "cancelled" and metadata_dict.get("lifecycle_state") == "paused":
            return "paused"
        return normalized

    def _normalize_seed_source(value: str | None) -> str:
        source = str(value or "").strip().lower()
        if source in _VALID_SEED_SOURCES:
            return source
        return "operator"

    def _ensure_engagement_metadata_column(con: sqlite3.Connection) -> None:
        if "metadata_json" in _table_columns(con, "engagements"):
            return
        try:
            con.execute(
                "ALTER TABLE engagements ADD COLUMN metadata_json TEXT NOT NULL DEFAULT '{}'"
            )
        except sqlite3.OperationalError as exc:
            if "duplicate column" not in str(exc).lower():
                raise

    def _engagement_seed_rows(con: sqlite3.Connection, engagement_id: int) -> list[dict[str, Any]]:
        rows = con.execute(
            """
            SELECT id,
                   seed_value,
                   seed_type,
                   source,
                   status,
                   depth,
                   confidence,
                   parent_seed_id,
                   metadata_json,
                   discovered_at,
                   updated_at
            FROM engagement_seeds
            WHERE engagement_id=?
            ORDER BY depth ASC, id ASC
            """,
            (engagement_id,),
        ).fetchall()
        items: list[dict[str, Any]] = []
        for row in rows:
            metadata = _safe_json_loads(str(row["metadata_json"] or "{}"))
            items.append(
                {
                    "id": int(row["id"]),
                    "seed_value": str(row["seed_value"] or ""),
                    "seed_type": str(row["seed_type"] or ""),
                    "source": str(row["source"] or ""),
                    "status": str(row["status"] or ""),
                    "depth": int(row["depth"] or 0),
                    "confidence": float(row["confidence"] or 0.0),
                    "parent_seed_id": int(row["parent_seed_id"]) if row["parent_seed_id"] is not None else None,
                    "metadata": metadata if isinstance(metadata, dict) else {},
                    "discovered_at": _format_dt(str(row["discovered_at"] or "")),
                    "updated_at": _format_dt(str(row["updated_at"] or "")),
                }
            )
        return items

    def _engagement_run_rows(
        con: sqlite3.Connection,
        engagement_id: int,
        *,
        db_path: Path | None = None,
        verify_manifests: bool = False,
    ) -> list[dict[str, Any]]:
        rows = con.execute(
            """
            SELECT id,
                   run_kind,
                   status,
                   seed_value,
                   seed_type,
                   seed_count,
                   max_iterations,
                   current_iteration,
                   resume_enabled,
                   dry_run,
                   attack_mode,
                   error,
                   metadata_json,
                   started_at,
                   completed_at,
                   updated_at
            FROM engagement_runs
            WHERE engagement_id=?
            ORDER BY started_at DESC, id DESC
            """,
            (engagement_id,),
        ).fetchall()
        items: list[dict[str, Any]] = []
        for row in rows:
            metadata = _safe_json_loads(str(row["metadata_json"] or "{}"))
            policy_summary = _run_policy_summary(
                metadata,
                dry_run=bool(row["dry_run"]),
                attack_mode=bool(row["attack_mode"]),
            )
            items.append(
                {
                    "id": int(row["id"]),
                    "run_kind": str(row["run_kind"] or ""),
                    "status": _effective_run_status(str(row["status"] or ""), metadata),
                    "raw_status": str(row["status"] or ""),
                    "seed_value": str(row["seed_value"] or ""),
                    "seed_type": str(row["seed_type"] or ""),
                    "seed_count": int(row["seed_count"] or 0),
                    "max_iterations": int(row["max_iterations"] or 0),
                    "current_iteration": int(row["current_iteration"] or 0),
                    "resume_enabled": bool(row["resume_enabled"]),
                    "dry_run": bool(row["dry_run"]),
                    "attack_mode": bool(row["attack_mode"]),
                    **policy_summary,
                    "error": str(row["error"] or "") or None,
                    "metadata": metadata if isinstance(metadata, dict) else {},
                    "audit_manifest": summarize_run_audit_manifest(
                        con,
                        db_path=db_path,
                        engagement_id=engagement_id,
                        run_id=int(row["id"]),
                        verify=verify_manifests and db_path is not None,
                    ),
                    "started_at": _format_dt(str(row["started_at"] or "")),
                    "completed_at": _format_dt(str(row["completed_at"] or "")),
                    "updated_at": _format_dt(str(row["updated_at"] or "")),
                }
            )
        return items

    def _control_dir() -> Path:
        path = cfg.data_dir / "run_control"
        path.mkdir(parents=True, exist_ok=True)
        return path

    def _stop_marker_path(engagement_id: int) -> Path:
        return _control_dir() / f"engagement_{engagement_id}_stop.json"

    def _pause_marker_path(engagement_id: int) -> Path:
        return _control_dir() / f"engagement_{engagement_id}_pause.json"

    def _clear_run_control_markers(engagement_id: int) -> None:
        _stop_marker_path(engagement_id).unlink(missing_ok=True)
        _pause_marker_path(engagement_id).unlink(missing_ok=True)

    def _latest_running_engagement_run(con: sqlite3.Connection, engagement_id: int) -> sqlite3.Row | None:
        return con.execute(
            """
            SELECT id, metadata_json
            FROM engagement_runs
            WHERE engagement_id=? AND status='running'
            ORDER BY started_at DESC, id DESC
            LIMIT 1
            """,
            (engagement_id,),
        ).fetchone()

    def _logs_dir() -> Path:
        path = cfg.data_dir / "logs"
        path.mkdir(parents=True, exist_ok=True)
        return path

    def _engagement_log_files(engagement_id: int) -> list[Path]:
        logs_dir = _logs_dir()
        return sorted(
            logs_dir.glob(f"engagement_{engagement_id}_kill_chain_*.log"),
            key=lambda item: item.stat().st_mtime,
            reverse=True,
        )

    def _log_payload(engagement_ref: str, log_path: Path) -> dict[str, Any]:
        stat = log_path.stat()
        return {
            "name": log_path.name,
            "href": f"/api/engagements/{quote(engagement_ref, safe='')}/logs/{quote(log_path.name, safe='')}",
            "tail_api": f"/api/engagements/{quote(engagement_ref, safe='')}/logs/{quote(log_path.name, safe='')}/tail",
            "size_bytes": int(stat.st_size),
            "size_label": _format_size(int(stat.st_size)),
            "modified_at": _format_dt(time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(stat.st_mtime))),
        }

    def _resolve_log_file(engagement_id: int, log_name: str) -> Path | None:
        candidate = (_logs_dir() / Path(log_name).name).resolve()
        logs_root = _logs_dir().resolve()
        if not candidate.is_file() or logs_root not in candidate.parents:
            return None
        expected_prefix = f"engagement_{engagement_id}_kill_chain_"
        if not candidate.name.startswith(expected_prefix):
            return None
        return candidate

    def _tail_lines(path: Path, max_lines: int) -> str:
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:  # noqa: BLE001
            return ""
        return "\n".join(lines[-max_lines:])

    def _ordered_launch_seeds(con: sqlite3.Connection, engagement_id: int) -> list[dict[str, str]]:
        rows = con.execute(
            """
            SELECT seed_value, seed_type
            FROM engagement_seeds
            WHERE engagement_id=?
            ORDER BY depth ASC,
                     CASE seed_type
                         WHEN 'domain' THEN 0
                         WHEN 'url' THEN 1
                         WHEN 'apk_url' THEN 2
                         WHEN 'subdomain' THEN 3
                         WHEN 'email' THEN 4
                         WHEN 'phone' THEN 5
                         WHEN 'username' THEN 6
                         WHEN 'name' THEN 7
                         WHEN 'company' THEN 8
                         WHEN 'ipv4' THEN 9
                         WHEN 'ipv6' THEN 10
                         ELSE 11
                     END,
                     CASE
                         WHEN source='operator' THEN 0
                         WHEN source='scope' THEN 1
                         ELSE 2
                     END,
                     id ASC
            """,
            (engagement_id,),
        ).fetchall()
        ordered: list[dict[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for row in rows:
            seed_value = str(row["seed_value"] or "").strip()
            seed_type = str(row["seed_type"] or "").strip().lower()
            if not seed_value:
                continue
            seed_key = (seed_type, seed_value)
            if seed_key in seen:
                continue
            seen.add(seed_key)
            ordered.append({"seed_value": seed_value, "seed_type": seed_type})
        return ordered

    def _update_scope_json(
        con: sqlite3.Connection,
        engagement_id: int,
        *,
        add_entries: list[str] | None = None,
        remove_entries: list[str] | None = None,
    ) -> list[str]:
        row = con.execute(
            "SELECT scope_json FROM engagements WHERE id=?",
            (engagement_id,),
        ).fetchone()
        scope = _safe_json_loads(str(row[0] or "[]")) if row is not None else []
        scope_list = [str(item).strip() for item in scope] if isinstance(scope, list) else []
        filtered = [
            item
            for item in scope_list
            if item and item not in set(remove_entries or [])
        ]
        seen = set(filtered)
        for entry in add_entries or []:
            value = str(entry).strip()
            if value and value not in seen:
                filtered.append(value)
                seen.add(value)
        con.execute(
            "UPDATE engagements SET scope_json=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
            (json.dumps(filtered), engagement_id),
        )
        return filtered

    def _upsert_engagement_seed(
        con: sqlite3.Connection,
        engagement_id: int,
        seed_value: str,
        *,
        seed_type: str | None = None,
        source: str = "operator",
        status: str = "pending",
        depth: int = 0,
        confidence: float = 1.0,
        metadata: dict[str, Any] | None = None,
    ) -> int:
        normalized_value = seed_value.strip()
        if not normalized_value:
            raise HTTPException(status_code=400, detail="seed_value must not be empty.")
        resolved_type = (seed_type or _classify_seed_value(normalized_value)).strip().lower()
        normalized_value = _canonical_seed_value(normalized_value, resolved_type)
        if status not in _VALID_SEED_STATUSES:
            raise HTTPException(status_code=400, detail=f"Invalid seed status: {status}")
        normalized_source = _normalize_seed_source(source)
        con.execute(
            """
            INSERT INTO engagement_seeds
                (
                    engagement_id,
                    seed_value,
                    seed_type,
                    source,
                    status,
                    depth,
                    confidence,
                    metadata_json
                )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(engagement_id, seed_type, seed_value) DO UPDATE SET
                source=excluded.source,
                status=excluded.status,
                depth=excluded.depth,
                confidence=excluded.confidence,
                metadata_json=excluded.metadata_json,
                updated_at=CURRENT_TIMESTAMP
            """,
            (
                engagement_id,
                normalized_value,
                resolved_type,
                normalized_source,
                status,
                max(0, int(depth)),
                float(confidence),
                json.dumps(metadata or {}, sort_keys=True),
            ),
        )
        row = con.execute(
            """
            SELECT id
            FROM engagement_seeds
            WHERE engagement_id=? AND seed_type=? AND seed_value=?
            """,
            (engagement_id, resolved_type, normalized_value),
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=500, detail="Seed insert failed.")
        return int(row[0])

    def _files_matching(patterns: tuple[str, ...]) -> list[Path]:
        reports_dir = _reports_dir()
        matches: list[Path] = []
        for pattern in patterns:
            matches.extend(reports_dir.glob(pattern))
        return sorted(set(matches), key=lambda path: (path.suffix, path.name.lower()))

    def _engagement_prefixed_artifact_files(
        *,
        prefix: str,
        engagement_id: int,
        suffixes: tuple[str, ...],
    ) -> list[Path]:
        reports_dir = _reports_dir()
        stem_prefix = f"{prefix}_{engagement_id}"
        return sorted(
            {
                path
                for suffix in suffixes
                for path in reports_dir.glob(f"{stem_prefix}*{suffix}")
                if path.stem == stem_prefix or path.stem.startswith(f"{stem_prefix}_")
            },
            key=lambda path: (path.suffix, path.name.lower()),
        )

    def _report_files(engagement_id: int) -> list[Path]:
        return _engagement_prefixed_artifact_files(
            prefix="engagement",
            engagement_id=engagement_id,
            suffixes=(".md", ".pdf", ".json", ".csv"),
        )

    def _audit_files(engagement_id: int) -> list[Path]:
        return _engagement_prefixed_artifact_files(
            prefix="audit",
            engagement_id=engagement_id,
            suffixes=(".md", ".pdf", ".json", ".csv"),
        )

    def _artifact_payload(engagement_ref: str, artifact: Path, kind: str) -> dict[str, Any]:
        stat = artifact.stat()
        return {
            "name": artifact.name,
            "kind": kind,
            "href": f"/api/engagements/{quote(engagement_ref, safe='')}/artifacts/{quote(artifact.name, safe='')}",
            "path": artifact.as_posix(),
            "size_bytes": int(stat.st_size),
            "size_label": _format_size(int(stat.st_size)),
            "modified_at": _format_dt(time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(stat.st_mtime))),
        }

    def _report_preview_payload(artifact: Path) -> dict[str, str]:
        try:
            preview = artifact.read_text(encoding="utf-8", errors="replace")[:7000]
        except Exception:  # noqa: BLE001
            preview = "(unreadable)"
        return {
            "name": artifact.name,
            "href": artifact.as_posix(),
            "preview": preview,
        }

    def _latest_audit(con: sqlite3.Connection, engagement_id: int) -> str:
        try:
            row = con.execute(
                """
                SELECT logged_at
                FROM audit_log
                WHERE engagement_id=?
                ORDER BY id DESC
                LIMIT 1
                """,
                (engagement_id,),
            ).fetchone()
        except sqlite3.OperationalError:
            row = None
        if row is None:
            return ""
        return _format_dt(str(row[0] or ""))

    def _engagement_summary_payload(
        db_file: Path,
        con: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> dict[str, Any]:
        engagement_id = int(row["id"])
        scope = _safe_json_loads(str(row["scope_json"] or "[]"))
        scope_list = scope if isinstance(scope, list) else []
        seeds = _seed_list(con, engagement_id, scope_list)
        primary_seed = seeds[0] if seeds else ""
        slug_source = str(row["name"] or primary_seed or f"engagement-{engagement_id}")
        slug = f"engagement-{engagement_id}-{_slugify(slug_source)}"
        report_files = _report_files(engagement_id)
        audit_files = _materialize_audit_manifest_artifacts(
            con,
            db_path=db_file,
            reports_dir=_reports_dir(),
            engagement_id=engagement_id,
            verify=False,
        )
        graph_files = _graph_files(str(engagement_id), _reports_dir())
        severity_summary = _severity_summary(con, engagement_id)
        graph_summary, _graph_payload, _graph_snapshot_at = _graph_state_for_engagement(
            con,
            engagement_id,
            graph_files,
        )
        tags = _engagement_tags(con, engagement_id)
        run_summary = _annotate_audit_manifest_bundle(
            _latest_engagement_run(
                con,
                engagement_id,
                db_path=db_file,
            ),
            [_artifact_payload(slug, path, "audit") for path in audit_files],
        )
        return {
            "db": db_file.name,
            "id": engagement_id,
            "slug": slug,
            "name": str(row["name"] or f"Engagement {engagement_id}"),
            "status": str(row["status"] or ""),
            "operator": str(row["operator"] or ""),
            "tags": tags,
            "created_at": _format_dt(str(row["created_at"] or "")),
            "updated_at": _format_dt(str(row["updated_at"] or "")),
            "latest_audit": _latest_audit(con, engagement_id),
            "primary_seed": primary_seed,
            "seeds": seeds,
            "counts": _summary_counts(con, engagement_id),
            "severity_summary": severity_summary,
            "highest_severity": _highest_severity(severity_summary),
            "graph_summary": graph_summary,
            "run_summary": run_summary,
            "seed_graph_summary": _seed_graph_summary(con, engagement_id),
            "report_count": len(report_files),
            "audit_count": len(audit_files),
            "graph_count": len(graph_files),
            "detail_route": f"/engagements/{slug}",
            "detail_api": f"/api/engagements/{slug}",
        }

    def _engagement_detail_payload(
        db_file: Path,
        con: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> dict[str, Any]:
        summary = _engagement_summary_payload(db_file, con, row)
        engagement_id = int(row["id"])
        report_files = _report_files(engagement_id)
        audit_files = _materialize_audit_manifest_artifacts(
            con,
            db_path=db_file,
            reports_dir=_reports_dir(),
            engagement_id=engagement_id,
            verify=True,
        )
        graph_files = _graph_files(str(engagement_id), _reports_dir())
        artifacts = [_artifact_payload(summary["slug"], path, "report") for path in report_files] + [
            _artifact_payload(summary["slug"], path, "graph") for path in graph_files
        ] + [
            _artifact_payload(summary["slug"], path, "audit") for path in audit_files
        ]
        report_history = _report_history_payload(report_files)
        preview_files = [
            path for path in _latest_report_family_files(report_files) if path.suffix.lower() == ".md"
        ]
        scope = _safe_json_loads(str(row["scope_json"] or "[]"))
        scope_list = scope if isinstance(scope, list) else []
        payload = {
            **summary,
            "path": db_file.as_posix(),
            "size_bytes": int(db_file.stat().st_size),
            "size_label": _format_size(int(db_file.stat().st_size)),
            "scope": scope_list,
            "run_summary": _annotate_audit_manifest_bundle(
                _latest_engagement_run(con, engagement_id, db_path=db_file),
                [artifact for artifact in artifacts if artifact["kind"] == "audit"],
            ),
            "sections": _detail_sections(con, engagement_id, db_path=db_file),
            "artifacts": artifacts,
            "report_previews": [_report_preview_payload(path) for path in preview_files],
            "report_count": len(report_files),
            "audit_count": len(audit_files),
            "graph_count": len(graph_files),
        }
        report_summary = _report_summary_payload(report_files)
        if report_summary is not None:
            payload["report_summary"] = report_summary
        if report_history:
            payload["report_history"] = report_history
        _graph_summary, graph_payload, graph_snapshot_at = _graph_state_for_engagement(
            con,
            engagement_id,
            graph_files,
        )
        if graph_payload is not None:
            payload["graph_payload"] = graph_payload
        if graph_snapshot_at:
            payload["graph_snapshot_at"] = graph_snapshot_at
        return payload

    def _iter_engagement_payloads() -> list[dict[str, Any]]:
        if not (cfg.data_dir / "engagements").exists():
            return []
        items: list[dict[str, Any]] = []
        for db_file in _numeric_engagement_db_files():
            con = sqlite3.connect(db_file)
            con.row_factory = sqlite3.Row
            try:
                rows = con.execute(
                    """
                    SELECT id, name, scope_json, status, operator, created_at, updated_at
                    FROM engagements
                    ORDER BY id
                    """
                ).fetchall()
                for row in rows:
                    items.append(_engagement_summary_payload(db_file, con, row))
            finally:
                con.close()
        items.sort(key=lambda item: (item["updated_at"], item["id"]), reverse=True)
        return items

    def _find_engagement_detail(engagement_ref: str) -> dict[str, Any] | None:
        if not (cfg.data_dir / "engagements").exists():
            return None
        ref = engagement_ref.strip().lower()
        for db_file in _numeric_engagement_db_files():
            con = sqlite3.connect(db_file)
            con.row_factory = sqlite3.Row
            try:
                rows = con.execute(
                    """
                    SELECT id, name, scope_json, status, operator, created_at, updated_at
                    FROM engagements
                    ORDER BY id
                    """
                ).fetchall()
                for row in rows:
                    summary = _engagement_summary_payload(db_file, con, row)
                    if ref in {str(summary["id"]).lower(), str(summary["slug"]).lower()}:
                        return _engagement_detail_payload(db_file, con, row)
            finally:
                con.close()
        return None

    def _find_engagement_artifact(engagement_ref: str, artifact_name: str) -> Path | None:
        if not (cfg.data_dir / "engagements").exists():
            return None
        ref = engagement_ref.strip().lower()
        requested_name = Path(artifact_name).name
        for db_file in _numeric_engagement_db_files():
            con = sqlite3.connect(db_file)
            con.row_factory = sqlite3.Row
            try:
                rows = con.execute(
                    """
                    SELECT id, name, scope_json, status, operator, created_at, updated_at
                    FROM engagements
                    ORDER BY id
                    """
                ).fetchall()
                for row in rows:
                    summary = _engagement_summary_payload(db_file, con, row)
                    if ref not in {str(summary["id"]).lower(), str(summary["slug"]).lower()}:
                        continue
                    engagement_id = int(summary["id"])
                    audit_files = _materialize_audit_manifest_artifacts(
                        con,
                        db_path=db_file,
                        reports_dir=_reports_dir(),
                        engagement_id=engagement_id,
                        verify=True,
                    )
                    files = _report_files(engagement_id) + audit_files + _graph_files(
                        str(summary["id"]),
                        _reports_dir(),
                    )
                    for path in files:
                        if path.is_file() and path.name == requested_name:
                            return path
                    return None
            finally:
                con.close()
        return None

    def _resolve_engagement_db(engagement_ref: str) -> tuple[Path, int] | None:
        if not (cfg.data_dir / "engagements").exists():
            return None
        ref = engagement_ref.strip().lower()
        for db_file in _numeric_engagement_db_files():
            con = sqlite3.connect(db_file)
            con.row_factory = sqlite3.Row
            try:
                rows = con.execute(
                    """
                    SELECT id, name, scope_json, status, operator, created_at, updated_at
                    FROM engagements
                    ORDER BY id
                    """
                ).fetchall()
                for row in rows:
                    summary = _engagement_summary_payload(db_file, con, row)
                    if ref in {str(summary["id"]).lower(), str(summary["slug"]).lower()}:
                        return db_file, int(summary["id"])
            finally:
                con.close()
        return None

    @app.get("/api/token")
    def get_token(operator: str, bootstrap_token: str | None = None) -> dict[str, str]:
        if not operator.strip():
            raise HTTPException(status_code=400, detail="operator is required.")
        if bootstrap_token is None or not bootstrap_token.strip():
            raise HTTPException(status_code=401, detail="Missing bootstrap credential.")
        if bootstrap_token != _bootstrap_secret():
            raise HTTPException(status_code=401, detail="Invalid bootstrap credential.")
        return {"token": mint_token(operator)}

    @app.get("/api/automation/suggestions")
    def get_automation_suggestions(
        engagement_id: int,
        _subject: str = Depends(_auth_subject),
    ) -> dict[str, Any]:
        engine = AutomationEngine(engagement_id)
        suggestions = engine.get_suggestions()
        return {"items": [s.__dict__ for s in suggestions]}

    @app.post("/api/automation/execute")
    async def execute_suggestion(
        body: dict[str, Any],
        _subject: str = Depends(_auth_subject),
    ) -> dict[str, str]:
        engagement_id = body.get("engagement_id")
        action = str(body.get("action") or "").strip()
        params = body.get("params", {})

        if not engagement_id or not action:
            raise HTTPException(status_code=400, detail="engagement_id and action are required.")
        if not isinstance(params, dict):
            raise HTTPException(status_code=400, detail="params must be an object.")

        task_type = EXECUTABLE_AUTOMATION_ACTIONS.get(action)
        if task_type is None:
            raise HTTPException(status_code=400, detail="Unsupported automation action.")

        target = str(params.get("target") or "").strip()
        if not target:
            raise HTTPException(status_code=400, detail="target is required for automation action.")

        # Re-use existing enqueue logic for admitted passive/recon suggestions.
        scheduler = TaskScheduler(
            db_path=cfg.engagement_db_path(str(engagement_id)),
            queue=coordinator,
            event_publisher=_publish_progress_sync,
        )

        task_key = f"{task_type}:{target}"

        scheduler.schedule(
            ScheduledTask(
                engagement_id=engagement_id,
                task_key=task_key,
                payload={"task_type": task_type, **params},
            )
        )

        return {"status": "queued", "task_key": task_key}

    @app.post("/api/automation/playbook")
    async def run_playbook(
        body: dict[str, Any],
        _subject: str = Depends(_auth_subject),
    ) -> dict[str, str]:
        engagement_id = body.get("engagement_id")
        playbook = body.get("playbook")
        target = body.get("target")

        if not engagement_id or not playbook or not target:
            raise HTTPException(
                status_code=400, detail="engagement_id, playbook, and target are required."
            )

        scheduler = TaskScheduler(
            db_path=cfg.engagement_db_path(str(engagement_id)),
            queue=coordinator,
            event_publisher=_publish_progress_sync,
        )
        engine = PlaybookEngine(scheduler)

        if playbook == "recon_full":
            engine.run_recon_full(engagement_id, target)
        elif playbook == "vuln_discovery":
            engine.run_vuln_discovery(engagement_id, target)
        else:
            raise HTTPException(status_code=400, detail=f"Unknown playbook: {playbook}")

        return {"status": "playbook_started"}

    @app.get("/")
    def dashboard() -> Any:
        return _frontend_entry_response()

    @app.get("/engagements/{engagement_path:path}")
    def engagement_spa_route(engagement_path: str) -> Any:
        return _frontend_entry_response()

    @app.get("/command-center")
    def legacy_command_center() -> Any:
        return FileResponse(legacy_template_path)

    @app.get("/favicon.svg")
    def frontend_favicon() -> Any:
        candidate = frontend_dist_dir / "favicon.svg"
        if not candidate.is_file():
            raise HTTPException(status_code=404, detail="favicon not found.")
        return FileResponse(candidate)

    @app.get("/icons.svg")
    def frontend_icons() -> Any:
        candidate = frontend_dist_dir / "icons.svg"
        if not candidate.is_file():
            raise HTTPException(status_code=404, detail="icons not found.")
        return FileResponse(candidate)

    @app.get("/data/{resource_path:path}")
    def generated_dashboard_data(resource_path: str) -> Any:
        candidate = (generated_dashboard_data_dir / resource_path).resolve()
        data_root = generated_dashboard_data_dir.resolve()
        if not candidate.is_file() or data_root not in candidate.parents:
            raise HTTPException(status_code=404, detail="data asset not found.")
        return FileResponse(candidate)

    @app.get("/api/engagements")
    def list_engagements(_subject: str = Depends(_auth_subject)) -> dict[str, Any]:
        return {
            "generated_at": _format_dt(time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime())),
            "items": _iter_engagement_payloads(),
        }

    @app.post("/api/engagements")
    def create_engagement(
        body: dict[str, Any],
        subject: str = Depends(_auth_subject),
    ) -> dict[str, Any]:
        from forge.db.migrations import run_migrations  # noqa: PLC0415
        from forge.db.schema import apply_schema  # noqa: PLC0415

        name_raw = body.get("name")
        operator_raw = body.get("operator")
        status_raw = str(body.get("status") or "ACTIVE").strip().upper()
        seeds_raw = body.get("seeds")
        if not isinstance(name_raw, str) or not name_raw.strip():
            raise HTTPException(status_code=400, detail="name is required.")
        if status_raw not in _VALID_ENGAGEMENT_STATUSES:
            raise HTTPException(status_code=400, detail=f"Invalid engagement status: {status_raw}")
        if not isinstance(seeds_raw, list) or not seeds_raw:
            raise HTTPException(status_code=400, detail="seeds must be a non-empty list.")
        metadata_raw = body.get("metadata") if isinstance(body.get("metadata"), dict) else {}
        tags = _normalize_engagement_tags(
            body.get("tags") if "tags" in body else metadata_raw.get("tags")
        )
        engagement_metadata = dict(metadata_raw)
        if tags:
            engagement_metadata["tags"] = tags
        else:
            engagement_metadata.pop("tags", None)

        parsed_seeds: list[dict[str, Any]] = []
        seen_seed_keys: set[tuple[str, str]] = set()
        for item in seeds_raw:
            if isinstance(item, str):
                seed_value = item.strip()
                seed_type = _classify_seed_value(seed_value)
                source = "operator"
            elif isinstance(item, dict):
                seed_value = str(item.get("seed_value") or item.get("value") or "").strip()
                seed_type = str(item.get("seed_type") or _classify_seed_value(seed_value)).strip().lower()
                source = _normalize_seed_source(str(item.get("source") or "operator"))
            else:
                raise HTTPException(status_code=400, detail="Each seed must be a string or object.")
            if not seed_value:
                raise HTTPException(status_code=400, detail="Seed values must not be empty.")
            seed_value = _canonical_seed_value(seed_value, seed_type)
            seed_key = (seed_type, seed_value)
            if seed_key in seen_seed_keys:
                continue
            seen_seed_keys.add(seed_key)
            parsed_seeds.append(
                {
                    "seed_value": seed_value,
                    "seed_type": seed_type,
                    "source": source,
                }
            )

        engagement_id = _allocate_engagement_id()
        db_path = cfg.engagement_db_path(str(engagement_id))
        con = sqlite3.connect(db_path)
        con.row_factory = sqlite3.Row
        try:
            apply_schema(con)
            run_migrations(con)
            scope_entries: list[str] = []
            for seed in parsed_seeds:
                for entry in _scope_entries_for_seed(seed["seed_value"], seed["seed_type"]):
                    if entry not in scope_entries:
                        scope_entries.append(entry)
            con.execute(
                """
                INSERT INTO engagements (id, name, scope_json, status, operator, metadata_json)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    engagement_id,
                    name_raw.strip(),
                    json.dumps(scope_entries),
                    status_raw,
                    str(operator_raw or subject or cfg.operator),
                    json.dumps(engagement_metadata, sort_keys=True),
                ),
            )
            for seed in parsed_seeds:
                _upsert_engagement_seed(
                    con,
                    engagement_id,
                    seed["seed_value"],
                    seed_type=seed["seed_type"],
                    source=seed["source"],
                )
            con.commit()
            row = con.execute(
                """
                SELECT id, name, scope_json, status, operator, created_at, updated_at
                FROM engagements
                WHERE id=?
                """,
                (engagement_id,),
            ).fetchone()
            if row is None:
                raise HTTPException(status_code=500, detail="Engagement creation failed.")
            return _engagement_detail_payload(db_path, con, row)
        finally:
            con.close()

    @app.get("/api/engagements/{engagement_ref}")
    def get_engagement_detail(
        engagement_ref: str, _subject: str = Depends(_auth_subject)
    ) -> dict[str, Any]:
        payload = _find_engagement_detail(engagement_ref)
        if payload is None:
            raise HTTPException(status_code=404, detail="Engagement not found.")
        return payload

    @app.patch("/api/engagements/{engagement_ref}")
    def update_engagement(
        engagement_ref: str,
        body: dict[str, Any],
        _subject: str = Depends(_auth_subject),
    ) -> dict[str, Any]:
        resolved = _resolve_engagement_db(engagement_ref)
        if resolved is None:
            raise HTTPException(status_code=404, detail="Engagement not found.")
        db_path, engagement_id = resolved
        con = sqlite3.connect(db_path)
        con.row_factory = sqlite3.Row
        try:
            _ensure_engagement_metadata_column(con)
            row = con.execute(
                """
                SELECT id, name, scope_json, status, operator, created_at, updated_at
                FROM engagements
                WHERE id=?
                """,
                (engagement_id,),
            ).fetchone()
            if row is None:
                raise HTTPException(status_code=404, detail="Engagement not found.")
            name = str(body.get("name") or row["name"] or "").strip()
            status = str(body.get("status") or row["status"] or "").strip().upper()
            operator = str(body.get("operator") or row["operator"] or "").strip()
            existing_metadata = _engagement_metadata(con, engagement_id)
            next_metadata = dict(existing_metadata)
            if isinstance(body.get("metadata"), dict):
                next_metadata.update(body["metadata"])
            normalized_tags = _normalize_engagement_tags(
                body.get("tags") if "tags" in body else next_metadata.get("tags")
            )
            if normalized_tags:
                next_metadata["tags"] = normalized_tags
            else:
                next_metadata.pop("tags", None)
            if not name:
                raise HTTPException(status_code=400, detail="name must not be empty.")
            if status not in _VALID_ENGAGEMENT_STATUSES:
                raise HTTPException(status_code=400, detail=f"Invalid engagement status: {status}")
            con.execute(
                """
                UPDATE engagements
                SET name=?,
                    status=?,
                    operator=?,
                    metadata_json=?,
                    updated_at=CURRENT_TIMESTAMP
                WHERE id=?
                """,
                (
                    name,
                    status,
                    operator,
                    json.dumps(next_metadata, sort_keys=True),
                    engagement_id,
                ),
            )
            con.commit()
            refreshed = con.execute(
                """
                SELECT id, name, scope_json, status, operator, created_at, updated_at
                FROM engagements
                WHERE id=?
                """,
                (engagement_id,),
            ).fetchone()
            if refreshed is None:
                raise HTTPException(status_code=500, detail="Engagement update failed.")
            return _engagement_detail_payload(db_path, con, refreshed)
        finally:
            con.close()

    @app.get("/api/engagements/{engagement_ref}/seeds")
    def list_engagement_seeds(
        engagement_ref: str,
        _subject: str = Depends(_auth_subject),
    ) -> dict[str, list[dict[str, Any]]]:
        resolved = _resolve_engagement_db(engagement_ref)
        if resolved is None:
            raise HTTPException(status_code=404, detail="Engagement not found.")
        db_path, engagement_id = resolved
        con = sqlite3.connect(db_path)
        con.row_factory = sqlite3.Row
        try:
            return {"items": _engagement_seed_rows(con, engagement_id)}
        finally:
            con.close()

    @app.post("/api/engagements/{engagement_ref}/seeds")
    def create_engagement_seed(
        engagement_ref: str,
        body: dict[str, Any],
        subject: str = Depends(_auth_subject),
    ) -> dict[str, Any]:
        resolved = _resolve_engagement_db(engagement_ref)
        if resolved is None:
            raise HTTPException(status_code=404, detail="Engagement not found.")
        db_path, engagement_id = resolved
        seed_value = str(body.get("seed_value") or body.get("value") or "").strip()
        seed_type = str(body.get("seed_type") or "").strip().lower() or None
        source = _normalize_seed_source(str(body.get("source") or "operator"))
        status = str(body.get("status") or "pending").strip().lower()
        metadata = body.get("metadata") if isinstance(body.get("metadata"), dict) else {}
        depth = int(body.get("depth") or 0)
        confidence = float(body.get("confidence") or 1.0)
        if not seed_value:
            raise HTTPException(status_code=400, detail="seed_value is required.")

        con = sqlite3.connect(db_path)
        con.row_factory = sqlite3.Row
        try:
            try:
                seed_id = _upsert_engagement_seed(
                    con,
                    engagement_id,
                    seed_value,
                    seed_type=seed_type,
                    source=source,
                    status=status,
                    depth=depth,
                    confidence=confidence,
                    metadata=metadata,
                )
            except sqlite3.IntegrityError as exc:
                raise HTTPException(status_code=409, detail=str(exc)) from exc
            resolved_type = seed_type or _classify_seed_value(seed_value)
            seed_value = _canonical_seed_value(seed_value, resolved_type)
            _update_scope_json(
                con,
                engagement_id,
                add_entries=_scope_entries_for_seed(seed_value, resolved_type),
            )
            con.commit()
            items = _engagement_seed_rows(con, engagement_id)
            seed_item = next((item for item in items if item["id"] == seed_id), None)
            return {"status": "upserted", "seed": seed_item, "items": items}
        finally:
            con.close()

    @app.patch("/api/engagements/{engagement_ref}/seeds/{seed_id}")
    def update_engagement_seed(
        engagement_ref: str,
        seed_id: int,
        body: dict[str, Any],
        _subject: str = Depends(_auth_subject),
    ) -> dict[str, Any]:
        resolved = _resolve_engagement_db(engagement_ref)
        if resolved is None:
            raise HTTPException(status_code=404, detail="Engagement not found.")
        db_path, engagement_id = resolved
        con = sqlite3.connect(db_path)
        con.row_factory = sqlite3.Row
        try:
            row = con.execute(
                """
                SELECT id, seed_value, seed_type, source, status, depth, confidence, metadata_json
                FROM engagement_seeds
                WHERE engagement_id=? AND id=?
                """,
                (engagement_id, seed_id),
            ).fetchone()
            if row is None:
                raise HTTPException(status_code=404, detail="Seed not found.")
            old_value = str(row["seed_value"] or "")
            old_type = str(row["seed_type"] or "")
            updated_value = str(body.get("seed_value") or body.get("value") or old_value).strip()
            updated_type = str(body.get("seed_type") or old_type).strip().lower() or _classify_seed_value(updated_value)
            updated_value = _canonical_seed_value(updated_value, updated_type)
            updated_source = _normalize_seed_source(str(body.get("source") or row["source"] or "operator"))
            updated_status = str(body.get("status") or row["status"] or "").strip().lower()
            updated_depth = int(body.get("depth") if "depth" in body else row["depth"] or 0)
            updated_confidence = float(body.get("confidence") if "confidence" in body else row["confidence"] or 0.0)
            existing_metadata = _safe_json_loads(str(row["metadata_json"] or "{}"))
            metadata = body.get("metadata") if isinstance(body.get("metadata"), dict) else existing_metadata
            if updated_status not in _VALID_SEED_STATUSES:
                raise HTTPException(status_code=400, detail=f"Invalid seed status: {updated_status}")
            if not updated_value:
                raise HTTPException(status_code=400, detail="seed_value must not be empty.")
            try:
                con.execute(
                    """
                    UPDATE engagement_seeds
                    SET seed_value=?,
                        seed_type=?,
                        source=?,
                        status=?,
                        depth=?,
                        confidence=?,
                        metadata_json=?,
                        updated_at=CURRENT_TIMESTAMP
                    WHERE engagement_id=? AND id=?
                    """,
                    (
                        updated_value,
                        updated_type,
                        updated_source,
                        updated_status,
                        max(0, updated_depth),
                        updated_confidence,
                        json.dumps(metadata or {}, sort_keys=True),
                        engagement_id,
                        seed_id,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise HTTPException(status_code=409, detail=str(exc)) from exc
            _update_scope_json(
                con,
                engagement_id,
                add_entries=_scope_entries_for_seed(updated_value, updated_type),
                remove_entries=_scope_entries_for_seed(old_value, old_type),
            )
            con.commit()
            items = _engagement_seed_rows(con, engagement_id)
            seed_item = next((item for item in items if item["id"] == seed_id), None)
            return {"status": "updated", "seed": seed_item, "items": items}
        finally:
            con.close()

    @app.delete("/api/engagements/{engagement_ref}/seeds/{seed_id}")
    def delete_engagement_seed(
        engagement_ref: str,
        seed_id: int,
        _subject: str = Depends(_auth_subject),
    ) -> dict[str, Any]:
        resolved = _resolve_engagement_db(engagement_ref)
        if resolved is None:
            raise HTTPException(status_code=404, detail="Engagement not found.")
        db_path, engagement_id = resolved
        con = sqlite3.connect(db_path)
        con.row_factory = sqlite3.Row
        try:
            row = con.execute(
                """
                SELECT seed_value, seed_type
                FROM engagement_seeds
                WHERE engagement_id=? AND id=?
                """,
                (engagement_id, seed_id),
            ).fetchone()
            if row is None:
                raise HTTPException(status_code=404, detail="Seed not found.")
            seed_value = str(row["seed_value"] or "")
            seed_type = str(row["seed_type"] or "")
            con.execute("DELETE FROM seed_runs WHERE engagement_id=? AND seed_id=?", (engagement_id, seed_id))
            con.execute(
                "DELETE FROM seed_relations WHERE engagement_id=? AND (source_seed_id=? OR target_seed_id=?)",
                (engagement_id, seed_id, seed_id),
            )
            con.execute(
                "DELETE FROM engagement_seeds WHERE engagement_id=? AND id=?",
                (engagement_id, seed_id),
            )
            _update_scope_json(
                con,
                engagement_id,
                remove_entries=_scope_entries_for_seed(seed_value, seed_type),
            )
            con.commit()
            return {"status": "deleted", "seed_id": seed_id, "items": _engagement_seed_rows(con, engagement_id)}
        finally:
            con.close()

    @app.post("/api/engagements/{engagement_ref}/runs/kill-chain")
    def launch_engagement_kill_chain(
        engagement_ref: str,
        body: dict[str, Any] | None = None,
        subject: str = Depends(_auth_subject),
    ) -> dict[str, Any]:
        return _launch_engagement_run_process(
            engagement_ref,
            body,
            subject=subject,
            force_resume=None,
            launch_status="started",
        )

    @app.post("/api/engagements/{engagement_ref}/runs/resume")
    def resume_engagement_kill_chain(
        engagement_ref: str,
        body: dict[str, Any] | None = None,
        subject: str = Depends(_auth_subject),
    ) -> dict[str, Any]:
        return _launch_engagement_run_process(
            engagement_ref,
            body,
            subject=subject,
            force_resume=True,
            launch_status="resumed",
        )

    @app.post("/api/engagements/{engagement_ref}/runs/restart")
    def restart_engagement_kill_chain(
        engagement_ref: str,
        body: dict[str, Any] | None = None,
        subject: str = Depends(_auth_subject),
    ) -> dict[str, Any]:
        return _launch_engagement_run_process(
            engagement_ref,
            body,
            subject=subject,
            force_resume=False,
            launch_status="restarted",
        )

    @app.post("/api/engagements/{engagement_ref}/runs/rerun")
    def rerun_engagement_kill_chain(
        engagement_ref: str,
        body: dict[str, Any] | None = None,
        subject: str = Depends(_auth_subject),
    ) -> dict[str, Any]:
        return _launch_engagement_run_process(
            engagement_ref,
            body,
            subject=subject,
            force_resume=False,
            launch_status="restarted",
        )

    def _launch_engagement_run_process(
        engagement_ref: str,
        body: dict[str, Any] | None,
        *,
        subject: str,
        force_resume: bool | None,
        launch_status: str,
    ) -> dict[str, Any]:
        resolved = _resolve_engagement_db(engagement_ref)
        if resolved is None:
            raise HTTPException(status_code=404, detail="Engagement not found.")
        db_path, engagement_id = resolved
        con = sqlite3.connect(db_path)
        con.row_factory = sqlite3.Row
        try:
            active_run = _latest_running_engagement_run(con, engagement_id)
            if active_run is not None:
                raise HTTPException(status_code=409, detail="An engagement run is already active.")
            seeds = _ordered_launch_seeds(con, engagement_id)
        finally:
            con.close()
        if not seeds:
            raise HTTPException(status_code=400, detail="Engagement has no launchable seeds.")

        options = body or {}
        resume = bool(options.get("resume", True)) if force_resume is None else force_resume
        dry_run = bool(options.get("dry_run", False))
        attack_mode = bool(options.get("attack_mode", False))
        auto_run_detected = bool(options.get("auto_run_detected", False))
        roe_id = " ".join(str(options.get("roe_id") or os.environ.get("FORGE_ROE_ID", "")).strip().split())[:160]
        scope_manifest = str(options.get("scope_manifest") or os.environ.get("FORGE_SCOPE_MANIFEST", "")).strip()
        require_scope_manifest = str(os.environ.get("FORGE_REQUIRE_SCOPE_MANIFEST", "")).strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }
        skip_cloud = bool(options.get("skip_cloud", False))
        skip_keyscan = bool(options.get("skip_keyscan", False))
        try:
            max_iter = normalize_kill_chain_max_iter(options.get("max_iter"), default=3)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        report_provider = str(options.get("report_provider") or "").strip().lower() or None
        report_max_loops_raw = options.get("report_max_loops")
        if report_max_loops_raw in (None, ""):
            report_max_loops = None
        else:
            try:
                report_max_loops = int(report_max_loops_raw)
            except (TypeError, ValueError) as exc:
                raise HTTPException(status_code=400, detail="report_max_loops must be an integer.") from exc
        if report_provider is not None and report_provider not in _VALID_REPORT_PROVIDERS:
            raise HTTPException(status_code=400, detail=f"Invalid report provider: {report_provider}")
        if report_max_loops is not None and (report_max_loops < 0 or report_max_loops > 10):
            raise HTTPException(status_code=400, detail="report_max_loops must be between 0 and 10.")
        if not dry_run and not roe_id and (attack_mode or auto_run_detected):
            raise HTTPException(
                status_code=400,
                detail=(
                    "Live attack_mode or auto_run_detected requires roe_id or FORGE_ROE_ID. "
                    "Use dry_run to preview without live execution."
                ),
            )
        if not dry_run and (attack_mode or auto_run_detected) and not scope_manifest:
            raise HTTPException(
                status_code=400,
                detail=(
                    "Live attack_mode or auto_run_detected requires scope_manifest or "
                    "FORGE_SCOPE_MANIFEST so execution is bounded to explicit authorization. "
                    "Use dry_run to preview without live execution."
                ),
            )
        if not dry_run and require_scope_manifest and not scope_manifest:
            raise HTTPException(
                status_code=400,
                detail=(
                    "FORGE_REQUIRE_SCOPE_MANIFEST=1 requires scope_manifest or "
                    "FORGE_SCOPE_MANIFEST for non-dry-run kill-chain launches. "
                    "Use dry_run to preview without live execution."
                ),
            )

        primary_seed = seeds[0]["seed_value"]
        related_seeds = [item["seed_value"] for item in seeds[1:]]
        command = [
            sys.executable,
            "-m",
            "forge.cli",
            "--no-tor",
            "kill-chain",
            primary_seed,
            "--engagement",
            str(engagement_id),
            "--max-iter",
            str(max_iter),
        ]
        if not resume:
            command.append("--no-resume")
        if dry_run:
            command.append("--dry-run")
        if attack_mode:
            command.append("--attack-mode")
        if auto_run_detected:
            command.append("--auto-run-detected")
        if roe_id:
            command.extend(["--roe-id", roe_id])
        if scope_manifest:
            command.extend(["--scope-manifest", scope_manifest])
        if skip_cloud:
            command.append("--skip-cloud")
        if skip_keyscan:
            command.append("--skip-keyscan")
        if report_provider:
            command.extend(["--report-provider", report_provider])
        if report_max_loops is not None:
            command.extend(["--report-max-loops", str(report_max_loops)])
        for seed_value in related_seeds:
            command.extend(["--related-seed", seed_value])

        _clear_run_control_markers(engagement_id)
        logs_dir = _logs_dir()
        log_path = logs_dir / f"engagement_{engagement_id}_kill_chain_{int(time.time())}.log"
        log_handle = log_path.open("w", encoding="utf-8")
        try:
            process = subprocess.Popen(  # noqa: S603
                command,
                cwd=str(Path.cwd()),
                stdout=log_handle,
                stderr=subprocess.STDOUT,
                text=True,
                env=os.environ.copy(),
            )
        except Exception:
            log_handle.close()
            raise
        log_handle.close()

        payload = {
            "status": launch_status,
            "engagement_id": engagement_id,
            "operator": subject,
            "pid": int(process.pid),
            "seed_count": len(seeds),
            "primary_seed": primary_seed,
            "related_seeds": related_seeds,
            "command_preview": " ".join(command),
            "log_path": log_path.as_posix(),
            "resume_enabled": resume,
            "dry_run": dry_run,
            "attack_mode": attack_mode,
            "auto_run_detected": auto_run_detected,
            "roe_id": roe_id,
            "scope_manifest": scope_manifest,
            "skip_cloud": skip_cloud,
            "skip_keyscan": skip_keyscan,
            "max_iter": max_iter,
            "report_provider": report_provider or "default",
            "report_max_loops": report_max_loops,
        }
        _publish_progress_sync(
            engagement_id,
            f"engagement_run_{launch_status}",
            {
                "operator": subject,
                "pid": int(process.pid),
                "seed_count": len(seeds),
                "primary_seed": primary_seed,
                "related_seeds": related_seeds,
                "log_path": log_path.as_posix(),
                "resume_enabled": resume,
                "dry_run": dry_run,
                "attack_mode": attack_mode,
                "auto_run_detected": auto_run_detected,
                "roe_id": roe_id,
                "scope_manifest": scope_manifest,
                "skip_cloud": skip_cloud,
                "skip_keyscan": skip_keyscan,
                "max_iter": max_iter,
                "report_provider": report_provider or "default",
                "report_max_loops": report_max_loops,
                "command_preview": " ".join(command),
            },
        )
        return payload

    @app.get("/api/engagements/{engagement_ref}/runs")
    def list_engagement_runs(
        engagement_ref: str,
        verify_manifests: bool = True,
        _subject: str = Depends(_auth_subject),
    ) -> dict[str, list[dict[str, Any]]]:
        resolved = _resolve_engagement_db(engagement_ref)
        if resolved is None:
            raise HTTPException(status_code=404, detail="Engagement not found.")
        db_path, engagement_id = resolved
        con = sqlite3.connect(db_path)
        con.row_factory = sqlite3.Row
        try:
            return {
                "items": _engagement_run_rows(
                    con,
                    engagement_id,
                    db_path=db_path,
                    verify_manifests=verify_manifests,
                )
            }
        finally:
            con.close()

    @app.post("/api/engagements/{engagement_ref}/runs/stop")
    def stop_engagement_kill_chain(
        engagement_ref: str,
        body: dict[str, Any] | None = None,
        subject: str = Depends(_auth_subject),
    ) -> dict[str, Any]:
        return _request_engagement_run_control(
            engagement_ref,
            body,
            subject=subject,
            control_kind="stop",
        )

    @app.post("/api/engagements/{engagement_ref}/runs/pause")
    def pause_engagement_kill_chain(
        engagement_ref: str,
        body: dict[str, Any] | None = None,
        subject: str = Depends(_auth_subject),
    ) -> dict[str, Any]:
        return _request_engagement_run_control(
            engagement_ref,
            body,
            subject=subject,
            control_kind="pause",
        )

    def _request_engagement_run_control(
        engagement_ref: str,
        body: dict[str, Any] | None,
        *,
        subject: str,
        control_kind: str,
    ) -> dict[str, Any]:
        resolved = _resolve_engagement_db(engagement_ref)
        if resolved is None:
            raise HTTPException(status_code=404, detail="Engagement not found.")
        db_path, engagement_id = resolved
        if control_kind not in {"stop", "pause"}:
            raise HTTPException(status_code=500, detail="Unsupported control action.")
        default_reason = "operator requested pause" if control_kind == "pause" else "operator requested stop"
        marker_path = _pause_marker_path(engagement_id) if control_kind == "pause" else _stop_marker_path(engagement_id)
        reason = str((body or {}).get("reason") or default_reason).strip()
        marker_payload = {
            "requested_at": _format_dt(time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime())),
            "requested_by": subject,
            "reason": reason,
        }
        marker_path.write_text(json.dumps(marker_payload, sort_keys=True), encoding="utf-8")

        active_run_id: int | None = None
        con = sqlite3.connect(db_path)
        con.row_factory = sqlite3.Row
        try:
            row = _latest_running_engagement_run(con, engagement_id)
            if row is not None:
                active_run_id = int(row["id"])
                metadata = _safe_json_loads(str(row["metadata_json"] or "{}"))
                metadata_dict = metadata if isinstance(metadata, dict) else {}
                metadata_dict[f"{control_kind}_requested"] = True
                metadata_dict[f"{control_kind}_requested_at"] = marker_payload["requested_at"]
                metadata_dict[f"{control_kind}_requested_by"] = subject
                metadata_dict[f"{control_kind}_reason"] = reason
                con.execute(
                    """
                    UPDATE engagement_runs
                    SET metadata_json=?,
                        updated_at=CURRENT_TIMESTAMP
                    WHERE engagement_id=? AND id=?
                    """,
                    (json.dumps(metadata_dict, sort_keys=True), engagement_id, active_run_id),
                )
                con.commit()
        finally:
            con.close()
        payload = {
            "status": f"{control_kind}_requested",
            "engagement_id": engagement_id,
            "active_run_id": active_run_id,
            "requested_by": subject,
            "reason": reason,
            "marker_path": marker_path.as_posix(),
        }
        _publish_progress_sync(
            engagement_id,
            f"engagement_run_{control_kind}_requested",
            {
                "active_run_id": active_run_id,
                "requested_by": subject,
                "reason": reason,
                "marker_path": marker_path.as_posix(),
            },
        )
        return payload

    @app.get("/api/engagements/{engagement_ref}/logs")
    def list_engagement_logs(
        engagement_ref: str,
        _subject: str = Depends(_auth_subject),
    ) -> dict[str, list[dict[str, Any]]]:
        resolved = _resolve_engagement_db(engagement_ref)
        if resolved is None:
            raise HTTPException(status_code=404, detail="Engagement not found.")
        _db_path, engagement_id = resolved
        return {
            "items": [
                _log_payload(engagement_ref, log_path)
                for log_path in _engagement_log_files(engagement_id)
            ]
        }

    @app.get("/api/engagements/{engagement_ref}/logs/{log_name}")
    def download_engagement_log(
        engagement_ref: str,
        log_name: str,
        _subject: str = Depends(_auth_subject),
    ) -> Any:
        resolved = _resolve_engagement_db(engagement_ref)
        if resolved is None:
            raise HTTPException(status_code=404, detail="Engagement not found.")
        _db_path, engagement_id = resolved
        artifact = _resolve_log_file(engagement_id, log_name)
        if artifact is None:
            raise HTTPException(status_code=404, detail="Log not found.")
        return FileResponse(path=artifact, filename=artifact.name)

    @app.get("/api/engagements/{engagement_ref}/logs/{log_name}/tail")
    def tail_engagement_log(
        engagement_ref: str,
        log_name: str,
        lines: int = 120,
        _subject: str = Depends(_auth_subject),
    ) -> dict[str, Any]:
        resolved = _resolve_engagement_db(engagement_ref)
        if resolved is None:
            raise HTTPException(status_code=404, detail="Engagement not found.")
        _db_path, engagement_id = resolved
        artifact = _resolve_log_file(engagement_id, log_name)
        if artifact is None:
            raise HTTPException(status_code=404, detail="Log not found.")
        max_lines = min(max(lines, 1), 1000)
        return {
            "name": artifact.name,
            "tail": _tail_lines(artifact, max_lines),
            "requested_lines": max_lines,
        }

    @app.get("/api/engagements/{engagement_ref}/artifacts/{artifact_name}")
    def download_engagement_artifact(
        engagement_ref: str,
        artifact_name: str,
        _subject: str = Depends(_auth_subject),
    ) -> Any:
        artifact = _find_engagement_artifact(engagement_ref, artifact_name)
        if artifact is None:
            raise HTTPException(status_code=404, detail="Artifact not found.")
        return FileResponse(path=artifact, filename=artifact.name)

    @app.post("/api/scans/start")
    async def start_scan(
        engagement_id: int,
        task_key: str,
        _subject: str = Depends(_auth_subject),
    ) -> dict[str, str]:
        cfg = ForgeConfig.load()
        con = get_engagement_db(cfg.engagement_db_path(str(engagement_id)))
        try:
            con.execute(
                """
                INSERT INTO task_progress (engagement_id, task_key, status, started_at)
                VALUES (?, ?, 'running', CURRENT_TIMESTAMP)
                ON CONFLICT(engagement_id, task_key) DO UPDATE SET
                    status='running', started_at=CURRENT_TIMESTAMP, completed_at=NULL
                """,
                (engagement_id, task_key),
            )
            con.commit()
        finally:
            con.close()
        await broker.publish(
            ProgressEvent(
                engagement_id=engagement_id,
                message="scan_started",
                payload={"task_key": task_key},
            )
        )
        return {"status": "started"}

    @app.post("/api/tasks/enqueue")
    async def enqueue_task(
        body: dict[str, Any],
        _subject: str = Depends(_auth_subject),
    ) -> dict[str, str]:
        engagement_id_raw = body.get("engagement_id")
        task_type_raw = body.get("task_type")
        target_raw = body.get("target")
        if not isinstance(engagement_id_raw, int) or engagement_id_raw <= 0:
            raise HTTPException(status_code=400, detail="engagement_id must be a positive integer.")
        if not isinstance(task_type_raw, str) or not task_type_raw:
            raise HTTPException(status_code=400, detail="task_type is required.")
        task_type = task_type_raw.strip().lower()
        target = str(target_raw or "").strip()
        payload = {"task_type": task_type, "target": target}
        scheduler = TaskScheduler(
            db_path=cfg.engagement_db_path(str(engagement_id_raw)),
            queue=coordinator,
            event_publisher=_publish_progress_sync,
        )
        task_key = f"{task_type}:{target or 'default'}"
        scheduler.schedule(
            ScheduledTask(
                engagement_id=engagement_id_raw,
                task_key=task_key,
                payload=payload,
            )
        )
        await broker.publish(
            ProgressEvent(
                engagement_id=engagement_id_raw,
                message="task_enqueued",
                payload={"task_key": task_key, "task_type": task_type},
            )
        )
        return {"status": "queued"}

    @app.get("/api/tasks")
    def list_tasks(
        engagement_id: int,
        _subject: str = Depends(_auth_subject),
    ) -> dict[str, list[dict[str, Any]]]:
        con = get_engagement_db(cfg.engagement_db_path(str(engagement_id)))
        try:
            rows = con.execute(
                """
                SELECT task_key, status, priority, worker_id, error, created_at, updated_at
                FROM distributed_tasks
                WHERE engagement_id=?
                ORDER BY created_at DESC
                """,
                (engagement_id,),
            ).fetchall()
        finally:
            con.close()
        return {
            "items": [
                {
                    "task_key": str(row[0]),
                    "status": str(row[1]),
                    "priority": int(row[2]),
                    "worker_id": str(row[3]) if row[3] is not None else None,
                    "error": str(row[4]) if row[4] is not None else None,
                    "created_at": str(row[5]),
                    "updated_at": str(row[6]),
                }
                for row in rows
            ]
        }

    @app.get("/api/workers")
    def list_workers(
        engagement_id: int,
        _subject: str = Depends(_auth_subject),
    ) -> dict[str, list[dict[str, Any]]]:
        con = get_engagement_db(cfg.engagement_db_path(str(engagement_id)))
        try:
            rows = con.execute(
                """
                SELECT
                    worker_id,
                    status,
                    last_task_key,
                    last_error,
                    tasks_completed,
                    tasks_failed,
                    heartbeat_at,
                    updated_at,
                    CASE WHEN heartbeat_at >= datetime('now', '-30 seconds') THEN 1 ELSE 0 END
                FROM worker_heartbeats
                WHERE engagement_id=?
                ORDER BY heartbeat_at DESC
                """,
                (engagement_id,),
            ).fetchall()
        finally:
            con.close()
        return {
            "items": [
                {
                    "worker_id": str(row[0]),
                    "status": str(row[1]),
                    "last_task_key": str(row[2]) if row[2] is not None else None,
                    "last_error": str(row[3]) if row[3] is not None else None,
                    "tasks_completed": int(row[4]),
                    "tasks_failed": int(row[5]),
                    "heartbeat_at": str(row[6]),
                    "updated_at": str(row[7]),
                    "online": bool(row[8]),
                }
                for row in rows
            ]
        }

    @app.get("/api/queue/metrics")
    def queue_metrics(
        engagement_id: int,
        limit: int = 50,
        _subject: str = Depends(_auth_subject),
    ) -> dict[str, Any]:
        max_rows = min(max(limit, 1), 500)
        con = get_engagement_db(cfg.engagement_db_path(str(engagement_id)))
        try:
            live_row = con.execute(
                """
                SELECT
                    COALESCE(SUM(CASE WHEN status='queued' THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN status='running' THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN status='done' THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN status='failed' THEN 1 ELSE 0 END), 0)
                FROM distributed_tasks
                WHERE engagement_id=?
                """,
                (engagement_id,),
            ).fetchone()
            history_rows = con.execute(
                """
                SELECT queued_count, running_count, done_count, failed_count, sampled_at
                FROM queue_metrics
                WHERE engagement_id=?
                ORDER BY sampled_at DESC
                LIMIT ?
                """,
                (engagement_id, max_rows),
            ).fetchall()
        finally:
            con.close()
        live = {
            "queued": int(live_row[0]) if live_row is not None else 0,
            "running": int(live_row[1]) if live_row is not None else 0,
            "done": int(live_row[2]) if live_row is not None else 0,
            "failed": int(live_row[3]) if live_row is not None else 0,
        }
        latest_snapshot = None
        if history_rows:
            first = history_rows[0]
            latest_snapshot = {
                "queued": int(first[0]),
                "running": int(first[1]),
                "done": int(first[2]),
                "failed": int(first[3]),
                "sampled_at": str(first[4]),
            }
        return {
            "live": live,
            "latest_snapshot": latest_snapshot,
            "history": [
                {
                    "queued": int(row[0]),
                    "running": int(row[1]),
                    "done": int(row[2]),
                    "failed": int(row[3]),
                    "sampled_at": str(row[4]),
                }
                for row in history_rows
            ],
        }

    @app.get("/api/scans/{engagement_id}/progress")
    def scan_progress(
        engagement_id: int, _subject: str = Depends(_auth_subject)
    ) -> dict[str, list[dict[str, Any]]]:
        cfg = ForgeConfig.load()
        con = get_engagement_db(cfg.engagement_db_path(str(engagement_id)))
        try:
            rows = con.execute(
                """
                SELECT task_key, status, started_at, completed_at
                FROM task_progress
                WHERE engagement_id=?
                ORDER BY started_at DESC
                """,
                (engagement_id,),
            ).fetchall()
        finally:
            con.close()
        return {
            "items": [
                {
                    "task_key": str(row[0]),
                    "status": str(row[1]),
                    "started_at": str(row[2]) if row[2] is not None else None,
                    "completed_at": str(row[3]) if row[3] is not None else None,
                }
                for row in rows
            ]
        }

    @app.get("/api/engagements/{engagement_id}/assets")
    def engagement_assets(
        engagement_id: int, _subject: str = Depends(_auth_subject)
    ) -> dict[str, Any]:
        con = get_engagement_db(cfg.engagement_db_path(str(engagement_id)))
        try:
            crawl_rows = con.execute(
                """
                SELECT final_url, title, screenshot_path, tech_stack_json, discovered_at
                FROM crawl_results
                WHERE engagement_id=?
                ORDER BY discovered_at DESC
                LIMIT 100
                """,
                (engagement_id,),
            ).fetchall()
            port_rows = con.execute(
                """
                SELECT host, port, service, version, confidence, cdn_detected, waf_detected, scanned_at
                FROM port_scan_results
                WHERE engagement_id=?
                ORDER BY scanned_at DESC
                LIMIT 200
                """,
                (engagement_id,),
            ).fetchall()
            passive_rows = con.execute(
                """
                SELECT vuln_id, plugin, url, severity, verified, false_positive, discovered_at
                FROM passive_vulns
                WHERE engagement_id=?
                  AND COALESCE(false_positive, 0)=0
                ORDER BY discovered_at DESC
                LIMIT 200
                """,
                (engagement_id,),
            ).fetchall()
            auth_rows = con.execute(
                """
                SELECT target_url, attack_type, success, tested_at
                FROM auth_test_results
                WHERE engagement_id=?
                ORDER BY tested_at DESC
                LIMIT 200
                """,
                (engagement_id,),
            ).fetchall()
        finally:
            con.close()
        return {
            "crawl": [
                {
                    "final_url": str(row[0]),
                    "title": str(row[1]) if row[1] is not None else "",
                    "screenshot_path": str(row[2]) if row[2] is not None else None,
                    "tech_stack_json": str(row[3]) if row[3] is not None else "{}",
                    "discovered_at": str(row[4]),
                }
                for row in crawl_rows
            ],
            "ports": [
                {
                    "host": str(row[0]),
                    "port": int(row[1]),
                    "service": str(row[2]) if row[2] is not None else "",
                    "version": str(row[3]) if row[3] is not None else None,
                    "confidence": float(row[4]) if row[4] is not None else None,
                    "cdn_detected": bool(row[5]),
                    "waf_detected": bool(row[6]),
                    "scanned_at": str(row[7]),
                }
                for row in port_rows
            ],
            "passive_vulns": [
                {
                    "vuln_id": str(row[0]),
                    "plugin": str(row[1]) if row[1] is not None else "",
                    "url": str(row[2]) if row[2] is not None else "",
                    "severity": str(row[3]) if row[3] is not None else "",
                    "verified": bool(row[4]),
                    "false_positive": bool(row[5]),
                    "discovered_at": str(row[6]),
                }
                for row in passive_rows
            ],
            "auth_results": [
                {
                    "target_url": str(row[0]),
                    "attack_type": str(row[1]) if row[1] is not None else "",
                    "success": bool(row[2]),
                    "tested_at": str(row[3]),
                }
                for row in auth_rows
            ],
        }

    @app.get("/api/engagements/{engagement_id}/vuln-summary")
    def vuln_summary(engagement_id: int, _subject: str = Depends(_auth_subject)) -> dict[str, Any]:
        con = get_engagement_db(cfg.engagement_db_path(str(engagement_id)))
        try:
            passive_rows = con.execute(
                """
                SELECT UPPER(COALESCE(severity, 'UNKNOWN')), COUNT(*)
                FROM passive_vulns
                WHERE engagement_id=?
                  AND COALESCE(false_positive, 0)=0
                GROUP BY UPPER(COALESCE(severity, 'UNKNOWN'))
                """,
                (engagement_id,),
            ).fetchall()
            active_rows = _reportable_vulnerability_rows(con, engagement_id)
            auth_rows = con.execute(
                """
                SELECT success, COUNT(*)
                FROM auth_test_results
                WHERE engagement_id=?
                GROUP BY success
                """,
                (engagement_id,),
            ).fetchall()
        finally:
            con.close()
        passive = {str(row[0]): int(row[1]) for row in passive_rows}
        active: dict[str, int] = {}
        for row in active_rows:
            severity = str(row["severity"] or "UNKNOWN").upper()
            active[severity] = active.get(severity, 0) + 1
        auth = {"success": 0, "failed": 0}
        for row in auth_rows:
            if int(row[0]) == 1:
                auth["success"] = int(row[1])
            else:
                auth["failed"] += int(row[1])
        return {"passive_vulns": passive, "vulnerability_findings": active, "auth_tests": auth}

    @app.get("/api/engagements/{engagement_id}/asset-tree")
    def asset_tree(
        engagement_id: int, _subject: str = Depends(_auth_subject)
    ) -> dict[str, list[dict[str, Any]]]:
        con = get_engagement_db(cfg.engagement_db_path(str(engagement_id)))
        try:
            port_rows = con.execute(
                """
                SELECT host, port, service, scanned_at
                FROM port_scan_results
                WHERE engagement_id=?
                ORDER BY scanned_at DESC
                LIMIT 1000
                """,
                (engagement_id,),
            ).fetchall()
            crawl_rows = con.execute(
                """
                SELECT COALESCE(final_url, url), title, discovered_at
                FROM crawl_results
                WHERE engagement_id=?
                ORDER BY discovered_at DESC
                LIMIT 1000
                """,
                (engagement_id,),
            ).fetchall()
        finally:
            con.close()

        ports_by_host: dict[str, list[dict[str, Any]]] = defaultdict(list)
        urls_by_host: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for row in port_rows:
            host = str(row[0]) if row[0] is not None else "unknown"
            ports_by_host[host].append(
                {
                    "port": int(row[1]),
                    "service": str(row[2]) if row[2] is not None else "",
                    "scanned_at": str(row[3]),
                }
            )
        for row in crawl_rows:
            raw_url = str(row[0]) if row[0] is not None else ""
            parsed = urlparse(raw_url)
            host = parsed.netloc or "unknown"
            urls_by_host[host].append(
                {
                    "url": raw_url,
                    "title": str(row[1]) if row[1] is not None else "",
                    "discovered_at": str(row[2]),
                }
            )

        all_hosts = sorted(set(ports_by_host.keys()) | set(urls_by_host.keys()))
        return {
            "items": [
                {
                    "host": host,
                    "ports": ports_by_host.get(host, []),
                    "urls": urls_by_host.get(host, []),
                }
                for host in all_hosts
            ]
        }

    def _publish_command_event(event: CommandEvent) -> None:
        broker.publish_sync(
            ProgressEvent(
                engagement_id=event.engagement_id,
                message=event.event_type,
                payload=event.payload,
            )
        )

    def get_command_center(engagement_id: int) -> CommandCenterService:
        return CommandCenterService(
            engagement_id=engagement_id,
            config=cfg,
            coordinator=coordinator,
            publish_event=_publish_command_event,
        )

    @app.get("/api/assets/{host}/context")
    def get_host_context_api(
        host: str, engagement_id: int, _subject: str = Depends(_auth_subject)
    ) -> dict[str, Any]:
        svc = get_command_center(engagement_id)
        return svc.get_host_context(host)

    @app.get("/api/assets/{host}/actions")
    def get_host_actions_api(
        host: str, engagement_id: int, _subject: str = Depends(_auth_subject)
    ) -> dict[str, Any]:
        svc = get_command_center(engagement_id)
        return {"actions": svc.list_host_actions(host)}

    @app.post("/api/actions/{action_id}/execute")
    def execute_action_api(
        action_id: str, body: dict[str, Any], _subject: str = Depends(_auth_subject)
    ) -> dict[str, Any]:
        engagement_id = body.get("engagement_id")
        if not engagement_id:
            from fastapi import HTTPException

            raise HTTPException(status_code=400, detail="engagement_id required in body")
        svc = get_command_center(engagement_id)
        return svc.execute_action(action_id)

    @app.post("/api/actions/{action_id}/approve")
    def approve_action_api(
        action_id: str, body: dict[str, Any], _subject: str = Depends(_auth_subject)
    ) -> dict[str, Any]:
        engagement_id = body.get("engagement_id")
        if not engagement_id:
            from fastapi import HTTPException

            raise HTTPException(status_code=400, detail="engagement_id required in body")
        svc = get_command_center(engagement_id)
        return svc.approve_action(action_id)

    @app.post("/api/sentry/toggle")
    def toggle_sentry_api(
        body: dict[str, Any], _subject: str = Depends(_auth_subject)
    ) -> dict[str, Any]:
        engagement_id = body.get("engagement_id")
        enabled = body.get("enabled", False)
        if not engagement_id:
            from fastapi import HTTPException

            raise HTTPException(status_code=400, detail="engagement_id required in body")
        svc = get_command_center(engagement_id)
        return svc.toggle_sentry(enabled)

    @app.post("/api/sentry/emergency-stop")
    def emergency_stop_api(
        body: dict[str, Any], _subject: str = Depends(_auth_subject)
    ) -> dict[str, Any]:
        engagement_id = body.get("engagement_id")
        if not engagement_id:
            from fastapi import HTTPException

            raise HTTPException(status_code=400, detail="engagement_id required in body")
        svc = get_command_center(engagement_id)
        return svc.emergency_stop()

    @app.get("/api/timeline")
    def get_timeline_api(
        engagement_id: int, _subject: str = Depends(_auth_subject)
    ) -> dict[str, Any]:
        svc = get_command_center(engagement_id)
        return {"events": svc.list_timeline()}

    @app.websocket("/ws/progress")
    async def progress_ws(websocket: WebSocket) -> None:
        await websocket.accept()
        queue = broker.subscribe()
        try:
            while True:
                event = await queue.get()
                await websocket.send_text(
                    json.dumps(
                        {
                            "engagement_id": event.engagement_id,
                            "message": event.message,
                            "payload": event.payload,
                        }
                    )
                )
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
