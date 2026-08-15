"""Web UI engagement discovery, resolution, and control-index helpers."""
from __future__ import annotations

import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from forge.db.control import (
    connect_control_db,
    engagement_index_is_fresh,
    engagement_index_summary,
    index_engagement_summary,
    list_engagement_index,
    list_missing_engagement_index,
    lookup_engagement_index,
    mark_engagement_index_missing,
    purge_missing_engagement_indexes,
)
from forge.db.direct_connect import direct_connect
from forge.engagement_ids import engagement_db_root, numeric_engagement_db_files
from forge.webui.engagement_lifecycle import index_webui_engagement_summary

CanAccessWorkspace = Callable[[Any, str, sqlite3.Connection | None], bool]
CanAccessEngagementRow = Callable[[sqlite3.Connection, Any, sqlite3.Row], bool]
ConnectionSetup = Callable[[sqlite3.Connection], None]
EngagementRows = Callable[[sqlite3.Connection], list[sqlite3.Row]]
EngagementRow = Callable[[sqlite3.Connection, int], sqlite3.Row | None]
PayloadBuilder = Callable[[Path, sqlite3.Connection, sqlite3.Row], dict[str, Any]]
ArtifactFileProvider = Callable[[sqlite3.Connection, Path, int, dict[str, Any]], list[Path]]


@dataclass(frozen=True)
class EngagementDiscoveryContext:
    data_dir: Path
    ensure_workspace_rbac_foundation: ConnectionSetup
    engagement_rows: EngagementRows
    engagement_row: EngagementRow
    summary_payload: PayloadBuilder
    detail_payload: PayloadBuilder
    can_access_workspace: CanAccessWorkspace
    can_access_engagement_row: CanAccessEngagementRow
    artifact_files: ArtifactFileProvider
    tombstone_retention_days: str = "30"


@dataclass(frozen=True)
class EngagementDiscoveryProviders:
    iter_engagement_payloads: Callable[[Any | None], list[dict[str, Any]]]
    iter_missing_engagement_index_payloads: Callable[[Any | None], list[dict[str, Any]]]
    find_engagement_detail: Callable[[str, Any | None], dict[str, Any] | None]
    find_engagement_artifact: Callable[[str, str, Any | None], Path | None]
    resolve_engagement_db: Callable[[str, Any | None], tuple[Path, int] | None]


def build_engagement_discovery_context_provider(
    *,
    data_dir: Path,
    ensure_workspace_rbac_foundation: ConnectionSetup,
    engagement_rows: EngagementRows,
    engagement_row: EngagementRow,
    summary_payload: PayloadBuilder,
    detail_payload: PayloadBuilder,
    can_access_workspace: CanAccessWorkspace,
    can_access_engagement_row: CanAccessEngagementRow,
    artifact_files: ArtifactFileProvider,
    tombstone_retention_days: str = "30",
) -> Callable[[], EngagementDiscoveryContext]:
    def _discovery_context() -> EngagementDiscoveryContext:
        return EngagementDiscoveryContext(
            data_dir=data_dir,
            ensure_workspace_rbac_foundation=ensure_workspace_rbac_foundation,
            engagement_rows=engagement_rows,
            engagement_row=engagement_row,
            summary_payload=summary_payload,
            detail_payload=detail_payload,
            can_access_workspace=can_access_workspace,
            can_access_engagement_row=can_access_engagement_row,
            artifact_files=artifact_files,
            tombstone_retention_days=tombstone_retention_days,
        )

    return _discovery_context


def build_engagement_discovery_providers(
    context_provider: Callable[[], EngagementDiscoveryContext],
) -> EngagementDiscoveryProviders:
    def _iter_engagement_payloads(principal: Any | None = None) -> list[dict[str, Any]]:
        return iter_engagement_payloads(context_provider(), principal)

    def _iter_missing_engagement_index_payloads(
        principal: Any | None = None,
    ) -> list[dict[str, Any]]:
        return iter_missing_engagement_index_payloads(context_provider(), principal)

    def _find_engagement_detail(
        engagement_ref: str,
        principal: Any | None = None,
    ) -> dict[str, Any] | None:
        return find_engagement_detail(context_provider(), engagement_ref, principal)

    def _find_engagement_artifact(
        engagement_ref: str,
        artifact_name: str,
        principal: Any | None = None,
    ) -> Path | None:
        return find_engagement_artifact(
            context_provider(),
            engagement_ref,
            artifact_name,
            principal,
        )

    def _resolve_engagement_db(
        engagement_ref: str,
        principal: Any | None = None,
    ) -> tuple[Path, int] | None:
        return resolve_engagement_db(context_provider(), engagement_ref, principal)

    return EngagementDiscoveryProviders(
        iter_engagement_payloads=_iter_engagement_payloads,
        iter_missing_engagement_index_payloads=_iter_missing_engagement_index_payloads,
        find_engagement_detail=_find_engagement_detail,
        find_engagement_artifact=_find_engagement_artifact,
        resolve_engagement_db=_resolve_engagement_db,
    )


def indexed_db_path(index_row: sqlite3.Row, data_dir: str | Path) -> Path | None:
    try:
        candidate = Path(str(index_row["db_path"] or "")).resolve()
        candidate.relative_to(engagement_db_root(data_dir).resolve())
    except (OSError, RuntimeError, ValueError):
        return None
    return candidate if candidate.is_file() else None


def fresh_index_summary(index_row: sqlite3.Row, data_dir: str | Path) -> dict[str, Any] | None:
    db_file = indexed_db_path(index_row, data_dir)
    if db_file is None:
        return None
    if not engagement_index_is_fresh(index_row, db_file):
        return None
    payload = engagement_index_summary(index_row)
    if not payload or "id" not in payload:
        return None
    return payload


def control_tombstone_retention_seconds(raw_value: str | None) -> int | None:
    value = str(raw_value or "30").strip()
    if value.lower() in {"", "off", "none", "disabled"}:
        return None
    try:
        days = float(value)
    except ValueError:
        days = 30.0
    if days < 0:
        return None
    return int(days * 86400)


def purge_expired_control_tombstones(
    control_con: sqlite3.Connection,
    *,
    retention_days: str | None,
) -> int:
    retention_seconds = control_tombstone_retention_seconds(retention_days)
    if retention_seconds is None:
        return 0
    purged = purge_missing_engagement_indexes(
        control_con,
        older_than_seconds=retention_seconds,
    )
    if purged:
        control_con.commit()
    return purged


def _open_workflow_db(db_file: Path) -> sqlite3.Connection:
    con = direct_connect(db_file)
    con.row_factory = sqlite3.Row
    return con


def index_engagement_db(
    control_con: sqlite3.Connection,
    ctx: EngagementDiscoveryContext,
    db_file: Path,
) -> list[dict[str, Any]]:
    if not db_file.is_file():
        return []
    con = _open_workflow_db(db_file)
    try:
        ctx.ensure_workspace_rbac_foundation(con)
        summaries: list[dict[str, Any]] = []
        for row in ctx.engagement_rows(con):
            summary = ctx.summary_payload(db_file, con, row)
            index_engagement_summary(control_con, db_path=db_file, summary=summary)
            summaries.append(summary)
        return summaries
    finally:
        con.close()


def iter_engagement_payloads(
    ctx: EngagementDiscoveryContext,
    principal: Any | None = None,
) -> list[dict[str, Any]]:
    if not (ctx.data_dir / "engagements").exists():
        return []
    items: list[dict[str, Any]] = []
    control_con = connect_control_db(ctx.data_dir)
    try:
        purge_expired_control_tombstones(
            control_con,
            retention_days=ctx.tombstone_retention_days,
        )
        for index_row in list_engagement_index(control_con):
            if not ctx.can_access_workspace(
                principal,
                str(index_row["workspace_id"] or "default"),
                control_con,
            ):
                continue
            db_file = indexed_db_path(index_row, ctx.data_dir)
            if db_file is None:
                mark_engagement_index_missing(control_con, int(index_row["engagement_id"]))
                continue
            cached = fresh_index_summary(index_row, ctx.data_dir)
            if cached is not None:
                items.append(cached)
                continue
            con = _open_workflow_db(db_file)
            try:
                ctx.ensure_workspace_rbac_foundation(con)
                row = ctx.engagement_row(con, int(index_row["engagement_id"]))
                if row is None:
                    continue
                if not ctx.can_access_engagement_row(con, principal, row):
                    continue
                summary = ctx.summary_payload(db_file, con, row)
                index_engagement_summary(control_con, db_path=db_file, summary=summary)
                items.append(summary)
            finally:
                con.close()
        indexed_ids = {int(row["engagement_id"]) for row in list_engagement_index(control_con)}
        for db_file in numeric_engagement_db_files(ctx.data_dir):
            if int(db_file.stem) in indexed_ids:
                continue
            summaries = index_engagement_db(control_con, ctx, db_file)
            for summary in summaries:
                if int(summary["id"]) in indexed_ids:
                    continue
                if ctx.can_access_workspace(
                    principal,
                    str(summary.get("workspace_id") or "default"),
                    control_con,
                ):
                    items.append(summary)
        control_con.commit()
    finally:
        control_con.close()
    items.sort(key=lambda item: (item["updated_at"], item["id"]), reverse=True)
    return items


def iter_missing_engagement_index_payloads(
    ctx: EngagementDiscoveryContext,
    principal: Any | None = None,
) -> list[dict[str, Any]]:
    control_con = connect_control_db(ctx.data_dir)
    try:
        purge_expired_control_tombstones(
            control_con,
            retention_days=ctx.tombstone_retention_days,
        )
        rows = list_missing_engagement_index(control_con)
        payloads: list[dict[str, Any]] = []
        for row in rows:
            workspace_id = str(row["workspace_id"] or "default")
            if not ctx.can_access_workspace(principal, workspace_id, control_con):
                continue
            db_file = indexed_db_path(row, ctx.data_dir)
            payloads.append(
                {
                    "engagement_id": int(row["engagement_id"]),
                    "workspace_id": workspace_id,
                    "slug": str(row["slug"] or ""),
                    "name": str(row["name"] or ""),
                    "status": str(row["status"] or ""),
                    "operator": str(row["operator"] or ""),
                    "db_path": str(row["db_path"] or ""),
                    "db_exists": db_file is not None,
                    "last_seen_at": str(row["last_seen_at"] or ""),
                    "missing_since": str(row["missing_since"] or ""),
                }
            )
        return payloads
    finally:
        control_con.close()


def resolve_engagement_db(
    ctx: EngagementDiscoveryContext,
    engagement_ref: str,
    principal: Any | None = None,
) -> tuple[Path, int] | None:
    if not (ctx.data_dir / "engagements").exists():
        return None
    ref = engagement_ref.strip().lower()
    control_con = connect_control_db(ctx.data_dir)
    try:
        purge_expired_control_tombstones(
            control_con,
            retention_days=ctx.tombstone_retention_days,
        )
        index_row = lookup_engagement_index(control_con, ref)
        if index_row is not None and ctx.can_access_workspace(
            principal,
            str(index_row["workspace_id"] or "default"),
            control_con,
        ):
            db_file = indexed_db_path(index_row, ctx.data_dir)
            if db_file is None:
                mark_engagement_index_missing(control_con, int(index_row["engagement_id"]))
                control_con.commit()
                return None
            engagement_id = int(index_row["engagement_id"])
            con = _open_workflow_db(db_file)
            try:
                ctx.ensure_workspace_rbac_foundation(con)
                row = ctx.engagement_row(con, engagement_id)
                if row is not None and ctx.can_access_engagement_row(con, principal, row):
                    return db_file, engagement_id
            finally:
                con.close()

        for db_file in numeric_engagement_db_files(ctx.data_dir):
            con = _open_workflow_db(db_file)
            try:
                ctx.ensure_workspace_rbac_foundation(con)
                for row in ctx.engagement_rows(con):
                    summary = ctx.summary_payload(db_file, con, row)
                    index_engagement_summary(control_con, db_path=db_file, summary=summary)
                    if ref in {str(summary["id"]).lower(), str(summary["slug"]).lower()}:
                        control_con.commit()
                        if not ctx.can_access_engagement_row(con, principal, row):
                            return None
                        return db_file, int(summary["id"])
            finally:
                con.close()
        control_con.commit()
    finally:
        control_con.close()
    return None


def find_engagement_detail(
    ctx: EngagementDiscoveryContext,
    engagement_ref: str,
    principal: Any | None = None,
) -> dict[str, Any] | None:
    resolved = resolve_engagement_db(ctx, engagement_ref, principal)
    if resolved is None:
        return None
    db_file, engagement_id = resolved
    con = _open_workflow_db(db_file)
    try:
        ctx.ensure_workspace_rbac_foundation(con)
        row = ctx.engagement_row(con, engagement_id)
        if row is None or not ctx.can_access_engagement_row(con, principal, row):
            return None
        detail = ctx.detail_payload(db_file, con, row)
        index_webui_engagement_summary(ctx.data_dir, db_file, detail)
        return detail
    finally:
        con.close()


def find_engagement_artifact(
    ctx: EngagementDiscoveryContext,
    engagement_ref: str,
    artifact_name: str,
    principal: Any | None = None,
) -> Path | None:
    resolved = resolve_engagement_db(ctx, engagement_ref, principal)
    if resolved is None:
        return None
    db_file, engagement_id = resolved
    requested_name = Path(artifact_name).name
    con = _open_workflow_db(db_file)
    try:
        ctx.ensure_workspace_rbac_foundation(con)
        row = ctx.engagement_row(con, engagement_id)
        if row is None or not ctx.can_access_engagement_row(con, principal, row):
            return None
        summary = ctx.summary_payload(db_file, con, row)
        index_webui_engagement_summary(ctx.data_dir, db_file, summary)
        for path in ctx.artifact_files(con, db_file, engagement_id, summary):
            if path.is_file() and path.name == requested_name:
                return path
    finally:
        con.close()
    return None


def authorized_engagement_db_path(
    ctx: EngagementDiscoveryContext,
    engagement_id: int,
    principal: Any,
) -> Path:
    resolved = resolve_engagement_db(ctx, str(engagement_id), principal)
    if resolved is None:
        raise LookupError("Engagement not found.")
    return resolved[0]


__all__ = [
    "EngagementDiscoveryContext",
    "EngagementDiscoveryProviders",
    "authorized_engagement_db_path",
    "build_engagement_discovery_context_provider",
    "build_engagement_discovery_providers",
    "control_tombstone_retention_seconds",
    "find_engagement_artifact",
    "find_engagement_detail",
    "fresh_index_summary",
    "index_engagement_db",
    "indexed_db_path",
    "iter_engagement_payloads",
    "iter_missing_engagement_index_payloads",
    "purge_expired_control_tombstones",
    "resolve_engagement_db",
]
