"""
forge/api/routes/quality.py - Data-quality metrics endpoint.

Exposes ``GET /api/engagements/{engagement_id}/quality`` which computes
and returns a :class:`QualitySnapshot` for the QualityWidget component.

The snapshot is derived from the engagement DB using
:func:`forge.report.quality_metrics.compute_quality_report`.  History is
sourced from the ``engagement_runs`` table (last 10 completed kill-chain
runs that stored a quality score in their metadata).

The route also broadcasts a ``quality:updated`` WebSocket event on the
shared message bus so connected QualityWidget instances refresh without
polling.

Requirements: MEDIUM-7 (quality metrics product integration)
"""

from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status

from forge.api.deps import get_bus, get_control_db, require_permission
from forge.bus.base import MessageBus
from forge.config import ForgeConfig
from forge.db.direct_connect import direct_connect
from forge.report.quality_metrics import QualityConfig, compute_quality_report
from forge.webui.auth import Principal

__all__ = ["router"]

_LOG = logging.getLogger(__name__)

router = APIRouter(prefix="/api/engagements", tags=["quality"])
_require_quality_read = require_permission("engagements:read")

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_METRIC_KEY_MAP = {
    "node_coverage": "coverage",
    "edge_completeness": "completeness",
    "stale_timestamps": "freshness",
    "orphan_nodes": "connectivity",
}

_METRIC_LABEL_MAP = {
    "coverage": "Coverage",
    "completeness": "Completeness",
    "freshness": "Freshness",
    "connectivity": "Connectivity",
}


def _open_engagement_db(engagement_id: str) -> sqlite3.Connection:
    """Open the SQLite engagement DB for *engagement_id*."""
    try:
        cfg = ForgeConfig.load()
        db_path = cfg.engagement_db_path(engagement_id)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"engagement_not_found:{engagement_id}",
        ) from exc
    try:
        return direct_connect(db_path, check_same_thread=False)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"engagement_db_unavailable:{engagement_id}",
        ) from exc


def _fetch_graph_stats(
    con: sqlite3.Connection,
    engagement_id: str,
) -> tuple[list[str], list[tuple[str, str]], dict[str, str], int, int]:
    """Return (node_ids, edges, timestamps, expected_nodes, expected_edges).

    Falls back to empty collections when the asset_entities / asset_relationships
    tables are absent (pre-migration DBs).
    """
    try:
        node_rows = con.execute(
            "SELECT entity_key, updated_at FROM asset_entities WHERE engagement_id=?",
            (int(engagement_id),),
        ).fetchall()
    except sqlite3.Error:
        node_rows = []

    try:
        edge_rows = con.execute(
            """
            SELECT ae_src.entity_key, ae_tgt.entity_key
            FROM asset_relationships ar
            JOIN asset_entities ae_src ON ae_src.id = ar.source_entity_id
            JOIN asset_entities ae_tgt ON ae_tgt.id = ar.target_entity_id
            WHERE ar.engagement_id=?
            """,
            (int(engagement_id),),
        ).fetchall()
    except sqlite3.Error:
        edge_rows = []

    # Derive expected counts from the latest engagement_runs metadata when
    # available; fall back to the observed counts so coverage = 100 %.
    try:
        meta_row = con.execute(
            """
            SELECT metadata_json FROM engagement_runs
            WHERE engagement_id=? AND run_kind='kill_chain'
            ORDER BY id DESC LIMIT 1
            """,
            (int(engagement_id),),
        ).fetchone()
        meta: dict[str, Any] = json.loads(meta_row[0]) if meta_row else {}
    except (sqlite3.Error, json.JSONDecodeError):
        meta = {}

    expected_nodes = int(meta.get("expected_node_count", 0))
    expected_edges = int(meta.get("expected_edge_count", 0))

    node_ids = [str(r[0]) for r in node_rows]
    edges = [(str(r[0]), str(r[1])) for r in edge_rows]
    timestamps = {str(r[0]): str(r[1]) for r in node_rows if r[1]}

    return node_ids, edges, timestamps, expected_nodes, expected_edges


def _fetch_run_history(
    con: sqlite3.Connection,
    engagement_id: str,
    limit: int = 10,
) -> list[dict[str, Any]]:
    """Return the last *limit* completed kill-chain run quality scores."""
    try:
        rows = con.execute(
            """
            SELECT metadata_json, completed_at, updated_at
            FROM engagement_runs
            WHERE engagement_id=? AND run_kind='kill_chain' AND status='completed'
            ORDER BY id DESC LIMIT ?
            """,
            (int(engagement_id), limit),
        ).fetchall()
    except sqlite3.Error:
        return []

    history: list[dict[str, Any]] = []
    for meta_json, completed_at, updated_at in reversed(rows):
        try:
            meta = json.loads(meta_json) if meta_json else {}
        except json.JSONDecodeError:
            meta = {}
        score = meta.get("quality_score")
        if score is None:
            continue
        ts = completed_at or updated_at or ""
        history.append({"timestamp": str(ts), "score": float(score)})
    return history


# ---------------------------------------------------------------------------
# Route
# ---------------------------------------------------------------------------


@router.get(
    "/{engagement_id}/quality",
    summary="Data-quality snapshot for an engagement",
)
async def get_quality(
    engagement_id: str,
    principal: Principal = Depends(_require_quality_read),
    control_con: sqlite3.Connection = Depends(get_control_db),
    bus: MessageBus = Depends(get_bus),
) -> dict[str, object]:
    """Compute and return a QualitySnapshot for *engagement_id*.

    The snapshot shape matches the TypeScript ``QualitySnapshot`` type in
    ``QualityWidget.tsx`` so the component can consume it directly.
    """
    con = _open_engagement_db(engagement_id)
    try:
        node_ids, edges, timestamps, expected_nodes, expected_edges = _fetch_graph_stats(
            con, engagement_id
        )
        history = _fetch_run_history(con, engagement_id)
    finally:
        con.close()

    reference_time = datetime.now(tz=timezone.utc)
    try:
        report = compute_quality_report(
            nodes=node_ids,
            edges=edges,
            expected_nodes=expected_nodes,
            expected_edges=expected_edges,
            node_timestamps=timestamps if timestamps else None,
            reference_time=reference_time,
            config=QualityConfig(),
        )
    except Exception as exc:
        _LOG.warning("quality_metrics compute failed for %s: %s", engagement_id, exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"quality_compute_failed:{exc}",
        ) from exc

    # Map internal metric keys to the widget's expected keys.
    metrics = []
    for internal_key, widget_key in _METRIC_KEY_MAP.items():
        metric = report.metrics.get(internal_key)
        if metric is None:
            continue
        metrics.append(
            {
                "key": widget_key,
                "label": _METRIC_LABEL_MAP[widget_key],
                "score": round(metric.score, 2),
            }
        )

    generated_at = reference_time.strftime("%Y-%m-%d %H:%M:%S")

    snapshot: dict[str, object] = {
        "engagement_id": engagement_id,
        "overall_score": report.overall_score,
        "generated_at": generated_at,
        "metrics": metrics,
        "history": history,
    }

    # Broadcast quality:updated so connected WebSocket clients refresh.
    try:
        await bus.publish(
            "quality:updated",
            {
                "event": "quality:updated",
                "engagement_id": engagement_id,
                "snapshot": snapshot,
            },
        )
    except Exception:  # noqa: BLE001 - best-effort; never block the HTTP response
        _LOG.debug("quality:updated broadcast failed for %s", engagement_id, exc_info=True)
    return snapshot
