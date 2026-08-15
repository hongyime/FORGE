"""Web UI connector route helpers."""
from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from forge.connectors.registry import (
    connector_plugin_dirs,
    connector_statuses,
    connector_summary,
    normalize_connector_domain,
)
from forge.connectors.secrets import (
    SECRET_MATERIAL_POLICY,
    connector_secret_readiness,
    list_connector_secrets,
    store_connector_secret,
)


class ConnectorRouteError(ValueError):
    """Request validation failure that should map to HTTP 400."""


class ConnectorRouteNotFound(LookupError):
    """Missing connector dependency that should map to HTTP 404."""


def connector_secret_summary(items: list[dict[str, Any]]) -> dict[str, Any]:
    connectors = sorted(
        {str(item.get("connector_id") or "") for item in items if item.get("connector_id")}
    )
    return {
        "count": len(items),
        "connectors": connectors,
        "secret_material_policy": SECRET_MATERIAL_POLICY,
    }


def connector_domain_filter(domain: str) -> str:
    try:
        return normalize_connector_domain(domain)
    except ValueError as exc:
        raise ConnectorRouteError(f"unknown connector domain: {domain}") from exc


def connector_catalog_payload(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    data_dir: Path,
    domain: str,
    include_paid: bool,
) -> dict[str, Any]:
    stored_secret_statuses = connector_secret_readiness(con, engagement_id=engagement_id)
    plugin_dirs = connector_plugin_dirs(data_dir=data_dir)
    try:
        connectors = connector_statuses(
            domain=connector_domain_filter(domain),
            include_paid=include_paid,
            stored_secret_statuses=stored_secret_statuses,
            plugin_dirs=plugin_dirs,
        )
    except ValueError as exc:
        raise ConnectorRouteError(str(exc)) from exc
    summary = connector_summary(connectors)
    summary["engagement_id"] = engagement_id
    summary["secret_store_connector_count"] = len(stored_secret_statuses)
    return {"connectors": connectors, "summary": summary}


def connector_secrets_payload(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    connector: str,
) -> dict[str, Any]:
    try:
        items = list_connector_secrets(
            con,
            engagement_id=engagement_id,
            connector_id=str(connector or "").strip(),
        )
    except ValueError as exc:
        raise ConnectorRouteError(str(exc)) from exc
    return {"items": items, "summary": connector_secret_summary(items)}


def store_connector_secret_payload(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    body: dict[str, Any] | None,
    operator: str,
) -> dict[str, Any]:
    payload = body or {}
    connector_id = str(payload.get("connector_id") or payload.get("connector") or "").strip()
    secret_name = str(payload.get("secret_name") or payload.get("name") or "").strip()
    secret_value = str(payload.get("secret_value") or "")
    if not secret_value.strip():
        raise ConnectorRouteError("secret_value is required.")
    secret_ref = str(payload.get("secret_ref") or "").strip()
    if not secret_ref or secret_value in secret_ref:
        secret_ref = "api:request-body"
    metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
    try:
        item = store_connector_secret(
            con,
            engagement_id=engagement_id,
            connector_id=connector_id,
            secret_name=secret_name,
            secret_value=secret_value,
            secret_ref=secret_ref,
            operator=operator,
            metadata=metadata,
        )
        items = list_connector_secrets(
            con,
            engagement_id=engagement_id,
            connector_id=connector_id,
        )
    except LookupError as exc:
        raise ConnectorRouteNotFound(str(exc)) from exc
    except ValueError as exc:
        raise ConnectorRouteError(str(exc)) from exc
    return {
        "status": "stored",
        "item": item,
        "summary": connector_secret_summary(items),
    }
