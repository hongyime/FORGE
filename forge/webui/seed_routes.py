"""Web UI engagement seed route helpers."""
from __future__ import annotations

import sqlite3
from collections.abc import Callable
from typing import Any

from forge.webui.seeds import (
    create_engagement_seed_payload,
    delete_engagement_seed_payload,
    engagement_seed_rows,
    update_engagement_seed_payload,
)

FormatDate = Callable[[str], str]


def engagement_seed_list_payload(
    con: sqlite3.Connection,
    engagement_id: int,
    *,
    format_dt: FormatDate,
) -> dict[str, list[dict[str, Any]]]:
    return {"items": engagement_seed_rows(con, engagement_id, format_dt=format_dt)}


def create_seed_route_payload(
    con: sqlite3.Connection,
    engagement_id: int,
    body: dict[str, Any],
    *,
    format_dt: FormatDate,
) -> dict[str, Any]:
    return create_engagement_seed_payload(con, engagement_id, body, format_dt=format_dt)


def update_seed_route_payload(
    con: sqlite3.Connection,
    engagement_id: int,
    seed_id: int,
    body: dict[str, Any],
    *,
    format_dt: FormatDate,
) -> dict[str, Any]:
    return update_engagement_seed_payload(con, engagement_id, seed_id, body, format_dt=format_dt)


def delete_seed_route_payload(
    con: sqlite3.Connection,
    engagement_id: int,
    seed_id: int,
    *,
    format_dt: FormatDate,
) -> dict[str, Any]:
    return delete_engagement_seed_payload(con, engagement_id, seed_id, format_dt=format_dt)


__all__ = [
    "create_seed_route_payload",
    "delete_seed_route_payload",
    "engagement_seed_list_payload",
    "update_seed_route_payload",
]
