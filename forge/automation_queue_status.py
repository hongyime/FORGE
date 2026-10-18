"""Low-level source-queue status calculation shared by automation entry points."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Callable

QueueLoader = Callable[[Path], list[dict[str, Any]]]
QueueClassifier = Callable[..., tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]]
PositiveIntParser = Callable[[Any], int | None]


def unavailable_queue_status(reason: str = "queue_status_provider_unavailable") -> dict[str, Any]:
    return {
        "checked": False,
        "reason": reason,
        "next_action": "Run forge automation status --json to inspect source queues.",
        "total": 0,
        "ready": 0,
        "blocked": 0,
        "ignored": 0,
        "total_count": 0,
        "ready_count": 0,
        "blocked_count": 0,
        "ignored_count": 0,
    }


def direct_source_queue_status(
    *,
    root: Path,
    config: dict[str, Any],
    skip_feed_build: bool,
    default_engagement_env: str,
    load_queue_items: QueueLoader,
    classify_queue_items: QueueClassifier,
    safe_positive_int: PositiveIntParser,
) -> dict[str, Any]:
    if skip_feed_build:
        return {**unavailable_queue_status("skip_feed_build"), "next_action": None}
    imports_dir = root / "imports"
    try:
        engagement = safe_positive_int(config.get("engagement_id"))
        if engagement is None:
            engagement = safe_positive_int(os.environ.get(default_engagement_env))
        items = load_queue_items(imports_dir)
        ready, blocked, ignored = classify_queue_items(
            items,
            imports_dir=imports_dir,
            engagement=engagement,
            import_item_limit=int(config["queue_import_item_limit"]),
            promote_targets=bool(config["queue_promote_targets"]),
        )
    except Exception as exc:  # noqa: BLE001
        return unavailable_queue_status(f"queue_status_unavailable:{type(exc).__name__}")
    return {
        "checked": True,
        "reason": "direct_guarded_autostart_queue_check",
        "next_action": (
            "Run forge automation cycle --apply --live --json so ready local "
            "source queues are consumed before guarded live work."
            if ready
            else None
        ),
        "total": len(items),
        "ready": len(ready),
        "blocked": len(blocked),
        "ignored": len(ignored),
        "total_count": len(items),
        "ready_count": len(ready),
        "blocked_count": len(blocked),
        "ignored_count": len(ignored),
        "ready_connectors": sorted({str(item["connector_id"]) for item in ready}),
    }
