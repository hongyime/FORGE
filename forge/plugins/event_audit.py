"""forge/plugins/event_audit.py — Durable audit log for plugin event bus dispatches.

Every accept/reject decision on the plugin event bus (E2.2/E2.3) is appended
here as a single JSON line. This satisfies the boundary spec §5.4 audit
requirement: dispatched and rejected events are both recorded with timestamp,
plugin_id, engagement_id, event_type, outcome, and payload byte size.

The sink is append-only: file is opened in ``"a"`` mode per write, flushed,
and closed. No update / delete API is exposed. Path defaults to
``<FORGE_DATA_DIR>/plugin_events_audit.jsonl`` but can be overridden with
``FORGE_PLUGIN_EVENT_AUDIT_PATH`` for tests or alternate storage roots.

Audit records intentionally do NOT include the payload contents — only its
serialized byte size. Secret material rejected upstream must never reach the
audit trail either.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, Literal

__all__ = [
    "AuditOutcome",
    "EventAuditWriteError",
    "record_event_audit",
    "resolve_audit_path",
]

_LOG: Final[logging.Logger] = logging.getLogger(__name__)

AuditOutcome = Literal["accepted", "rejected", "rate_limited"]

# One process-wide lock prevents interleaved writes from in-process publishers.
# Deployments with multiple processes must provide a process-safe sink path per
# worker or route these records into the central audit service.
_WRITE_LOCK: Final[threading.Lock] = threading.Lock()

_DEFAULT_FILENAME: Final[str] = "plugin_events_audit.jsonl"


class EventAuditWriteError(RuntimeError):
    """Raised when an event dispatch decision cannot be persisted."""


def resolve_audit_path() -> Path:
    """Return the effective audit log path.

    Precedence: ``FORGE_PLUGIN_EVENT_AUDIT_PATH`` env override, else
    ``<FORGE_DATA_DIR>/plugin_events_audit.jsonl``, else
    ``./plugin_events_audit.jsonl`` in the current working directory.
    """
    override = os.environ.get("FORGE_PLUGIN_EVENT_AUDIT_PATH")
    if override:
        return Path(override).expanduser()
    data_dir = os.environ.get("FORGE_DATA_DIR")
    if data_dir:
        return Path(data_dir).expanduser() / _DEFAULT_FILENAME
    return Path.cwd() / _DEFAULT_FILENAME


def record_event_audit(
    *,
    outcome: AuditOutcome,
    engagement_id: int | str,
    plugin_id: str,
    event_type: str,
    payload_bytes: int,
    reason: str = "",
) -> None:
    """Append one audit record for an event bus dispatch decision.

    Audit persistence is fail-closed: a caller must not dispatch an event when
    the corresponding audit decision could not be stored.
    """
    record = {
        "timestamp": datetime.now(UTC).isoformat(),
        "outcome": outcome,
        "engagement_id": engagement_id,
        "plugin_id": plugin_id,
        "event_type": event_type,
        "payload_bytes": int(payload_bytes),
        "reason": reason,
    }
    line = json.dumps(record, ensure_ascii=False, separators=(",", ":"))
    path = resolve_audit_path()
    try:
        with _WRITE_LOCK:
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
                handle.flush()
    except OSError as exc:
        _LOG.error(
            "plugin event audit write failed: path=%s outcome=%s event_type=%s error=%s",
            path,
            outcome,
            event_type,
            exc,
        )
        raise EventAuditWriteError(
            f"plugin event audit write failed for {path}: {exc}"
        ) from exc
