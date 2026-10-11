"""JSON-RPC 2.0 MCP server surface for FORGE engagement evidence.

Exposes read-only tools:

* ``forge.engagements.list``  — list engagements across local DBs
* ``forge.findings.list``     — list vulnerability findings for an engagement
* ``forge.hosts.list``        — list discovered hosts for an engagement
* ``forge.graph.get``         — latest attack-graph snapshot for an engagement

Transport layers:

* Stdio   — line-delimited JSON-RPC requests on ``stdin``
* HTTP    — loopback-only ``POST /mcp`` with ``Authorization: Bearer <token>``

Invariants:

* No writes. Every tool runs read-only SQL against engagement DBs.
* Secrets, raw credentials, and sensitive fields are never returned.
* Bind address is forced to ``127.0.0.1`` / ``::1`` loopback.
* Bearer-token auth is required when the token is supplied; missing-token
  mode is only allowed when the caller explicitly opts in via a flag.
* Result payloads are capped by a bounded ``--limit``.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import sqlite3
import socket
import sys
import threading
import time
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from forge.db.direct_connect import direct_connect

LOGGER = logging.getLogger(__name__)

MCP_PROTOCOL_VERSION = "2025-06-18"
MCP_SERVER_VERSION = "0.1.0"
_DEFAULT_LIMIT = 100
_MAX_LIMIT = 500
_DEFAULT_DATA_DIR = Path.home() / ".forge" / "data"
_MAX_REQUEST_BYTES = 1_048_576  # 1 MiB — far more than any legitimate MCP call

# JSON-RPC 2.0 error codes
_PARSE_ERROR = -32700
_INVALID_REQUEST = -32600
_METHOD_NOT_FOUND = -32601
_INVALID_PARAMS = -32602
_INTERNAL_ERROR = -32603

ToolHandler = Callable[[Mapping[str, Any], "ServerContext"], dict[str, Any]]

#: Roles that imply write access when carried as the ``role`` claim in an
#: :class:`AuthContext`. Case-insensitive comparison.
DEFAULT_WRITE_ROLES: tuple[str, ...] = ("operator", "owner", "admin")


# ---------------------------------------------------------------------------
# Error / response envelopes


class MCPError(Exception):
    """JSON-RPC error with ``code`` + ``message``."""

    def __init__(self, code: int, message: str, data: Any = None) -> None:
        super().__init__(message)
        self.code = int(code)
        self.message = str(message)
        self.data = data

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.data is not None:
            payload["data"] = self.data
        return payload


@dataclass
class MCPResponse:
    """Container for JSON-RPC 2.0 responses."""

    id: Any
    result: Any | None = None
    error: MCPError | None = None

    def to_dict(self) -> dict[str, Any]:
        envelope: dict[str, Any] = {"jsonrpc": "2.0", "id": self.id}
        if self.error is not None:
            envelope["error"] = self.error.to_dict()
        else:
            envelope["result"] = self.result
        return envelope


# ---------------------------------------------------------------------------
# Auth / permission context


@dataclass
class AuthContext:
    """Per-request authentication / authorization state.

    Write-capable tools reject the call unless ``has_write_access`` is true
    against the ambient :class:`ServerContext`. Read-only tools ignore the
    auth context entirely so the existing read surface stays unchanged.
    """

    role: str | None = None
    write_token: str | None = None
    source: str = "unknown"

    def normalized_role(self) -> str | None:
        if not self.role:
            return None
        return self.role.strip().lower() or None

    def has_write_access(self, ctx: "ServerContext") -> bool:
        """Return ``True`` when this auth context grants write permission.

        Two independent paths grant write access:

        * ``write_token`` matches ``ctx.expected_write_token`` byte-for-byte.
        * ``role`` is in ``ctx.allowed_write_roles`` (case-insensitive).

        Either path is sufficient; neither is required when the other
        passes. Falls back to ``False`` when both are missing or empty.
        """
        token_claim = (self.write_token or "").strip()
        if ctx.expected_write_token and token_claim:
            # ``compare_digest`` guards against timing side channels when the
            # server-side secret is set. Both values must be non-empty for
            # the comparison to be meaningful.
            if secrets.compare_digest(token_claim, ctx.expected_write_token):
                return True
        role = self.normalized_role()
        if role and role in {r.lower() for r in ctx.allowed_write_roles}:
            return True
        return False


# ---------------------------------------------------------------------------
# Server context (shared across tool handlers)


@dataclass
class ServerContext:
    """Context passed to every tool invocation."""

    data_dir: Path
    limit_default: int = _DEFAULT_LIMIT
    limit_max: int = _MAX_LIMIT
    tools: dict[str, dict[str, Any]] = field(default_factory=dict)
    #: Server-side write token. Clients present a matching ``write_token``
    #: via :class:`AuthContext` to prove permission for write-capable tools.
    #: ``None`` means no write-token path is enabled on this server.
    expected_write_token: str | None = None
    #: Role names that imply write access when carried as the ``role`` claim
    #: in an :class:`AuthContext`. Case-insensitive comparison.
    allowed_write_roles: tuple[str, ...] = DEFAULT_WRITE_ROLES
    #: Per-request auth context, populated by the dispatcher immediately
    #: before a handler runs and reset to ``None`` afterwards. Handlers that
    #: want to inspect it must copy it into a local variable; it is not
    #: safe to hold across awaits or threads.
    auth: AuthContext | None = None

    def engagement_db_path(self, engagement_id: int) -> Path:
        return self.data_dir / "engagements" / f"{int(engagement_id)}.db"


# ---------------------------------------------------------------------------
# Tool handlers


def _coerce_engagement_id(params: Mapping[str, Any]) -> int:
    raw = params.get("engagement_id")
    if raw is None:
        raise MCPError(_INVALID_PARAMS, "engagement_id is required")
    try:
        value = int(raw)
    except (TypeError, ValueError) as exc:
        raise MCPError(_INVALID_PARAMS, f"engagement_id must be an integer: {raw!r}") from exc
    if value <= 0:
        raise MCPError(_INVALID_PARAMS, "engagement_id must be a positive integer")
    return value


def _coerce_limit(params: Mapping[str, Any], ctx: ServerContext) -> int:
    raw = params.get("limit")
    if raw is None:
        return ctx.limit_default
    try:
        value = int(raw)
    except (TypeError, ValueError) as exc:
        raise MCPError(_INVALID_PARAMS, f"limit must be an integer: {raw!r}") from exc
    if value <= 0:
        raise MCPError(_INVALID_PARAMS, "limit must be a positive integer")
    return min(value, ctx.limit_max)


def _open_engagement_db(engagement_id: int, ctx: ServerContext) -> sqlite3.Connection:
    path = ctx.engagement_db_path(engagement_id)
    if not path.exists():
        raise MCPError(
            _INVALID_PARAMS,
            f"engagement {engagement_id} does not exist",
            data={"engagement_id": engagement_id, "db_path": str(path)},
        )
    try:
        conn = direct_connect(path)
    except sqlite3.OperationalError as exc:
        raise MCPError(
            _INTERNAL_ERROR,
            f"cannot open engagement DB {engagement_id}: {exc}",
        ) from exc
    conn.row_factory = sqlite3.Row
    return conn


# ---------------------------------------------------------------------------
# Shared helpers for write-capable tools


_SEVERITY_VALUES: frozenset[str] = frozenset(
    {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
)
_FINDINGS_TEXT_FIELDS: Mapping[str, int] = {
    "vuln_type": 128,
    "target_url": 2048,
    "title": 512,
    "description": 4096,
    "parameter": 256,
    "cve_id": 32,
    "evidence": 512,
}
#: Exploitation modules that the MCP ``forge.exploitation.start`` tool may
#: record an authorized-start intent for. Keep this list conservative; the
#: operator still runs the actual module through the audited CLI.
_EXPLOITATION_MODULES: frozenset[str] = frozenset(
    {
        "credential_capture",
        "post_login_automation",
        "autonomous_exploit",
        "goal_directed",
    }
)
#: Audit-log phase prefix used for exploitation-related events, including
#: both the ``forge.exploitation.start`` intent and any downstream module
#: outcomes written by the orchestrator.
_EXPLOITATION_AUDIT_PHASE: str = "exploitation"


def _require_text(
    params: Mapping[str, Any],
    key: str,
    *,
    max_length: int,
) -> str:
    raw = params.get(key)
    if raw is None:
        raise MCPError(_INVALID_PARAMS, f"{key} is required")
    value = str(raw).strip()
    if not value:
        raise MCPError(_INVALID_PARAMS, f"{key} must be a non-empty string")
    if len(value) > max_length:
        raise MCPError(
            _INVALID_PARAMS,
            f"{key} too long ({len(value)} > {max_length})",
        )
    return value


def _optional_text(
    params: Mapping[str, Any],
    key: str,
    *,
    max_length: int,
) -> str | None:
    raw = params.get(key)
    if raw is None:
        return None
    value = str(raw).strip()
    if not value:
        return None
    if len(value) > max_length:
        raise MCPError(
            _INVALID_PARAMS,
            f"{key} too long ({len(value)} > {max_length})",
        )
    return value


def _optional_number(
    params: Mapping[str, Any],
    key: str,
    *,
    min_value: float | None = None,
    max_value: float | None = None,
) -> float | None:
    raw = params.get(key)
    if raw is None:
        return None
    try:
        value = float(raw)
    except (TypeError, ValueError) as exc:
        raise MCPError(_INVALID_PARAMS, f"{key} must be numeric: {raw!r}") from exc
    if min_value is not None and value < min_value:
        raise MCPError(_INVALID_PARAMS, f"{key} must be >= {min_value}")
    if max_value is not None and value > max_value:
        raise MCPError(_INVALID_PARAMS, f"{key} must be <= {max_value}")
    return value


def _require_bool(
    params: Mapping[str, Any],
    key: str,
) -> bool:
    raw = params.get(key)
    if isinstance(raw, bool):
        return raw
    if raw is None:
        raise MCPError(_INVALID_PARAMS, f"{key} is required")
    raise MCPError(_INVALID_PARAMS, f"{key} must be a JSON boolean")


def _require_severity(params: Mapping[str, Any]) -> str:
    raw = params.get("severity")
    if raw is None:
        raise MCPError(_INVALID_PARAMS, "severity is required")
    value = str(raw).strip().upper()
    if value not in _SEVERITY_VALUES:
        raise MCPError(
            _INVALID_PARAMS,
            f"severity must be one of {sorted(_SEVERITY_VALUES)}; got {raw!r}",
        )
    return value


def _require_exploitation_module(params: Mapping[str, Any]) -> str:
    raw = params.get("module")
    if raw is None:
        raise MCPError(_INVALID_PARAMS, "module is required")
    value = str(raw).strip().lower()
    if value not in _EXPLOITATION_MODULES:
        raise MCPError(
            _INVALID_PARAMS,
            f"module must be one of {sorted(_EXPLOITATION_MODULES)}; got {raw!r}",
        )
    return value


def _tool_engagements_list(params: Mapping[str, Any], ctx: ServerContext) -> dict[str, Any]:
    limit = _coerce_limit(params, ctx)
    engagements_dir = ctx.data_dir / "engagements"
    rows: list[dict[str, Any]] = []
    if not engagements_dir.exists():
        return {"total_count": 0, "limit": limit, "engagements": []}
    db_files = sorted(engagements_dir.glob("*.db"))
    for db_path in db_files:
        try:
            engagement_id = int(db_path.stem)
        except ValueError:
            continue
        try:
            conn = direct_connect(db_path)
        except sqlite3.OperationalError:
            continue
        try:
            cursor = conn.execute(
                "SELECT id, name, status, operator, created_at, updated_at FROM engagements WHERE id = ?",
                (engagement_id,),
            )
            engagement = cursor.fetchone()
            if engagement is None:
                continue
            rows.append(
                {
                    "id": int(engagement[0]),
                    "name": engagement[1],
                    "status": engagement[2],
                    "operator": engagement[3],
                    "created_at": engagement[4],
                    "updated_at": engagement[5],
                }
            )
        except sqlite3.Error as exc:
            LOGGER.debug("Skipping %s: %s", db_path, exc)
            continue
        finally:
            conn.close()
        if len(rows) >= limit:
            break
    return {
        "total_count": len(rows),
        "limit": limit,
        "engagements": rows,
    }


def _tool_findings_list(params: Mapping[str, Any], ctx: ServerContext) -> dict[str, Any]:
    engagement_id = _coerce_engagement_id(params)
    limit = _coerce_limit(params, ctx)
    conn = _open_engagement_db(engagement_id, ctx)
    try:
        cursor = conn.execute(
            """
            SELECT id, vuln_type, target_url, severity, title,
                   cvss_score, cve_id, found_at
            FROM vulnerability_findings
            WHERE engagement_id = ?
            ORDER BY id DESC
            LIMIT ?
            """,
            (engagement_id, limit),
        )
        rows = [
            {
                "id": int(r[0]),
                "vuln_type": r[1],
                "target_url": r[2],
                "severity": r[3],
                "title": r[4],
                "cvss_score": r[5],
                "cve_id": r[6],
                "found_at": r[7],
            }
            for r in cursor.fetchall()
        ]
    finally:
        conn.close()
    return {
        "engagement_id": engagement_id,
        "total_count": len(rows),
        "limit": limit,
        "findings": rows,
    }


def _tool_hosts_list(params: Mapping[str, Any], ctx: ServerContext) -> dict[str, Any]:
    engagement_id = _coerce_engagement_id(params)
    limit = _coerce_limit(params, ctx)
    conn = _open_engagement_db(engagement_id, ctx)
    try:
        cursor = conn.execute(
            """
            SELECT id, ip, hostname, os_family, in_scope, discovered_at
            FROM hosts
            WHERE engagement_id = ?
            ORDER BY id DESC
            LIMIT ?
            """,
            (engagement_id, limit),
        )
        rows = [
            {
                "id": int(r[0]),
                "ip": r[1],
                "hostname": r[2],
                "os_family": r[3],
                "in_scope": bool(r[4]) if r[4] is not None else None,
                "discovered_at": r[5],
            }
            for r in cursor.fetchall()
        ]
    finally:
        conn.close()
    return {
        "engagement_id": engagement_id,
        "total_count": len(rows),
        "limit": limit,
        "hosts": rows,
    }


def _tool_graph_get(params: Mapping[str, Any], ctx: ServerContext) -> dict[str, Any]:
    engagement_id = _coerce_engagement_id(params)
    conn = _open_engagement_db(engagement_id, ctx)
    try:
        cursor = conn.execute(
            """
            SELECT id, snapshot_at, node_count, edge_count,
                   critical_path_weight, min_severity, pruned, graph_json
            FROM attack_graph_snapshots
            WHERE engagement_id = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (engagement_id,),
        )
        row = cursor.fetchone()
    finally:
        conn.close()
    if row is None:
        return {
            "engagement_id": engagement_id,
            "has_snapshot": False,
            "snapshot": None,
        }
    graph_json_raw = row[7]
    graph_payload: Any = None
    if graph_json_raw:
        try:
            graph_payload = json.loads(graph_json_raw)
        except json.JSONDecodeError:
            graph_payload = None
    return {
        "engagement_id": engagement_id,
        "has_snapshot": True,
        "snapshot": {
            "id": int(row[0]),
            "snapshot_at": row[1],
            "node_count": int(row[2]) if row[2] is not None else 0,
            "edge_count": int(row[3]) if row[3] is not None else 0,
            "critical_path_weight": row[4],
            "min_severity": row[5],
            "pruned": bool(row[6]) if row[6] is not None else False,
            "graph": graph_payload,
        },
    }


# ---------------------------------------------------------------------------
# Write-capable tools (require AuthContext.has_write_access)


def _tool_findings_create(
    params: Mapping[str, Any], ctx: ServerContext
) -> dict[str, Any]:
    """Create a new vulnerability finding row.

    Enforces the UNIQUE(engagement_id, vuln_type, target_url, parameter)
    constraint declared in the engagement schema. Severity is normalized to
    the five canonical values before insert. Secrets and raw credentials
    MUST NOT be passed in ``description``, ``evidence``, or ``target_url``;
    callers should scrub those first — this handler does not sniff them.
    """
    engagement_id = _coerce_engagement_id(params)
    vuln_type = _require_text(params, "vuln_type", max_length=_FINDINGS_TEXT_FIELDS["vuln_type"])
    target_url = _require_text(params, "target_url", max_length=_FINDINGS_TEXT_FIELDS["target_url"])
    title = _require_text(params, "title", max_length=_FINDINGS_TEXT_FIELDS["title"])
    severity = _require_severity(params)
    description = _optional_text(params, "description", max_length=_FINDINGS_TEXT_FIELDS["description"])
    parameter = _optional_text(params, "parameter", max_length=_FINDINGS_TEXT_FIELDS["parameter"])
    cve_id = _optional_text(params, "cve_id", max_length=_FINDINGS_TEXT_FIELDS["cve_id"])
    evidence = _optional_text(params, "evidence", max_length=_FINDINGS_TEXT_FIELDS["evidence"])
    cvss_score = _optional_number(params, "cvss_score", min_value=0.0, max_value=10.0)

    conn = _open_engagement_db(engagement_id, ctx)
    try:
        try:
            cursor = conn.execute(
                """
                INSERT INTO vulnerability_findings (
                    engagement_id,
                    vuln_type,
                    target_url,
                    parameter,
                    severity,
                    title,
                    description,
                    evidence,
                    cve_id,
                    cvss_score
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    engagement_id,
                    vuln_type,
                    target_url,
                    parameter,
                    severity,
                    title,
                    description,
                    evidence,
                    cve_id,
                    cvss_score,
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise MCPError(
                _INVALID_PARAMS,
                f"duplicate finding or constraint violation: {exc}",
                data={
                    "engagement_id": engagement_id,
                    "vuln_type": vuln_type,
                    "target_url": target_url,
                    "parameter": parameter,
                },
            ) from exc
        finding_id = int(cursor.lastrowid or 0)
        conn.commit()
        row = conn.execute(
            """
            SELECT id, vuln_type, target_url, severity, title, cve_id,
                   cvss_score, found_at, parameter
            FROM vulnerability_findings
            WHERE id = ?
            """,
            (finding_id,),
        ).fetchone()
    finally:
        conn.close()
    if row is None:  # pragma: no cover — defensive, insert succeeded above
        raise MCPError(
            _INTERNAL_ERROR,
            f"finding {finding_id} not visible after insert",
        )
    return {
        "engagement_id": engagement_id,
        "finding": {
            "id": int(row[0]),
            "vuln_type": row[1],
            "target_url": row[2],
            "severity": row[3],
            "title": row[4],
            "cve_id": row[5],
            "cvss_score": row[6],
            "found_at": row[7],
            "parameter": row[8],
        },
    }


def _tool_intents_create(
    params: Mapping[str, Any], ctx: ServerContext
) -> dict[str, Any]:
    """Create a new recursion intent (Fact/Intent/Hint board, Wave 2 #20)."""
    # Import at call time to avoid pulling the recursion store into module
    # import tracebacks when the MCP server is used purely for reads.
    from forge.recursion.store import IntentStoreError, add_intent

    engagement_id = _coerce_engagement_id(params)
    target_seed = _require_text(params, "target_seed", max_length=512)
    rationale = _optional_text(params, "rationale", max_length=4096)
    source_fact_id = _optional_text(params, "source_fact_id", max_length=256)
    seed_type = _optional_text(params, "seed_type", max_length=64)
    intent_id = _optional_text(params, "intent_id", max_length=64)

    conn = _open_engagement_db(engagement_id, ctx)
    try:
        try:
            created = add_intent(
                conn,
                target_seed=target_seed,
                rationale=rationale,
                source_fact_id=source_fact_id,
                seed_type=seed_type,
                engagement_id=engagement_id,
                intent_id=intent_id,
                status="open",
            )
        except IntentStoreError as exc:
            raise MCPError(
                _INVALID_PARAMS,
                f"could not create recursion intent: {exc}",
                data={"engagement_id": engagement_id, "target_seed": target_seed},
            ) from exc
        except sqlite3.OperationalError as exc:
            raise MCPError(
                _INTERNAL_ERROR,
                f"engagement DB missing recursion_intents schema: {exc}",
                data={"engagement_id": engagement_id},
            ) from exc
        conn.commit()
    finally:
        conn.close()
    return {
        "engagement_id": engagement_id,
        "intent": created,
    }


def _tool_exploitation_status(
    params: Mapping[str, Any], ctx: ServerContext
) -> dict[str, Any]:
    """Return the exploitation state of an engagement.

    Reads:
      * The engagement's declared status and operator.
      * The latest audit_log entries whose ``phase`` is ``exploitation``
        (capped by ``limit``, default 50).
      * The number of persisted ``payloads`` rows, if any.
      * The declared scope_json capabilities (reverse_proxy, post_login,
        autonomous_exploit, goal_targets) parsed defensively from the
        engagements row.

    This tool is read-only and does not require write permission.
    """
    engagement_id = _coerce_engagement_id(params)
    limit = _coerce_limit(params, ctx)
    conn = _open_engagement_db(engagement_id, ctx)
    try:
        engagement_row = conn.execute(
            "SELECT status, operator, scope_json FROM engagements WHERE id = ?",
            (engagement_id,),
        ).fetchone()
        audit_rows = conn.execute(
            """
            SELECT id, phase, module, action, target, result, operator, logged_at
            FROM audit_log
            WHERE engagement_id = ? AND phase = ?
            ORDER BY id DESC
            LIMIT ?
            """,
            (engagement_id, _EXPLOITATION_AUDIT_PHASE, limit),
        ).fetchall()
        try:
            payload_count = int(
                conn.execute(
                    "SELECT COUNT(*) FROM payloads WHERE engagement_id = ?",
                    (engagement_id,),
                ).fetchone()[0]
            )
        except sqlite3.OperationalError:
            payload_count = 0
    finally:
        conn.close()

    scope_json_raw = engagement_row[2] if engagement_row else None
    scope_capabilities: dict[str, bool] = {
        module: False for module in sorted(_EXPLOITATION_MODULES)
    }
    if scope_json_raw:
        try:
            scope_payload = json.loads(scope_json_raw)
        except json.JSONDecodeError:
            scope_payload = None
        if isinstance(scope_payload, Mapping):
            policy = scope_payload.get("policy") or {}
            if isinstance(policy, Mapping):
                for module in scope_capabilities:
                    if bool(policy.get(module)):
                        scope_capabilities[module] = True
    recent_events = [
        {
            "id": int(r[0]),
            "phase": r[1],
            "module": r[2],
            "action": r[3],
            "target": r[4],
            "result": r[5],
            "operator": r[6],
            "logged_at": r[7],
        }
        for r in audit_rows
    ]
    return {
        "engagement_id": engagement_id,
        "status": engagement_row[0] if engagement_row else None,
        "operator": engagement_row[1] if engagement_row else None,
        "scope_authorized_capabilities": scope_capabilities,
        "payload_count": payload_count,
        "recent_event_count": len(recent_events),
        "recent_events": recent_events,
        "limit": limit,
    }


def _tool_exploitation_start(
    params: Mapping[str, Any], ctx: ServerContext
) -> dict[str, Any]:
    """Record an operator-authorized exploitation-module start intent.

    This tool does **not** execute the exploitation module itself; the
    actual module execution runs through the normal audited CLI/orchestrator
    path. What this tool does is persist a durable, hash-chain-ready
    ``audit_log`` entry so coding agents can hand off "start module X
    against target Y" intents while every FORGE invariant (scope gate,
    ROE check, hash-chain audit) is still enforced by the executor.

    Parameters:
      * ``engagement_id``: target engagement.
      * ``module``: one of :data:`_EXPLOITATION_MODULES`.
      * ``target``: scope-manifest-approved target reference (host, URL,
        or seed). Max 512 chars. The underlying executor performs the
        actual scope check; this tool records intent only.
      * ``roe_id``: ROE reference recorded with the intent.
      * ``authorized``: MUST be the literal boolean ``true`` to confirm
        the operator has reviewed the module and target. Omitting the
        field or passing any other value rejects the call.
    """
    engagement_id = _coerce_engagement_id(params)
    module = _require_exploitation_module(params)
    target = _require_text(params, "target", max_length=512)
    roe_id = _require_text(params, "roe_id", max_length=128)
    authorized = _require_bool(params, "authorized")
    if authorized is not True:
        raise MCPError(
            _INVALID_PARAMS,
            "authorized must be the literal boolean true",
            data={"module": module, "target": target},
        )
    rationale = _optional_text(params, "rationale", max_length=1024)

    # The operator's identity comes from the auth context when present
    # so audit rows attribute intent correctly even over MCP transport.
    operator_claim = None
    if ctx.auth is not None:
        operator_claim = ctx.auth.normalized_role() or None
    operator_text = operator_claim or "mcp-authorized"

    conn = _open_engagement_db(engagement_id, ctx)
    try:
        try:
            cursor = conn.execute(
                """
                INSERT INTO audit_log (
                    engagement_id, phase, module, action, target, result, operator
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    engagement_id,
                    _EXPLOITATION_AUDIT_PHASE,
                    module,
                    "start_intent",
                    target,
                    json.dumps(
                        {
                            "roe_id": roe_id,
                            "rationale": rationale,
                            "authorized": True,
                            "source": "mcp",
                        },
                        sort_keys=True,
                    ),
                    operator_text,
                ),
            )
        except sqlite3.OperationalError as exc:
            raise MCPError(
                _INTERNAL_ERROR,
                f"engagement DB missing audit_log schema: {exc}",
                data={"engagement_id": engagement_id},
            ) from exc
        audit_id = int(cursor.lastrowid or 0)
        conn.commit()
        row = conn.execute(
            "SELECT id, phase, module, action, target, result, operator, logged_at "
            "FROM audit_log WHERE id = ?",
            (audit_id,),
        ).fetchone()
    finally:
        conn.close()
    if row is None:  # pragma: no cover — defensive
        raise MCPError(
            _INTERNAL_ERROR,
            f"audit_log row {audit_id} not visible after insert",
        )
    return {
        "engagement_id": engagement_id,
        "module": module,
        "target": target,
        "roe_id": roe_id,
        "authorized": True,
        "audit_log": {
            "id": int(row[0]),
            "phase": row[1],
            "module": row[2],
            "action": row[3],
            "target": row[4],
            "result": row[5],
            "operator": row[6],
            "logged_at": row[7],
        },
    }


_TOOL_DEFINITIONS: tuple[dict[str, Any], ...] = (
    {
        "name": "forge.engagements.list",
        "description": "List engagements across local engagement databases (read-only).",
        "handler": _tool_engagements_list,
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": _MAX_LIMIT,
                    "description": "Maximum number of engagements to return.",
                },
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "forge.findings.list",
        "description": "List vulnerability findings for an engagement (read-only).",
        "handler": _tool_findings_list,
        "inputSchema": {
            "type": "object",
            "properties": {
                "engagement_id": {
                    "type": "integer",
                    "minimum": 1,
                    "description": "Target engagement identifier.",
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": _MAX_LIMIT,
                },
            },
            "required": ["engagement_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "forge.hosts.list",
        "description": "List discovered hosts for an engagement (read-only).",
        "handler": _tool_hosts_list,
        "inputSchema": {
            "type": "object",
            "properties": {
                "engagement_id": {
                    "type": "integer",
                    "minimum": 1,
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": _MAX_LIMIT,
                },
            },
            "required": ["engagement_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "forge.graph.get",
        "description": "Latest attack-graph snapshot for an engagement (read-only).",
        "handler": _tool_graph_get,
        "inputSchema": {
            "type": "object",
            "properties": {
                "engagement_id": {
                    "type": "integer",
                    "minimum": 1,
                },
            },
            "required": ["engagement_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "forge.findings.create",
        "description": (
            "Create a new vulnerability finding for an engagement. "
            "Requires write permission (AuthContext role or write_token)."
        ),
        "handler": _tool_findings_create,
        "requires_write": True,
        "inputSchema": {
            "type": "object",
            "properties": {
                "engagement_id": {"type": "integer", "minimum": 1},
                "vuln_type": {"type": "string", "minLength": 1, "maxLength": 128},
                "target_url": {"type": "string", "minLength": 1, "maxLength": 2048},
                "severity": {
                    "type": "string",
                    "enum": sorted(_SEVERITY_VALUES),
                },
                "title": {"type": "string", "minLength": 1, "maxLength": 512},
                "description": {"type": "string", "maxLength": 4096},
                "parameter": {"type": "string", "maxLength": 256},
                "cve_id": {"type": "string", "maxLength": 32},
                "evidence": {"type": "string", "maxLength": 512},
                "cvss_score": {"type": "number", "minimum": 0, "maximum": 10},
            },
            "required": ["engagement_id", "vuln_type", "target_url", "severity", "title"],
            "additionalProperties": False,
        },
    },
    {
        "name": "forge.intents.create",
        "description": (
            "Record a new recursion intent (Fact/Intent/Hint board). "
            "Requires write permission (AuthContext role or write_token)."
        ),
        "handler": _tool_intents_create,
        "requires_write": True,
        "inputSchema": {
            "type": "object",
            "properties": {
                "engagement_id": {"type": "integer", "minimum": 1},
                "target_seed": {"type": "string", "minLength": 1, "maxLength": 512},
                "rationale": {"type": "string", "maxLength": 4096},
                "source_fact_id": {"type": "string", "maxLength": 256},
                "seed_type": {"type": "string", "maxLength": 64},
                "intent_id": {"type": "string", "maxLength": 64},
            },
            "required": ["engagement_id", "target_seed"],
            "additionalProperties": False,
        },
    },
    {
        "name": "forge.exploitation.status",
        "description": (
            "Return the exploitation state of an engagement: declared "
            "status, recent exploitation audit events, scope-authorized "
            "capability flags, and payload inventory. Read-only."
        ),
        "handler": _tool_exploitation_status,
        "inputSchema": {
            "type": "object",
            "properties": {
                "engagement_id": {"type": "integer", "minimum": 1},
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": _MAX_LIMIT,
                },
            },
            "required": ["engagement_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "forge.exploitation.start",
        "description": (
            "Record an operator-authorized exploitation module start intent "
            "to the engagement's audit_log. The actual module execution "
            "runs through the normal audited CLI/orchestrator path; this "
            "tool only persists the intent so coding agents can hand off. "
            "Requires write permission AND the literal `authorized: true` "
            "flag in the arguments; omitting the flag rejects the call."
        ),
        "handler": _tool_exploitation_start,
        "requires_write": True,
        "requires_explicit_authorization": True,
        "inputSchema": {
            "type": "object",
            "properties": {
                "engagement_id": {"type": "integer", "minimum": 1},
                "module": {
                    "type": "string",
                    "enum": sorted(_EXPLOITATION_MODULES),
                },
                "target": {"type": "string", "minLength": 1, "maxLength": 512},
                "roe_id": {"type": "string", "minLength": 1, "maxLength": 128},
                "authorized": {"type": "boolean"},
                "rationale": {"type": "string", "maxLength": 1024},
            },
            "required": ["engagement_id", "module", "target", "roe_id", "authorized"],
            "additionalProperties": False,
        },
    },
)


def build_tool_registry() -> dict[str, dict[str, Any]]:
    """Return a ``{tool_name: definition}`` map of every exposed MCP tool."""
    return {tool["name"]: dict(tool) for tool in _TOOL_DEFINITIONS}


def _public_tool_descriptor(tool: Mapping[str, Any]) -> dict[str, Any]:
    """Strip the ``handler`` callable before shipping the descriptor over JSON."""
    return {
        "name": tool["name"],
        "description": tool["description"],
        "inputSchema": tool["inputSchema"],
    }


# ---------------------------------------------------------------------------
# JSON-RPC 2.0 dispatcher


def _validate_jsonrpc_envelope(payload: Any) -> tuple[Any, str, Mapping[str, Any] | None]:
    if not isinstance(payload, Mapping):
        raise MCPError(_INVALID_REQUEST, "request must be a JSON object")
    version = payload.get("jsonrpc")
    if version != "2.0":
        raise MCPError(_INVALID_REQUEST, "jsonrpc version must be '2.0'")
    method = payload.get("method")
    if not isinstance(method, str) or not method:
        raise MCPError(_INVALID_REQUEST, "method must be a non-empty string")
    params = payload.get("params")
    if params is not None and not isinstance(params, Mapping):
        raise MCPError(_INVALID_PARAMS, "params must be a JSON object when present")
    request_id = payload.get("id")
    return request_id, method, params


def _handle_initialize(_params: Mapping[str, Any] | None, _ctx: ServerContext) -> dict[str, Any]:
    return {
        "protocolVersion": MCP_PROTOCOL_VERSION,
        "capabilities": {
            "tools": {"listChanged": False},
            "resources": {},
            "prompts": {},
        },
        "serverInfo": {
            "name": "forge-mcp",
            "version": MCP_SERVER_VERSION,
            "description": "FORGE engagement evidence (read-only) over MCP",
        },
    }


def _handle_tools_list(_params: Mapping[str, Any] | None, ctx: ServerContext) -> dict[str, Any]:
    return {"tools": [_public_tool_descriptor(t) for t in ctx.tools.values()]}


def _handle_tools_call(params: Mapping[str, Any] | None, ctx: ServerContext) -> dict[str, Any]:
    if not params:
        raise MCPError(_INVALID_PARAMS, "tools/call requires {name, arguments}")
    name = params.get("name")
    if not isinstance(name, str) or not name:
        raise MCPError(_INVALID_PARAMS, "tools/call name must be a non-empty string")
    arguments = params.get("arguments", {}) or {}
    if not isinstance(arguments, Mapping):
        raise MCPError(_INVALID_PARAMS, "tools/call arguments must be a JSON object")
    tool = ctx.tools.get(name)
    if tool is None:
        raise MCPError(_METHOD_NOT_FOUND, f"unknown tool: {name}")
    if tool.get("requires_write"):
        auth = ctx.auth
        if auth is None or not auth.has_write_access(ctx):
            raise MCPError(
                _INVALID_REQUEST,
                f"tool {name!r} requires write permission "
                "(set AuthContext.role to an allowed write role, "
                "or supply a matching write_token)",
                data={
                    "tool": name,
                    "required": "write",
                    "has_role": bool(auth and auth.normalized_role()),
                    "has_write_token": bool(auth and auth.write_token),
                },
            )
    handler: ToolHandler = tool["handler"]
    data = handler(arguments, ctx)
    return {
        "content": [
            {
                "type": "text",
                "text": json.dumps(data, sort_keys=True, separators=(",", ":")),
            }
        ],
        "structuredContent": data,
        "isError": False,
    }


_RPC_METHODS: dict[str, Callable[[Mapping[str, Any] | None, ServerContext], dict[str, Any]]] = {
    "initialize": _handle_initialize,
    "tools/list": _handle_tools_list,
    "tools/call": _handle_tools_call,
}


def dispatch_jsonrpc(
    payload: Any,
    ctx: ServerContext,
    auth: AuthContext | None = None,
) -> MCPResponse | None:
    """Validate and dispatch a single JSON-RPC 2.0 request.

    Returns ``None`` for notifications (payload without an ``id`` field).
    The optional ``auth`` context is bound to ``ctx.auth`` for the
    duration of the dispatch so write-capable tools can gate on it; the
    binding is reset on return to avoid leaking per-request state across
    threads.
    """
    try:
        request_id, method, params = _validate_jsonrpc_envelope(payload)
    except MCPError as exc:
        return MCPResponse(id=None, error=exc)

    handler = _RPC_METHODS.get(method)
    if handler is None:
        return MCPResponse(id=request_id, error=MCPError(_METHOD_NOT_FOUND, f"unknown method: {method}"))

    previous_auth = ctx.auth
    ctx.auth = auth
    try:
        result = handler(params, ctx)
    except MCPError as exc:
        return MCPResponse(id=request_id, error=exc)
    except Exception as exc:  # noqa: BLE001 — surface the raw error as JSON-RPC
        LOGGER.exception("MCP handler raised: %s", exc)
        return MCPResponse(
            id=request_id,
            error=MCPError(_INTERNAL_ERROR, f"internal server error: {exc}"),
        )
    finally:
        ctx.auth = previous_auth

    # Notifications (no `id` field) MUST NOT get a response per JSON-RPC 2.0.
    if request_id is None and "id" not in dict(payload):
        return None
    return MCPResponse(id=request_id, result=result)


# ---------------------------------------------------------------------------
# HTTP transport (loopback only, bearer-token authenticated)


def _is_loopback(host: str) -> bool:
    normalized = (host or "").strip().lower()
    if normalized in {"localhost", "127.0.0.1", "::1"}:
        return True
    try:
        info = socket.getaddrinfo(normalized, None)
    except socket.gaierror:
        return False
    for family, _socktype, _proto, _canonname, addr in info:
        ip = addr[0]
        if family == socket.AF_INET and ip.startswith("127."):
            continue
        if family == socket.AF_INET6 and ip in {"::1"}:
            continue
        return False
    return bool(info)


def _make_request_handler(server: "ForgeMCPServer") -> type[BaseHTTPRequestHandler]:
    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 — stdlib signature
            # Suppress default stderr logging; routed through LOGGER.
            LOGGER.debug("mcp.http: %s", format % args)

        def _write_json(self, code: int, payload: Mapping[str, Any]) -> None:
            body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def _require_loopback(self) -> bool:
            client_host = self.client_address[0] if self.client_address else ""
            if client_host in {"127.0.0.1", "::1"} or client_host.startswith("127."):
                return True
            self._write_json(403, {"error": "mcp server is loopback-only"})
            return False

        def _authorized(self) -> bool:
            expected = server.auth_token
            if not expected:
                return True
            header = self.headers.get("Authorization", "")
            if not header.startswith("Bearer "):
                self._write_json(401, {"error": "missing bearer token"})
                return False
            provided = header.split(" ", 1)[1].strip()
            if not secrets.compare_digest(provided, expected):
                self._write_json(401, {"error": "invalid bearer token"})
                return False
            return True

        def do_POST(self) -> None:  # noqa: N802 — stdlib override
            if not self._require_loopback():
                return
            if not self._authorized():
                return
            if self.path != "/mcp":
                self._write_json(404, {"error": "unknown path"})
                return
            try:
                length = int(self.headers.get("Content-Length", "0") or "0")
            except ValueError:
                self._write_json(400, {"error": "invalid Content-Length"})
                return
            if length <= 0 or length > _MAX_REQUEST_BYTES:
                self._write_json(413, {"error": "request too large"})
                return
            raw = self.rfile.read(length)
            try:
                payload = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                self._write_json(
                    200,
                    MCPResponse(id=None, error=MCPError(_PARSE_ERROR, "parse error")).to_dict(),
                )
                return
            # Extract per-request AuthContext from headers; both role and
            # write_token are optional and only consulted by write-capable
            # tools. The HTTP transport treats missing values as empty.
            auth = AuthContext(
                role=self.headers.get("X-Forge-Role", "") or None,
                write_token=self.headers.get("X-Forge-Write-Token", "") or None,
                source="http",
            )
            # Batch requests are a MUST for JSON-RPC 2.0, but MCP typically
            # uses single-call semantics.  Support both for robustness.
            if isinstance(payload, list):
                responses: list[dict[str, Any]] = []
                for item in payload:
                    resp = dispatch_jsonrpc(item, server.context, auth=auth)
                    if resp is not None:
                        responses.append(resp.to_dict())
                self._write_json(200, {"responses": responses} if responses else {"responses": []})
                return
            resp = dispatch_jsonrpc(payload, server.context, auth=auth)
            if resp is None:
                self.send_response(204)
                self.end_headers()
                return
            self._write_json(200, resp.to_dict())

        def do_GET(self) -> None:  # noqa: N802 — stdlib override
            if not self._require_loopback():
                return
            if self.path == "/healthz":
                self._write_json(200, {"status": "ok", "server": "forge-mcp"})
                return
            self._write_json(404, {"error": "unknown path"})

    return _Handler


class ForgeMCPServer:
    """Thin wrapper around :class:`ThreadingHTTPServer` for the FORGE MCP server.

    The HTTP transport is loopback-bound and bearer-token authenticated;
    the ``run_stdio()`` method services stdio clients instead.
    """

    def __init__(
        self,
        *,
        data_dir: str | Path | None = None,
        host: str = "127.0.0.1",
        port: int = 0,
        auth_token: str | None = None,
        require_token: bool = True,
        write_token: str | None = None,
        allowed_write_roles: tuple[str, ...] = DEFAULT_WRITE_ROLES,
    ) -> None:
        if not _is_loopback(host):
            raise ValueError(
                f"MCP server refuses non-loopback bind address: {host!r}"
            )
        resolved_data_dir = Path(
            data_dir
            or os.environ.get("FORGE_DATA_DIR")
            or _DEFAULT_DATA_DIR
        ).expanduser()
        self.context = ServerContext(
            data_dir=resolved_data_dir,
            tools=build_tool_registry(),
            expected_write_token=write_token or None,
            allowed_write_roles=tuple(allowed_write_roles),
        )
        self.host = host
        self.port = int(port)
        if auth_token is None and require_token:
            auth_token = secrets.token_urlsafe(32)
        self.auth_token = auth_token or None
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    # ------------------------------------------------------------------
    # HTTP

    def start(self) -> tuple[str, int]:
        """Start the HTTP server on a daemon thread and return ``(host, port)``."""
        handler = _make_request_handler(self)
        self._httpd = ThreadingHTTPServer((self.host, self.port), handler)
        bound_host, bound_port = self._httpd.server_address[0], self._httpd.server_address[1]
        self.host = bound_host
        self.port = int(bound_port)
        self._thread = threading.Thread(
            target=self._httpd.serve_forever,
            name="forge-mcp-http",
            daemon=True,
        )
        self._thread.start()
        return self.host, self.port

    def stop(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
        self._thread = None

    def serve_forever(self) -> None:
        """Block the current thread until stopped."""
        self.start()
        try:
            while self._thread is not None and self._thread.is_alive():
                time.sleep(0.5)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    # ------------------------------------------------------------------
    # Stdio

    def run_stdio(self) -> None:
        """Serve JSON-RPC over stdin/stdout (one JSON object per line)."""
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                sys.stdout.write(
                    json.dumps(
                        MCPResponse(id=None, error=MCPError(_PARSE_ERROR, "parse error")).to_dict(),
                        separators=(",", ":"),
                    )
                    + "\n"
                )
                sys.stdout.flush()
                continue
            resp = dispatch_jsonrpc(payload, self.context)
            if resp is None:
                continue
            sys.stdout.write(json.dumps(resp.to_dict(), separators=(",", ":")) + "\n")
            sys.stdout.flush()


# ---------------------------------------------------------------------------
# Public helpers for tests


__all__ = [
    "DEFAULT_WRITE_ROLES",
    "MCP_PROTOCOL_VERSION",
    "MCP_SERVER_VERSION",
    "AuthContext",
    "ForgeMCPServer",
    "MCPError",
    "MCPResponse",
    "ServerContext",
    "build_tool_registry",
    "dispatch_jsonrpc",
]
