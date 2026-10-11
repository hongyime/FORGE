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
# Server context (shared across tool handlers)


@dataclass
class ServerContext:
    """Context passed to every tool invocation."""

    data_dir: Path
    limit_default: int = _DEFAULT_LIMIT
    limit_max: int = _MAX_LIMIT
    tools: dict[str, dict[str, Any]] = field(default_factory=dict)

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


def dispatch_jsonrpc(payload: Any, ctx: ServerContext) -> MCPResponse | None:
    """Validate and dispatch a single JSON-RPC 2.0 request.

    Returns ``None`` for notifications (payload without an ``id`` field).
    """
    try:
        request_id, method, params = _validate_jsonrpc_envelope(payload)
    except MCPError as exc:
        return MCPResponse(id=None, error=exc)

    handler = _RPC_METHODS.get(method)
    if handler is None:
        return MCPResponse(id=request_id, error=MCPError(_METHOD_NOT_FOUND, f"unknown method: {method}"))

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
            # Batch requests are a MUST for JSON-RPC 2.0, but MCP typically
            # uses single-call semantics.  Support both for robustness.
            if isinstance(payload, list):
                responses: list[dict[str, Any]] = []
                for item in payload:
                    resp = dispatch_jsonrpc(item, server.context)
                    if resp is not None:
                        responses.append(resp.to_dict())
                self._write_json(200, {"responses": responses} if responses else {"responses": []})
                return
            resp = dispatch_jsonrpc(payload, server.context)
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
    "MCP_PROTOCOL_VERSION",
    "MCP_SERVER_VERSION",
    "ForgeMCPServer",
    "MCPError",
    "MCPResponse",
    "ServerContext",
    "build_tool_registry",
    "dispatch_jsonrpc",
]
