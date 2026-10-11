"""Unit tests for forge.mcp.server (Wave 3, Explore #22)."""

from __future__ import annotations

import json
import sqlite3
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from forge.mcp.server import (
    MCP_PROTOCOL_VERSION,
    MCP_SERVER_VERSION,
    ForgeMCPServer,
    MCPError,
    MCPResponse,
    ServerContext,
    _is_loopback,
    build_tool_registry,
    dispatch_jsonrpc,
)


# ---------------------------------------------------------------------------
# Fixtures: seed a minimal engagement DB for the four tools


def _seed_engagement_db(path: Path, engagement_id: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    try:
        conn.executescript(
            """
            CREATE TABLE engagements (
                id INTEGER PRIMARY KEY,
                name TEXT,
                scope_json TEXT,
                status TEXT,
                operator TEXT,
                metadata_json TEXT,
                created_at TEXT,
                updated_at TEXT,
                workspace_id INTEGER
            );
            CREATE TABLE hosts (
                id INTEGER PRIMARY KEY,
                engagement_id INTEGER,
                ip TEXT,
                hostname TEXT,
                os_family TEXT,
                host_context TEXT,
                in_scope INTEGER,
                discovered_at TEXT
            );
            CREATE TABLE vulnerability_findings (
                id INTEGER PRIMARY KEY,
                engagement_id INTEGER,
                vuln_type TEXT,
                target_url TEXT,
                parameter TEXT,
                severity TEXT,
                title TEXT,
                description TEXT,
                evidence TEXT,
                cvss_score REAL,
                found_at TEXT,
                cloud_provider TEXT,
                resource_id TEXT,
                compliance_control TEXT,
                remediation_cli TEXT,
                cve_id TEXT,
                cvss_version TEXT,
                cvss_vector TEXT,
                cwe_ids TEXT,
                cpe_matches TEXT,
                epss_score REAL,
                epss_percentile REAL,
                cisa_kev INTEGER,
                cisa_kev_due_date TEXT,
                attack_techniques TEXT,
                stix_external_refs_json TEXT,
                standards_json TEXT
            );
            CREATE TABLE attack_graph_snapshots (
                id INTEGER PRIMARY KEY,
                engagement_id INTEGER,
                snapshot_at TEXT,
                node_count INTEGER,
                edge_count INTEGER,
                critical_path_weight REAL,
                min_severity TEXT,
                pruned INTEGER,
                graph_json TEXT,
                mermaid_output TEXT,
                dot_output TEXT
            );
            """
        )
        conn.execute(
            "INSERT INTO engagements (id, name, status, operator, created_at, updated_at) "
            "VALUES (?, 'demo-engagement', 'active', 'operator', '2026-01-01', '2026-01-02')",
            (engagement_id,),
        )
        conn.execute(
            "INSERT INTO hosts (engagement_id, ip, hostname, os_family, in_scope, discovered_at) "
            "VALUES (?, '10.0.0.1', 'host-1.example', 'linux', 1, '2026-01-01')",
            (engagement_id,),
        )
        conn.execute(
            "INSERT INTO vulnerability_findings "
            "(engagement_id, vuln_type, target_url, severity, title, cvss_score, cve_id, found_at) "
            "VALUES (?, 'cve', 'https://host-1.example', 'high', 'Example CVE', 7.5, 'CVE-2026-0001', '2026-01-02')",
            (engagement_id,),
        )
        conn.execute(
            "INSERT INTO attack_graph_snapshots "
            "(engagement_id, snapshot_at, node_count, edge_count, graph_json) "
            "VALUES (?, '2026-01-03', 4, 3, '{\"nodes\": [], \"edges\": []}')",
            (engagement_id,),
        )
        conn.commit()
    finally:
        conn.close()


@pytest.fixture()
def seeded_data_dir(tmp_path: Path) -> Path:
    data_dir = tmp_path / "forge-data"
    _seed_engagement_db(data_dir / "engagements" / "1001.db", 1001)
    return data_dir


@pytest.fixture()
def ctx(seeded_data_dir: Path) -> ServerContext:
    return ServerContext(
        data_dir=seeded_data_dir,
        tools=build_tool_registry(),
    )


# ---------------------------------------------------------------------------
# Tool registry


def test_tool_registry_exposes_four_tools():
    registry = build_tool_registry()
    assert set(registry.keys()) == {
        "forge.engagements.list",
        "forge.findings.list",
        "forge.hosts.list",
        "forge.graph.get",
    }
    for tool in registry.values():
        assert "inputSchema" in tool
        assert callable(tool["handler"])


# ---------------------------------------------------------------------------
# JSON-RPC envelope validation


def test_dispatch_requires_jsonrpc_version(ctx: ServerContext):
    resp = dispatch_jsonrpc({"method": "initialize", "id": 1}, ctx)
    assert resp is not None
    assert resp.error is not None
    assert resp.error.code == -32600


def test_dispatch_rejects_non_object_request(ctx: ServerContext):
    resp = dispatch_jsonrpc("hello", ctx)
    assert resp is not None
    assert resp.error is not None
    assert resp.error.code == -32600


def test_dispatch_unknown_method(ctx: ServerContext):
    resp = dispatch_jsonrpc(
        {"jsonrpc": "2.0", "method": "no.such.method", "id": 7},
        ctx,
    )
    assert resp is not None
    assert resp.error is not None
    assert resp.error.code == -32601
    assert resp.id == 7


def test_dispatch_notification_returns_none(ctx: ServerContext):
    # No ``id`` field = JSON-RPC notification. No response.
    resp = dispatch_jsonrpc(
        {"jsonrpc": "2.0", "method": "initialize"},
        ctx,
    )
    assert resp is None


# ---------------------------------------------------------------------------
# initialize + tools/list


def test_initialize_returns_server_info(ctx: ServerContext):
    resp = dispatch_jsonrpc(
        {"jsonrpc": "2.0", "method": "initialize", "id": 1},
        ctx,
    )
    assert resp is not None
    assert resp.error is None
    assert resp.result["protocolVersion"] == MCP_PROTOCOL_VERSION
    assert resp.result["serverInfo"]["version"] == MCP_SERVER_VERSION
    assert resp.result["serverInfo"]["name"] == "forge-mcp"


def test_tools_list_returns_descriptors(ctx: ServerContext):
    resp = dispatch_jsonrpc(
        {"jsonrpc": "2.0", "method": "tools/list", "id": 2},
        ctx,
    )
    assert resp is not None
    assert resp.error is None
    names = {tool["name"] for tool in resp.result["tools"]}
    assert names == {
        "forge.engagements.list",
        "forge.findings.list",
        "forge.hosts.list",
        "forge.graph.get",
    }
    for tool in resp.result["tools"]:
        assert "inputSchema" in tool
        assert "handler" not in tool  # handler stripped before transport


# ---------------------------------------------------------------------------
# tools/call: engagements.list


def test_tool_engagements_list_returns_seeded_engagement(ctx: ServerContext):
    resp = dispatch_jsonrpc(
        {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": 10,
            "params": {"name": "forge.engagements.list", "arguments": {}},
        },
        ctx,
    )
    assert resp is not None
    assert resp.error is None
    structured = resp.result["structuredContent"]
    assert structured["total_count"] == 1
    assert structured["engagements"][0]["id"] == 1001
    assert structured["engagements"][0]["status"] == "active"


# ---------------------------------------------------------------------------
# tools/call: findings.list


def test_tool_findings_list_requires_engagement_id(ctx: ServerContext):
    resp = dispatch_jsonrpc(
        {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": 11,
            "params": {"name": "forge.findings.list", "arguments": {}},
        },
        ctx,
    )
    assert resp is not None
    assert resp.error is not None
    assert resp.error.code == -32602


def test_tool_findings_list_returns_findings(ctx: ServerContext):
    resp = dispatch_jsonrpc(
        {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": 12,
            "params": {
                "name": "forge.findings.list",
                "arguments": {"engagement_id": 1001},
            },
        },
        ctx,
    )
    assert resp is not None
    assert resp.error is None
    structured = resp.result["structuredContent"]
    assert structured["engagement_id"] == 1001
    assert structured["total_count"] == 1
    assert structured["findings"][0]["cve_id"] == "CVE-2026-0001"


def test_tool_findings_list_rejects_bad_engagement_id(ctx: ServerContext):
    resp = dispatch_jsonrpc(
        {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": 13,
            "params": {
                "name": "forge.findings.list",
                "arguments": {"engagement_id": "not-an-int"},
            },
        },
        ctx,
    )
    assert resp is not None
    assert resp.error is not None
    assert resp.error.code == -32602


# ---------------------------------------------------------------------------
# tools/call: hosts.list


def test_tool_hosts_list_returns_hosts(ctx: ServerContext):
    resp = dispatch_jsonrpc(
        {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": 14,
            "params": {
                "name": "forge.hosts.list",
                "arguments": {"engagement_id": 1001},
            },
        },
        ctx,
    )
    assert resp is not None
    assert resp.error is None
    structured = resp.result["structuredContent"]
    assert structured["engagement_id"] == 1001
    assert structured["total_count"] == 1
    assert structured["hosts"][0]["ip"] == "10.0.0.1"
    assert structured["hosts"][0]["in_scope"] is True


def test_tool_hosts_list_missing_engagement(ctx: ServerContext):
    resp = dispatch_jsonrpc(
        {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": 15,
            "params": {
                "name": "forge.hosts.list",
                "arguments": {"engagement_id": 9999},
            },
        },
        ctx,
    )
    assert resp is not None
    assert resp.error is not None
    assert resp.error.code == -32602  # invalid params -> engagement not found


# ---------------------------------------------------------------------------
# tools/call: graph.get


def test_tool_graph_get_returns_latest_snapshot(ctx: ServerContext):
    resp = dispatch_jsonrpc(
        {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": 16,
            "params": {
                "name": "forge.graph.get",
                "arguments": {"engagement_id": 1001},
            },
        },
        ctx,
    )
    assert resp is not None
    assert resp.error is None
    structured = resp.result["structuredContent"]
    assert structured["engagement_id"] == 1001
    assert structured["has_snapshot"] is True
    assert structured["snapshot"]["node_count"] == 4
    assert structured["snapshot"]["edge_count"] == 3
    assert structured["snapshot"]["graph"] == {"nodes": [], "edges": []}


# ---------------------------------------------------------------------------
# tools/call: unknown tool


def test_tools_call_unknown_tool(ctx: ServerContext):
    resp = dispatch_jsonrpc(
        {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": 17,
            "params": {"name": "forge.nope", "arguments": {}},
        },
        ctx,
    )
    assert resp is not None
    assert resp.error is not None
    assert resp.error.code == -32601


# ---------------------------------------------------------------------------
# limit enforcement


def test_tool_engagements_list_respects_limit(seeded_data_dir: Path, tmp_path: Path):
    # Seed a second engagement.
    _seed_engagement_db(seeded_data_dir / "engagements" / "1002.db", 1002)
    ctx = ServerContext(
        data_dir=seeded_data_dir,
        tools=build_tool_registry(),
    )
    resp = dispatch_jsonrpc(
        {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": 18,
            "params": {
                "name": "forge.engagements.list",
                "arguments": {"limit": 1},
            },
        },
        ctx,
    )
    assert resp is not None
    assert resp.error is None
    assert resp.result["structuredContent"]["total_count"] == 1


# ---------------------------------------------------------------------------
# Loopback / token guards


def test_server_rejects_non_loopback_bind():
    with pytest.raises(ValueError, match="loopback"):
        ForgeMCPServer(host="0.0.0.0")


def test_is_loopback_recognizes_standard_values():
    assert _is_loopback("127.0.0.1")
    assert _is_loopback("::1")
    assert _is_loopback("localhost")
    assert not _is_loopback("0.0.0.0")
    assert not _is_loopback("192.168.1.5")


# ---------------------------------------------------------------------------
# HTTP transport


def _http_rpc(url: str, token: str | None, payload: dict) -> dict:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read().decode("utf-8"))


def test_http_transport_requires_token(seeded_data_dir: Path):
    server = ForgeMCPServer(data_dir=seeded_data_dir, host="127.0.0.1", port=0)
    host, port = server.start()
    try:
        url = f"http://{host}:{port}/mcp"
        with pytest.raises(urllib.error.HTTPError) as excinfo:
            _http_rpc(
                url,
                token=None,
                payload={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
            )
        assert excinfo.value.code == 401
    finally:
        server.stop()


def test_http_transport_dispatches_initialize(seeded_data_dir: Path):
    server = ForgeMCPServer(data_dir=seeded_data_dir, host="127.0.0.1", port=0)
    host, port = server.start()
    try:
        url = f"http://{host}:{port}/mcp"
        resp = _http_rpc(
            url,
            token=server.auth_token,
            payload={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
        )
        assert resp["jsonrpc"] == "2.0"
        assert resp["result"]["serverInfo"]["name"] == "forge-mcp"
    finally:
        server.stop()


def test_http_transport_dispatches_tools_call(seeded_data_dir: Path):
    server = ForgeMCPServer(data_dir=seeded_data_dir, host="127.0.0.1", port=0)
    host, port = server.start()
    try:
        url = f"http://{host}:{port}/mcp"
        resp = _http_rpc(
            url,
            token=server.auth_token,
            payload={
                "jsonrpc": "2.0",
                "id": 42,
                "method": "tools/call",
                "params": {
                    "name": "forge.engagements.list",
                    "arguments": {},
                },
            },
        )
        assert resp["id"] == 42
        assert resp["result"]["structuredContent"]["engagements"][0]["id"] == 1001
    finally:
        server.stop()


def test_http_health_endpoint(seeded_data_dir: Path):
    server = ForgeMCPServer(data_dir=seeded_data_dir, host="127.0.0.1", port=0)
    host, port = server.start()
    try:
        with urllib.request.urlopen(f"http://{host}:{port}/healthz", timeout=5) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
            assert payload["status"] == "ok"
            assert payload["server"] == "forge-mcp"
    finally:
        server.stop()


# ---------------------------------------------------------------------------
# Error envelope


def test_mcp_error_includes_data_when_present():
    err = MCPError(-32602, "bad input", data={"field": "limit"})
    payload = err.to_dict()
    assert payload["code"] == -32602
    assert payload["data"]["field"] == "limit"


def test_mcp_response_error_vs_result_envelope():
    ok = MCPResponse(id=1, result={"x": 1}).to_dict()
    err = MCPResponse(id=2, error=MCPError(-32601, "nope")).to_dict()
    assert "result" in ok and "error" not in ok
    assert "error" in err and "result" not in err
