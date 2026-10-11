"""Unit tests for forge.mcp.server (Wave 3, Explore #22)."""

from __future__ import annotations

import json
import sqlite3
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from forge.mcp.server import (
    DEFAULT_WRITE_ROLES,
    MCP_PROTOCOL_VERSION,
    MCP_SERVER_VERSION,
    AuthContext,
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
                vuln_type TEXT NOT NULL,
                target_url TEXT NOT NULL,
                parameter TEXT,
                severity TEXT NOT NULL
                    CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO')),
                title TEXT NOT NULL,
                description TEXT,
                evidence TEXT,
                cvss_score REAL,
                found_at TEXT DEFAULT CURRENT_TIMESTAMP,
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
                standards_json TEXT,
                UNIQUE (engagement_id, vuln_type, target_url, parameter)
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
            CREATE TABLE audit_log (
                id INTEGER PRIMARY KEY,
                engagement_id INTEGER,
                phase TEXT,
                module TEXT,
                action TEXT NOT NULL,
                target TEXT,
                result TEXT,
                operator TEXT,
                logged_at TEXT DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE recursion_intents (
                intent_id TEXT PRIMARY KEY,
                source_fact_id TEXT,
                target_seed TEXT NOT NULL,
                seed_type TEXT,
                rationale TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                claimed_by TEXT,
                claimed_at TEXT,
                completed_fact_id TEXT,
                status TEXT NOT NULL DEFAULT 'open'
                    CHECK (status IN ('open','claimed','completed','abandoned')),
                engagement_id TEXT
            );
            CREATE TABLE payloads (
                id INTEGER PRIMARY KEY,
                engagement_id INTEGER
            );
            """
        )
        scope_json = json.dumps(
            {
                "domains": ["example.com"],
                "policy": {
                    "credential_capture": True,
                    "post_login_automation": False,
                    "autonomous_exploit": False,
                    "goal_directed": False,
                },
            },
            sort_keys=True,
        )
        conn.execute(
            "INSERT INTO engagements (id, name, scope_json, status, operator, created_at, updated_at) "
            "VALUES (?, 'demo-engagement', ?, 'active', 'operator', '2026-01-01', '2026-01-02')",
            (engagement_id, scope_json),
        )
        conn.execute(
            "INSERT INTO hosts (engagement_id, ip, hostname, os_family, in_scope, discovered_at) "
            "VALUES (?, '10.0.0.1', 'host-1.example', 'linux', 1, '2026-01-01')",
            (engagement_id,),
        )
        conn.execute(
            "INSERT INTO vulnerability_findings "
            "(engagement_id, vuln_type, target_url, severity, title, cvss_score, cve_id, found_at) "
            "VALUES (?, 'cve', 'https://host-1.example', 'HIGH', 'Example CVE', 7.5, 'CVE-2026-0001', '2026-01-02')",
            (engagement_id,),
        )
        conn.execute(
            "INSERT INTO attack_graph_snapshots "
            "(engagement_id, snapshot_at, node_count, edge_count, graph_json) "
            "VALUES (?, '2026-01-03', 4, 3, '{\"nodes\": [], \"edges\": []}')",
            (engagement_id,),
        )
        conn.execute(
            "INSERT INTO audit_log (engagement_id, phase, module, action, target, result, operator) "
            "VALUES (?, 'exploitation', 'credential_capture', 'start_intent', 'https://example.com/login', "
            "'{\"status\": \"queued\"}', 'operator')",
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


def test_tool_registry_exposes_eight_tools():
    """4 original read-only tools + 4 write/exploitation tools from Task 5."""
    registry = build_tool_registry()
    assert set(registry.keys()) == {
        "forge.engagements.list",
        "forge.findings.list",
        "forge.hosts.list",
        "forge.graph.get",
        "forge.findings.create",
        "forge.intents.create",
        "forge.exploitation.status",
        "forge.exploitation.start",
    }
    for tool in registry.values():
        assert "inputSchema" in tool
        assert callable(tool["handler"])


def test_write_capable_tools_declare_requires_write():
    registry = build_tool_registry()
    expected_write = {
        "forge.findings.create",
        "forge.intents.create",
        "forge.exploitation.start",
    }
    for name, tool in registry.items():
        if name in expected_write:
            assert tool.get("requires_write") is True, name
        else:
            assert not tool.get("requires_write"), name


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
        "forge.findings.create",
        "forge.intents.create",
        "forge.exploitation.status",
        "forge.exploitation.start",
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



# ===========================================================================
# Task 5 — Write-capable MCP tools
# ===========================================================================


# ---------------------------------------------------------------------------
# AuthContext basics


def test_auth_context_default_has_no_write_access():
    ctx = ServerContext(data_dir=Path("/tmp"), tools=build_tool_registry())
    auth = AuthContext()
    assert not auth.has_write_access(ctx)


def test_auth_context_role_grants_write_access():
    ctx = ServerContext(data_dir=Path("/tmp"), tools=build_tool_registry())
    assert AuthContext(role="operator").has_write_access(ctx)
    assert AuthContext(role="OPERATOR").has_write_access(ctx)
    assert AuthContext(role="Owner").has_write_access(ctx)
    assert AuthContext(role="admin").has_write_access(ctx)


def test_auth_context_unknown_role_rejected():
    ctx = ServerContext(data_dir=Path("/tmp"), tools=build_tool_registry())
    assert not AuthContext(role="viewer").has_write_access(ctx)
    assert not AuthContext(role="guest").has_write_access(ctx)


def test_auth_context_write_token_grants_access_only_when_set_on_server():
    ctx = ServerContext(data_dir=Path("/tmp"), tools=build_tool_registry())
    # No expected_write_token on server → write_token claim ignored
    assert not AuthContext(write_token="any").has_write_access(ctx)
    ctx_with_token = ServerContext(
        data_dir=Path("/tmp"),
        tools=build_tool_registry(),
        expected_write_token="secret-forge-write-token-123",
    )
    assert AuthContext(write_token="secret-forge-write-token-123").has_write_access(
        ctx_with_token
    )
    assert not AuthContext(write_token="wrong").has_write_access(ctx_with_token)


def test_auth_context_custom_write_roles():
    ctx = ServerContext(
        data_dir=Path("/tmp"),
        tools=build_tool_registry(),
        allowed_write_roles=("custom_role",),
    )
    assert AuthContext(role="custom_role").has_write_access(ctx)
    # Original defaults no longer apply
    assert not AuthContext(role="operator").has_write_access(ctx)


# ---------------------------------------------------------------------------
# Write-capable tools reject calls without auth


def _call_tool(ctx: ServerContext, name: str, arguments: dict, *, auth: AuthContext | None = None):
    return dispatch_jsonrpc(
        {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": 100,
            "params": {"name": name, "arguments": arguments},
        },
        ctx,
        auth=auth,
    )


def test_findings_create_rejects_missing_auth(ctx: ServerContext):
    resp = _call_tool(
        ctx,
        "forge.findings.create",
        {
            "engagement_id": 1001,
            "vuln_type": "cve",
            "target_url": "https://new.example",
            "severity": "LOW",
            "title": "demo-finding",
        },
    )
    assert resp is not None
    assert resp.error is not None
    assert resp.error.code == -32600  # invalid request
    assert "write permission" in resp.error.message


def test_findings_create_rejects_wrong_role(ctx: ServerContext):
    resp = _call_tool(
        ctx,
        "forge.findings.create",
        {
            "engagement_id": 1001,
            "vuln_type": "cve",
            "target_url": "https://new.example",
            "severity": "LOW",
            "title": "demo-finding",
        },
        auth=AuthContext(role="viewer"),
    )
    assert resp.error is not None
    assert resp.error.code == -32600


def test_intents_create_rejects_missing_auth(ctx: ServerContext):
    resp = _call_tool(
        ctx,
        "forge.intents.create",
        {"engagement_id": 1001, "target_seed": "pivot.example"},
    )
    assert resp.error is not None
    assert resp.error.code == -32600


def test_exploitation_start_rejects_missing_auth(ctx: ServerContext):
    resp = _call_tool(
        ctx,
        "forge.exploitation.start",
        {
            "engagement_id": 1001,
            "module": "credential_capture",
            "target": "https://example.com/login",
            "roe_id": "ROE-123",
            "authorized": True,
        },
    )
    assert resp.error is not None
    assert resp.error.code == -32600


def test_exploitation_status_is_readonly_and_needs_no_auth(ctx: ServerContext):
    """Exploitation.status reads audit_log + scope — no write permission required."""
    resp = _call_tool(ctx, "forge.exploitation.status", {"engagement_id": 1001})
    assert resp.error is None
    structured = resp.result["structuredContent"]
    assert structured["engagement_id"] == 1001
    assert structured["status"] == "active"
    assert isinstance(structured["scope_authorized_capabilities"], dict)


# ---------------------------------------------------------------------------
# forge.findings.create — success + validation


def test_findings_create_success_with_role(ctx: ServerContext):
    resp = _call_tool(
        ctx,
        "forge.findings.create",
        {
            "engagement_id": 1001,
            "vuln_type": "cve",
            "target_url": "https://new.example",
            "severity": "medium",  # case-insensitive input
            "title": "Example New Finding",
            "description": "Non-blank description",
            "cvss_score": 5.0,
            "cve_id": "CVE-2026-0002",
        },
        auth=AuthContext(role="operator"),
    )
    assert resp.error is None, resp.error
    structured = resp.result["structuredContent"]
    assert structured["engagement_id"] == 1001
    finding = structured["finding"]
    assert finding["vuln_type"] == "cve"
    assert finding["target_url"] == "https://new.example"
    assert finding["severity"] == "MEDIUM"
    assert finding["cvss_score"] == 5.0
    assert finding["cve_id"] == "CVE-2026-0002"
    assert finding["id"] > 0


def test_findings_create_rejects_bad_severity(ctx: ServerContext):
    resp = _call_tool(
        ctx,
        "forge.findings.create",
        {
            "engagement_id": 1001,
            "vuln_type": "cve",
            "target_url": "https://bad-sev.example",
            "severity": "ULTRA_CRITICAL",
            "title": "nope",
        },
        auth=AuthContext(role="operator"),
    )
    assert resp.error is not None
    assert resp.error.code == -32602


def test_findings_create_rejects_duplicate(ctx: ServerContext):
    # SQL UNIQUE treats multiple NULLs as distinct, so use a concrete
    # parameter value to exercise the engagement_id/vuln_type/target_url/
    # parameter uniqueness constraint.
    auth = AuthContext(role="operator")
    resp = _call_tool(
        ctx,
        "forge.findings.create",
        {
            "engagement_id": 1001,
            "vuln_type": "cve_dup",
            "target_url": "https://dup.example",
            "severity": "LOW",
            "title": "dup-1",
            "parameter": "q",
        },
        auth=auth,
    )
    assert resp.error is None
    # Insert the same vuln/target/parameter again
    resp = _call_tool(
        ctx,
        "forge.findings.create",
        {
            "engagement_id": 1001,
            "vuln_type": "cve_dup",
            "target_url": "https://dup.example",
            "severity": "LOW",
            "title": "dup-2",
            "parameter": "q",
        },
        auth=auth,
    )
    assert resp.error is not None
    assert resp.error.code == -32602  # UNIQUE constraint violation


def test_findings_create_rejects_missing_required_fields(ctx: ServerContext):
    resp = _call_tool(
        ctx,
        "forge.findings.create",
        {"engagement_id": 1001, "severity": "LOW"},
        auth=AuthContext(role="operator"),
    )
    assert resp.error is not None
    assert resp.error.code == -32602


# ---------------------------------------------------------------------------
# forge.intents.create — success


def test_intents_create_success(ctx: ServerContext):
    resp = _call_tool(
        ctx,
        "forge.intents.create",
        {
            "engagement_id": 1001,
            "target_seed": "pivot.example",
            "rationale": "cloud_ref pivot from validated finding",
            "source_fact_id": "cloud_ref:42",
            "seed_type": "domain",
        },
        auth=AuthContext(role="operator"),
    )
    assert resp.error is None, resp.error
    structured = resp.result["structuredContent"]
    assert structured["engagement_id"] == 1001
    intent = structured["intent"]
    assert intent["target_seed"] == "pivot.example"
    assert intent["status"] == "open"
    assert intent["engagement_id"] == "1001"
    assert intent["seed_type"] == "domain"
    assert intent["intent_id"]


def test_intents_create_rejects_blank_target_seed(ctx: ServerContext):
    resp = _call_tool(
        ctx,
        "forge.intents.create",
        {"engagement_id": 1001, "target_seed": "   "},
        auth=AuthContext(role="operator"),
    )
    assert resp.error is not None
    assert resp.error.code == -32602


def test_intents_create_with_write_token(seeded_data_dir: Path):
    ctx_token = ServerContext(
        data_dir=seeded_data_dir,
        tools=build_tool_registry(),
        expected_write_token="forge-write-456",
    )
    resp = _call_tool(
        ctx_token,
        "forge.intents.create",
        {"engagement_id": 1001, "target_seed": "token.example"},
        auth=AuthContext(write_token="forge-write-456"),
    )
    assert resp.error is None, resp.error
    assert resp.result["structuredContent"]["intent"]["target_seed"] == "token.example"


# ---------------------------------------------------------------------------
# forge.exploitation.status


def test_exploitation_status_returns_recent_events(ctx: ServerContext):
    resp = _call_tool(ctx, "forge.exploitation.status", {"engagement_id": 1001})
    assert resp.error is None, resp.error
    structured = resp.result["structuredContent"]
    assert structured["recent_event_count"] == 1
    event = structured["recent_events"][0]
    assert event["phase"] == "exploitation"
    assert event["module"] == "credential_capture"
    assert event["target"] == "https://example.com/login"


def test_exploitation_status_parses_scope_policy(ctx: ServerContext):
    resp = _call_tool(ctx, "forge.exploitation.status", {"engagement_id": 1001})
    structured = resp.result["structuredContent"]
    caps = structured["scope_authorized_capabilities"]
    assert caps["credential_capture"] is True
    assert caps["post_login_automation"] is False
    assert caps["autonomous_exploit"] is False
    assert caps["goal_directed"] is False


# ---------------------------------------------------------------------------
# forge.exploitation.start — explicit authorization + write permission


def test_exploitation_start_rejects_authorized_false(ctx: ServerContext):
    resp = _call_tool(
        ctx,
        "forge.exploitation.start",
        {
            "engagement_id": 1001,
            "module": "credential_capture",
            "target": "https://example.com/login",
            "roe_id": "ROE-123",
            "authorized": False,
        },
        auth=AuthContext(role="operator"),
    )
    assert resp.error is not None
    assert resp.error.code == -32602
    assert "authorized" in resp.error.message


def test_exploitation_start_rejects_unknown_module(ctx: ServerContext):
    resp = _call_tool(
        ctx,
        "forge.exploitation.start",
        {
            "engagement_id": 1001,
            "module": "ransomware_deploy",  # not in allowed set
            "target": "https://example.com/login",
            "roe_id": "ROE-123",
            "authorized": True,
        },
        auth=AuthContext(role="operator"),
    )
    assert resp.error is not None
    assert resp.error.code == -32602


def test_exploitation_start_success_writes_audit_row(ctx: ServerContext):
    resp = _call_tool(
        ctx,
        "forge.exploitation.start",
        {
            "engagement_id": 1001,
            "module": "credential_capture",
            "target": "https://portal.example.com/sso",
            "roe_id": "ROE-ACME-2026-001",
            "authorized": True,
            "rationale": "authorized SSO phishing exercise",
        },
        auth=AuthContext(role="operator"),
    )
    assert resp.error is None, resp.error
    structured = resp.result["structuredContent"]
    assert structured["module"] == "credential_capture"
    assert structured["authorized"] is True
    assert structured["audit_log"]["action"] == "start_intent"
    assert structured["audit_log"]["phase"] == "exploitation"
    # Also check that exploitation.status now shows the new row
    status = _call_tool(ctx, "forge.exploitation.status", {"engagement_id": 1001})
    assert status.error is None
    assert status.result["structuredContent"]["recent_event_count"] >= 2


def test_exploitation_start_requires_authorized_field(ctx: ServerContext):
    """Missing `authorized` key is just as bad as `authorized: false`."""
    resp = _call_tool(
        ctx,
        "forge.exploitation.start",
        {
            "engagement_id": 1001,
            "module": "credential_capture",
            "target": "https://example.com/login",
            "roe_id": "ROE-123",
        },
        auth=AuthContext(role="operator"),
    )
    assert resp.error is not None
    assert resp.error.code == -32602


# ---------------------------------------------------------------------------
# HTTP transport with role / write-token headers


def test_http_transport_role_header_grants_write_access(seeded_data_dir: Path):
    server = ForgeMCPServer(data_dir=seeded_data_dir, host="127.0.0.1", port=0)
    host, port = server.start()
    try:
        url = f"http://{host}:{port}/mcp"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {server.auth_token}",
            "X-Forge-Role": "operator",
        }
        req = urllib.request.Request(
            url,
            data=json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 7,
                    "method": "tools/call",
                    "params": {
                        "name": "forge.intents.create",
                        "arguments": {
                            "engagement_id": 1001,
                            "target_seed": "http-role.example",
                        },
                    },
                }
            ).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        assert body["result"]["structuredContent"]["intent"]["target_seed"] == "http-role.example"
    finally:
        server.stop()


def test_http_transport_write_token_header_grants_write_access(seeded_data_dir: Path):
    server = ForgeMCPServer(
        data_dir=seeded_data_dir,
        host="127.0.0.1",
        port=0,
        write_token="forge-write-abc",
    )
    host, port = server.start()
    try:
        url = f"http://{host}:{port}/mcp"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {server.auth_token}",
            "X-Forge-Write-Token": "forge-write-abc",
        }
        req = urllib.request.Request(
            url,
            data=json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 8,
                    "method": "tools/call",
                    "params": {
                        "name": "forge.intents.create",
                        "arguments": {
                            "engagement_id": 1001,
                            "target_seed": "http-token.example",
                        },
                    },
                }
            ).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        assert body["result"]["structuredContent"]["intent"]["target_seed"] == "http-token.example"
    finally:
        server.stop()


def test_http_transport_missing_role_header_rejects_write(seeded_data_dir: Path):
    server = ForgeMCPServer(data_dir=seeded_data_dir, host="127.0.0.1", port=0)
    host, port = server.start()
    try:
        url = f"http://{host}:{port}/mcp"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {server.auth_token}",
        }
        req = urllib.request.Request(
            url,
            data=json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 9,
                    "method": "tools/call",
                    "params": {
                        "name": "forge.findings.create",
                        "arguments": {
                            "engagement_id": 1001,
                            "vuln_type": "cve",
                            "target_url": "https://no-role.example",
                            "severity": "LOW",
                            "title": "no-role-finding",
                        },
                    },
                }
            ).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        assert body["error"]["code"] == -32600
        assert "write permission" in body["error"]["message"]
    finally:
        server.stop()


# ---------------------------------------------------------------------------
# Dispatcher resets auth after each call


def test_dispatcher_resets_auth_after_call(ctx: ServerContext):
    assert ctx.auth is None
    resp = dispatch_jsonrpc(
        {
            "jsonrpc": "2.0",
            "id": 500,
            "method": "tools/call",
            "params": {
                "name": "forge.engagements.list",
                "arguments": {},
            },
        },
        ctx,
        auth=AuthContext(role="viewer"),
    )
    assert resp.error is None
    # Auth must not leak between dispatches
    assert ctx.auth is None


def test_default_write_roles_contains_expected_values():
    assert "operator" in DEFAULT_WRITE_ROLES
    assert "owner" in DEFAULT_WRITE_ROLES
    assert "admin" in DEFAULT_WRITE_ROLES
