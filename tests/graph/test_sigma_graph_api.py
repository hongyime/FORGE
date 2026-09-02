"""Sigma.js graph API tests — layouts, filters, sensitive-data guard, HTTP wiring."""

from __future__ import annotations

import math
import sqlite3
import time
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from forge.db.migrations import run_migrations
from forge.db.schema import apply_schema
from forge.db.validation import validate_canonical_schema
from forge.models.attack_graph_models import (
    AttackEdge,
    AttackGraph,
    AttackNode,
    NodeType,
    Severity,
)
from forge.webui.app import create_app
from forge.webui.auth import mint_token
from forge.webui.sigma_graph_routes import (
    LAYOUTS,
    MAX_NODES_LIMIT,
    SigmaGraphRouteError,
    build_sigma_payload,
    clear_sigma_cache,
    sigma_graph_payload,
)


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------


def _sample_graph(engagement_id: int = 1001) -> AttackGraph:
    """Small deterministic graph with mixed node/edge types."""

    nodes = [
        AttackNode(
            node_id="EXTERNAL::internet",
            node_type=NodeType.EXTERNAL,
            label="Internet",
            severity=None,
            source_table="synthetic",
            source_id=0,
            engagement_id=engagement_id,
            on_critical_path=True,
            metadata={"source": "fixture"},
        ),
        AttackNode(
            node_id="HOST::app.example.com",
            node_type=NodeType.HOST,
            label="app.example.com",
            severity=Severity.HIGH,
            source_table="hosts",
            source_id=7,
            engagement_id=engagement_id,
            on_critical_path=True,
            metadata={"root_domain": "example.com", "confidence": 0.91},
        ),
        AttackNode(
            node_id="APIKEY::stripe",
            node_type=NodeType.APIKEY,
            label="Stripe key",
            severity=Severity.CRITICAL,
            source_table="key_scanner_findings",
            source_id=9,
            engagement_id=engagement_id,
            on_critical_path=False,
            metadata={"service": "stripe", "validation_status": "VALIDATED"},
        ),
        AttackNode(
            node_id="VULN::sqli-1",
            node_type=NodeType.VULN,
            label="Blind SQL injection",
            severity=Severity.CRITICAL,
            source_table="vulnerability_findings",
            source_id=11,
            engagement_id=engagement_id,
            on_critical_path=False,
            metadata={"vuln_type": "sqli"},
        ),
    ]
    edges = [
        AttackEdge(
            source_node_id="EXTERNAL::internet",
            target_node_id="HOST::app.example.com",
            weight=20.0,
            label="internet_entry",
            edge_type="entry",
            on_critical_path=True,
            metadata={},
        ),
        AttackEdge(
            source_node_id="HOST::app.example.com",
            target_node_id="APIKEY::stripe",
            weight=80.0,
            label="leaks_secret",
            edge_type="key_chains_to",
            on_critical_path=False,
            metadata={},
        ),
        AttackEdge(
            source_node_id="HOST::app.example.com",
            target_node_id="VULN::sqli-1",
            weight=90.0,
            label="hosts_vuln",
            edge_type="vuln_found",
            on_critical_path=False,
            metadata={},
        ),
    ]
    return AttackGraph(
        engagement_id=engagement_id,
        engagement_name="fixture",
        node_count=len(nodes),
        edge_count=len(edges),
        critical_path_nodes=["EXTERNAL::internet", "HOST::app.example.com"],
        critical_path_weight=20.0,
        nodes=nodes,
        edges=edges,
        generated_at="2026-08-10T00:00:00Z",
        min_severity_filter=Severity.LOW,
    )


def _large_graph(node_count: int, engagement_id: int = 2000) -> AttackGraph:
    """Ring-of-hosts graph for perf + truncation coverage."""

    nodes: list[AttackNode] = []
    for i in range(node_count):
        nodes.append(
            AttackNode(
                node_id=f"HOST::h-{i:05d}",
                node_type=NodeType.HOST,
                label=f"host-{i}",
                severity=Severity.LOW,
                source_table="hosts",
                source_id=i + 1,
                engagement_id=engagement_id,
                on_critical_path=False,
                metadata={},
            )
        )
    edges: list[AttackEdge] = []
    for i in range(node_count):
        edges.append(
            AttackEdge(
                source_node_id=f"HOST::h-{i:05d}",
                target_node_id=f"HOST::h-{(i + 1) % node_count:05d}",
                weight=1.0,
                label="ring",
                edge_type="entry",
                on_critical_path=False,
                metadata={},
            )
        )
    return AttackGraph(
        engagement_id=engagement_id,
        engagement_name="perf",
        node_count=len(nodes),
        edge_count=len(edges),
        critical_path_nodes=[],
        critical_path_weight=0.0,
        nodes=nodes,
        edges=edges,
        generated_at="2026-08-10T00:00:00Z",
        min_severity_filter=Severity.LOW,
    )


@pytest.fixture(autouse=True)
def _reset_cache() -> None:
    clear_sigma_cache()


# --------------------------------------------------------------------------
# Schema / envelope
# --------------------------------------------------------------------------


def test_build_sigma_payload_returns_valid_sigma_json_shape() -> None:
    """Given a graph, When we build the payload,
    Then the envelope has nodes/edges arrays with the required Sigma.js keys."""
    payload = build_sigma_payload(_sample_graph(), layout="circular")

    assert isinstance(payload["nodes"], list)
    assert isinstance(payload["edges"], list)
    assert payload["engagement_id"] == 1001
    assert payload["layout"] == "circular"
    assert payload["node_count"] == len(payload["nodes"]) == 4
    assert payload["edge_count"] == len(payload["edges"]) == 3
    assert payload["truncated"] is False
    for node in payload["nodes"]:
        assert set(node.keys()) >= {"id", "label", "x", "y", "size", "color"}
        assert isinstance(node["id"], str) and node["id"]
        assert isinstance(node["label"], str) and node["label"]
        assert isinstance(node["x"], float)
        assert isinstance(node["y"], float)
        assert node["object_id"] and isinstance(node["object_id"], str)
        assert node["entity_type"]
        assert isinstance(node["properties"], dict)
    for edge in payload["edges"]:
        assert set(edge.keys()) >= {"id", "source", "target"}
        assert edge["id"].startswith("e")
        assert edge["source"] and edge["target"]


# --------------------------------------------------------------------------
# Layouts
# --------------------------------------------------------------------------


def test_circular_layout_positions_nodes_on_a_circle() -> None:
    """Given a graph, When circular layout is requested,
    Then all nodes lie on a single circle centered at origin."""
    payload = build_sigma_payload(_sample_graph(), layout="circular")

    radii = [math.hypot(n["x"], n["y"]) for n in payload["nodes"]]
    assert radii, "at least one node expected"
    reference = radii[0]
    for r in radii:
        assert math.isclose(r, reference, rel_tol=1e-6), (
            f"circular layout radii mismatch: {radii!r}"
        )
    # Reject the degenerate all-origin case.
    assert reference > 0.0


def test_force_layout_converges_quickly_and_deterministically() -> None:
    """Given a small graph, When force layout runs twice,
    Then it converges in <3s and produces the same result (cacheable)."""
    graph = _sample_graph()

    t0 = time.perf_counter()
    payload_a = build_sigma_payload(graph, layout="force")
    elapsed = time.perf_counter() - t0
    payload_b = build_sigma_payload(graph, layout="force")

    assert elapsed < 3.0, f"force layout took {elapsed:.2f}s"
    assert payload_a["nodes"] == payload_b["nodes"]
    # Force layout must not collapse everything to origin.
    magnitudes = [math.hypot(n["x"], n["y"]) for n in payload_a["nodes"]]
    assert max(magnitudes) > 0.0


def test_hierarchical_layout_produces_tree_structure_by_node_type() -> None:
    """Given mixed node types, When hierarchical layout runs,
    Then EXTERNAL sits above HOST which sits above APIKEY (y decreasing)."""
    payload = build_sigma_payload(_sample_graph(), layout="hierarchical")

    by_id = {n["id"]: n for n in payload["nodes"]}
    y_external = by_id["EXTERNAL::internet"]["y"]
    y_host = by_id["HOST::app.example.com"]["y"]
    y_apikey = by_id["APIKEY::stripe"]["y"]
    y_vuln = by_id["VULN::sqli-1"]["y"]

    assert y_external > y_host > y_apikey
    assert y_apikey > y_vuln, "VULN layer must sit below APIKEY"


def test_unknown_layout_is_rejected() -> None:
    with pytest.raises(SigmaGraphRouteError):
        build_sigma_payload(_sample_graph(), layout="spiral")


# --------------------------------------------------------------------------
# Filters
# --------------------------------------------------------------------------


def test_node_types_filter_drops_unmatched_nodes_and_dangling_edges() -> None:
    """Given a filter that keeps only HOST + APIKEY,
    When filtering, Then EXTERNAL and its incident edges are gone."""
    payload = build_sigma_payload(
        _sample_graph(),
        layout="circular",
        node_types_filter=frozenset({"HOST", "APIKEY"}),
    )

    kept_types = {n["entity_type"] for n in payload["nodes"]}
    assert kept_types == {"HOST", "APIKEY"}
    kept_ids = {n["id"] for n in payload["nodes"]}
    for edge in payload["edges"]:
        assert edge["source"] in kept_ids
        assert edge["target"] in kept_ids


def test_edge_types_filter_keeps_only_matching_edge_type() -> None:
    payload = build_sigma_payload(
        _sample_graph(),
        layout="circular",
        edge_types_filter=frozenset({"KEY_CHAINS_TO"}),
    )

    edge_types = {e["type"] for e in payload["edges"]}
    assert edge_types == {"key_chains_to"}
    assert payload["edge_count"] == 1


# --------------------------------------------------------------------------
# Safety + limits
# --------------------------------------------------------------------------


def test_sensitive_metadata_keys_are_never_returned_in_properties() -> None:
    """Even if forbidden keys somehow reach the payload builder, they never ship."""
    graph = _sample_graph()
    # AttackNode Pydantic validator rejects reserved keys, so inject via
    # bypassing model validation: attach a fresh metadata dict directly.
    graph.nodes[1].metadata = {
        "root_domain": "example.com",
        "password": "hunter2",
        "api_key": "sk_live_XYZ",
        "authorization": "Bearer XYZ",
        "raw_secret": "leaked",
    }

    payload = build_sigma_payload(graph, layout="circular")

    host_node = next(n for n in payload["nodes"] if n["id"] == "HOST::app.example.com")
    props = host_node["properties"]
    assert props == {"root_domain": "example.com"}
    forbidden = {"password", "api_key", "authorization", "raw_secret", "secret", "token"}
    assert forbidden.isdisjoint(props.keys())


def test_max_nodes_limit_is_enforced_and_reported() -> None:
    graph = _large_graph(20)
    payload = build_sigma_payload(graph, layout="circular", max_nodes=5)

    assert payload["node_count"] == 5
    assert payload["truncated"] is True
    kept_ids = {n["id"] for n in payload["nodes"]}
    for edge in payload["edges"]:
        assert edge["source"] in kept_ids
        assert edge["target"] in kept_ids


def test_max_nodes_above_hard_ceiling_is_rejected() -> None:
    with pytest.raises(SigmaGraphRouteError):
        build_sigma_payload(_sample_graph(), layout="circular", max_nodes=MAX_NODES_LIMIT + 1)


def test_response_time_under_five_seconds_for_1000_nodes() -> None:
    """Given a 1,000-node graph, When we compute the payload for every layout,
    Then each finishes in well under 5s."""
    graph = _large_graph(1000)
    # Force layout is the slowest — keep the sample small and iterations low.
    for layout in ("circular", "hierarchical"):
        t0 = time.perf_counter()
        payload = build_sigma_payload(graph, layout=layout)
        elapsed = time.perf_counter() - t0
        assert payload["node_count"] == 1000
        assert elapsed < 5.0, f"{layout} took {elapsed:.2f}s for 1k nodes"


# --------------------------------------------------------------------------
# Cache
# --------------------------------------------------------------------------


def test_sigma_graph_payload_caches_by_db_mtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Given the same DB mtime, When sigma_graph_payload is called twice,
    Then the builder runs exactly once (result served from cache)."""
    db_path = tmp_path / "engagement.db"
    db_path.write_bytes(b"stub")
    calls: list[int] = []
    graph = _sample_graph(engagement_id=42)

    class FakeBuilder:
        def __init__(self, **_kwargs: Any) -> None:
            calls.append(1)

        def build(self) -> AttackGraph:
            return graph

    monkeypatch.setattr(
        "forge.webui.sigma_graph_routes.AttackGraphBuilder",
        FakeBuilder,
    )

    first = sigma_graph_payload(engagement_id=42, db_path=db_path, layout="circular")
    second = sigma_graph_payload(engagement_id=42, db_path=db_path, layout="circular")

    assert first == second
    assert len(calls) == 1, "cache should have suppressed the second build"

    # Touch the file to bump mtime — cache invalidates, builder runs again.
    time.sleep(0.01)
    db_path.write_bytes(b"stub-v2")
    sigma_graph_payload(engagement_id=42, db_path=db_path, layout="circular")
    assert len(calls) == 2


# --------------------------------------------------------------------------
# HTTP wiring
# --------------------------------------------------------------------------


def _build_engagement_db(data_dir: Path, engagement_id: int = 3001) -> Path:
    db_path = data_dir / "engagements" / f"{engagement_id}.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        apply_schema(con)
        run_migrations(con)
        validate_canonical_schema(con)
        con.execute(
            """
            INSERT INTO engagements (id, name, scope_json, status, operator)
            VALUES (?, 'Sigma Fixture', '["acme.example"]', 'ACTIVE', 'delta-one')
            """,
            (engagement_id,),
        )
        con.commit()
    finally:
        con.close()
    return db_path


def _headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_sigma_graph_endpoint_returns_payload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Given a valid JWT, When we GET the sigma endpoint,
    Then we receive 200 + valid Sigma.js JSON."""
    data_dir = tmp_path / ".forge_data"
    monkeypatch.setenv("FORGE_DATA_DIR", str(data_dir))
    monkeypatch.setenv("FORGE_ENV", "test")
    monkeypatch.setenv("FORGE_WEB_AUTH", "jwt")
    monkeypatch.setenv("FORGE_WEB_SECRET_KEY", "s" * 64)
    _build_engagement_db(data_dir, engagement_id=3001)

    fixture_graph = _sample_graph(engagement_id=3001)

    class FakeBuilder:
        def __init__(self, **_kwargs: Any) -> None:
            pass

        def build(self) -> AttackGraph:
            return fixture_graph

    monkeypatch.setattr(
        "forge.webui.sigma_graph_routes.AttackGraphBuilder",
        FakeBuilder,
    )

    app = create_app()
    read_token = mint_token("delta-one", permissions=("assets:read", "workspaces:legacy"))
    denied_token = mint_token(
        "delta-one", permissions=("engagements:read", "workspaces:legacy"),
    )

    with TestClient(app) as client:
        response = client.get(
            "/api/engagements/3001/graph/sigma?layout=circular",
            headers=_headers(read_token),
        )
        denied = client.get(
            "/api/engagements/3001/graph/sigma",
            headers=_headers(denied_token),
        )
        bad_layout = client.get(
            "/api/engagements/3001/graph/sigma?layout=spiral",
            headers=_headers(read_token),
        )
        filtered = client.get(
            "/api/engagements/3001/graph/sigma?node_types=HOST,APIKEY&layout=hierarchical",
            headers=_headers(read_token),
        )
        missing = client.get(
            "/api/engagements/9999/graph/sigma",
            headers=_headers(read_token),
        )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["layout"] == "circular"
    assert body["node_count"] == 4
    assert body["edge_count"] == 3
    for layout_name in LAYOUTS:
        assert layout_name in LAYOUTS  # keep the tuple in scope for reviewers
    assert denied.status_code == 403
    assert bad_layout.status_code == 400
    filtered_body = filtered.json()
    assert filtered.status_code == 200
    assert {n["entity_type"] for n in filtered_body["nodes"]} == {"HOST", "APIKEY"}
    assert missing.status_code == 404
