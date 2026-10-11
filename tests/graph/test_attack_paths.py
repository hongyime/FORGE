"""Tests for forge.graph.attack_paths — AttackPathManager (Explore #16)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from forge.graph.attack_paths import (
    TIER_ZERO_GOALS,
    AttackPath,
    AttackPathManager,
    ChokePoint,
    FixCandidate,
    GoalRecord,
    IntentRecord,
)
from forge.models.attack_graph_models import (
    AttackEdge,
    AttackGraph,
    AttackNode,
    NodeType,
    Severity,
)


# ---------------------------------------------------------------------------
# Fixture graphs
# ---------------------------------------------------------------------------


def _dc_graph(engagement_id: int = 1001) -> AttackGraph:
    """Classic AD attack chain:

        EXT -> HOST(public web) -> VULN(SSRF) -> CRED(low-priv) ->
        HOST(DC01) -> IMP

    DC01 should be flagged tier-zero by label pattern. The IMP node acts
    as the ultimate sink. CRED is a validated credential, so exposure
    scoring includes it.
    """
    engagement = engagement_id
    nodes = [
        AttackNode(
            node_id=f"EXT::engagement-{engagement}",
            node_type=NodeType.EXTERNAL,
            label="Internet",
            severity=None,
            source_table="synthetic",
            source_id=0,
            engagement_id=engagement,
            on_critical_path=True,
            metadata={},
        ),
        AttackNode(
            node_id="HOST::web.example.com",
            node_type=NodeType.HOST,
            label="web.example.com",
            severity=Severity.MEDIUM,
            source_table="hosts",
            source_id=1,
            engagement_id=engagement,
            on_critical_path=True,
            metadata={"os_family": "linux"},
        ),
        AttackNode(
            node_id="VULN::ssrf-1",
            node_type=NodeType.VULN,
            label="SSRF to internal metadata",
            severity=Severity.HIGH,
            source_table="vulnerability_findings",
            source_id=2,
            engagement_id=engagement,
            on_critical_path=True,
            metadata={"vuln_type": "ssrf"},
        ),
        AttackNode(
            node_id="CRED::42",
            node_type=NodeType.CREDENTIAL,
            label="dev-user@example.com",
            severity=Severity.MEDIUM,
            source_table="credentials",
            source_id=42,
            engagement_id=engagement,
            on_critical_path=True,
            metadata={"validated": True, "service": "ssh"},
        ),
        AttackNode(
            node_id="HOST::DC01.corp.example",
            node_type=NodeType.HOST,
            label="DC01.corp.example (Domain Controller)",
            severity=Severity.CRITICAL,
            source_table="hosts",
            source_id=99,
            engagement_id=engagement,
            on_critical_path=True,
            metadata={"os_family": "windows", "role": "domain_controller"},
        ),
        AttackNode(
            node_id=f"IMP::engagement-{engagement}",
            node_type=NodeType.IMPACT,
            label="Impact",
            severity=None,
            source_table="synthetic",
            source_id=0,
            engagement_id=engagement,
            on_critical_path=True,
            metadata={},
        ),
    ]
    edges = [
        AttackEdge(
            source_node_id=f"EXT::engagement-{engagement}",
            target_node_id="HOST::web.example.com",
            weight=10.0,
            edge_type="entry",
        ),
        AttackEdge(
            source_node_id="HOST::web.example.com",
            target_node_id="VULN::ssrf-1",
            weight=70.0,
            edge_type="vuln_found",
        ),
        AttackEdge(
            source_node_id="VULN::ssrf-1",
            target_node_id="CRED::42",
            weight=65.0,
            edge_type="exploit_applies",
        ),
        AttackEdge(
            source_node_id="CRED::42",
            target_node_id="HOST::DC01.corp.example",
            weight=90.0,
            edge_type="credential_use",
        ),
        AttackEdge(
            source_node_id="HOST::DC01.corp.example",
            target_node_id=f"IMP::engagement-{engagement}",
            weight=110.0,
            edge_type="impact",
        ),
    ]
    return AttackGraph(
        engagement_id=engagement,
        engagement_name="dc-fixture",
        node_count=len(nodes),
        edge_count=len(edges),
        critical_path_nodes=[n.node_id for n in nodes],
        critical_path_weight=sum(e.weight for e in edges),
        nodes=nodes,
        edges=edges,
        generated_at="2026-10-11T00:00:00Z",
        min_severity_filter=Severity.LOW,
    )


def _branching_graph(engagement_id: int = 2002) -> AttackGraph:
    """Diamond graph with a shared choke point:

        EXT -> A -> CHOKE -> DC
        EXT -> B -> CHOKE -> DC
        EXT -> C -> DC   (short direct path)
    """
    engagement = engagement_id
    nodes = [
        AttackNode(
            node_id=f"EXT::engagement-{engagement}",
            node_type=NodeType.EXTERNAL,
            label="Internet",
            severity=None,
            source_table="synthetic",
            source_id=0,
            engagement_id=engagement,
            metadata={},
        ),
        AttackNode(
            node_id="HOST::A",
            node_type=NodeType.HOST,
            label="A.example.com",
            severity=Severity.LOW,
            source_table="hosts",
            source_id=1,
            engagement_id=engagement,
            metadata={},
        ),
        AttackNode(
            node_id="HOST::B",
            node_type=NodeType.HOST,
            label="B.example.com",
            severity=Severity.LOW,
            source_table="hosts",
            source_id=2,
            engagement_id=engagement,
            metadata={},
        ),
        AttackNode(
            node_id="HOST::C",
            node_type=NodeType.HOST,
            label="C.example.com",
            severity=Severity.LOW,
            source_table="hosts",
            source_id=3,
            engagement_id=engagement,
            metadata={},
        ),
        AttackNode(
            node_id="HOST::CHOKE",
            node_type=NodeType.HOST,
            label="jumpbox.corp.example",
            severity=Severity.MEDIUM,
            source_table="hosts",
            source_id=4,
            engagement_id=engagement,
            metadata={},
        ),
        AttackNode(
            node_id="HOST::DC",
            node_type=NodeType.HOST,
            label="dc01.corp.example (Domain Controller)",
            severity=Severity.CRITICAL,
            source_table="hosts",
            source_id=5,
            engagement_id=engagement,
            metadata={"tier_zero": True},
        ),
    ]
    edges = [
        AttackEdge(
            source_node_id=f"EXT::engagement-{engagement}",
            target_node_id="HOST::A",
            weight=10.0,
            edge_type="entry",
        ),
        AttackEdge(
            source_node_id=f"EXT::engagement-{engagement}",
            target_node_id="HOST::B",
            weight=10.0,
            edge_type="entry",
        ),
        AttackEdge(
            source_node_id=f"EXT::engagement-{engagement}",
            target_node_id="HOST::C",
            weight=10.0,
            edge_type="entry",
        ),
        AttackEdge(
            source_node_id="HOST::A",
            target_node_id="HOST::CHOKE",
            weight=20.0,
            edge_type="credential_use",
        ),
        AttackEdge(
            source_node_id="HOST::B",
            target_node_id="HOST::CHOKE",
            weight=20.0,
            edge_type="credential_use",
        ),
        AttackEdge(
            source_node_id="HOST::CHOKE",
            target_node_id="HOST::DC",
            weight=80.0,
            edge_type="credential_use",
        ),
        AttackEdge(
            source_node_id="HOST::C",
            target_node_id="HOST::DC",
            weight=40.0,
            edge_type="credential_use",
        ),
    ]
    return AttackGraph(
        engagement_id=engagement,
        engagement_name="branching-fixture",
        node_count=len(nodes),
        edge_count=len(edges),
        critical_path_nodes=[
            f"EXT::engagement-{engagement}",
            "HOST::C",
            "HOST::DC",
        ],
        critical_path_weight=50.0,
        nodes=nodes,
        edges=edges,
        generated_at="2026-10-11T00:00:00Z",
        min_severity_filter=Severity.LOW,
    )


def _empty_graph(engagement_id: int = 9999) -> AttackGraph:
    nodes: list[AttackNode] = []
    edges: list[AttackEdge] = []
    return AttackGraph(
        engagement_id=engagement_id,
        engagement_name="empty-fixture",
        node_count=0,
        edge_count=0,
        critical_path_nodes=[],
        critical_path_weight=0.0,
        nodes=nodes,
        edges=edges,
        generated_at="2026-10-11T00:00:00Z",
        min_severity_filter=Severity.LOW,
    )


# ---------------------------------------------------------------------------
# compute_paths
# ---------------------------------------------------------------------------


def test_compute_paths_default_uses_entry_and_tier_zero(tmp_path: Path) -> None:
    graph = _dc_graph()
    mgr = AttackPathManager(
        db_path=tmp_path / "x.db", engagement_id=graph.engagement_id, graph=graph
    )
    paths = mgr.compute_paths()
    assert paths, "expected at least one path from EXT to tier-zero node"
    assert all(path.length >= 1 for path in paths)
    assert any(path.reaches_tier_zero for path in paths)
    # Determinism — identical call returns identical ordering
    paths_again = mgr.compute_paths()
    assert [p.nodes for p in paths] == [p.nodes for p in paths_again]


def test_compute_paths_respects_explicit_source_and_target(tmp_path: Path) -> None:
    graph = _dc_graph()
    mgr = AttackPathManager(
        db_path=tmp_path / "x.db", engagement_id=graph.engagement_id, graph=graph
    )
    paths = mgr.compute_paths(
        source=f"EXT::engagement-{graph.engagement_id}",
        target="HOST::DC01.corp.example",
    )
    assert len(paths) == 1
    assert paths[0].nodes[0].startswith("EXT::")
    assert paths[0].nodes[-1] == "HOST::DC01.corp.example"


def test_compute_paths_returns_empty_when_target_missing(tmp_path: Path) -> None:
    graph = _dc_graph()
    mgr = AttackPathManager(
        db_path=tmp_path / "x.db", engagement_id=graph.engagement_id, graph=graph
    )
    assert mgr.compute_paths(target="HOST::does.not.exist") == []


def test_compute_paths_returns_empty_on_empty_graph(tmp_path: Path) -> None:
    graph = _empty_graph()
    mgr = AttackPathManager(
        db_path=tmp_path / "x.db", engagement_id=graph.engagement_id, graph=graph
    )
    assert mgr.compute_paths() == []


def test_compute_paths_depth_cap_bounds_recursion(tmp_path: Path) -> None:
    graph = _dc_graph()
    mgr = AttackPathManager(
        db_path=tmp_path / "x.db", engagement_id=graph.engagement_id, graph=graph
    )
    # Max depth 1 is too short to reach the DC — expect no paths.
    paths = mgr.compute_paths(
        source=f"EXT::engagement-{graph.engagement_id}",
        target=f"IMP::engagement-{graph.engagement_id}",
        max_depth=1,
    )
    assert paths == []


# ---------------------------------------------------------------------------
# rank_paths
# ---------------------------------------------------------------------------


def test_rank_paths_prefers_tier_zero_and_higher_weight(tmp_path: Path) -> None:
    graph = _branching_graph()
    mgr = AttackPathManager(
        db_path=tmp_path / "x.db", engagement_id=graph.engagement_id, graph=graph
    )
    paths = mgr.compute_paths()
    ranked = mgr.rank_paths(paths)
    assert ranked
    # Highest-weight tier-zero path first
    assert ranked[0].reaches_tier_zero is True
    weights = [p.weight for p in ranked if p.reaches_tier_zero]
    assert weights == sorted(weights, reverse=True)


def test_rank_paths_handles_empty_input(tmp_path: Path) -> None:
    graph = _dc_graph()
    mgr = AttackPathManager(
        db_path=tmp_path / "x.db", engagement_id=graph.engagement_id, graph=graph
    )
    assert mgr.rank_paths([]) == []


# ---------------------------------------------------------------------------
# get_tier_zero_assets
# ---------------------------------------------------------------------------


def test_get_tier_zero_assets_detects_domain_controller_by_label(tmp_path: Path) -> None:
    graph = _dc_graph()
    mgr = AttackPathManager(
        db_path=tmp_path / "x.db", engagement_id=graph.engagement_id, graph=graph
    )
    tier_zero = mgr.get_tier_zero_assets()
    labels = {entry["label"] for entry in tier_zero}
    assert any("Domain Controller" in label or "DC01" in label for label in labels)


def test_get_tier_zero_assets_detects_explicit_metadata_tag(tmp_path: Path) -> None:
    graph = _branching_graph()
    mgr = AttackPathManager(
        db_path=tmp_path / "x.db", engagement_id=graph.engagement_id, graph=graph
    )
    tier_zero = mgr.get_tier_zero_assets()
    assert any(entry["node_id"] == "HOST::DC" for entry in tier_zero)


def test_get_tier_zero_assets_empty_graph_returns_empty_list(tmp_path: Path) -> None:
    graph = _empty_graph()
    mgr = AttackPathManager(
        db_path=tmp_path / "x.db", engagement_id=graph.engagement_id, graph=graph
    )
    assert mgr.get_tier_zero_assets() == []


# ---------------------------------------------------------------------------
# get_choke_points
# ---------------------------------------------------------------------------


def test_get_choke_points_ranks_shared_hop_above_leaf(tmp_path: Path) -> None:
    graph = _branching_graph()
    mgr = AttackPathManager(
        db_path=tmp_path / "x.db", engagement_id=graph.engagement_id, graph=graph
    )
    chokes = mgr.get_choke_points(top_n=5)
    assert any(isinstance(c, ChokePoint) for c in chokes)
    # HOST::CHOKE sits on both A→CHOKE→DC and B→CHOKE→DC paths.
    choke_ids = [c.node_id for c in chokes]
    assert "HOST::CHOKE" in choke_ids
    # And it should be the highest-ranked choke point.
    assert chokes[0].node_id == "HOST::CHOKE"


def test_get_choke_points_empty_graph(tmp_path: Path) -> None:
    graph = _empty_graph()
    mgr = AttackPathManager(
        db_path=tmp_path / "x.db", engagement_id=graph.engagement_id, graph=graph
    )
    assert mgr.get_choke_points() == []


# ---------------------------------------------------------------------------
# get_minimal_fix_set
# ---------------------------------------------------------------------------


def test_get_minimal_fix_set_removes_choke_point_first(tmp_path: Path) -> None:
    graph = _branching_graph()
    mgr = AttackPathManager(
        db_path=tmp_path / "x.db", engagement_id=graph.engagement_id, graph=graph
    )
    fixes = mgr.get_minimal_fix_set(max_candidates=5)
    assert fixes, "expected at least one fix candidate on a graph with tier-zero reachability"
    # The CHOKE→DC edge covers two paths; it must be ranked highest or
    # chosen very early.
    top_edges = [(fix.source_node_id, fix.target_node_id) for fix in fixes[:3]]
    assert ("HOST::CHOKE", "HOST::DC") in top_edges


def test_get_minimal_fix_set_without_tier_zero_returns_empty(tmp_path: Path) -> None:
    # A graph with no tier-zero signals yields no fix candidates.
    engagement = 1234
    nodes = [
        AttackNode(
            node_id=f"EXT::engagement-{engagement}",
            node_type=NodeType.EXTERNAL,
            label="Internet",
            source_table="synthetic",
            source_id=0,
            engagement_id=engagement,
            metadata={},
        ),
        AttackNode(
            node_id="HOST::leaf",
            node_type=NodeType.HOST,
            label="leaf.example.com",
            severity=Severity.INFO,
            source_table="hosts",
            source_id=1,
            engagement_id=engagement,
            metadata={},
        ),
    ]
    edges = [
        AttackEdge(
            source_node_id=f"EXT::engagement-{engagement}",
            target_node_id="HOST::leaf",
            weight=5.0,
            edge_type="entry",
        )
    ]
    graph = AttackGraph(
        engagement_id=engagement,
        engagement_name="no-tier-zero",
        node_count=2,
        edge_count=1,
        critical_path_nodes=[],
        critical_path_weight=0.0,
        nodes=nodes,
        edges=edges,
        generated_at="2026-10-11T00:00:00Z",
    )
    mgr = AttackPathManager(
        db_path=tmp_path / "x.db", engagement_id=engagement, graph=graph
    )
    assert mgr.get_minimal_fix_set() == []


# ---------------------------------------------------------------------------
# bootstrap_goals
# ---------------------------------------------------------------------------


def test_bootstrap_goals_generates_forge_owned_catalog_entries(tmp_path: Path) -> None:
    graph = _dc_graph()
    mgr = AttackPathManager(
        db_path=tmp_path / "x.db", engagement_id=graph.engagement_id, graph=graph
    )
    goals = mgr.bootstrap_goals()
    assert goals, "expected goals when tier-zero is reachable"
    assert all(goal.goal_id in TIER_ZERO_GOALS for goal in goals)
    assert any(goal.goal_id == "get_domain_admin" for goal in goals)


def test_bootstrap_goals_empty_graph(tmp_path: Path) -> None:
    graph = _empty_graph()
    mgr = AttackPathManager(
        db_path=tmp_path / "x.db", engagement_id=graph.engagement_id, graph=graph
    )
    assert mgr.bootstrap_goals() == []


# ---------------------------------------------------------------------------
# reason_about_paths
# ---------------------------------------------------------------------------


def test_reason_about_paths_recommends_next_unvalidated_hop(tmp_path: Path) -> None:
    graph = _dc_graph()
    mgr = AttackPathManager(
        db_path=tmp_path / "x.db", engagement_id=graph.engagement_id, graph=graph
    )
    intents = mgr.reason_about_paths(
        facts={
            "validated_nodes": [
                f"EXT::engagement-{graph.engagement_id}",
                "HOST::web.example.com",
            ],
            "goal_targets": ["get_domain_admin"],
        }
    )
    assert intents, "expected an intent toward DC01 given validated web host"
    assert isinstance(intents[0], IntentRecord)
    # First unvalidated hop should be VULN::ssrf-1
    assert intents[0].target_node_id == "VULN::ssrf-1"
    assert intents[0].source_node_id == "HOST::web.example.com"


def test_reason_about_paths_skips_blocked_hops(tmp_path: Path) -> None:
    graph = _dc_graph()
    mgr = AttackPathManager(
        db_path=tmp_path / "x.db", engagement_id=graph.engagement_id, graph=graph
    )
    intents = mgr.reason_about_paths(
        facts={
            "blocked_nodes": ["VULN::ssrf-1"],
            "goal_targets": ["get_domain_admin"],
        }
    )
    # The single path is blocked at VULN::ssrf-1 — no intents should be
    # emitted.
    assert intents == []


def test_reason_about_paths_filters_by_requested_goal(tmp_path: Path) -> None:
    graph = _dc_graph()
    mgr = AttackPathManager(
        db_path=tmp_path / "x.db", engagement_id=graph.engagement_id, graph=graph
    )
    intents = mgr.reason_about_paths(
        facts={"goal_targets": ["enumerate_tenant"]}
    )
    # No tier-zero signals match 'enumerate_tenant' in this fixture, so
    # no intents.
    assert intents == []


# ---------------------------------------------------------------------------
# get_exposure_score
# ---------------------------------------------------------------------------


def test_get_exposure_score_bounded_zero_to_hundred(tmp_path: Path) -> None:
    graph = _dc_graph()
    mgr = AttackPathManager(
        db_path=tmp_path / "x.db", engagement_id=graph.engagement_id, graph=graph
    )
    exposure = mgr.get_exposure_score()
    assert 0 <= exposure["score"] <= 100
    assert exposure["tier_zero_total"] >= 1
    assert exposure["paths_count"] >= 1
    assert exposure["min_path_length"] is not None
    assert "Tier-zero exposure" in exposure["summary"]


def test_get_exposure_score_empty_graph_returns_zero(tmp_path: Path) -> None:
    graph = _empty_graph()
    mgr = AttackPathManager(
        db_path=tmp_path / "x.db", engagement_id=graph.engagement_id, graph=graph
    )
    exposure = mgr.get_exposure_score()
    assert exposure["score"] == 0
    assert exposure["tier_zero_total"] == 0
    assert exposure["paths_count"] == 0


def test_get_exposure_score_deterministic_across_runs(tmp_path: Path) -> None:
    graph = _dc_graph()
    mgr = AttackPathManager(
        db_path=tmp_path / "x.db", engagement_id=graph.engagement_id, graph=graph
    )
    first = mgr.get_exposure_score()
    second = mgr.get_exposure_score()
    assert first == second


# ---------------------------------------------------------------------------
# Dataclass serialization
# ---------------------------------------------------------------------------


def test_attack_path_to_dict_round_trips_core_fields() -> None:
    path = AttackPath(
        nodes=("a", "b"),
        edge_types=("entry",),
        weight=12.345,
        length=1,
        reaches_tier_zero=True,
        critical_severity_count=0,
    )
    payload = path.to_dict()
    assert payload == {
        "nodes": ["a", "b"],
        "edge_types": ["entry"],
        "weight": 12.345,
        "length": 1,
        "reaches_tier_zero": True,
        "critical_severity_count": 0,
    }


def test_choke_point_to_dict_rounds_betweenness() -> None:
    cp = ChokePoint(
        node_id="X",
        label="x.example",
        node_type="HOST",
        betweenness=0.123456,
        path_count=3,
    )
    payload = cp.to_dict()
    assert payload["betweenness"] == 0.1235
    assert payload["path_count"] == 3


def test_fix_candidate_to_dict() -> None:
    fix = FixCandidate(
        source_node_id="A",
        target_node_id="B",
        edge_type="credential_use",
        weight=50.0,
        paths_broken=2,
    )
    assert fix.to_dict()["paths_broken"] == 2
    assert fix.to_dict()["edge_type"] == "credential_use"


def test_goal_record_to_dict_only_catalog_ids() -> None:
    goal = GoalRecord(
        goal_id="get_domain_admin",
        rationale="path exists",
        source_node_id="EXT::1",
        target_node_id="HOST::DC",
        confidence=0.8,
    )
    assert goal.to_dict()["goal_id"] in TIER_ZERO_GOALS


def test_intent_record_to_dict() -> None:
    intent = IntentRecord(
        source_node_id="A",
        target_node_id="B",
        rationale="advance",
        priority=0.75,
    )
    payload = intent.to_dict()
    assert payload["priority"] == 0.75
    assert payload["target_node_id"] == "B"


# ---------------------------------------------------------------------------
# CLI integration
# ---------------------------------------------------------------------------


def test_attack_paths_cli_outputs_json(monkeypatch: pytest.MonkeyPatch) -> None:
    from forge.cli import app
    from forge.graph import attack_path_cli

    graph = _dc_graph(engagement_id=1001)

    class _StubManager:
        def __init__(self, db_path: Path, engagement_id: int) -> None:
            self.engagement_id = engagement_id
            self._mgr = AttackPathManager(
                db_path=db_path, engagement_id=engagement_id, graph=graph
            )

        def compute_paths(self, source=None, target=None, max_depth=10):
            return self._mgr.compute_paths(source=source, target=target, max_depth=max_depth)

        def rank_paths(self, paths):
            return self._mgr.rank_paths(paths)

        def get_tier_zero_assets(self):
            return self._mgr.get_tier_zero_assets()

        def get_choke_points(self, top_n=10):
            return self._mgr.get_choke_points(top_n=top_n)

        def get_exposure_score(self):
            return self._mgr.get_exposure_score()

    def _fake_load_graph_manager(engagement: str) -> _StubManager:
        return _StubManager(db_path=Path("/does/not/exist.db"), engagement_id=int(engagement))

    monkeypatch.setattr(attack_path_cli, "_load_graph_manager", _fake_load_graph_manager)

    result = CliRunner().invoke(
        app,
        ["graph", "attack-paths", "--engagement", "1001", "--json"],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["schema"] == "forge.graph.attack_paths.v1"
    assert payload["execution_policy"] == "read_only"
    assert payload["engagement_id"] == 1001
    assert isinstance(payload["paths"], list)
    assert payload["total_count"] >= 1


def test_tier_zero_cli_outputs_json(monkeypatch: pytest.MonkeyPatch) -> None:
    from forge.cli import app
    from forge.graph import attack_path_cli

    graph = _branching_graph(engagement_id=2002)

    class _StubManager:
        def __init__(self, db_path: Path, engagement_id: int) -> None:
            self.engagement_id = engagement_id
            self._mgr = AttackPathManager(
                db_path=db_path, engagement_id=engagement_id, graph=graph
            )

        def compute_paths(self, source=None, target=None, max_depth=10):
            return self._mgr.compute_paths(source=source, target=target, max_depth=max_depth)

        def rank_paths(self, paths):
            return self._mgr.rank_paths(paths)

        def get_tier_zero_assets(self):
            return self._mgr.get_tier_zero_assets()

        def get_choke_points(self, top_n=10):
            return self._mgr.get_choke_points(top_n=top_n)

        def get_exposure_score(self):
            return self._mgr.get_exposure_score()

    def _fake_load_graph_manager(engagement: str) -> _StubManager:
        return _StubManager(db_path=Path("/does/not/exist.db"), engagement_id=int(engagement))

    monkeypatch.setattr(attack_path_cli, "_load_graph_manager", _fake_load_graph_manager)

    result = CliRunner().invoke(
        app,
        ["graph", "tier-zero", "--engagement", "2002", "--top", "5", "--json"],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["schema"] == "forge.graph.tier_zero.v1"
    assert payload["engagement_id"] == 2002
    assert isinstance(payload["tier_zero"], list)
    assert any(entry["node_id"] == "HOST::DC" for entry in payload["tier_zero"])
    assert 0 <= payload["exposure_score"]["score"] <= 100
