"""Focused tests for the reusable attack-graph export service."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path
from typing import Any

from forge.models.attack_graph_models import (
    AttackEdge,
    AttackGraph,
    AttackNode,
    NodeType,
    Severity,
)


def _sample_graph(engagement_id: int = 42) -> AttackGraph:
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
    ]
    edges = [
        AttackEdge(
            source_node_id="EXTERNAL::internet",
            target_node_id="HOST::app.example.com",
            weight=20.0,
            label="internet_entry",
            edge_type="entry",
            on_critical_path=True,
            metadata={"rule": "fixture"},
        ),
        AttackEdge(
            source_node_id="HOST::app.example.com",
            target_node_id="APIKEY::stripe",
            weight=80.0,
            label="leaks_secret",
            edge_type="key_chains_to",
            on_critical_path=False,
            metadata={"rule": "fixture"},
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


def test_export_attack_graph_writes_artifacts_and_snapshot(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from forge.graph import export as export_module  # noqa: PLC0415
    from forge.graph.export import export_attack_graph  # noqa: PLC0415

    writes: list[dict[str, Any]] = []

    class FakeBuilder:
        def __init__(self, **kwargs: Any) -> None:
            writes.append({"init": kwargs})

        def build(self) -> AttackGraph:
            return _sample_graph()

        def write_snapshot(self, graph: AttackGraph, *, mermaid: str, dot: str) -> None:
            writes.append(
                {
                    "snapshot": True,
                    "node_count": graph.node_count,
                    "mermaid": mermaid,
                    "dot": dot,
                }
            )

    monkeypatch.setattr(export_module, "AttackGraphBuilder", FakeBuilder)
    emitted: list[str] = []

    result = export_attack_graph(
        engagement_id=42,
        db_path=tmp_path / "engagement.db",
        output_dir=tmp_path / "reports",
        fmt="all",
        min_severity="LOW",
        critical_path_only=False,
        snapshot=True,
        max_nodes=50,
        emit=emitted.append,
    )

    assert result.snapshot_written is True
    assert result.artifacts.keys() == {
        "mermaid",
        "dot",
        "json",
        "mtgx",
        "graphml",
        "nodes_csv",
        "edges_csv",
    }
    for path in result.artifacts.values():
        assert path.is_file()
    assert writes[0]["init"]["db_path"] == tmp_path / "engagement.db"
    assert writes[0]["init"]["max_nodes"] == 50
    assert writes[-1]["snapshot"] is True
    assert "flowchart" in writes[-1]["mermaid"]
    assert "digraph" in writes[-1]["dot"]

    graph_json = json.loads(result.artifacts["json"].read_text(encoding="utf-8"))
    assert graph_json["engagement_id"] == 42
    assert any(node["source_table"] == "hosts" for node in graph_json["nodes"])
    assert 'key id="maltego_entity_type"' in result.artifacts["graphml"].read_text(
        encoding="utf-8"
    )
    with zipfile.ZipFile(result.artifacts["mtgx"]) as archive:
        assert "Graphs/Graph1.graphml" in archive.namelist()
        manifest = json.loads(archive.read("manifest.json").decode("utf-8"))
    assert manifest["schema"] == "forge.mtgx.manifest.v1"
    assert manifest["node_type_counts"]["HOST"] == 1
    assert any("Maltego MTGX" in message for message in emitted)
    assert any(message.startswith("[bold]Graph:") for message in emitted)


def test_export_attack_graph_sanitizes_metadata_in_all_artifacts(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from forge.graph import export as export_module  # noqa: PLC0415
    from forge.graph.export import export_attack_graph  # noqa: PLC0415

    graph = _sample_graph()
    graph.nodes[1].metadata.update(
        {
            "source_url": (
                "https://user:pass@app.example.com/download?"
                "token=node-secret&ok=1"
            ),
            "key_enc": "node-encrypted-secret",
            "nested": {
                "client_secret": "nested-client-secret",
                "source_url": "https://app.example.com/config?sig=nested-secret&ok=1",
            },
            "provider_sources": ["urlscan"],
        }
    )
    graph.edges[0].metadata.update(
        {
            "proof": "observed relation",
            "token": "edge-token-secret",
            "evidence": {
                "authorization": "Bearer edge-secret",
                "source_url": "https://edge.example.com/path?api_key=edge-secret&view=1",
            },
        }
    )

    class FakeBuilder:
        def __init__(self, **_kwargs: Any) -> None:
            pass

        def build(self) -> AttackGraph:
            return graph

    monkeypatch.setattr(export_module, "AttackGraphBuilder", FakeBuilder)

    result = export_attack_graph(
        engagement_id=42,
        db_path=tmp_path / "engagement.db",
        output_dir=tmp_path / "reports",
        fmt="all",
    )

    artifact_text = "\n".join(
        path.read_text(encoding="utf-8")
        for name, path in result.artifacts.items()
        if name != "mtgx"
    )
    with zipfile.ZipFile(result.artifacts["mtgx"]) as archive:
        artifact_text += archive.read("manifest.json").decode("utf-8")
        artifact_text += archive.read("Graphs/Graph1.graphml").decode("utf-8")

    assert "node-encrypted-secret" not in artifact_text
    assert "node-secret" not in artifact_text
    assert "user:pass" not in artifact_text
    assert "nested-client-secret" not in artifact_text
    assert "nested-secret" not in artifact_text
    assert "edge-token-secret" not in artifact_text
    assert "edge-secret" not in artifact_text

    graph_json = json.loads(result.artifacts["json"].read_text(encoding="utf-8"))
    host_node = next(node for node in graph_json["nodes"] if node["source_table"] == "hosts")
    assert host_node["metadata"]["source_url"] == "https://app.example.com/download?ok=1"
    assert host_node["metadata"]["nested"]["source_url"] == "https://app.example.com/config?ok=1"
    assert "key_enc" not in host_node["metadata"]
    assert graph_json["edges"][0]["metadata"] == {
        "evidence": {"source_url": "https://edge.example.com/path?view=1"},
        "proof": "observed relation",
        "rule": "fixture",
    }


def test_export_attack_graph_can_emit_critical_path_only_json(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from forge.graph import export as export_module  # noqa: PLC0415
    from forge.graph.export import export_attack_graph  # noqa: PLC0415

    class FakeBuilder:
        def __init__(self, **_kwargs: Any) -> None:
            pass

        def build(self) -> AttackGraph:
            return _sample_graph()

    monkeypatch.setattr(export_module, "AttackGraphBuilder", FakeBuilder)

    result = export_attack_graph(
        engagement_id=42,
        db_path=tmp_path / "engagement.db",
        output_dir=tmp_path,
        fmt="json",
        critical_path_only=True,
    )

    graph_json = json.loads(result.artifacts["json"].read_text(encoding="utf-8"))
    assert {node["node_id"] for node in graph_json["nodes"]} == {
        "EXTERNAL::internet",
        "HOST::app.example.com",
    }
    assert graph_json["edges"][0]["target_node_id"] == "HOST::app.example.com"


def test_graph_build_delegates_to_export_service(tmp_path: Path, monkeypatch) -> None:
    import forge.config as config_module  # noqa: PLC0415
    import forge.graph.export as export_module  # noqa: PLC0415
    from forge.cli_graph import graph_build  # noqa: PLC0415

    class FakeConfig:
        def engagement_db_path(self, engagement: str) -> Path:
            assert engagement == "42"
            return tmp_path / "42.db"

    calls: dict[str, Any] = {}

    def fake_export_attack_graph(**kwargs: Any) -> None:
        calls.update(kwargs)

    monkeypatch.setattr(config_module.ForgeConfig, "load", staticmethod(lambda: FakeConfig()))
    monkeypatch.setattr(export_module, "export_attack_graph", fake_export_attack_graph)

    graph_build(
        engagement="42",
        fmt="all",
        output_dir=str(tmp_path / "reports"),
        min_severity="HIGH",
        critical_path_only=True,
        snapshot=True,
        max_nodes=25,
    )

    assert calls["engagement_id"] == 42
    assert calls["db_path"] == tmp_path / "42.db"
    assert calls["output_dir"] == str(tmp_path / "reports")
    assert calls["fmt"] == "all"
    assert calls["min_severity"] == "HIGH"
    assert calls["critical_path_only"] is True
    assert calls["snapshot"] is True
    assert calls["max_nodes"] == 25
