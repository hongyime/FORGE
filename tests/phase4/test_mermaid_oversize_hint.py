"""Test that oversize Mermaid output warns operators about the CLI escape hatch.

P2/P3 audit item #6: the warning historically referenced only the Python
``render_bounded_preview()`` API, which isn't visible to CLI users. The
warning must now mention ``--critical-path-only`` so operators know how to
shrink the graph without editing code.
"""

from __future__ import annotations

import warnings

from forge.phase4.attack_path import MermaidRenderer, _MERMAID_CHAR_LIMIT
from forge.models.attack_graph_models import (
    AttackEdge,
    AttackGraph,
    AttackNode,
    NodeType,
    Severity,
)


def _make_oversize_graph() -> AttackGraph:
    """Build a synthetic graph large enough to blow past the char limit."""
    node_count = max(80, _MERMAID_CHAR_LIMIT // 24)
    nodes: list[AttackNode] = []
    edges: list[AttackEdge] = []
    for idx in range(node_count):
        nodes.append(
            AttackNode(
                node_id=f"HOST::synthetic-oversize-{idx:04d}",
                node_type=NodeType.HOST,
                label=f"synthetic_host_with_long_label_number_{idx:04d}",
                severity=Severity.LOW,
                source_table="hosts",
                source_id=idx + 1,
                engagement_id=999999,
                on_critical_path=False,
            )
        )
        if idx > 0:
            edges.append(
                AttackEdge(
                    source_node_id=f"HOST::synthetic-oversize-{idx - 1:04d}",
                    target_node_id=f"HOST::synthetic-oversize-{idx:04d}",
                    weight=1.0,
                    label=f"synthetic_edge_padding_number_{idx:04d}",
                    on_critical_path=False,
                    edge_type="vuln_found",
                )
            )
    return AttackGraph(
        engagement_id=999999,
        engagement_name="mermaid-hint-test",
        node_count=len(nodes),
        edge_count=len(edges),
        nodes=nodes,
        edges=edges,
        generated_at="2026-08-04T00:00:00Z",
    )


def test_oversize_mermaid_warning_mentions_critical_path_flag() -> None:
    renderer = MermaidRenderer()
    graph = _make_oversize_graph()
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        output = renderer.render(graph)
    assert len(output) > _MERMAID_CHAR_LIMIT, (
        "sanity check failed: synthetic graph rendered under the limit"
    )
    messages = [str(w.message) for w in caught]
    assert messages, "expected an oversize warning to be emitted"
    combined = "\n".join(messages)
    assert "--critical-path-only" in combined, (
        f"warning should mention the CLI escape hatch; got: {combined!r}"
    )
    assert "forge graph build" in combined, (
        "warning should mention the concrete CLI command"
    )
