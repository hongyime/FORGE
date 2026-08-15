"""Reusable attack-graph export service.

This module keeps graph rendering and artifact packaging out of Typer command
wrappers so scheduled jobs, demo proof packs, APIs, and tests can call the same
export path without importing ``forge.cli``.
"""

from __future__ import annotations

import csv as _csv
import json as _json
import re as _re
import zipfile as _zipfile
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit
from xml.etree import ElementTree as _ElementTree
import xml.sax.saxutils as _xs

from forge.models.attack_graph_models import AttackGraph, OutputFormat, Severity
from forge.phase4.attack_path import AttackGraphBuilder, DotRenderer, MermaidRenderer
from forge.utils.artifact_url_sanitizer import strip_sensitive_url_query


_FORBIDDEN_METADATA_KEYS = {
    "api_key",
    "apikey",
    "access_token",
    "authorization",
    "client_secret",
    "credential",
    "credentials",
    "hash_plaintext",
    "key_enc",
    "key_raw",
    "password",
    "password_enc",
    "password_hash",
    "password_plaintext_enc",
    "private_key",
    "raw_secret",
    "raw_token",
    "refresh_token",
    "secret",
    "secret_enc",
    "token",
    "token_enc",
}
_FORBIDDEN_METADATA_KEY_FRAGMENTS = ("authorization", "password", "secret", "token")


@dataclass(frozen=True)
class AttackGraphExportResult:
    """Artifacts emitted by an attack-graph export run."""

    engagement_id: int
    output_dir: Path
    graph: AttackGraph
    artifacts: dict[str, Path]
    snapshot_written: bool = False

    @property
    def node_count(self) -> int:
        return int(self.graph.node_count)

    @property
    def edge_count(self) -> int:
        return int(self.graph.edge_count)

    @property
    def critical_path_weight(self) -> float:
        return float(self.graph.critical_path_weight)


def _coerce_output_format(value: str | OutputFormat) -> OutputFormat:
    if isinstance(value, OutputFormat):
        return value
    return OutputFormat(str(value).strip().lower())


def _coerce_severity(value: str | Severity) -> Severity:
    if isinstance(value, Severity):
        return value
    return Severity(str(value).strip().upper())


def _is_sensitive_metadata_key(key: object) -> bool:
    normalized = str(key or "").strip().lower()
    return (
        not normalized
        or normalized in _FORBIDDEN_METADATA_KEYS
        or normalized.endswith("_enc")
        or any(fragment in normalized for fragment in _FORBIDDEN_METADATA_KEY_FRAGMENTS)
    )


def _safe_export_metadata_value(value: object) -> object:
    if value is None or isinstance(value, (int, float, bool)):
        return value
    if isinstance(value, str):
        return _safe_export_text_value(value)
    if isinstance(value, list):
        return [_safe_export_metadata_value(item) for item in value[:50]]
    if isinstance(value, tuple):
        return [_safe_export_metadata_value(item) for item in value[:50]]
    if isinstance(value, dict):
        return _safe_export_metadata(value)
    return str(value)


def _safe_export_text_value(value: str) -> str:
    stripped = strip_sensitive_url_query(value)
    parsed = urlsplit(stripped)
    if parsed.scheme not in {"http", "https"} or "@" not in parsed.netloc:
        return stripped
    host = parsed.hostname or ""
    if parsed.port is not None:
        host = f"{host}:{parsed.port}"
    return urlunsplit((parsed.scheme, host, parsed.path, parsed.query, parsed.fragment))


def _safe_export_metadata(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        return {}
    clean: dict[str, object] = {}
    for raw_key, raw_value in value.items():
        if _is_sensitive_metadata_key(raw_key):
            continue
        clean[str(raw_key).strip()] = _safe_export_metadata_value(raw_value)
    return clean


def _sanitize_graph_metadata(graph: AttackGraph) -> None:
    for node in graph.nodes:
        node.metadata = _safe_export_metadata(getattr(node, "metadata", {}) or {})
    for edge in graph.edges:
        edge.metadata = _safe_export_metadata(getattr(edge, "metadata", {}) or {})


def export_attack_graph(
    *,
    engagement_id: int,
    db_path: str | Path,
    output_dir: str | Path | None = None,
    fmt: str | OutputFormat = OutputFormat.JSON,
    min_severity: str | Severity = Severity.LOW,
    critical_path_only: bool = False,
    snapshot: bool = False,
    max_nodes: int = 150,
    emit: Callable[[str], None] | None = None,
) -> AttackGraphExportResult:
    """Build and write attack graph artifacts for one engagement DB."""

    out_dir = Path(output_dir) if output_dir is not None else Path(".")
    out_dir.mkdir(parents=True, exist_ok=True)

    builder = AttackGraphBuilder(
        engagement_id=int(engagement_id),
        db_path=Path(db_path),
        min_severity=_coerce_severity(min_severity),
        max_nodes=max_nodes,
    )
    graph = builder.build()

    if critical_path_only:
        cp_ids = set(graph.critical_path_nodes)
        graph.nodes[:] = [n for n in graph.nodes if n.node_id in cp_ids]
        graph.edges[:] = [
            e for e in graph.edges if e.source_node_id in cp_ids and e.target_node_id in cp_ids
        ]
    _sanitize_graph_metadata(graph)

    requested = _coerce_output_format(fmt)
    stem = f"{int(engagement_id)}_attack_graph"
    artifacts: dict[str, Path] = {}
    snapshot_written = False

    def _emit(message: str) -> None:
        if emit is not None:
            emit(message)

    def _node_type_text(node) -> str:
        raw = node.node_type.value if hasattr(node.node_type, "value") else str(node.node_type)
        return str(raw or "UNKNOWN").strip().upper() or "UNKNOWN"

    def _severity_text(node) -> str:
        raw = node.severity.value if node.severity and hasattr(node.severity, "value") else node.severity
        return str(raw or "").strip().upper()

    def _edge_relation(edge) -> str:
        label = str(getattr(edge, "label", "") or "").strip()
        if label:
            return label
        return str(getattr(edge, "edge_type", "") or "").strip()

    def _node_metadata_for_export(node) -> dict[str, object]:
        raw_metadata = getattr(node, "metadata", {}) or {}
        if not isinstance(raw_metadata, dict):
            return {}
        try:
            normalized = _json.loads(
                _json.dumps(raw_metadata, sort_keys=True, default=str)
            )
            return _safe_export_metadata(normalized)
        except Exception:
            return _safe_export_metadata({
                str(key): str(value)
                for key, value in sorted(raw_metadata.items(), key=lambda item: str(item[0]))
            })

    def _node_metadata_text(node) -> str:
        return _json.dumps(
            _node_metadata_for_export(node),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )

    def _analyst_property_text(value: object) -> str:
        if value is None:
            return ""
        if isinstance(value, (dict, list, tuple)):
            try:
                return _json.dumps(
                    value,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                    default=str,
                ).strip()
            except Exception:
                return str(value).strip()
        return str(value).strip()

    def _node_analyst_properties(node) -> dict[str, str]:
        metadata = _node_metadata_for_export(node)
        ordered_keys = (
            "source",
            "discovery_source",
            "seed_type",
            "depth",
            "confidence",
            "root_domain",
            "format",
            "payload_count",
            "archive_sources",
            "provider_sources",
            "content_type",
            "download_filename",
            "remote_download",
            "service",
            "identifier",
            "validation_status",
            "validation_method",
            "validation_state",
            "validation_detail",
            "validated_at",
            "source_backend",
            "source_url",
            "repo_name",
            "domain",
            "pattern_name",
            "cloud_provider",
            "resource_id",
            "vuln_type",
        )
        properties: dict[str, str] = {}
        for key in ordered_keys:
            value = metadata.get(key)
            text = _analyst_property_text(value)
            if not text:
                continue
            properties[key] = text[:512]
        return properties

    def _edge_metadata_for_export(edge) -> dict[str, object]:
        raw_metadata = getattr(edge, "metadata", {}) or {}
        if not isinstance(raw_metadata, dict):
            return {}
        try:
            normalized = _json.loads(
                _json.dumps(raw_metadata, sort_keys=True, default=str)
            )
            return _safe_export_metadata(normalized)
        except Exception:
            return _safe_export_metadata({
                str(key): str(value)
                for key, value in sorted(raw_metadata.items(), key=lambda item: str(item[0]))
            })

    def _edge_metadata_text(edge) -> str:
        return _json.dumps(
            _edge_metadata_for_export(edge),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )

    def _domain_like(value: str) -> bool:
        return bool(_re.fullmatch(r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+", value))

    def _phone_like(value: str) -> bool:
        digits = "".join(ch for ch in value if ch.isdigit())
        return len(digits) >= 7 and bool(_re.fullmatch(r"[+()0-9 .-]+", value))

    def _primary_entity_type(node) -> tuple[str, str, str]:
        import ipaddress as _ipaddress  # noqa: PLC0415

        label = str(node.label or node.node_id or "").strip()
        node_type = _node_type_text(node)
        metadata = _node_metadata_for_export(node)
        if node_type == "CLOUD":
            identifier = str(metadata.get("identifier") or "").strip()
            if identifier:
                label = identifier
        if node_type == "EXTERNAL" and " " in label and any(
            token in label.lower() for token in ("corp", "inc", "llc", "ltd", "company", "organization")
        ):
            return "maltego.Company", "company.name", label
        if "@" in label and " " not in label:
            return "maltego.EmailAddress", "email", label
        if label.lower().startswith(("http://", "https://")):
            return "maltego.URL", "short-title", label
        try:
            parsed_ip = _ipaddress.ip_address(label)
            if parsed_ip.version == 4:
                return "maltego.IPv4Address", "ipv4-address", label
        except ValueError:
            pass
        if node_type in {"HOST", "CLOUD"} and _domain_like(label.lower()):
            return "maltego.Domain", "fqdn", label.lower()
        if node_type == "EXTERNAL" and " " in label:
            return "maltego.Person", "person.fullname", label
        if _phone_like(label):
            return "maltego.PhoneNumber", "phone-number", label
        return "maltego.Alias", "alias", label

    def _layout_positions() -> dict[str, tuple[float, float]]:
        ordered_types = (
            "EXTERNAL",
            "HOST",
            "CLOUD",
            "CREDENTIAL",
            "APIKEY",
            "VULN",
            "EXPLOIT",
            "IMPACT",
            "UNKNOWN",
        )
        groups: dict[str, list[Any]] = {kind: [] for kind in ordered_types}
        for node in graph.nodes:
            groups.setdefault(_node_type_text(node), []).append(node)
        positions: dict[str, tuple[float, float]] = {}
        x_base = 120.0
        x_step = 220.0
        y_base = 120.0
        y_step = 120.0
        for column, kind in enumerate(list(ordered_types) + [kind for kind in groups if kind not in ordered_types]):
            nodes_for_kind = groups.get(kind, [])
            if not nodes_for_kind:
                continue
            for row_index, node in enumerate(nodes_for_kind):
                positions[str(node.node_id)] = (
                    x_base + column * x_step,
                    y_base + row_index * y_step,
                )
        return positions

    def _count_by(values: Iterable[str]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for raw in values:
            key = str(raw or "UNKNOWN").strip() or "UNKNOWN"
            counts[key] = counts.get(key, 0) + 1
        return dict(sorted(counts.items(), key=lambda item: item[0]))

    def _mtgx_manifest_payload() -> dict[str, object]:
        positions = _layout_positions()
        node_manifest: list[dict[str, object]] = []
        for node in graph.nodes:
            entity_type, primary_property, primary_value = _primary_entity_type(node)
            x, y = positions.get(str(node.node_id), (0.0, 0.0))
            node_manifest.append(
                {
                    "node_id": str(node.node_id),
                    "label": str(node.label or ""),
                    "forge_node_type": _node_type_text(node),
                    "maltego_entity_type": entity_type,
                    "primary_property": primary_property,
                    "primary_value": primary_value,
                    "severity": _severity_text(node),
                    "source_table": str(node.source_table or ""),
                    "source_id": int(node.source_id or 0),
                    "metadata": _node_metadata_for_export(node),
                    "analyst_properties": _node_analyst_properties(node),
                    "on_critical_path": bool(node.on_critical_path),
                    "layout": {"x": round(float(x), 1), "y": round(float(y), 1)},
                }
            )
        edge_manifest: list[dict[str, object]] = []
        for edge in graph.edges:
            edge_manifest.append(
                {
                    "source_node_id": str(edge.source_node_id),
                    "target_node_id": str(edge.target_node_id),
                    "relation": _edge_relation(edge),
                    "edge_type": str(getattr(edge, "edge_type", "") or ""),
                    "weight": float(getattr(edge, "weight", 1.0)),
                    "metadata": _edge_metadata_for_export(edge),
                    "on_critical_path": bool(getattr(edge, "on_critical_path", False)),
                }
            )

        return {
            "schema": "forge.mtgx.manifest.v1",
            "generated_at": str(graph.generated_at or ""),
            "engagement_id": int(graph.engagement_id),
            "engagement_name": str(graph.engagement_name or ""),
            "node_count": int(graph.node_count),
            "edge_count": int(graph.edge_count),
            "critical_path_node_count": len(graph.critical_path_nodes),
            "critical_path_weight": float(graph.critical_path_weight),
            "min_severity_filter": (
                graph.min_severity_filter.value
                if hasattr(graph.min_severity_filter, "value")
                else str(graph.min_severity_filter)
            ),
            "pruned": bool(graph.pruned),
            "prune_reason": graph.prune_reason,
            "node_type_counts": _count_by(_node_type_text(node) for node in graph.nodes),
            "severity_counts": _count_by(_severity_text(node) or "NONE" for node in graph.nodes),
            "layout_strategy": "deterministic_columnar_by_forge_node_type",
            "maltego_type_mapping": {
                "email_label": "maltego.EmailAddress",
                "url_label": "maltego.URL",
                "ip_label": "maltego.IPv4Address",
                "domain_host_or_cloud": "maltego.Domain",
                "person_external": "maltego.Person",
                "company_external": "maltego.Company",
                "phone_label": "maltego.PhoneNumber",
                "fallback": "maltego.Alias",
            },
            "nodes": node_manifest,
            "edges": edge_manifest,
            "safety_notes": [
                "FORGE graph exports are generated from persisted engagement evidence only.",
                "Sensitive plaintext credential fields are excluded by the graph exporter guard.",
                "Critical-path flags are deterministic graph annotations, not LLM output.",
            ],
        }

    def _mtgx_readme_text(manifest: dict[str, object]) -> str:
        node_type_counts = manifest.get("node_type_counts") or {}
        severity_counts = manifest.get("severity_counts") or {}
        lines = [
            "# FORGE Maltego Workspace",
            "",
            f"Engagement: {manifest.get('engagement_name') or manifest.get('engagement_id')}",
            f"Generated: {manifest.get('generated_at') or '-'}",
            f"Nodes: {manifest.get('node_count')}  Edges: {manifest.get('edge_count')}",
            f"Critical path nodes: {manifest.get('critical_path_node_count')}",
            f"Layout: {manifest.get('layout_strategy')}",
            "",
            "## Files",
            "",
            "- Graphs/Graph1.graphml: native Maltego graph workspace payload.",
            "- manifest.json: deterministic FORGE graph/export metadata and node mapping.",
            "- README.md: analyst quick-reference for this archive.",
            "",
            "## Node Types",
            "",
        ]
        if isinstance(node_type_counts, dict) and node_type_counts:
            lines.extend(f"- {key}: {value}" for key, value in sorted(node_type_counts.items()))
        else:
            lines.append("- none")
        lines.extend(["", "## Severities", ""])
        if isinstance(severity_counts, dict) and severity_counts:
            lines.extend(f"- {key}: {value}" for key, value in sorted(severity_counts.items()))
        else:
            lines.append("- none")
        lines.extend(
            [
                "",
                "## Analyst Notes",
                "",
                "- FORGE properties are stored on each Maltego entity under forge.* names.",
                "- The forge.node_type, forge.severity, and forge.on_critical_path fields are the primary filters.",
                "- Risk/severity values are produced by deterministic rule engines, not by LLM report text.",
            ]
        )
        return "\n".join(lines).rstrip() + "\n"

    def _generic_graphml() -> str:
        positions = _layout_positions()
        lines = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<graphml xmlns="http://graphml.graphdrawing.org/xmlns">',
            '  <key id="label" for="node" attr.name="label" attr.type="string"/>',
            '  <key id="entity_type" for="node" attr.name="entity_type" attr.type="string"/>',
            '  <key id="maltego_entity_type" for="node" attr.name="maltego_entity_type" attr.type="string"/>',
            '  <key id="primary_property" for="node" attr.name="primary_property" attr.type="string"/>',
            '  <key id="primary_value" for="node" attr.name="primary_value" attr.type="string"/>',
            '  <key id="severity" for="node" attr.name="severity" attr.type="string"/>',
            '  <key id="critical" for="node" attr.name="critical" attr.type="string"/>',
            '  <key id="source_table" for="node" attr.name="source_table" attr.type="string"/>',
            '  <key id="source_id" for="node" attr.name="source_id" attr.type="int"/>',
            '  <key id="metadata_json" for="node" attr.name="metadata_json" attr.type="string"/>',
            '  <key id="analyst_properties_json" for="node" attr.name="analyst_properties_json" attr.type="string"/>',
            '  <key id="layout_x" for="node" attr.name="layout_x" attr.type="double"/>',
            '  <key id="layout_y" for="node" attr.name="layout_y" attr.type="double"/>',
            '  <key id="weight" for="edge" attr.name="weight" attr.type="double"/>',
            '  <key id="edge_type" for="edge" attr.name="edge_type" attr.type="string"/>',
            '  <key id="relation" for="edge" attr.name="relation" attr.type="string"/>',
            '  <key id="edge_critical" for="edge" attr.name="critical" attr.type="string"/>',
            '  <key id="edge_metadata_json" for="edge" attr.name="metadata_json" attr.type="string"/>',
            '  <graph id="G" edgedefault="directed">',
        ]
        for node in graph.nodes:
            entity_type, primary_property, primary_value = _primary_entity_type(node)
            x, y = positions.get(str(node.node_id), (0.0, 0.0))
            lines.append(f'    <node id="{_xs.quoteattr(node.node_id)[1:-1]}">')
            lines.append(f'      <data key="label">{_xs.escape(str(node.label or ""))}</data>')
            lines.append(f'      <data key="entity_type">{_xs.escape(_node_type_text(node))}</data>')
            lines.append(f'      <data key="maltego_entity_type">{_xs.escape(entity_type)}</data>')
            lines.append(f'      <data key="primary_property">{_xs.escape(primary_property)}</data>')
            lines.append(f'      <data key="primary_value">{_xs.escape(primary_value)}</data>')
            lines.append(f'      <data key="severity">{_xs.escape(_severity_text(node))}</data>')
            lines.append(f'      <data key="critical">{"1" if node.on_critical_path else "0"}</data>')
            lines.append(f'      <data key="source_table">{_xs.escape(str(node.source_table or ""))}</data>')
            lines.append(f'      <data key="source_id">{int(node.source_id or 0)}</data>')
            lines.append(f'      <data key="metadata_json">{_xs.escape(_node_metadata_text(node))}</data>')
            lines.append(
                "      <data key=\"analyst_properties_json\">"
                f"{_xs.escape(_json.dumps(_node_analyst_properties(node), ensure_ascii=False, separators=(',', ':'), sort_keys=True))}"
                "</data>"
            )
            lines.append(f'      <data key="layout_x">{x:.1f}</data>')
            lines.append(f'      <data key="layout_y">{y:.1f}</data>')
            lines.append("    </node>")
        for edge in graph.edges:
            lines.append(
                f'    <edge source="{_xs.quoteattr(edge.source_node_id)[1:-1]}" '
                f'target="{_xs.quoteattr(edge.target_node_id)[1:-1]}">'
            )
            lines.append(f'      <data key="weight">{float(getattr(edge, "weight", 1.0))}</data>')
            lines.append(
                f'      <data key="edge_type">{_xs.escape(str(getattr(edge, "edge_type", "") or ""))}</data>'
            )
            lines.append(f'      <data key="relation">{_xs.escape(_edge_relation(edge))}</data>')
            lines.append(
                f'      <data key="edge_critical">{"1" if bool(getattr(edge, "on_critical_path", False)) else "0"}</data>'
            )
            lines.append(f'      <data key="edge_metadata_json">{_xs.escape(_edge_metadata_text(edge))}</data>')
            lines.append("    </edge>")
        lines.append("  </graph>")
        lines.append("</graphml>")
        return "\n".join(lines) + "\n"

    def _maltego_workspace_graphml() -> str:
        _ElementTree.register_namespace("", "http://graphml.graphdrawing.org/xmlns")
        _ElementTree.register_namespace("mtg", "http://maltego.paterva.com/xml/mtgx")
        graphml = _ElementTree.Element(
            "graphml",
            {
                "xmlns": "http://graphml.graphdrawing.org/xmlns",
                "xmlns:mtg": "http://maltego.paterva.com/xml/mtgx",
            },
        )
        for attrs in (
            {"id": "mtg_entity", "for": "node", "attr.name": "MaltegoEntity", "attr.type": "string"},
            {"id": "mtg_entity_renderer", "for": "node", "attr.name": "EntityRenderer", "yfiles.type": "nodegraphics"},
            {"id": "mtg_link", "for": "edge", "attr.name": "MaltegoLink", "attr.type": "string"},
            {"id": "mtg_link_renderer", "for": "edge", "attr.name": "LinkRenderer", "yfiles.type": "edgegraphics"},
        ):
            _ElementTree.SubElement(graphml, "key", attrs)

        graph_el = _ElementTree.SubElement(graphml, "graph", {"id": "G", "edgedefault": "directed"})
        positions = _layout_positions()

        def _property(parent, name: str, value: str, *, display_name: str = "") -> None:
            attrs = {
                "name": name,
                "type": "string",
                "hidden": "false",
                "nullable": "true",
                "readonly": "false",
            }
            if display_name:
                attrs["displayName"] = display_name
            prop = _ElementTree.SubElement(parent, "{http://maltego.paterva.com/xml/mtgx}Property", attrs)
            val = _ElementTree.SubElement(prop, "{http://maltego.paterva.com/xml/mtgx}Value")
            val.text = value

        for node in graph.nodes:
            node_el = _ElementTree.SubElement(graph_el, "node", {"id": str(node.node_id)})
            entity_type, primary_property, primary_value = _primary_entity_type(node)
            entity_data = _ElementTree.SubElement(node_el, "data", {"key": "mtg_entity"})
            entity_el = _ElementTree.SubElement(
                entity_data,
                "{http://maltego.paterva.com/xml/mtgx}MaltegoEntity",
                {"type": entity_type},
            )
            properties_el = _ElementTree.SubElement(
                entity_el,
                "{http://maltego.paterva.com/xml/mtgx}Properties",
            )
            _property(properties_el, primary_property, primary_value, display_name="Primary Value")
            _property(properties_el, "forge.label", str(node.label or ""), display_name="FORGE Label")
            _property(properties_el, "forge.node_type", _node_type_text(node), display_name="FORGE Node Type")
            _property(properties_el, "forge.severity", _severity_text(node), display_name="FORGE Severity")
            _property(properties_el, "forge.source_table", str(node.source_table or ""), display_name="FORGE Source Table")
            _property(properties_el, "forge.source_id", str(node.source_id), display_name="FORGE Source ID")
            _property(
                properties_el,
                "forge.metadata_json",
                _node_metadata_text(node),
                display_name="FORGE Metadata JSON",
            )
            for property_name, property_value in _node_analyst_properties(node).items():
                _property(
                    properties_el,
                    f"forge.{property_name}",
                    property_value,
                    display_name=f"FORGE {property_name.replace('_', ' ').title()}",
                )
            _property(
                properties_el,
                "forge.on_critical_path",
                "1" if bool(node.on_critical_path) else "0",
                display_name="FORGE Critical Path",
            )

            renderer_data = _ElementTree.SubElement(node_el, "data", {"key": "mtg_entity_renderer"})
            renderer_el = _ElementTree.SubElement(
                renderer_data,
                "{http://maltego.paterva.com/xml/mtgx}EntityRenderer",
            )
            x, y = positions.get(str(node.node_id), (0.0, 0.0))
            _ElementTree.SubElement(
                renderer_el,
                "{http://maltego.paterva.com/xml/mtgx}Position",
                {"x": f"{x:.1f}", "y": f"{y:.1f}"},
            )

        for edge_index, edge in enumerate(graph.edges, start=1):
            edge_el = _ElementTree.SubElement(
                graph_el,
                "edge",
                {
                    "id": f"e{edge_index}",
                    "source": str(edge.source_node_id),
                    "target": str(edge.target_node_id),
                },
            )
            link_data = _ElementTree.SubElement(edge_el, "data", {"key": "mtg_link"})
            link_el = _ElementTree.SubElement(
                link_data,
                "{http://maltego.paterva.com/xml/mtgx}MaltegoLink",
                {"type": "maltego.link.manual-link"},
            )
            link_props = _ElementTree.SubElement(
                link_el,
                "{http://maltego.paterva.com/xml/mtgx}Properties",
            )
            _property(
                link_props,
                "maltego.link.manual.type",
                _edge_relation(edge),
                display_name="Label",
            )
            _property(
                link_props,
                "forge.edge_type",
                str(getattr(edge, "edge_type", "") or ""),
                display_name="FORGE Edge Type",
            )
            _property(
                link_props,
                "forge.weight",
                str(float(getattr(edge, "weight", 1.0))),
                display_name="FORGE Weight",
            )
            _property(
                link_props,
                "forge.on_critical_path",
                "1" if bool(getattr(edge, "on_critical_path", False)) else "0",
                display_name="FORGE Critical Path",
            )
            _property(
                link_props,
                "forge.metadata_json",
                _edge_metadata_text(edge),
                display_name="FORGE Metadata JSON",
            )

            link_renderer_data = _ElementTree.SubElement(edge_el, "data", {"key": "mtg_link_renderer"})
            _ElementTree.SubElement(
                link_renderer_data,
                "{http://maltego.paterva.com/xml/mtgx}LinkRenderer",
            )

        return _ElementTree.tostring(graphml, encoding="utf-8", xml_declaration=True).decode("utf-8")

    mermaid_str = dot_str = json_str = ""

    if requested in (OutputFormat.MERMAID, OutputFormat.ALL):
        mermaid_str = MermaidRenderer().render_bounded_preview(graph)
        (out_dir / f"{stem}.mmd").write_text(mermaid_str, encoding="utf-8")
        artifacts["mermaid"] = out_dir / f"{stem}.mmd"
        _emit(f"[green]Mermaid:[/green] {artifacts['mermaid']}")

    if requested in (OutputFormat.DOT, OutputFormat.ALL):
        dot_str = DotRenderer().render(graph)
        (out_dir / f"{stem}.dot").write_text(dot_str, encoding="utf-8")
        artifacts["dot"] = out_dir / f"{stem}.dot"
        _emit(f"[green]DOT:[/green] {artifacts['dot']}")

    if requested in (OutputFormat.JSON, OutputFormat.ALL):
        json_str = graph.model_dump_json(indent=2)
        (out_dir / f"{stem}.json").write_text(json_str, encoding="utf-8")
        artifacts["json"] = out_dir / f"{stem}.json"
        _emit(f"[green]JSON:[/green] {artifacts['json']}")

    if requested in (OutputFormat.MALTEGO, OutputFormat.ALL):
        # Generic GraphML: portable import artifact used by the dashboard and
        # third-party tooling. The native MTGX workspace archive is emitted too.
        graphml_path = out_dir / f"{stem}.graphml"
        graphml_path.write_text(_generic_graphml(), encoding="utf-8")

        mtgx_path = out_dir / f"{stem}.mtgx"
        mtgx_manifest = _mtgx_manifest_payload()
        with _zipfile.ZipFile(mtgx_path, mode="w", compression=_zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("Graphs/Graph1.graphml", _maltego_workspace_graphml())
            archive.writestr(
                "manifest.json",
                _json.dumps(mtgx_manifest, indent=2, sort_keys=True),
            )
            archive.writestr("README.md", _mtgx_readme_text(mtgx_manifest))

        # Companion CSVs: friendly for "New Entities From CSV" wizard
        nodes_csv = out_dir / f"{stem}_nodes.csv"
        edges_csv = out_dir / f"{stem}_edges.csv"
        with nodes_csv.open("w", newline="", encoding="utf-8") as fh:
            w = _csv.writer(fh)
            w.writerow(["EntityID", "EntityType", "Label", "Severity",
                        "OnCriticalPath", "SourceTable", "MetadataJSON"])
            for n in graph.nodes:
                nt = n.node_type.value if hasattr(n.node_type, "value") else str(n.node_type)
                sev = n.severity.value if n.severity and hasattr(n.severity, "value") else (n.severity or "")
                w.writerow([n.node_id, nt, n.label, sev,
                            "1" if n.on_critical_path else "0", n.source_table,
                            _node_metadata_text(n)])
        with edges_csv.open("w", newline="", encoding="utf-8") as fh:
            w = _csv.writer(fh)
            w.writerow(["Source", "Target", "Weight", "Relation", "MetadataJSON"])
            for e in graph.edges:
                w.writerow([
                    e.source_node_id,
                    e.target_node_id,
                    float(getattr(e, "weight", 1.0)),
                    _edge_relation(e),
                    _edge_metadata_text(e),
                ])

        artifacts["mtgx"] = mtgx_path
        artifacts["graphml"] = graphml_path
        artifacts["nodes_csv"] = nodes_csv
        artifacts["edges_csv"] = edges_csv
        _emit(f"[green]Maltego MTGX:[/green] {mtgx_path}")
        _emit(f"[green]Maltego GraphML:[/green] {graphml_path}")
        _emit(f"[green]Nodes CSV:[/green] {nodes_csv}")
        _emit(f"[green]Edges CSV:[/green] {edges_csv}")
        _emit(
            "[dim]Open the .mtgx file in Maltego Graph (Desktop), or import the "
            ".graphml file in Community Edition if you need the lightweight path.[/dim]"
        )

    if snapshot:
        builder.write_snapshot(graph, mermaid=mermaid_str, dot=dot_str)
        snapshot_written = True
        _emit("[green]Snapshot written to attack_graph_snapshots.[/green]")

    _emit(
        f"[bold]Graph:[/bold] {graph.node_count} nodes · {graph.edge_count} edges · "
        f"critical path weight: {graph.critical_path_weight:.1f}"
    )

    return AttackGraphExportResult(
        engagement_id=int(engagement_id),
        output_dir=out_dir,
        graph=graph,
        artifacts=dict(artifacts),
        snapshot_written=snapshot_written,
    )
