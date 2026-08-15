"""Graph artifact discovery and GraphML/MTGX payload parsing."""
from __future__ import annotations

import json
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

from forge.audit.manifest import _graph_artifact_names
from forge.utils.validation_proof import parse_validated_detail
from forge.utils.validation_summary import safe_validation_summary as _safe_validation_summary

GRAPHML_NS = {"g": "http://graphml.graphdrawing.org/xmlns"}
MALTEGO_NS = {"m": "http://maltego.paterva.com/xml/mtgx"}

GRAPH_FORBIDDEN_METADATA_KEYS = {
    "api_key",
    "apikey",
    "access_token",
    "client_secret",
    "credential",
    "credentials",
    "key_enc",
    "key_raw",
    "password",
    "password_enc",
    "private_key",
    "raw_secret",
    "raw_token",
    "refresh_token",
    "secret",
    "secret_enc",
    "token",
    "token_enc",
}

_MTGX_NODE_CONTROL_PROPERTIES = {
    "label",
    "metadata_json",
    "node_type",
    "on_critical_path",
    "severity",
    "source_id",
    "source_table",
}
_MTGX_EDGE_CONTROL_PROPERTIES = {
    "edge_type",
    "metadata_json",
    "on_critical_path",
    "weight",
}


def _format_dt(value: str) -> str:
    if not value:
        return ""
    cleaned = value.replace("Z", "+00:00")
    for candidate in (cleaned, cleaned.replace(" ", "T", 1)):
        try:
            dt = datetime.fromisoformat(candidate)
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue
    return value


def _safe_json_loads(value: str) -> Any:
    try:
        return json.loads(value)
    except Exception:  # noqa: BLE001
        return None


def _is_sensitive_metadata_key(key: Any) -> bool:
    normalized = str(key or "").strip().lower()
    return (
        not normalized
        or normalized in GRAPH_FORBIDDEN_METADATA_KEYS
        or normalized.endswith("_enc")
    )


def _safe_graph_metadata_value(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, list):
        return [_safe_graph_metadata_value(item) for item in value[:50]]
    if isinstance(value, dict):
        return _safe_graph_metadata(value)
    return str(value)


def _safe_graph_metadata(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    clean: dict[str, Any] = {}
    for raw_key, raw_value in value.items():
        if _is_sensitive_metadata_key(raw_key):
            continue
        key = str(raw_key).strip()
        clean[key] = _safe_graph_metadata_value(raw_value)
    return clean


def _safe_metadata_property_value(raw: str) -> Any:
    parsed = _safe_json_loads(raw)
    if isinstance(parsed, dict):
        return _safe_graph_metadata(parsed)
    if parsed is not None:
        return _safe_graph_metadata_value(parsed)
    return raw


def _merge_validation_detail_metadata(metadata: dict[str, Any], raw: object) -> None:
    detail = str(raw or "").strip()
    if not detail:
        return
    metadata["validation_detail"] = detail
    proof = parse_validated_detail(detail, include_raw_proof=True)
    method = str(proof["validation_method"] or "").strip()
    if not method:
        return
    metadata["validation_status"] = str(proof["validation_status"] or "").strip()
    metadata["validation_method"] = method
    safe_proof = _safe_validation_summary(proof["validation_proof"])
    if safe_proof:
        metadata["validation_proof"] = safe_proof
    else:
        metadata.pop("validation_proof", None)
    safe_raw_proof = _safe_validation_summary(proof["validation_raw_proof"])
    if safe_raw_proof:
        metadata["validation_notes"] = safe_proof or safe_raw_proof


def _merge_metadata_json(metadata: dict[str, Any], raw: str) -> None:
    parsed_metadata = _safe_json_loads(raw)
    if isinstance(parsed_metadata, dict):
        metadata.update(_safe_graph_metadata(parsed_metadata))
        detail = metadata.get("validation_detail")
        if detail:
            _merge_validation_detail_metadata(metadata, detail)
    else:
        metadata["metadata_json"] = raw


def _merge_safe_forge_property(
    metadata: dict[str, Any],
    raw_name: str,
    raw_value: str,
    *,
    control_properties: set[str],
) -> None:
    if not raw_value:
        return
    name = str(raw_name or "").strip()
    if not name.startswith("forge."):
        return
    key = name.removeprefix("forge.").strip()
    if not key or key in control_properties or _is_sensitive_metadata_key(key):
        return
    if key == "validation_detail":
        _merge_validation_detail_metadata(metadata, raw_value)
        return
    metadata.setdefault(key, _safe_metadata_property_value(raw_value))


def graph_files(eng_id: str, reports_dir: Path) -> list[Path]:
    names = set(_graph_artifact_names(int(eng_id)))
    return sorted(
        (reports_dir / name for name in names if (reports_dir / name).exists()),
        key=lambda path: path.name.lower(),
    )


def graph_root_from_artifact(path: Path) -> ElementTree.Element | None:
    try:
        if path.suffix.lower() == ".graphml":
            return ElementTree.parse(path).getroot()
        if path.suffix.lower() == ".mtgx":
            with zipfile.ZipFile(path) as archive:
                graphml_name = next(
                    (
                        name
                        for name in archive.namelist()
                        if (
                            name.lower() == "graphs/graph1.graphml"
                            or name.lower().endswith(".graphml")
                        )
                    ),
                    "",
                )
                if not graphml_name:
                    return None
                return ElementTree.fromstring(archive.read(graphml_name))
    except Exception:  # noqa: BLE001
        return None
    return None


def graph_entity_type_to_node_type(entity_type: str) -> str:
    normalized = str(entity_type or "").strip().lower()
    if normalized in {
        "maltego.domain",
        "maltego.url",
        "maltego.ipv4address",
        "maltego.ipv6address",
    }:
        return "HOST"
    if normalized in {"maltego.emailaddress", "maltego.phonenumber", "maltego.alias"}:
        return "CREDENTIAL"
    if normalized in {"maltego.person", "maltego.company"}:
        return "EXTERNAL"
    return "UNKNOWN"


def graph_entity_properties(data: ElementTree.Element) -> tuple[str, dict[str, str]]:
    entity = data.find("m:MaltegoEntity", MALTEGO_NS)
    if entity is None:
        return "", {}
    entity_type = str(entity.attrib.get("type") or "").strip()
    properties: dict[str, str] = {}
    for prop in entity.findall(".//m:Property", MALTEGO_NS):
        name = str(prop.attrib.get("name") or "").strip()
        if not name:
            continue
        value = str(
            prop.findtext("m:Value", default="", namespaces=MALTEGO_NS) or ""
        ).strip()
        properties[name] = value
    return entity_type, properties


def graph_link_properties(data: ElementTree.Element) -> dict[str, str]:
    link = data.find("m:MaltegoLink", MALTEGO_NS)
    if link is None:
        return {}
    properties: dict[str, str] = {}
    for prop in link.findall(".//m:Property", MALTEGO_NS):
        name = str(prop.attrib.get("name") or "").strip()
        if not name:
            continue
        value = str(
            prop.findtext("m:Value", default="", namespaces=MALTEGO_NS) or ""
        ).strip()
        properties[name] = value
    return properties


def graph_payload_from_root(
    root: ElementTree.Element,
    *,
    source: str,
    generated_at: str,
) -> dict[str, Any] | None:
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []

    for node in root.findall(".//g:node", GRAPHML_NS):
        node_id = str(node.attrib.get("id") or "").strip()
        node_payload: dict[str, Any] = {
            "node_id": node_id or f"node-{len(nodes) + 1}",
            "label": node_id or f"Node {len(nodes) + 1}",
            "node_type": "UNKNOWN",
            "severity": "INFO",
            "source_table": "graphml",
            "source_id": 0,
            "on_critical_path": False,
            "metadata": {},
        }
        for data in node.findall("g:data", GRAPHML_NS):
            entity_type, properties = graph_entity_properties(data)
            if entity_type:
                label = (
                    properties.get("forge.label")
                    or properties.get("fqdn")
                    or properties.get("email")
                    or properties.get("person.fullname")
                    or properties.get("phone-number")
                    or properties.get("short-title")
                    or properties.get("alias")
                    or next(
                        (
                            value
                            for name, value in properties.items()
                            if value and not name.startswith("forge.")
                        ),
                        "",
                    )
                )
                if label:
                    node_payload["label"] = label
                node_payload["node_type"] = (
                    str(properties.get("forge.node_type") or "").strip().upper()
                    or graph_entity_type_to_node_type(entity_type)
                )
                node_payload["severity"] = (
                    str(properties.get("forge.severity") or "").strip().upper() or "INFO"
                )
                node_payload["source_table"] = (
                    str(properties.get("forge.source_table") or "").strip() or "mtgx"
                )
                if properties.get("forge.source_id"):
                    try:
                        node_payload["source_id"] = int(
                            str(properties["forge.source_id"]).strip()
                        )
                    except ValueError:
                        node_payload["source_id"] = str(
                            properties["forge.source_id"]
                        ).strip()
                metadata_json = str(properties.get("forge.metadata_json") or "").strip()
                if metadata_json:
                    _merge_metadata_json(node_payload["metadata"], metadata_json)
                node_payload["on_critical_path"] = (
                    properties.get("forge.on_critical_path") == "1"
                )
                node_payload["metadata"]["maltego_entity_type"] = entity_type
                for name, value in properties.items():
                    if not value:
                        continue
                    if name.startswith("forge."):
                        _merge_safe_forge_property(
                            node_payload["metadata"],
                            name,
                            value,
                            control_properties=_MTGX_NODE_CONTROL_PROPERTIES,
                        )
                        continue
                    if value == node_payload["label"] or _is_sensitive_metadata_key(name):
                        continue
                    node_payload["metadata"][name] = value
                continue

            for child in list(data):
                if child.tag.endswith("EntityRenderer"):
                    continue
            key = str(data.attrib.get("key") or "").strip().lower()
            text = str(data.text or "").strip()
            if not key:
                continue
            if key == "label" and text:
                node_payload["label"] = text
            elif key in {"entity_type", "node_type"} and text:
                node_payload["node_type"] = text.upper()
            elif key == "severity" and text:
                node_payload["severity"] = text.upper()
            elif key == "critical":
                node_payload["on_critical_path"] = text == "1"
            elif key == "source_table" and text:
                node_payload["source_table"] = text
            elif key == "source_id" and text:
                try:
                    node_payload["source_id"] = int(text)
                except ValueError:
                    node_payload["source_id"] = text
            elif key == "metadata_json" and text:
                _merge_metadata_json(node_payload["metadata"], text)
            elif text:
                if not _is_sensitive_metadata_key(key):
                    if key == "validation_detail":
                        _merge_validation_detail_metadata(node_payload["metadata"], text)
                    else:
                        node_payload["metadata"][key] = text
        nodes.append(node_payload)

    for edge in root.findall(".//g:edge", GRAPHML_NS):
        source_node_id = str(edge.attrib.get("source") or "").strip()
        target_node_id = str(edge.attrib.get("target") or "").strip()
        if not source_node_id or not target_node_id:
            continue
        edge_payload: dict[str, Any] = {
            "source_node_id": source_node_id,
            "target_node_id": target_node_id,
            "edge_type": "relationship",
            "weight": 1.0,
            "on_critical_path": False,
            "metadata": {},
        }
        for data in edge.findall("g:data", GRAPHML_NS):
            properties = graph_link_properties(data)
            if properties:
                edge_payload["edge_type"] = (
                    str(
                        properties.get("forge.edge_type")
                        or properties.get("maltego.link.manual.type")
                        or edge_payload["edge_type"]
                    )
                    .strip()
                    or "relationship"
                )
                if properties.get("forge.weight"):
                    try:
                        edge_payload["weight"] = float(properties["forge.weight"])
                    except ValueError:
                        pass
                edge_payload["on_critical_path"] = (
                    properties.get("forge.on_critical_path") == "1"
                )
                if properties.get("maltego.link.manual.type"):
                    edge_payload["label"] = properties["maltego.link.manual.type"]
                metadata_json = str(properties.get("forge.metadata_json") or "").strip()
                if metadata_json:
                    _merge_metadata_json(edge_payload["metadata"], metadata_json)
                for name, value in properties.items():
                    _merge_safe_forge_property(
                        edge_payload["metadata"],
                        name,
                        value,
                        control_properties=_MTGX_EDGE_CONTROL_PROPERTIES,
                    )
                continue

            key = str(data.attrib.get("key") or "").strip().lower()
            text = str(data.text or "").strip()
            if not key:
                continue
            if key in {"relation", "edge_type"} and text:
                edge_payload["edge_type"] = text
            elif key == "weight" and text:
                try:
                    edge_payload["weight"] = float(text)
                except ValueError:
                    pass
            elif key == "critical":
                edge_payload["on_critical_path"] = text == "1"
            elif key == "label" and text:
                edge_payload["label"] = text
            elif key in {"metadata_json", "edge_metadata_json"} and text:
                _merge_metadata_json(edge_payload["metadata"], text)
            elif text and not _is_sensitive_metadata_key(key):
                if key == "validation_detail":
                    _merge_validation_detail_metadata(edge_payload["metadata"], text)
                else:
                    edge_payload["metadata"][key] = text
        edges.append(edge_payload)

    if not nodes:
        return None

    critical_path_nodes = [
        str(node.get("node_id") or "")
        for node in nodes
        if bool(node.get("on_critical_path"))
    ]
    return {
        "nodes": nodes,
        "edges": edges,
        "critical_path_nodes": critical_path_nodes,
        "critical_path_weight": 0.0,
        "generated_at": generated_at,
        "source": source,
    }


def graph_payload_from_graphml(graphml_path: Path) -> dict[str, Any] | None:
    root = graph_root_from_artifact(graphml_path)
    if root is None:
        return None
    return graph_payload_from_root(
        root,
        source=graphml_path.name,
        generated_at=_format_dt(datetime.fromtimestamp(graphml_path.stat().st_mtime).isoformat()),
    )
