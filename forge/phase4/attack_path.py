from __future__ import annotations

import json
import re
import sqlite3
import warnings
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import networkx as nx

from forge.models.attack_graph_models import (
    AttackEdge,
    AttackGraph,
    AttackGraphReportContext,
    AttackNode,
    NodeType,
    Severity,
)
from forge.utils.artifact_url_sanitizer import strip_sensitive_url_query
from forge.utils.cloud_exposure_gate import (
    is_deterministic_cloud_exposure,
    is_reportable_cloud_validation,
    linked_cloud_validation_reportability,
    normalize_cloud_exposure_asset_type,
)
from forge.utils.validation_summary import safe_validation_summary as _safe_validation_summary
from forge.utils.validation_proof import parse_validated_detail

_MERMAID_CHAR_LIMIT = 4_000
_DEFAULT_MAX_NODES = 150
_FORBIDDEN_KEYS = (
    "api_key",
    "apikey",
    "access_token",
    "client_secret",
    "credential",
    "credentials",
    "hash_plaintext",
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
)
_MAX_NODE_LABEL_LENGTH = 120
_SEED_BASE_METADATA_KEYS = {
    "confidence",
    "confidence_band",
    "depth",
    "seed_type",
    "source",
    "status",
}
_DISCOVERY_PROVIDER_SOURCES = {
    "shodan": ("shodan",),
    "shodan_dns": ("shodan",),
    "shodan_host": ("shodan",),
    "urlscan": ("urlscan",),
    "urlscan_related": ("urlscan",),
    "wayback": ("wayback",),
    "wayback_cdx": ("wayback",),
    "commoncrawl": ("commoncrawl",),
    # The kill-chain archive fan-out currently stores the merged Wayback
    # and CommonCrawl output as historical_cdx.
    "historical_cdx": ("wayback", "commoncrawl"),
}
_CLOUD_ASSET_GRAPH_LIST_METADATA_KEYS = {"archive_sources", "provider_sources"}
_CLOUD_ASSET_GRAPH_URL_METADATA_KEYS = {"source_file", "source_seed_url", "source_url"}
_CLOUD_ASSET_GRAPH_METADATA_KEYS = {
    "archive_sources",
    "artifact_provenance",
    "artifact_source_seed_id",
    "artifact_type",
    "barcode_payload_count",
    "content_type",
    "discovered_from",
    "download_filename",
    "downloaded_from_remote",
    "extract_path",
    "extract_rule",
    "fixture_provider",
    "format",
    "hostname",
    "metadata_payload_count",
    "ocr_payload_count",
    "parser",
    "payload_count",
    "port",
    "provider_sources",
    "relationship_payload_count",
    "root_domain",
    "rule",
    "scan_domain",
    "scan_id",
    "scheme",
    "source",
    "source_backend",
    "source_file",
    "source_provider",
    "source_seed_url",
    "source_url",
}


class _ForgeConnection(sqlite3.Connection):
    pass


class _AttackGraph(AttackGraph):
    def model_dump_json(self, *args: Any, **kwargs: Any) -> str:
        if args or kwargs:
            return super().model_dump_json(*args, **kwargs)
        return json.dumps(self.model_dump(mode="json"), separators=(", ", ": "))


def _mermaid_escape(value: str | None) -> str:
    if value is None:
        return ""
    return (
        value.replace(":", "-")
        .replace('"', "'")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def _apc_to_severity(attack_path_class: str | None) -> Severity:
    if not attack_path_class:
        return Severity.INFO
    key = attack_path_class.strip().upper()
    if key == "CRITICAL":
        return Severity.CRITICAL
    if key == "HIGH":
        return Severity.HIGH
    if key == "MEDIUM":
        return Severity.MEDIUM
    if key == "LOW":
        return Severity.LOW
    if key == "INFO":
        return Severity.INFO
    return Severity.INFO


def _severity_to_weight(severity: Severity) -> float:
    if severity == Severity.CRITICAL:
        return 120.0
    if severity == Severity.HIGH:
        return 90.0
    if severity == Severity.MEDIUM:
        return 60.0
    if severity == Severity.LOW:
        return 30.0
    return 10.0


def _assert_no_sensitive_data(graph_json: str) -> None:
    forbidden_fingerprints = {_metadata_key_fingerprint(key) for key in _FORBIDDEN_KEYS}
    for key in _FORBIDDEN_KEYS:
        if re.search(rf'"{re.escape(key)}"\s*:', graph_json):
            raise ValueError(f"Sensitive key detected in graph output: {key}")
    try:
        payload = json.loads(graph_json)
    except Exception:
        return
    stack: list[object] = [payload]
    while stack:
        current = stack.pop()
        if isinstance(current, dict):
            for key, value in current.items():
                if key in _FORBIDDEN_KEYS or _metadata_key_fingerprint(key) in forbidden_fingerprints:
                    raise ValueError(f"Sensitive key detected in graph output: {key}")
                stack.append(value)
        elif isinstance(current, list):
                stack.extend(current)


def _metadata_key_fingerprint(key: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(key).lower())


def _scrub_graph_metadata(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}

    forbidden = {key.lower() for key in _FORBIDDEN_KEYS}
    forbidden.update(_metadata_key_fingerprint(key) for key in _FORBIDDEN_KEYS)

    def _scrub(current: Any) -> Any:
        if isinstance(current, dict):
            clean: dict[str, Any] = {}
            for raw_key, raw_value in current.items():
                key = str(raw_key)
                if key.lower() in forbidden or _metadata_key_fingerprint(key) in forbidden:
                    continue
                clean[key] = _scrub(raw_value)
            return clean
        if isinstance(current, list):
            return [_scrub(item) for item in current]
        if current is None or isinstance(current, (str, int, float, bool)):
            return current
        return str(current)

    scrubbed = _scrub(value)
    return scrubbed if isinstance(scrubbed, dict) else {}


def _append_unique_provider_sources(target: list[str], raw_value: Any) -> None:
    normalized = str(raw_value or "").strip().lower()
    if not normalized:
        return
    candidates = _DISCOVERY_PROVIDER_SOURCES.get(normalized, (normalized,))
    for candidate in candidates:
        if candidate and candidate not in target:
            target.append(candidate)


def _host_context_graph_metadata(raw_context: Any) -> dict[str, Any]:
    raw_text = str(raw_context or "").strip()
    if not raw_text:
        return {}
    try:
        parsed = json.loads(raw_text)
    except (TypeError, ValueError):
        return {}
    context = _scrub_graph_metadata(parsed)
    if not context:
        return {}

    metadata: dict[str, Any] = {"host_context": context}
    for key in (
        "discovery",
        "fixture_provider",
        "source",
        "source_backend",
        "source_provider",
        "root_domain",
        "synthetic_ip",
    ):
        if key in context:
            metadata[key] = context[key]

    provider_sources: list[str] = []
    for key in ("fixture_provider", "provider", "source_backend", "source_provider", "source", "discovery"):
        _append_unique_provider_sources(provider_sources, context.get(key))
    if provider_sources:
        metadata["provider_sources"] = provider_sources
    return metadata


def _stored_json_graph_metadata(raw_metadata: Any) -> dict[str, Any]:
    if raw_metadata is None:
        return {}
    if isinstance(raw_metadata, str):
        raw_text = raw_metadata.strip()
        if not raw_text:
            return {}
        try:
            parsed = json.loads(raw_text)
        except (TypeError, ValueError):
            return {}
        return _scrub_graph_metadata(parsed)
    return _scrub_graph_metadata(raw_metadata)


def _sanitize_graph_url_metadata(value: Any) -> str:
    text = str(value or "").strip()
    parsed = urlparse(text)
    if parsed.scheme not in {"http", "https"}:
        return text
    stripped = strip_sensitive_url_query(text)
    parsed = urlparse(stripped)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return stripped
    netloc = parsed.hostname
    if parsed.port:
        netloc = f"{netloc}:{parsed.port}"
    return parsed._replace(netloc=netloc).geturl()


def _stored_cloud_asset_graph_metadata(raw_metadata: Any) -> dict[str, Any]:
    metadata = _stored_json_graph_metadata(raw_metadata)
    if not metadata:
        return {}
    clean: dict[str, Any] = {}
    for key in sorted(_CLOUD_ASSET_GRAPH_METADATA_KEYS):
        value = metadata.get(key)
        if value in (None, "", [], {}):
            continue
        if key in _CLOUD_ASSET_GRAPH_LIST_METADATA_KEYS:
            if not isinstance(value, list):
                continue
            normalized: list[str] = []
            for raw_item in value:
                item = str(raw_item or "").strip()
                if item and item not in normalized:
                    normalized.append(item)
                if len(normalized) >= 8:
                    break
            if normalized:
                clean[key] = normalized
            continue
        if not isinstance(value, (str, int, float, bool)):
            continue
        clean[key] = (
            _sanitize_graph_url_metadata(value)
            if key in _CLOUD_ASSET_GRAPH_URL_METADATA_KEYS
            else value
        )
    return clean


def _seed_graph_metadata(raw_metadata: Any) -> dict[str, Any]:
    metadata = _scrub_graph_metadata(raw_metadata)
    if not metadata:
        return {}
    metadata.pop("synthesis", None)

    clean: dict[str, Any] = {}
    for key, value in metadata.items():
        output_key = "discovery_source" if key == "source" else key
        if output_key in _SEED_BASE_METADATA_KEYS:
            output_key = f"metadata_{output_key}"
        clean[output_key] = value
    return clean


def _table_exists(con: sqlite3.Connection, table_name: str) -> bool:
    try:
        row = con.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
            (table_name,),
        ).fetchone()
    except sqlite3.OperationalError:
        return False
    return row is not None


def _table_columns(con: sqlite3.Connection, table_name: str) -> set[str]:
    try:
        return {str(row[1]) for row in con.execute(f"PRAGMA table_info({table_name})").fetchall()}
    except sqlite3.OperationalError:
        return set()


def _safe_node_label(value: str | None) -> str:
    label = str(value or "").strip()
    if len(label) <= _MAX_NODE_LABEL_LENGTH:
        return label
    return label[: _MAX_NODE_LABEL_LENGTH - 1] + "…"


def _node_type_label(node_type: NodeType) -> str:
    return node_type.value if hasattr(node_type, "value") else str(node_type)


class AttackGraphBuilder:
    def __init__(
        self,
        engagement_id: int,
        db_path: Path,
        min_severity: Severity = Severity.LOW,
        max_nodes: int = _DEFAULT_MAX_NODES,
    ) -> None:
        self.engagement_id = engagement_id
        self.db_path = Path(db_path)
        self.min_severity = min_severity
        self.max_nodes = max_nodes
        self._g = nx.DiGraph()
        self._critical_path_nodes: list[str] = []
        self._critical_path_weight: float = 0.0
        self._pruned = False
        self._prune_reason: str | None = None
        self._host_by_id: dict[int, str] = {}
        self._host_by_ip: dict[str, str] = {}
        self._host_by_name: dict[str, str] = {}
        self._cloud_by_key: dict[tuple[str, str], str] = {}
        self._cloud_by_service: dict[str, str] = {}
        self._cloud_validation_by_key: dict[tuple[str, str], dict[str, Any]] = {}
        self._seed_node_by_id: dict[int, str] = {}

    def build(self) -> AttackGraph:
        self._reset()
        con = sqlite3.connect(self.db_path, factory=_ForgeConnection)
        try:
            con.execute("PRAGMA query_only=ON")
            engagement_name = self._load_engagement_name(con)
            self._load_hosts(con)
            self._load_cloud_validation_results(con)
            self._load_cloud_assets(con)
            self._load_engagement_seeds(con)
            self._load_seed_relations(con)
            self._load_credentials(con)
            self._load_exploits(con)
            self._load_vulns(con)
            self._load_api_keys(con)
            self._synthesise_impact()
            self._compute_critical_path()
            self._prune_to_limit()
            return self._to_graph_model(engagement_name)
        finally:
            con.close()

    def write_snapshot(self, graph: AttackGraph, mermaid: str, dot: str) -> None:
        graph_json = graph.model_dump_json()
        _assert_no_sensitive_data(graph_json)
        if not mermaid or len(mermaid) > _MERMAID_CHAR_LIMIT:
            mermaid = MermaidRenderer().render_bounded_preview(graph)
        con = sqlite3.connect(self.db_path)
        try:
            from forge.db.schema import apply_schema  # noqa: PLC0415

            apply_schema(con)
            con.execute(
                """
                INSERT INTO attack_graph_snapshots
                    (engagement_id, node_count, edge_count, critical_path_weight,
                     min_severity, pruned, graph_json, mermaid_output, dot_output)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    self.engagement_id,
                    graph.node_count,
                    graph.edge_count,
                    graph.critical_path_weight,
                    graph.min_severity_filter.value,
                    1 if graph.pruned else 0,
                    graph_json,
                    mermaid,
                    dot,
                ),
            )
            con.commit()
        finally:
            con.close()

    def _reset(self) -> None:
        self._g = nx.DiGraph()
        self._critical_path_nodes = []
        self._critical_path_weight = 0.0
        self._pruned = False
        self._prune_reason = None
        self._host_by_id = {}
        self._host_by_ip = {}
        self._host_by_name = {}
        self._cloud_by_key = {}
        self._cloud_by_service = {}
        self._cloud_validation_by_key = {}
        self._seed_node_by_id = {}

    def _load_engagement_name(self, con: sqlite3.Connection) -> str:
        row = con.execute(
            "SELECT name FROM engagements WHERE id=?",
            (self.engagement_id,),
        ).fetchone()
        return str(row[0]) if row and row[0] else f"engagement-{self.engagement_id}"

    def _passes_min_severity(self, severity: Severity) -> bool:
        if self.min_severity == Severity.LOW:
            return True
        return severity.numeric >= self.min_severity.numeric

    def _add_node(self, node: AttackNode) -> None:
        self._g.add_node(node.node_id, data=node)

    def _add_edge(self, edge: AttackEdge) -> None:
        if edge.source_node_id not in self._g.nodes or edge.target_node_id not in self._g.nodes:
            return
        existing = self._g.get_edge_data(edge.source_node_id, edge.target_node_id)
        if existing and existing.get("data"):
            prev: AttackEdge = existing["data"]
            if prev.weight >= edge.weight:
                return
        self._g.add_edge(edge.source_node_id, edge.target_node_id, data=edge, weight=edge.weight)

    def _node_for_host(self, host_ref: str | None) -> str | None:
        if not host_ref:
            return None
        key = host_ref.strip().lower()
        if key in self._host_by_ip:
            return self._host_by_ip[key]
        if key in self._host_by_name:
            return self._host_by_name[key]
        node_id = f"HOST::{host_ref}"
        node = AttackNode(
            node_id=node_id,
            node_type=NodeType.HOST,
            label=host_ref,
            source_table="hosts",
            source_id=0,
            engagement_id=self.engagement_id,
            metadata={},
        )
        self._add_node(node)
        self._host_by_ip[key] = node_id
        self._host_by_name[key] = node_id
        ext_id = f"EXT::engagement-{self.engagement_id}"
        if ext_id in self._g.nodes:
            self._add_edge(
                AttackEdge(
                    source_node_id=ext_id,
                    target_node_id=node_id,
                    weight=10.0,
                    edge_type="entry",
                )
            )
        return node_id

    def _node_for_cloud(self, service: str, identifier: str | None = None) -> str:
        raw_svc = (service or "cloud").strip().lower()
        svc = normalize_cloud_exposure_asset_type(raw_svc)
        ident = (identifier or svc).strip().lower()
        cloud_key = (svc, ident)
        explicit_identifier = bool(identifier and ident and ident != svc)
        if cloud_key in self._cloud_by_key:
            return self._cloud_by_key[cloud_key]
        if not explicit_identifier and svc in self._cloud_by_service:
            return self._cloud_by_service[svc]
        node_id = f"CLOUD::{svc}::{ident}"
        node = AttackNode(
            node_id=node_id,
            node_type=NodeType.CLOUD,
            label=_safe_node_label(f"{svc}:{ident}"),
            source_table="cloud_assets",
            source_id=0,
            engagement_id=self.engagement_id,
            metadata={
                "service": svc,
                "identifier": ident,
                **({"asset_type_original": raw_svc} if raw_svc and raw_svc != svc else {}),
                **self._cloud_validation_by_key.get((svc, ident), {}),
            },
        )
        self._add_node(node)
        self._cloud_by_key[cloud_key] = node_id
        if not explicit_identifier or svc not in self._cloud_by_service:
            self._cloud_by_service[svc] = node_id
        return node_id

    def _load_cloud_validation_results(self, con: sqlite3.Connection) -> None:
        if not _table_exists(con, "cloud_validation_results"):
            return
        columns = _table_columns(con, "cloud_validation_results")
        id_expr = "id" if "id" in columns else "0 AS id"
        checked_at_expr = "checked_at" if "checked_at" in columns else "'' AS checked_at"
        provider_expr = (
            "COALESCE(NULLIF(provider_identifier, ''), identifier) AS provider_identifier"
            if "provider_identifier" in columns
            else "identifier AS provider_identifier"
        )
        notes_expr = "notes" if "notes" in columns else "NULL AS notes"
        evidence_expr = "evidence" if "evidence" in columns else "NULL AS evidence"
        order_checked_at_expr = "COALESCE(checked_at, '')" if "checked_at" in columns else "''"
        order_id_expr = "id" if "id" in columns else "0"
        rows = con.execute(
            f"""
            SELECT {id_expr},
                   asset_type,
                   identifier,
                   {provider_expr},
                   validation_status,
                   validation_method,
                   http_status,
                   {checked_at_expr},
                   {notes_expr},
                   {evidence_expr}
            FROM cloud_validation_results
            WHERE engagement_id=?
            ORDER BY asset_type ASC,
                     identifier ASC,
                     {order_checked_at_expr} ASC,
                     {order_id_expr} ASC
            """,
            (self.engagement_id,),
        ).fetchall()
        for (
            _row_id,
            asset_type,
            identifier,
            provider_identifier,
            status,
            method,
            http_status,
            checked_at,
            notes,
            evidence,
        ) in rows:
            raw_svc = str(asset_type or "cloud").strip().lower()
            svc = normalize_cloud_exposure_asset_type(raw_svc)
            ident = str(identifier or svc).strip().lower()
            metadata: dict[str, Any] = {
                "provider_identifier": str(provider_identifier or identifier or ""),
                "validation_asset_type": svc,
                **({"validation_asset_type_original": raw_svc} if raw_svc and raw_svc != svc else {}),
                "validation_status": str(status or ""),
                "validation_method": str(method or ""),
                "validation_reportable": is_reportable_cloud_validation(
                    svc,
                    str(status or ""),
                    str(method or ""),
                    evidence=evidence,
                    notes=notes,
                    require_stable_proof=True,
                ),
                "checked_at": str(checked_at or ""),
            }
            if http_status is not None:
                try:
                    metadata["http_status"] = int(http_status)
                except (TypeError, ValueError):
                    metadata["http_status"] = str(http_status)
            safe_notes = _safe_validation_summary(notes)
            safe_evidence = _safe_validation_summary(evidence)
            if safe_notes:
                metadata["validation_notes"] = safe_notes
            if safe_evidence:
                metadata["validation_evidence_summary"] = safe_evidence
            self._cloud_validation_by_key[(svc, ident)] = metadata

    def _load_hosts(self, con: sqlite3.Connection) -> None:
        ext_id = f"EXT::engagement-{self.engagement_id}"
        self._add_node(
            AttackNode(
                node_id=ext_id,
                node_type=NodeType.EXTERNAL,
                label="External",
                source_table="synthetic",
                source_id=0,
                engagement_id=self.engagement_id,
                metadata={},
            )
        )
        if not _table_exists(con, "hosts"):
            return
        columns = _table_columns(con, "hosts")
        host_context_expr = "host_context" if "host_context" in columns else "NULL AS host_context"
        rows = con.execute(
            f"""
            SELECT id, ip, hostname, os_family, {host_context_expr}
            FROM hosts
            WHERE engagement_id=?
            """,
            (self.engagement_id,),
        ).fetchall()
        for host_id, ip, hostname, os_family, host_context in rows:
            label = str(ip)
            if os_family:
                label = f"{ip} ({os_family})"
            node_id = f"HOST::{ip}"
            metadata = {
                "ip": str(ip),
                "hostname": str(hostname or ""),
                "os_family": str(os_family or ""),
            }
            metadata.update(_host_context_graph_metadata(host_context))
            node = AttackNode(
                node_id=node_id,
                node_type=NodeType.HOST,
                label=label,
                source_table="hosts",
                source_id=int(host_id),
                engagement_id=self.engagement_id,
                metadata=metadata,
            )
            self._add_node(node)
            self._host_by_id[int(host_id)] = node_id
            self._host_by_ip[str(ip).lower()] = node_id
            if hostname:
                self._host_by_name[str(hostname).lower()] = node_id
            self._add_edge(
                AttackEdge(
                    source_node_id=ext_id,
                    target_node_id=node_id,
                    weight=10.0,
                    edge_type="entry",
                )
            )

    def _load_cloud_assets(self, con: sqlite3.Connection) -> None:
        if not _table_exists(con, "cloud_assets"):
            return
        columns = _table_columns(con, "cloud_assets")
        provider_expr = (
            "COALESCE(NULLIF(provider_identifier, ''), identifier) AS provider_identifier"
            if "provider_identifier" in columns
            else "identifier AS provider_identifier"
        )
        metadata_expr = (
            "metadata_json"
            if "metadata_json" in columns
            else "NULL AS metadata_json"
        )
        rows = con.execute(
            f"""
            SELECT id, asset_type, identifier, {provider_expr}, source, {metadata_expr}
            FROM cloud_assets
            WHERE engagement_id=?
            """,
            (self.engagement_id,),
        ).fetchall()
        for asset_id, asset_type, identifier, provider_identifier, source, metadata_json in rows:
            raw_svc = str(asset_type or "cloud").strip().lower()
            svc = normalize_cloud_exposure_asset_type(raw_svc)
            ident = str(identifier or svc).strip().lower()
            cloud_key = (svc, ident)
            display_identifier = str(provider_identifier or identifier or ident)
            node_id = f"CLOUD::{svc}::{ident}"
            stored_metadata = _stored_cloud_asset_graph_metadata(metadata_json)
            metadata = {
                "service": svc,
                "identifier": ident,
                "provider_identifier": display_identifier,
                "source": str(source or ""),
                **({"asset_type_original": raw_svc} if raw_svc and raw_svc != svc else {}),
                **self._cloud_validation_by_key.get((svc, ident), {}),
            }
            for key, value in stored_metadata.items():
                if value is None or value == "":
                    continue
                output_key = str(key)
                if output_key in metadata:
                    output_key = f"metadata_{output_key}"
                metadata[output_key] = value
            existing_node = self._g.nodes.get(node_id, {}).get("data")
            if isinstance(existing_node, AttackNode):
                original_types = set(existing_node.metadata.get("asset_type_aliases") or [])
                for candidate_type in (
                    existing_node.metadata.get("asset_type_original"),
                    raw_svc,
                ):
                    candidate = str(candidate_type or "").strip().lower()
                    if candidate and candidate != svc:
                        original_types.add(candidate)
                existing_node.metadata.update(
                    {
                        key: value
                        for key, value in metadata.items()
                        if value not in (None, "")
                    }
                )
                if original_types:
                    existing_node.metadata["asset_type_aliases"] = sorted(original_types)
                self._cloud_by_key[cloud_key] = node_id
                self._cloud_by_service[svc] = node_id
                continue
            node = AttackNode(
                node_id=node_id,
                node_type=NodeType.CLOUD,
                label=_safe_node_label(f"{svc}:{display_identifier}"),
                source_table="cloud_assets",
                source_id=int(asset_id),
                engagement_id=self.engagement_id,
                metadata=metadata,
            )
            self._add_node(node)
            self._cloud_by_key[cloud_key] = node_id
            self._cloud_by_service[svc] = node_id
            ext_id = f"EXT::engagement-{self.engagement_id}"
            if ext_id in self._g.nodes:
                self._add_edge(
                    AttackEdge(
                        source_node_id=ext_id,
                        target_node_id=node_id,
                        weight=15.0,
                        label="cloud reference",
                        edge_type="cloud_reference",
                    )
                )

    def _seed_node_type(self, seed_type: str) -> NodeType:
        if seed_type in {"email", "phone", "username"}:
            return NodeType.CREDENTIAL
        if seed_type in {"domain", "subdomain", "url", "apk_url", "ipv4", "ipv6"}:
            return NodeType.HOST
        if seed_type in {"name", "company"}:
            return NodeType.EXTERNAL
        return NodeType.HOST

    def _load_engagement_seeds(self, con: sqlite3.Connection) -> None:
        if not _table_exists(con, "engagement_seeds"):
            return
        rows = con.execute(
            """
            SELECT id, seed_value, seed_type, source, status, depth, confidence, parent_seed_id, metadata_json
            FROM engagement_seeds
            WHERE engagement_id=?
            ORDER BY depth ASC, id ASC
            """,
            (self.engagement_id,),
        ).fetchall()
        ext_id = f"EXT::engagement-{self.engagement_id}"
        pending_parent_edges: list[tuple[int, int, float]] = []
        for seed_id, seed_value, seed_type, source, status, depth, confidence, parent_seed_id, metadata_json in rows:
            sid = int(seed_id)
            seed_type_text = str(seed_type or "other").lower()
            label = _safe_node_label(str(seed_value or ""))
            node_id = f"SEED::{sid}"
            metadata: dict[str, Any] = {
                "seed_type": seed_type_text,
                "source": str(source or ""),
                "status": str(status or ""),
                "depth": int(depth or 0),
                "confidence": float(confidence or 0.0),
            }
            if metadata_json:
                try:
                    parsed_metadata = json.loads(str(metadata_json))
                except Exception:
                    parsed_metadata = {}
                if isinstance(parsed_metadata, dict):
                    synthesis = (
                        parsed_metadata.get("synthesis")
                        if isinstance(parsed_metadata.get("synthesis"), dict)
                        else {}
                    )
                    confidence_band = parsed_metadata.get("confidence_band") or synthesis.get("confidence_band")
                    if confidence_band:
                        metadata["confidence_band"] = str(confidence_band)
                    metadata.update(_seed_graph_metadata(parsed_metadata))
            node = AttackNode(
                node_id=node_id,
                node_type=self._seed_node_type(seed_type_text),
                label=label,
                severity=Severity.INFO,
                source_table="engagement_seeds",
                source_id=sid,
                engagement_id=self.engagement_id,
                metadata=metadata,
            )
            self._add_node(node)
            self._seed_node_by_id[sid] = node_id
            if seed_type_text in {"domain", "subdomain", "ipv4", "ipv6", "url", "apk_url"}:
                self._host_by_name[str(seed_value or "").lower()] = node_id
            if parent_seed_id is not None:
                pending_parent_edges.append((int(parent_seed_id), sid, float(confidence or 0.5)))
            elif ext_id in self._g.nodes:
                self._add_edge(
                    AttackEdge(
                        source_node_id=ext_id,
                        target_node_id=node_id,
                        weight=max(5.0, min(80.0, float(confidence or 1.0) * 30.0)),
                        label="seed",
                        edge_type="seed",
                    )
                )

        for parent_seed_id, child_seed_id, confidence in pending_parent_edges:
            source_id = self._seed_node_by_id.get(parent_seed_id)
            target_id = self._seed_node_by_id.get(child_seed_id)
            if not source_id or not target_id:
                continue
            self._add_edge(
                AttackEdge(
                    source_node_id=source_id,
                    target_node_id=target_id,
                    weight=max(5.0, min(80.0, confidence * 60.0)),
                    label="derived",
                    edge_type="derived_from",
                )
            )

    def _load_seed_relations(self, con: sqlite3.Connection) -> None:
        if not _table_exists(con, "seed_relations"):
            return
        rows = con.execute(
            """
            SELECT source_seed_id, target_seed_id, relation_type, confidence, evidence_json
            FROM seed_relations
            WHERE engagement_id=?
            ORDER BY confidence DESC, id ASC
            """,
            (self.engagement_id,),
        ).fetchall()
        for source_seed_id, target_seed_id, relation_type, confidence, evidence_json in rows:
            source_id = self._seed_node_by_id.get(int(source_seed_id))
            target_id = self._seed_node_by_id.get(int(target_seed_id))
            if not source_id or not target_id:
                continue
            relation = str(relation_type or "related_asset")
            evidence: dict[str, Any] = {}
            if evidence_json:
                try:
                    parsed_evidence = json.loads(str(evidence_json))
                except Exception:
                    parsed_evidence = {}
                evidence = _scrub_graph_metadata(parsed_evidence)
            self._add_edge(
                AttackEdge(
                    source_node_id=source_id,
                    target_node_id=target_id,
                    weight=max(5.0, min(100.0, float(confidence or 0.5) * 80.0)),
                    label=relation.replace("_", " "),
                    edge_type=relation,
                    metadata=evidence,
                )
            )

    def _load_credentials(self, con: sqlite3.Connection) -> None:
        if not _table_exists(con, "credentials"):
            return
        rows = con.execute(
            """
            SELECT id, email, validated_host, validated_service
            FROM credentials
            WHERE engagement_id=? AND validated=1
            """,
            (self.engagement_id,),
        ).fetchall()
        for cred_id, email, validated_host, validated_service in rows:
            domain = str(email).split("@")[-1].lower() if "@" in str(email) else "unknown"
            node_id = f"CRED::{cred_id}"
            node = AttackNode(
                node_id=node_id,
                node_type=NodeType.CREDENTIAL,
                label=f"credential @{domain}",
                source_table="credentials",
                source_id=int(cred_id),
                engagement_id=self.engagement_id,
                metadata={"validated_service": str(validated_service or "")},
            )
            self._add_node(node)
            host_id = self._node_for_host(str(validated_host or ""))
            if host_id:
                self._add_edge(
                    AttackEdge(
                        source_node_id=node_id,
                        target_node_id=host_id,
                        weight=70.0,
                        edge_type="credential_use",
                    )
                )

    def _load_exploits(self, con: sqlite3.Connection) -> None:
        if not _table_exists(con, "exploit_suggestions"):
            return
        rows = con.execute(
            """
            SELECT es.id, es.host_id, es.exploit_db_id, es.exploit_title, es.priority, es.attack_path_class, h.ip
            FROM exploit_suggestions es
            LEFT JOIN hosts h ON h.id = es.host_id
            WHERE es.engagement_id=?
            """,
            (self.engagement_id,),
        ).fetchall()
        for expl_id, host_id, edb_id, title, priority, apc, host_ip in rows:
            severity = _apc_to_severity(apc)
            if not self._passes_min_severity(severity):
                continue
            eid = str(edb_id or f"EXP-{expl_id}")
            node_id = f"EXPL::{eid}-{expl_id}"
            node = AttackNode(
                node_id=node_id,
                node_type=NodeType.EXPLOIT,
                label=str(title or eid)[:120],
                severity=severity,
                source_table="exploit_suggestions",
                source_id=int(expl_id),
                engagement_id=self.engagement_id,
                metadata={"priority": float(priority or 0.0), "edb_id": eid},
            )
            self._add_node(node)
            host_node = self._host_by_id.get(int(host_id)) if host_id is not None else None
            if not host_node:
                host_node = self._node_for_host(str(host_ip or ""))
            if host_node:
                self._add_edge(
                    AttackEdge(
                        source_node_id=host_node,
                        target_node_id=node_id,
                        weight=max(1.0, float(priority or _severity_to_weight(severity))),
                        edge_type="exploit_applies",
                    )
                )

    def _vuln_cloud_identity(self, vuln_type: str, target_url: str) -> tuple[str, str]:
        host = urlparse(target_url).hostname or ""
        host = host.lower()
        if vuln_type == "FIREBASE_MISCONFIG":
            project = host.split(".")[0] if host else "firebase"
            return "firebase", project
        if vuln_type == "SUPABASE_RLS":
            project = host.split(".")[0] if host else "supabase"
            return "supabase", project
        return "cloud", host or "cloud"

    def _validation_lookup_service(self, provider: str, parameter: str, target_url: str) -> str:
        normalized = str(provider or "").strip().lower()
        hint = f"{parameter} {target_url}".lower()
        if normalized in {"firebase", "supabase"}:
            return normalized
        if not normalized and "firebase" in hint:
            return "firebase"
        if not normalized and "supabase" in hint:
            return "supabase"
        if normalized in {"s3", "aws_s3"}:
            return "aws_s3"
        if (normalized == "aws" and ("aws_s3" in hint or "s3://" in hint)) or (
            not normalized and ("aws_s3" in hint or "s3://" in hint)
        ):
            return "aws_s3"
        if normalized in {"gcs", "google_cloud_storage"}:
            return "gcs"
        if (normalized in {"gcp", "google"} and ("gcs" in hint or "gs://" in hint)) or (
            not normalized and ("gcs" in hint or "gs://" in hint)
        ):
            return "gcs"
        if normalized in {"azure_blob", "azure_blob_storage"}:
            return "azure_blob"
        if (normalized == "azure" and "blob" in hint) or (
            not normalized and ("azure_blob" in hint or "blob.core.windows.net" in hint)
        ):
            return "azure_blob"
        if normalized in {"do_spaces", "digitalocean_spaces"}:
            return "do_spaces"
        if (normalized in {"digitalocean", "do"} and "space" in hint) or (
            not normalized and ("do_spaces" in hint or "digitaloceanspaces.com" in hint)
        ):
            return "do_spaces"
        return normalize_cloud_exposure_asset_type(normalized)

    @staticmethod
    def _validation_lookup_identifier(
        service: str,
        resource_id: str,
        parameter: str,
        target_url: str,
    ) -> str:
        explicit = str(resource_id or "").strip().lower()
        if explicit:
            return explicit
        service_normalized = normalize_cloud_exposure_asset_type(service)
        candidates = [str(target_url or "").strip(), str(parameter or "").strip()]
        for raw_candidate in candidates:
            candidate = raw_candidate.lower()
            if not candidate:
                continue
            parsed = urlparse(candidate)
            host = (parsed.hostname or "").lower()
            if service_normalized == "firebase" and host.endswith(".firebaseio.com"):
                return host.split(".", 1)[0]
            if service_normalized == "supabase" and host.endswith(".supabase.co"):
                return host.split(".", 1)[0]
            if host and service_normalized in {"aws_s3", "azure_blob", "do_spaces", "gcs"}:
                return host.split(".", 1)[0]
            if "://" not in candidate and "/" not in candidate and " " not in candidate:
                if normalize_cloud_exposure_asset_type(candidate) != service_normalized:
                    return candidate
            if service_normalized == "azure_blob" and "/" in candidate and "://" not in candidate:
                return candidate
        return ""

    @staticmethod
    def _cloud_exposure_is_validated(validation_metadata: dict[str, Any] | None) -> bool:
        if not validation_metadata:
            return False
        if "validation_reportable" in validation_metadata:
            return validation_metadata.get("validation_reportable") is True
        return is_reportable_cloud_validation(
            str(validation_metadata.get("validation_asset_type") or ""),
            str(validation_metadata.get("validation_status") or ""),
            str(validation_metadata.get("validation_method") or ""),
            evidence=validation_metadata.get("validation_evidence_summary"),
            notes=validation_metadata.get("validation_notes"),
            require_stable_proof=True,
        )

    @staticmethod
    def _vuln_is_deterministic_cloud_exposure(
        vuln_type: str,
        title: str,
        validation_lookup_service: str,
    ) -> bool:
        return is_deterministic_cloud_exposure(
            vuln_type,
            title,
            (validation_lookup_service,),
        )

    @staticmethod
    def _vuln_is_deterministic_key_exposure(vuln_type: str, title: str) -> bool:
        return (
            str(vuln_type or "").strip().upper() == "DETERMINISTIC_KEY_EXPOSURE"
            or str(title or "").strip().lower().startswith("active exposed ")
        )

    def _load_vulns(self, con: sqlite3.Connection) -> None:
        if not _table_exists(con, "vulnerability_findings"):
            return
        columns = _table_columns(con, "vulnerability_findings")
        cloud_provider_expr = "cloud_provider" if "cloud_provider" in columns else "NULL AS cloud_provider"
        resource_id_expr = "resource_id" if "resource_id" in columns else "NULL AS resource_id"
        rows = con.execute(
            f"""
            SELECT id, vuln_type, target_url, parameter, severity, title,
                   {cloud_provider_expr}, {resource_id_expr}
            FROM vulnerability_findings
            WHERE engagement_id=?
            """,
            (self.engagement_id,),
        ).fetchall()
        for (
            vuln_id,
            vuln_type,
            target_url,
            parameter,
            severity_raw,
            title,
            cloud_provider,
            resource_id,
        ) in rows:
            try:
                severity = Severity(str(severity_raw).upper())
            except Exception:
                severity = Severity.INFO
            if not self._passes_min_severity(severity):
                continue
            vuln_type_str = str(vuln_type or "").upper()
            cloud_provider_str = str(cloud_provider or "").strip().lower()
            resource_id_str = str(resource_id or "").strip().lower()
            validation_lookup_service = self._validation_lookup_service(
                cloud_provider_str,
                str(parameter or ""),
                str(target_url or ""),
            )
            resource_id_str = self._validation_lookup_identifier(
                validation_lookup_service,
                resource_id_str,
                str(parameter or ""),
                str(target_url or ""),
            )
            validation_metadata = (
                self._cloud_validation_by_key.get((validation_lookup_service, resource_id_str))
                if validation_lookup_service and resource_id_str
                else None
            )
            if (
                self._vuln_is_deterministic_cloud_exposure(
                    vuln_type_str,
                    str(title or ""),
                    validation_lookup_service,
                )
                and not self._cloud_exposure_is_validated(validation_metadata)
            ):
                if validation_lookup_service and resource_id_str:
                    self._node_for_cloud(validation_lookup_service, resource_id_str)
                continue
            if self._vuln_is_deterministic_key_exposure(vuln_type_str, str(title or "")):
                linked_reportable = linked_cloud_validation_reportability(
                    {
                        key: value.get("validation_reportable") is True
                        for key, value in self._cloud_validation_by_key.items()
                    },
                    (validation_lookup_service,),
                    resource_id_str,
                )
                if linked_reportable is False:
                    if validation_lookup_service and resource_id_str:
                        self._node_for_cloud(validation_lookup_service, resource_id_str)
                    continue
            metadata: dict[str, Any] = {
                "vuln_type": vuln_type_str,
                "parameter": str(parameter or ""),
                "target_url": str(target_url or ""),
            }
            if cloud_provider_str:
                metadata["cloud_provider"] = cloud_provider_str
            if validation_lookup_service and validation_lookup_service != cloud_provider_str:
                metadata["validation_asset_type"] = validation_lookup_service
            if resource_id_str:
                metadata["resource_id"] = resource_id_str
            if validation_metadata:
                metadata.update(validation_metadata)
            node_id = f"VULN::{vuln_id}"
            node = AttackNode(
                node_id=node_id,
                node_type=NodeType.VULN,
                label=str(title or vuln_type_str)[:120],
                severity=severity,
                source_table="vulnerability_findings",
                source_id=int(vuln_id),
                engagement_id=self.engagement_id,
                metadata=metadata,
            )
            self._add_node(node)
            if validation_lookup_service and resource_id_str:
                cloud_id = self._node_for_cloud(validation_lookup_service, resource_id_str)
                self._add_edge(
                    AttackEdge(
                        source_node_id=cloud_id,
                        target_node_id=node_id,
                        weight=_severity_to_weight(severity),
                        edge_type="cloud_misconfig",
                    )
                )
            elif vuln_type_str in {"FIREBASE_MISCONFIG", "SUPABASE_RLS"}:
                service, identifier = self._vuln_cloud_identity(vuln_type_str, str(target_url or ""))
                cloud_id = self._node_for_cloud(service, identifier)
                self._add_edge(
                    AttackEdge(
                        source_node_id=cloud_id,
                        target_node_id=node_id,
                        weight=_severity_to_weight(severity),
                        edge_type="cloud_misconfig",
                    )
                )
            else:
                host = urlparse(str(target_url or "")).hostname or ""
                host_id = self._node_for_host(host)
                if host_id:
                    self._add_edge(
                        AttackEdge(
                            source_node_id=host_id,
                            target_node_id=node_id,
                            weight=_severity_to_weight(severity),
                            edge_type="vuln_found",
                        )
                    )

    def _load_api_keys(self, con: sqlite3.Connection) -> None:
        if not _table_exists(con, "key_scanner_findings"):
            return
        columns = _table_columns(con, "key_scanner_findings")
        validation_detail_expr = (
            "validation_detail" if "validation_detail" in columns else "NULL AS validation_detail"
        )
        validated_at_expr = "validated_at" if "validated_at" in columns else "NULL AS validated_at"
        source_backend_expr = (
            "source_backend" if "source_backend" in columns else "NULL AS source_backend"
        )
        repo_name_expr = "repo_name" if "repo_name" in columns else "NULL AS repo_name"
        rows = con.execute(
            f"""
            SELECT id, service, pattern_name, key_redacted, domain, source_url,
                   validation_state,
                   {validation_detail_expr},
                   {validated_at_expr},
                   {source_backend_expr},
                   {repo_name_expr}
            FROM key_scanner_findings
            WHERE engagement_id=? AND validation_state='ACTIVE'
            """,
            (self.engagement_id,),
        ).fetchall()
        for (
            row_id,
            service,
            pattern_name,
            key_redacted,
            domain,
            source_url,
            validation_state,
            validation_detail,
            validated_at,
            source_backend,
            repo_name,
        ) in rows:
            svc = str(service or "unknown").lower()
            validation_proof = parse_validated_detail(validation_detail)
            if str(validation_proof["validation_status"] or "").upper() != "VALIDATED":
                continue
            metadata = {
                "service": svc,
                "pattern_name": str(pattern_name or ""),
                "domain": str(domain or ""),
                "source_url": str(source_url or ""),
                "source_backend": str(source_backend or ""),
                "repo_name": str(repo_name or ""),
                "validation_state": str(validation_state or ""),
                "validation_detail": str(validation_detail or "")[:512],
                "validation_status": str(validation_proof["validation_status"] or ""),
                "validation_method": str(validation_proof["validation_method"] or ""),
                "validation_proof": str(validation_proof["validation_proof"] or ""),
                "validated_at": str(validated_at or ""),
            }
            node_id = f"KEY::{row_id}"
            node = AttackNode(
                node_id=node_id,
                node_type=NodeType.APIKEY,
                label=f"{svc}:{key_redacted}",
                severity=Severity.HIGH,
                source_table="key_scanner_findings",
                source_id=int(row_id),
                engagement_id=self.engagement_id,
                metadata=metadata,
            )
            self._add_node(node)
            cloud_id = self._node_for_cloud(svc, svc)
            self._add_edge(
                AttackEdge(
                    source_node_id=node_id,
                    target_node_id=cloud_id,
                    weight=85.0,
                    edge_type="key_chains_to",
                )
            )

    def _synthesise_impact(self) -> None:
        candidates: list[str] = []
        for node_id, payload in self._g.nodes(data=True):
            node: AttackNode | None = payload.get("data")
            if not node:
                continue
            if node.node_type not in {NodeType.EXPLOIT, NodeType.VULN}:
                continue
            if node.severity not in {Severity.CRITICAL, Severity.HIGH}:
                continue
            candidates.append(node_id)
        if not candidates:
            return
        impact_id = f"IMP::engagement-{self.engagement_id}"
        impact = AttackNode(
            node_id=impact_id,
            node_type=NodeType.IMPACT,
            label="Impact",
            source_table="synthetic",
            source_id=0,
            engagement_id=self.engagement_id,
            metadata={},
        )
        self._add_node(impact)
        for source in candidates:
            source_node = self._g.nodes[source].get("data")
            if not isinstance(source_node, AttackNode):
                continue
            sev = source_node.severity or Severity.INFO
            self._add_edge(
                AttackEdge(
                    source_node_id=source,
                    target_node_id=impact_id,
                    weight=_severity_to_weight(sev) + 20.0,
                    edge_type="impact",
                )
            )

    def _compute_critical_path(self) -> None:
        for _, payload in self._g.nodes(data=True):
            node = payload.get("data")
            if node:
                node.on_critical_path = False
        for _, _, payload in self._g.edges(data=True):
            edge = payload.get("data")
            if edge:
                edge.on_critical_path = False
        if self._g.number_of_edges() == 0:
            self._critical_path_nodes = []
            self._critical_path_weight = 0.0
            return
        try:
            path = nx.dag_longest_path(self._g, weight="weight")
        except Exception:
            path = []
            ext = f"EXT::engagement-{self.engagement_id}"
            impact = f"IMP::engagement-{self.engagement_id}"
            if ext in self._g.nodes and impact in self._g.nodes:
                try:
                    path = nx.shortest_path(self._g, ext, impact)
                except Exception:
                    path = []
        if not path:
            self._critical_path_nodes = []
            self._critical_path_weight = 0.0
            return
        total = 0.0
        for node_id in path:
            self._g.nodes[node_id]["data"].on_critical_path = True
        for i in range(len(path) - 1):
            u = path[i]
            v = path[i + 1]
            payload = self._g.get_edge_data(u, v)
            if not payload or not payload.get("data"):
                continue
            path_edge: AttackEdge = payload["data"]
            path_edge.on_critical_path = True
            total += float(path_edge.weight)
        self._critical_path_nodes = path
        self._critical_path_weight = total

    def _severity_rank(self, node: AttackNode) -> int:
        if node.severity is None:
            return -1
        return node.severity.numeric

    def _prune_to_limit(self) -> None:
        if self._g.number_of_nodes() <= self.max_nodes:
            self._pruned = False
            self._prune_reason = None
            return
        self._pruned = True
        self._prune_reason = f"node_count>{self.max_nodes}"
        guard = 0
        while self._g.number_of_nodes() > self.max_nodes and guard < 10_000:
            guard += 1
            removable: list[tuple[int, str]] = []
            for node_id, payload in self._g.nodes(data=True):
                node: AttackNode | None = payload.get("data")
                if not node:
                    continue
                if node.node_type in {NodeType.EXTERNAL, NodeType.IMPACT}:
                    continue
                if node.on_critical_path:
                    continue
                if self._g.out_degree(node_id) != 0:
                    continue
                removable.append((self._severity_rank(node), node_id))
            if not removable:
                break
            removable.sort(key=lambda item: item[0])
            _, victim = removable[0]
            self._g.remove_node(victim)

    def _to_graph_model(self, engagement_name: str) -> AttackGraph:
        nodes = [payload["data"] for _, payload in self._g.nodes(data=True) if payload.get("data")]
        edges = [payload["data"] for _, _, payload in self._g.edges(data=True) if payload.get("data")]
        return _AttackGraph(
            engagement_id=self.engagement_id,
            engagement_name=engagement_name,
            node_count=len(nodes),
            edge_count=len(edges),
            critical_path_nodes=self._critical_path_nodes,
            critical_path_weight=self._critical_path_weight,
            nodes=nodes,
            edges=edges,
            generated_at=datetime.now(timezone.utc).isoformat(),
            min_severity_filter=self.min_severity,
            pruned=self._pruned,
            prune_reason=self._prune_reason,
        )


class MermaidRenderer:
    def render(self, graph: AttackGraph) -> str:
        output = self._render_full(graph)
        if len(output) > _MERMAID_CHAR_LIMIT:
            warnings.warn(
                f"Mermaid output is {len(output)} chars; exceeds {_MERMAID_CHAR_LIMIT}. "
                "Use render_bounded_preview() for report and snapshot previews.",
                stacklevel=2,
            )
        return output

    def render_bounded_preview(self, graph: AttackGraph, max_chars: int = _MERMAID_CHAR_LIMIT) -> str:
        """Return a valid Mermaid preview that never silently truncates large graphs."""
        full = self._render_full(graph)
        if len(full) <= max_chars:
            return full
        summary = self._render_summary(graph, original_chars=len(full))
        if len(summary) <= max_chars:
            return summary
        return "\n".join(
            [
                "flowchart LR",
                f"    S[Large graph summary: {graph.node_count} nodes / {graph.edge_count} edges]",
                "    S --> F[Full graph preserved in JSON GraphML MTGX and DOT artifacts]",
            ]
        )[:max_chars]

    def _render_full(self, graph: AttackGraph) -> str:
        node_alias: dict[str, str] = {node.node_id: f"N{i}" for i, node in enumerate(graph.nodes)}
        lines: list[str] = ["flowchart LR"]
        for node in graph.nodes:
            alias = node_alias[node.node_id]
            label = _mermaid_escape(node.label)
            shape = self._shape(node.node_type, alias, label)
            lines.append(f"    {shape}")
        for edge in graph.edges:
            src = node_alias.get(edge.source_node_id)
            dst = node_alias.get(edge.target_node_id)
            if not src or not dst:
                continue
            arrow = "==>" if edge.on_critical_path else "-->"
            label = f"|{_mermaid_escape(edge.label)}|" if edge.label else ""
            lines.append(f"    {src} {label}{arrow} {dst}")
        for node in graph.nodes:
            alias = node_alias[node.node_id]
            color = self._fill(node.node_type)
            lines.append(f"    style {alias} fill:{color},stroke:#333,stroke-width:1px")
        return "\n".join(lines)

    def _render_summary(self, graph: AttackGraph, original_chars: int) -> str:
        node_type_counts = Counter(_node_type_label(node.node_type) for node in graph.nodes)
        severity_counts = Counter(
            node.severity.value for node in graph.nodes if node.severity is not None
        )
        node_by_id = {node.node_id: node for node in graph.nodes}
        critical_path = []
        for node_id in graph.critical_path_nodes:
            if node_id not in node_by_id:
                continue
            label = _safe_node_label(node_by_id[node_id].label)
            if len(label) > 48:
                label = label[:47] + "…"
            critical_path.append(label)
            if len(critical_path) >= 8:
                break
        if len(graph.critical_path_nodes) > len(critical_path):
            critical_path.append(f"+{len(graph.critical_path_nodes) - len(critical_path)} more")

        lines = [
            "flowchart LR",
            (
                "    S[Large graph preview summarized: "
                f"{graph.node_count} nodes / {graph.edge_count} edges]"
            ),
            f"    S --> O[Original Mermaid: {original_chars} chars]",
            "    S --> F[Full graph preserved in JSON GraphML MTGX and DOT artifacts]",
        ]
        if graph.pruned:
            lines.append(f"    S --> P[Builder pruned graph: {_mermaid_escape(graph.prune_reason)}]")
        if critical_path:
            lines.append(
                "    S --> C[Critical path: "
                f"{_mermaid_escape(' -> '.join(critical_path))}]"
            )
        for index, (node_type, count) in enumerate(sorted(node_type_counts.items())):
            lines.append(f"    S --> T{index}[{_mermaid_escape(node_type)} nodes: {count}]")
        for index, severity in enumerate(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]):
            count = severity_counts.get(severity)
            if count:
                lines.append(f"    S --> V{index}[{severity}: {count}]")
        return "\n".join(lines)

    def _shape(self, node_type: NodeType, alias: str, label: str) -> str:
        if node_type == NodeType.EXTERNAL:
            return f"{alias}>{label}]"
        if node_type == NodeType.HOST:
            return f"{alias}[{label}]"
        if node_type == NodeType.CREDENTIAL:
            return f"{alias}[/{label}/]"
        if node_type == NodeType.EXPLOIT:
            return f"{alias}{{{label}}}"
        if node_type == NodeType.VULN:
            return f"{alias}[[{label}]]"
        if node_type == NodeType.CLOUD:
            return f"{alias}[({label})]"
        if node_type == NodeType.APIKEY:
            return f"{alias}{{{{{label}}}}}"
        return f"{alias}(({label}))"

    def _fill(self, node_type: NodeType) -> str:
        if node_type == NodeType.EXTERNAL:
            return "#6b7280"
        if node_type == NodeType.HOST:
            return "#2563eb"
        if node_type == NodeType.CREDENTIAL:
            return "#7c3aed"
        if node_type == NodeType.EXPLOIT:
            return "#dc2626"
        if node_type == NodeType.VULN:
            return "#ea580c"
        if node_type == NodeType.CLOUD:
            return "#0891b2"
        if node_type == NodeType.APIKEY:
            return "#0d9488"
        return "#22863a"


class DotRenderer:
    def render(self, graph: AttackGraph) -> str:
        lines = ["digraph attack_path {", "  rankdir=LR;"]
        for idx, node in enumerate(graph.nodes):
            alias = f"N{idx}"
            label = node.label.replace('"', "'")
            shape = self._shape(node.node_type)
            fill = self._fill(node.node_type)
            lines.append(
                f'  {alias} [label="{label}", shape={shape}, style=filled, fillcolor="{fill}"];'
            )
        node_alias: dict[str, str] = {node.node_id: f"N{i}" for i, node in enumerate(graph.nodes)}
        for edge in graph.edges:
            src = node_alias.get(edge.source_node_id)
            dst = node_alias.get(edge.target_node_id)
            if not src or not dst:
                continue
            attrs = [f'weight={edge.weight:.1f}']
            if edge.label:
                attrs.append(f'label="{edge.label.replace(chr(34), chr(39))}"')
            if edge.on_critical_path:
                attrs.append('color="red"')
                attrs.append("penwidth=2.0")
            lines.append(f"  {src} -> {dst} [{', '.join(attrs)}];")
        lines.append("}")
        return "\n".join(lines)

    def _shape(self, node_type: NodeType) -> str:
        if node_type == NodeType.HOST:
            return "ellipse"
        if node_type == NodeType.EXPLOIT:
            return "diamond"
        if node_type == NodeType.VULN:
            return "box"
        if node_type == NodeType.CLOUD:
            return "cylinder"
        if node_type == NodeType.CREDENTIAL:
            return "parallelogram"
        if node_type == NodeType.APIKEY:
            return "hexagon"
        if node_type == NodeType.EXTERNAL:
            return "invtriangle"
        return "doubleoctagon"

    def _fill(self, node_type: NodeType) -> str:
        if node_type == NodeType.EXTERNAL:
            return "#6b7280"
        if node_type == NodeType.HOST:
            return "#60a5fa"
        if node_type == NodeType.CREDENTIAL:
            return "#a78bfa"
        if node_type == NodeType.EXPLOIT:
            return "#f87171"
        if node_type == NodeType.VULN:
            return "#fb923c"
        if node_type == NodeType.CLOUD:
            return "#67e8f9"
        if node_type == NodeType.APIKEY:
            return "#5eead4"
        return "#86efac"


def build_report_context(
    engagement_id: int,
    db_path: Path,
    min_severity: Severity = Severity.HIGH,
) -> AttackGraphReportContext:
    builder = AttackGraphBuilder(
        engagement_id=engagement_id,
        db_path=db_path,
        min_severity=min_severity,
        max_nodes=60,
    )
    graph = builder.build()
    mermaid = MermaidRenderer().render_bounded_preview(graph)
    label_by_id = {node.node_id: node.label for node in graph.nodes}
    top_exploit_nodes = sorted(
        [n for n in graph.nodes if n.node_type == NodeType.EXPLOIT],
        key=lambda n: float(n.metadata.get("priority", 0.0)),
        reverse=True,
    )[:5]
    return AttackGraphReportContext(
        engagement_id=engagement_id,
        critical_path_summary=[label_by_id.get(nid, nid) for nid in graph.critical_path_nodes],
        critical_path_weight=graph.critical_path_weight,
        total_critical_nodes=sum(1 for n in graph.nodes if n.severity == Severity.CRITICAL),
        total_high_nodes=sum(1 for n in graph.nodes if n.severity == Severity.HIGH),
        top_exploits=[n.label for n in top_exploit_nodes],
        cloud_misconfig_count=sum(1 for n in graph.nodes if n.node_type == NodeType.CLOUD),
        idor_finding_count=sum(
            1
            for n in graph.nodes
            if n.node_type == NodeType.VULN and n.metadata.get("vuln_type") == "IDOR"
        ),
        has_validated_creds=any(n.node_type == NodeType.CREDENTIAL for n in graph.nodes),
        mermaid_snippet=mermaid,
    )
