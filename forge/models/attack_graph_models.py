"""
forge/models/attack_graph_models.py
Pydantic v2 contracts for Module 4-H (Attack Path Visualizer).

These models are the canonical data contracts between:
  - The graph builder (AttackGraphBuilder) and all renderers.
  - The snapshot serialiser and Phase 6 report context builder.
  - pytest fixtures (use model_validate() to construct typed test inputs).

Design constraints (PRD v7.2 §9.18):
  - No credential plaintexts or hash values in any field.
  - All node IDs are engagement-scoped opaque strings (not raw DB IDs).
  - JSON serialisation via model.model_dump(mode='json') only — no custom
    __dict__ access or manual field iteration.
  - AttackNode._no_sensitive_metadata validator is the first line of defence
    against accidental credential leakage into the graph output.
  - AttackGraph._node_id_consistency validator catches dangling edge references
    at construction time, before any rendering or snapshot write.
"""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, model_validator

# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class NodeType(str, Enum):
    """Node type taxonomy — determines Mermaid shape, DOT shape, and rendering colour."""

    EXTERNAL = "EXTERNAL"  # Synthetic entry point (one per engagement)
    HOST = "HOST"  # Discovered host from hosts table
    CREDENTIAL = "CREDENTIAL"  # Validated credential from credentials table
    EXPLOIT = "EXPLOIT"  # Exploit suggestion from exploit_suggestions table
    VULN = "VULN"  # Vulnerability finding from vulnerability_findings table
    CLOUD = "CLOUD"  # Cloud asset from cloud_assets table
    APIKEY = "APIKEY"  # Active API key from key_scanner_findings table
    IMPACT = "IMPACT"  # Synthetic terminal node (compromise / exfiltration)


class Severity(str, Enum):
    """Finding severity levels — mirrors the CHECK constraint in vulnerability_findings."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def numeric(self) -> int:
        """Integer representation for severity comparisons and weight calculations."""
        return {
            "CRITICAL": 4,
            "HIGH": 3,
            "MEDIUM": 2,
            "LOW": 1,
            "INFO": 0,
        }[self.value]


class OutputFormat(str, Enum):
    """Supported rendering formats for the attack graph."""

    MERMAID = "mermaid"
    DOT = "dot"
    JSON = "json"
    MALTEGO = "maltego"
    ALL = "all"


# ---------------------------------------------------------------------------
# Node model
# ---------------------------------------------------------------------------


class AttackNode(BaseModel):
    """
    A single node in the attack graph.

    Node IDs are opaque engagement-scoped strings formatted as
    ``<NodeType>::<short_label>`` (e.g., ``HOST::10.0.0.5``,
    ``CRED::42``, ``EXPL::EDB-50560-7``).  They must never contain
    credential plaintexts, hash values, or API key material.
    """

    node_id: str = Field(
        description=(
            "Opaque engagement-scoped node identifier. "
            "Format: '<NodeType>::<short_label>'. "
            "Must never contain credential plaintexts, hash values, or API keys."
        )
    )
    node_type: NodeType
    label: str = Field(
        max_length=120,
        description=(
            "Human-readable display label. Truncated to 120 chars. Must not expose PII or secrets."
        ),
    )
    severity: Optional[Severity] = None
    source_table: str = Field(
        description="Name of the DB table this node was derived from (e.g., 'hosts')."
    )
    source_id: int = Field(description="Primary key of the source row in source_table.")
    engagement_id: int
    on_critical_path: bool = False
    metadata: dict = Field(
        default_factory=dict,
        description=(
            "Non-sensitive supplementary data for rendering "
            "(e.g., os_family, vuln_type, edb_id, service). "
            "FORBIDDEN keys: password, hash_plaintext, key_enc, key_raw, password_enc."
        ),
    )

    @model_validator(mode="after")
    def _no_sensitive_metadata(self) -> "AttackNode":
        """
        Reject nodes whose metadata dict contains any forbidden sensitive key.

        This is the first line of defence against credential material leaking
        into the serialised graph JSON.  A second guard (_assert_no_sensitive_data)
        runs at snapshot write time as a belt-and-suspenders check.
        """
        _FORBIDDEN: frozenset[str] = frozenset(
            {"password", "hash_plaintext", "key_enc", "key_raw", "password_enc"}
        )
        leaks = _FORBIDDEN & set(self.metadata.keys())
        if leaks:
            raise ValueError(
                f"AttackNode.metadata contains forbidden sensitive keys: {sorted(leaks)}. "
                "Strip all credential material before graph construction. "
                "Labels use entity IDs and short descriptive strings only."
            )
        return self


# ---------------------------------------------------------------------------
# Edge model
# ---------------------------------------------------------------------------


class AttackEdge(BaseModel):
    """
    A directed, weighted edge between two nodes in the attack graph.

    ``weight`` corresponds to the ``priority`` score from
    ``exploit_suggestions`` (0–200 scale) or a normalised equivalent for
    ``vulnerability_findings``.  Higher weight = more actionable attack path.
    """

    source_node_id: str
    target_node_id: str
    weight: float = Field(
        ge=0.0,
        le=200.0,
        description="Priority score on a 0–200 scale. Higher = more impactful.",
    )
    label: Optional[str] = Field(
        default=None,
        max_length=80,
        description=(
            "Human-readable relationship label "
            "(e.g., 'PTH via SMB', 'IDOR → PII exposure'). Optional."
        ),
    )
    on_critical_path: bool = False
    edge_type: str = Field(
        description=(
            "Relationship class. One of: "
            "'credential_use', 'exploit_applies', 'vuln_found', "
            "'cloud_misconfig', 'key_chains_to', 'entry', 'impact'."
        )
    )
    metadata: dict = Field(
        default_factory=dict,
        description=(
            "Non-sensitive supplementary relationship evidence. "
            "FORBIDDEN keys: password, hash_plaintext, key_enc, key_raw, password_enc."
        ),
    )

    @model_validator(mode="after")
    def _no_sensitive_metadata(self) -> "AttackEdge":
        _FORBIDDEN: frozenset[str] = frozenset(
            {"password", "hash_plaintext", "key_enc", "key_raw", "password_enc"}
        )
        leaks = _FORBIDDEN & set(self.metadata.keys())
        if leaks:
            raise ValueError(
                f"AttackEdge.metadata contains forbidden sensitive keys: {sorted(leaks)}. "
                "Strip all credential material before graph construction."
            )
        return self


# ---------------------------------------------------------------------------
# Graph model
# ---------------------------------------------------------------------------


class AttackGraph(BaseModel):
    """
    Complete serialisable attack graph for one engagement.

    Produced by AttackGraphBuilder.build() and consumed by:
      - MermaidRenderer  → Mermaid flowchart string
      - DotRenderer      → Graphviz DOT string
      - JsonRenderer     → JSON string (via model_dump_json())
      - Phase 6          → AttackGraphReportContext (summary slice)
      - attack_graph_snapshots table  → snapshot_at, graph_json, ...

    The _node_id_consistency validator guarantees every edge references a
    node that is actually present in the ``nodes`` list.  This catches bugs
    where a loader adds an edge before its endpoint node is created.
    """

    engagement_id: int
    engagement_name: str
    node_count: int = Field(ge=0)
    edge_count: int = Field(ge=0)
    critical_path_nodes: list[str] = Field(
        default_factory=list,
        description="Ordered list of node_ids on the highest-weight path.",
    )
    critical_path_weight: float = 0.0
    nodes: list[AttackNode]
    edges: list[AttackEdge]
    generated_at: str = Field(description="ISO-8601 UTC timestamp of graph generation.")
    min_severity_filter: Severity = Severity.LOW
    pruned: bool = False
    prune_reason: Optional[str] = None

    @model_validator(mode="after")
    def _node_id_consistency(self) -> "AttackGraph":
        """
        Validate that every edge references node IDs present in the nodes list.

        Raises ValueError listing all dangling edge references so the caller
        can trace the loader that produced them.
        """
        node_ids: set[str] = {n.node_id for n in self.nodes}
        missing: list[str] = []
        for edge in self.edges:
            if edge.source_node_id not in node_ids:
                missing.append(f"edge source '{edge.source_node_id}' not in node set")
            if edge.target_node_id not in node_ids:
                missing.append(f"edge target '{edge.target_node_id}' not in node set")
        if missing:
            details = "; ".join(missing)
            raise ValueError(
                f"AttackGraph has {len(missing)} dangling edge reference(s): {details}. "
                "Check that all loader methods add nodes before adding edges."
            )
        return self


# ---------------------------------------------------------------------------
# Phase 6 context slice
# ---------------------------------------------------------------------------


class AttackGraphReportContext(BaseModel):
    """
    Minimal graph summary injected into the Phase 6 LLM context.

    Derived from AttackGraph; never includes the full node/edge lists
    (too large for the Qwen2.5-1.5B model's context window).

    Used by forge/phase6/report_synthesizer.py to populate the
    "Attack Surface Summary" section of the engagement report.
    """

    engagement_id: int
    critical_path_summary: list[str] = Field(
        description="Human-readable labels of critical path nodes in traversal order.",
    )
    critical_path_weight: float
    total_critical_nodes: int = Field(
        ge=0,
        description="Count of nodes with severity=CRITICAL.",
    )
    total_high_nodes: int = Field(
        ge=0,
        description="Count of nodes with severity=HIGH.",
    )
    top_exploits: list[str] = Field(
        description=(
            "EDB IDs or vulnerability titles of the five highest-priority findings. "
            "Truncated to 5 entries at construction time."
        ),
    )
    cloud_misconfig_count: int = 0
    idor_finding_count: int = 0
    has_validated_creds: bool = False
    mermaid_snippet: Optional[str] = Field(
        default=None,
        description=(
            "Critical-path-only Mermaid graph embedded in the Phase 6 HTML report. "
            "Max 4 000 chars enforced at construction time by MermaidRenderer."
        ),
    )

    @model_validator(mode="after")
    def _truncate_top_exploits(self) -> "AttackGraphReportContext":
        """Ensure top_exploits never exceeds 5 entries (LLM context budget)."""
        if len(self.top_exploits) > 5:
            object.__setattr__(self, "top_exploits", self.top_exploits[:5])
        return self

    @model_validator(mode="after")
    def _mermaid_char_limit(self) -> "AttackGraphReportContext":
        """Warn and truncate mermaid_snippet if it exceeds 4 000 chars."""
        if self.mermaid_snippet and len(self.mermaid_snippet) > 4_000:
            import warnings

            warnings.warn(
                f"AttackGraphReportContext.mermaid_snippet is "
                f"{len(self.mermaid_snippet)} chars; truncating to 4 000. "
                "Re-run with --critical-path-only or --min-severity HIGH.",
                stacklevel=2,
            )
            object.__setattr__(self, "mermaid_snippet", self.mermaid_snippet[:4_000])
        return self
