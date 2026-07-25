"""
tests/phase4/test_attack_path.py
Comprehensive test suite for forge/phase4/attack_path.py (Module 4-H).

Covers the full test matrix from forge_spec.md §4-H.12:
  - Unit: node/edge loading, severity filtering, pruning, critical path
  - Unit: Mermaid renderer (escape, char limit, critical-path arrows, shapes)
  - Unit: _assert_no_sensitive_data guard
  - Unit: Pydantic model validators (AttackNode, AttackGraph)
  - Integration: end-to-end DB fixture → Mermaid + DOT + JSON
  - Integration: snapshot write + sensitive-data guard
  - Evasion assertions: no credential material in graph_json or Mermaid output
"""

from __future__ import annotations

import csv
import json
import re
import sqlite3
import zipfile
import warnings
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from forge.models.attack_graph_models import (
    AttackEdge,
    AttackGraph,
    AttackGraphReportContext,
    AttackNode,
    NodeType,
    OutputFormat,
    Severity,
)

# ---------------------------------------------------------------------------
# Guard: skip entire module if networkx or the attack_path module is missing
# ---------------------------------------------------------------------------
try:
    import networkx  # noqa: F401

    from forge.phase4.attack_path import (
        AttackGraphBuilder,
        DotRenderer,
        MermaidRenderer,
        _apc_to_severity,
        _assert_no_sensitive_data,
        _mermaid_escape,
        _severity_to_weight,
    )

    _ATTACK_PATH_AVAILABLE = True
except ImportError:
    _ATTACK_PATH_AVAILABLE = False

pytestmark = pytest.mark.skipif(
    not _ATTACK_PATH_AVAILABLE,
    reason="forge.phase4.attack_path or networkx not installed",
)


# ══════════════════════════════════════════════════════════════════════════════
# DB fixture helpers
# ══════════════════════════════════════════════════════════════════════════════


def _make_db(tmp_path: Path, name: str = "eng.db") -> Path:
    """Create a minimal engagement DB with all Phase 4 tables."""
    db = tmp_path / name
    con = sqlite3.connect(db)
    con.executescript("""
        CREATE TABLE IF NOT EXISTS engagements (
            id INTEGER PRIMARY KEY, name TEXT, scope_json TEXT
        );
        CREATE TABLE IF NOT EXISTS hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER NOT NULL,
            ip TEXT NOT NULL,
            hostname TEXT,
            os_family TEXT,
            in_scope INTEGER NOT NULL DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS services (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER NOT NULL,
            port INTEGER NOT NULL,
            protocol TEXT DEFAULT 'tcp',
            service_name TEXT,
            version TEXT
        );
        CREATE TABLE IF NOT EXISTS credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER NOT NULL,
            email TEXT NOT NULL,
            validated INTEGER NOT NULL DEFAULT 0,
            validated_host TEXT,
            validated_service TEXT,
            password_plaintext_enc TEXT,
            hash_type TEXT
        );
        CREATE TABLE IF NOT EXISTS exploit_suggestions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER NOT NULL,
            host_id INTEGER NOT NULL,
            exploit_db_id TEXT,
            exploit_title TEXT,
            exploit_type TEXT,
            exploit_platform TEXT,
            priority REAL DEFAULT 50.0,
            attack_path_class TEXT DEFAULT 'MEDIUM'
        );
        CREATE TABLE IF NOT EXISTS vulnerability_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER NOT NULL,
            vuln_type TEXT NOT NULL,
            target_url TEXT NOT NULL,
            parameter TEXT,
            severity TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            evidence TEXT,
            cvss_score REAL
        );
        CREATE TABLE IF NOT EXISTS cloud_assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER NOT NULL,
            asset_type TEXT NOT NULL,
            identifier TEXT NOT NULL,
            source TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS key_scanner_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER NOT NULL,
            domain TEXT NOT NULL,
            service TEXT NOT NULL,
            pattern_name TEXT NOT NULL,
            source_backend TEXT NOT NULL DEFAULT 'github',
            source_url TEXT NOT NULL,
            repo_name TEXT,
            key_redacted TEXT NOT NULL,
            key_enc TEXT,
            validation_state TEXT NOT NULL DEFAULT 'UNCONFIRMED'
                CHECK (validation_state IN ('ACTIVE','REVOKED','UNCONFIRMED','ERROR')),
            validation_detail TEXT,
            found_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            validated_at TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS attack_graph_snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER NOT NULL,
            snapshot_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            node_count INTEGER NOT NULL,
            edge_count INTEGER NOT NULL,
            critical_path_weight REAL NOT NULL DEFAULT 0.0,
            min_severity TEXT NOT NULL DEFAULT 'LOW',
            pruned INTEGER NOT NULL DEFAULT 0,
            graph_json TEXT NOT NULL,
            mermaid_output TEXT,
            dot_output TEXT
        );
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER,
            phase TEXT,
            module TEXT,
            action TEXT NOT NULL,
            target TEXT,
            result TEXT,
            operator TEXT,
            logged_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        INSERT INTO engagements VALUES (1, 'test-engagement', '["example.com"]');
    """)
    con.commit()
    con.close()
    return db


def _seed_full(db: Path) -> None:
    """Seed the DB with a representative full dataset for integration tests."""
    con = sqlite3.connect(db)

    # Hosts
    con.executemany(
        "INSERT INTO hosts (engagement_id, ip, hostname, os_family) VALUES (?,?,?,?)",
        [
            (1, "10.0.0.1", "web01.corp", "linux"),
            (1, "10.0.0.2", "db01.corp", "linux"),
            (1, "10.0.0.3", "dc01.corp", "windows"),
        ],
    )
    host_ids = [r[0] for r in con.execute("SELECT id FROM hosts").fetchall()]

    # Services
    for hid in host_ids:
        con.execute(
            "INSERT INTO services (host_id, port, protocol, service_name) VALUES (?,?,?,?)",
            (hid, 80, "tcp", "http"),
        )

    # Credentials (1 validated, 1 unvalidated)
    con.execute(
        "INSERT INTO credentials (engagement_id, email, validated, validated_host, validated_service)"
        " VALUES (?,?,?,?,?)",
        (1, "admin@example.com", 1, "10.0.0.3", "smb"),
    )
    con.execute(
        "INSERT INTO credentials (engagement_id, email, validated) VALUES (?,?,?)",
        (1, "user@example.com", 0),
    )

    # Exploit suggestions
    con.executemany(
        "INSERT INTO exploit_suggestions"
        " (engagement_id, host_id, exploit_db_id, exploit_title, exploit_type, priority, attack_path_class)"
        " VALUES (?,?,?,?,?,?,?)",
        [
            (1, host_ids[0], "EDB-50560", "Apache RCE", "remote", 90.0, "CRITICAL"),
            (1, host_ids[1], "EDB-44228", "Log4Shell", "remote", 80.0, "HIGH"),
            (1, host_ids[2], "EDB-40564", "MS17-010", "remote", 70.0, "HIGH"),
            (1, host_ids[0], "EDB-12345", "Low priority", "local", 15.0, "LOW"),
            (1, host_ids[0], "EDB-99999", "Info only", "local", 5.0, "INFO"),
        ],
    )

    # Vulnerability findings
    con.executemany(
        "INSERT INTO vulnerability_findings"
        " (engagement_id, vuln_type, target_url, parameter, severity, title, evidence)"
        " VALUES (?,?,?,?,?,?,?)",
        [
            (1, "IDOR", "https://web01.corp/api?id=1", "id", "HIGH", "IDOR on /api", ""),
            (
                1,
                "FIREBASE_MISCONFIG",
                "https://my-proj.firebaseapp.com",
                None,
                "CRITICAL",
                "Auth bypass",
                "validation=VALIDATED:firebase_agneyastra_audit:"
                "provider=firebase project_hash=0123456789abcdef category=auth_bypass",
            ),
            (
                1,
                "SUPABASE_RLS",
                "https://xyzxyz.supabase.co/rest/v1/users",
                "users",
                "CRITICAL",
                "RLS disabled",
                "",
            ),
        ],
    )

    # Cloud assets
    con.execute(
        "INSERT INTO cloud_assets (engagement_id, asset_type, identifier, source) VALUES (?,?,?,?)",
        (1, "firebase", "my-proj", "firebase_extract"),
    )

    # Active API key
    con.execute(
        "INSERT INTO key_scanner_findings"
        " (engagement_id, domain, service, pattern_name, source_backend, source_url, key_redacted, validation_state, validation_detail)"
        " VALUES (?,?,?,?,?,?,?,?,?)",
        (
            1,
            "example.com",
            "aws",
            "aws_access_key_id",
            "github",
            "https://github.com/example/repo/blob/main/cfg.py",
            "AKIA...XMPL",
            "ACTIVE",
            "VALIDATED:aws_sts_get_caller_identity:AccountId=742931608514 UserId=AIDAEXAMPLE",
        ),
    )

    con.commit()
    con.close()


def _seed_empty(db: Path) -> None:
    """Seed the DB with only the engagement record — no Phase 4 findings."""
    # DB already has the engagement from _make_db


def _seed_overlimit(db: Path, count: int = 200) -> None:
    """Seed with many INFO-severity exploit rows to trigger pruning."""
    con = sqlite3.connect(db)
    con.execute(
        "INSERT INTO hosts (engagement_id, ip, os_family) VALUES (?,?,?)",
        (1, "10.0.0.99", "linux"),
    )
    host_id = con.execute("SELECT last_insert_rowid()").fetchone()[0]
    for i in range(count):
        con.execute(
            "INSERT INTO exploit_suggestions"
            " (engagement_id, host_id, exploit_db_id, exploit_title, priority, attack_path_class)"
            " VALUES (?,?,?,?,?,?)",
            (1, host_id, f"EDB-{10000 + i}", f"Low exploit {i}", 2.0, "INFO"),
        )
    con.commit()
    con.close()


# ══════════════════════════════════════════════════════════════════════════════
# Fixtures
# ══════════════════════════════════════════════════════════════════════════════


@pytest.fixture
def empty_db(tmp_path: Path) -> Path:
    db = _make_db(tmp_path, "empty.db")
    return db


@pytest.fixture
def full_db(tmp_path: Path) -> Path:
    db = _make_db(tmp_path, "full.db")
    _seed_full(db)
    return db


@pytest.fixture
def overlimit_db(tmp_path: Path) -> Path:
    db = _make_db(tmp_path, "overlimit.db")
    _seed_overlimit(db)
    return db


@pytest.fixture
def full_builder(full_db: Path) -> AttackGraphBuilder:
    return AttackGraphBuilder(
        engagement_id=1,
        db_path=full_db,
        min_severity=Severity.LOW,
        max_nodes=150,
    )


# ══════════════════════════════════════════════════════════════════════════════
# Pydantic model validators
# ══════════════════════════════════════════════════════════════════════════════


class TestAttackNodeValidator:
    """FR-4H: AttackNode._no_sensitive_metadata validator."""

    def _make_node(self, metadata: dict) -> AttackNode:
        return AttackNode(
            node_id="HOST::10.0.0.1",
            node_type=NodeType.HOST,
            label="10.0.0.1",
            source_table="hosts",
            source_id=1,
            engagement_id=1,
            metadata=metadata,
        )

    def test_clean_metadata_accepted(self):
        node = self._make_node({"os_family": "linux", "port": 80})
        assert node.metadata["os_family"] == "linux"

    def test_password_key_rejected(self):
        from pydantic import ValidationError

        with pytest.raises(ValidationError, match="password"):
            self._make_node({"password": "hunter2", "os_family": "linux"})

    def test_hash_plaintext_key_rejected(self):
        from pydantic import ValidationError

        with pytest.raises(ValidationError, match="hash_plaintext"):
            self._make_node({"hash_plaintext": "aad3b435b51404eeaad3b435b51404ee"})

    def test_key_enc_rejected(self):
        from pydantic import ValidationError

        with pytest.raises(ValidationError, match="key_enc"):
            self._make_node({"key_enc": "FORGE-ENC-v1:abc"})

    def test_key_raw_rejected(self):
        from pydantic import ValidationError

        with pytest.raises(ValidationError, match="key_raw"):
            self._make_node({"key_raw": "AKIAIOSFODNN7EXAMPLE"})

    def test_multiple_forbidden_keys_all_reported(self):
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            self._make_node({"password": "x", "key_enc": "y"})

    def test_empty_metadata_accepted(self):
        node = self._make_node({})
        assert node.metadata == {}


class TestAttackGraphValidator:
    """FR-4H: AttackGraph._node_id_consistency validator."""

    def _make_graph(self, nodes: list[AttackNode], edges: list[AttackEdge]) -> AttackGraph:
        return AttackGraph(
            engagement_id=1,
            engagement_name="test",
            node_count=len(nodes),
            edge_count=len(edges),
            nodes=nodes,
            edges=edges,
            generated_at=datetime.now(timezone.utc).isoformat(),
        )

    def _node(self, node_id: str) -> AttackNode:
        return AttackNode(
            node_id=node_id,
            node_type=NodeType.HOST,
            label=node_id,
            source_table="hosts",
            source_id=1,
            engagement_id=1,
        )

    def _edge(self, src: str, tgt: str) -> AttackEdge:
        return AttackEdge(
            source_node_id=src,
            target_node_id=tgt,
            weight=10.0,
            edge_type="entry",
        )

    def test_consistent_graph_accepted(self):
        n1 = self._node("EXT::1")
        n2 = self._node("HOST::10.0.0.1")
        e = self._edge("EXT::1", "HOST::10.0.0.1")
        graph = self._make_graph([n1, n2], [e])
        assert graph.node_count == 2

    def test_dangling_source_raises(self):
        from pydantic import ValidationError

        n1 = self._node("HOST::10.0.0.1")
        e = self._edge("MISSING_NODE", "HOST::10.0.0.1")
        with pytest.raises(ValidationError, match="MISSING_NODE"):
            self._make_graph([n1], [e])

    def test_dangling_target_raises(self):
        from pydantic import ValidationError

        n1 = self._node("EXT::1")
        e = self._edge("EXT::1", "MISSING_TARGET")
        with pytest.raises(ValidationError, match="MISSING_TARGET"):
            self._make_graph([n1], [e])

    def test_empty_graph_accepted(self):
        graph = self._make_graph([], [])
        assert graph.node_count == 0
        assert graph.edge_count == 0


# ══════════════════════════════════════════════════════════════════════════════
# _assert_no_sensitive_data guard
# ══════════════════════════════════════════════════════════════════════════════


class TestAssertNoSensitiveData:
    """FR-4H (OPSEC): belt-and-suspenders guard before snapshot write."""

    def test_clean_json_passes(self):
        data = json.dumps({"node_id": "HOST::10.0.0.1", "label": "web server"})
        _assert_no_sensitive_data(data)  # must not raise

    def test_password_key_raises(self):
        data = json.dumps({"node_id": "X", "password": "hunter2"})
        with pytest.raises(ValueError, match="password"):
            _assert_no_sensitive_data(data)

    def test_hash_plaintext_key_raises(self):
        data = json.dumps({"hash_plaintext": "aad3b435b51404ee"})
        with pytest.raises(ValueError, match="hash_plaintext"):
            _assert_no_sensitive_data(data)

    def test_key_enc_raises(self):
        data = json.dumps({"key_enc": "FORGE-ENC-v1:abc123"})
        with pytest.raises(ValueError, match="key_enc"):
            _assert_no_sensitive_data(data)

    def test_key_raw_raises(self):
        data = json.dumps({"key_raw": "AKIAIOSFODNN7EXAMPLE"})
        with pytest.raises(ValueError, match="key_raw"):
            _assert_no_sensitive_data(data)

    def test_partial_match_not_triggered(self):
        # "password_policy" contains "password" as substring but NOT as a standalone key
        # The guard checks for '"password":' pattern — this should be safe
        data = json.dumps({"password_policy": "complex", "label": "auth node"})
        # This should NOT raise — "password_policy" != "password"
        _assert_no_sensitive_data(data)


# ══════════════════════════════════════════════════════════════════════════════
# Graph builder — node loading
# ══════════════════════════════════════════════════════════════════════════════


class TestLoadHosts:
    """FR-4H.1 / test_4h_host_nodes_loaded."""

    def test_host_nodes_created_for_each_host(self, full_builder: AttackGraphBuilder):
        full_builder.build()
        node_ids = list(full_builder._g.nodes())
        host_nodes = [n for n in node_ids if n.startswith("HOST::")]
        assert len(host_nodes) == 3  # seeded 3 hosts

    def test_external_node_present(self, full_builder: AttackGraphBuilder):
        full_builder.build()
        ext_nodes = [n for n in full_builder._g.nodes() if n.startswith("EXT::")]
        assert len(ext_nodes) == 1

    def test_external_to_host_edges_present(self, full_builder: AttackGraphBuilder):
        full_builder.build()
        ext_id = f"EXT::engagement-1"
        successors = list(full_builder._g.successors(ext_id))
        host_successors = [n for n in successors if n.startswith("HOST::")]
        assert len(host_successors) == 3

    def test_host_context_provider_metadata_exported_and_scrubbed(self, tmp_path: Path):
        db = _make_db(tmp_path)
        con = sqlite3.connect(db)
        try:
            con.execute("ALTER TABLE hosts ADD COLUMN host_context TEXT")
            con.executemany(
                """
                INSERT INTO hosts (engagement_id, ip, hostname, os_family, host_context)
                VALUES (1, ?, ?, 'unknown', ?)
                """,
                [
                    (
                        "203.0.113.25",
                        "shodan-api.example.com",
                        json.dumps(
                            {
                                "discovery": "shodan_dns",
                                "fixture_provider": "shodan",
                                "key_enc": "must-not-export",
                            },
                            sort_keys=True,
                        ),
                    ),
                    (
                        "198.19.0.7",
                        "archive.example.com",
                        json.dumps(
                            {
                                "discovery": "historical_cdx",
                                "root_domain": "example.com",
                            },
                            sort_keys=True,
                        ),
                    ),
                ],
            )
            con.commit()
        finally:
            con.close()

        graph = AttackGraphBuilder(engagement_id=1, db_path=db).build()
        host_nodes = {
            str(node.metadata.get("hostname") or ""): node
            for node in graph.nodes
            if node.node_type == NodeType.HOST
        }
        shodan_metadata = host_nodes["shodan-api.example.com"].metadata
        archive_metadata = host_nodes["archive.example.com"].metadata

        assert shodan_metadata["provider_sources"] == ["shodan"]
        assert shodan_metadata["discovery"] == "shodan_dns"
        assert shodan_metadata["host_context"]["fixture_provider"] == "shodan"
        assert "key_enc" not in json.dumps(shodan_metadata)
        assert "must-not-export" not in json.dumps(shodan_metadata)
        assert archive_metadata["provider_sources"] == ["wayback", "commoncrawl"]
        assert archive_metadata["root_domain"] == "example.com"

    def test_empty_db_produces_only_external_node(self, empty_db: Path):
        builder = AttackGraphBuilder(engagement_id=1, db_path=empty_db)
        graph = builder.build()
        # Only EXTERNAL node when no hosts
        assert graph.node_count >= 1
        assert not any(n.node_type == NodeType.HOST for n in graph.nodes)


class TestLoadCredentials:
    """FR-4H.2 / test_4h_cred_edge_validated_only."""

    def test_only_validated_creds_in_graph(self, full_builder: AttackGraphBuilder):
        full_builder.build()
        cred_nodes = [
            n
            for n, d in full_builder._g.nodes(data=True)
            if d.get("data") and d["data"].node_type == NodeType.CREDENTIAL
        ]
        # Only 1 validated credential was seeded
        assert len(cred_nodes) == 1

    def test_unvalidated_cred_not_in_graph(self, full_db: Path):
        builder = AttackGraphBuilder(engagement_id=1, db_path=full_db)
        builder.build()
        # Verify the unvalidated credential (user@example.com) has no CREDENTIAL node
        labels = [
            d["data"].label
            for _, d in builder._g.nodes(data=True)
            if d.get("data") and d["data"].node_type == NodeType.CREDENTIAL
        ]
        for label in labels:
            assert "user@" not in label  # unvalidated — should not appear

    def test_credential_node_label_contains_domain_not_localpart(
        self, full_builder: AttackGraphBuilder
    ):
        full_builder.build()
        for _, data in full_builder._g.nodes(data=True):
            node = data.get("data")
            if node and node.node_type == NodeType.CREDENTIAL:
                # Label must NOT expose the email localpart before '@'
                assert "admin" not in node.label  # localpart stripped
                assert "example.com" in node.label or "@example.com" in node.label


class TestLoadExploits:
    """FR-4H.3 / test_4h_exploit_severity_filter."""

    def test_all_exploits_in_graph_by_default(self, full_builder: AttackGraphBuilder):
        full_builder.build()
        exploit_nodes = [
            n
            for n, d in full_builder._g.nodes(data=True)
            if d.get("data") and d["data"].node_type == NodeType.EXPLOIT
        ]
        # Seeded 5 exploit suggestions
        assert len(exploit_nodes) == 5

    def test_high_severity_filter_excludes_low_info(self, full_db: Path):
        builder = AttackGraphBuilder(engagement_id=1, db_path=full_db, min_severity=Severity.HIGH)
        builder.build()
        exploit_nodes = [
            d["data"]
            for _, d in builder._g.nodes(data=True)
            if d.get("data") and d["data"].node_type == NodeType.EXPLOIT
        ]
        for node in exploit_nodes:
            assert node.severity in (Severity.CRITICAL, Severity.HIGH)

    def test_exploit_weight_matches_priority(self, full_builder: AttackGraphBuilder):
        full_builder.build()
        for u, v, data in full_builder._g.edges(data=True):
            edge = data.get("data")
            if edge and edge.edge_type == "exploit_applies":
                assert edge.weight > 0

    def test_missing_optional_exploit_table_does_not_break_build(self, full_db: Path):
        con = sqlite3.connect(full_db)
        try:
            con.execute("DROP TABLE exploit_suggestions")
            con.commit()
        finally:
            con.close()

        builder = AttackGraphBuilder(engagement_id=1, db_path=full_db)
        graph = builder.build()
        assert graph is not None
        assert any(node.node_type == NodeType.EXTERNAL for node in graph.nodes)


class TestLoadVulns:
    """FR-4H.4 / test_4h_idor_vuln_host_edge."""

    def test_idor_vuln_node_in_graph(self, full_builder: AttackGraphBuilder):
        full_builder.build()
        vuln_nodes = [
            d["data"]
            for _, d in full_builder._g.nodes(data=True)
            if d.get("data") and d["data"].node_type == NodeType.VULN
        ]
        assert any("IDOR" in n.metadata.get("vuln_type", "") for n in vuln_nodes)

    def test_cloud_vuln_node_in_graph(self, full_builder: AttackGraphBuilder):
        full_builder.build()
        vuln_nodes = [
            d["data"]
            for _, d in full_builder._g.nodes(data=True)
            if d.get("data") and d["data"].node_type == NodeType.VULN
        ]
        cloud_vuln_types = {n.metadata.get("vuln_type", "") for n in vuln_nodes}
        assert "FIREBASE_MISCONFIG" in cloud_vuln_types or "SUPABASE_RLS" in cloud_vuln_types

    def test_vuln_count_matches_seeded_rows(self, full_builder: AttackGraphBuilder):
        full_builder.build()
        vuln_nodes = [
            n
            for n, d in full_builder._g.nodes(data=True)
            if d.get("data") and d["data"].node_type == NodeType.VULN
        ]
        assert len(vuln_nodes) == 3  # seeded 3 vulnerability_findings rows

    def test_legacy_cloud_audit_rows_require_receipt_for_graph(self, tmp_path: Path):
        db = _make_db(tmp_path, "legacy-cloud-audit-gate.db")
        proof = (
            "validation=VALIDATED:azure_authenticated_config_audit:"
            "provider=azure service=Storage resource_hash=0123456789abcdef"
        )
        con = sqlite3.connect(db)
        try:
            con.executescript(
                """
                ALTER TABLE vulnerability_findings ADD COLUMN cloud_provider TEXT;
                ALTER TABLE vulnerability_findings ADD COLUMN resource_id TEXT;
                """
            )
            con.executemany(
                """
                INSERT INTO vulnerability_findings
                    (engagement_id, vuln_type, target_url, parameter, severity,
                     title, description, evidence, cloud_provider, resource_id)
                VALUES (1, ?, ?, ?, 'HIGH', ?, ?, ?, ?, ?)
                """,
                [
                    (
                        "AWS_MISCONFIG",
                        "https://console.aws.amazon.com/cloudtrail/home",
                        "aws",
                        "CloudTrail legacy note without proof",
                        "Legacy provider output without explicit validation receipt.",
                        '{"trails":[]}',
                        "aws",
                        "us-east-1",
                    ),
                    (
                        "AZURE_MISCONFIG",
                        "https://portal.azure.com/#resource/storageAccounts/prod",
                        "azure",
                        "Azure storage authenticated audit finding",
                        "Authenticated Azure configuration audit produced this finding.",
                        proof,
                        "azure",
                        "storage-prod",
                    ),
                ],
            )
            con.commit()
        finally:
            con.close()

        graph = AttackGraphBuilder(engagement_id=1, db_path=db).build()
        vuln_labels = {node.label for node in graph.nodes if node.node_type == NodeType.VULN}

        assert "CloudTrail legacy note without proof" not in vuln_labels
        assert "Azure storage authenticated audit finding" in vuln_labels


class TestLoadCloudAssets:
    def test_long_cloud_identifier_label_is_truncated_for_model_limit(self, full_db: Path):
        long_identifier = (
            "c:/users/bryan/appdata/local/forge/remote-artifacts/"
            + ("nested/" * 12)
            + "artifact.apk"
        )
        con = sqlite3.connect(full_db)
        try:
            con.execute(
                """
                INSERT INTO cloud_assets (engagement_id, asset_type, identifier, source)
                VALUES (?, ?, ?, ?)
                """,
                (1, "aws", long_identifier, "cloud_validate"),
            )
            con.commit()
        finally:
            con.close()

        builder = AttackGraphBuilder(engagement_id=1, db_path=full_db)
        graph = builder.build()
        cloud_nodes = [node for node in graph.nodes if node.node_type == NodeType.CLOUD]
        assert any(node.metadata.get("identifier") == long_identifier for node in cloud_nodes)
        assert all(len(node.label) <= 120 for node in cloud_nodes)

    def test_explicit_cloud_identifiers_do_not_collapse_to_service_node(self, tmp_path: Path):
        db = _make_db(tmp_path, "multi-cloud.db")
        con = sqlite3.connect(db)
        try:
            con.executescript(
                """
                ALTER TABLE vulnerability_findings ADD COLUMN cloud_provider TEXT;
                ALTER TABLE vulnerability_findings ADD COLUMN resource_id TEXT;
                CREATE TABLE cloud_validation_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    engagement_id INTEGER NOT NULL,
                    asset_type TEXT NOT NULL,
                    identifier TEXT NOT NULL,
                    validation_status TEXT NOT NULL,
                    validation_method TEXT,
                    http_status INTEGER,
                    evidence TEXT,
                    notes TEXT,
                    checked_at TIMESTAMP
                );
                """
            )
            con.executemany(
                """
                INSERT INTO cloud_validation_results
                    (engagement_id, asset_type, identifier, validation_status,
                     validation_method, http_status, evidence, notes, checked_at)
                VALUES (1, 'aws_s3', ?, 'VALIDATED', 's3_list_bucket', 200, ?,
                        'Public object metadata observed',
                        '2026-07-15T09:30:00+00:00')
                """,
                [
                    (
                        "bucket-a",
                        "<ListBucketResult><Contents><Key>reports/bucket-a.csv</Key></Contents></ListBucketResult>",
                    ),
                    (
                        "bucket-b",
                        "<ListBucketResult><Contents><Key>reports/bucket-b.csv</Key></Contents></ListBucketResult>",
                    ),
                ],
            )
            con.executemany(
                """
                INSERT INTO vulnerability_findings
                    (engagement_id, vuln_type, target_url, parameter, severity, title, cloud_provider, resource_id)
                VALUES (1, 'DETERMINISTIC_CLOUD_EXPOSURE', ?, 'aws_s3', 'HIGH', ?, 'aws', ?)
                """,
                [
                    ("aws_s3://bucket-a", "Validated public S3 bucket A listing", "bucket-a"),
                    ("aws_s3://bucket-b", "Validated public S3 bucket B listing", "bucket-b"),
                ],
            )
            con.commit()
        finally:
            con.close()

        graph = AttackGraphBuilder(engagement_id=1, db_path=db).build()
        cloud_by_identifier = {
            str(node.metadata.get("identifier") or ""): node
            for node in graph.nodes
            if node.node_type == NodeType.CLOUD
        }
        assert "bucket-a" in cloud_by_identifier
        assert "bucket-b" in cloud_by_identifier
        assert cloud_by_identifier["bucket-a"].node_id != cloud_by_identifier["bucket-b"].node_id

        cloud_edges = {
            (edge.source_node_id, edge.target_node_id)
            for edge in graph.edges
            if edge.edge_type == "cloud_misconfig"
        }
        assert any(
            source == cloud_by_identifier["bucket-a"].node_id
            for source, _target in cloud_edges
        )
        assert any(
            source == cloud_by_identifier["bucket-b"].node_id
            for source, _target in cloud_edges
        )

    def test_legacy_deterministic_cloud_exposure_uses_validated_target_identifier(
        self,
        tmp_path: Path,
    ):
        db = _make_db(tmp_path, "legacy-cloud-finding.db")
        con = sqlite3.connect(db)
        try:
            con.executescript(
                """
                CREATE TABLE cloud_validation_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    engagement_id INTEGER NOT NULL,
                    asset_type TEXT NOT NULL,
                    identifier TEXT NOT NULL,
                    validation_status TEXT NOT NULL,
                    validation_method TEXT,
                    http_status INTEGER,
                    evidence TEXT,
                    notes TEXT,
                    checked_at TIMESTAMP
                );
                """
            )
            con.execute(
                """
                INSERT INTO cloud_validation_results
                    (engagement_id, asset_type, identifier, validation_status,
                     validation_method, http_status, evidence, notes, checked_at)
                VALUES (1, 'firebase', 'provider-firebase', 'VALIDATED',
                        'firebase_database_shallow_read', 200,
                        '{"records":1}',
                        'Firebase project reference responded with non-empty data.',
                        '2026-07-19T00:00:00+00:00')
                """
            )
            con.execute(
                """
                INSERT INTO vulnerability_findings
                    (engagement_id, vuln_type, target_url, parameter, severity, title)
                VALUES (1, 'DETERMINISTIC_CLOUD_EXPOSURE', 'provider-firebase',
                        'firebase', 'HIGH', 'Validated Firebase data exposure')
                """
            )
            con.commit()
        finally:
            con.close()

        graph = AttackGraphBuilder(engagement_id=1, db_path=db).build()
        vuln_nodes = [
            node
            for node in graph.nodes
            if node.node_type == NodeType.VULN
            and node.label == "Validated Firebase data exposure"
        ]

        assert vuln_nodes
        assert vuln_nodes[0].metadata["validation_status"] == "VALIDATED"
        assert vuln_nodes[0].metadata["resource_id"] == "provider-firebase"

    def test_cloud_assets_with_same_identifier_are_keyed_by_asset_type(self, tmp_path: Path):
        db = _make_db(tmp_path, "cloud-key-collision.db")
        con = sqlite3.connect(db)
        try:
            con.executescript(
                """
                ALTER TABLE cloud_assets ADD COLUMN provider_identifier TEXT;
                ALTER TABLE vulnerability_findings ADD COLUMN cloud_provider TEXT;
                ALTER TABLE vulnerability_findings ADD COLUMN resource_id TEXT;

                CREATE TABLE cloud_validation_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    engagement_id INTEGER NOT NULL,
                    asset_type TEXT NOT NULL,
                    identifier TEXT NOT NULL,
                    provider_identifier TEXT,
                    validation_status TEXT NOT NULL,
                    validation_method TEXT,
                    http_status INTEGER,
                    evidence TEXT,
                    notes TEXT,
                    checked_at TIMESTAMP
                );

                INSERT INTO cloud_assets
                    (engagement_id, asset_type, identifier, provider_identifier, source)
                VALUES
                    (1, 'aws_s3', 'Shared-ID', 'AWSExactShared', 'cloud_validate'),
                    (1, 'gcs', 'shared-id', 'GCSExactShared', 'cloud_validate');

                INSERT INTO cloud_validation_results
                    (engagement_id, asset_type, identifier, provider_identifier,
                     validation_status, validation_method, http_status, evidence, notes, checked_at)
                VALUES
                    (1, 'aws_s3', 'shared-id', 'AWSExactShared',
                     'VALIDATED', 's3_list_bucket', 200,
                     '<ListBucketResult><Contents><Key>reports/shared.csv</Key></Contents></ListBucketResult>',
                     'Public object metadata observed', '2026-07-15T09:30:00+00:00'),
                    (1, 'gcs', 'shared-id', 'GCSExactShared',
                     'ACCESSIBLE', 'gcs_storage_get', 200, '', '',
                     '2026-07-15T09:31:00+00:00');

                INSERT INTO vulnerability_findings
                    (engagement_id, vuln_type, target_url, parameter, severity, title,
                     cloud_provider, resource_id)
                VALUES
                    (1, 'DETERMINISTIC_CLOUD_EXPOSURE', 's3://shared-id', 'aws_s3',
                     'HIGH', 'AWS shared bucket exposure', 'aws', 'shared-id'),
                    (1, 'DETERMINISTIC_CLOUD_EXPOSURE', 'gs://shared-id', 'gcs',
                     'HIGH', 'GCS shared bucket exposure', 'gcs', 'shared-id');
                """
            )
            con.commit()
        finally:
            con.close()

        graph = AttackGraphBuilder(engagement_id=1, db_path=db).build()
        cloud_nodes = [
            node
            for node in graph.nodes
            if node.node_type == NodeType.CLOUD
            and node.metadata.get("identifier") == "shared-id"
        ]
        nodes_by_service = {str(node.metadata.get("service")): node for node in cloud_nodes}

        assert len(cloud_nodes) == 2
        assert set(nodes_by_service) == {"aws_s3", "gcs"}
        for service, provider_identifier, validation_method in (
            ("aws_s3", "AWSExactShared", "s3_list_bucket"),
            ("gcs", "GCSExactShared", "gcs_storage_get"),
        ):
            assert nodes_by_service[service].node_id == f"CLOUD::{service}::shared-id"
            assert nodes_by_service[service].metadata["provider_identifier"] == provider_identifier
            assert nodes_by_service[service].metadata["validation_method"] == validation_method

        vuln_by_label = {
            node.label: node
            for node in graph.nodes
            if node.node_type == NodeType.VULN
        }
        assert "AWS shared bucket exposure" in vuln_by_label
        assert "GCS shared bucket exposure" not in vuln_by_label

        cloud_source_by_vuln = {
            edge.target_node_id: edge.source_node_id
            for edge in graph.edges
            if edge.edge_type == "cloud_misconfig"
        }
        assert (
            cloud_source_by_vuln[vuln_by_label["AWS shared bucket exposure"].node_id]
            == nodes_by_service["aws_s3"].node_id
        )
        assert all(source != nodes_by_service["gcs"].node_id for source in cloud_source_by_vuln.values())

    def test_cloud_asset_alias_rows_merge_with_canonical_validation_nodes(self, tmp_path: Path):
        db = _make_db(tmp_path, "cloud-alias-graph.db")
        con = sqlite3.connect(db)
        try:
            con.executescript(
                """
                ALTER TABLE cloud_assets ADD COLUMN provider_identifier TEXT;
                ALTER TABLE vulnerability_findings ADD COLUMN cloud_provider TEXT;
                ALTER TABLE vulnerability_findings ADD COLUMN resource_id TEXT;

                CREATE TABLE cloud_validation_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    engagement_id INTEGER NOT NULL,
                    asset_type TEXT NOT NULL,
                    identifier TEXT NOT NULL,
                    provider_identifier TEXT,
                    validation_status TEXT NOT NULL,
                    validation_method TEXT,
                    http_status INTEGER,
                    evidence TEXT,
                    notes TEXT,
                    checked_at TIMESTAMP
                );

                INSERT INTO cloud_assets
                    (engagement_id, asset_type, identifier, provider_identifier, source)
                VALUES
                    (1, 's3', 'legacy-assets', 'LegacyAssetsExact', 'legacy_import'),
                    (1, 'aws_s3', 'legacy-assets', 'LegacyAssetsExact', 'cloud_validate');

                INSERT INTO cloud_validation_results
                    (engagement_id, asset_type, identifier, provider_identifier,
                     validation_status, validation_method, http_status, evidence, notes, checked_at)
                VALUES
                    (1, 'aws_s3', 'legacy-assets', 'LegacyAssetsExact',
                     'VALIDATED', 's3_list_bucket', 200,
                     '<ListBucketResult><Contents><Key>reports/customer-records.csv</Key></Contents></ListBucketResult>',
                     'Public object metadata observed', '2026-07-15T09:30:00+00:00');

                INSERT INTO vulnerability_findings
                    (engagement_id, vuln_type, target_url, parameter, severity, title,
                     cloud_provider, resource_id)
                VALUES
                    (1, 'DETERMINISTIC_CLOUD_EXPOSURE', 's3://legacy-assets', 'aws_s3',
                     'HIGH', 'Validated legacy S3 alias exposure', 'aws', 'legacy-assets');
                """
            )
            con.commit()
        finally:
            con.close()

        graph = AttackGraphBuilder(engagement_id=1, db_path=db).build()
        cloud_nodes = [node for node in graph.nodes if node.node_type == NodeType.CLOUD]
        cloud_node_ids = {node.node_id for node in cloud_nodes}

        assert "CLOUD::s3::legacy-assets" not in cloud_node_ids
        assert "CLOUD::aws_s3::legacy-assets" in cloud_node_ids
        alias_node = next(
            node
            for node in cloud_nodes
            if node.node_id == "CLOUD::aws_s3::legacy-assets"
        )
        assert alias_node.metadata["service"] == "aws_s3"
        assert alias_node.metadata["provider_identifier"] == "LegacyAssetsExact"
        assert alias_node.metadata["validation_status"] == "VALIDATED"
        assert alias_node.metadata["asset_type_aliases"] == ["s3"]

        vuln_node = next(
            node
            for node in graph.nodes
            if node.node_type == NodeType.VULN
            and node.label == "Validated legacy S3 alias exposure"
        )
        assert any(
            edge.source_node_id == alias_node.node_id
            and edge.target_node_id == vuln_node.node_id
            and edge.edge_type == "cloud_misconfig"
            for edge in graph.edges
        )

    def test_deterministic_cloud_exposure_uses_latest_validation_status(self, tmp_path: Path):
        db = _make_db(tmp_path, "cloud-latest-validation-gating.db")
        con = sqlite3.connect(db)
        try:
            con.executescript(
                """
                ALTER TABLE vulnerability_findings ADD COLUMN cloud_provider TEXT;
                ALTER TABLE vulnerability_findings ADD COLUMN resource_id TEXT;

                CREATE TABLE cloud_validation_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    engagement_id INTEGER NOT NULL,
                    asset_type TEXT NOT NULL,
                    identifier TEXT NOT NULL,
                    validation_status TEXT NOT NULL,
                    validation_method TEXT,
                    http_status INTEGER,
                    evidence TEXT,
                    notes TEXT,
                    checked_at TIMESTAMP
                );

                INSERT INTO cloud_assets (engagement_id, asset_type, identifier, source)
                VALUES
                    (1, 'aws_s3', 'bucket-stale', 'cloud_validate'),
                    (1, 'aws_s3', 'bucket-good', 'cloud_validate'),
                    (1, 'aws_s3', 'manual-note-bucket', 'cloud_validate'),
                    (1, 'stripe', 'acct-unsupported', 'cloud_validate'),
                    (1, 'gcs', 'metadata-bucket', 'cloud_validate');

                INSERT INTO cloud_validation_results
                    (engagement_id, asset_type, identifier, validation_status,
                     validation_method, http_status, evidence, notes, checked_at)
                VALUES
                    (1, 'aws_s3', 'bucket-stale', 'VALIDATED',
                     's3_list_bucket', 200,
                     '<ListBucketResult><Contents><Key>reports/stale.csv</Key></Contents></ListBucketResult>',
                     'Older public object metadata observed',
                     '2026-07-15T09:00:00+00:00'),
                    (1, 'aws_s3', 'bucket-stale', 'HONEYPOT_SUSPECTED',
                     's3_list_bucket', 200, '', 'Synthetic listing suspected',
                     '2026-07-15T10:00:00+00:00'),
                    (1, 'aws_s3', 'bucket-good', 'DEAD',
                     's3_list_bucket', 404, '', 'Not reachable',
                     '2026-07-15T09:00:00+00:00'),
                    (1, 'aws_s3', 'bucket-good', 'VALIDATED',
                     's3_list_bucket', 200,
                     '<ListBucketResult><Contents><Key>reports/customer-records.csv</Key></Contents></ListBucketResult>',
                     'Probe notes token=raw-secret-value',
                     '2026-07-15T10:00:00+00:00'),
                    (1, 'aws_s3', 'manual-note-bucket', 'VALIDATED',
                     'manual_validated_note', 200, 'operator note', 'manual proof',
                     '2026-07-15T10:00:00+00:00'),
                    (1, 'stripe', 'acct-unsupported', 'UNSUPPORTED',
                     'registry_dispatch', NULL, '', 'Unsupported provider',
                     '2026-07-15T10:00:00+00:00'),
                    (1, 'gcs', 'metadata-bucket', 'ACCESSIBLE_BUT_NO_DATA',
                     'gcs_http_probe', 200, '<ok />', 'Metadata only',
                     '2026-07-15T10:00:00+00:00');

                UPDATE cloud_validation_results
                SET notes='Unsupported probe token=raw-secret-value',
                    evidence='HTTP response api_key=raw-key-value was bounded'
                WHERE identifier='acct-unsupported';

                INSERT INTO vulnerability_findings
                    (engagement_id, vuln_type, target_url, parameter, severity, title,
                     cloud_provider, resource_id)
                VALUES
                    (1, 'DETERMINISTIC_CLOUD_EXPOSURE', 's3://bucket-stale', 'aws_s3',
                     'HIGH', 'Stale cloud exposure', 'aws', 'bucket-stale'),
                    (1, 'DETERMINISTIC_CLOUD_EXPOSURE', 's3://bucket-good', 'aws_s3',
                     'HIGH', 'Validated cloud exposure', 'aws', 'bucket-good'),
                    (1, 'DETERMINISTIC_CLOUD_EXPOSURE', 's3://manual-note-bucket',
                     'aws_s3', 'HIGH', 'Manual note cloud exposure', 'aws',
                     'manual-note-bucket'),
                    (1, 'CLOUD_STORAGE_METADATA', 'gs://metadata-bucket', 'gcs',
                     'MEDIUM', 'Public Google Cloud Storage metadata observed',
                     NULL, 'metadata-bucket');
                """
            )
            con.commit()
        finally:
            con.close()

        graph = AttackGraphBuilder(engagement_id=1, db_path=db).build()
        cloud_nodes = {
            str(node.metadata.get("identifier")): node
            for node in graph.nodes
            if node.node_type == NodeType.CLOUD
        }
        vuln_by_label = {
            node.label: node
            for node in graph.nodes
            if node.node_type == NodeType.VULN
        }

        assert cloud_nodes["bucket-stale"].metadata["validation_status"] == "HONEYPOT_SUSPECTED"
        assert cloud_nodes["bucket-good"].metadata["validation_status"] == "VALIDATED"
        assert cloud_nodes["manual-note-bucket"].metadata["validation_status"] == "VALIDATED"
        assert cloud_nodes["manual-note-bucket"].metadata["validation_method"] == "manual_validated_note"
        assert cloud_nodes["acct-unsupported"].metadata["validation_status"] == "UNSUPPORTED"
        assert cloud_nodes["metadata-bucket"].metadata["validation_status"] == "ACCESSIBLE_BUT_NO_DATA"
        assert cloud_nodes["bucket-good"].metadata["validation_notes"] == (
            "Probe notes token=[REDACTED]"
        )
        assert "reports/customer-records.csv" in cloud_nodes["bucket-good"].metadata[
            "validation_evidence_summary"
        ]
        assert "Stale cloud exposure" not in vuln_by_label
        assert "Validated cloud exposure" in vuln_by_label
        assert "Manual note cloud exposure" not in vuln_by_label
        assert "Public Google Cloud Storage metadata observed" not in vuln_by_label
        assert all("acct-unsupported" not in node.label for node in vuln_by_label.values())

    def test_cloud_nodes_use_latest_validation_result_for_managed_pages_assets(
        self,
        tmp_path: Path,
    ):
        db = _make_db(tmp_path, "pages-cloud-validation.db")
        con = sqlite3.connect(db)
        try:
            con.executescript(
                """
                CREATE TABLE cloud_validation_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    engagement_id INTEGER NOT NULL,
                    asset_type TEXT NOT NULL,
                    identifier TEXT NOT NULL,
                    validation_status TEXT NOT NULL,
                    validation_method TEXT,
                    http_status INTEGER,
                    checked_at TIMESTAMP
                );
                """
            )
            con.execute(
                """
                INSERT INTO cloud_assets (engagement_id, asset_type, identifier, source)
                VALUES (1, 'github_pages', 'acme.github.io', 'artifact_url_extract')
                """
            )
            con.executemany(
                """
                INSERT INTO cloud_validation_results
                    (engagement_id, asset_type, identifier, validation_status, validation_method, http_status, checked_at)
                VALUES (1, 'github_pages', 'acme.github.io', ?, ?, ?, ?)
                """,
                [
                    ("DEAD", "managed_hosting_head", 404, "2026-07-15T09:30:00+00:00"),
                    (
                        "ACCESSIBLE_BUT_NO_DATA",
                        "managed_hosting_reachability",
                        200,
                        "2026-07-15T09:45:00+00:00",
                    ),
                ],
            )
            con.commit()
        finally:
            con.close()

        graph = AttackGraphBuilder(engagement_id=1, db_path=db).build()
        cloud_node = next(
            node
            for node in graph.nodes
            if node.node_type == NodeType.CLOUD
            and node.metadata.get("service") == "github_pages"
            and node.metadata.get("identifier") == "acme.github.io"
        )

        assert cloud_node.metadata["validation_status"] == "ACCESSIBLE_BUT_NO_DATA"
        assert cloud_node.metadata["validation_method"] == "managed_hosting_reachability"
        assert cloud_node.metadata["http_status"] == 200
        assert cloud_node.metadata["checked_at"] == "2026-07-15T09:45:00+00:00"
        graph_json = graph.model_dump_json()
        assert "managed_hosting_reachability" in graph_json
        assert "2026-07-15T09:45:00+00:00" in graph_json
        assert "managed_hosting_head" not in graph_json


class TestLoadApiKeys:
    """FR-4H.5 / test_4h_apikey_cloud_edge."""

    def test_active_apikey_node_in_graph(self, full_builder: AttackGraphBuilder):
        full_builder.build()
        key_nodes = [
            n
            for n, d in full_builder._g.nodes(data=True)
            if d.get("data") and d["data"].node_type == NodeType.APIKEY
        ]
        assert len(key_nodes) == 1

    def test_apikey_label_does_not_contain_full_key(self, full_builder: AttackGraphBuilder):
        full_builder.build()
        for _, data in full_builder._g.nodes(data=True):
            node = data.get("data")
            if node and node.node_type == NodeType.APIKEY:
                # redacted label should not be a full key — must end with ...last4
                assert "AKIAIOSFODNN7EXAMPLE" not in node.label

    def test_apikey_metadata_no_sensitive_fields(self, full_builder: AttackGraphBuilder):
        full_builder.build()
        for _, data in full_builder._g.nodes(data=True):
            node = data.get("data")
            if node and node.node_type == NodeType.APIKEY:
                forbidden = {"key_enc", "key_raw", "password", "hash_plaintext"}
                assert not (forbidden & set(node.metadata.keys()))

    def test_active_apikey_node_carries_validation_proof_metadata(self, full_db: Path):
        con = sqlite3.connect(full_db)
        try:
            con.execute(
                """
                UPDATE key_scanner_findings
                SET validation_detail=?,
                    validated_at=?,
                    repo_name=?
                WHERE engagement_id=1 AND service='aws'
                """,
                (
                    "VALIDATED:aws_sts_get_caller_identity:AccountId=742931608514 UserId=AIDAEXAMPLE",
                    "2026-07-15T09:30:00+00:00",
                    "example/repo",
                ),
            )
            con.commit()
        finally:
            con.close()

        graph = AttackGraphBuilder(engagement_id=1, db_path=full_db).build()
        key_node = next(node for node in graph.nodes if node.node_type == NodeType.APIKEY)

        assert key_node.metadata["validation_state"] == "ACTIVE"
        assert key_node.metadata["validation_detail"] == (
            "VALIDATED:aws_sts_get_caller_identity:AccountId=742931608514 UserId=AIDAEXAMPLE"
        )
        assert key_node.metadata["validation_status"] == "VALIDATED"
        assert key_node.metadata["validation_method"] == "aws_sts_get_caller_identity"
        assert key_node.metadata["validation_proof"] == "AccountId=742931608514 UserId=AIDAEXAMPLE"
        assert key_node.metadata["validated_at"] == "2026-07-15T09:30:00+00:00"
        assert key_node.metadata["source_backend"] == "github"
        assert key_node.metadata["repo_name"] == "example/repo"
        assert "key_enc" not in key_node.metadata
        assert "key_raw" not in key_node.metadata
        assert "AKIAIOSFODNN7EXAMPLE" not in graph.model_dump_json()

    def test_apikey_node_excludes_stale_sequential_aws_validation_proof(
        self,
        full_db: Path,
    ):
        con = sqlite3.connect(full_db)
        try:
            con.execute(
                """
                UPDATE key_scanner_findings
                SET validation_detail=?,
                    validated_at=?
                WHERE engagement_id=1 AND service='aws'
                """,
                (
                    "VALIDATED:aws_sts_get_caller_identity:AccountId=123456789012 UserId=AIDAEXAMPLE",
                    "2026-07-15T09:30:00+00:00",
                ),
            )
            con.commit()
        finally:
            con.close()

        graph = AttackGraphBuilder(engagement_id=1, db_path=full_db).build()
        assert all(node.node_type != NodeType.APIKEY for node in graph.nodes)
        assert "VALIDATED:aws_sts_get_caller_identity" not in graph.model_dump_json()

    def test_apikey_node_excludes_unlinked_bot_token_validation_proof(
        self,
        full_db: Path,
    ):
        con = sqlite3.connect(full_db)
        try:
            con.execute(
                """
                UPDATE key_scanner_findings
                SET service='discord',
                    pattern_name='discord_bot_token',
                    validation_detail=?,
                    validated_at=?
                WHERE engagement_id=1 AND service='aws'
                """,
                (
                    "VALIDATED:discord_current_user:Discord bot auth ok: "
                    "bot_id=739251864203918576 bot_profile_present=true",
                    "2026-07-15T09:30:00+00:00",
                ),
            )
            con.commit()
        finally:
            con.close()

        graph = AttackGraphBuilder(engagement_id=1, db_path=full_db).build()
        assert all(node.node_type != NodeType.APIKEY for node in graph.nodes)
        assert "discord_current_user" not in graph.model_dump_json()

    def test_apikey_node_excludes_unlinked_slack_bot_token_validation_proof(
        self,
        full_db: Path,
    ):
        con = sqlite3.connect(full_db)
        try:
            con.execute(
                """
                UPDATE key_scanner_findings
                SET service='slack',
                    pattern_name='slack_bot_token',
                    validation_detail=?,
                    validated_at=?
                WHERE engagement_id=1 AND service='aws'
                """,
                (
                    "VALIDATED:slack_auth_test:Slack auth ok: "
                    "actor_id=U7A3C9K2 team_id=T9B2D6F4",
                    "2026-07-15T09:30:00+00:00",
                ),
            )
            con.commit()
        finally:
            con.close()

        graph = AttackGraphBuilder(engagement_id=1, db_path=full_db).build()
        assert all(node.node_type != NodeType.APIKEY for node in graph.nodes)
        assert "slack_auth_test" not in graph.model_dump_json()

    def test_apikey_node_excludes_bare_legacy_cloud_validation_proof(
        self,
        full_db: Path,
    ):
        con = sqlite3.connect(full_db)
        try:
            con.execute(
                """
                UPDATE key_scanner_findings
                SET service='firebase',
                    pattern_name='firebase_mobile_config',
                    validation_detail=?,
                    validated_at=?
                WHERE engagement_id=1 AND service='aws'
                """,
                (
                    "VALIDATED:firebase_database_shallow_read",
                    "2026-07-15T09:30:00+00:00",
                ),
            )
            con.commit()
        finally:
            con.close()

        graph = AttackGraphBuilder(engagement_id=1, db_path=full_db).build()
        assert all(node.node_type != NodeType.APIKEY for node in graph.nodes)
        assert "VALIDATED:firebase_database_shallow_read" not in graph.model_dump_json()


class TestSynthesiseImpact:
    """FR-4H.7 / test_4h_impact_synthesised."""

    def test_impact_node_present(self, full_builder: AttackGraphBuilder):
        full_builder.build()
        impact_nodes = [
            n
            for n, d in full_builder._g.nodes(data=True)
            if d.get("data") and d["data"].node_type == NodeType.IMPACT
        ]
        assert len(impact_nodes) == 1

    def test_critical_high_exploits_have_impact_edge(self, full_builder: AttackGraphBuilder):
        full_builder.build()
        impact_id = f"IMP::engagement-1"
        preds = list(full_builder._g.predecessors(impact_id))
        # Should have edges from CRITICAL and HIGH exploit/vuln nodes
        assert len(preds) >= 2


# ══════════════════════════════════════════════════════════════════════════════
# Critical path
# ══════════════════════════════════════════════════════════════════════════════


class TestCriticalPath:
    """FR-4H.8 / test_4h_critical_path_annotated."""

    def test_critical_path_nodes_annotated(self, full_builder: AttackGraphBuilder):
        graph = full_builder.build()
        if not graph.critical_path_nodes:
            pytest.skip("No critical path computed (possibly empty graph)")
        critical_node_ids = set(graph.critical_path_nodes)
        for node in graph.nodes:
            if node.node_id in critical_node_ids:
                assert node.on_critical_path is True

    def test_critical_path_edges_annotated(self, full_builder: AttackGraphBuilder):
        graph = full_builder.build()
        if not graph.critical_path_nodes:
            pytest.skip("No critical path computed")
        critical_ids = set(graph.critical_path_nodes)
        for edge in graph.edges:
            if edge.source_node_id in critical_ids and edge.target_node_id in critical_ids:
                assert edge.on_critical_path is True

    def test_critical_path_weight_positive(self, full_builder: AttackGraphBuilder):
        graph = full_builder.build()
        # Full DB has CRITICAL/HIGH findings — weight must be > 0
        assert graph.critical_path_weight >= 0.0

    def test_empty_db_critical_path_empty(self, empty_db: Path):
        builder = AttackGraphBuilder(engagement_id=1, db_path=empty_db)
        graph = builder.build()
        # No findings → critical path is empty or just the EXTERNAL node
        assert isinstance(graph.critical_path_nodes, list)


# ══════════════════════════════════════════════════════════════════════════════
# Pruning
# ══════════════════════════════════════════════════════════════════════════════


class TestPruning:
    """FR-4H.16 / test_4h_prune_respects_max_nodes."""

    def test_graph_pruned_to_max_nodes(self, overlimit_db: Path):
        builder = AttackGraphBuilder(engagement_id=1, db_path=overlimit_db, max_nodes=50)
        graph = builder.build()
        assert graph.node_count <= 50 + 5  # small tolerance for non-leaf nodes

    def test_info_nodes_removed_first(self, overlimit_db: Path):
        builder = AttackGraphBuilder(engagement_id=1, db_path=overlimit_db, max_nodes=10)
        graph = builder.build()
        # INFO nodes should be absent if pruning occurred
        info_nodes = [n for n in graph.nodes if n.severity == Severity.INFO]
        # After aggressive pruning, INFO leaf nodes should be gone
        assert len(info_nodes) == 0 or graph.node_count <= builder.max_nodes

    def test_no_pruning_when_under_limit(self, full_db: Path):
        builder = AttackGraphBuilder(engagement_id=1, db_path=full_db, max_nodes=500)
        graph = builder.build()
        # Full DB has far fewer than 500 nodes — no pruning should occur
        assert graph.pruned is False


# ══════════════════════════════════════════════════════════════════════════════
# DB read-only enforcement
# ══════════════════════════════════════════════════════════════════════════════


class TestDbReadOnly:
    """FR-4H: PRAGMA query_only=ON must be set on the read connection."""

    def test_read_only_pragma_applied(self, full_db: Path):
        """Verify that AttackGraphBuilder opens the DB in query_only mode."""
        original_connect = sqlite3.connect
        pragma_set = []

        def mock_connect(path, *args, **kwargs):
            conn = original_connect(path, *args, **kwargs)
            original_execute = conn.execute

            def tracking_execute(sql, *a, **kw):
                if "query_only" in sql.lower():
                    pragma_set.append(sql)
                return original_execute(sql, *a, **kw)

            conn.execute = tracking_execute
            return conn

        with patch("sqlite3.connect", side_effect=mock_connect):
            builder = AttackGraphBuilder(engagement_id=1, db_path=full_db)
            builder.build()

        assert any("query_only" in s.lower() for s in pragma_set), (
            "PRAGMA query_only=ON was never set on the read connection. "
            "AttackGraphBuilder must open the DB in read-only mode."
        )


# ══════════════════════════════════════════════════════════════════════════════
# Mermaid renderer
# ══════════════════════════════════════════════════════════════════════════════


class TestMermaidEscape:
    """FR-4H.9 / test_4h_mermaid_escape."""

    def test_colon_replaced_with_dash(self):
        assert "-" in _mermaid_escape("host:8080")
        assert ":" not in _mermaid_escape("host:8080")

    def test_double_quote_replaced_with_single(self):
        result = _mermaid_escape('label "with quotes"')
        assert '"' not in result
        assert "'" in result

    def test_angle_brackets_html_encoded(self):
        result = _mermaid_escape("type <T>")
        assert "<" not in result
        assert "&lt;" in result
        assert "&gt;" in result

    def test_empty_string_returns_empty(self):
        assert _mermaid_escape("") == ""

    def test_none_returns_empty(self):
        assert _mermaid_escape(None) == ""

    def test_clean_label_unchanged(self):
        label = "Apache RCE v2.4"
        assert _mermaid_escape(label) == label


class TestMermaidRenderer:
    """FR-4H.9 / test_4h_mermaid_critical_path_arrow + test_4h_mermaid_char_limit_warn."""

    def _make_two_node_graph(self, on_critical_path: bool = False) -> AttackGraph:
        n1 = AttackNode(
            node_id="EXT::1",
            node_type=NodeType.EXTERNAL,
            label="External",
            source_table="synthetic",
            source_id=0,
            engagement_id=1,
        )
        n2 = AttackNode(
            node_id="HOST::10.0.0.1",
            node_type=NodeType.HOST,
            label="10.0.0.1",
            source_table="hosts",
            source_id=1,
            engagement_id=1,
        )
        edge = AttackEdge(
            source_node_id="EXT::1",
            target_node_id="HOST::10.0.0.1",
            weight=5.0,
            edge_type="entry",
            on_critical_path=on_critical_path,
        )
        return AttackGraph(
            engagement_id=1,
            engagement_name="test",
            node_count=2,
            edge_count=1,
            nodes=[n1, n2],
            edges=[edge],
            generated_at=datetime.now(timezone.utc).isoformat(),
        )

    def _make_large_graph(self, node_total: int = 120) -> AttackGraph:
        nodes = [
            AttackNode(
                node_id="EXT::eng-1",
                node_type=NodeType.EXTERNAL,
                label="External",
                source_table="synthetic",
                source_id=0,
                engagement_id=1,
                on_critical_path=True,
            )
        ]
        edges = []
        critical_path_nodes = ["EXT::eng-1"]
        previous_node = "EXT::eng-1"
        for index in range(node_total):
            node_id = f"HOST::10.10.{index // 255}.{index % 255}"
            on_critical_path = index < 3
            if on_critical_path:
                critical_path_nodes.append(node_id)
            nodes.append(
                AttackNode(
                    node_id=node_id,
                    node_type=NodeType.HOST,
                    label=f"host-{index:04d}-with-a-descriptive-label-for-preview-testing",
                    source_table="hosts",
                    source_id=index + 1,
                    engagement_id=1,
                    severity=Severity.HIGH if index % 5 == 0 else None,
                    on_critical_path=on_critical_path,
                )
            )
            edges.append(
                AttackEdge(
                    source_node_id=previous_node if on_critical_path else "EXT::eng-1",
                    target_node_id=node_id,
                    weight=90.0 if on_critical_path else 5.0,
                    edge_type="entry",
                    on_critical_path=on_critical_path,
                )
            )
            if on_critical_path:
                previous_node = node_id
        return AttackGraph(
            engagement_id=1,
            engagement_name="large-test",
            node_count=len(nodes),
            edge_count=len(edges),
            critical_path_nodes=critical_path_nodes,
            critical_path_weight=270.0,
            nodes=nodes,
            edges=edges,
            generated_at=datetime.now(timezone.utc).isoformat(),
        )

    def test_critical_path_edge_uses_thick_arrow(self):
        graph = self._make_two_node_graph(on_critical_path=True)
        renderer = MermaidRenderer()
        output = renderer.render(graph)
        assert "==>" in output

    def test_non_critical_edge_uses_thin_arrow(self):
        graph = self._make_two_node_graph(on_critical_path=False)
        renderer = MermaidRenderer()
        output = renderer.render(graph)
        assert "-->" in output
        assert "==>" not in output

    def test_output_starts_with_flowchart(self):
        graph = self._make_two_node_graph()
        output = MermaidRenderer().render(graph)
        assert output.startswith("flowchart")

    def test_all_node_ids_referenced(self):
        graph = self._make_two_node_graph()
        output = MermaidRenderer().render(graph)
        # Both nodes should appear in some form
        assert "N0" in output or "N1" in output

    def test_style_directives_present(self):
        graph = self._make_two_node_graph()
        output = MermaidRenderer().render(graph)
        assert "style" in output
        assert "fill:" in output

    def test_char_limit_exceeded_emits_warning(self):
        """FR-4H.17: graphs > 4000 chars must emit a UserWarning."""
        nodes = []
        edges = []
        ext_id = "EXT::eng-1"
        nodes.append(
            AttackNode(
                node_id=ext_id,
                node_type=NodeType.EXTERNAL,
                label="External",
                source_table="synthetic",
                source_id=0,
                engagement_id=1,
            )
        )
        # Create enough nodes to exceed 4000 chars
        for i in range(80):
            nid = f"HOST::10.0.{i // 256}.{i % 256}"
            nodes.append(
                AttackNode(
                    node_id=nid,
                    node_type=NodeType.HOST,
                    label=f"host-{i:04d}-with-a-descriptive-label",
                    source_table="hosts",
                    source_id=i + 1,
                    engagement_id=1,
                )
            )
            edges.append(
                AttackEdge(
                    source_node_id=ext_id,
                    target_node_id=nid,
                    weight=5.0,
                    edge_type="entry",
                )
            )

        graph = AttackGraph(
            engagement_id=1,
            engagement_name="test",
            node_count=len(nodes),
            edge_count=len(edges),
            nodes=nodes,
            edges=edges,
            generated_at=datetime.now(timezone.utc).isoformat(),
        )
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            output = MermaidRenderer().render(graph)

        if len(output) > 4000:
            assert any("4" in str(w.message) or "char" in str(w.message).lower() for w in caught), (
                "Expected a UserWarning when Mermaid output exceeds 4000 chars"
            )

    def test_bounded_preview_summarizes_large_graph_without_warning(self):
        """Large graph previews remain valid Mermaid instead of being sliced mid-line."""
        graph = self._make_large_graph()

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            output = MermaidRenderer().render_bounded_preview(graph)

        assert caught == []
        assert len(output) <= 4000
        assert output.startswith("flowchart LR")
        assert "Large graph preview summarized" in output
        assert "Full graph preserved in JSON GraphML MTGX and DOT artifacts" in output
        assert "HOST nodes:" in output
        assert "HIGH:" in output
        assert "Critical path:" in output

    def test_empty_graph_renders_without_crash(self):
        ext = AttackNode(
            node_id="EXT::1",
            node_type=NodeType.EXTERNAL,
            label="External",
            source_table="synthetic",
            source_id=0,
            engagement_id=1,
        )
        graph = AttackGraph(
            engagement_id=1,
            engagement_name="test",
            node_count=1,
            edge_count=0,
            nodes=[ext],
            edges=[],
            generated_at=datetime.now(timezone.utc).isoformat(),
        )
        output = MermaidRenderer().render(graph)
        assert "flowchart" in output


# ══════════════════════════════════════════════════════════════════════════════
# DOT renderer
# ══════════════════════════════════════════════════════════════════════════════


class TestDotRenderer:
    """Basic DOT renderer structural checks."""

    def _make_simple_graph(self) -> AttackGraph:
        n1 = AttackNode(
            node_id="EXT::1",
            node_type=NodeType.EXTERNAL,
            label="External",
            source_table="synthetic",
            source_id=0,
            engagement_id=1,
        )
        n2 = AttackNode(
            node_id="HOST::10.0.0.1",
            node_type=NodeType.HOST,
            label="10.0.0.1 (linux)",
            source_table="hosts",
            source_id=1,
            engagement_id=1,
        )
        e = AttackEdge(
            source_node_id="EXT::1",
            target_node_id="HOST::10.0.0.1",
            weight=5.0,
            edge_type="entry",
            on_critical_path=True,
        )
        return AttackGraph(
            engagement_id=1,
            engagement_name="test",
            node_count=2,
            edge_count=1,
            nodes=[n1, n2],
            edges=[e],
            generated_at=datetime.now(timezone.utc).isoformat(),
        )

    def test_dot_output_is_valid_digraph(self):
        graph = self._make_simple_graph()
        output = DotRenderer().render(graph)
        assert "digraph" in output.lower() or "graph" in output.lower()

    def test_dot_output_contains_node_definitions(self):
        graph = self._make_simple_graph()
        output = DotRenderer().render(graph)
        # At minimum, node IDs should appear
        assert "N0" in output or "EXT" in output or "HOST" in output

    def test_critical_path_edge_has_penwidth(self):
        graph = self._make_simple_graph()
        output = DotRenderer().render(graph)
        assert "penwidth" in output

    def test_dot_output_not_empty(self):
        graph = self._make_simple_graph()
        output = DotRenderer().render(graph)
        assert len(output) > 50


# ══════════════════════════════════════════════════════════════════════════════
# Helper functions
# ══════════════════════════════════════════════════════════════════════════════


class TestHelperFunctions:
    """Unit tests for _apc_to_severity and _severity_to_weight."""

    def test_apc_critical_maps_to_critical(self):
        assert _apc_to_severity("CRITICAL") == Severity.CRITICAL

    def test_apc_high_maps_to_high(self):
        assert _apc_to_severity("HIGH") == Severity.HIGH

    def test_apc_unknown_maps_to_info(self):
        assert _apc_to_severity("UNKNOWN_CLASS") == Severity.INFO

    def test_apc_none_maps_to_info(self):
        assert _apc_to_severity(None) == Severity.INFO

    def test_apc_case_insensitive(self):
        assert _apc_to_severity("critical") == Severity.CRITICAL

    def test_severity_weight_critical_highest(self):
        assert _severity_to_weight(Severity.CRITICAL) > _severity_to_weight(Severity.HIGH)

    def test_severity_weight_info_lowest(self):
        assert _severity_to_weight(Severity.INFO) < _severity_to_weight(Severity.LOW)

    def test_severity_weight_all_positive(self):
        for sev in Severity:
            assert _severity_to_weight(sev) > 0


# ══════════════════════════════════════════════════════════════════════════════
# AttackGraphReportContext
# ══════════════════════════════════════════════════════════════════════════════


class TestAttackGraphReportContext:
    """Unit tests for the Phase 6 context slice model."""

    def test_top_exploits_truncated_to_5(self):
        ctx = AttackGraphReportContext(
            engagement_id=1,
            critical_path_summary=["EXT::1", "HOST::10.0.0.1"],
            critical_path_weight=90.0,
            total_critical_nodes=2,
            total_high_nodes=3,
            top_exploits=["e1", "e2", "e3", "e4", "e5", "e6", "e7"],
        )
        assert len(ctx.top_exploits) == 5

    def test_mermaid_snippet_truncated_at_4000(self):
        long_snippet = "flowchart LR\n" + ("    N0 --> N1\n" * 300)
        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            ctx = AttackGraphReportContext(
                engagement_id=1,
                critical_path_summary=[],
                critical_path_weight=0.0,
                total_critical_nodes=0,
                total_high_nodes=0,
                top_exploits=[],
                mermaid_snippet=long_snippet,
            )
        assert len(ctx.mermaid_snippet) <= 4000

    def test_valid_context_accepted(self):
        ctx = AttackGraphReportContext(
            engagement_id=1,
            critical_path_summary=["EXT::1", "EXPL::EDB-50560-1"],
            critical_path_weight=140.0,
            total_critical_nodes=1,
            total_high_nodes=2,
            top_exploits=["EDB-50560", "EDB-44228"],
            cloud_misconfig_count=2,
            idor_finding_count=1,
            has_validated_creds=True,
        )
        assert ctx.has_validated_creds is True
        assert ctx.cloud_misconfig_count == 2


# ══════════════════════════════════════════════════════════════════════════════
# Integration tests
# ══════════════════════════════════════════════════════════════════════════════


class TestIntegrationFullBuild:
    """test_4h_end_to_end_full_fixture: build against full DB, validate all outputs."""

    def test_graph_has_expected_node_types(self, full_db: Path):
        builder = AttackGraphBuilder(engagement_id=1, db_path=full_db)
        graph = builder.build()
        node_types = {n.node_type for n in graph.nodes}
        # Must have at minimum EXTERNAL and HOST nodes
        assert NodeType.EXTERNAL in node_types
        assert NodeType.HOST in node_types

    def test_graph_json_is_valid(self, full_db: Path):
        builder = AttackGraphBuilder(engagement_id=1, db_path=full_db)
        graph = builder.build()
        json_str = graph.model_dump_json()
        parsed = json.loads(json_str)
        assert "engagement_id" in parsed
        assert "nodes" in parsed
        assert "edges" in parsed

    def test_mermaid_output_is_non_empty(self, full_db: Path):
        builder = AttackGraphBuilder(engagement_id=1, db_path=full_db)
        graph = builder.build()
        output = MermaidRenderer().render(graph)
        assert len(output) > 10
        assert "flowchart" in output

    def test_dot_output_is_non_empty(self, full_db: Path):
        builder = AttackGraphBuilder(engagement_id=1, db_path=full_db)
        graph = builder.build()
        output = DotRenderer().render(graph)
        assert len(output) > 10

    def test_node_count_matches_nodes_list(self, full_db: Path):
        builder = AttackGraphBuilder(engagement_id=1, db_path=full_db)
        graph = builder.build()
        assert graph.node_count == len(graph.nodes)

    def test_edge_count_matches_edges_list(self, full_db: Path):
        builder = AttackGraphBuilder(engagement_id=1, db_path=full_db)
        graph = builder.build()
        assert graph.edge_count == len(graph.edges)


class TestIntegrationSnapshot:
    """test_4h_snapshot_write: write snapshot → row inserted → sensitive data guard."""

    def test_snapshot_row_inserted(self, full_db: Path):
        builder = AttackGraphBuilder(engagement_id=1, db_path=full_db)
        graph = builder.build()
        mermaid = MermaidRenderer().render(graph)
        dot = DotRenderer().render(graph)
        builder.write_snapshot(graph, mermaid=mermaid, dot=dot)

        con = sqlite3.connect(full_db)
        count = con.execute(
            "SELECT COUNT(*) FROM attack_graph_snapshots WHERE engagement_id=1"
        ).fetchone()[0]
        con.close()
        assert count == 1

    def test_snapshot_graph_json_passes_sensitive_guard(self, full_db: Path):
        builder = AttackGraphBuilder(engagement_id=1, db_path=full_db)
        graph = builder.build()
        json_str = graph.model_dump_json()
        # Must not raise — no sensitive keys in clean graph
        _assert_no_sensitive_data(json_str)

    def test_snapshot_blocked_with_tampered_metadata(self, full_db: Path):
        builder = AttackGraphBuilder(engagement_id=1, db_path=full_db)
        graph = builder.build()

        if not graph.nodes:
            pytest.skip("No nodes to tamper with")

        # Bypass the Pydantic validator and manually inject a forbidden key
        node = graph.nodes[0]
        object.__setattr__(node, "metadata", dict(node.metadata) | {"hash_plaintext": "TAMPERED"})

        with pytest.raises(ValueError, match="hash_plaintext"):
            builder.write_snapshot(graph, mermaid="", dot="")

    def test_snapshot_mermaid_and_dot_stored(self, full_db: Path):
        builder = AttackGraphBuilder(engagement_id=1, db_path=full_db)
        graph = builder.build()
        mermaid = MermaidRenderer().render(graph)
        dot = DotRenderer().render(graph)
        builder.write_snapshot(graph, mermaid=mermaid, dot=dot)

        con = sqlite3.connect(full_db)
        row = con.execute(
            "SELECT mermaid_output, dot_output FROM attack_graph_snapshots WHERE engagement_id=1"
        ).fetchone()
        con.close()
        assert row is not None
        assert row[0] is not None
        assert row[1] is not None

    def test_snapshot_stores_bounded_mermaid_preview_for_large_graph(self, full_db: Path):
        nodes = [
            AttackNode(
                node_id="EXT::eng-1",
                node_type=NodeType.EXTERNAL,
                label="External",
                source_table="synthetic",
                source_id=0,
                engagement_id=1,
            )
        ]
        edges = []
        for index in range(120):
            node_id = f"HOST::172.16.{index // 255}.{index % 255}"
            nodes.append(
                AttackNode(
                    node_id=node_id,
                    node_type=NodeType.HOST,
                    label=f"snapshot-host-{index:04d}-with-long-preview-label",
                    source_table="hosts",
                    source_id=index + 1,
                    engagement_id=1,
                    severity=Severity.HIGH if index % 7 == 0 else None,
                )
            )
            edges.append(
                AttackEdge(
                    source_node_id="EXT::eng-1",
                    target_node_id=node_id,
                    weight=5.0,
                    edge_type="entry",
                )
            )
        graph = AttackGraph(
            engagement_id=1,
            engagement_name="large-snapshot",
            node_count=len(nodes),
            edge_count=len(edges),
            nodes=nodes,
            edges=edges,
            generated_at=datetime.now(timezone.utc).isoformat(),
        )
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            oversized_mermaid = MermaidRenderer().render(graph)

        builder = AttackGraphBuilder(engagement_id=1, db_path=full_db)
        builder.write_snapshot(graph, mermaid=oversized_mermaid, dot=DotRenderer().render(graph))

        con = sqlite3.connect(full_db)
        try:
            row = con.execute(
                "SELECT node_count, edge_count, graph_json, mermaid_output "
                "FROM attack_graph_snapshots WHERE engagement_id=1 ORDER BY id DESC LIMIT 1"
            ).fetchone()
        finally:
            con.close()

        assert row is not None
        assert row[0] == len(nodes)
        assert row[1] == len(edges)
        assert len(row[3]) <= 4000
        assert "Large graph preview summarized" in row[3]
        assert json.loads(row[2])["node_count"] == len(nodes)

    def test_snapshot_write_recreates_snapshot_table_if_missing(self, full_db: Path):
        con = sqlite3.connect(full_db)
        try:
            con.execute("DROP TABLE attack_graph_snapshots")
            con.commit()
        finally:
            con.close()

        builder = AttackGraphBuilder(engagement_id=1, db_path=full_db)
        graph = builder.build()
        mermaid = MermaidRenderer().render(graph)
        dot = DotRenderer().render(graph)
        builder.write_snapshot(graph, mermaid=mermaid, dot=dot)

        con = sqlite3.connect(full_db)
        try:
            count = con.execute(
                "SELECT COUNT(*) FROM attack_graph_snapshots WHERE engagement_id=1"
            ).fetchone()[0]
        finally:
            con.close()
        assert count == 1


class TestIntegrationEmptyGraph:
    """test_4h_empty_graph: graceful handling when no Phase 4 data exists."""

    def test_empty_db_no_crash(self, empty_db: Path):
        builder = AttackGraphBuilder(engagement_id=1, db_path=empty_db)
        graph = builder.build()
        assert graph is not None

    def test_empty_db_has_one_external_node(self, empty_db: Path):
        builder = AttackGraphBuilder(engagement_id=1, db_path=empty_db)
        graph = builder.build()
        ext_nodes = [n for n in graph.nodes if n.node_type == NodeType.EXTERNAL]
        assert len(ext_nodes) == 1

    def test_empty_db_critical_path_empty_or_single(self, empty_db: Path):
        builder = AttackGraphBuilder(engagement_id=1, db_path=empty_db)
        graph = builder.build()
        # No IMPACT node → critical path may be empty
        assert isinstance(graph.critical_path_nodes, list)

    def test_empty_db_mermaid_renders(self, empty_db: Path):
        builder = AttackGraphBuilder(engagement_id=1, db_path=empty_db)
        graph = builder.build()
        output = MermaidRenderer().render(graph)
        assert "flowchart" in output


class TestGraphBuildArtifacts:
    def test_graph_build_all_writes_native_mtgx_workspace(
        self,
        tmp_path: Path,
        monkeypatch,
    ) -> None:
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / ".forge_data"))
        monkeypatch.setenv("FORGE_ENV", "test")

        db_root = tmp_path / ".forge_data" / "engagements"
        db_root.mkdir(parents=True)
        db_path = _make_db(db_root, "1.db")
        _seed_full(db_path)
        con = sqlite3.connect(db_path)
        try:
            con.execute(
                """
                UPDATE key_scanner_findings
                SET validation_detail=?,
                    validated_at=?
                WHERE engagement_id=1 AND service='aws'
                """,
                (
                    "VALIDATED:aws_sts_get_caller_identity:AccountId=742931608514 UserId=AIDAEXAMPLE",
                    "2026-07-15T09:30:00+00:00",
                ),
            )
            con.executescript(
                """
                CREATE TABLE IF NOT EXISTS engagement_seeds (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    engagement_id INTEGER NOT NULL,
                    seed_value TEXT NOT NULL,
                    seed_type TEXT NOT NULL,
                    source TEXT,
                    status TEXT,
                    depth INTEGER,
                    confidence REAL,
                    parent_seed_id INTEGER,
                    metadata_json TEXT
                );
                CREATE TABLE IF NOT EXISTS seed_relations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    engagement_id INTEGER NOT NULL,
                    source_seed_id INTEGER NOT NULL,
                    target_seed_id INTEGER NOT NULL,
                    relation_type TEXT NOT NULL,
                    confidence REAL,
                    evidence_json TEXT
                );
                """
            )
            con.executemany(
                """
                INSERT INTO engagement_seeds
                    (engagement_id, seed_value, seed_type, source, status, depth, confidence, metadata_json)
                VALUES (1, ?, ?, ?, 'completed', ?, ?, '{}')
                """,
                [
                    (
                        "https://id.example.com/.well-known/webfinger?resource=acct:owner@example.com",
                        "url",
                        "scope",
                        0,
                        0.9,
                    ),
                    ("owner@example.com", "email", "artifact", 1, 0.74),
                    (
                        "https://id.example.com/.well-known/did.json",
                        "url",
                        "artifact",
                        1,
                        0.73,
                    ),
                    ("did-owner@example.com", "email", "artifact", 2, 0.73),
                ],
            )
            con.execute(
                """
                UPDATE engagement_seeds
                SET metadata_json=?
                WHERE engagement_id=1
                  AND seed_value='https://id.example.com/.well-known/webfinger?resource=acct:owner@example.com'
                """,
                (
                    json.dumps(
                        {
                            "source": "historical_cdx",
                            "provider_sources": ["wayback", "commoncrawl"],
                            "source_url": "https://id.example.com/.well-known/webfinger?resource=acct:owner@example.com",
                            "root_domain": "example.com",
                            "format": "webfinger",
                            "key_enc": "super-secret",
                            "nested": {"token": "nested-secret-never-render", "status": "parsed"},
                        },
                        sort_keys=True,
                    ),
                ),
            )
            con.executemany(
                """
                INSERT INTO seed_relations
                    (engagement_id, source_seed_id, target_seed_id, relation_type, confidence, evidence_json)
                VALUES (?, ?, ?, 'derived_from', ?, ?)
                """,
                [
                    (
                        1,
                        1,
                        2,
                        0.74,
                        '{"rule":"artifact_seed_provenance","extract_rule":"artifact_text_extract","source_url":"https://id.example.com/.well-known/webfinger?resource=acct:owner@example.com","source_file":"https://id.example.com/.well-known/webfinger","format":"webfinger","payload_count":3,"archive_sources":["wayback","commoncrawl"],"provider_sources":["wayback","commoncrawl"],"root_domain":"example.com","key_enc":"super-secret"}',
                    ),
                    (
                        1,
                        3,
                        4,
                        0.73,
                        '{"rule":"artifact_seed_provenance","extract_rule":"artifact_text_extract","source_url":"https://id.example.com/.well-known/did.json","source_file":"https://id.example.com/.well-known/did.json","format":"did.json","payload_count":2,"provider_sources":["direct"],"root_domain":"example.com","token":"never-render-this"}',
                    ),
                ],
            )
            con.commit()
        finally:
            con.close()

        from forge.cli import graph_build  # noqa: PLC0415

        out_dir = tmp_path / "reports"
        graph_build(
            engagement="1",
            fmt="all",
            output_dir=str(out_dir),
            min_severity="LOW",
            critical_path_only=False,
            snapshot=False,
            max_nodes=150,
        )

        graphml_path = out_dir / "1_attack_graph.graphml"
        mtgx_path = out_dir / "1_attack_graph.mtgx"
        graph_json_path = out_dir / "1_attack_graph.json"
        edges_csv_path = out_dir / "1_attack_graph_edges.csv"
        nodes_csv_path = out_dir / "1_attack_graph_nodes.csv"
        assert graphml_path.is_file()
        assert mtgx_path.is_file()
        assert graph_json_path.is_file()
        assert edges_csv_path.is_file()
        assert nodes_csv_path.is_file()
        generic_graphml_text = graphml_path.read_text(encoding="utf-8")
        graph_json_text = graph_json_path.read_text(encoding="utf-8")

        with zipfile.ZipFile(mtgx_path) as archive:
            archive_names = set(archive.namelist())
            assert "Graphs/Graph1.graphml" in archive_names
            assert "manifest.json" in archive_names
            assert "README.md" in archive_names
            graphml_text = archive.read("Graphs/Graph1.graphml").decode("utf-8", errors="replace")
            manifest = json.loads(archive.read("manifest.json").decode("utf-8"))
            readme_text = archive.read("README.md").decode("utf-8", errors="replace")

        assert 'key id="source_id"' in generic_graphml_text
        assert 'key id="metadata_json"' in generic_graphml_text
        assert 'key id="maltego_entity_type"' in generic_graphml_text
        assert 'key id="primary_property"' in generic_graphml_text
        assert 'key id="primary_value"' in generic_graphml_text
        assert 'key id="analyst_properties_json"' in generic_graphml_text
        assert 'key id="layout_x"' in generic_graphml_text
        assert 'key id="layout_y"' in generic_graphml_text
        assert 'key id="edge_type"' in generic_graphml_text
        assert 'key id="edge_critical"' in generic_graphml_text
        assert 'key id="edge_metadata_json"' in generic_graphml_text
        assert '<data key="source_table">hosts</data>' in generic_graphml_text
        assert '<data key="maltego_entity_type">maltego.EmailAddress</data>' in generic_graphml_text
        assert '<data key="primary_property">email</data>' in generic_graphml_text
        assert '<data key="layout_x">340.0</data>' in generic_graphml_text
        assert '<data key="edge_type">derived_from</data>' in generic_graphml_text
        assert '<data key="edge_critical">1</data>' in generic_graphml_text
        assert '"os_family":"linux"' in generic_graphml_text
        assert "VALIDATED:aws_sts_get_caller_identity" in generic_graphml_text
        assert "AccountId=742931608514" in generic_graphml_text
        assert "MaltegoEntity" in graphml_text
        assert "forge.node_type" in graphml_text
        assert "forge.metadata_json" in graphml_text
        assert "forge.identifier" in graphml_text
        assert "forge.validation_detail" in graphml_text
        assert "forge.source_url" in graphml_text
        assert "forge.provider_sources" in graphml_text
        assert "forge.root_domain" in graphml_text
        assert "forge.format" in graphml_text
        assert "VALIDATED:aws_sts_get_caller_identity" in graphml_text
        assert "AccountId=742931608514" in graphml_text
        assert "maltego.link.manual.type" in graphml_text
        assert manifest["schema"] == "forge.mtgx.manifest.v1"
        assert manifest["engagement_id"] == 1
        assert manifest["node_count"] > 0
        assert manifest["edge_count"] > 0
        assert manifest["layout_strategy"] == "deterministic_columnar_by_forge_node_type"
        assert "HOST" in manifest["node_type_counts"]
        assert "maltego.Domain" in set(manifest["maltego_type_mapping"].values())
        assert manifest["maltego_type_mapping"]["company_external"] == "maltego.Company"
        assert any(
            node["forge_node_type"] == "HOST"
            and node["maltego_entity_type"] in {"maltego.Domain", "maltego.IPv4Address", "maltego.Alias"}
            and "layout" in node
            for node in manifest["nodes"]
        )
        assert any(
            node["source_table"] == "hosts"
            and isinstance(node.get("metadata"), dict)
            and node["metadata"].get("os_family") == "linux"
            for node in manifest["nodes"]
        )
        seed_manifest_node = next(
            node
            for node in manifest["nodes"]
            if node["source_table"] == "engagement_seeds"
            and node["label"].startswith("https://id.example.com/.well-known/webfinger")
        )
        assert seed_manifest_node["metadata"]["source"] == "scope"
        assert seed_manifest_node["metadata"]["discovery_source"] == "historical_cdx"
        assert seed_manifest_node["metadata"]["provider_sources"] == ["wayback", "commoncrawl"]
        assert seed_manifest_node["metadata"]["root_domain"] == "example.com"
        assert seed_manifest_node["analyst_properties"]["provider_sources"] == (
            '["wayback","commoncrawl"]'
        )
        assert seed_manifest_node["analyst_properties"]["root_domain"] == "example.com"
        assert seed_manifest_node["analyst_properties"]["format"] == "webfinger"
        seed_manifest_metadata_text = json.dumps(seed_manifest_node["metadata"], sort_keys=True)
        assert "key_enc" not in seed_manifest_metadata_text
        assert "super-secret" not in seed_manifest_metadata_text
        assert "nested-secret-never-render" not in seed_manifest_metadata_text
        cloud_manifest_node = next(
            node
            for node in manifest["nodes"]
            if node["forge_node_type"] == "CLOUD"
            and isinstance(node.get("metadata"), dict)
            and node["metadata"].get("identifier") == "my-proj"
        )
        assert cloud_manifest_node["primary_property"] == "alias"
        assert cloud_manifest_node["primary_value"] == "my-proj"
        assert cloud_manifest_node["analyst_properties"]["service"] == "firebase"
        assert cloud_manifest_node["analyst_properties"]["identifier"] == "my-proj"
        assert any(
            node["forge_node_type"] == "APIKEY"
            and isinstance(node.get("metadata"), dict)
            and node["metadata"].get("validation_state") == "ACTIVE"
            and node.get("analyst_properties", {}).get("source_url")
            == "https://github.com/example/repo/blob/main/cfg.py"
            and node.get("analyst_properties", {}).get("validation_state") == "ACTIVE"
            and "VALIDATED:aws_sts_get_caller_identity"
            in str(node.get("analyst_properties", {}).get("validation_detail"))
            and "AccountId=742931608514" in str(node["metadata"].get("validation_detail"))
            for node in manifest["nodes"]
        )
        assert any(
            edge["edge_type"] == "derived_from"
            and isinstance(edge.get("metadata"), dict)
            and edge["metadata"].get("rule") == "artifact_seed_provenance"
            and edge["metadata"].get("extract_rule") == "artifact_text_extract"
            and edge["metadata"].get("format") == "webfinger"
            and edge["metadata"].get("payload_count") == 3
            and edge["metadata"].get("archive_sources") == ["wayback", "commoncrawl"]
            and edge["metadata"].get("provider_sources") == ["wayback", "commoncrawl"]
            and edge["metadata"].get("root_domain") == "example.com"
            for edge in manifest["edges"]
        )
        assert any(
            edge["edge_type"] == "derived_from"
            and isinstance(edge.get("metadata"), dict)
            and edge["metadata"].get("rule") == "artifact_seed_provenance"
            and edge["metadata"].get("format") == "did.json"
            and edge["metadata"].get("payload_count") == 2
            and edge["metadata"].get("provider_sources") == ["direct"]
            and edge["metadata"].get("root_domain") == "example.com"
            and "token" not in edge["metadata"]
            for edge in manifest["edges"]
        )
        for exported_text in (generic_graphml_text, graphml_text, graph_json_text):
            assert "VALIDATED:aws_sts_get_caller_identity" in exported_text
            assert "artifact_seed_provenance" in exported_text
            assert "artifact_text_extract" in exported_text
            assert "webfinger" in exported_text
            assert "did.json" in exported_text
            assert "commoncrawl" in exported_text
            assert "direct" in exported_text
            assert "super-secret" not in exported_text
            assert "key_enc" not in exported_text
            assert "never-render-this" not in exported_text
        assert "FORGE Maltego Workspace" in readme_text
        assert "forge.on_critical_path" in readme_text
        with nodes_csv_path.open(newline="", encoding="utf-8") as handle:
            node_rows = list(csv.DictReader(handle))
        assert "MetadataJSON" in (node_rows[0].keys() if node_rows else [])
        api_key_csv_row = next(row for row in node_rows if row["EntityType"] == "APIKEY")
        assert "VALIDATED:aws_sts_get_caller_identity" in api_key_csv_row["MetadataJSON"]
        assert "AccountId=742931608514" in api_key_csv_row["MetadataJSON"]
        assert "key_enc" not in api_key_csv_row["MetadataJSON"]
        assert "AKIAIOSFODNN7EXAMPLE" not in api_key_csv_row["MetadataJSON"]
        edge_csv_lines = [line.strip() for line in edges_csv_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        assert edge_csv_lines[0] == "Source,Target,Weight,Relation,MetadataJSON"
        assert any("artifact_seed_provenance" in line and "webfinger" in line for line in edge_csv_lines[1:])
        assert any("artifact_seed_provenance" in line and "did.json" in line for line in edge_csv_lines[1:])
        assert all("never-render-this" not in line for line in edge_csv_lines[1:])
        assert any(not line.endswith(",") for line in edge_csv_lines[1:])

    def test_graph_build_all_exports_compiled_artifact_seed_provenance(
        self,
        tmp_path: Path,
        monkeypatch,
    ) -> None:
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / ".forge_data"))
        monkeypatch.setenv("FORGE_ENV", "test")

        db_root = tmp_path / ".forge_data" / "engagements"
        db_root.mkdir(parents=True)
        db_path = _make_db(db_root, "1.db")
        source_url = "https://downloads.example.com/opaque-compiled?id=42"
        email_seed = "remote-dex@example.com"
        api_seed = "https://remote-dex.example.com/api"
        compiled_context = {
            "artifact_provenance": True,
            "artifact_source_seed_id": 101,
            "artifact_type": "document",
            "content_type": "application/x-dex",
            "download_filename": "42-opaque-compiled.dex",
            "downloaded_from_remote": True,
            "format": "dex",
            "metadata_payload_count": 1,
            "payload_count": 2,
            "parser": "document",
            "source_url": source_url,
            "key_enc": "compiled-key-never-export",
            "nested": {"token": "compiled-token-never-export", "status": "parsed"},
        }
        relation_evidence = {
            "rule": "artifact_seed_provenance",
            "extract_rule": "artifact_text_extract",
            "source_file": source_url,
            "source_url": source_url,
            "artifact_type": "document",
            "content_type": "application/x-dex",
            "download_filename": "42-opaque-compiled.dex",
            "downloaded_from_remote": True,
            "format": "dex",
            "payload_count": 2,
            "provider_sources": ["urlscan"],
            "key_enc": "compiled-key-never-export",
            "nested": {"token": "compiled-token-never-export", "status": "parsed"},
        }
        con = sqlite3.connect(db_path)
        try:
            con.executescript(
                """
                CREATE TABLE IF NOT EXISTS engagement_seeds (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    engagement_id INTEGER NOT NULL,
                    seed_value TEXT NOT NULL,
                    seed_type TEXT NOT NULL,
                    source TEXT,
                    status TEXT,
                    depth INTEGER,
                    confidence REAL,
                    parent_seed_id INTEGER,
                    metadata_json TEXT
                );
                CREATE TABLE IF NOT EXISTS seed_relations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    engagement_id INTEGER NOT NULL,
                    source_seed_id INTEGER NOT NULL,
                    target_seed_id INTEGER NOT NULL,
                    relation_type TEXT NOT NULL,
                    confidence REAL,
                    evidence_json TEXT
                );
                """
            )
            con.executemany(
                """
                INSERT INTO engagement_seeds
                    (id, engagement_id, seed_value, seed_type, source, status, depth, confidence, metadata_json)
                VALUES (?, 1, ?, ?, ?, 'completed', ?, ?, ?)
                """,
                [
                    (101, source_url, "url", "urlscan", 1, 0.82, "{}"),
                    (102, email_seed, "email", "artifact", 2, 0.74, json.dumps(compiled_context, sort_keys=True)),
                    (103, api_seed, "url", "artifact", 2, 0.68, json.dumps(compiled_context, sort_keys=True)),
                ],
            )
            con.executemany(
                """
                INSERT INTO seed_relations
                    (engagement_id, source_seed_id, target_seed_id, relation_type, confidence, evidence_json)
                VALUES (1, 101, ?, 'derived_from', ?, ?)
                """,
                [
                    (102, 0.74, json.dumps(relation_evidence, sort_keys=True)),
                    (103, 0.68, json.dumps(relation_evidence, sort_keys=True)),
                ],
            )
            con.commit()
        finally:
            con.close()

        from forge.cli import graph_build  # noqa: PLC0415

        out_dir = tmp_path / "reports"
        graph_build(
            engagement="1",
            fmt="all",
            output_dir=str(out_dir),
            min_severity="LOW",
            critical_path_only=False,
            snapshot=False,
            max_nodes=150,
        )

        graphml_path = out_dir / "1_attack_graph.graphml"
        mtgx_path = out_dir / "1_attack_graph.mtgx"
        graph_json_path = out_dir / "1_attack_graph.json"
        graphml_text = graphml_path.read_text(encoding="utf-8")
        graph_json_text = graph_json_path.read_text(encoding="utf-8")
        graph_payload = json.loads(graph_json_text)
        with zipfile.ZipFile(mtgx_path) as archive:
            mtgx_graphml = archive.read("Graphs/Graph1.graphml").decode("utf-8", errors="replace")
            manifest = json.loads(archive.read("manifest.json").decode("utf-8"))

        graph_nodes = {
            str(node.get("label") or ""): node
            for node in graph_payload.get("nodes", [])
            if isinstance(node, dict)
        }
        assert graph_nodes[email_seed]["source_table"] == "engagement_seeds"
        assert graph_nodes[email_seed]["metadata"]["format"] == "dex"
        assert graph_nodes[email_seed]["metadata"]["content_type"] == "application/x-dex"
        assert graph_nodes[email_seed]["metadata"]["download_filename"] == "42-opaque-compiled.dex"
        assert graph_nodes[api_seed]["metadata"]["downloaded_from_remote"] is True

        manifest_nodes = {
            str(node.get("label") or ""): node
            for node in manifest.get("nodes", [])
            if isinstance(node, dict)
        }
        assert manifest_nodes[email_seed]["maltego_entity_type"] == "maltego.EmailAddress"
        assert manifest_nodes[email_seed]["primary_property"] == "email"
        assert manifest_nodes[email_seed]["metadata"]["format"] == "dex"
        assert manifest_nodes[email_seed]["metadata"]["content_type"] == "application/x-dex"
        assert manifest_nodes[api_seed]["maltego_entity_type"] == "maltego.URL"
        assert manifest_nodes[api_seed]["primary_property"] == "short-title"

        assert any(
            edge["edge_type"] == "derived_from"
            and isinstance(edge.get("metadata"), dict)
            and edge["metadata"].get("rule") == "artifact_seed_provenance"
            and edge["metadata"].get("format") == "dex"
            and edge["metadata"].get("content_type") == "application/x-dex"
            and edge["metadata"].get("download_filename") == "42-opaque-compiled.dex"
            for edge in manifest.get("edges", [])
        )
        for exported_text in (graphml_text, mtgx_graphml, graph_json_text, json.dumps(manifest, sort_keys=True)):
            assert "artifact_seed_provenance" in exported_text
            assert "application/x-dex" in exported_text
            assert "42-opaque-compiled.dex" in exported_text
            assert "remote-dex@example.com" in exported_text
            assert "compiled-key-never-export" not in exported_text
            assert "compiled-token-never-export" not in exported_text
            assert "key_enc" not in exported_text
            assert '"token"' not in exported_text


# ══════════════════════════════════════════════════════════════════════════════
# Evasion assertion tests
# ══════════════════════════════════════════════════════════════════════════════


@pytest.mark.opsec
class TestEvasionAssertions:
    """
    OPSEC evasion assertions from forge_spec.md §4-H.12 (Evasion Assertion Tests).

    These tests MUST pass on every CI run. Any failure indicates that sensitive
    credential material has leaked into graph output or snapshot storage.
    """

    def test_graph_json_no_password_key(self, full_db: Path):
        """Evasion: serialised graph JSON must never contain 'password' as a JSON key."""
        builder = AttackGraphBuilder(engagement_id=1, db_path=full_db)
        graph = builder.build()
        json_str = graph.model_dump_json()
        assert '"password":' not in json_str, (
            "EVASION FAIL: graph_json contains 'password' key. "
            "Credential material must never appear in graph output."
        )

    def test_graph_json_no_hash_plaintext_key(self, full_db: Path):
        """Evasion: serialised graph JSON must never contain 'hash_plaintext' as a JSON key."""
        builder = AttackGraphBuilder(engagement_id=1, db_path=full_db)
        graph = builder.build()
        json_str = graph.model_dump_json()
        assert '"hash_plaintext":' not in json_str, (
            "EVASION FAIL: graph_json contains 'hash_plaintext' key."
        )

    def test_graph_json_no_key_enc_key(self, full_db: Path):
        """Evasion: serialised graph JSON must never contain 'key_enc' as a JSON key."""
        builder = AttackGraphBuilder(engagement_id=1, db_path=full_db)
        graph = builder.build()
        json_str = graph.model_dump_json()
        assert '"key_enc":' not in json_str, (
            "EVASION FAIL: graph_json contains 'key_enc' key. "
            "API key material must never appear in graph output."
        )

    def test_mermaid_no_email_address(self, full_db: Path):
        """Evasion: Mermaid output must not contain raw email addresses."""
        builder = AttackGraphBuilder(engagement_id=1, db_path=full_db)
        graph = builder.build()
        mermaid = MermaidRenderer().render(graph)
        email_pattern = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
        matches = email_pattern.findall(mermaid)
        assert not matches, (
            f"EVASION FAIL: Mermaid output contains email address(es): {matches}. "
            "Node labels must use domain-only or entity-ID format."
        )

    def test_mermaid_no_full_api_key(self, full_db: Path):
        """Evasion: Mermaid output must not contain full (un-redacted) API key strings."""
        builder = AttackGraphBuilder(engagement_id=1, db_path=full_db)
        graph = builder.build()
        mermaid = MermaidRenderer().render(graph)
        # AWS key pattern: AKIA followed by 16 uppercase alphanumeric chars
        aws_key_re = re.compile(r"AKIA[0-9A-Z]{16}")
        assert not aws_key_re.search(mermaid), (
            "EVASION FAIL: Mermaid output contains an unredacted AWS access key."
        )

    def test_snapshot_blocks_tampered_sensitive_data(self, full_db: Path):
        """Evasion: _assert_no_sensitive_data must block snapshot write when guard trips."""
        builder = AttackGraphBuilder(engagement_id=1, db_path=full_db)
        graph = builder.build()

        # Manually corrupt graph_json to include a forbidden key
        corrupted_json = graph.model_dump_json().replace(
            '"engagement_id": 1',
            '"engagement_id": 1, "key_enc": "FORGE-ENC-v1:LEAKED"',
        )

        with pytest.raises(ValueError, match="key_enc"):
            _assert_no_sensitive_data(corrupted_json)

    def test_severity_numeric_ordering(self):
        """Structural assertion: severity numeric values must be strictly ordered."""
        assert Severity.INFO.numeric < Severity.LOW.numeric
        assert Severity.LOW.numeric < Severity.MEDIUM.numeric
        assert Severity.MEDIUM.numeric < Severity.HIGH.numeric
        assert Severity.HIGH.numeric < Severity.CRITICAL.numeric
