from __future__ import annotations

import json
import sqlite3

from forge.orchestration.seed_promotion import (
    insert_seed_relation,
    lookup_engagement_seed_id,
    promote_cloud_asset_seed_refs,
    promote_email_localpart_seed_refs,
    promote_pending_cloud_targets,
    promote_social_url_seed_refs,
)


def _cloud_con() -> sqlite3.Connection:
    con = sqlite3.connect(":memory:")
    con.execute(
        """
        CREATE TABLE cloud_assets (
            engagement_id INTEGER NOT NULL,
            asset_type TEXT NOT NULL,
            identifier TEXT NOT NULL,
            provider_identifier TEXT,
            source TEXT,
            UNIQUE(engagement_id, asset_type, identifier)
        )
        """
    )
    return con


def _seed_relation_con() -> sqlite3.Connection:
    con = sqlite3.connect(":memory:")
    con.execute(
        """
        CREATE TABLE engagement_seeds (
            id INTEGER PRIMARY KEY,
            engagement_id INTEGER NOT NULL,
            seed_value TEXT NOT NULL,
            seed_type TEXT NOT NULL,
            UNIQUE(engagement_id, seed_value, seed_type)
        )
        """
    )
    con.execute(
        """
        CREATE TABLE seed_relations (
            engagement_id INTEGER NOT NULL,
            source_seed_id INTEGER NOT NULL,
            target_seed_id INTEGER NOT NULL,
            relation_type TEXT NOT NULL,
            confidence REAL NOT NULL,
            evidence_json TEXT NOT NULL,
            UNIQUE(engagement_id, source_seed_id, target_seed_id, relation_type)
        )
        """
    )
    return con


def _upsert_seed_for_engagement(engagement_id: int):
    def _upsert_seed(
        con: sqlite3.Connection,
        seed_value: str,
        seed_type: str,
        *,
        source: str,
        status: str,
        depth: int,
        confidence: float,
    ) -> None:
        con.execute(
            """
            INSERT OR IGNORE INTO engagement_seeds
                (engagement_id, seed_value, seed_type)
            VALUES (?, ?, ?)
            """,
            (engagement_id, seed_value, seed_type),
        )

    return _upsert_seed


def test_lookup_engagement_seed_id_scopes_by_engagement_and_type() -> None:
    con = _seed_relation_con()
    con.execute(
        """
        INSERT INTO engagement_seeds (id, engagement_id, seed_value, seed_type)
        VALUES
            (7, 42, 'ops.example', 'domain'),
            (8, 43, 'ops.example', 'domain'),
            (9, 42, 'ops.example', 'hostname')
        """
    )

    assert lookup_engagement_seed_id(con, 42, "ops.example", "domain") == 7
    assert lookup_engagement_seed_id(con, 43, "ops.example", "domain") == 8
    assert lookup_engagement_seed_id(con, 42, "ops.example", "hostname") == 9
    assert lookup_engagement_seed_id(con, 42, "missing.example", "domain") is None


def test_lookup_engagement_seed_id_returns_none_for_malformed_rows() -> None:
    con = sqlite3.connect(":memory:")
    con.execute(
        """
        CREATE TABLE engagement_seeds (
            id TEXT,
            engagement_id INTEGER NOT NULL,
            seed_value TEXT NOT NULL,
            seed_type TEXT NOT NULL
        )
        """
    )
    con.execute(
        """
        INSERT INTO engagement_seeds (id, engagement_id, seed_value, seed_type)
        VALUES ('not-int', 42, 'ops.example', 'domain')
        """
    )

    assert lookup_engagement_seed_id(con, 42, "ops.example", "domain") is None


def test_insert_seed_relation_writes_sorted_evidence_once_and_skips_invalid_ids() -> None:
    con = _seed_relation_con()

    insert_seed_relation(
        con,
        42,
        1,
        2,
        relation_type="derived_from",
        confidence=0.72,
        evidence={"b": 2, "a": 1},
    )
    insert_seed_relation(
        con,
        42,
        1,
        2,
        relation_type="derived_from",
        confidence=0.72,
        evidence={"b": 2, "a": 1},
    )
    insert_seed_relation(
        con,
        42,
        None,
        2,
        relation_type="derived_from",
        confidence=0.72,
        evidence={"a": 1},
    )
    insert_seed_relation(
        con,
        42,
        1,
        1,
        relation_type="derived_from",
        confidence=0.72,
        evidence={"a": 1},
    )

    rows = con.execute(
        """
        SELECT engagement_id, source_seed_id, target_seed_id, relation_type, confidence, evidence_json
        FROM seed_relations
        """
    ).fetchall()
    assert rows == [
        (42, 1, 2, "derived_from", 0.72, '{"a": 1, "b": 2}'),
    ]


def test_promote_email_localpart_seed_refs_normalizes_email_and_links_usernames() -> None:
    con = _seed_relation_con()

    promote_email_localpart_seed_refs(
        con,
        42,
        " User@Example.COM ",
        [" user ", "", "ops"],
        upsert_engagement_seed=_upsert_seed_for_engagement(42),
    )

    seeds = con.execute(
        """
        SELECT seed_value, seed_type
        FROM engagement_seeds
        ORDER BY id
        """
    ).fetchall()
    assert seeds == [
        ("user@example.com", "email"),
        ("user", "username"),
        ("ops", "username"),
    ]
    relations = con.execute(
        """
        SELECT source_seed_id, target_seed_id, relation_type, confidence, evidence_json
        FROM seed_relations
        ORDER BY target_seed_id
        """
    ).fetchall()
    assert relations == [
        (1, 2, "derived_from", 0.72, '{"rule": "email_localpart_username"}'),
        (1, 3, "derived_from", 0.72, '{"rule": "email_localpart_username"}'),
    ]


def test_promote_social_url_seed_refs_expands_profile_context_and_bluesky_domain() -> None:
    con = _seed_relation_con()
    con.execute(
        """
        INSERT INTO engagement_seeds (id, engagement_id, seed_value, seed_type)
        VALUES (1, 42, 'https://bsky.app/profile/Ops.Example', 'url')
        """
    )

    promote_social_url_seed_refs(
        con,
        42,
        "https://bsky.app/profile/Ops.Example",
        "url",
        upsert_engagement_seed=_upsert_seed_for_engagement(42),
        platform_hint=lambda _profile: "bluesky",
        extract_handle=lambda _url: "Ops.Example",
        extract_company_name=lambda _profile, **_kwargs: "Acme Security",
        extract_profile_name=lambda _profile: "Ada Lovelace",
        classify_seed_value=lambda value: "domain" if value == "ops.example" else "username",
        evidence_rule="operator_social_url_extract",
    )

    seeds = con.execute(
        """
        SELECT id, seed_value, seed_type
        FROM engagement_seeds
        ORDER BY id
        """
    ).fetchall()
    assert seeds == [
        (1, "https://bsky.app/profile/Ops.Example", "url"),
        (2, "Ops.Example", "username"),
        (3, "ops.example", "domain"),
        (4, "Acme Security", "company"),
        (5, "Ada Lovelace", "name"),
    ]
    rows = con.execute(
        """
        SELECT target_seed_id, confidence, evidence_json
        FROM seed_relations
        ORDER BY target_seed_id
        """
    ).fetchall()
    relation_evidence = {
        target_id: (confidence, json.loads(evidence_json))
        for target_id, confidence, evidence_json in rows
    }
    assert relation_evidence == {
        2: (0.78, {"platform": "bluesky", "rule": "operator_social_url_extract"}),
        3: (
            0.82,
            {
                "platform": "bluesky",
                "rule": "social_profile_domain_handle",
                "source_rule": "operator_social_url_extract",
            },
        ),
        4: (0.76, {"platform": "bluesky", "rule": "operator_social_url_extract"}),
        5: (0.74, {"platform": "bluesky", "rule": "operator_social_url_extract"}),
    }


def test_promote_cloud_asset_seed_refs_merges_literal_and_url_refs() -> None:
    con = _cloud_con()

    promote_cloud_asset_seed_refs(
        con,
        42,
        "https://bucket.s3.amazonaws.com/object.txt",
        extract_cloud_asset_seed_refs=lambda _value: [("aws_s3", "bucket")],
        parse_literal_cloud_ref=lambda _value: ("gcs", "other-bucket"),
    )
    promote_cloud_asset_seed_refs(
        con,
        42,
        "https://bucket.s3.amazonaws.com/object.txt",
        extract_cloud_asset_seed_refs=lambda _value: [("aws_s3", "bucket")],
        parse_literal_cloud_ref=lambda _value: None,
    )

    rows = con.execute(
        """
        SELECT asset_type, identifier, provider_identifier, source
        FROM cloud_assets
        ORDER BY asset_type, identifier
        """
    ).fetchall()
    assert rows == [
        ("aws_s3", "bucket", "bucket", "kill_chain_seed_url"),
        ("gcs", "other-bucket", "other-bucket", "kill_chain_seed_url"),
    ]


def test_promote_pending_cloud_targets_upserts_provider_identifier() -> None:
    con = _cloud_con()
    con.execute(
        """
        INSERT INTO cloud_assets
            (engagement_id, asset_type, identifier, provider_identifier, source)
        VALUES (42, 'aws_s3', 'ops-bucket', 'ops-bucket', 'old-source')
        """
    )

    count = promote_pending_cloud_targets(
        con,
        42,
        [
            {"service": " AWS_S3 ", "ref": "Ops-Bucket"},
            {"service": "", "ref": "missing-service"},
            {"service": "gcs", "ref": ""},
            {"service": "firebase", "ref": "App-Prod"},
        ],
    )

    assert count == 2
    rows = con.execute(
        """
        SELECT asset_type, identifier, provider_identifier, source
        FROM cloud_assets
        ORDER BY asset_type, identifier
        """
    ).fetchall()
    assert rows == [
        ("aws_s3", "ops-bucket", "Ops-Bucket", "old-source"),
        ("firebase", "app-prod", "App-Prod", "kill_chain_cloud_ref"),
    ]


def test_promote_pending_cloud_targets_preserves_existing_provider_identifier() -> None:
    con = _cloud_con()
    con.execute(
        """
        INSERT INTO cloud_assets
            (engagement_id, asset_type, identifier, provider_identifier, source)
        VALUES (42, 'aws_s3', 'ops-bucket', 'arn:aws:s3:::ops-bucket', 'old-source')
        """
    )

    promote_pending_cloud_targets(con, 42, [{"service": "aws_s3", "ref": "Ops-Bucket"}])

    row = con.execute(
        """
        SELECT provider_identifier, source
        FROM cloud_assets
        WHERE engagement_id=42 AND asset_type='aws_s3' AND identifier='ops-bucket'
        """
    ).fetchone()
    assert row == ("arn:aws:s3:::ops-bucket", "old-source")
