import json
import sqlite3
from typing import Any

import pytest

from forge.webui.seeds import (
    canonical_seed_value,
    create_engagement_seed_payload,
    delete_engagement_seed_payload,
    engagement_seed_rows,
    parsed_engagement_seed_items,
    seed_scope_entries,
    update_engagement_seed_payload,
)


def _format_dt(value: str) -> str:
    return f"formatted:{value}" if value else ""


def _connect() -> sqlite3.Connection:
    con = sqlite3.connect(":memory:")
    con.row_factory = sqlite3.Row
    con.executescript(
        """
        CREATE TABLE engagements (
            id INTEGER PRIMARY KEY,
            scope_json TEXT NOT NULL DEFAULT '[]',
            updated_at TEXT
        );

        CREATE TABLE engagement_seeds (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER NOT NULL,
            seed_value TEXT NOT NULL,
            seed_type TEXT NOT NULL,
            source TEXT NOT NULL DEFAULT 'operator',
            status TEXT NOT NULL DEFAULT 'pending',
            depth INTEGER NOT NULL DEFAULT 0,
            confidence REAL NOT NULL DEFAULT 1.0,
            parent_seed_id INTEGER,
            metadata_json TEXT NOT NULL DEFAULT '{}',
            discovered_at TEXT NOT NULL DEFAULT '2026-08-13 10:00:00',
            updated_at TEXT NOT NULL DEFAULT '2026-08-13 10:00:00',
            UNIQUE (engagement_id, seed_type, seed_value)
        );

        CREATE TABLE seed_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER NOT NULL,
            seed_id INTEGER NOT NULL
        );

        CREATE TABLE seed_relations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER NOT NULL,
            source_seed_id INTEGER NOT NULL,
            target_seed_id INTEGER NOT NULL,
            relation_type TEXT NOT NULL
        );
        """
    )
    con.execute("INSERT INTO engagements (id, scope_json) VALUES (1001, '[]')")
    return con


def test_parse_engagement_seed_items_canonicalizes_and_deduplicates() -> None:
    parsed = parsed_engagement_seed_items(
        [
            "HTTPS://GAMMA.EXAMPLE:443/login#top",
            "https://gamma.example/login",
            "HTTPS://downloads.gamma.example:443/mobile/app.xapk#download",
            "https://downloads.gamma.example/mobile/app.xapk",
            {"seed_value": "cloud_ref:aws_s3:GammaBucket", "source": "not-valid"},
            {"seed_value": "s3://GammaBucket/private/config.json", "source": "scope"},
            "Acme Corp",
        ]
    )

    assert parsed == [
        {
            "seed_value": "https://gamma.example/login",
            "seed_type": "url",
            "source": "operator",
        },
        {
            "seed_value": "https://downloads.gamma.example/mobile/app.xapk",
            "seed_type": "apk_url",
            "source": "operator",
        },
        {
            "seed_value": "aws_s3:gammabucket",
            "seed_type": "cloud_ref",
            "source": "operator",
        },
        {
            "seed_value": "Acme Corp",
            "seed_type": "company",
            "source": "operator",
        },
    ]
    assert canonical_seed_value("HTTPS://Gamma.SUPABASE.CO:443/rest#details", "cloud_ref") == (
        "https://gamma.supabase.co/rest"
    )


def test_seed_scope_entries_adds_wildcard_only_for_domain_seeds() -> None:
    parsed = parsed_engagement_seed_items(["beta.example", "security@beta.example"])

    assert seed_scope_entries(parsed) == [
        "beta.example",
        "*.beta.example",
        "security@beta.example",
    ]


def test_create_update_delete_seed_payloads_mutate_rows_scope_and_relations() -> None:
    con = _connect()

    created = create_engagement_seed_payload(
        con,
        1001,
        {"seed_value": "beta.example", "confidence": 0.82, "metadata": {"source": "test"}},
        format_dt=_format_dt,
    )

    seed = created["seed"]
    seed_id = int(seed["id"])
    assert seed["seed_value"] == "beta.example"
    assert seed["seed_type"] == "domain"
    assert seed["confidence"] == 0.82
    assert seed["metadata"] == {"source": "test"}
    assert json.loads(con.execute("SELECT scope_json FROM engagements WHERE id=1001").fetchone()[0]) == [
        "beta.example",
        "*.beta.example",
    ]

    patched = update_engagement_seed_payload(
        con,
        1001,
        seed_id,
        {
            "seed_value": "HTTPS://portal.beta.example:443/app#details",
            "seed_type": "url",
            "status": "completed",
            "metadata": {"reviewed": True},
        },
        format_dt=_format_dt,
    )

    updated_seed = patched["seed"]
    assert updated_seed["seed_value"] == "https://portal.beta.example/app"
    assert updated_seed["seed_type"] == "url"
    assert updated_seed["status"] == "completed"
    assert updated_seed["metadata"] == {"reviewed": True}
    assert json.loads(con.execute("SELECT scope_json FROM engagements WHERE id=1001").fetchone()[0]) == [
        "https://portal.beta.example/app",
    ]

    target_seed_id = create_engagement_seed_payload(
        con,
        1001,
        {"seed_value": "security@beta.example"},
        format_dt=_format_dt,
    )["seed"]["id"]
    con.execute("INSERT INTO seed_runs (engagement_id, seed_id) VALUES (1001, ?)", (seed_id,))
    con.execute(
        """
        INSERT INTO seed_relations
            (engagement_id, source_seed_id, target_seed_id, relation_type)
        VALUES (1001, ?, ?, 'derived_from')
        """,
        (seed_id, target_seed_id),
    )
    con.commit()

    deleted = delete_engagement_seed_payload(con, 1001, seed_id, format_dt=_format_dt)

    assert deleted["status"] == "deleted"
    assert deleted["seed_id"] == seed_id
    assert all(item["id"] != seed_id for item in deleted["items"])
    assert con.execute("SELECT COUNT(*) FROM seed_runs WHERE seed_id=?", (seed_id,)).fetchone()[0] == 0
    assert con.execute(
        "SELECT COUNT(*) FROM seed_relations WHERE source_seed_id=? OR target_seed_id=?",
        (seed_id, seed_id),
    ).fetchone()[0] == 0
    assert json.loads(con.execute("SELECT scope_json FROM engagements WHERE id=1001").fetchone()[0]) == [
        "security@beta.example",
    ]


@pytest.mark.parametrize(
    ("body", "message"),
    [
        ({}, "seed_value is required"),
        ({"seed_value": "beta.example", "status": "unknown"}, "Invalid seed status: unknown"),
    ],
)
def test_create_seed_payload_rejects_invalid_input(body: dict[str, Any], message: str) -> None:
    con = _connect()

    with pytest.raises(ValueError, match=message):
        create_engagement_seed_payload(con, 1001, body, format_dt=_format_dt)


def test_engagement_seed_rows_clamps_bad_metadata_to_empty_dict() -> None:
    con = _connect()
    con.execute(
        """
        INSERT INTO engagement_seeds
            (engagement_id, seed_value, seed_type, metadata_json)
        VALUES (1001, 'beta.example', 'domain', 'not-json')
        """
    )

    rows = engagement_seed_rows(con, 1001, format_dt=_format_dt)

    assert rows[0]["metadata"] == {}
    assert rows[0]["discovered_at"] == "formatted:2026-08-13 10:00:00"
