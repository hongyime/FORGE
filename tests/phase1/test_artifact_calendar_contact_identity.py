from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from textwrap import dedent

from forge.engagement_orchestrator import ArtifactQueueProcessor
from tests.phase1.artifact_test_support import bootstrap_engagement


def test_calendar_contact_explicit_identity_fields_become_seeds_with_provenance(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_contacts"
    artifact_root.mkdir()
    bootstrap_engagement(db_path, name="Artifact Contact Identity Test")

    (artifact_root / "team.vcard").write_text(
        dedent(
            """
            BEGIN:VCARD
            VERSION:4.0
            FN:Alice Example
            N:Example;Alice;;;
            ORG:Acme Corp;Incident Response
            TITLE:Incident Commander
            EMAIL;TYPE=work:alice@example.acme
            DESCRIPTION:Bob Noise from Noise Corp must stay free text
            END:VCARD
            """
        ).strip(),
        encoding="utf-8",
    )

    processor = ArtifactQueueProcessor(db_path, 1001)
    assert processor.ingest_local_artifacts([artifact_root]) == 1
    summary = processor.process()

    con = sqlite3.connect(db_path)
    try:
        seeds = {
            (row[0], row[1])
            for row in con.execute(
                """
                SELECT seed_value, seed_type
                FROM engagement_seeds
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
        metadata_by_seed = {
            (row[0], row[1]): json.loads(row[2])
            for row in con.execute(
                """
                SELECT seed_value, seed_type, metadata_json
                FROM engagement_seeds
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
    finally:
        con.close()

    assert summary.processed == 1
    assert ("Alice Example", "name") in seeds
    assert ("Acme Corp", "company") in seeds
    assert ("Incident Commander", "other") not in seeds
    assert ("Bob Noise", "name") not in seeds
    assert ("Noise Corp", "company") not in seeds
    assert metadata_by_seed[("Alice Example", "name")]["artifact_contact_identity"] is True
    assert metadata_by_seed[("Alice Example", "name")]["contact_field"] == "fn"
    assert metadata_by_seed[("Alice Example", "name")]["contact_title"] == "Incident Commander"
    assert metadata_by_seed[("Acme Corp", "company")]["contact_field"] == "org"
    assert metadata_by_seed[("Acme Corp", "company")]["contact_title"] == "Incident Commander"


def test_calendar_contact_identity_ignores_summary_description_and_cn_only(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_calendar_noise"
    artifact_root.mkdir()
    bootstrap_engagement(db_path, name="Artifact Calendar Identity Negative Test")

    (artifact_root / "meeting.ics").write_text(
        dedent(
            """
            BEGIN:VCALENDAR
            VERSION:2.0
            BEGIN:VEVENT
            SUMMARY:Review with Bob Noise
            DESCRIPTION:Noise Corp and Carol Example are mentioned here only
            ORGANIZER;CN=Calendar Owner:mailto:owner@example.acme
            END:VEVENT
            END:VCALENDAR
            """
        ).strip(),
        encoding="utf-8",
    )

    processor = ArtifactQueueProcessor(db_path, 1001)
    assert processor.ingest_local_artifacts([artifact_root]) == 1
    summary = processor.process()

    con = sqlite3.connect(db_path)
    try:
        seeds = {
            (row[0], row[1])
            for row in con.execute(
                """
                SELECT seed_value, seed_type
                FROM engagement_seeds
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
    finally:
        con.close()

    assert summary.processed == 1
    assert ("owner@example.acme", "email") in seeds
    assert ("Bob Noise", "name") not in seeds
    assert ("Carol Example", "name") not in seeds
    assert ("Calendar Owner", "name") not in seeds
    assert ("Noise Corp", "company") not in seeds
