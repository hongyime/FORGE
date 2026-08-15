from __future__ import annotations

import json
import hashlib
import sqlite3
from pathlib import Path

import pytest

from forge.audit.manifest import canonical_json, verify_run_audit_manifest
from forge.audit.review import audit_review_summary, list_audit_reviews, record_audit_review
from forge.db.migrations import run_migrations
from forge.db.schema import apply_schema
from forge.engagement_orchestrator import EngagementRunTracker


def _bootstrap(db_path: Path) -> None:
    con = sqlite3.connect(db_path)
    try:
        apply_schema(con)
        run_migrations(con)
        con.execute(
            """
            INSERT INTO engagements (id, name, scope_json, status, operator)
            VALUES (1001, 'Acme Example', '["acme.example"]', 'ACTIVE', 'delta-one')
            """
        )
        con.commit()
    finally:
        con.close()


def _write_report(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("# Report\n", encoding="utf-8")


def _finished_run(db_path: Path, report_path: Path) -> tuple[int, str]:
    tracker = EngagementRunTracker(db_path, 1001)
    handle = tracker.start_run(run_kind="kill_chain", metadata={"phase": "start"})
    tracker.finish_run(
        handle,
        status="completed",
        metadata={"phase": "completed", "report_path": str(report_path)},
    )
    con = sqlite3.connect(db_path)
    try:
        row = con.execute(
            """
            SELECT manifest_hash
            FROM run_audit_manifests
            WHERE engagement_id=1001 AND run_id=?
            """,
            (handle.run_id,),
        ).fetchone()
    finally:
        con.close()
    assert row is not None
    return handle.run_id, str(row[0])


def _rewrite_manifest_without_audit_review_exclusion(db_path: Path, run_id: int) -> str:
    con = sqlite3.connect(db_path)
    try:
        row = con.execute(
            """
            SELECT manifest_json
            FROM run_audit_manifests
            WHERE engagement_id=1001 AND run_id=?
            """,
            (run_id,),
        ).fetchone()
        assert row is not None
        payload = json.loads(str(row[0]))
        payload["database"]["excluded_tables"] = [
            item
            for item in payload["database"].get("excluded_tables", [])
            if item.get("table") != "audit_reviews"
        ]
        manifest_json = canonical_json(payload)
        manifest_hash = hashlib.sha256(manifest_json.encode("utf-8")).hexdigest()
        con.execute(
            """
            UPDATE run_audit_manifests
            SET manifest_json=?, manifest_hash=?
            WHERE engagement_id=1001 AND run_id=?
            """,
            (manifest_json, manifest_hash, run_id),
        )
        con.commit()
    finally:
        con.close()
    return manifest_hash


def test_audit_review_records_scrub_attestation_and_do_not_break_manifest(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.db"
    report_path = tmp_path / "reports" / "engagement_1001_report.md"
    _write_report(report_path)
    _bootstrap(db_path)
    run_id, manifest_hash = _finished_run(db_path, report_path)
    manifest_hash = _rewrite_manifest_without_audit_review_exclusion(db_path, run_id)

    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        review = record_audit_review(
            con,
            engagement_id=1001,
            run_id=run_id,
            manifest_hash=manifest_hash,
            review_status="attested",
            reviewer="auditor@example.com",
            comment="Reviewed evidence bundle.",
            attestation={
                "checklist": "ok",
                "api_token": "secret-token",
                "nested": {"password": "secret-password"},
            },
            legal_hold=True,
        )
        assert review["review_status"] == "attested"
        assert review["manifest_hash"] == manifest_hash
        assert review["attestation"]["api_token"] == "[redacted]"
        assert review["attestation"]["nested"]["password"] == "[redacted]"
        assert review["legal_hold"] is True

        summary = audit_review_summary(
            con,
            engagement_id=1001,
            run_id=run_id,
            manifest_hash=manifest_hash,
        )
        assert summary["present"] is True
        assert summary["review_status"] == "attested"
        assert summary["legal_hold"] is True
        assert summary["status_counts"]["attested"] == 1
        assert list_audit_reviews(con, engagement_id=1001)[0]["id"] == review["id"]

        audit_row = con.execute(
            """
            SELECT result
            FROM audit_log
            WHERE engagement_id=1001 AND module='audit_review'
            ORDER BY id DESC
            LIMIT 1
            """
        ).fetchone()
        assert audit_row is not None
        assert "secret-token" not in str(audit_row["result"])
        assert "status=attested" in str(audit_row["result"])

        verification = verify_run_audit_manifest(
            con,
            db_path=db_path,
            engagement_id=1001,
            run_id=run_id,
        )
        assert verification.ok is True

        stored = con.execute("SELECT attestation_json FROM audit_reviews").fetchone()
        assert stored is not None
        assert "secret-token" not in str(stored["attestation_json"])
        assert json.loads(str(stored["attestation_json"]))["api_token"] == "[redacted]"
    finally:
        con.close()


def test_audit_review_rejects_invalid_status_and_manifest_mismatch(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.db"
    report_path = tmp_path / "reports" / "engagement_1001_report.md"
    _write_report(report_path)
    _bootstrap(db_path)
    run_id, _manifest_hash = _finished_run(db_path, report_path)

    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        with pytest.raises(ValueError, match="review_status"):
            record_audit_review(
                con,
                engagement_id=1001,
                run_id=run_id,
                review_status="done",
                reviewer="auditor@example.com",
            )
        with pytest.raises(ValueError, match="manifest_hash"):
            record_audit_review(
                con,
                engagement_id=1001,
                run_id=run_id,
                manifest_hash="0" * 64,
                review_status="approved",
                reviewer="auditor@example.com",
            )
        with pytest.raises(LookupError, match="engagement run not found"):
            record_audit_review(
                con,
                engagement_id=1001,
                run_id=999,
                review_status="approved",
                reviewer="auditor@example.com",
            )
    finally:
        con.close()
