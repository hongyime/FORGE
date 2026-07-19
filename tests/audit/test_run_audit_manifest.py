from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

from forge.audit.manifest import (
    GENESIS_HASH,
    canonical_json,
    summarize_run_audit_manifest,
    verify_run_audit_manifest,
)
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


def _manifest_row(db_path: Path, run_id: int) -> tuple[str, str]:
    con = sqlite3.connect(db_path)
    try:
        row = con.execute(
            """
            SELECT manifest_json, manifest_hash
            FROM run_audit_manifests
            WHERE engagement_id=1001 AND run_id=?
            """,
            (run_id,),
        ).fetchone()
    finally:
        con.close()
    assert row is not None
    return str(row[0]), str(row[1])


def test_engagement_finish_writes_manifest_without_secret_material(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    report_path = tmp_path / "reports" / "engagement_1001_report.md"
    report_path.parent.mkdir()
    report_path.write_text("# Report\n", encoding="utf-8")
    _bootstrap(db_path)

    tracker = EngagementRunTracker(db_path, 1001)
    handle = tracker.start_run(run_kind="kill_chain", metadata={"phase": "start"})

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO audit_log (engagement_id, phase, module, action, target, result)
            VALUES (1001, 'phase4', 'cloud_validate', 'validated', 'firebase', 'real-data')
            """
        )
        con.execute(
            """
            INSERT INTO key_scanner_findings
                (engagement_id, domain, service, pattern_name, source_url, key_redacted, key_enc)
            VALUES
                (1001, 'acme.example', 'firebase', 'firebase_api_key',
                 'https://repo.example/config.js', 'AIza...abcd', 'super-secret-value')
            """
        )
        con.commit()
    finally:
        con.close()

    tracker.finish_run(
        handle,
        status="completed",
        metadata={"phase": "completed", "report_path": str(report_path)},
    )

    manifest_json, manifest_hash = _manifest_row(db_path, handle.run_id)
    payload = json.loads(manifest_json)

    assert payload["previous_manifest_hash"] == GENESIS_HASH
    assert hashlib.sha256(manifest_json.encode("utf-8")).hexdigest() == manifest_hash
    assert hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest() == manifest_hash
    assert "super-secret-value" not in manifest_json
    assert "key_enc" not in manifest_json
    assert any(table["table"] == "engagements" for table in payload["database"]["tables"])
    artifact_hashes = {artifact["sha256"] for artifact in payload["artifacts"]}
    assert hashlib.sha256(report_path.read_bytes()).hexdigest() in artifact_hashes

    con = sqlite3.connect(db_path)
    try:
        result = verify_run_audit_manifest(
            con,
            db_path=db_path,
            engagement_id=1001,
            run_id=handle.run_id,
        )
    finally:
        con.close()
    assert result.ok is True


def test_manifest_summary_is_dashboard_safe_and_verifies(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap(db_path)
    tracker = EngagementRunTracker(db_path, 1001)
    handle = tracker.start_run(run_kind="kill_chain")
    tracker.finish_run(handle, status="completed")

    con = sqlite3.connect(db_path)
    try:
        summary = summarize_run_audit_manifest(
            con,
            db_path=db_path,
            engagement_id=1001,
            run_id=handle.run_id,
        )
        unchecked = summarize_run_audit_manifest(
            con,
            db_path=db_path,
            engagement_id=1001,
            run_id=handle.run_id,
            verify=False,
        )
    finally:
        con.close()

    assert summary["present"] is True
    assert summary["verified"] is True
    assert summary["verification_status"] == "verified"
    assert summary["previous_manifest_hash"] == GENESIS_HASH
    assert summary["short_hash"] == summary["manifest_hash"][:12]
    assert "manifest_json" not in summary
    assert unchecked["verification_status"] == "not_checked"
    assert unchecked["verified"] is False


def test_manifest_summary_handles_tamper_missing_and_old_schema(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap(db_path)
    tracker = EngagementRunTracker(db_path, 1001)
    handle = tracker.start_run(run_kind="kill_chain")
    tracker.finish_run(handle, status="completed")

    con = sqlite3.connect(db_path)
    try:
        missing = summarize_run_audit_manifest(
            con,
            db_path=db_path,
            engagement_id=1001,
            run_id=9999,
        )
        con.execute("UPDATE engagements SET operator='tampered' WHERE id=1001")
        con.commit()
        tampered = summarize_run_audit_manifest(
            con,
            db_path=db_path,
            engagement_id=1001,
            run_id=handle.run_id,
        )
    finally:
        con.close()

    old_schema = sqlite3.connect(":memory:")
    try:
        old = summarize_run_audit_manifest(
            old_schema,
            db_path=None,
            engagement_id=1001,
            run_id=handle.run_id,
        )
    finally:
        old_schema.close()

    assert missing["present"] is False
    assert missing["verification_status"] == "missing"
    assert tampered["present"] is True
    assert tampered["verified"] is False
    assert tampered["verification_status"] == "failed"
    assert tampered["reason"] == "manifest hash mismatch"
    assert old["present"] is False
    assert old["verification_status"] == "unavailable"


def test_run_manifests_chain_and_detect_db_tamper(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap(db_path)
    tracker = EngagementRunTracker(db_path, 1001)

    first = tracker.start_run(run_kind="kill_chain")
    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO audit_log (engagement_id, phase, module, action, target, result)
            VALUES (1001, 'phase1', 'orchestrator', 'started', 'acme.example', 'ok')
            """
        )
        con.commit()
    finally:
        con.close()
    tracker.finish_run(first, status="completed")
    _first_json, first_hash = _manifest_row(db_path, first.run_id)

    second = tracker.start_run(run_kind="kill_chain")
    tracker.finish_run(second, status="completed")
    second_json, _second_hash = _manifest_row(db_path, second.run_id)
    assert json.loads(second_json)["previous_manifest_hash"] == first_hash

    con = sqlite3.connect(db_path)
    try:
        unchanged = verify_run_audit_manifest(
            con,
            db_path=db_path,
            engagement_id=1001,
            run_id=first.run_id,
        )
        assert unchanged.ok is True

        con.execute(
            "UPDATE audit_log SET result='tampered' WHERE engagement_id=1001 AND action='started'"
        )
        con.commit()
        result = verify_run_audit_manifest(
            con,
            db_path=db_path,
            engagement_id=1001,
            run_id=first.run_id,
        )
    finally:
        con.close()
    assert result.ok is False
    assert result.reason == "manifest hash mismatch"


def test_manifest_verifier_rejects_manifest_json_tamper(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap(db_path)
    tracker = EngagementRunTracker(db_path, 1001)
    handle = tracker.start_run(run_kind="kill_chain")
    tracker.finish_run(handle, status="completed")

    manifest_json, _manifest_hash = _manifest_row(db_path, handle.run_id)
    payload = json.loads(manifest_json)
    payload["database"]["name"] = "tampered.db"

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            UPDATE run_audit_manifests
            SET manifest_json=?
            WHERE engagement_id=1001 AND run_id=?
            """,
            (canonical_json(payload), handle.run_id),
        )
        con.commit()
        result = verify_run_audit_manifest(
            con,
            db_path=db_path,
            engagement_id=1001,
            run_id=handle.run_id,
        )
    finally:
        con.close()

    assert result.ok is False
    assert result.reason == "stored manifest_json hash mismatch"


def test_manifest_verifier_detects_engagement_metadata_tamper(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap(db_path)
    tracker = EngagementRunTracker(db_path, 1001)
    handle = tracker.start_run(run_kind="kill_chain")
    tracker.finish_run(handle, status="completed")

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            "UPDATE engagements SET scope_json='[\"evil.example\"]' WHERE id=1001"
        )
        con.commit()
        result = verify_run_audit_manifest(
            con,
            db_path=db_path,
            engagement_id=1001,
            run_id=handle.run_id,
        )
    finally:
        con.close()

    assert result.ok is False
    assert result.reason == "manifest hash mismatch"


def test_manifest_ignores_report_path_outside_reports_dir(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    private_report = tmp_path / "private" / "engagement_1001_report.md"
    private_report.parent.mkdir()
    private_report.write_text("private content\n", encoding="utf-8")
    _bootstrap(db_path)

    tracker = EngagementRunTracker(db_path, 1001)
    handle = tracker.start_run(run_kind="kill_chain")
    tracker.finish_run(
        handle,
        status="completed",
        metadata={"report_path": str(private_report)},
    )

    manifest_json, _manifest_hash = _manifest_row(db_path, handle.run_id)
    payload = json.loads(manifest_json)

    assert payload["artifacts"] == []
    assert "private" not in manifest_json
    assert str(private_report) not in manifest_json
