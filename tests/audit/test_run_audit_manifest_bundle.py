from __future__ import annotations

import hashlib
import json
import sqlite3
import zipfile
from pathlib import Path

from forge.audit.manifest_bundle import export_run_audit_manifest_bundle
from forge.db.migrations import run_migrations
from forge.db.schema import apply_schema
from forge.engagement_orchestrator import EngagementRunTracker


def _bootstrap(db_path: Path) -> int:
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
    tracker = EngagementRunTracker(db_path, 1001)
    handle = tracker.start_run(run_kind="kill_chain")
    tracker.finish_run(handle, status="completed")
    return handle.run_id


def test_manifest_bundle_exports_receipt_without_raw_rows(tmp_path: Path) -> None:
    db_path = tmp_path / "1001.db"
    run_id = _bootstrap(db_path)
    out_path = tmp_path / "manifest.zip"

    con = sqlite3.connect(db_path)
    try:
        bundle = export_run_audit_manifest_bundle(
            con,
            db_path=db_path,
            engagement_id=1001,
            run_id=run_id,
            output_path=out_path,
            exported_at="2026-07-20T02:00:00+00:00",
        )
    finally:
        con.close()

    assert bundle.path == out_path
    assert bundle.verification_ok is True
    assert bundle.files == ("README.md", "checksums.sha256", "manifest.json", "verification.json")
    with zipfile.ZipFile(out_path) as archive:
        assert sorted(archive.namelist()) == list(bundle.files)
        assert {info.date_time for info in archive.infolist()} == {(1980, 1, 1, 0, 0, 0)}
        manifest_bytes = archive.read("manifest.json")
        verification = json.loads(archive.read("verification.json"))
        checksums = archive.read("checksums.sha256").decode("utf-8")
        archive_text = "\n".join(
            archive.read(name).decode("utf-8", errors="replace") for name in archive.namelist()
        )

    assert bundle.bundle_sha256 == hashlib.sha256(out_path.read_bytes()).hexdigest()
    assert bundle.manifest_hash == hashlib.sha256(manifest_bytes).hexdigest()
    assert verification["schema"] == "forge.run_audit_manifest_bundle.v1"
    assert verification["verification"]["ok"] is True
    assert verification["manifest_hash"] == bundle.manifest_hash
    assert f"{hashlib.sha256(manifest_bytes).hexdigest()}  manifest.json" in checksums
    assert "manifest_json" not in archive_text
    assert "Acme Example" not in archive_text
    assert "acme.example" not in archive_text
    assert str(db_path) not in archive_text


def test_manifest_bundle_exports_failed_verification_receipt(tmp_path: Path) -> None:
    db_path = tmp_path / "1001.db"
    run_id = _bootstrap(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.execute("UPDATE engagements SET scope_json='[\"evil.example\"]' WHERE id=1001")
        con.commit()
        bundle = export_run_audit_manifest_bundle(
            con,
            db_path=db_path,
            engagement_id=1001,
            run_id=run_id,
            output_path=tmp_path / "tampered.zip",
            exported_at="2026-07-20T02:05:00+00:00",
        )
    finally:
        con.close()

    assert bundle.verification_ok is False
    with zipfile.ZipFile(bundle.path) as archive:
        verification = json.loads(archive.read("verification.json"))
    assert verification["verification"]["ok"] is False
    assert verification["verification"]["reason"] == "manifest hash mismatch"
