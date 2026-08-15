import json
import sqlite3
from pathlib import Path
from typing import Any

from forge.reporting.audit_manifest_artifacts import (
    AuditManifestArtifactCallbacks,
    audit_files,
    engagement_prefixed_artifact_files,
    materialize_audit_manifest_artifacts,
    report_files,
)


def _write(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("artifact", encoding="utf-8")
    return path


def test_audit_and_report_files_keep_engagement_prefix_boundary(tmp_path: Path) -> None:
    reports_dir = tmp_path / "reports"
    expected_audit = [
        _write(reports_dir / "audit_1001.csv"),
        _write(reports_dir / "audit_1001.json"),
        _write(reports_dir / "audit_1001_run_7_abc123.json"),
        _write(reports_dir / "audit_1001.md"),
        _write(reports_dir / "audit_1001.pdf"),
    ]
    expected_report = [
        _write(reports_dir / "engagement_1001.csv"),
        _write(reports_dir / "engagement_1001.html"),
        _write(reports_dir / "engagement_1001.json"),
        _write(reports_dir / "engagement_1001.md"),
        _write(reports_dir / "engagement_1001.pdf"),
    ]
    _write(reports_dir / "audit_10010.json")
    _write(reports_dir / "audit_1001.html")
    _write(reports_dir / "engagement_10010.md")
    _write(reports_dir / "engagement_1001.graphml")

    assert audit_files("1001", reports_dir) == expected_audit
    assert report_files("1001", reports_dir) == expected_report


def test_materialize_audit_manifest_artifacts_returns_existing_without_manifest_table(
    tmp_path: Path,
) -> None:
    reports_dir = tmp_path / "reports"
    existing = _write(reports_dir / "audit_1001_existing.json")
    con = sqlite3.connect(":memory:")

    try:
        assert materialize_audit_manifest_artifacts(
            con,
            db_path=tmp_path / "1001.db",
            reports_dir=reports_dir,
            engagement_id=1001,
            verify=True,
        ) == [existing]
    finally:
        con.close()


def test_materialize_audit_manifest_artifacts_writes_summary_artifacts(
    tmp_path: Path,
) -> None:
    reports_dir = tmp_path / "reports"
    existing = _write(reports_dir / "audit_1001_existing.json")
    calls: list[dict[str, Any]] = []
    con = sqlite3.connect(":memory:")

    def summarize_manifest(
        _con: sqlite3.Connection,
        *,
        db_path: Path,
        engagement_id: int,
        run_id: int,
        verify: bool,
    ) -> dict[str, Any]:
        calls.append(
            {
                "db_path": db_path,
                "engagement_id": engagement_id,
                "run_id": run_id,
                "verify": verify,
            }
        )
        if run_id == 8:
            return {"present": False}
        return {
            "present": True,
            "verified": True,
            "verification_status": "verified",
            "manifest_hash": "abcdef1234567890",
            "short_hash": "abcdef123456",
            "generated_at": "2026-08-13T10:00:00+08:00",
        }

    callbacks = AuditManifestArtifactCallbacks(
        table_exists=lambda _con, table: table == "run_audit_manifests",
        fetch_rows=lambda *_args: [
            {"id": 3, "run_id": 8},
            {"id": 2, "run_id": 0},
            {"id": 1, "run_id": 7},
        ],
        summarize_run_audit_manifest=summarize_manifest,
    )

    try:
        artifacts = materialize_audit_manifest_artifacts(
            con,
            db_path=tmp_path / "1001.db",
            reports_dir=reports_dir,
            engagement_id=1001,
            verify=False,
            callbacks=callbacks,
        )
    finally:
        con.close()

    materialized = reports_dir / "audit_1001_run_7_abcdef123456.json"
    assert artifacts == [existing, materialized]
    assert [call["run_id"] for call in calls] == [8, 7]
    assert all(call["verify"] is False for call in calls)

    payload = json.loads(materialized.read_text(encoding="utf-8"))
    assert payload == {
        "schema": "forge.run_audit_manifest_summary.v1",
        "engagement_id": 1001,
        "run_id": 7,
        "present": True,
        "verified": True,
        "verification_status": "verified",
        "manifest_hash": "abcdef1234567890",
        "short_hash": "abcdef123456",
        "generated_at": "2026-08-13T10:00:00+08:00",
    }


def test_dashboard_audit_artifact_wrappers_preserve_module_output(
    tmp_path: Path,
) -> None:
    from forge.reporting.dashboard import (
        _artifact_files,
        _audit_files,
        _engagement_prefixed_artifact_files,
    )

    reports_dir = tmp_path / "reports"
    _write(reports_dir / "engagement_1001.md")
    _write(reports_dir / "audit_1001.json")

    assert _artifact_files("1001", reports_dir) == report_files("1001", reports_dir)
    assert _audit_files("1001", reports_dir) == audit_files("1001", reports_dir)
    assert _engagement_prefixed_artifact_files(
        reports_dir,
        prefix="audit",
        engagement_id="1001",
        suffixes=(".json",),
    ) == engagement_prefixed_artifact_files(
        reports_dir,
        prefix="audit",
        engagement_id="1001",
        suffixes=(".json",),
    )
