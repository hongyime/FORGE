from __future__ import annotations

import json
import sqlite3
import zipfile
from pathlib import Path

from typer.testing import CliRunner

from forge.cli import app
from forge.db.migrations import run_migrations
from forge.db.schema import apply_schema
from forge.engagement_orchestrator import EngagementRunTracker


def _bootstrap_cli_db(data_dir: Path) -> tuple[Path, int]:
    db_root = data_dir / "engagements"
    db_root.mkdir(parents=True)
    db_path = db_root / "1001.db"
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
    return db_path, handle.run_id


def test_audit_manifest_verify_cli_reports_ok_and_tamper(
    tmp_path: Path,
    monkeypatch,
) -> None:
    data_dir = tmp_path / ".forge_data"
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FORGE_DATA_DIR", str(data_dir))
    monkeypatch.setenv("FORGE_ENV", "test")
    db_path, run_id = _bootstrap_cli_db(data_dir)
    runner = CliRunner()

    ok = runner.invoke(
        app,
        ["audit", "manifest-verify", "--engagement", "1001", "--json"],
    )
    assert ok.exit_code == 0, ok.output
    ok_payload = json.loads(ok.output)
    assert ok_payload["schema_version"] == "forge.audit.manifest_verify.v1"
    assert ok_payload["execution_policy"] == "read_only_audit_manifest_verification_no_writes"
    assert ok_payload["total_count"] == 1
    assert ok_payload["selected_count"] == 1
    assert ok_payload["omitted_count"] == 0
    assert ok_payload["engagement_id"] == 1001
    assert ok_payload["run_id"] == run_id
    assert ok_payload["ok"] is True
    assert ok_payload["stored_hash"] == ok_payload["recomputed_hash"]

    export_path = tmp_path / "manifest-export.zip"
    exported = runner.invoke(
        app,
        [
            "audit",
            "manifest-export",
            "--engagement",
            "1001",
            "--run-id",
            str(run_id),
            "--output",
            str(export_path),
            "--json",
        ],
    )
    assert exported.exit_code == 0, exported.output
    export_payload = json.loads(exported.output)
    assert export_payload["engagement_id"] == 1001
    assert export_payload["run_id"] == run_id
    assert export_payload["path"] == str(export_path)
    assert export_payload["verification_ok"] is True
    assert export_payload["manifest_hash"] == ok_payload["stored_hash"]
    with zipfile.ZipFile(export_path) as archive:
        assert sorted(archive.namelist()) == [
            "README.md",
            "checksums.sha256",
            "manifest.json",
            "verification.json",
        ]
        receipt = json.loads(archive.read("verification.json"))
    assert receipt["verification"]["ok"] is True

    signed_path = tmp_path / "manifest-signed.zip"
    monkeypatch.setenv("FORGE_TEST_MANIFEST_SIGNING_KEY", "cli-signing-key")
    signed = runner.invoke(
        app,
        [
            "audit",
            "manifest-export",
            "--engagement",
            "1001",
            "--run-id",
            str(run_id),
            "--output",
            str(signed_path),
            "--sign",
            "--signing-key-env",
            "FORGE_TEST_MANIFEST_SIGNING_KEY",
            "--signer-id",
            "cli-test",
            "--json",
        ],
    )
    assert signed.exit_code == 0, signed.output
    signed_payload = json.loads(signed.output)
    assert signed_payload["signature_present"] is True
    assert "signature.json" in signed_payload["files"]
    with zipfile.ZipFile(signed_path) as archive:
        signature = json.loads(archive.read("signature.json"))
    assert signature["algorithm"] == "HMAC-SHA256"
    assert signature["signer_id"] == "cli-test"

    remote_root = tmp_path / "remote-audit"
    remote_path = tmp_path / "manifest-remote.zip"
    monkeypatch.setenv("FORGE_TEST_AUDIT_REMOTE_URI", str(remote_root))
    monkeypatch.setenv("FORGE_TEST_AUDIT_REMOTE_SCOPE", "customer-acme")
    remote_export = runner.invoke(
        app,
        [
            "audit",
            "manifest-export",
            "--engagement",
            "1001",
            "--run-id",
            str(run_id),
            "--output",
            str(remote_path),
            "--remote-store",
            "--remote-uri-env",
            "FORGE_TEST_AUDIT_REMOTE_URI",
            "--remote-scope-env",
            "FORGE_TEST_AUDIT_REMOTE_SCOPE",
            "--json",
        ],
    )
    assert remote_export.exit_code == 0, remote_export.output
    remote_payload = json.loads(remote_export.output)
    assert remote_payload["remote_store"]["scope"] == "customer-acme"
    stored_path = Path(remote_payload["remote_store"]["storage_path"])
    receipt_path = Path(remote_payload["remote_store"]["receipt_path"])
    assert stored_path.is_file()
    assert receipt_path.is_file()
    assert stored_path.read_bytes() == remote_path.read_bytes()
    assert str(stored_path).startswith(str(remote_root))
    assert "FORGE_TEST_AUDIT_REMOTE_URI" not in json.dumps(remote_payload)

    missing_remote = runner.invoke(
        app,
        [
            "audit",
            "manifest-export",
            "--engagement",
            "1001",
            "--run-id",
            str(run_id),
            "--remote-store",
            "--remote-uri-env",
            "FORGE_MISSING_AUDIT_REMOTE_URI",
            "--remote-scope-env",
            "FORGE_MISSING_AUDIT_REMOTE_SCOPE",
        ],
    )
    assert missing_remote.exit_code == 1
    assert "remote audit bundle storage is not configured" in missing_remote.output

    verify_signed = runner.invoke(
        app,
        [
            "audit",
            "manifest-bundle-verify",
            "--bundle",
            str(signed_path),
            "--signing-key-env",
            "FORGE_TEST_MANIFEST_SIGNING_KEY",
            "--json",
        ],
    )
    assert verify_signed.exit_code == 0, verify_signed.output
    verify_payload = json.loads(verify_signed.output)
    assert verify_payload["schema_version"] == "forge.audit.manifest_bundle_verify.v1"
    assert (
        verify_payload["execution_policy"]
        == "read_only_audit_bundle_signature_verification_no_writes"
    )
    assert verify_payload["total_count"] == 1
    assert verify_payload["selected_count"] == 1
    assert verify_payload["omitted_count"] == 0
    assert verify_payload["ok"] is True
    assert verify_payload["signer_id"] == "cli-test"

    monkeypatch.setenv("FORGE_TEST_MANIFEST_SIGNING_KEY", "wrong-key")
    verify_wrong_key = runner.invoke(
        app,
        [
            "audit",
            "manifest-bundle-verify",
            "--bundle",
            str(signed_path),
            "--signing-key-env",
            "FORGE_TEST_MANIFEST_SIGNING_KEY",
            "--json",
        ],
    )
    assert verify_wrong_key.exit_code == 2, verify_wrong_key.output
    wrong_key_payload = json.loads(verify_wrong_key.output)
    assert wrong_key_payload["schema_version"] == "forge.audit.manifest_bundle_verify.v1"
    assert wrong_key_payload["selected_count"] == 1
    assert wrong_key_payload["reason"] == "signature mismatch"

    missing_key = runner.invoke(
        app,
        [
            "audit",
            "manifest-export",
            "--engagement",
            "1001",
            "--run-id",
            str(run_id),
            "--sign",
            "--signing-key-env",
            "FORGE_MISSING_MANIFEST_SIGNING_KEY",
        ],
    )
    assert missing_key.exit_code == 1
    assert "signing key env var is not set" in missing_key.output

    con = sqlite3.connect(db_path)
    try:
        con.execute("UPDATE engagements SET scope_json='[\"evil.example\"]' WHERE id=1001")
        con.commit()
    finally:
        con.close()

    tampered = runner.invoke(
        app,
        ["audit", "manifest-verify", "--engagement", "1001", "--run-id", str(run_id), "--json"],
    )
    assert tampered.exit_code == 2, tampered.output
    tampered_payload = json.loads(tampered.output)
    assert tampered_payload["schema_version"] == "forge.audit.manifest_verify.v1"
    assert tampered_payload["selected_count"] == 1
    assert tampered_payload["ok"] is False
    assert tampered_payload["reason"] == "manifest hash mismatch"
