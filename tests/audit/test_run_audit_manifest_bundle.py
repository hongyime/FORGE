from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import warnings
import zipfile
from pathlib import Path

from forge.audit.manifest_bundle import (
    export_run_audit_manifest_bundle,
    verify_run_audit_manifest_bundle_signature,
)
from forge.audit.remote_storage import (
    parse_remote_store,
    store_audit_manifest_bundle_remote,
)
from forge.db.migrations import run_migrations
from forge.db.schema import apply_schema
from forge.engagement_orchestrator import EngagementRunTracker


def _write_report_family(primary_path: Path) -> None:
    primary_path.parent.mkdir(parents=True, exist_ok=True)
    for suffix, content in {
        ".md": "# Report\n",
        ".json": '{"report": true}\n',
        ".pdf": "%PDF-1.4\n",
        ".html": "<!doctype html><title>Report</title>\n",
        ".csv": "section,value\nsummary,ok\n",
    }.items():
        primary_path.with_suffix(suffix).write_text(content, encoding="utf-8")


def _bootstrap(db_path: Path) -> int:
    report_path = db_path.parent / "reports" / "engagement_1001_report.md"
    _write_report_family(report_path)
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
    tracker.finish_run(handle, status="completed", metadata={"report_path": str(report_path)})
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
        manifest = json.loads(manifest_bytes)
        verification = json.loads(archive.read("verification.json"))
        checksums = archive.read("checksums.sha256").decode("utf-8")
        archive_text = "\n".join(
            archive.read(name).decode("utf-8", errors="replace") for name in archive.namelist()
        )

    assert bundle.bundle_sha256 == hashlib.sha256(out_path.read_bytes()).hexdigest()
    assert bundle.manifest_hash == hashlib.sha256(manifest_bytes).hexdigest()
    assert verification["schema"] == "forge.run_audit_manifest_bundle.v1"
    assert verification["verification"]["ok"] is True
    assert {artifact["path"] for artifact in manifest["artifacts"]} >= {
        "engagement_1001_report.md",
        "engagement_1001_report.json",
        "engagement_1001_report.pdf",
        "engagement_1001_report.html",
        "engagement_1001_report.csv",
    }
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


def test_manifest_bundle_can_include_hmac_signature(tmp_path: Path) -> None:
    db_path = tmp_path / "1001.db"
    run_id = _bootstrap(db_path)

    con = sqlite3.connect(db_path)
    try:
        bundle = export_run_audit_manifest_bundle(
            con,
            db_path=db_path,
            engagement_id=1001,
            run_id=run_id,
            output_path=tmp_path / "signed.zip",
            exported_at="2026-07-20T02:10:00+00:00",
            signing_key="test-signing-key",
            signer_id="ci-test",
            signed_at="2026-07-20T02:11:00+00:00",
        )
    finally:
        con.close()

    assert bundle.signature_present is True
    assert bundle.files == (
        "README.md",
        "checksums.sha256",
        "manifest.json",
        "signature.json",
        "verification.json",
    )
    with zipfile.ZipFile(bundle.path) as archive:
        signature = json.loads(archive.read("signature.json"))
        signed_files = {
            name: hashlib.sha256(archive.read(name)).hexdigest()
            for name in ("README.md", "checksums.sha256", "manifest.json", "verification.json")
        }

    assert signature["schema"] == "forge.run_audit_manifest_signature.v1"
    assert signature["algorithm"] == "HMAC-SHA256"
    assert signature["signer_id"] == "ci-test"
    assert signature["signed_files"] == signed_files
    expected_payload = {
        key: signature[key]
        for key in ("algorithm", "schema", "signed_at", "signed_files", "signer_id")
    }
    expected_signature = hmac.new(
        b"test-signing-key",
        json.dumps(
            expected_payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    assert signature["signature"] == expected_signature

    verified = verify_run_audit_manifest_bundle_signature(
        bundle.path,
        signing_key="test-signing-key",
    )
    assert verified.ok is True
    assert verified.signer_id == "ci-test"


def test_manifest_bundle_remote_store_is_scoped_append_only(tmp_path: Path) -> None:
    db_path = tmp_path / "1001.db"
    run_id = _bootstrap(db_path)
    out_path = tmp_path / "signed.zip"
    remote_root = tmp_path / "remote-store"

    con = sqlite3.connect(db_path)
    try:
        bundle = export_run_audit_manifest_bundle(
            con,
            db_path=db_path,
            engagement_id=1001,
            run_id=run_id,
            output_path=out_path,
            exported_at="2026-07-20T02:12:00+00:00",
            signing_key="test-signing-key",
        )
    finally:
        con.close()

    store = parse_remote_store(str(remote_root), scope="customer-acme")
    receipt = store_audit_manifest_bundle_remote(
        bundle,
        engagement_id=1001,
        run_id=run_id,
        store=store,
        stored_at="2026-07-20T02:13:00+00:00",
    )

    assert receipt.already_present is False
    assert receipt.receipt_already_present is False
    assert receipt.storage_path.is_file()
    assert receipt.receipt_path.is_file()
    assert receipt.storage_path.read_bytes() == out_path.read_bytes()
    assert receipt.storage_path.parent == remote_root / "customer-acme" / "engagement_1001" / f"run_{run_id}"
    receipt_payload = json.loads(receipt.receipt_path.read_text(encoding="utf-8"))
    assert receipt_payload["schema"] == "forge.run_audit_manifest_remote_store.v1"
    assert receipt_payload["append_only"] is True
    assert receipt_payload["bundle_sha256"] == bundle.bundle_sha256
    assert "manifest_json" not in receipt.receipt_path.read_text(encoding="utf-8")

    second_receipt = store_audit_manifest_bundle_remote(
        bundle,
        engagement_id=1001,
        run_id=run_id,
        store=store,
        stored_at="2026-07-20T02:14:00+00:00",
    )
    assert second_receipt.already_present is True
    assert second_receipt.receipt_already_present is True

    receipt.storage_path.write_bytes(b"tampered\n")
    try:
        store_audit_manifest_bundle_remote(bundle, engagement_id=1001, run_id=run_id, store=store)
    except ValueError as exc:
        assert "different content" in str(exc)
    else:  # pragma: no cover - defensive assertion.
        raise AssertionError("expected append-only conflict")


def test_manifest_bundle_remote_store_rejects_unsafe_scope_and_uri(tmp_path: Path) -> None:
    assert parse_remote_store(str(tmp_path), scope="acme_01").scope == "acme_01"
    try:
        parse_remote_store("https://example.test/bucket", scope="acme")
    except ValueError as exc:
        assert "supports only file:// or mounted paths" in str(exc)
    else:  # pragma: no cover - defensive assertion.
        raise AssertionError("expected unsupported URI error")
    try:
        parse_remote_store(str(tmp_path), scope="../acme")
    except ValueError as exc:
        assert "scope must be" in str(exc)
    else:  # pragma: no cover - defensive assertion.
        raise AssertionError("expected unsafe scope error")


def test_manifest_bundle_signature_verifier_detects_tampered_payload(tmp_path: Path) -> None:
    db_path = tmp_path / "1001.db"
    run_id = _bootstrap(db_path)
    out_path = tmp_path / "signed.zip"

    con = sqlite3.connect(db_path)
    try:
        export_run_audit_manifest_bundle(
            con,
            db_path=db_path,
            engagement_id=1001,
            run_id=run_id,
            output_path=out_path,
            exported_at="2026-07-20T02:20:00+00:00",
            signing_key="test-signing-key",
        )
    finally:
        con.close()

    with zipfile.ZipFile(out_path) as archive:
        files = {name: archive.read(name) for name in archive.namelist()}
    files["README.md"] = b"tampered\n"
    with zipfile.ZipFile(out_path, mode="w", compression=zipfile.ZIP_STORED) as archive:
        for name, data in sorted(files.items()):
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_STORED
            archive.writestr(info, data)

    result = verify_run_audit_manifest_bundle_signature(
        out_path,
        signing_key="test-signing-key",
    )
    assert result.ok is False
    assert result.reason == "signed file hash mismatch: README.md"


def test_manifest_bundle_signature_verifier_rejects_unsigned_extra_files(tmp_path: Path) -> None:
    db_path = tmp_path / "1001.db"
    run_id = _bootstrap(db_path)
    out_path = tmp_path / "signed.zip"

    con = sqlite3.connect(db_path)
    try:
        export_run_audit_manifest_bundle(
            con,
            db_path=db_path,
            engagement_id=1001,
            run_id=run_id,
            output_path=out_path,
            signing_key="test-signing-key",
        )
    finally:
        con.close()

    with zipfile.ZipFile(out_path, mode="a", compression=zipfile.ZIP_STORED) as archive:
        info = zipfile.ZipInfo("unsigned.txt", (1980, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_STORED
        archive.writestr(info, b"not attested\n")

    result = verify_run_audit_manifest_bundle_signature(
        out_path,
        signing_key="test-signing-key",
    )
    assert result.ok is False
    assert result.reason == "unsigned zip entry: unsigned.txt"


def test_manifest_bundle_signature_verifier_rejects_duplicate_zip_entries(tmp_path: Path) -> None:
    db_path = tmp_path / "1001.db"
    run_id = _bootstrap(db_path)
    out_path = tmp_path / "signed.zip"

    con = sqlite3.connect(db_path)
    try:
        export_run_audit_manifest_bundle(
            con,
            db_path=db_path,
            engagement_id=1001,
            run_id=run_id,
            output_path=out_path,
            signing_key="test-signing-key",
        )
    finally:
        con.close()

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(out_path, mode="a", compression=zipfile.ZIP_STORED) as archive:
            info = zipfile.ZipInfo("README.md", (1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_STORED
            archive.writestr(info, b"duplicate\n")

    result = verify_run_audit_manifest_bundle_signature(
        out_path,
        signing_key="test-signing-key",
    )
    assert result.ok is False
    assert result.reason == "duplicate zip entry: README.md"


def test_manifest_bundle_signature_verifier_reports_missing_bundle(tmp_path: Path) -> None:
    result = verify_run_audit_manifest_bundle_signature(
        tmp_path / "missing.zip",
        signing_key="test-signing-key",
    )
    assert result.ok is False
    assert result.reason == "bundle not found"
