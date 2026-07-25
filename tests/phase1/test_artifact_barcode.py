from __future__ import annotations

import base64
import json
import sqlite3
import zipfile
from pathlib import Path

from forge.engagement_orchestrator import ArtifactQueueProcessor
from forge.utils import artifact_barcode
from tests.phase1.artifact_test_support import bootstrap_engagement


def _patch_barcode_decoder(monkeypatch, *payloads: str) -> None:  # noqa: ANN001
    monkeypatch.setattr(artifact_barcode, "_available_backend_names", lambda: ("pyzbar",))
    monkeypatch.setattr(artifact_barcode, "_decode_with_pyzbar", lambda _data: list(payloads))
    monkeypatch.setattr(artifact_barcode, "_decode_with_opencv", lambda _data: [])


def test_barcode_payloads_suppress_sensitive_qr_schemes(monkeypatch) -> None:  # noqa: ANN001
    _patch_barcode_decoder(
        monkeypatch,
        "WIFI:T:WPA;S:corp;P:secret;;",
        "otpauth://totp/acme?secret=ABC123",
        "https://qr.acme.example/bootstrap",
        "https://qr.acme.example/bootstrap",
    )

    assert artifact_barcode.barcode_payloads_from_bytes(b"fake-image") == [
        "https://qr.acme.example/bootstrap"
    ]


def test_barcode_payloads_real_decode_path_is_safe_without_optional_backends() -> None:
    artifact_barcode._available_backend_names.cache_clear()

    assert isinstance(artifact_barcode.barcode_decoder_backend_names(), tuple)
    assert artifact_barcode.barcode_payloads_from_bytes(b"not an image") == []


def test_barcode_payloads_sanitize_url_userinfo_and_query(monkeypatch) -> None:  # noqa: ANN001
    _patch_barcode_decoder(
        monkeypatch,
        "https://user:password@Qr.Acme.Example/bootstrap?token=secret&view=public",
    )

    assert artifact_barcode.barcode_payloads_from_bytes(b"fake-image") == [
        "https://qr.acme.example/bootstrap?view=public"
    ]


def test_artifact_queue_processor_extracts_image_qr_payloads(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_barcode_image"
    artifact_root.mkdir()
    image_path = artifact_root / "qr-intel.png"
    image_path.write_bytes(b"\x89PNG\r\n\x1a\nfake-qr")
    bootstrap_engagement(db_path)
    _patch_barcode_decoder(
        monkeypatch,
        "qr-owner@acme.example https://qr.acme.example/bootstrap?token=secret&view=public",
    )
    monkeypatch.setattr(ArtifactQueueProcessor, "_ocr_image_path", lambda _self, _path: "")

    processor = ArtifactQueueProcessor(db_path, 1001)
    source_url = "https://cdn.acme.example/static/qr-intel.png"
    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO engagement_seeds
                (engagement_id, seed_value, seed_type, source, depth, confidence, metadata_json)
            VALUES
                (1001, ?, 'url', 'operator', 0, 1.0, '{}')
            """,
            (source_url,),
        )
        con.execute(
            """
            INSERT INTO artifact_queue
                (engagement_id, source_url, local_path, artifact_type,
                 discovered_from, status, metadata_json)
            VALUES
                (1001, ?, ?, 'document', 'remote_artifact', 'downloaded', '{}')
            """,
            (source_url, image_path.resolve().as_posix()),
        )
        con.commit()
    finally:
        con.close()

    assert processor.process().processed == 1

    con = sqlite3.connect(db_path)
    try:
        metadata = json.loads(
            str(
                con.execute(
                    "SELECT metadata_json FROM artifact_queue WHERE engagement_id=1001"
                ).fetchone()[0]
            )
        )
        emails = {
            row[0]
            for row in con.execute(
                "SELECT email FROM emails WHERE engagement_id=1001"
            ).fetchall()
        }
        seeds = {
            (row[0], row[1])
            for row in con.execute(
                "SELECT seed_value, seed_type FROM engagement_seeds WHERE engagement_id=1001"
            ).fetchall()
        }
        seed_metadata = {
            (row[0], row[1]): json.loads(str(row[2] or "{}"))
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

    assert metadata["barcode_payload_count"] == 1
    assert "qr-owner@acme.example" in emails
    assert ("qr-owner@acme.example", "email") in seeds
    assert ("https://qr.acme.example/bootstrap?view=public", "url") in seeds
    for seed_key in (
        ("qr-owner@acme.example", "email"),
        ("https://qr.acme.example/bootstrap?view=public", "url"),
    ):
        assert seed_metadata[seed_key]["artifact_provenance"] is True
        assert seed_metadata[seed_key]["format"] == "png"
        assert seed_metadata[seed_key]["barcode_payload_count"] == 1
        assert seed_metadata[seed_key].get("ocr_payload_count") in (None, 0)
    assert not any("token=secret" in seed for seed, _type in seeds)


def test_artifact_queue_processor_extracts_embedded_image_qr_payloads(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_barcode_zip"
    artifact_root.mkdir()
    archive_path = artifact_root / "evidence.zip"
    with zipfile.ZipFile(archive_path, "w") as zf:
        zf.writestr("screenshots/qr.png", b"\x89PNG\r\n\x1a\nembedded-qr")
    bootstrap_engagement(db_path)
    _patch_barcode_decoder(
        monkeypatch,
        "zip-qr@acme.example https://zip-qr.acme.example/path?api_key=hidden&lang=en",
    )

    processor = ArtifactQueueProcessor(db_path, 1001)
    assert processor.ingest_local_artifacts([artifact_root]) == 1
    assert processor.process().processed == 1

    con = sqlite3.connect(db_path)
    try:
        seeds = {
            (row[0], row[1])
            for row in con.execute(
                "SELECT seed_value, seed_type FROM engagement_seeds WHERE engagement_id=1001"
            ).fetchall()
        }
    finally:
        con.close()

    assert ("zip-qr@acme.example", "email") in seeds
    assert ("https://zip-qr.acme.example/path?lang=en", "url") in seeds
    assert not any("api_key=hidden" in seed for seed, _type in seeds)


def test_pdf_page_barcode_payloads_do_not_require_ocr_binary(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    bootstrap_engagement(db_path)
    pdf_path = tmp_path / "scanned.pdf"
    page_image = tmp_path / "page-1.png"
    pdf_path.write_bytes(b"%PDF-1.7 fake")
    page_image.write_bytes(b"\x89PNG\r\n\x1a\npdf-page-qr")
    _patch_barcode_decoder(monkeypatch, "https://pdf-qr.acme.example/runbook")

    processor = ArtifactQueueProcessor(db_path, 1001)
    processor._ocr_binary = None
    processor._pdf_raster_binary = "fake-pdftoppm"
    monkeypatch.setattr(
        ArtifactQueueProcessor,
        "_render_pdf_pages_for_ocr",
        lambda _self, _path: [page_image],
    )

    payloads = processor._extract_pdf_ocr_payloads_from_path(
        pdf_path,
        source_file=str(pdf_path),
        member_name=pdf_path.name,
    )

    assert payloads == [
        (str(pdf_path), "scanned.pdf#barcode-page-1", "https://pdf-qr.acme.example/runbook")
    ]
    assert not page_image.exists()


def test_archived_pdf_page_barcode_payloads_do_not_require_ocr_binary(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_barcode_pdf_zip"
    artifact_root.mkdir()
    archive_path = artifact_root / "evidence.zip"
    page_image = tmp_path / "archived-page-1.png"
    page_image.write_bytes(b"\x89PNG\r\n\x1a\narchived-pdf-page-qr")
    with zipfile.ZipFile(archive_path, "w") as zf:
        zf.writestr("docs/scanned.pdf", b"%PDF-1.7 archived fake")
    bootstrap_engagement(db_path)
    _patch_barcode_decoder(monkeypatch, "https://archived-pdf-qr.acme.example/runbook")

    processor = ArtifactQueueProcessor(db_path, 1001)
    processor._ocr_binary = None
    processor._pdf_raster_binary = "fake-pdftoppm"
    monkeypatch.setattr(
        ArtifactQueueProcessor,
        "_render_pdf_pages_for_ocr",
        lambda _self, _path: [page_image],
    )

    assert processor.ingest_local_artifacts([artifact_root]) == 1
    assert processor.process().processed == 1

    con = sqlite3.connect(db_path)
    try:
        seeds = {
            (row[0], row[1])
            for row in con.execute(
                "SELECT seed_value, seed_type FROM engagement_seeds WHERE engagement_id=1001"
            ).fetchall()
        }
    finally:
        con.close()

    assert ("https://archived-pdf-qr.acme.example/runbook", "url") in seeds
    assert not page_image.exists()


def test_data_uri_image_barcode_payloads_feed_structured_text(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    bootstrap_engagement(db_path)
    _patch_barcode_decoder(monkeypatch, "data-uri-qr@acme.example")
    image_data = base64.b64encode(b"\x89PNG\r\n\x1a\ndata-uri-qr").decode("ascii")
    processor = ArtifactQueueProcessor(db_path, 1001)

    payload = processor._data_uri_image_structured_payload_text(
        f'<image href="data:image/png;base64,{image_data}" />'
    )

    assert "data_uri_image_0#barcode" in payload
    assert "data-uri-qr@acme.example" in payload
