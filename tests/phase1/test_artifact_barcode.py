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
    assert processor.ingest_local_artifacts([artifact_root]) == 1
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
    finally:
        con.close()

    assert metadata["barcode_payload_count"] == 1
    assert "qr-owner@acme.example" in emails
    assert ("qr-owner@acme.example", "email") in seeds
    assert ("https://qr.acme.example/bootstrap?view=public", "url") in seeds
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
