from __future__ import annotations

import sqlite3
from pathlib import Path

from forge.engagement_orchestrator import ArtifactQueueProcessor, OLEStreamExtractionJob
from forge.utils import artifact_barcode
from tests.phase1.artifact_test_support import bootstrap_engagement


def _png_bytes(label: bytes = b"embedded") -> bytes:
    return (
        b"\x89PNG\r\n\x1a\n"
        b"\x00\x00\x00\rIHDR"
        b"\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00"
        b"\x90wS\xde"
        + label
        + b"\x00\x00\x00\x00IEND\xaeB`\x82"
    )


def _jpeg_bytes(label: bytes = b"embedded") -> bytes:
    return b"\xff\xd8\xff\xe0\x00\x10JFIF\x00" + label + b"\xff\xd9"


def _patch_barcode_decoder(monkeypatch, payload: str) -> None:  # noqa: ANN001
    monkeypatch.setattr(artifact_barcode, "_available_backend_names", lambda: ("pyzbar",))
    monkeypatch.setattr(artifact_barcode, "_decode_with_pyzbar", lambda _data: [payload])
    monkeypatch.setattr(artifact_barcode, "_decode_with_opencv", lambda _data: [])
    monkeypatch.setattr(ArtifactQueueProcessor, "_ocr_image_bytes", lambda _self, _data, _suffix: "")


def test_embedded_image_carving_preserves_offset_order_and_caps(tmp_path: Path) -> None:
    processor = ArtifactQueueProcessor(tmp_path / "engagement.db", 1001)
    data = (
        b"prefix"
        + _jpeg_bytes(b"first")
        + b"middle"
        + b"".join(_png_bytes(f"png-{index}".encode("ascii")) for index in range(12))
    )

    entries = processor._embedded_image_entries(data)

    assert len(entries) == 8
    assert [(entry[0], entry[1]) for entry in entries[:2]] == [
        ("jpeg", ".jpg"),
        ("png", ".png"),
    ]
    assert [entry[2] for entry in entries] == sorted(entry[2] for entry in entries)
    assert all(entry[3] for entry in entries)


def test_legacy_binary_embedded_image_barcode_feeds_recursive_seeds(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_binary_image"
    artifact_root.mkdir()
    bootstrap_engagement(db_path)
    binary_path = artifact_root / "memory-dump.bin"
    binary_path.write_bytes(b"\x00\x01binary-prefix" + _png_bytes(b"qr") + b"binary-suffix")
    _patch_barcode_decoder(
        monkeypatch,
        "binary-qr@acme.example https://binary-qr.acme.example/run?token=secret&view=public",
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
    assert ("binary-qr@acme.example", "email") in seeds
    assert ("https://binary-qr.acme.example/run?view=public", "url") in seeds
    assert not any("token=secret" in seed for seed, _seed_type in seeds)


def test_ole_stream_embedded_image_payloads_use_image_member_pipeline(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    bootstrap_engagement(db_path)
    _patch_barcode_decoder(monkeypatch, "ole-stream-qr@acme.example")
    processor = ArtifactQueueProcessor(db_path, 1001)
    source_file = str(tmp_path / "legacy.doc")
    job = OLEStreamExtractionJob(
        source_file=source_file,
        member_name="legacy.doc",
        stream_name="Pictures/Preview",
        stream_data=b"ole-prefix" + _png_bytes(b"ole-qr") + b"ole-suffix",
        depth=0,
    )

    payloads = processor._extract_ole_stream_payloads(job)

    assert (
        source_file,
        "legacy.doc/Pictures/Preview#embedded-image-0.png#barcode",
        "ole-stream-qr@acme.example",
    ) in payloads
