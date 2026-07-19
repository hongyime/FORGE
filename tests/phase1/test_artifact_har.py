from __future__ import annotations

import base64
import json
import sqlite3
from pathlib import Path
from typing import Any

from forge.db.migrations import run_migrations
from forge.db.schema import apply_schema
from forge.engagement_orchestrator import ArtifactQueueProcessor
from forge.utils.artifact_har import (
    har_content_image_payload_lines,
    har_content_text,
    har_scalar_text,
)


def _bootstrap_engagement(db_path: Path, engagement_id: int = 1001) -> None:
    con = sqlite3.connect(db_path)
    try:
        apply_schema(con)
        run_migrations(con)
        con.execute(
            """
            INSERT INTO engagements (id, name, scope_json, status, operator)
            VALUES (?, 'Acme Example', '["*.acme.example"]', 'ACTIVE', 'delta-one')
            """,
            (engagement_id,),
        )
        con.commit()
    finally:
        con.close()


def test_har_content_text_decodes_non_image_base64_without_ocr() -> None:
    text = har_content_text(
        {
            "mimeType": "application/json",
            "encoding": "base64",
            "text": base64.b64encode(b'{"owner":"json-har@acme.example"}').decode("ascii"),
        },
        scalar_text=lambda value, limit: har_scalar_text(value, limit=limit),
        text_from_bytes=lambda data, _limit: data.decode("utf-8"),
    )

    assert "json-har@acme.example" in text


def test_har_content_image_payload_lines_ocrs_and_extracts_metadata() -> None:
    image_bytes = b"\x89PNG\r\n\x1a\nfake-image"
    lines = har_content_image_payload_lines(
        {
            "mimeType": "image/png",
            "encoding": "base64",
            "text": base64.b64encode(image_bytes).decode("ascii"),
        },
        mime_type="image/png",
        suffix=".png",
        image_suffixes={".png"},
        max_image_bytes=8,
        ocr_text_limit=64,
        ocr_image_bytes=lambda data, suffix: f"{suffix}: ocr-owner@acme.example {len(data)}",
        image_metadata_payload=lambda data: f"meta-owner@acme.example {len(data)}",
    )

    assert lines == [
        "response.content.ocr=.png: ocr-owner@acme.example 8",
        "response.content.imageMetadata=meta-owner@acme.example 8",
    ]


def test_har_content_image_payload_lines_skips_non_image_base64() -> None:
    def _fail_ocr(_data: bytes, _suffix: str) -> str:
        raise AssertionError("non-image HAR response content should not invoke OCR")

    lines = har_content_image_payload_lines(
        {
            "mimeType": "application/json",
            "encoding": "base64",
            "text": base64.b64encode(b'{"owner":"json-har@acme.example"}').decode("ascii"),
        },
        mime_type="application/json",
        suffix=".json",
        image_suffixes={".png"},
        max_image_bytes=8,
        ocr_text_limit=64,
        ocr_image_bytes=_fail_ocr,
        image_metadata_payload=lambda _data: "",
    )

    assert lines == []


def test_artifact_queue_processor_ocrs_har_base64_image_response_bodies(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_har_image"
    artifact_root.mkdir()
    _bootstrap_engagement(db_path)

    har_path = artifact_root / "image-response.har"
    image_bytes = b"\x89PNG\r\n\x1a\nfake-image"
    har_path.write_text(
        json.dumps(
            {
                "log": {
                    "version": "1.2",
                    "entries": [
                        {
                            "request": {
                                "method": "GET",
                                "url": "https://portal.acme.example/banner.png",
                            },
                            "response": {
                                "status": 200,
                                "content": {
                                    "mimeType": "image/png",
                                    "encoding": "base64",
                                    "text": base64.b64encode(image_bytes).decode("ascii"),
                                },
                            },
                        }
                    ],
                }
            }
        ),
        encoding="utf-8",
    )

    ocr_calls: list[str] = []

    def _fake_ocr_bytes(_self: ArtifactQueueProcessor, data: bytes, suffix: str) -> str:
        ocr_calls.append(suffix)
        assert data.startswith(b"\x89PNG")
        return "har-image-owner@acme.example https://har-image.acme.example/poster"

    def _fake_image_metadata(_self: ArtifactQueueProcessor, data: bytes) -> str:
        assert data.startswith(b"\x89PNG")
        return "har-image-meta@acme.example https://har-meta.acme.example/xmp"

    monkeypatch.setattr(ArtifactQueueProcessor, "_ocr_image_bytes", _fake_ocr_bytes)
    monkeypatch.setattr(ArtifactQueueProcessor, "_image_metadata_payload", _fake_image_metadata)

    processor = ArtifactQueueProcessor(db_path, 1001)
    assert processor.ingest_local_artifacts([artifact_root]) >= 1
    assert processor.process().processed >= 1
    assert ocr_calls == [".png"]

    con = sqlite3.connect(db_path)
    try:
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

    assert {"har-image-owner@acme.example", "har-image-meta@acme.example"} <= emails
    assert ("https://har-image.acme.example/poster", "url") in seeds
    assert ("https://har-meta.acme.example/xmp", "url") in seeds


def test_artifact_queue_processor_parses_large_har_before_image_response(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_engagement(db_path)
    har_path = tmp_path / "large-image-response.har"
    image_bytes = b"\x89PNG\r\n\x1a\nfake-image"
    har_path.write_text(
        json.dumps(
            {
                "log": {
                    "comment": "x" * 1_100_000,
                    "entries": [
                        {
                            "request": {
                                "method": "GET",
                                "url": "https://portal.acme.example/large-banner.png",
                            },
                            "response": {
                                "status": 200,
                                "content": {
                                    "mimeType": "image/png",
                                    "encoding": "base64",
                                    "text": base64.b64encode(image_bytes).decode("ascii"),
                                },
                            },
                        }
                    ],
                }
            }
        ),
        encoding="utf-8",
    )

    def _fake_ocr_bytes(_self: ArtifactQueueProcessor, data: bytes, suffix: str) -> str:
        assert suffix == ".png"
        assert data.startswith(b"\x89PNG")
        return "large-har-image@acme.example"

    monkeypatch.setattr(ArtifactQueueProcessor, "_ocr_image_bytes", _fake_ocr_bytes)
    monkeypatch.setattr(
        ArtifactQueueProcessor,
        "_image_metadata_payload",
        lambda _self, _data: "",
    )

    payloads = ArtifactQueueProcessor(db_path, 1001)._extract_har_payloads(har_path)

    assert any("large-har-image@acme.example" in text for _, _, text in payloads)
