from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from forge.engagement_orchestrator import ArtifactQueueProcessor, _artifact_format_label
from tests.phase1.artifact_test_support import bootstrap_engagement


def test_sbom_multisuffix_artifact_format_labels() -> None:
    assert _artifact_format_label("bom.cyclonedx.json") == "cyclonedx"
    assert _artifact_format_label("bom.cyclonedx.xml") == "cyclonedx"
    assert _artifact_format_label("bom.cdx.json") == "cdx"
    assert _artifact_format_label("bom.spdx.json") == "spdx"
    assert _artifact_format_label("bom.spdx.yaml") == "spdx"
    assert _artifact_format_label("inventory.spdx.json") == "spdx"
    assert _artifact_format_label("bom.syft.json") == "syft"


def test_artifact_queue_preserves_multisuffix_sbom_format_metadata(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "sbom_formats"
    artifact_root.mkdir()
    bootstrap_engagement(db_path, name="SBOM Format Label Test")

    fixtures = {
        "portal.cyclonedx.json": {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [{"name": "portal", "purl": "pkg:npm/@acme/portal@1.2.3"}],
        },
        "worker.cdx.json": {
            "bomFormat": "CycloneDX",
            "components": [{"name": "worker", "purl": "pkg:pypi/acme-worker@0.4.0"}],
        },
        "inventory.spdx.json": {
            "spdxVersion": "SPDX-2.3",
            "packages": [{"name": "api", "externalRefs": []}],
        },
    }
    for name, payload in fixtures.items():
        (artifact_root / name).write_text(json.dumps(payload), encoding="utf-8")

    processor = ArtifactQueueProcessor(db_path, 1001)
    assert processor.ingest_local_artifacts([artifact_root]) == len(fixtures)
    assert processor.process().processed == len(fixtures)

    con = sqlite3.connect(db_path)
    try:
        formats = {
            Path(row[0]).name: json.loads(str(row[1] or "{}")).get("format")
            for row in con.execute(
                """
                SELECT source_url, metadata_json
                FROM artifact_queue
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
    finally:
        con.close()

    assert formats["portal.cyclonedx.json"] == "cyclonedx"
    assert formats["worker.cdx.json"] == "cdx"
    assert formats["inventory.spdx.json"] == "spdx"
