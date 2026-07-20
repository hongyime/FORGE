from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from forge.engagement_orchestrator import ArtifactQueueProcessor
from forge.utils.artifact_package_url import long_tail_package_url_registry_candidate
from tests.phase1.artifact_test_support import bootstrap_engagement


def test_long_tail_package_url_registry_candidates() -> None:
    assert (
        long_tail_package_url_registry_candidate("swift", "apple/swift-nio")
        == "https://swiftpackageindex.com/apple/swift-nio"
    )
    assert (
        long_tail_package_url_registry_candidate("cocoapods", "Alamofire")
        == "https://cocoapods.org/pods/Alamofire"
    )
    assert (
        long_tail_package_url_registry_candidate("pub", "flutter_secure_storage")
        == "https://pub.dev/packages/flutter_secure_storage"
    )
    assert long_tail_package_url_registry_candidate("hex", "phoenix") == "https://hex.pm/packages/phoenix"
    assert long_tail_package_url_registry_candidate("cran", "dplyr") == "https://cran.r-project.org/package=dplyr"
    assert (
        long_tail_package_url_registry_candidate("huggingface", "bigscience/bloom")
        == "https://huggingface.co/bigscience/bloom"
    )


def test_cyclonedx_long_tail_package_urls_become_recursive_seeds(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "sbom_package_urls"
    artifact_root.mkdir()
    bootstrap_engagement(db_path, name="SBOM Package URL Ecosystem Test")

    (artifact_root / "mobile.cyclonedx.json").write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "components": [
                    {"name": "swift-nio", "purl": "pkg:swift/apple/swift-nio@2.62.0"},
                    {"name": "Alamofire", "purl": "pkg:cocoapods/Alamofire@5.8.1"},
                    {"name": "flutter_secure_storage", "purl": "pkg:pub/flutter_secure_storage@9.2.4"},
                    {"name": "phoenix", "purl": "pkg:hex/phoenix@1.7.14"},
                    {"name": "dplyr", "purl": "pkg:cran/dplyr@1.1.4"},
                ],
            }
        ),
        encoding="utf-8",
    )

    processor = ArtifactQueueProcessor(db_path, 1001)
    assert processor.ingest_local_artifacts([artifact_root]) == 1
    assert processor.process().processed == 1

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

    assert ("https://swiftpackageindex.com/apple/swift-nio", "url") in seeds
    assert ("https://cocoapods.org/pods/Alamofire", "url") in seeds
    assert ("https://pub.dev/packages/flutter_secure_storage", "url") in seeds
    assert ("https://hex.pm/packages/phoenix", "url") in seeds
    assert ("https://cran.r-project.org/package=dplyr", "url") in seeds
