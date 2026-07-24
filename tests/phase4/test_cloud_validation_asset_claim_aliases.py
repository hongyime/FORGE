from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from forge.db.migrations import run_migrations
from forge.db.schema import apply_schema
from forge.phase4 import cloud_validate

ENGAGEMENT_ID = 1001


def _bootstrap_db(db_path: Path) -> None:
    con = sqlite3.connect(db_path)
    try:
        apply_schema(con)
        run_migrations(con)
        con.execute(
            """
            INSERT INTO engagements (id, name, scope_json, status, operator)
            VALUES (?, 'Acme Example', '["acme.example"]', 'ACTIVE', 'delta-one')
            """,
            (ENGAGEMENT_ID,),
        )
        con.commit()
    finally:
        con.close()


def test_sweep_pending_cloud_asset_validations_skips_alias_assets_with_normalized_results(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.executemany(
            """
            INSERT INTO cloud_assets (engagement_id, asset_type, identifier, source)
            VALUES (?, ?, ?, ?)
            """,
            [
                (ENGAGEMENT_ID, "s3", "legacy-s3-assets", "legacy_import"),
                (ENGAGEMENT_ID, "digitalocean_spaces", "nyc3/legacy-space", "legacy_import"),
                (ENGAGEMENT_ID, "google_cloud_storage", "legacy-gcs-assets", "legacy_import"),
                (ENGAGEMENT_ID, "azure_blob_storage", "legacyblob/public", "legacy_import"),
            ],
        )
        con.executemany(
            """
            INSERT INTO cloud_validation_results
                (engagement_id, asset_type, identifier, validation_status, validation_method, evidence, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (ENGAGEMENT_ID, "aws_s3", "legacy-s3-assets", "UNVERIFIED", "scope_manifest", "denied", "done"),
                (ENGAGEMENT_ID, "do_spaces", "nyc3/legacy-space", "UNVERIFIED", "scope_manifest", "denied", "done"),
                (ENGAGEMENT_ID, "gcs", "legacy-gcs-assets", "UNVERIFIED", "scope_manifest", "denied", "done"),
                (ENGAGEMENT_ID, "azure_blob", "legacyblob/public", "UNVERIFIED", "scope_manifest", "denied", "done"),
            ],
        )
        con.commit()
    finally:
        con.close()

    def _fail_validate_batch(*args: Any, **kwargs: Any) -> None:
        del args, kwargs
        raise AssertionError("normalized validation rows should suppress legacy alias claims")

    monkeypatch.setattr(cloud_validate, "run_cloud_asset_validate_batch", _fail_validate_batch)

    summary = cloud_validate.sweep_pending_cloud_asset_validations(
        ENGAGEMENT_ID,
        db_path,
        limit=10,
        max_workers=4,
    )

    assert summary == {
        "status": "success",
        "engagement_id": ENGAGEMENT_ID,
        "attempted": 0,
        "succeeded": 0,
        "failed": 0,
        "status_counts": {},
        "results": [],
    }
    con = sqlite3.connect(db_path)
    try:
        assert con.execute("SELECT COUNT(*) FROM validation_claims").fetchone()[0] == 0
    finally:
        con.close()


def test_sweep_pending_cloud_asset_validations_dedupes_alias_and_canonical_assets(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.executemany(
            """
            INSERT INTO cloud_assets (engagement_id, asset_type, identifier, source)
            VALUES (?, ?, ?, ?)
            """,
            [
                (ENGAGEMENT_ID, "s3", "shared-assets", "legacy_import"),
                (ENGAGEMENT_ID, "aws_s3", "shared-assets", "artifact_s3_uri"),
            ],
        )
        con.commit()
    finally:
        con.close()

    provider_batches: list[list[tuple[str, str]]] = []

    def _fake_validate_batch(
        engagement_id: int,
        assets: list[tuple[str, str]],
        batch_db_path: Path,
        **kwargs: Any,
    ) -> dict[str, Any]:
        del batch_db_path, kwargs
        normalized_assets = [(str(asset[0]), str(asset[1])) for asset in assets]
        provider_batches.append(normalized_assets)
        return {
            "status": "success",
            "engagement_id": int(engagement_id),
            "attempted": len(normalized_assets),
            "succeeded": len(normalized_assets),
            "failed": 0,
            "status_counts": {"VALIDATED": len(normalized_assets)},
            "results": [
                {
                    "status": "success",
                    "engagement_id": int(engagement_id),
                    "asset_type": asset_type,
                    "identifier": identifier,
                    "validation_status": "VALIDATED",
                    "validation_method": "stub_provider",
                }
                for asset_type, identifier in normalized_assets
            ],
        }

    monkeypatch.setattr(cloud_validate, "run_cloud_asset_validate_batch", _fake_validate_batch)

    summary = cloud_validate.sweep_pending_cloud_asset_validations(
        ENGAGEMENT_ID,
        db_path,
        limit=10,
        max_workers=4,
    )

    assert provider_batches == [[("s3", "shared-assets")]]
    assert summary["attempted"] == 1
    assert summary["succeeded"] == 1
    assert summary["failed"] == 0
    assert summary["status_counts"]["VALIDATED"] == 1
    con = sqlite3.connect(db_path)
    try:
        assert con.execute("SELECT COUNT(*) FROM validation_claims").fetchone()[0] == 0
    finally:
        con.close()
