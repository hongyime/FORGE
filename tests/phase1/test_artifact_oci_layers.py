from __future__ import annotations

import gzip
import json
import sqlite3
import tarfile
from io import BytesIO
from pathlib import Path

from forge.engagement_orchestrator import ArtifactQueueProcessor
from tests.phase1.artifact_test_support import bootstrap_engagement


def _tar_bytes(members: dict[str, bytes]) -> bytes:
    buffer = BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for member_name, payload in members.items():
            info = tarfile.TarInfo(member_name)
            info.size = len(payload)
            archive.addfile(info, BytesIO(payload))
    return buffer.getvalue()


def test_artifact_queue_processor_extracts_oci_layer_member_static_artifacts(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_oci_layers"
    artifact_root.mkdir()
    bootstrap_engagement(db_path)

    manifest_digest = "a" * 64
    config_digest = "b" * 64
    layer_digest = "c" * 64
    layer_payload = _tar_bytes(
        {
            "app/.env": b"\n".join(
                [
                    b"OWNER_EMAIL=oci-layer-owner@acme.example",
                    b"PUBLIC_URL=https://oci-layer.acme.example/status",
                    b"FIREBASE_DATABASE_URL=https://oci-layer-firebase.firebaseio.com",
                    b"SUPABASE_URL=https://ocilayervault.supabase.co/rest/v1",
                    b"AWS_S3_BUCKET=acme-oci-layer-bucket",
                    b"GCS_BUCKET=acme-oci-layer-gcs",
                ]
            ),
        }
    )
    image_tar_path = artifact_root / "acme-oci-layer-image.tar"
    image_payload = _tar_bytes(
        {
            "oci-layout": b'{"imageLayoutVersion":"1.0.0"}',
            "index.json": json.dumps(
                {
                    "schemaVersion": 2,
                    "manifests": [
                        {
                            "mediaType": "application/vnd.oci.image.manifest.v1+json",
                            "digest": f"sha256:{manifest_digest}",
                        }
                    ],
                }
            ).encode(),
            f"blobs/sha256/{manifest_digest}": json.dumps(
                {
                    "schemaVersion": 2,
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "config": {
                        "mediaType": "application/vnd.oci.image.config.v1+json",
                        "digest": f"sha256:{config_digest}",
                    },
                    "layers": [
                        {
                            "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                            "digest": f"sha256:{layer_digest}",
                        }
                    ],
                }
            ).encode(),
            f"blobs/sha256/{config_digest}": b'{"architecture":"amd64","os":"linux"}',
            f"blobs/sha256/{layer_digest}": gzip.compress(layer_payload),
            f"blobs/sha256/{'d' * 64}": gzip.compress(
                _tar_bytes({"app/unreferenced.env": b"UNREF=skip@acme.example"})
            ),
        }
    )
    image_tar_path.write_bytes(image_payload)

    processor = ArtifactQueueProcessor(db_path, 1001)
    payloads = processor._extract_archive_bytes_payloads(
        image_payload,
        image_tar_path.resolve().as_posix(),
        image_tar_path.name,
        depth=0,
    )
    joined_payloads = "\n".join(f"{source}\n{path}\n{text}" for source, path, text in payloads)
    assert f"blobs/sha256/{layer_digest}#oci-layer/app/.env" in joined_payloads
    assert "oci-layer-owner@acme.example" in joined_payloads
    assert "skip@acme.example" not in joined_payloads

    assert processor.ingest_local_artifacts([artifact_root]) == 1
    summary = processor.process()

    assert summary.processed == 1
    assert summary.discovered_seeds >= 4

    con = sqlite3.connect(db_path)
    try:
        emails = {
            row[0]
            for row in con.execute(
                "SELECT email FROM emails WHERE engagement_id=1001"
            ).fetchall()
        }
        assert "oci-layer-owner@acme.example" in emails
        assert "skip@acme.example" not in emails

        seeds = {
            (row[0], row[1])
            for row in con.execute(
                "SELECT seed_value, seed_type FROM engagement_seeds WHERE engagement_id=1001"
            ).fetchall()
        }
        assert ("oci-layer-owner@acme.example", "email") in seeds
        assert ("https://oci-layer.acme.example/status", "url") in seeds

        cloud_assets = {
            (row[0], row[1])
            for row in con.execute(
                "SELECT asset_type, identifier FROM cloud_assets WHERE engagement_id=1001"
            ).fetchall()
        }
        assert ("aws_s3", "acme-oci-layer-bucket") in cloud_assets
        assert ("firebase", "oci-layer-firebase") in cloud_assets
        assert ("gcs", "acme-oci-layer-gcs") in cloud_assets
        assert ("supabase", "ocilayervault") in cloud_assets

        artifact_meta = json.loads(
            str(
                con.execute(
                    "SELECT metadata_json FROM artifact_queue WHERE source_url=?",
                    (image_tar_path.resolve().as_posix(),),
                ).fetchone()[0]
            )
        )
        assert artifact_meta["format"] == "tar"
        assert artifact_meta["payload_count"] >= 5
    finally:
        con.close()


def test_artifact_queue_processor_extracts_docker_save_layer_member_static_artifacts(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_docker_save_layers"
    artifact_root.mkdir()
    bootstrap_engagement(db_path)

    config_name = "a" * 64 + ".json"
    layer_name = "b" * 64 + "/layer.tar"
    unreferenced_layer_name = "c" * 64 + "/layer.tar"
    large_prefix = b"#" * (1_100_000)
    layer_payload = _tar_bytes(
        {
            "app/padding.bin": large_prefix,
            "app/.env": b"\n".join(
                [
                    b"OWNER_EMAIL=docker-save-owner@acme.example",
                    b"PUBLIC_URL=https://docker-save.acme.example/status",
                    b"FIREBASE_DATABASE_URL=https://docker-save-firebase.firebaseio.com",
                    b"SUPABASE_URL=https://dockersavevault.supabase.co/rest/v1",
                    b"AWS_S3_BUCKET=acme-docker-save-bucket",
                    b"GCS_BUCKET=acme-docker-save-gcs",
                ]
            ),
        }
    )
    image_payload = _tar_bytes(
        {
            "manifest.json": json.dumps(
                [
                    {
                        "Config": config_name,
                        "RepoTags": ["acme/docker-save:latest"],
                        "Layers": [layer_name],
                    }
                ]
            ).encode(),
            config_name: json.dumps(
                {
                    "config": {
                        "Env": ["API_URL=https://docker-config.acme.example/api"],
                        "Labels": {"owner": "docker-config-owner@acme.example"},
                    }
                }
            ).encode(),
            layer_name: layer_payload,
            unreferenced_layer_name: _tar_bytes(
                {"app/unreferenced.env": b"UNREF=docker-unref@acme.example"}
            ),
        }
    )
    image_tar_path = artifact_root / "acme-docker-save-image.tar"
    image_tar_path.write_bytes(image_payload)

    processor = ArtifactQueueProcessor(db_path, 1001)
    payloads = processor._extract_archive_bytes_payloads(
        image_payload,
        image_tar_path.resolve().as_posix(),
        image_tar_path.name,
        depth=0,
    )
    joined_payloads = "\n".join(f"{source}\n{path}\n{text}" for source, path, text in payloads)
    assert f"{layer_name}#docker-layer/app/.env" in joined_payloads
    assert "docker-save-owner@acme.example" in joined_payloads
    assert "docker-config-owner@acme.example" in joined_payloads
    assert "docker-unref@acme.example" not in joined_payloads

    assert processor.ingest_local_artifacts([artifact_root]) == 1
    summary = processor.process()

    assert summary.processed == 1
    assert summary.discovered_seeds >= 4

    con = sqlite3.connect(db_path)
    try:
        emails = {
            row[0]
            for row in con.execute(
                "SELECT email FROM emails WHERE engagement_id=1001"
            ).fetchall()
        }
        assert "docker-save-owner@acme.example" in emails
        assert "docker-config-owner@acme.example" in emails
        assert "docker-unref@acme.example" not in emails

        seeds = {
            (row[0], row[1])
            for row in con.execute(
                "SELECT seed_value, seed_type FROM engagement_seeds WHERE engagement_id=1001"
            ).fetchall()
        }
        assert ("docker-save-owner@acme.example", "email") in seeds
        assert ("https://docker-save.acme.example/status", "url") in seeds
        assert ("https://docker-config.acme.example/api", "url") in seeds

        cloud_assets = {
            (row[0], row[1])
            for row in con.execute(
                "SELECT asset_type, identifier FROM cloud_assets WHERE engagement_id=1001"
            ).fetchall()
        }
        assert ("aws_s3", "acme-docker-save-bucket") in cloud_assets
        assert ("firebase", "docker-save-firebase") in cloud_assets
        assert ("gcs", "acme-docker-save-gcs") in cloud_assets
        assert ("supabase", "dockersavevault") in cloud_assets
    finally:
        con.close()
