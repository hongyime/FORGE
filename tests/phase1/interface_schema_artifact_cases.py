from __future__ import annotations

import json
import sqlite3
import zipfile
from pathlib import Path
from textwrap import dedent
from typing import Callable

from forge.engagement_orchestrator import ArtifactQueueProcessor


def run_queue_processor_extracts_interface_schema_artifacts(
    tmp_path: Path,
    bootstrap_engagement: Callable[[Path], None],
) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_interface_schemas"
    artifact_root.mkdir()
    bootstrap_engagement(db_path)

    proto_path = artifact_root / "identity.proto"
    proto_path.write_text(
        dedent(
            """
            syntax = "proto3";
            package acme.identity;
            option java_package = "io.acme.identity";
            option (acme.owner) = "proto-owner@acme.example";
            option (acme.endpoint) = "https://proto.acme.example/grpc";
            option (acme.internal_endpoint) = "proto-hostonly.acme.example/grpc";
            option (acme.firebase) = "https://proto-firebase.firebaseio.com";
            """
        ).strip(),
        encoding="utf-8",
    )

    asyncapi_path = artifact_root / "asyncapi"
    asyncapi_path.write_text(
        dedent(
            """
            asyncapi: 3.0.0
            info:
              title: Acme Events
              contact:
                email: async-owner@acme.example
            servers:
              production:
                host: async.acme.example
                protocol: https
                url: https://async.acme.example/events
              hostOnly:
                host: async-hostonly.acme.example/events
                protocol: https
            x-bucket: s3://acme-asyncapi-bucket/schemas/events.yaml
            """
        ).strip(),
        encoding="utf-8",
    )

    bundle_path = artifact_root / "interface-schema-bundle.zip"
    with zipfile.ZipFile(bundle_path, "w") as zf:
        zf.writestr(
            "avro/user.avsc",
            json.dumps(
                {
                    "type": "record",
                    "name": "User",
                    "doc": (
                        "avro-owner@acme.example "
                        "https://avro.acme.example/schema "
                        "https://avroworkspace.supabase.co/rest/v1/users"
                    ),
                    "fields": [{"name": "id", "type": "string"}],
                },
                indent=2,
            ),
        )
        zf.writestr(
            "thrift/account.thrift",
            dedent(
                """
                namespace py acme.account
                // owner thrift-owner@acme.example
                // endpoint https://thrift.acme.example/rpc
                // reports gs://acme-thrift-gcs/reports/latest.json
                service AccountService {
                  string lookup(1:string id)
                }
                """
            ).strip(),
        )
        zf.writestr(
            "graphql/schema.graphqls",
            dedent(
                """
                # graphqls-owner@acme.example
                # https://graphqls.acme.example/schema
                type Query { viewer: User }
                type User { id: ID! }
                """
            ).strip(),
        )

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued >= 3
    assert summary.processed >= 3
    assert summary.discovered_seeds >= 8

    con = sqlite3.connect(db_path)
    try:
        emails = {
            row[0]
            for row in con.execute("SELECT email FROM emails WHERE engagement_id=1001").fetchall()
        }
        assert "proto-owner@acme.example" in emails
        assert "async-owner@acme.example" in emails
        assert "avro-owner@acme.example" in emails
        assert "thrift-owner@acme.example" in emails
        assert "graphqls-owner@acme.example" in emails

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
        assert ("https://proto.acme.example/grpc", "url") in seeds
        assert ("https://proto-hostonly.acme.example/grpc", "url") in seeds
        assert ("https://async.acme.example/events", "url") in seeds
        assert ("https://async-hostonly.acme.example/events", "url") in seeds
        assert ("https://avro.acme.example/schema", "url") in seeds
        assert ("https://thrift.acme.example/rpc", "url") in seeds
        assert ("https://graphqls.acme.example/schema", "url") in seeds
        assert ("proto-owner@acme.example", "email") in seeds
        assert ("async-owner@acme.example", "email") in seeds

        cloud_assets = con.execute(
            """
            SELECT asset_type, identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert ("aws_s3", "acme-asyncapi-bucket") in cloud_assets
        assert ("firebase", "proto-firebase") in cloud_assets
        assert ("gcs", "acme-thrift-gcs") in cloud_assets
        assert ("supabase", "avroworkspace") in cloud_assets

        artifact_meta = {
            row[0]: json.loads(str(row[1] or "{}"))
            for row in con.execute(
                """
                SELECT source_url, metadata_json
                FROM artifact_queue
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
        assert artifact_meta[proto_path.resolve().as_posix()]["format"] == "proto"
        assert artifact_meta[asyncapi_path.resolve().as_posix()]["format"] == "asyncapi"
        assert artifact_meta[bundle_path.resolve().as_posix()]["format"] == "zip"
        assert artifact_meta[bundle_path.resolve().as_posix()]["payload_count"] >= 3
    finally:
        con.close()
