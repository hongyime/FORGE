from __future__ import annotations

import json
import sqlite3
import zipfile
from pathlib import Path
from textwrap import dedent
from typing import Callable

from forge.engagement_orchestrator import ArtifactQueueProcessor


def run_queue_processor_extracts_http_and_graphql_text_artifacts(
    tmp_path: Path,
    bootstrap_engagement: Callable[[Path], None],
) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_http_graphql"
    artifact_root.mkdir()
    bootstrap_engagement(db_path)

    http_path = artifact_root / "session.http"
    http_path.write_text(
        """
        @baseUrl = http-env.acme.example/api
        GET http-hostonly.acme.example/v1/users HTTP/1.1
        Host: http-host-header.acme.example

        POST https://http.acme.example/api/session
        Content-Type: application/json
        X-Owner: http-owner@acme.example

        {
          "email": "http-body@acme.example",
          "redirect": "https://http-body.acme.example/review",
          "bucket": "s3://acme-http-bucket/reports/latest.pdf"
        }
        """.strip(),
        encoding="utf-8",
    )

    hurl_path = artifact_root / "session.hurl"
    hurl_path.write_text(
        """
        apiHost: hurl-env.acme.example/api
        GET hurl-hostonly.acme.example/v1/users
        X-Owner: hurl-owner@acme.example
        HTTP 200

        POST https://hurl-live.acme.example/v2/session
        GET {{apiHost}}/users
        """.strip(),
        encoding="utf-8",
    )

    graphql_path = artifact_root / "schema.graphql"
    graphql_path.write_text(
        """
        query ViewerProfile {
          viewer(email: "graphql-owner@acme.example") {
            profileUrl
            backupUrl
          }
        }

        # https://graphql.acme.example/portal
        # https://graphql-firebase.firebaseio.com
        # https://graphqlworkspace.supabase.co
        # eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImdyYXBocWx3b3Jrc3BhY2UiLCJyb2xlIjoiYW5vbiJ9.signature444
        """.strip(),
        encoding="utf-8",
    )

    graphql_rc_path = artifact_root / ".graphqlrc.yml"
    graphql_rc_path.write_text(
        dedent(
            """
            schema: graphql-config.acme.example/graphql
            extensions:
              endpoints:
                prod:
                  url: graphql-endpoint.acme.example/api
            """
        ).strip(),
        encoding="utf-8",
    )

    graphql_config_path = artifact_root / "graphql.config.json"
    graphql_config_path.write_text(
        json.dumps(
            {
                "schema": "graphql-json.acme.example/schema",
                "extensions": {
                    "endpoints": {"prod": {"url": "graphql-json-endpoint.acme.example/graphql"}}
                },
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    graphql_codegen_path = artifact_root / "graphql-codegen.yml"
    graphql_codegen_path.write_text(
        dedent(
            """
            schema: codegen-hostonly.acme.example/graphql
            documents: src/**/*.graphql
            generates:
              src/generated.ts:
                plugins:
                  - typescript
            """
        ).strip(),
        encoding="utf-8",
    )

    apollo_config_path = artifact_root / "apollo.config.json"
    apollo_config_path.write_text(
        json.dumps(
            {
                "client": {
                    "service": {
                        "url": "apollo-hostonly.acme.example/graphql",
                    }
                }
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    archive_path = artifact_root / "api-definitions.zip"
    with zipfile.ZipFile(archive_path, "w") as zf:
        zf.writestr(
            "requests/nested.rest",
            """
            baseUrl=rest-env.acme.example/api
            GET rest-hostonly.acme.example/v1/users
            GET https://nested-http.acme.example/health
            X-Contact: nested-http@acme.example
            """.strip(),
        )
        zf.writestr(
            "queries/nested.gql",
            """
            mutation UpdateTenant {
              updateTenant(email: "nested-graphql@acme.example")
            }

            # https://nested-graphql.acme.example/panel
            """.strip(),
        )

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued >= 8
    assert summary.processed >= 8
    assert summary.firebase_projects >= 1
    assert summary.supabase_configs >= 1
    assert summary.discovered_seeds >= 9

    con = sqlite3.connect(db_path)
    try:
        emails = {
            row[0]
            for row in con.execute("SELECT email FROM emails WHERE engagement_id=1001").fetchall()
        }
        assert "http-owner@acme.example" in emails
        assert "http-body@acme.example" in emails
        assert "hurl-owner@acme.example" in emails
        assert "graphql-owner@acme.example" in emails
        assert "nested-http@acme.example" in emails
        assert "nested-graphql@acme.example" in emails

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
        assert ("https://http.acme.example/api/session", "url") in seeds
        assert ("https://http-env.acme.example/api", "url") in seeds
        assert ("https://http-hostonly.acme.example/v1/users", "url") in seeds
        assert ("https://http-host-header.acme.example", "url") in seeds
        assert ("https://http-body.acme.example/review", "url") in seeds
        assert ("https://hurl-env.acme.example/api", "url") in seeds
        assert ("https://hurl-hostonly.acme.example/v1/users", "url") in seeds
        assert ("https://hurl-live.acme.example/v2/session", "url") in seeds
        assert ("{{apiHost}}/users", "url") not in seeds
        assert ("https://graphql.acme.example/portal", "url") in seeds
        assert ("https://graphql-config.acme.example/graphql", "url") in seeds
        assert ("https://graphql-endpoint.acme.example/api", "url") in seeds
        assert ("https://graphql-json.acme.example/schema", "url") in seeds
        assert ("https://graphql-json-endpoint.acme.example/graphql", "url") in seeds
        assert ("https://codegen-hostonly.acme.example/graphql", "url") in seeds
        assert ("https://apollo-hostonly.acme.example/graphql", "url") in seeds
        assert ("https://rest-env.acme.example/api", "url") in seeds
        assert ("https://rest-hostonly.acme.example/v1/users", "url") in seeds
        assert ("https://nested-http.acme.example/health", "url") in seeds
        assert ("https://nested-graphql.acme.example/panel", "url") in seeds
        assert ("hurl-owner@acme.example", "email") in seeds
        assert ("graphql-owner@acme.example", "email") in seeds
        assert ("nested-graphql@acme.example", "email") in seeds

        cloud_assets = con.execute(
            """
            SELECT asset_type, identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert ("aws_s3", "acme-http-bucket") in cloud_assets
        assert ("firebase", "graphql-firebase") in cloud_assets
        assert ("supabase", "graphqlworkspace") in cloud_assets

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
        assert artifact_meta[http_path.resolve().as_posix()]["format"] == "http"
        assert artifact_meta[hurl_path.resolve().as_posix()]["format"] == "hurl"
        assert artifact_meta[graphql_rc_path.resolve().as_posix()]["format"] == "graphql-config"
        assert artifact_meta[graphql_config_path.resolve().as_posix()]["format"] == "graphql-config"
        assert (
            artifact_meta[graphql_codegen_path.resolve().as_posix()]["format"] == "graphql-codegen"
        )
        assert artifact_meta[apollo_config_path.resolve().as_posix()]["format"] == "apollo-config"
    finally:
        con.close()
