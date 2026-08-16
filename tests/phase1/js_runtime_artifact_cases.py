from __future__ import annotations

import json
import sqlite3
import struct
import zipfile
from pathlib import Path
from textwrap import dedent
from typing import Any

from forge.engagement_orchestrator import ArtifactQueueProcessor
from tests.phase1.artifact_test_support import bootstrap_engagement


def _asar_bytes(members: list[tuple[str, bytes]]) -> bytes:
    header_files: dict[str, Any] = {}
    content = bytearray()
    for raw_member_name, payload in members:
        parts = [part for part in str(raw_member_name).split("/") if part]
        if not parts:
            continue
        cursor = header_files
        for part in parts[:-1]:
            entry = cursor.setdefault(part, {"files": {}})
            cursor = entry["files"]
        cursor[parts[-1]] = {"size": len(payload), "offset": str(len(content))}
        content.extend(payload)

    header_json = json.dumps({"files": header_files}, separators=(",", ":")).encode()
    padding = b"\x00" * ((4 - (len(header_json) % 4)) % 4)
    header_size = 4 + len(header_json) + len(padding)
    return (
        struct.pack("<II", header_size, len(header_json)) + header_json + padding + bytes(content)
    )


def run_queue_processor_extracts_electron_asar_static_artifacts(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_asar"
    artifact_root.mkdir()
    bootstrap_engagement(db_path)

    asar_path = artifact_root / "app.asar"
    asar_path.write_bytes(
        _asar_bytes(
            [
                (
                    "app/main.js",
                    dedent(
                        """
                        const owner = "asar-owner@acme.example";
                        const apiBase = "https://electron.acme.example/api";
                        const firebase = "https://asar-firebase.firebaseio.com";
                        const supabase = "https://asarworkspace.supabase.co/rest/v1/events";
                        const releaseBucket = "s3://acme-asar-bucket/releases/app.asar";
                        const gcs = "gs://acme-asar-gcs/reports/latest.json";
                        const nextArtifact = "https://downloads.acme.example/client.apk";
                        """
                    )
                    .strip()
                    .encode("utf-8"),
                ),
                (
                    "resources/package.json",
                    b'{"maintainer":"asar-package@acme.example","homepage":"https://asar.acme.example"}',
                ),
                ("../escaped.env", b"ESCAPED=escaped-asar@acme.example\n"),
            ]
        )
    )

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued >= 1
    assert summary.processed >= 1
    assert summary.discovered_seeds >= 5

    con = sqlite3.connect(db_path)
    try:
        emails = {
            row[0]
            for row in con.execute("SELECT email FROM emails WHERE engagement_id=1001").fetchall()
        }
        assert "asar-owner@acme.example" in emails
        assert "asar-package@acme.example" in emails
        assert "escaped-asar@acme.example" not in emails

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
        assert ("asar-owner@acme.example", "email") in seeds
        assert ("asar-package@acme.example", "email") in seeds
        assert ("https://electron.acme.example/api", "url") in seeds
        assert ("https://asarworkspace.supabase.co/rest/v1/events", "url") in seeds
        assert ("https://downloads.acme.example/client.apk", "apk_url") in seeds

        cloud_assets = con.execute(
            """
            SELECT asset_type, identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert ("aws_s3", "acme-asar-bucket") in cloud_assets
        assert ("firebase", "asar-firebase") in cloud_assets
        assert ("gcs", "acme-asar-gcs") in cloud_assets
        assert ("supabase", "asarworkspace") in cloud_assets

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
        assert artifact_meta[asar_path.resolve().as_posix()]["format"] == "asar"
        assert artifact_meta[asar_path.resolve().as_posix()]["payload_count"] >= 2
    finally:
        con.close()


def run_queue_processor_extracts_nested_electron_asar_static_artifacts(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_nested_asar"
    artifact_root.mkdir()
    bootstrap_engagement(db_path)

    bundle_path = artifact_root / "electron-release.zip"
    nested_asar = _asar_bytes(
        [
            (
                "dist/preload.js",
                b"\n".join(
                    [
                        b"const owner = 'nested-asar-owner@acme.example';",
                        b"const api = 'https://nested-asar.acme.example/api';",
                        b"const firebase = 'https://nested-asar-firebase.firebaseio.com';",
                        b"const supabase = 'https://nestedasar.supabase.co/rest/v1/events';",
                        b"const bucket = 's3://acme-nested-asar-bucket/releases/app.asar';",
                    ]
                ),
            )
        ]
    )
    with zipfile.ZipFile(bundle_path, "w") as zf:
        zf.writestr("resources/app.asar", nested_asar)

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued >= 1
    assert summary.processed >= 1
    assert summary.discovered_seeds >= 3

    con = sqlite3.connect(db_path)
    try:
        emails = {
            row[0]
            for row in con.execute("SELECT email FROM emails WHERE engagement_id=1001").fetchall()
        }
        assert "nested-asar-owner@acme.example" in emails

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
        assert ("nested-asar-owner@acme.example", "email") in seeds
        assert ("https://nested-asar.acme.example/api", "url") in seeds
        assert ("https://nestedasar.supabase.co/rest/v1/events", "url") in seeds

        cloud_assets = con.execute(
            """
            SELECT asset_type, identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert ("aws_s3", "acme-nested-asar-bucket") in cloud_assets
        assert ("firebase", "nested-asar-firebase") in cloud_assets
        assert ("supabase", "nestedasar") in cloud_assets

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
        assert artifact_meta[bundle_path.resolve().as_posix()]["format"] == "zip"
        assert artifact_meta[bundle_path.resolve().as_posix()]["payload_count"] >= 1
    finally:
        con.close()


def run_js_runtime_text_structured_payload_uses_bounded_workers_and_preserves_order(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    db_path = tmp_path / "engagement.db"
    processor = ArtifactQueueProcessor(db_path, 1001)
    payload = dedent(
        """
        {
          "imports": {
            "@std/assert": "jsr:@std/assert@1",
            "chalk": "npm:chalk@5"
          },
          "publish": {
            "registry": "jsr.acme.example/api"
          }
        }
        """
    ).strip()
    observed_candidate_batches: list[list[str]] = []
    original_batch = ArtifactQueueProcessor._run_ordered_local_batch

    def _tracking_batch(self, items, worker, *, default_factory):  # noqa: ANN001
        materialized = list(items)
        if getattr(worker, "__name__", "") == "_js_runtime_url_candidate_entry":
            observed_candidate_batches.append([str(item) for item in materialized])
        return original_batch(self, materialized, worker, default_factory=default_factory)

    monkeypatch.setattr(ArtifactQueueProcessor, "_run_ordered_local_batch", _tracking_batch)

    result = processor._js_runtime_text_structured_payload_text(
        payload,
        source_hint="deno.jsonc",
    )

    assert observed_candidate_batches == [
        [
            "jsr:@std/assert@1",
            "npm:chalk@5",
            "jsr.acme.example/api",
        ]
    ]
    assert result.splitlines() == [
        "https://jsr.io/@std/assert",
        "https://www.npmjs.com/package/chalk",
        "https://jsr.acme.example/api",
    ]


def run_browser_test_js_runtime_config_promotes_hostonly_urls_with_bounded_workers(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    db_path = tmp_path / "engagement.db"
    processor = ArtifactQueueProcessor(db_path, 1001)
    payload = dedent(
        """
        import { defineConfig } from '@playwright/test';

        export default defineConfig({
          use: {
            baseURL: process.env.BASE_URL || 'playwright-hostonly.acme.example/app',
          },
          webServer: {
            url: "https://playwright-live.acme.example",
          },
          projects: [
            { use: { baseURL: 'https://${tenant}.acme.example/app' } },
            { use: { baseURL: '/relative' } },
          ],
        });
        """
    ).strip()
    observed_candidate_batches: list[list[str]] = []
    original_batch = ArtifactQueueProcessor._run_ordered_local_batch

    def _tracking_batch(self, items, worker, *, default_factory):  # noqa: ANN001
        materialized = list(items)
        if getattr(worker, "__name__", "") == "_js_runtime_url_candidate_entry":
            observed_candidate_batches.append([str(item) for item in materialized])
        return original_batch(self, materialized, worker, default_factory=default_factory)

    monkeypatch.setattr(ArtifactQueueProcessor, "_run_ordered_local_batch", _tracking_batch)

    result = processor._js_runtime_text_structured_payload_text(
        payload,
        source_hint="playwright.config.ts",
    )

    assert observed_candidate_batches == [
        [
            "playwright-hostonly.acme.example/app",
            "https://playwright-live.acme.example",
            "/relative",
        ]
    ]
    assert result.splitlines() == [
        "https://playwright-hostonly.acme.example/app",
        "https://playwright-live.acme.example",
    ]


def run_testcafe_js_runtime_config_promotes_hostonly_urls_with_bounded_workers(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    db_path = tmp_path / "engagement.db"
    processor = ArtifactQueueProcessor(db_path, 1001)
    payload = dedent(
        """
        module.exports = {
          baseUrl: process.env.BASE_URL || 'testcafe-hostonly.acme.example/app',
          appUrl: "https://testcafe-live.acme.example",
          src: "/relative-tests/**/*.js",
          tenantUrl: "https://${tenant}.acme.example/app",
        };
        """
    ).strip()
    observed_candidate_batches: list[list[str]] = []
    original_batch = ArtifactQueueProcessor._run_ordered_local_batch

    def _tracking_batch(self, items, worker, *, default_factory):  # noqa: ANN001
        materialized = list(items)
        if getattr(worker, "__name__", "") == "_js_runtime_url_candidate_entry":
            observed_candidate_batches.append([str(item) for item in materialized])
        return original_batch(self, materialized, worker, default_factory=default_factory)

    monkeypatch.setattr(ArtifactQueueProcessor, "_run_ordered_local_batch", _tracking_batch)

    result = processor._js_runtime_text_structured_payload_text(
        payload,
        source_hint="testcafe.config.ts",
    )

    assert observed_candidate_batches == [
        [
            "testcafe-hostonly.acme.example/app",
            "https://testcafe-live.acme.example",
            "/relative-tests/**/*.js",
        ]
    ]
    assert result.splitlines() == [
        "https://testcafe-hostonly.acme.example/app",
        "https://testcafe-live.acme.example",
    ]


def run_frontend_framework_js_runtime_config_promotes_hostonly_urls_with_bounded_workers(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    db_path = tmp_path / "engagement.db"
    processor = ArtifactQueueProcessor(db_path, 1001)
    payload = dedent(
        """
        import { defineConfig } from 'vite';

        export default defineConfig({
          server: {
            proxy: {
              '/api': {
                target: 'vite-hostonly.acme.example/api',
                changeOrigin: true,
              },
            },
          },
          preview: {
            origin: "https://vite-preview.acme.example",
          },
          build: {
            assets: '/relative-assets',
          },
          test: {
            apiBase: 'https://${tenant}.acme.example/api',
          },
        });
        """
    ).strip()
    observed_candidate_batches: list[list[str]] = []
    original_batch = ArtifactQueueProcessor._run_ordered_local_batch

    def _tracking_batch(self, items, worker, *, default_factory):  # noqa: ANN001
        materialized = list(items)
        if getattr(worker, "__name__", "") == "_js_runtime_url_candidate_entry":
            observed_candidate_batches.append([str(item) for item in materialized])
        return original_batch(self, materialized, worker, default_factory=default_factory)

    monkeypatch.setattr(ArtifactQueueProcessor, "_run_ordered_local_batch", _tracking_batch)

    result = processor._js_runtime_text_structured_payload_text(
        payload,
        source_hint="vite.config.ts",
    )

    assert observed_candidate_batches == [
        [
            "vite-hostonly.acme.example/api",
            "https://vite-preview.acme.example",
            "/relative-assets",
        ]
    ]
    assert result.splitlines() == [
        "https://vite-hostonly.acme.example/api",
        "https://vite-preview.acme.example",
    ]


def run_mobile_and_deploy_runtime_config_promotes_hostonly_urls_with_bounded_workers(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    db_path = tmp_path / "engagement.db"
    processor = ArtifactQueueProcessor(db_path, 1001)
    observed_candidate_batches: list[list[str]] = []
    original_batch = ArtifactQueueProcessor._run_ordered_local_batch

    def _tracking_batch(self, items, worker, *, default_factory):  # noqa: ANN001
        materialized = list(items)
        if getattr(worker, "__name__", "") == "_js_runtime_url_candidate_entry":
            observed_candidate_batches.append([str(item) for item in materialized])
        return original_batch(self, materialized, worker, default_factory=default_factory)

    monkeypatch.setattr(ArtifactQueueProcessor, "_run_ordered_local_batch", _tracking_batch)

    expo_payload = dedent(
        """
        export default {
          expo: {
            updates: { url: 'expo-updates.acme.example/update' },
            extra: {
              apiBase: process.env.API_URL || 'expo-api.acme.example/v1',
              relativeUrl: '/ignored',
              tenantUrl: 'https://${tenant}.acme.example/app',
            },
          },
        };
        """
    ).strip()
    capacitor_payload = dedent(
        """
        export default {
          server: { url: "capacitor-api.acme.example/mobile" },
          appUrl: "/relative",
        };
        """
    ).strip()
    cordova_payload = dedent(
        """
        <widget id="com.acme.mobile">
          <content src="cordova-api.acme.example/app" />
          <access origin="https://${tenant}.acme.example/mobile" />
          <allow-navigation href="/relative" />
        </widget>
        """
    ).strip()
    vercel_payload = (
        '{"rewrites":[{"source":"/api/(.*)","destination":"vercel-api.acme.example/status"}]}'
    )
    netlify_payload = '[[redirects]]\nfrom = "/api/*"\nto = "netlify-edge.acme.example/status"\n'

    assert processor._js_runtime_text_structured_payload_text(
        expo_payload,
        source_hint="app.config.ts",
    ).splitlines() == [
        "https://expo-updates.acme.example/update",
        "https://expo-api.acme.example/v1",
    ]
    assert processor._js_runtime_text_structured_payload_text(
        capacitor_payload,
        source_hint="capacitor.config.ts",
    ).splitlines() == ["https://capacitor-api.acme.example/mobile"]
    assert processor._js_runtime_text_structured_payload_text(
        cordova_payload,
        source_hint="cordova/config.xml",
    ).splitlines() == ["https://cordova-api.acme.example/app"]
    assert processor._js_runtime_text_structured_payload_text(
        vercel_payload,
        source_hint="vercel.json",
    ).splitlines() == ["https://vercel-api.acme.example/status"]
    assert processor._js_runtime_text_structured_payload_text(
        netlify_payload,
        source_hint="netlify.toml",
    ).splitlines() == ["https://netlify-edge.acme.example/status"]

    assert observed_candidate_batches == [
        [
            "expo-updates.acme.example/update",
            "expo-api.acme.example/v1",
        ],
        ["capacitor-api.acme.example/mobile", "/relative"],
        [
            "cordova-api.acme.example/app",
            "/relative",
        ],
        ["vercel-api.acme.example/status"],
        ["netlify-edge.acme.example/status"],
    ]
