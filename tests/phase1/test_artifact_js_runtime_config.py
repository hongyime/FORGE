from __future__ import annotations

import sqlite3
from pathlib import Path

from forge.engagement_orchestrator import ArtifactQueueProcessor
from forge.engagement_orchestrator import _artifact_format_label
from tests.phase1.artifact_test_support import bootstrap_engagement


_RUNTIME_ENV_PAYLOAD = """
window.__ENV__ = {
  API_HOST: "api.runtime.acme.example",
  API_BASE: "runtime-api.acme.example/v1",
  FIREBASE_PROJECT_ID: "runtime-firebase",
  NEXT_PUBLIC_SUPABASE_PROJECT_REF: "runtimevault"
};
""".strip()

_SERVICE_WORKER_PAYLOAD = """
importScripts(
  "https://cdn.acme.example/sw-lib.js",
  "https://static.acme.example/workbox-helper.js"
);
firebase.initializeApp({
  projectId: "acme-prod",
  messagingSenderId: "1234567890"
});
self.__CONFIG__ = { apiUrl: "https://api.acme.example/v1" };
""".strip()


def test_bun_scope_candidate_values_do_not_reuse_stale_registry_value(tmp_path) -> None:
    processor = ArtifactQueueProcessor(tmp_path / "engagement.db", 1001)
    payload = """
registry = "registry.npmjs.org"

[install.scopes]
# comment-only line must not reuse the registry candidate
@acme = "npm.pkg.github.com/acme"
""".strip()

    assert processor._js_runtime_text_candidate_values(
        payload,
        source_label="bunfig",
    ) == [
        "registry.npmjs.org",
        "npm.pkg.github.com/acme",
    ]


def test_runtime_js_config_extracts_env_hosts_and_cloud_refs(tmp_path: Path) -> None:
    processor = ArtifactQueueProcessor(tmp_path / "engagement.db", 1001)

    assert _artifact_format_label("public/runtime-env.js") == "runtime-js-config"
    assert _artifact_format_label("public/config.js") == "runtime-js-config"
    assert _artifact_format_label("config.js") == "js"
    assert (
        processor._js_runtime_text_structured_payload_text(
            _RUNTIME_ENV_PAYLOAD,
            source_hint="public/runtime-env.js",
        ).splitlines()
        == [
            "https://api.runtime.acme.example",
            "https://runtime-api.acme.example/v1",
            "https://runtime-firebase.firebaseio.com",
            "https://runtimevault.supabase.co",
        ]
    )
    assert (
        processor._js_runtime_text_structured_payload_text(
            _RUNTIME_ENV_PAYLOAD,
            source_hint="public/notes.js",
        )
        == ""
    )
    assert (
        processor._js_runtime_text_structured_payload_text(
            _RUNTIME_ENV_PAYLOAD,
            source_hint="config.js",
        )
        == ""
    )


def test_service_worker_js_extracts_public_imports_and_cloud_refs(tmp_path: Path) -> None:
    processor = ArtifactQueueProcessor(tmp_path / "engagement.db", 1001)

    assert _artifact_format_label("public/service-worker.js") == "service-worker-js"
    assert _artifact_format_label("public/workbox-abc123.js") == "service-worker-js"
    assert _artifact_format_label("public/precache-manifest.abc123.js") == "service-worker-js"
    assert _artifact_format_label("public/firebase-messaging-sw.js") == "service-worker-js"
    assert _artifact_format_label("public/app.js") == "js"
    assert (
        processor._js_runtime_text_structured_payload_text(
            _SERVICE_WORKER_PAYLOAD,
            source_hint="public/service-worker.js",
        ).splitlines()
        == [
            "https://cdn.acme.example/sw-lib.js",
            "https://static.acme.example/workbox-helper.js",
            "https://acme-prod.firebaseio.com",
            "https://api.acme.example/v1",
        ]
    )
    assert (
        processor._js_runtime_text_structured_payload_text(
            _SERVICE_WORKER_PAYLOAD,
            source_hint="public/app.js",
        )
        == ""
    )


def test_runtime_js_config_artifact_recurses_public_endpoints_and_cloud_refs(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "public"
    artifact_root.mkdir()
    bootstrap_engagement(db_path, name="Runtime JS Config Test")
    (artifact_root / "runtime-env.js").write_text(_RUNTIME_ENV_PAYLOAD, encoding="utf-8")

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued == 1
    assert summary.processed == 1

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
        cloud_assets = {
            (row[0], row[1], row[2])
            for row in con.execute(
                """
                SELECT asset_type, identifier, provider_identifier
                FROM cloud_assets
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
    finally:
        con.close()

    assert ("https://api.runtime.acme.example", "url") in seeds
    assert ("https://runtime-api.acme.example/v1", "url") in seeds
    assert ("firebase", "runtime-firebase", "runtime-firebase") in cloud_assets
    assert ("supabase", "runtimevault", "runtimevault") in cloud_assets


def test_service_worker_artifact_recurses_public_imports_and_cloud_refs(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "public"
    artifact_root.mkdir()
    bootstrap_engagement(db_path, name="Service Worker Recursion Test")
    (artifact_root / "service-worker.js").write_text(
        _SERVICE_WORKER_PAYLOAD,
        encoding="utf-8",
    )

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued == 1
    assert summary.processed == 1

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
        cloud_assets = {
            (row[0], row[1], row[2])
            for row in con.execute(
                """
                SELECT asset_type, identifier, provider_identifier
                FROM cloud_assets
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
    finally:
        con.close()

    assert ("https://cdn.acme.example/sw-lib.js", "url") in seeds
    assert ("https://api.acme.example/v1", "url") in seeds
    assert ("firebase", "acme-prod", "acme-prod") in cloud_assets
