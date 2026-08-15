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
  NEXT_PUBLIC_SUPABASE_PROJECT_REF: "runtimevault",
  NEXT_PUBLIC_SANITY_PROJECT_ID: "runtimecms123",
  NEXT_PUBLIC_SANITY_DATASET: "production"
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

_DENO_CONFIG_PAYLOAD = """
{
  "imports": {
    "@std/http": "https://deno.land/std@0.224.0/http/server.ts",
    "@acme/api": "jsr:@acme/api@1.2.3",
    "oak": "npm:@oak/oak@12.6.1",
    "ignoredTemplate": "https://{{tenant}}.example.invalid/mod.ts",
    "credentialed": "https://deno-user:deno-token-do-not-store@deno-private.acme.example/mod.ts"
  },
  "deploy": {
    "apiUrl": "https://deno-api.acme.example/v1"
  }
}
""".strip()

_DENO_LOCK_PAYLOAD = """
{
  "version": "4",
  "specifiers": {
    "jsr:@acme/worker@1.2.3": "1.2.3",
    "npm:@hono/node-server@1.13.8": "1.13.8"
  },
  "remote": {
    "https://deno.land/x/oak@v12.6.1/mod.ts": "sha256-old",
    "https://deno-user:deno-lock-token-do-not-store@deno-lock-private.acme.example/mod.ts": "sha256-private"
  },
  "workspaceEndpoint": "https://deno-lock-api.acme.example/v1"
}
""".strip()

_MONOREPO_BUILD_CONFIG_PAYLOADS = {
    "turbo.json": """
{
  "$schema": "https://turbo.build/schema.json",
  "remoteCache": {
    "apiUrl": "https://turbo-user:turbo-token-do-not-store@turbo-cache.acme.example/v8",
    "loginUrl": "https://turbo-login.acme.example/login"
  },
  "team": "acme",
  "owner": "turbo-owner@acme.example"
}
""".strip(),
    "nx.json": """
{
  "tasksRunnerOptions": {
    "default": {
      "runner": "nx/tasks-runners/default",
      "options": {
        "url": "https://nx-user:nx-token-do-not-store@nx-cache.acme.example/cache",
        "apiUrl": "https://nx-api.acme.example/v1"
      }
    }
  },
  "owner": "nx-owner@acme.example"
}
""".strip(),
}


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
    assert processor._js_runtime_text_structured_payload_text(
        _RUNTIME_ENV_PAYLOAD,
        source_hint="public/runtime-env.js",
    ).splitlines() == [
        "https://api.runtime.acme.example",
        "https://runtime-api.acme.example/v1",
        "https://runtime-firebase.firebaseio.com",
        "https://runtimevault.supabase.co",
        "https://runtimecms123.api.sanity.io",
    ]
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
    assert processor._js_runtime_text_structured_payload_text(
        _SERVICE_WORKER_PAYLOAD,
        source_hint="public/service-worker.js",
    ).splitlines() == [
        "https://cdn.acme.example/sw-lib.js",
        "https://static.acme.example/workbox-helper.js",
        "https://acme-prod.firebaseio.com",
        "https://api.acme.example/v1",
    ]
    assert (
        processor._js_runtime_text_structured_payload_text(
            _SERVICE_WORKER_PAYLOAD,
            source_hint="public/app.js",
        )
        == ""
    )


def test_service_worker_js_resolves_relative_imports_from_remote_source(
    tmp_path: Path,
) -> None:
    processor = ArtifactQueueProcessor(tmp_path / "engagement.db", 1001)
    payload = """
    importScripts("/precache-manifest.abc123.js", "./workbox-helper.js", "data:text/plain,nope");
    """.strip()

    assert processor._js_runtime_text_structured_payload_text(
        payload,
        source_hint="https://app.acme.example/service-worker.js",
        base_url="https://app.acme.example/service-worker.js",
    ).splitlines() == [
        "https://app.acme.example/precache-manifest.abc123.js",
        "https://app.acme.example/workbox-helper.js",
    ]
    assert (
        processor._js_runtime_text_structured_payload_text(
            payload,
            source_hint="public/service-worker.js",
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
    assert ("https://runtimecms123.api.sanity.io", "url") in seeds
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


def test_monorepo_build_configs_extract_remote_cache_endpoints(tmp_path: Path) -> None:
    processor = ArtifactQueueProcessor(tmp_path / "engagement.db", 1001)

    assert _artifact_format_label("turbo.json") == "turbo-config"
    assert _artifact_format_label("nx.json") == "nx-config"
    assert processor._js_runtime_text_structured_payload_text(
        _MONOREPO_BUILD_CONFIG_PAYLOADS["turbo.json"],
        source_hint="turbo.json",
    ).splitlines() == [
        "https://turbo-cache.acme.example/v8",
        "https://turbo-login.acme.example/login",
    ]
    assert processor._js_runtime_text_structured_payload_text(
        _MONOREPO_BUILD_CONFIG_PAYLOADS["nx.json"],
        source_hint="nx.json",
    ).splitlines() == [
        "https://nx-cache.acme.example/cache",
        "https://nx-api.acme.example/v1",
    ]
    assert (
        processor._js_runtime_text_structured_payload_text(
            _MONOREPO_BUILD_CONFIG_PAYLOADS["turbo.json"],
            source_hint="notes.json",
        )
        == ""
    )


def test_monorepo_build_config_artifacts_recurse_without_persisting_userinfo(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "monorepo"
    artifact_root.mkdir()
    bootstrap_engagement(db_path, name="Monorepo Build Config Recursion Test")
    for filename, payload in _MONOREPO_BUILD_CONFIG_PAYLOADS.items():
        (artifact_root / filename).write_text(payload, encoding="utf-8")

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued == 2
    assert summary.processed == 2

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
        artifact_meta = {
            row[0]: row[1]
            for row in con.execute(
                """
                SELECT source_url, metadata_json
                FROM artifact_queue
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
        persisted_text = "\n".join(con.iterdump())
    finally:
        con.close()

    assert ("https://turbo-cache.acme.example/v8", "url") in seeds
    assert ("https://turbo-login.acme.example/login", "url") in seeds
    assert ("https://nx-cache.acme.example/cache", "url") in seeds
    assert ("https://nx-api.acme.example/v1", "url") in seeds
    assert ("turbo-owner@acme.example", "email") in seeds
    assert ("nx-owner@acme.example", "email") in seeds
    assert artifact_meta[(artifact_root / "turbo.json").resolve().as_posix()]
    assert artifact_meta[(artifact_root / "nx.json").resolve().as_posix()]
    assert "turbo-token-do-not-store" not in persisted_text
    assert "nx-token-do-not-store" not in persisted_text


def test_deno_config_extracts_static_imports_and_endpoints(tmp_path: Path) -> None:
    processor = ArtifactQueueProcessor(tmp_path / "engagement.db", 1001)

    assert _artifact_format_label("deno.json") == "deno-config"
    assert _artifact_format_label("deno.jsonc") == "deno-config"
    assert _artifact_format_label("import_map.json") == "deno-import-map"
    assert _artifact_format_label("jsr.json") == "jsr-config"
    assert _artifact_format_label("notes.json") == "json"
    assert processor._js_runtime_text_structured_payload_text(
        _DENO_CONFIG_PAYLOAD,
        source_hint="deno.json",
    ).splitlines() == [
        "https://deno.land/std@0.224.0/http/server.ts",
        "https://jsr.io/@acme/api",
        "https://www.npmjs.com/package/@oak/oak",
        "https://deno-private.acme.example/mod.ts",
        "https://deno-api.acme.example/v1",
    ]
    assert (
        processor._js_runtime_text_structured_payload_text(
            _DENO_CONFIG_PAYLOAD,
            source_hint="notes.json",
        )
        == ""
    )


def test_deno_config_artifact_recurses_without_persisting_userinfo(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "deno-app"
    artifact_root.mkdir()
    bootstrap_engagement(db_path, name="Deno Config Recursion Test")
    (artifact_root / "deno.json").write_text(_DENO_CONFIG_PAYLOAD, encoding="utf-8")

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
        artifact_meta = {
            row[0]: row[1]
            for row in con.execute(
                """
                SELECT source_url, metadata_json
                FROM artifact_queue
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
        persisted_text = "\n".join(con.iterdump())
    finally:
        con.close()

    assert ("https://deno.land/std@0.224.0/http/server.ts", "url") in seeds
    assert ("https://www.npmjs.com/package/@oak/oak", "url") in seeds
    assert ("https://jsr.io/@acme/api", "url") in seeds
    assert ("https://deno-private.acme.example/mod.ts", "url") in seeds
    assert ("https://deno-api.acme.example/v1", "url") in seeds
    assert artifact_meta[(artifact_root / "deno.json").resolve().as_posix()]
    assert "deno-token-do-not-store" not in persisted_text


def test_deno_lock_artifact_recurses_static_modules_without_persisting_userinfo(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "deno-lock-app"
    artifact_root.mkdir()
    bootstrap_engagement(db_path, name="Deno Lock Recursion Test")
    deno_lock_path = artifact_root / "deno.lock"
    deno_lock_path.write_text(_DENO_LOCK_PAYLOAD, encoding="utf-8")

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
        artifact_meta = {
            row[0]: row[1]
            for row in con.execute(
                """
                SELECT source_url, metadata_json
                FROM artifact_queue
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
        persisted_text = "\n".join(con.iterdump())
    finally:
        con.close()

    assert ("https://deno.land/x/oak@v12.6.1/mod.ts", "url") in seeds
    assert ("https://jsr.io/@acme/worker", "url") in seeds
    assert ("https://www.npmjs.com/package/@hono/node-server", "url") in seeds
    assert ("https://deno-lock-private.acme.example/mod.ts", "url") in seeds
    assert ("https://deno-lock-api.acme.example/v1", "url") in seeds
    assert artifact_meta[deno_lock_path.resolve().as_posix()]
    assert "deno-lock-token-do-not-store" not in persisted_text
