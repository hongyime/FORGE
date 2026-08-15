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

_BUNDLER_CONFIG_PAYLOADS = {
    "webpack.config.mjs": """
export default {
  owner: "webpack-owner@acme.example",
  output: {
    publicPath: "https://webpack-user:webpack-token-do-not-store@webpack-cdn.acme.example/assets/"
  },
  devServer: {
    proxy: {
      "/api": {
        target: "webpack-api.acme.example/v1"
      }
    }
  }
};
""".strip(),
    "rollup.config.js": """
export default {
  owner: "rollup-owner@acme.example",
  output: {
    assetFileNames: "assets/[name]-[hash][extname]",
    sourcemapBaseUrl: "https://rollup-cdn.acme.example/maps/"
  },
  plugins: [
    publish({ url: "https://rollup-user:rollup-token-do-not-store@rollup-api.acme.example/upload" })
  ]
};
""".strip(),
    "rspack.config.ts": """
export default {
  owner: "rspack-owner@acme.example",
  output: {
    publicPath: "rspack-cdn.acme.example/assets/"
  },
  devServer: {
    client: {
      webSocketURL: "https://rspack-live.acme.example/ws"
    }
  }
};
""".strip(),
    "rsbuild.config.mjs": """
export default {
  owner: "rsbuild-owner@acme.example",
  source: {
    define: {
      API_URL: "https://rsbuild-api.acme.example/v1"
    }
  },
  output: {
    assetPrefix: "https://rsbuild-cdn.acme.example/assets/"
  }
};
""".strip(),
}

_TEST_RUNNER_CONFIG_PAYLOADS = {
    "vitest.config.ts": """
export default {
  owner: "vitest-owner@acme.example",
  test: {
    apiUrl: "https://vitest-user:vitest-token-do-not-store@vitest-api.acme.example/v1",
    coverage: {
      reporterUrl: "https://vitest-coverage.acme.example/report"
    }
  }
};
""".strip(),
    "jest.config.cjs": """
module.exports = {
  owner: "jest-owner@acme.example",
  testEnvironmentOptions: {
    url: "https://jest-app.acme.example"
  },
  reporters: [
    ["jest-junit", { outputUrl: "https://jest-report.acme.example/junit" }]
  ]
};
""".strip(),
    "karma.conf.js": """
module.exports = function(config) {
  config.set({
    owner: "karma-owner@acme.example",
    proxies: {
      "/api": {
        target: "https://karma-user:karma-token-do-not-store@karma-api.acme.example/v1"
      }
    },
    client: {
      serverUrl: "karma-dashboard.acme.example/run"
    }
  });
};
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


def test_bundler_configs_extract_static_public_endpoints(tmp_path: Path) -> None:
    processor = ArtifactQueueProcessor(tmp_path / "engagement.db", 1001)

    assert _artifact_format_label("webpack.config.mjs") == "webpack-config"
    assert _artifact_format_label("rollup.config.js") == "rollup-config"
    assert _artifact_format_label("rspack.config.ts") == "rspack-config"
    assert _artifact_format_label("rsbuild.config.mjs") == "rsbuild-config"
    assert processor._js_runtime_text_structured_payload_text(
        _BUNDLER_CONFIG_PAYLOADS["webpack.config.mjs"],
        source_hint="webpack.config.mjs",
    ).splitlines() == [
        "https://webpack-cdn.acme.example/assets/",
        "https://webpack-api.acme.example/v1",
    ]
    assert processor._js_runtime_text_structured_payload_text(
        _BUNDLER_CONFIG_PAYLOADS["rollup.config.js"],
        source_hint="rollup.config.js",
    ).splitlines() == [
        "https://rollup-cdn.acme.example/maps/",
        "https://rollup-api.acme.example/upload",
    ]
    assert processor._js_runtime_text_structured_payload_text(
        _BUNDLER_CONFIG_PAYLOADS["rspack.config.ts"],
        source_hint="rspack.config.ts",
    ).splitlines() == [
        "https://rspack-cdn.acme.example/assets/",
        "https://rspack-live.acme.example/ws",
    ]
    assert processor._js_runtime_text_structured_payload_text(
        _BUNDLER_CONFIG_PAYLOADS["rsbuild.config.mjs"],
        source_hint="rsbuild.config.mjs",
    ).splitlines() == [
        "https://rsbuild-api.acme.example/v1",
        "https://rsbuild-cdn.acme.example/assets/",
    ]
    assert (
        processor._js_runtime_text_structured_payload_text(
            _BUNDLER_CONFIG_PAYLOADS["webpack.config.mjs"],
            source_hint="webpack.notes.mjs",
        )
        == ""
    )


def test_bundler_config_artifacts_recurse_without_persisting_userinfo(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "bundlers"
    artifact_root.mkdir()
    bootstrap_engagement(db_path, name="Bundler Config Recursion Test")
    for filename, payload in _BUNDLER_CONFIG_PAYLOADS.items():
        (artifact_root / filename).write_text(payload, encoding="utf-8")

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued == 4
    assert summary.processed == 4

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

    for expected_seed in {
        ("https://webpack-cdn.acme.example/assets/", "url"),
        ("https://webpack-api.acme.example/v1", "url"),
        ("https://rollup-cdn.acme.example/maps/", "url"),
        ("https://rollup-api.acme.example/upload", "url"),
        ("https://rspack-cdn.acme.example/assets/", "url"),
        ("https://rspack-live.acme.example/ws", "url"),
        ("https://rsbuild-api.acme.example/v1", "url"),
        ("https://rsbuild-cdn.acme.example/assets/", "url"),
        ("webpack-owner@acme.example", "email"),
        ("rollup-owner@acme.example", "email"),
        ("rspack-owner@acme.example", "email"),
        ("rsbuild-owner@acme.example", "email"),
    }:
        assert expected_seed in seeds
    for filename in _BUNDLER_CONFIG_PAYLOADS:
        assert artifact_meta[(artifact_root / filename).resolve().as_posix()]
    assert "webpack-token-do-not-store" not in persisted_text
    assert "rollup-token-do-not-store" not in persisted_text


def test_test_runner_configs_extract_static_public_endpoints(tmp_path: Path) -> None:
    processor = ArtifactQueueProcessor(tmp_path / "engagement.db", 1001)

    assert _artifact_format_label("vitest.config.ts") == "vitest-config"
    assert _artifact_format_label("jest.config.cjs") == "jest-config"
    assert _artifact_format_label("karma.conf.js") == "karma-config"
    assert processor._js_runtime_text_structured_payload_text(
        _TEST_RUNNER_CONFIG_PAYLOADS["vitest.config.ts"],
        source_hint="vitest.config.ts",
    ).splitlines() == [
        "https://vitest-api.acme.example/v1",
        "https://vitest-coverage.acme.example/report",
    ]
    assert processor._js_runtime_text_structured_payload_text(
        _TEST_RUNNER_CONFIG_PAYLOADS["jest.config.cjs"],
        source_hint="jest.config.cjs",
    ).splitlines() == [
        "https://jest-app.acme.example",
        "https://jest-report.acme.example/junit",
    ]
    assert processor._js_runtime_text_structured_payload_text(
        _TEST_RUNNER_CONFIG_PAYLOADS["karma.conf.js"],
        source_hint="karma.conf.js",
    ).splitlines() == [
        "https://karma-api.acme.example/v1",
        "https://karma-dashboard.acme.example/run",
    ]
    assert (
        processor._js_runtime_text_structured_payload_text(
            _TEST_RUNNER_CONFIG_PAYLOADS["vitest.config.ts"],
            source_hint="vitest.notes.ts",
        )
        == ""
    )


def test_test_runner_config_artifacts_recurse_without_persisting_userinfo(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "test-runners"
    artifact_root.mkdir()
    bootstrap_engagement(db_path, name="Test Runner Config Recursion Test")
    for filename, payload in _TEST_RUNNER_CONFIG_PAYLOADS.items():
        (artifact_root / filename).write_text(payload, encoding="utf-8")

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued == 3
    assert summary.processed == 3

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

    for expected_seed in {
        ("https://vitest-api.acme.example/v1", "url"),
        ("https://vitest-coverage.acme.example/report", "url"),
        ("https://jest-app.acme.example", "url"),
        ("https://jest-report.acme.example/junit", "url"),
        ("https://karma-api.acme.example/v1", "url"),
        ("https://karma-dashboard.acme.example/run", "url"),
        ("vitest-owner@acme.example", "email"),
        ("jest-owner@acme.example", "email"),
        ("karma-owner@acme.example", "email"),
    }:
        assert expected_seed in seeds
    for filename in _TEST_RUNNER_CONFIG_PAYLOADS:
        assert artifact_meta[(artifact_root / filename).resolve().as_posix()]
    assert "vitest-token-do-not-store" not in persisted_text
    assert "karma-token-do-not-store" not in persisted_text


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
