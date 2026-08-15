from __future__ import annotations

from pathlib import Path
from textwrap import dedent
from typing import Any

from forge.engagement_orchestrator import ArtifactQueueProcessor


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
