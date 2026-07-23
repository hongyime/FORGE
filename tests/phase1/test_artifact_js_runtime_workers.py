from __future__ import annotations

import threading
import time
from pathlib import Path
from textwrap import dedent

from forge.engagement_orchestrator import ArtifactQueueProcessor


def test_js_runtime_regex_families_use_bounded_workers_and_preserve_order(
    tmp_path: Path,
    monkeypatch,
) -> None:
    processor = ArtifactQueueProcessor(tmp_path / "engagement.db", 1001, max_workers=4)
    payload = dedent(
        """
        const dep = "npm:chalk@5";
        registry = "registry.npmjs.org"

        [install.scopes]
        @acme = "npm.pkg.github.com/acme"

        export default {
          apiUrl: "https://api.acme.example/v1?token=hidden&view=public",
          endpoint: process.env.API_URL || "fallback.acme.example/api",
          ignored: "https://${tenant}.acme.example/template"
        }
        """
    ).strip()
    original_family = ArtifactQueueProcessor._js_runtime_text_candidate_family_entries
    original_browser = ArtifactQueueProcessor._js_runtime_browser_endpoint_pattern_entries
    active_family = 0
    peak_family = 0
    active_browser = 0
    peak_browser = 0
    lock = threading.Lock()

    def _tracking_family_entries(
        self: ArtifactQueueProcessor,
        item: tuple[str, str],
    ) -> list[tuple[int, str]]:
        nonlocal active_family, peak_family
        with lock:
            active_family += 1
            peak_family = max(peak_family, active_family)
        try:
            time.sleep(0.05)
            return original_family(item)
        finally:
            with lock:
                active_family -= 1

    def _tracking_browser_entries(
        self: ArtifactQueueProcessor,
        item: tuple[int, object, str],
    ) -> list[tuple[int, str]]:
        nonlocal active_browser, peak_browser
        with lock:
            active_browser += 1
            peak_browser = max(peak_browser, active_browser)
        try:
            time.sleep(0.05)
            return original_browser(item)  # type: ignore[arg-type]
        finally:
            with lock:
                active_browser -= 1

    monkeypatch.setattr(
        ArtifactQueueProcessor,
        "_js_runtime_text_candidate_family_entries",
        _tracking_family_entries,
    )
    monkeypatch.setattr(
        ArtifactQueueProcessor,
        "_js_runtime_browser_endpoint_pattern_entries",
        _tracking_browser_entries,
    )

    assert processor._js_runtime_text_candidate_values(
        payload,
        source_label="vite-config",
    ) == [
        "npm:chalk@5",
        "registry.npmjs.org",
        "npm.pkg.github.com/acme",
        "https://api.acme.example/v1?token=hidden&view=public",
        "fallback.acme.example/api",
    ]
    assert processor._js_runtime_text_structured_payload_text(
        payload,
        source_hint="vite.config.ts",
    ).splitlines() == [
        "https://www.npmjs.com/package/chalk",
        "https://registry.npmjs.org",
        "https://npm.pkg.github.com/acme",
        "https://api.acme.example/v1?view=public",
        "https://fallback.acme.example/api",
    ]
    assert peak_family == 2
    assert peak_browser == 2
