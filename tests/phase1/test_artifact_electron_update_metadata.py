from __future__ import annotations

from forge.engagement_orchestrator import (
    _artifact_format_label,
    _classify_remote_artifact_url,
    _extract_artifact_relative_route_urls,
    _suffix_from_content_type,
)
from forge.utils.artifact_electron_update_metadata import (
    electron_update_metadata_artifact_label,
    electron_update_metadata_candidates,
)


def test_classify_remote_artifact_url_recognizes_electron_asar_archives() -> None:
    assert (
        _classify_remote_artifact_url("https://downloads.acme.example/app.asar?sig=abc")
        == "archive"
    )
    assert _suffix_from_content_type("application/x-asar") == ".asar"
    assert _suffix_from_content_type("application/vnd.electron.asar; charset=binary") == ".asar"
    assert _extract_artifact_relative_route_urls(
        'const bundle = "/downloads/desktop/app.asar";',
        base_url="https://downloads.acme.example/static/main.js",
    ) == ["https://downloads.acme.example/downloads/desktop/app.asar"]


def test_artifact_relative_route_urls_promote_electron_update_metadata_files() -> None:
    urls = _extract_artifact_relative_route_urls(
        """
        const latest = "latest.yml";
        const platformLatest = "./latest-mac.yml";
        const appUpdate = "../app-update.yaml";
        const unrelated = "notlatest.yml";
        const releaseNotes = "release-notes.yaml";
        """,
        base_url="https://updates.acme.example/releases/app.js",
    )

    assert urls == [
        "https://updates.acme.example/releases/latest.yml",
        "https://updates.acme.example/releases/latest-mac.yml",
        "https://updates.acme.example/app-update.yaml",
    ]


def test_electron_update_metadata_labels_are_source_aware() -> None:
    assert electron_update_metadata_artifact_label("latest.yml") == "electron-update-metadata"
    assert electron_update_metadata_artifact_label("latest-mac.yml") == "electron-update-metadata"
    assert electron_update_metadata_artifact_label("app-update.yaml") == "electron-update-metadata"
    assert electron_update_metadata_artifact_label("release-notes.yaml") == ""
    assert electron_update_metadata_artifact_label("notlatest.yml") == ""
    assert _artifact_format_label("latest.yml") == "electron-update-metadata"
    assert _artifact_format_label("release-notes.yaml") == "yaml"


def test_electron_update_metadata_candidates_resolve_safe_release_urls() -> None:
    candidates = electron_update_metadata_candidates(
        """
        version: 1.2.3
        path: acme-1.2.3.exe
        files:
          - url: acme-1.2.3.exe
          - path: acme-1.2.3.exe.blockmap
          - url: https://cdn.acme.example/acme-1.2.3.dmg
          - url: https://user:pass@cdn.acme.example/secret.dmg
          - url: ${CHANNEL}/templated.dmg
        packages:
          x64:
            path: packages/acme-1.2.3-x64.nsis.7z
        """,
        source_hint="latest.yml",
        base_url="https://updates.acme.example/releases/latest.yml",
    )

    assert candidates == [
        "https://updates.acme.example/releases/acme-1.2.3.exe",
        "https://updates.acme.example/releases/acme-1.2.3.exe.blockmap",
        "https://cdn.acme.example/acme-1.2.3.dmg",
        "https://updates.acme.example/releases/packages/acme-1.2.3-x64.nsis.7z",
    ]
    assert (
        electron_update_metadata_candidates(
            "path: acme-1.2.3.exe",
            source_hint="release-notes.yaml",
            base_url="https://updates.acme.example/releases/release-notes.yaml",
        )
        == []
    )
    assert (
        electron_update_metadata_candidates(
            "path: acme-1.2.3.exe",
            source_hint="latest.yml",
        )
        == []
    )
