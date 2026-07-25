from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from textwrap import dedent

from forge.engagement_orchestrator import (
    ArtifactQueueProcessor,
    _extract_artifact_relative_route_urls,
)
from tests.phase1.artifact_test_support import bootstrap_engagement


def test_css_and_html_route_extractor_handles_unquoted_asset_refs() -> None:
    text = dedent(
        """
        @import url(/static/css/theme.css);
        @import "theme.css";
        @import url(print.css);
        .hero { background: url(../img/banner.png?token=secret&view=public); }
        .logo { background: url(hero.png); }
        .font { src: url(//cdn.acme.example/fonts/app.woff2); }
        .skip-data { background: url(data:image/png;base64,AAAA); }
        .skip-js { background: url(javascript:alert(1)); }
        <img srcset="/img/card-640.html 640w, /img/card-1280.html 1280w">
        <script src=/assets/app.js></script>
        <link rel=manifest href=/manifest.webmanifest>
        <meta http-equiv="refresh" content="0; url=/login">
        """
    )

    urls = _extract_artifact_relative_route_urls(
        text,
        base_url="https://app.acme.example/static/css/app.css",
    )

    assert urls == [
        "https://app.acme.example/static/css/theme.css",
        "https://app.acme.example/static/css/print.css",
        "https://app.acme.example/static/img/banner.png?view=public",
        "https://app.acme.example/static/css/hero.png",
        "https://cdn.acme.example/fonts/app.woff2",
        "https://app.acme.example/assets/app.js",
        "https://app.acme.example/manifest.webmanifest",
        "https://app.acme.example/img/card-640.html",
        "https://app.acme.example/img/card-1280.html",
        "https://app.acme.example/login",
    ]


def test_remote_css_and_html_artifacts_promote_recursive_route_seeds(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "downloaded"
    artifact_root.mkdir()
    bootstrap_engagement(db_path, name="CSS HTML Route Recursion Test")
    css_path = artifact_root / "app.css"
    html_path = artifact_root / "index.html"
    css_path.write_text(
        """
        @import url(/static/css/theme.css);
        @import "base.css";
        @import url(print.css);
        .hero { background: url(../img/banner.png?token=secret&view=public); }
        .logo { background: url(hero.png); }
        """.strip(),
        encoding="utf-8",
    )
    html_path.write_text(
        """
        <img srcset="/img/card-640.html 640w, /img/card-1280.html 1280w">
        <script src=/assets/app.js></script>
        <link rel=stylesheet href=/static/css/app.css>
        <meta http-equiv="refresh" content="0; url=/login">
        """.strip(),
        encoding="utf-8",
    )

    con = sqlite3.connect(db_path)
    try:
        con.executemany(
            """
            INSERT INTO artifact_queue
                (engagement_id, source_url, local_path, artifact_type,
                 discovered_from, status, metadata_json)
            VALUES
                (1001, ?, ?, 'config', 'crawl_results', 'downloaded', '{}')
            """,
            [
                (
                    "https://app.acme.example/static/css/app.css",
                    css_path.resolve().as_posix(),
                ),
                (
                    "https://app.acme.example/index.html",
                    html_path.resolve().as_posix(),
                ),
            ],
        )
        con.commit()
    finally:
        con.close()

    processor = ArtifactQueueProcessor(db_path, 1001)
    summary = processor.process()

    assert summary.processed == 2
    con = sqlite3.connect(db_path)
    try:
        url_seeds = {
            row[0]
            for row in con.execute(
                """
                SELECT seed_value
                FROM engagement_seeds
                WHERE engagement_id=1001 AND seed_type='url'
                """
            ).fetchall()
        }
        queued_artifacts = {
            row[0]: (row[1], row[2], json.loads(str(row[3] or "{}")))
            for row in con.execute(
                """
                SELECT source_url, artifact_type, status, metadata_json
                FROM artifact_queue
                WHERE engagement_id=1001
                  AND source_url LIKE 'https://app.acme.example/%'
                """
            ).fetchall()
        }
    finally:
        con.close()

    assert "https://app.acme.example/static/css/theme.css" in url_seeds
    assert "https://app.acme.example/static/css/base.css" in url_seeds
    assert "https://app.acme.example/static/css/print.css" in url_seeds
    assert "https://app.acme.example/static/img/banner.png?view=public" in url_seeds
    assert "https://app.acme.example/static/css/hero.png" in url_seeds
    assert "https://app.acme.example/img/card-640.html" in url_seeds
    assert "https://app.acme.example/img/card-1280.html" in url_seeds
    assert "https://app.acme.example/assets/app.js" in url_seeds
    assert "https://app.acme.example/login" in url_seeds
    assert not any("token=secret" in value for value in url_seeds)

    assert queued_artifacts["https://app.acme.example/static/css/theme.css"][:2] == (
        "config",
        "queued",
    )
    assert queued_artifacts["https://app.acme.example/static/css/base.css"][:2] == (
        "config",
        "queued",
    )
    assert queued_artifacts["https://app.acme.example/static/css/print.css"][:2] == (
        "config",
        "queued",
    )
    assert queued_artifacts["https://app.acme.example/assets/app.js"][:2] == (
        "config",
        "queued",
    )
    assert queued_artifacts["https://app.acme.example/static/css/theme.css"][2]["source_rule"] == (
        "artifact_text_extract"
    )
