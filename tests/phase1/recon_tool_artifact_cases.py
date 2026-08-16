from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Callable

from forge.engagement_orchestrator import ArtifactQueueProcessor


def run_queue_processor_extracts_recon_tool_output_artifacts(
    tmp_path: Path,
    bootstrap_engagement: Callable[[Path], None],
) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_recon_tool_outputs"
    artifact_root.mkdir()
    bootstrap_engagement(db_path)

    subfinder_path = artifact_root / "subfinder.jsonl"
    subfinder_path.write_text(
        "\n".join(
            [
                json.dumps({"host": "api.acme.example", "source": "crtsh"}),
                json.dumps({"host": "cdn.acme.example", "source": "dnsdb"}),
            ]
        ),
        encoding="utf-8",
    )

    amass_path = artifact_root / "amass.json"
    amass_path.write_text(
        json.dumps(
            {
                "name": "amass.acme.example",
                "addresses": [{"ip": "203.0.113.66"}],
                "owner": "amass-owner@acme.example",
            }
        ),
        encoding="utf-8",
    )

    httpx_path = artifact_root / "httpx-output.jsonl"
    httpx_path.write_text(
        json.dumps(
            {
                "url": "https://httpx.acme.example/login?token=httpx-token-do-not-store&view=public",
                "input": "httpx.acme.example",
                "owner": "httpx-owner@acme.example",
            }
        ),
        encoding="utf-8",
    )

    katana_path = artifact_root / "katana.jsonl"
    katana_path.write_text(
        json.dumps(
            {
                "request": {
                    "endpoint": "https://katana.acme.example/api/config?secret=katana-token-do-not-store&mode=public"
                },
                "response": {"location": "/login"},
                "contact": "katana-owner@acme.example",
            }
        ),
        encoding="utf-8",
    )

    gau_path = artifact_root / "gau.txt"
    gau_path.write_text(
        "https://gau.acme.example/archive?api_key=gau-token-do-not-store&page=1\n"
        "s3://acme-recon-bucket/reports/latest.json\n"
        "gau-owner@acme.example\n",
        encoding="utf-8",
    )

    waybackurls_path = artifact_root / "waybackurls.txt"
    waybackurls_path.write_text(
        "https://wayback.acme.example/static/app.js?access_token=wayback-token-do-not-store&v=2\n",
        encoding="utf-8",
    )

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued >= 6
    assert summary.processed >= 6
    assert summary.discovered_seeds >= 12

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
        for expected_seed in {
            ("https://api.acme.example", "url"),
            ("https://cdn.acme.example", "url"),
            ("https://amass.acme.example", "url"),
            ("https://httpx.acme.example/login?view=public", "url"),
            ("https://katana.acme.example/api/config?mode=public", "url"),
            ("https://gau.acme.example/archive?page=1", "url"),
            ("https://wayback.acme.example/static/app.js?v=2", "url"),
            ("amass-owner@acme.example", "email"),
            ("httpx-owner@acme.example", "email"),
            ("katana-owner@acme.example", "email"),
            ("gau-owner@acme.example", "email"),
        }:
            assert expected_seed in seeds

        cloud_assets = con.execute(
            """
            SELECT asset_type, identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert ("aws_s3", "acme-recon-bucket") in cloud_assets

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
        assert artifact_meta[subfinder_path.resolve().as_posix()]["format"] == "subfinder-output"
        assert artifact_meta[amass_path.resolve().as_posix()]["format"] == "amass-output"
        assert artifact_meta[httpx_path.resolve().as_posix()]["format"] == "httpx-output"
        assert artifact_meta[katana_path.resolve().as_posix()]["format"] == "katana-output"
        assert artifact_meta[gau_path.resolve().as_posix()]["format"] == "gau-output"
        assert (
            artifact_meta[waybackurls_path.resolve().as_posix()]["format"]
            == "waybackurls-output"
        )

        db_dump = "\n".join(con.iterdump())
        assert "httpx-token-do-not-store" not in db_dump
        assert "katana-token-do-not-store" not in db_dump
        assert "gau-token-do-not-store" not in db_dump
        assert "wayback-token-do-not-store" not in db_dump
    finally:
        con.close()


def run_queue_processor_extracts_search_recon_provider_exports(
    tmp_path: Path,
    bootstrap_engagement: Callable[[Path], None],
) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_search_recon_provider_exports"
    artifact_root.mkdir()
    bootstrap_engagement(db_path)

    shodan_path = artifact_root / "shodan-export.json"
    shodan_path.write_text(
        json.dumps(
            {
                "matches": [
                    {
                        "ip_str": "198.51.100.20",
                        "hostnames": ["shodan-api.acme.example"],
                        "http": {
                            "host": "shodan-web.acme.example",
                            "location": (
                                "https://shodan-web.acme.example/login?"
                                "token=shodan-token-do-not-store&view=public"
                            ),
                        },
                        "data": (
                            "Owner shodan-export-owner@acme.example "
                            "archive s3://acme-shodan-export/reports/latest.json"
                        ),
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    censys_path = artifact_root / "censys-hosts.json"
    censys_path.write_text(
        json.dumps(
            {
                "result": {
                    "services": [
                        {
                            "observed_name": "censys.acme.example",
                            "web_url": (
                                "https://censys.acme.example:8443/status?"
                                "api_key=censys-token-do-not-store&ok=1"
                            ),
                        }
                    ],
                    "contact": "censys-export-owner@acme.example",
                }
            }
        ),
        encoding="utf-8",
    )

    fofa_path = artifact_root / "fofa-results.json"
    fofa_path.write_text(
        json.dumps(
            {
                "results": [
                    [
                        "https://fofa.acme.example/admin?key=fofa-token-do-not-store&open=1",
                        "fofa-export-owner@acme.example",
                        "fofa-row.acme.example",
                    ]
                ]
            }
        ),
        encoding="utf-8",
    )

    urlscan_path = artifact_root / "urlscan-results.json"
    urlscan_path.write_text(
        json.dumps(
            {
                "page": {
                    "url": (
                        "https://urlscan.acme.example/result?"
                        "access_token=urlscan-token-do-not-store&view=1"
                    ),
                    "domain": "urlscan.acme.example",
                },
                "owner": "urlscan-export-owner@acme.example",
                "firebase": "https://recon-export-firebase.firebaseio.com",
            }
        ),
        encoding="utf-8",
    )

    zoomeye_path = artifact_root / "zoomeye-output.json"
    zoomeye_path.write_text(
        json.dumps(
            {
                "matches": [
                    {
                        "site": (
                            "https://zoomeye.acme.example/login?"
                            "secret=zoomeye-token-do-not-store&status=public"
                        ),
                        "hostname": "zoomeye.acme.example",
                    }
                ],
                "email": "zoomeye-export-owner@acme.example",
                "supabase": "https://reconexportvault.supabase.co/rest/v1/",
            }
        ),
        encoding="utf-8",
    )

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued >= 5
    assert summary.processed >= 5
    assert summary.discovered_seeds >= 12

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
        for expected_seed in {
            ("https://shodan-api.acme.example", "url"),
            ("https://shodan-web.acme.example", "url"),
            ("https://shodan-web.acme.example/login?view=public", "url"),
            ("https://censys.acme.example", "url"),
            ("https://censys.acme.example:8443/status?ok=1", "url"),
            ("https://fofa.acme.example/admin?open=1", "url"),
            ("https://fofa-row.acme.example", "url"),
            ("https://urlscan.acme.example/result?view=1", "url"),
            ("https://urlscan.acme.example", "url"),
            ("https://zoomeye.acme.example/login?status=public", "url"),
            ("https://zoomeye.acme.example", "url"),
            ("shodan-export-owner@acme.example", "email"),
            ("censys-export-owner@acme.example", "email"),
            ("fofa-export-owner@acme.example", "email"),
            ("urlscan-export-owner@acme.example", "email"),
            ("zoomeye-export-owner@acme.example", "email"),
        }:
            assert expected_seed in seeds

        assert ("https://acme.example", "url") not in seeds

        cloud_assets = con.execute(
            """
            SELECT asset_type, identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert ("aws_s3", "acme-shodan-export") in cloud_assets
        assert ("firebase", "recon-export-firebase") in cloud_assets
        assert ("supabase", "reconexportvault") in cloud_assets

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
        assert artifact_meta[shodan_path.resolve().as_posix()]["format"] == "shodan-output"
        assert artifact_meta[censys_path.resolve().as_posix()]["format"] == "censys-output"
        assert artifact_meta[fofa_path.resolve().as_posix()]["format"] == "fofa-output"
        assert artifact_meta[urlscan_path.resolve().as_posix()]["format"] == "urlscan-output"
        assert artifact_meta[zoomeye_path.resolve().as_posix()]["format"] == "zoomeye-output"

        db_dump = "\n".join(con.iterdump())
        assert "shodan-token-do-not-store" not in db_dump
        assert "censys-token-do-not-store" not in db_dump
        assert "fofa-token-do-not-store" not in db_dump
        assert "urlscan-token-do-not-store" not in db_dump
        assert "zoomeye-token-do-not-store" not in db_dump
    finally:
        con.close()


def run_recon_tool_output_structured_payload_uses_bounded_workers_and_preserves_order(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    db_path = tmp_path / "engagement.db"
    processor = ArtifactQueueProcessor(db_path, 1001)
    payload = "\n".join(
        [
            json.dumps({"host": "one.acme.example"}),
            json.dumps({"url": "two.acme.example/status?token=drop-me&view=public"}),
            json.dumps({"name": "three.acme.example"}),
            json.dumps({"matched-url": "https://four.acme.example/path"}),
        ]
    )
    observed_candidate_batches: list[list[str]] = []
    original_batch = ArtifactQueueProcessor._run_ordered_local_batch

    def _tracking_batch(self, items, worker, *, default_factory):  # noqa: ANN001
        materialized = list(items)
        if getattr(worker, "__name__", "") == "_recon_tool_output_candidate_entry":
            observed_candidate_batches.append([str(item) for item in materialized])
        return original_batch(self, materialized, worker, default_factory=default_factory)

    monkeypatch.setattr(ArtifactQueueProcessor, "_run_ordered_local_batch", _tracking_batch)

    result = processor._recon_tool_output_structured_payload_text(
        payload,
        source_hint="subfinder.jsonl",
    )

    assert observed_candidate_batches == [
        [
            "one.acme.example",
            "two.acme.example/status?token=drop-me&view=public",
            "three.acme.example",
            "https://four.acme.example/path",
        ]
    ]
    assert result.splitlines() == [
        "https://one.acme.example",
        "https://two.acme.example/status?view=public",
        "https://three.acme.example",
        "https://four.acme.example/path",
    ]
