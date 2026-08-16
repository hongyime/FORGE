from __future__ import annotations

import base64
import json
import sqlite3
import threading
import time
import zipfile
from pathlib import Path
from textwrap import dedent
from typing import Any

from forge.engagement_orchestrator import ArtifactQueueProcessor, EngagementSynthesisEngine
from tests.phase1.artifact_test_support import bootstrap_engagement


def run_http_request_text_structured_payload_uses_bounded_workers_and_preserves_order(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    db_path = tmp_path / "engagement.db"
    processor = ArtifactQueueProcessor(db_path, 1001)
    payload = dedent(
        """
        @baseUrl = http-env.acme.example/api
        GET http-one.acme.example/v1/users HTTP/1.1
        POST https://http-two.acme.example/v2/session
        GET {{baseUrl}}/users
        Host: http-host.acme.example
        Content-Type: application/json
        """
    ).strip()
    observed_candidate_batches: list[list[str]] = []
    original_batch = ArtifactQueueProcessor._run_ordered_local_batch

    def _tracking_batch(self, items, worker, *, default_factory):  # noqa: ANN001
        materialized = list(items)
        if getattr(worker, "__name__", "") == "_http_request_url_candidate_entry":
            observed_candidate_batches.append([str(item) for item in materialized])
        return original_batch(self, materialized, worker, default_factory=default_factory)

    monkeypatch.setattr(ArtifactQueueProcessor, "_run_ordered_local_batch", _tracking_batch)

    result = processor._http_request_text_structured_payload_text(
        payload,
        source_hint="requests/session.http",
    )

    assert observed_candidate_batches == [
        [
            "http-env.acme.example/api",
            "http-one.acme.example/v1/users",
            "https://http-two.acme.example/v2/session",
            "{{baseUrl}}/users",
            "http-host.acme.example",
        ]
    ]
    assert result.splitlines() == [
        "https://http-env.acme.example/api",
        "https://http-one.acme.example/v1/users",
        "https://http-two.acme.example/v2/session",
        "https://http-host.acme.example",
    ]


def run_hurl_request_text_structured_payload_uses_bounded_workers_and_preserves_order(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    db_path = tmp_path / "engagement.db"
    processor = ArtifactQueueProcessor(db_path, 1001)
    payload = dedent(
        """
        apiHost: hurl-env.acme.example/api
        GET hurl-one.acme.example/v1/users
        HTTP 200
        POST https://hurl-two.acme.example/v2/session
        GET {{apiHost}}/users
        """
    ).strip()
    observed_candidate_batches: list[list[str]] = []
    original_batch = ArtifactQueueProcessor._run_ordered_local_batch

    def _tracking_batch(self, items, worker, *, default_factory):  # noqa: ANN001
        materialized = list(items)
        if getattr(worker, "__name__", "") == "_http_request_url_candidate_entry":
            observed_candidate_batches.append([str(item) for item in materialized])
        return original_batch(self, materialized, worker, default_factory=default_factory)

    monkeypatch.setattr(ArtifactQueueProcessor, "_run_ordered_local_batch", _tracking_batch)

    result = processor._http_request_text_structured_payload_text(
        payload,
        source_hint="requests/session.hurl",
    )

    assert observed_candidate_batches == [
        [
            "hurl-env.acme.example/api",
            "hurl-one.acme.example/v1/users",
            "https://hurl-two.acme.example/v2/session",
            "{{apiHost}}/users",
        ]
    ]
    assert result.splitlines() == [
        "https://hurl-env.acme.example/api",
        "https://hurl-one.acme.example/v1/users",
        "https://hurl-two.acme.example/v2/session",
    ]


def run_saz_http_transcript_artifacts(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_saz_http_transcript"
    artifact_root.mkdir()
    bootstrap_engagement(
        db_path,
        name="Acme Example",
        scope_json='["*.acme.example","+15551234567","security@acme.example","https://downloads.acme.example/app.apk"]',
        operator="delta-one",
    )

    saz_path = artifact_root / "browser-session.saz"
    with zipfile.ZipFile(saz_path, "w") as zf:
        zf.writestr(
            "raw/0001_c.txt",
            "\r\n".join(
                [
                    "GET /api/v1/config?token=secret-token&view=public HTTP/1.1",
                    "Host: transcript.acme.example",
                    "X-Forwarded-Proto: https",
                    "Origin: https://origin.acme.example",
                    "X-Owner: saz-owner@acme.example",
                    "",
                    "",
                ]
            ),
        )
        zf.writestr(
            "raw/0001_s.txt",
            "\r\n".join(
                [
                    "HTTP/1.1 200 OK",
                    "Content-Type: application/json",
                    "Location: /redirect/next?session_token=hidden&view=public",
                    "",
                    json.dumps(
                        {
                            "support": "saz-body@acme.example",
                            "firebase": "https://saz-firebase.firebaseio.com",
                            "supabase_url": "https://sazworkspace.supabase.co",
                            "supabase_anon_key": (
                                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                                "eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InNhendvcmtzcGFjZSIsInJvbGUiOiJhbm9uIn0."
                                "signature789"
                            ),
                            "bucket": "s3://acme-saz-bucket/reports/latest.pdf",
                        },
                        sort_keys=True,
                    ),
                ]
            ),
        )

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()
    synthesis_summary = EngagementSynthesisEngine(db_path, 1001, depth_limit=3).run()

    assert queued >= 1
    assert summary.processed >= 1
    assert summary.firebase_projects >= 1
    assert summary.supabase_configs >= 1
    assert summary.discovered_seeds >= 6
    assert "acme.example" in synthesis_summary.root_domains
    assert "saz-firebase" not in synthesis_summary.root_domains
    assert "sazworkspace" not in synthesis_summary.root_domains

    con = sqlite3.connect(db_path)
    try:
        emails = {
            row[0]
            for row in con.execute("SELECT email FROM emails WHERE engagement_id=1001").fetchall()
        }
        assert "saz-owner@acme.example" in emails
        assert "saz-body@acme.example" in emails

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
        assert ("https://transcript.acme.example/api/v1/config?view=public", "url") in seeds
        assert ("https://transcript.acme.example/redirect/next?view=public", "url") in seeds
        assert ("https://origin.acme.example", "url") in seeds
        assert ("saz-owner@acme.example", "email") in seeds
        assert ("saz-body@acme.example", "email") in seeds
        assert ("sazworkspace", "other") in seeds
        assert ("saz-firebase", "other") in seeds
        assert ("sazworkspace.supabase.co", "subdomain") not in seeds
        assert ("saz-firebase.firebaseio.com", "subdomain") not in seeds

        cloud_assets = con.execute(
            """
            SELECT asset_type, identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert ("aws_s3", "acme-saz-bucket") in cloud_assets
        assert ("firebase", "saz-firebase") in cloud_assets
        assert ("supabase", "sazworkspace") in cloud_assets

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
        assert artifact_meta[saz_path.resolve().as_posix()]["format"] == "saz"
        assert artifact_meta[saz_path.resolve().as_posix()]["payload_count"] >= 2
    finally:
        con.close()


def run_charles_session_json_artifacts(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_charles_session"
    artifact_root.mkdir()
    bootstrap_engagement(
        db_path,
        name="Acme Example",
        scope_json='["*.acme.example","+15551234567","security@acme.example","https://downloads.acme.example/app.apk"]',
        operator="delta-one",
    )

    charles_path = artifact_root / "browser-session.chlsj"
    charles_path.write_text(
        json.dumps(
            {
                "sessions": [
                    {
                        "request": {
                            "method": "GET",
                            "protocol": "https",
                            "host": "charles.acme.example",
                            "path": "/api/config?api_key=hidden&view=public",
                            "headers": [
                                {"name": "X-Owner", "value": "charles-owner@acme.example"},
                            ],
                        },
                        "response": {
                            "status": 302,
                            "headers": [
                                {
                                    "name": "Location",
                                    "value": "/login?session_token=hidden&next=home",
                                },
                            ],
                            "body": {
                                "support": "charles-body@acme.example",
                                "firebase": "https://charles-firebase.firebaseio.com",
                                "supabase_url": "https://charlesworkspace.supabase.co",
                                "supabase_anon_key": (
                                    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                                    "eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImNoYXJsZXN3b3Jrc3BhY2UiLCJyb2xlIjoiYW5vbiJ9."
                                    "signature456"
                                ),
                                "bucket": "s3://acme-charles-bucket/reports/latest.pdf",
                            },
                        },
                    },
                    {
                        "request": {
                            "url": "https://direct-charles.acme.example/status?secret=hidden&ok=1",
                        }
                    },
                ]
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()
    synthesis_summary = EngagementSynthesisEngine(db_path, 1001, depth_limit=3).run()

    assert queued >= 1
    assert summary.processed >= 1
    assert summary.firebase_projects >= 1
    assert summary.supabase_configs >= 1
    assert summary.discovered_seeds >= 7
    assert "acme.example" in synthesis_summary.root_domains
    assert "charles-firebase" not in synthesis_summary.root_domains
    assert "charlesworkspace" not in synthesis_summary.root_domains

    con = sqlite3.connect(db_path)
    try:
        emails = {
            row[0]
            for row in con.execute("SELECT email FROM emails WHERE engagement_id=1001").fetchall()
        }
        assert "charles-owner@acme.example" in emails
        assert "charles-body@acme.example" in emails

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
        assert ("https://charles.acme.example/api/config?view=public", "url") in seeds
        assert ("https://charles.acme.example/login?next=home", "url") in seeds
        assert ("https://direct-charles.acme.example/status?ok=1", "url") in seeds
        assert ("charles-owner@acme.example", "email") in seeds
        assert ("charles-body@acme.example", "email") in seeds
        assert ("charlesworkspace", "other") in seeds
        assert ("charles-firebase", "other") in seeds
        assert ("charlesworkspace.supabase.co", "subdomain") not in seeds
        assert ("charles-firebase.firebaseio.com", "subdomain") not in seeds

        cloud_assets = con.execute(
            """
            SELECT asset_type, identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert ("aws_s3", "acme-charles-bucket") in cloud_assets
        assert ("firebase", "charles-firebase") in cloud_assets
        assert ("supabase", "charlesworkspace") in cloud_assets

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
        assert artifact_meta[charles_path.resolve().as_posix()]["format"] == "charles-session-json"
        assert artifact_meta[charles_path.resolve().as_posix()]["payload_count"] >= 1
    finally:
        con.close()


def run_burp_site_map_xml_artifacts(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_burp_site_map"
    artifact_root.mkdir()
    bootstrap_engagement(
        db_path,
        name="Acme Example",
        scope_json='["*.acme.example","+15551234567","security@acme.example","https://downloads.acme.example/app.apk"]',
        operator="delta-one",
    )

    request_text = "\r\n".join(
        [
            "GET /api/config?api_key=hidden&view=public HTTP/1.1",
            "Host: burp.acme.example",
            "X-Owner: burp-request@acme.example",
            "",
            "",
        ]
    )
    response_text = "\r\n".join(
        [
            "HTTP/1.1 302 Found",
            "Location: /login?session_token=hidden&next=home",
            "Content-Type: application/json",
            "",
            json.dumps(
                {
                    "support": "burp-body@acme.example",
                    "firebase": "https://burp-firebase.firebaseio.com",
                    "supabase_url": "https://burpworkspace.supabase.co",
                    "supabase_anon_key": (
                        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                        "eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImJ1cnB3b3Jrc3BhY2UiLCJyb2xlIjoiYW5vbiJ9."
                        "signature987"
                    ),
                    "bucket": "s3://acme-burp-bucket/reports/latest.pdf",
                },
                sort_keys=True,
            ),
        ]
    )
    burp_path = artifact_root / "burp-site-map.xml"
    burp_path.write_text(
        dedent(
            f"""
            <?xml version="1.0"?>
            <items>
              <item>
                <url>https://burp.acme.example/api/config?api_key=hidden&amp;view=public</url>
                <host ip="203.0.113.45">burp.acme.example</host>
                <protocol>https</protocol>
                <path>/api/config?api_key=hidden&amp;view=public</path>
                <request base64="true">{base64.b64encode(request_text.encode("utf-8")).decode("ascii")}</request>
                <response base64="true">{base64.b64encode(response_text.encode("utf-8")).decode("ascii")}</response>
              </item>
            </items>
            """
        ).strip(),
        encoding="utf-8",
    )

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()
    synthesis_summary = EngagementSynthesisEngine(db_path, 1001, depth_limit=3).run()

    assert queued >= 1
    assert summary.processed >= 1
    assert summary.firebase_projects >= 1
    assert summary.supabase_configs >= 1
    assert summary.discovered_seeds >= 6
    assert "acme.example" in synthesis_summary.root_domains
    assert "burp-firebase" not in synthesis_summary.root_domains
    assert "burpworkspace" not in synthesis_summary.root_domains

    con = sqlite3.connect(db_path)
    try:
        emails = {
            row[0]
            for row in con.execute("SELECT email FROM emails WHERE engagement_id=1001").fetchall()
        }
        assert "burp-request@acme.example" in emails
        assert "burp-body@acme.example" in emails

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
        assert ("https://burp.acme.example/api/config?view=public", "url") in seeds
        assert ("https://burp.acme.example/login?next=home", "url") in seeds
        assert ("burp-request@acme.example", "email") in seeds
        assert ("burp-body@acme.example", "email") in seeds
        assert ("burpworkspace", "other") in seeds
        assert ("burp-firebase", "other") in seeds
        assert ("burpworkspace.supabase.co", "subdomain") not in seeds
        assert ("burp-firebase.firebaseio.com", "subdomain") not in seeds

        cloud_assets = con.execute(
            """
            SELECT asset_type, identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert ("aws_s3", "acme-burp-bucket") in cloud_assets
        assert ("firebase", "burp-firebase") in cloud_assets
        assert ("supabase", "burpworkspace") in cloud_assets

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
        assert artifact_meta[burp_path.resolve().as_posix()]["format"] == "burp-site-map"
        assert artifact_meta[burp_path.resolve().as_posix()]["payload_count"] >= 1
    finally:
        con.close()


def run_har_entries_parallel_order(tmp_path: Path, monkeypatch: Any) -> None:
    db_path = tmp_path / "engagement.db"
    payload = {
        "log": {
            "version": "1.2",
            "entries": [
                {"request": {"url": "https://one.acme.example"}},
                {"request": {"url": "https://two.acme.example"}},
                {"request": {"url": "https://three.acme.example"}},
            ],
        }
    }
    delays = {
        1: 0.05,
        2: 0.01,
        3: 0.03,
    }
    active = 0
    peak = 0
    lock = threading.Lock()

    def _fake_extract_har_entry_payload(
        _self,
        job,
    ) -> tuple[str, str, str]:  # noqa: ANN001
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        try:
            time.sleep(delays[job.entry_index])
            return (
                job.source_file,
                f"{job.member_name}#har-entry-{job.entry_index}",
                f"entry-{job.entry_index}",
            )
        finally:
            with lock:
                active -= 1

    monkeypatch.setattr(
        ArtifactQueueProcessor,
        "_extract_har_entry_payload",
        _fake_extract_har_entry_payload,
    )

    processor = ArtifactQueueProcessor(db_path, 1001, max_workers=2)
    payloads = processor._har_payload_tuples(
        payload,
        str(tmp_path / "parallel.har"),
        "parallel.har",
    )

    assert peak == 2
    assert payloads == [
        (str(tmp_path / "parallel.har"), "parallel.har#har-summary", "log.version=1.2\nentries=3"),
        (str(tmp_path / "parallel.har"), "parallel.har#har-entry-1", "entry-1"),
        (str(tmp_path / "parallel.har"), "parallel.har#har-entry-2", "entry-2"),
        (str(tmp_path / "parallel.har"), "parallel.har#har-entry-3", "entry-3"),
    ]


def run_har_entry_job_planning_parallel_order(tmp_path: Path, monkeypatch: Any) -> None:
    db_path = tmp_path / "engagement.db"
    source_file = str(tmp_path / "parallel.har")
    member_name = "parallel.har"
    payload = {
        "log": {
            "version": "1.2",
            "entries": [
                {"request": {"url": "https://one.acme.example"}},
                {"request": {"url": "https://two.acme.example"}},
                {"request": {"url": "https://three.acme.example"}},
                {"request": {"url": "https://four.acme.example"}},
                {"request": {"url": "https://five.acme.example"}},
            ],
        }
    }
    delays = {
        1: 0.05,
        2: 0.01,
        3: 0.03,
        4: 0.02,
        5: 0.04,
    }
    active = 0
    peak = 0
    lock = threading.Lock()
    original_entry = ArtifactQueueProcessor._har_entry_job

    def _tracking_entry(item, *, source_file, member_name):  # noqa: ANN001
        nonlocal active, peak
        entry_index, _entry = item
        with lock:
            active += 1
            peak = max(peak, active)
        try:
            time.sleep(delays[entry_index])
            return original_entry(item, source_file=source_file, member_name=member_name)
        finally:
            with lock:
                active -= 1

    def _fake_extract_har_entry_payload(
        _self,
        job,
    ) -> tuple[str, str, str]:  # noqa: ANN001
        return (
            job.source_file,
            f"{job.member_name}#har-entry-{job.entry_index}",
            f"entry-{job.entry_index}",
        )

    monkeypatch.setattr(
        ArtifactQueueProcessor,
        "_har_entry_job",
        staticmethod(_tracking_entry),
    )
    monkeypatch.setattr(
        ArtifactQueueProcessor,
        "_extract_har_entry_payload",
        _fake_extract_har_entry_payload,
    )

    processor = ArtifactQueueProcessor(db_path, 1001, max_workers=8)
    payloads = processor._extract_har_entry_payloads(
        payload["log"],
        source_file=source_file,
        member_name=member_name,
    )

    assert peak == 4
    assert payloads == [
        (source_file, "parallel.har#har-entry-1", "entry-1"),
        (source_file, "parallel.har#har-entry-2", "entry-2"),
        (source_file, "parallel.har#har-entry-3", "entry-3"),
        (source_file, "parallel.har#har-entry-4", "entry-4"),
        (source_file, "parallel.har#har-entry-5", "entry-5"),
    ]
