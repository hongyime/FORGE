from __future__ import annotations

import csv
import json
import socket
import sqlite3
import subprocess
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import pytest

import forge.cli as cli
from forge.core.errors import ProviderUnavailableError
from forge.engagement_orchestrator import ArtifactDownloadResult, ArtifactQueueProcessor
from forge.phase4 import cloud_validate
from forge.phase6.report_synthesizer import ReportSynthesizer
from forge.reporting.dashboard import generate_dashboard

EID = 5151
FALLBACK_REASON = "mock quota exhausted"
SERVICE_WORKER_URL = "https://app.acme.test/service-worker.js"
MANIFEST_URL = "https://app.acme.test/app.webmanifest"
PRECACHE_URL = "https://app.acme.test/precache-manifest.abcd1234.js"
REPORT_CHUNK_URL = "https://cdn.acme.test/static/report-output.js"
DASHBOARD_CHUNK_URL = "https://cdn.acme.test/static/dashboard-output.js"


def test_kill_chain_multiseed_service_worker_precache_recurses_to_validated_report_outputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_dir = tmp_path / ".forge_data"
    db_path = data_dir / "engagements" / f"{EID}.db"
    reports_dir = tmp_path / "reports"
    monkeypatch.chdir(tmp_path)
    for key, value in {
        "FORGE_DATA_DIR": str(data_dir),
        "FORGE_ENGAGEMENT_KEY": "FORGE-TEST-ENGAGEMENT-KEY",
        "FORGE_ENV": "test",
        "FORGE_OFFLINE_STRICT": "1",
        "FORGE_SAFE_MODE": "1",
    }.items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv("FORGE_REDIS_URL", raising=False)

    _install_network_blocks(monkeypatch)
    _install_html_mock(monkeypatch)
    _install_remote_artifact_mock(monkeypatch, tmp_path)
    _install_module_mock(monkeypatch, tmp_path)
    _install_cloud_validation_mock(monkeypatch, db_path)
    monkeypatch.setattr(ReportSynthesizer, "_ensure_provider_loaded", lambda self: None)
    monkeypatch.setattr(
        ReportSynthesizer,
        "_infer",
        lambda self, _prompt: (_ for _ in ()).throw(ProviderUnavailableError(FALLBACK_REASON)),
    )

    cli.kill_chain(
        "acme.test",
        related_seed=["ops@acme.test"],
        engagement=str(EID),
        max_iter=6,
        parallel_fanout=1,
        skip_keyscan=True,
        report_provider="auto",
        report_max_loops=0,
    )

    report_path = _latest_report(reports_dir)
    report_text = report_path.read_text(encoding="utf-8")
    report_payload = json.loads(report_path.with_suffix(".json").read_text(encoding="utf-8"))
    graph = json.loads((reports_dir / f"{EID}_attack_graph.json").read_text(encoding="utf-8"))

    assert report_path.with_suffix(".pdf").read_bytes().startswith(b"%PDF-1.4")
    assert report_payload["provider"] == "template"
    assert report_payload["requested_provider"] == "auto"
    assert report_payload["fallback_reason"] == FALLBACK_REASON
    assert report_payload["report_lineage"]["rendered_provider"] == "template"
    assert report_payload["report_lineage"]["findings_checksum"] == report_payload["findings_checksum"]
    assert str(report_payload["findings_checksum"]).startswith("sha256:")
    assert f"LLM fallback engaged: {FALLBACK_REASON}" in report_text

    with sqlite3.connect(db_path) as con:
        con.row_factory = sqlite3.Row
        _assert_artifacts(con)
        _assert_recursive_seeds_and_relations(con)
        _assert_validation_and_findings(con)
        run = con.execute(
            "SELECT status, current_iteration, metadata_json FROM engagement_runs ORDER BY id DESC LIMIT 1"
        ).fetchone()
        assert run["status"] == "completed"
        assert int(run["current_iteration"]) < 6
        assert json.loads(run["metadata_json"])["last_iteration_stable"] is True

    _assert_report_exports(report_path, report_text, report_payload)
    _assert_graph_outputs(graph)
    _assert_dashboard_outputs(data_dir, reports_dir)


def _install_network_blocks(monkeypatch: pytest.MonkeyPatch) -> None:
    def blocked(*args, **kwargs):  # noqa: ANN002, ANN003
        raise AssertionError(f"external network disabled: {args!r} {kwargs!r}")

    def ip(host: str) -> str:
        total = sum(ord(char) for char in host)
        return f"198.18.{total % 200}.{(total // 200) % 200 + 1}"

    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "gethostbyname", lambda host: ip(str(host)))
    monkeypatch.setattr(socket, "gethostbyaddr", lambda addr: (_ for _ in ()).throw(OSError(addr)))
    try:
        import httpx

        monkeypatch.setattr(httpx, "Client", blocked)
    except ImportError:
        pass


def _install_html_mock(monkeypatch: pytest.MonkeyPatch) -> None:
    root_html = f"""
        <link rel="manifest" href="{MANIFEST_URL}">
        <script src="{SERVICE_WORKER_URL}"></script>
        ops@acme.test
    """

    def html_batch(specs, fetch_playwright, fetch_target_html, **kwargs):  # noqa: ANN001, ANN003
        del fetch_playwright, fetch_target_html, kwargs
        bodies: list[str] = []
        for spec in specs:
            parsed = urlparse(spec.url)
            if (parsed.hostname or "").lower() == "acme.test" and not parsed.path.strip("/"):
                bodies.append(root_html)
            else:
                bodies.append("")
        return bodies

    monkeypatch.setattr(cli, "_run_html_fetch_batch", html_batch)


def _install_remote_artifact_mock(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    bodies = {
        MANIFEST_URL: (
            "app.webmanifest",
            json.dumps(
                {
                    "name": "Acme PWA",
                    "start_url": "https://app.acme.test/app",
                    "scope": "https://app.acme.test/",
                    "description": "Contact manifest-sw-owner@acme.test",
                    "serviceworker": {"src": SERVICE_WORKER_URL},
                },
                sort_keys=True,
            ),
            "application/manifest+json",
        ),
        SERVICE_WORKER_URL: (
            "service-worker.js",
            f"""
            importScripts("/{Path(PRECACHE_URL).name}");
            firebase.initializeApp({{ projectId: "sw-firebase-prod" }});
            self.__CONFIG__ = {{ apiUrl: "https://api.acme.test/v1" }};
            """,
            "application/javascript",
        ),
        PRECACHE_URL: (
            "precache-manifest.abcd1234.js",
            f"""
            self.__precacheManifest = [
              {{ url: "{REPORT_CHUNK_URL}" }},
              {{ url: "{DASHBOARD_CHUNK_URL}" }}
            ];
            """,
            "application/javascript",
        ),
        REPORT_CHUNK_URL: (
            "report-output.js",
            """
            export const owner = "sw-report-owner@acme.test";
            export const firebase = "https://sw-report-firebase.firebaseio.com";
            export const supabase = "https://swreportvault.supabase.co";
            export const storage = "s3://sw-precache-logs/reports/latest.json";
            """,
            "application/javascript",
        ),
        DASHBOARD_CHUNK_URL: (
            "dashboard-output.js",
            """
            export const owner = "sw-dashboard-owner@acme.test";
            export const firebase = "https://sw-dashboard-firebase.firebaseio.com";
            export const storage = "gs://sw-precache-public/assets/app.js";
            """,
            "application/javascript",
        ),
    }

    def download_remote_artifact(
        self: ArtifactQueueProcessor,
        request: Any,
    ) -> ArtifactDownloadResult:
        del self
        fixture = bodies.get(request.source_url)
        if fixture is None:
            return ArtifactDownloadResult(
                artifact_id=request.artifact_id,
                source_url=request.source_url,
                artifact_type=request.artifact_type,
                error="fixture did not define this remote artifact",
            )
        filename, body, content_type = fixture
        path = tmp_path / "remote_artifacts" / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(str(body).strip(), encoding="utf-8")
        return ArtifactDownloadResult(
            artifact_id=request.artifact_id,
            source_url=request.source_url,
            artifact_type=request.artifact_type,
            path=path,
            metadata_extra={
                "content_type": content_type,
                "downloaded_from_remote": True,
                "download_filename": filename,
            },
        )

    monkeypatch.setattr(ArtifactQueueProcessor, "_download_remote_artifact_request", download_remote_artifact)


def _install_module_mock(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def fake_module(cmd_argv, **kwargs):  # noqa: ANN001, ANN003
        del kwargs
        argv = [str(part) for part in cmd_argv]
        if argv[:2] == ["graph", "build"]:
            cli.graph_build(
                engagement=str(EID),
                fmt="all",
                output_dir="reports",
                min_severity="LOW",
                critical_path_only=False,
                snapshot=True,
                max_nodes=400,
            )
            return subprocess.CompletedProcess(["forge", *argv], 0, "graph built\n", "")
        if argv[:2] == ["report", "generate"]:
            from forge.phase6.report_synthesizer import synthesise

            output = argv[argv.index("--output") + 1]
            provider = argv[argv.index("--provider") + 1] if "--provider" in argv else "auto"
            max_loops = int(argv[argv.index("--max-loops") + 1]) if "--max-loops" in argv else None
            synthesise(
                str(EID),
                output_path=str(tmp_path / output),
                assume_yes=True,
                provider=provider,
                max_correction_loops=max_loops,
            )
            return subprocess.CompletedProcess(["forge", *argv], 0, "report built\n", "")
        return subprocess.CompletedProcess(["forge", *argv], 0, "mock ok\n", "")

    monkeypatch.setattr(cli, "_run_forge_module_subprocess", fake_module)
    monkeypatch.setattr(cli, "_run_callable_batch", lambda items, worker, **_kwargs: [worker(item) for item in items])
    monkeypatch.setattr(cli, "_run_ptr_lookup_batch", lambda ips, *_args, **_kwargs: [(str(ip_), "") for ip_ in ips])


def _install_cloud_validation_mock(monkeypatch: pytest.MonkeyPatch, db_path: Path) -> None:
    methods = {
        "firebase": "firebase_database_shallow_read",
        "supabase": "supabase_rest_root",
    }

    def validate_asset(con: sqlite3.Connection, kind: str, ref: str) -> dict[str, str]:
        status = "VALIDATED" if kind in methods else "UNSUPPORTED"
        method = methods.get(kind, "registry_lookup")
        evidence = '{"records":2}' if status == "VALIDATED" else "unsupported passive inventory"
        notes = "Live records observed" if status == "VALIDATED" else "inventory only"
        con.execute(
            "INSERT INTO cloud_assets (engagement_id, asset_type, identifier, provider_identifier, source) "
            "VALUES (?, ?, ?, ?, 'mock_provider') "
            "ON CONFLICT(engagement_id, asset_type, identifier) DO NOTHING",
            (EID, kind, ref, ref),
        )
        con.execute(
            """
            INSERT INTO cloud_validation_results
                (engagement_id, asset_type, identifier, provider_identifier,
                 validation_status, validation_method, http_status, evidence, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(engagement_id, asset_type, identifier) DO UPDATE SET
                validation_status=excluded.validation_status,
                validation_method=excluded.validation_method,
                evidence=excluded.evidence,
                notes=excluded.notes,
                checked_at=CURRENT_TIMESTAMP
            """,
            (
                EID,
                kind,
                ref,
                ref,
                status,
                method,
                200 if status == "VALIDATED" else None,
                evidence,
                notes,
            ),
        )
        return {"status": "success", "validation_status": status, "validation_method": method}

    def validate_batch(engagement_id, targets, db_path_arg, **kwargs):  # noqa: ANN001, ANN003
        del engagement_id, db_path_arg, kwargs
        with sqlite3.connect(db_path) as con:
            results = [validate_asset(con, str(kind), str(ref)) for kind, ref in targets]
            con.commit()
        return {"attempted": len(results), "succeeded": len(results), "failed": 0, "results": results}

    def sweep_assets(engagement_id, db_path_arg, limit=16, **kwargs):  # noqa: ANN001, ANN003
        del engagement_id, db_path_arg, kwargs
        with sqlite3.connect(db_path) as con:
            rows = con.execute(
                """
                SELECT ca.asset_type, ca.identifier
                FROM cloud_assets ca
                LEFT JOIN cloud_validation_results cvr
                  ON cvr.engagement_id=ca.engagement_id
                 AND cvr.asset_type=ca.asset_type
                 AND cvr.identifier=ca.identifier
                WHERE ca.engagement_id=? AND cvr.id IS NULL
                ORDER BY ca.id ASC
                LIMIT ?
                """,
                (EID, int(limit)),
            ).fetchall()
            results = [validate_asset(con, str(kind), str(ref)) for kind, ref in rows]
            con.commit()
        return {"attempted": len(results), "succeeded": len(results), "failed": 0, "results": results}

    monkeypatch.setattr(cloud_validate, "run_cloud_asset_validate_batch", validate_batch)
    monkeypatch.setattr(cloud_validate, "sweep_pending_cloud_asset_validations", sweep_assets)
    monkeypatch.setattr(cloud_validate, "sweep_pending_cloud_validations", lambda *_, **__: {"attempted": 0})


def _latest_report(reports_dir: Path) -> Path:
    reports = sorted(reports_dir.glob(f"engagement_{EID}_kill_chain_*.md"))
    assert len(reports) == 1
    return reports[0]


def _assert_artifacts(con: sqlite3.Connection) -> None:
    expected_formats = {
        MANIFEST_URL: "webmanifest",
        SERVICE_WORKER_URL: "service-worker-js",
        PRECACHE_URL: "service-worker-js",
        REPORT_CHUNK_URL: "js",
        DASHBOARD_CHUNK_URL: "js",
    }
    rows = {
        row["source_url"]: row
        for row in con.execute(
            """
            SELECT source_url, status, artifact_type, metadata_json
            FROM artifact_queue
            WHERE source_url IN (?, ?, ?, ?, ?)
            """,
            (MANIFEST_URL, SERVICE_WORKER_URL, PRECACHE_URL, REPORT_CHUNK_URL, DASHBOARD_CHUNK_URL),
        )
    }
    assert set(rows) == set(expected_formats)
    for source_url, expected_format in expected_formats.items():
        metadata = json.loads(rows[source_url]["metadata_json"])
        assert rows[source_url]["status"] == "parsed"
        assert rows[source_url]["artifact_type"] == "config"
        assert metadata["downloaded_from_remote"] is True
        assert metadata["format"] == expected_format
        assert int(metadata["payload_count"]) > 0


def _assert_recursive_seeds_and_relations(con: sqlite3.Connection) -> None:
    seeds = {(row["seed_value"], row["seed_type"]) for row in con.execute("SELECT seed_value, seed_type FROM engagement_seeds")}
    assert {
        ("acme.test", "domain"),
        ("ops@acme.test", "email"),
        ("manifest-sw-owner@acme.test", "email"),
        ("sw-report-owner@acme.test", "email"),
        ("sw-dashboard-owner@acme.test", "email"),
        (MANIFEST_URL, "url"),
        (SERVICE_WORKER_URL, "url"),
        (PRECACHE_URL, "url"),
        (REPORT_CHUNK_URL, "url"),
        (DASHBOARD_CHUNK_URL, "url"),
        ("https://sw-firebase-prod.firebaseio.com", "url"),
        ("https://sw-report-firebase.firebaseio.com", "url"),
        ("https://swreportvault.supabase.co", "url"),
        ("https://sw-dashboard-firebase.firebaseio.com", "url"),
        ("sw-report-firebase", "other"),
        ("sw-dashboard-firebase", "other"),
    } <= seeds

    relations = {
        (row["source_value"], row["target_value"], row["relation_type"])
        for row in con.execute(
            """
            SELECT source.seed_value AS source_value,
                   target.seed_value AS target_value,
                   sr.relation_type
            FROM seed_relations sr
            JOIN engagement_seeds source ON source.id=sr.source_seed_id
            JOIN engagement_seeds target ON target.id=sr.target_seed_id
            WHERE sr.engagement_id=?
            """,
            (EID,),
        )
    }
    assert (MANIFEST_URL, SERVICE_WORKER_URL, "derived_from") in relations
    assert (SERVICE_WORKER_URL, PRECACHE_URL, "derived_from") in relations
    assert (SERVICE_WORKER_URL, "https://sw-firebase-prod.firebaseio.com", "derived_from") in relations
    assert (PRECACHE_URL, REPORT_CHUNK_URL, "derived_from") in relations
    assert (PRECACHE_URL, DASHBOARD_CHUNK_URL, "derived_from") in relations
    assert (REPORT_CHUNK_URL, "sw-report-owner@acme.test", "derived_from") in relations
    assert (REPORT_CHUNK_URL, "https://swreportvault.supabase.co", "derived_from") in relations
    assert (DASHBOARD_CHUNK_URL, "sw-dashboard-owner@acme.test", "derived_from") in relations


def _assert_validation_and_findings(con: sqlite3.Connection) -> None:
    assets = {(row["asset_type"], row["identifier"]) for row in con.execute("SELECT asset_type, identifier FROM cloud_assets")}
    assert {
        ("firebase", "sw-firebase-prod"),
        ("firebase", "sw-report-firebase"),
        ("supabase", "swreportvault"),
        ("firebase", "sw-dashboard-firebase"),
        ("aws_s3", "sw-precache-logs"),
        ("gcs", "sw-precache-public"),
    } <= assets

    statuses = {
        (row["asset_type"], row["identifier"]): row["validation_status"]
        for row in con.execute("SELECT asset_type, identifier, validation_status FROM cloud_validation_results")
    }
    assert statuses[("firebase", "sw-firebase-prod")] == "VALIDATED"
    assert statuses[("firebase", "sw-report-firebase")] == "VALIDATED"
    assert statuses[("supabase", "swreportvault")] == "VALIDATED"
    assert statuses[("firebase", "sw-dashboard-firebase")] == "VALIDATED"
    assert statuses[("aws_s3", "sw-precache-logs")] == "UNSUPPORTED"
    assert statuses[("gcs", "sw-precache-public")] == "UNSUPPORTED"

    findings = con.execute(
        "SELECT title, target_url, severity, evidence FROM vulnerability_findings"
    ).fetchall()
    finding_targets = {row["target_url"] for row in findings}
    assert {
        "firebase://sw-firebase-prod",
        "firebase://sw-report-firebase",
        "supabase://swreportvault",
        "firebase://sw-dashboard-firebase",
    } <= finding_targets
    assert all(row["severity"] == "HIGH" for row in findings if row["target_url"] in finding_targets)
    assert not any("sw-precache-logs" in json.dumps(dict(row), sort_keys=True) for row in findings)
    assert not any("sw-precache-public" in json.dumps(dict(row), sort_keys=True) for row in findings)


def _assert_report_exports(report_path: Path, report_text: str, report_payload: dict[str, Any]) -> None:
    assert "firebase://sw-report-firebase" in report_text
    assert "supabase://swreportvault" in report_text
    assert "sw-precache-logs" not in report_text
    assert "sw-precache-public" not in report_text
    exported_findings = report_payload["context"]["exploits"]["exploited"]
    assert exported_findings
    assert all(finding["validation_status"] == "VALIDATED" for finding in exported_findings)
    assert not any("sw-precache-logs" in json.dumps(finding, sort_keys=True) for finding in exported_findings)
    assert any(
        item.get("identifier") == "sw-precache-logs"
        and item.get("validation_status") == "UNSUPPORTED"
        for item in report_payload["context"]["cloud_validation_inventory"]
    )

    with report_path.with_suffix(".csv").open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    finding_rows = [row for row in rows if row.get("record_type") == "finding"]
    validation_rows = [row for row in rows if row.get("record_type") == "cloud_validation"]
    assert finding_rows
    assert all(row["validation_status"] == "VALIDATED" for row in finding_rows)
    assert not any(row.get("cloud_identifier") == "sw-precache-logs" for row in finding_rows)
    assert any(
        row.get("cloud_identifier") == "sw-precache-logs"
        and row.get("validation_status") == "UNSUPPORTED"
        for row in validation_rows
    )


def _assert_graph_outputs(graph: dict[str, Any]) -> None:
    assert any(
        node.get("source_table") == "cloud_assets"
        and (node.get("metadata") or {}).get("identifier") == "swreportvault"
        and (node.get("metadata") or {}).get("validation_status") == "VALIDATED"
        for node in graph["nodes"]
    )
    assert any(
        node.get("source_table") == "vulnerability_findings"
        and (node.get("metadata") or {}).get("resource_id") == "swreportvault"
        and (node.get("metadata") or {}).get("validation_status") == "VALIDATED"
        for node in graph["nodes"]
    )
    assert not any(
        node.get("source_table") == "vulnerability_findings"
        and (node.get("metadata") or {}).get("resource_id") == "sw-precache-logs"
        for node in graph["nodes"]
    )


def _assert_dashboard_outputs(data_dir: Path, reports_dir: Path) -> None:
    output_path = reports_dir / "dashboard.html"
    generate_dashboard(data_dir=data_dir, reports_dir=reports_dir, output_path=output_path)
    site_root = reports_dir / "dashboard"
    overview = json.loads((site_root / "data" / "engagements.json").read_text(encoding="utf-8"))
    item = next(row for row in overview["items"] if row["id"] == str(EID))
    slug = item["slug"]
    detail_json = site_root / "data" / "engagements" / f"{slug}.json"
    detail_html = site_root / "engagements" / slug / "index.html"
    detail_payload = json.loads(detail_json.read_text(encoding="utf-8"))

    assert detail_html.exists()
    assert detail_payload["report_summary"]["provider"] == "template"
    assert detail_payload["report_summary"]["requested_provider"] == "auto"
    assert detail_payload["report_summary"]["fallback_reason"] == FALLBACK_REASON
    assert "sw-report-owner@acme.test" in detail_payload["seeds"]
    assert "sw-dashboard-owner@acme.test" in detail_payload["seeds"]
    findings = detail_payload["sections"]["vulnerability_findings"]
    assert any(row["Target"] == "firebase://sw-report-firebase" for row in findings)
    assert not any("sw-precache-logs" in json.dumps(row, sort_keys=True) for row in findings)
    validation_rows = {
        (row["Type"], row["Asset"]): row
        for row in detail_payload["sections"]["cloud_validation_results"]
    }
    assert validation_rows[("aws_s3", "sw-precache-logs")]["Status"] == "UNSUPPORTED"
    assert "Maltego Workspace" in detail_html.read_text(encoding="utf-8")
