from __future__ import annotations

import csv
import json
import socket
import sqlite3
import subprocess
from pathlib import Path
from urllib.parse import urlparse

import pytest

import forge.cli as cli
from forge.core.errors import ProviderUnavailableError
from forge.phase4 import cloud_validate
from forge.phase6.report_synthesizer import ReportSynthesizer

EID = 4242
SUPABASE_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImFjbWViYXNlIiwicm9sZSI6ImFub24ifQ."
    "signature"
)


def test_kill_chain_multiseed_recursive_discovery_stabilizes_with_validated_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    data_dir = tmp_path / ".forge_data"
    db_path = data_dir / "engagements" / f"{EID}.db"
    config = tmp_path / "data" / "artifacts" / "client-config.js"
    config.parent.mkdir(parents=True)
    config.write_text(
        f"""
        export const FIREBASE_URL = "https://artifact-firebase-prod.firebaseio.com";
        export const FIREBASE_DUP = "https://artifact-firebase-prod.firebaseio.com";
        export const DEAD_FIREBASE = "https://dead-firebase-prod.firebaseio.com";
        export const SUPABASE_URL = "https://acmebase.supabase.co";
        export const SUPABASE_ANON_KEY = "{SUPABASE_JWT}";
        export const OWNER = "artifact-owner@acme.test";
        export const DUPLICATE_OWNER = "ops@acme.test";
        export const CONFIG_URL = "https://app.acme.test/config";
        """.strip(),
        encoding="utf-8",
    )
    opensearch = config.parent / "opensearch.xml"
    opensearch.write_text(
        """
        <OpenSearchDescription
            xmlns="http://a9.com/-/spec/opensearch/1.1/"
            xmlns:moz="http://www.mozilla.org/2006/browser/search/">
          <Url type="text/html"
               template="https://search.acme.test/query?q={searchTerms}&amp;token=hidden&amp;view=public" />
          <moz:SearchForm>https://search.acme.test/advanced</moz:SearchForm>
          <Developer>search-owner@acme.test</Developer>
        </OpenSearchDescription>
        """.strip(),
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    for key, value in {
        "FORGE_DATA_DIR": str(data_dir),
        "FORGE_ENV": "test",
        "FORGE_ENGAGEMENT_KEY": "FORGE-TEST-ENGAGEMENT-KEY",
        "FORGE_OFFLINE_STRICT": "1",
    }.items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv("FORGE_REDIS_URL", raising=False)

    calls: list[list[str]] = []

    def connect() -> sqlite3.Connection:
        con = sqlite3.connect(db_path)
        con.execute(
            "CREATE TABLE IF NOT EXISTS social_profiles ("
            "id INTEGER PRIMARY KEY, engagement_id INTEGER NOT NULL, email TEXT NOT NULL, "
            "source TEXT NOT NULL DEFAULT 'mock_identity', profile_data TEXT, "
            "queried_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, "
            "UNIQUE(engagement_id, email, source))"
        )
        return con

    def ip(host: str) -> str:
        total = sum(ord(char) for char in host)
        return f"198.18.{total % 200}.{(total // 200) % 200 + 1}"

    def blocked(*args, **kwargs):  # noqa: ANN002, ANN003
        raise AssertionError(f"external network disabled: {args!r} {kwargs!r}")

    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "gethostbyname", lambda host: ip(str(host)))
    monkeypatch.setattr(socket, "gethostbyaddr", lambda addr: (_ for _ in ()).throw(OSError(addr)))
    try:
        import httpx

        monkeypatch.setattr(httpx, "Client", blocked)
    except ImportError:
        pass

    html = {
        "acme.test": """
            <a href="https://app.acme.test/config">config</a>
            <a href="https://github.com/acmeidentity">identity</a>
            ops@acme.test web-id@acme.test web-id@acme.test
            https://web-firebase-prod.firebaseio.com
            https://dead-firebase-prod.firebaseio.com
            https://acmebase.supabase.co
        """,
        "app.acme.test": """
            nested-web@acme.test https://web-firebase-prod.firebaseio.com
            <a href="https://static.acme.test/portal">portal</a>
        """,
        "static.acme.test": "ops@acme.test https://acmebase.supabase.co",
    }

    def html_batch(specs, fetch_playwright, fetch_target_html, **kwargs):  # noqa: ANN001, ANN003
        del fetch_playwright, fetch_target_html, kwargs
        return [
            ""
            if urlparse(spec.url).path.endswith(("robots.txt", "sitemap.xml"))
            else html.get((urlparse(spec.url).hostname or "").lower(), "")
            for spec in specs
        ]

    def callable_batch(items, worker, **kwargs):  # noqa: ANN001, ANN003
        label = str(kwargs.get("progress_label") or "")
        if "DNS enrichment" in label:
            return [
                {"root_domain": item, "queried_hosts": [str(item)], "cname_targets": ["static.acme.test"]}
                for item in items
            ]
        if "whois/RDAP" in label:
            return [{"root_domain": item, "rdap": {"registrant_emails": ["ops@acme.test"]}} for item in items]
        if "Wayback CDX" in label:
            urls = ["https://app.acme.test/config", "https://static.acme.test/portal"]
            return [{"root_domain": item, "urls": urls, "url_metadata": {}} for item in items]
        return [worker(item) for item in items]

    def fake_module(cmd_argv, **kwargs):  # noqa: ANN001, ANN003
        del kwargs
        argv = [str(part) for part in cmd_argv]
        calls.append(argv)
        if argv[:2] == ["graph", "build"]:
            cli.graph_build(
                engagement=str(EID),
                fmt="all",
                output_dir="reports",
                min_severity="LOW",
                critical_path_only=False,
                snapshot=True,
                max_nodes=150,
            )
            return subprocess.CompletedProcess(["forge", *argv], 0, "graph built\n", "")
        if argv[:2] == ["report", "generate"]:
            from forge.phase6.report_synthesizer import synthesise

            output = argv[argv.index("--output") + 1]
            provider = argv[argv.index("--provider") + 1] if "--provider" in argv else "auto"
            max_loops = int(argv[argv.index("--max-loops") + 1]) if "--max-loops" in argv else None
            synthesise(
                str(EID),
                output_path=output,
                assume_yes=True,
                provider=provider,
                max_correction_loops=max_loops,
            )
            return subprocess.CompletedProcess(["forge", *argv], 0, "report built\n", "")
        with connect() as con:
            if argv[:2] == ["recon", "subdomains"]:
                for host in ("app.acme.test", "static.acme.test", "app.acme.test"):
                    con.execute(
                        "INSERT OR IGNORE INTO hosts "
                        "(engagement_id, ip, hostname, os_family, host_context) "
                        'VALUES (?, ?, ?, \'unknown\', \'{"source":"mock"}\')',
                        (EID, ip(host), host),
                    )
            elif argv[:2] == ["osint", "harvest"]:
                for email in ("harvested@acme.test", "ops@acme.test"):
                    con.execute(
                        "INSERT OR IGNORE INTO emails (engagement_id, email, source) VALUES (?, ?, 'mock_harvest')",
                        (EID, email),
                    )
            elif argv[:2] == ["osint", "social"]:
                email = argv[argv.index("--emails") + 1]
                profile = {
                    "profiles": [
                        {
                            "platform": "github",
                            "profile_url": "https://github.com/acmeidentity",
                            "username": "acmeidentity",
                        }
                    ]
                }
                con.execute(
                    """
                    INSERT OR IGNORE INTO social_profiles
                        (engagement_id, email, source, profile_data)
                    VALUES (?, ?, 'mock_identity', ?)
                    """,
                    (EID, email, json.dumps(profile)),
                )
            con.commit()
        return subprocess.CompletedProcess(["forge", *argv], 0, "mock ok\n", "")

    def validate_asset(con: sqlite3.Connection, kind: str, ref: str) -> dict[str, str]:
        status = "UNVERIFIED" if ref.startswith("dead-") else "VALIDATED"
        methods = {
            "firebase": "firebase_database_shallow_read",
            "supabase": "supabase_rest_root",
        }
        method = "mock_unverified" if status == "UNVERIFIED" else methods[kind]
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
            VALUES (?, ?, ?, ?, ?, ?, 200, '{"records":1}', 'mock provider')
            ON CONFLICT(engagement_id, asset_type, identifier) DO UPDATE SET
                validation_status=excluded.validation_status,
                validation_method=excluded.validation_method,
                checked_at=CURRENT_TIMESTAMP
            """,
            (EID, kind, ref, ref, status, method),
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
                "SELECT ca.asset_type, ca.identifier FROM cloud_assets ca "
                "LEFT JOIN cloud_validation_results cvr ON cvr.engagement_id=ca.engagement_id "
                "AND cvr.asset_type=ca.asset_type AND cvr.identifier=ca.identifier "
                "WHERE ca.engagement_id=? AND cvr.id IS NULL LIMIT ?",
                (EID, int(limit)),
            ).fetchall()
            results = [validate_asset(con, str(kind), str(ref)) for kind, ref in rows]
            con.commit()
        counts = {status: sum(row["validation_status"] == status for row in results) for status in {"VALIDATED", "UNVERIFIED"}}
        return {"attempted": len(results), "succeeded": len(results), "failed": 0, "status_counts": counts}

    monkeypatch.setattr(cli, "_run_html_fetch_batch", html_batch)
    monkeypatch.setattr(cli, "_run_callable_batch", callable_batch)
    monkeypatch.setattr(cli, "_run_ptr_lookup_batch", lambda ips, *_args, **_kwargs: [(str(ip_), "") for ip_ in ips])
    monkeypatch.setattr(cli, "_run_forge_module_subprocess", fake_module)
    monkeypatch.setattr(cloud_validate, "run_cloud_asset_validate_batch", validate_batch)
    monkeypatch.setattr(cloud_validate, "sweep_pending_cloud_asset_validations", sweep_assets)
    monkeypatch.setattr(cloud_validate, "sweep_pending_cloud_validations", lambda *_, **__: {"attempted": 0})
    monkeypatch.setattr(ReportSynthesizer, "_ensure_provider_loaded", lambda self: None)
    monkeypatch.setattr(
        ReportSynthesizer,
        "_infer",
        lambda self, _prompt: (_ for _ in ()).throw(ProviderUnavailableError("mock quota exhausted")),
    )

    cli.kill_chain(
        "acme.test",
        related_seed=["ops@acme.test", "ops@acme.test"],
        engagement=str(EID),
        max_iter=4,
        parallel_fanout=1,
        skip_keyscan=True,
        report_provider="auto",
        report_max_loops=0,
    )

    reports = sorted((tmp_path / "reports").glob(f"engagement_{EID}_kill_chain_*.md"))
    assert len(reports) == 1
    report_path = reports[0]
    report_text = report_path.read_text(encoding="utf-8")
    report_json_path = report_path.with_suffix(".json")
    report_pdf_path = report_path.with_suffix(".pdf")
    report_csv_path = report_path.with_suffix(".csv")
    assert report_json_path.exists()
    assert report_pdf_path.exists()
    assert report_csv_path.exists()
    assert report_pdf_path.read_bytes().startswith(b"%PDF-1.4")
    report_payload = json.loads(report_json_path.read_text(encoding="utf-8"))
    assert report_payload["provider"] == "template"
    assert report_payload["requested_provider"] == "auto"
    assert report_payload["fallback_reason"] == "mock quota exhausted"
    assert report_payload["format"] == "markdown"
    assert str(report_payload["findings_checksum"]).startswith("sha256:")
    assert "LLM fallback engaged: mock quota exhausted" in report_text
    assert report_payload["report_lineage"]["rendered_provider"] == "template"
    assert report_payload["report_lineage"]["requested_provider"] == "auto"
    assert report_payload["report_lineage"]["fallback_reason"] == "mock quota exhausted"
    assert report_payload["report_lineage"]["findings_checksum"] == report_payload["findings_checksum"]
    graph = json.loads((tmp_path / "reports" / f"{EID}_attack_graph.json").read_text(encoding="utf-8"))

    with sqlite3.connect(db_path) as con:
        con.row_factory = sqlite3.Row
        seeds = {(row["seed_value"], row["seed_type"]) for row in con.execute("SELECT seed_value, seed_type FROM engagement_seeds")}
        assert {
            ("acme.test", "domain"),
            ("ops@acme.test", "email"),
            ("artifact-owner@acme.test", "email"),
            ("web-id@acme.test", "email"),
            ("nested-web@acme.test", "email"),
            ("search-owner@acme.test", "email"),
            ("app.acme.test", "subdomain"),
            ("static.acme.test", "subdomain"),
            ("https://app.acme.test/config", "url"),
            ("https://search.acme.test/query", "url"),
            ("https://search.acme.test/advanced", "url"),
        } <= seeds
        for table, columns in {
            "engagement_seeds": "seed_type, seed_value",
            "cloud_assets": "asset_type, identifier",
        }.items():
            duplicates = con.execute(f"SELECT {columns}, COUNT(*) n FROM {table} GROUP BY {columns} HAVING n > 1").fetchall()
            assert duplicates == []

        artifact = con.execute("SELECT status FROM artifact_queue WHERE local_path LIKE '%client-config.js'").fetchone()
        assert artifact is not None
        assert artifact["status"] == "parsed"
        opensearch_artifact = con.execute(
            "SELECT status, metadata_json FROM artifact_queue WHERE local_path LIKE '%opensearch.xml'"
        ).fetchone()
        assert opensearch_artifact is not None
        assert opensearch_artifact["status"] == "parsed"
        assert json.loads(opensearch_artifact["metadata_json"])["format"] == "opensearch-description"

        assets = {(row["asset_type"], row["identifier"]) for row in con.execute("SELECT asset_type, identifier FROM cloud_assets")}
        assert {
            ("firebase", "artifact-firebase-prod"),
            ("firebase", "web-firebase-prod"),
            ("firebase", "dead-firebase-prod"),
            ("supabase", "acmebase"),
        } <= assets
        statuses = {
            (row["asset_type"], row["identifier"]): row["validation_status"]
            for row in con.execute("SELECT asset_type, identifier, validation_status FROM cloud_validation_results")
        }
        assert statuses[("firebase", "web-firebase-prod")] == "VALIDATED"
        assert statuses[("firebase", "dead-firebase-prod")] == "UNVERIFIED"

        findings = con.execute("SELECT title, target_url, parameter, evidence FROM vulnerability_findings").fetchall()
        titles = {row["title"] for row in findings}
        assert {"Validated Firebase data exposure", "Validated Supabase data exposure"} <= titles
        assert not any("dead-firebase-prod" in " ".join(str(value or "") for value in row) for row in findings)

        loops = {row[0] for row in con.execute("SELECT DISTINCT loop_name FROM seed_runs")}
        assert {"fanout_a_subdomains", "fanout_e_chain", "fanout_d5_url_seed_html", "fanout_j_cloud_scan"} <= loops
        audit_actions = {row[0] for row in con.execute("SELECT action FROM audit_log")}
        assert {"kill_chain_start", "kill_chain_complete"} <= audit_actions

        run = con.execute(
            "SELECT current_iteration, status, metadata_json FROM engagement_runs ORDER BY id DESC LIMIT 1"
        ).fetchone()
        metadata = json.loads(run["metadata_json"])
        assert run["status"] == "completed"
        assert int(run["current_iteration"]) < 4
        assert metadata["last_iteration_stable"] is True
        assert all(delta == 0 for delta in metadata["last_iteration_delta"].values())

    assert any(call[:2] == ["osint", "social"] for call in calls)
    finding_nodes = [node for node in graph["nodes"] if node.get("source_table") == "vulnerability_findings"]
    assert finding_nodes
    assert all((node.get("metadata") or {}).get("validation_status") == "VALIDATED" for node in finding_nodes)
    finding_report = report_text.split("## 5. Vulnerability", 1)[1].split("## 6. Post-Exploitation", 1)[0]
    assert "Validated Firebase data exposure" in finding_report
    assert "Validated Supabase data exposure" in finding_report
    assert "dead-firebase-prod" not in finding_report
    exported_findings = report_payload["context"]["exploits"]["exploited"]
    assert exported_findings
    assert all(finding["validation_status"] == "VALIDATED" for finding in exported_findings)
    assert not any(
        "dead-firebase-prod" in json.dumps(finding, sort_keys=True)
        for finding in exported_findings
    )
    with report_csv_path.open(encoding="utf-8", newline="") as handle:
        csv_rows = list(csv.DictReader(handle))
    finding_rows = [row for row in csv_rows if row.get("record_type") == "finding"]
    validation_rows = [row for row in csv_rows if row.get("record_type") == "cloud_validation"]
    assert finding_rows
    assert all(row["validation_status"] == "VALIDATED" for row in finding_rows)
    assert not any("dead-firebase-prod" in json.dumps(row, sort_keys=True) for row in finding_rows)
    assert any(
        row.get("cloud_identifier") == "dead-firebase-prod"
        and row.get("validation_status") == "UNVERIFIED"
        for row in validation_rows
    )
