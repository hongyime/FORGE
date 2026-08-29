from __future__ import annotations

import gzip
import json
import sqlite3
import zipfile
from pathlib import Path

import typer
import pytest
from typer.testing import CliRunner

import forge.automation_cycle as automation_cycle_module
from forge.automation_cli import register_automation_commands
from forge.automation_target_feed import build_target_feed
from forge.connectors.secrets import store_connector_secret
from forge.db.session import get_engagement_db


app = typer.Typer()
register_automation_commands(app)
runner = CliRunner()


def _make_engagement_db(
    data_dir: Path, engagement_id: int, seeds: list[tuple[str, str]]
) -> None:
    db_path = data_dir / "engagements" / f"{engagement_id}.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            "CREATE TABLE engagement_seeds ("
            " id INTEGER PRIMARY KEY AUTOINCREMENT,"
            " engagement_id INTEGER NOT NULL,"
            " seed_value TEXT NOT NULL,"
            " seed_type TEXT NOT NULL,"
            " source TEXT DEFAULT 'discovered',"
            " status TEXT DEFAULT 'pending')"
        )
        for value, seed_type in seeds:
            conn.execute(
                "INSERT INTO engagement_seeds (engagement_id, seed_value, seed_type)"
                " VALUES (?, ?, ?)",
                (engagement_id, value, seed_type),
            )
        conn.commit()
    finally:
        conn.close()


def _make_dashboard_report(reports_dir: Path, family_id: str, payload: dict) -> None:
    data_dir = reports_dir / "dashboard" / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    (data_dir / f"{family_id}.json").write_text(json.dumps(payload), encoding="utf-8")


def test_feed_build_dry_run_merges_sources_with_provenance_and_writes_nothing(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    reports_dir = tmp_path / "reports"
    imports_dir = tmp_path / "imports"
    _make_engagement_db(data_dir, 1, [("portal.example", "domain")])
    _make_dashboard_report(
        reports_dir,
        "abc123",
        {
            "summary": {
                "hosts": ["web.example"],
                "urls": ["https://api.example/v1"],
                "emails": ["ops@example.com"],
            }
        },
    )
    imports_dir.mkdir(parents=True)
    (imports_dir / "threatfox.json").write_text(
        json.dumps({"data": [{"ioc": "badguy.example"}]}), encoding="utf-8"
    )
    out = tmp_path / "out" / "target-feed.json"

    result = runner.invoke(
        app,
        [
            "feed-build",
            "--output",
            str(out),
            "--json",
            "--data-dir",
            str(data_dir),
            "--reports-dir",
            str(reports_dir),
            "--imports-dir",
            str(imports_dir),
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["schema_version"] == "target-feed.v1"
    assert payload["dry_run"] is True
    assert payload["apply_requested"] is False
    assert not out.exists()

    typed_items = {
        (item["target_type"], item["canonical_value"]) for item in payload["items"]
    }
    assert ("domain", "portal.example") in typed_items
    provenances = " ".join(item["provenance"] for item in payload["items"])
    assert "report_family:abc123" in provenances
    assert "cti_file:threatfox.json" in provenances

    counts = payload["counts"]
    assert counts["total"] == len(payload["items"])
    assert counts["total"] >= 4
    assert counts["by_source"]["db"] >= 1
    assert counts["by_source"]["reports"] == 3
    assert counts["by_source"]["cti"] == 1
    assert counts["by_source_group"]["report_family:abc123"] == 3
    # deterministic ordering by target_key
    ordered_keys = [item["target_key"] for item in payload["items"]]
    assert ordered_keys == sorted(ordered_keys)
    assert any(item["source_group"] == "report_family:abc123" for item in payload["items"])


def test_feed_build_prioritizes_targets_seen_from_multiple_sources(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    reports_dir = tmp_path / "reports"
    _make_engagement_db(
        data_dir,
        1,
        [
            ("single-db.example", "domain"),
            ("shared.example", "domain"),
        ],
    )
    _make_dashboard_report(
        reports_dir,
        "sharedfam",
        {"summary": {"hosts": ["shared.example", "single-report.example"]}},
    )

    payload = build_target_feed(
        sources=["db", "reports"],
        data_dir=data_dir,
        reports_dir=reports_dir,
        imports_dir=tmp_path / "imports",
        limit=None,
        existing_feed_path=None,
    )

    first = payload["items"][0]
    assert first["canonical_value"] == "shared.example"
    assert first["source_count"] == 2
    assert first["priority"] == 90
    assert first["source_groups"] == ["db", "report_family:sharedfam"]
    assert all(item["priority"] == 60 for item in payload["items"][1:])


def test_feed_build_marks_non_global_ips_ineligible_for_autonomous_scan(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    reports_dir = tmp_path / "reports"
    _make_engagement_db(data_dir, 1, [("0.0.0.0", "ip")])
    _make_dashboard_report(reports_dir, "noise", {"summary": {"ips": ["0.0.0.0"]}})

    payload = build_target_feed(
        sources=["db", "reports"],
        data_dir=data_dir,
        reports_dir=reports_dir,
        imports_dir=tmp_path / "imports",
        limit=None,
        existing_feed_path=None,
    )

    item = payload["items"][0]
    assert item["canonical_value"] == "0.0.0.0"
    assert item["source_count"] == 2
    assert item["priority"] == 10
    assert item["scan_eligible"] is False
    assert item["scan_eligibility_reason"] == "non_global_ip"


def test_feed_build_apply_writes_then_rerun_reports_no_new(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    _make_engagement_db(data_dir, 7, [("resume.example", "domain")])
    out = tmp_path / "imports" / "target-feed.json"

    first = runner.invoke(
        app,
        [
            "feed-build",
            "--apply",
            "--json",
            "--output",
            str(out),
            "--data-dir",
            str(data_dir),
            "--reports-dir",
            str(tmp_path / "missing-reports"),
            "--imports-dir",
            str(tmp_path / "missing-imports"),
        ],
    )
    assert first.exit_code == 0, first.output
    first_payload = json.loads(first.output)
    assert first_payload["dry_run"] is False
    assert first_payload["apply_requested"] is True
    assert out.exists()
    on_disk = json.loads(out.read_text(encoding="utf-8"))
    assert on_disk["schema_version"] == "target-feed.v1"
    assert len(on_disk["items"]) == first_payload["counts"]["total"]
    assert on_disk["items"][0]["source_group"] == "db"

    second = runner.invoke(
        app,
        [
            "feed-build",
            "--apply",
            "--json",
            "--output",
            str(out),
            "--data-dir",
            str(data_dir),
            "--reports-dir",
            str(tmp_path / "missing-reports"),
            "--imports-dir",
            str(tmp_path / "missing-imports"),
        ],
    )
    assert second.exit_code == 0, second.output
    second_payload = json.loads(second.output)
    assert second_payload["counts"]["new_vs_existing"] == 0
    assert second_payload["counts"]["omitted_duplicate"] >= 1
    assert second_payload["items"][0]["source_group"] == "db"


def test_feed_build_rerun_reads_large_existing_feed_without_legacy_item_cap(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    existing = tmp_path / "imports" / "target-feed.json"
    existing.parent.mkdir(parents=True)
    existing_items = [
        {
            "target_type": "domain",
            "target_value": f"bulk-{index}.example",
            "source_kind": "previous",
            "source_group": "previous",
            "confidence": 0.9,
            "first_seen_at": "2026-08-28T00:00:00Z",
            "provenance": "previous-feed",
        }
        for index in range(1200)
    ]
    existing.write_text(
        json.dumps(
            {
                "schema_version": "target-feed.v1",
                "generated_at": "2026-08-28T00:00:00Z",
                "items": existing_items,
            }
        ),
        encoding="utf-8",
    )
    _make_engagement_db(data_dir, 8, [("bulk-1100.example", "domain")])

    payload = build_target_feed(
        sources=["db"],
        data_dir=data_dir,
        reports_dir=tmp_path / "reports",
        imports_dir=tmp_path / "imports",
        limit=None,
        existing_feed_path=existing,
    )

    assert payload["source_errors"] == []
    assert payload["counts"]["new_vs_existing"] == 0
    assert payload["counts"]["omitted_duplicate"] == 1
    assert payload["counts"]["existing_feed_items"] == 1200
    assert payload["counts"]["selected_existing_preserved"] == 1200
    assert payload["counts"]["selected_from_current_sources"] == 1
    assert payload["counts"]["generated_candidate_total"] == 1
    assert payload["counts"]["generated_unique_candidate_total"] == 1
    assert payload["counts"]["selected_includes_existing"] is True
    matched = [
        item for item in payload["items"] if item["canonical_value"] == "bulk-1100.example"
    ]
    assert matched[0]["source_group"] == "previous"


def test_feed_build_source_only_counts_do_not_confuse_preserved_existing_feed(
    tmp_path: Path,
) -> None:
    existing = tmp_path / "imports" / "target-feed.json"
    existing.parent.mkdir(parents=True)
    existing.write_text(
        json.dumps(
            {
                "schema_version": "target-feed.v1",
                "generated_at": "2026-08-28T00:00:00Z",
                "items": [
                    {
                        "target_type": "domain",
                        "target_value": "preserved.example",
                        "source_kind": "previous",
                        "source_group": "previous",
                        "confidence": 0.9,
                        "first_seen_at": "2026-08-28T00:00:00Z",
                        "provenance": "previous-feed",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    payload = build_target_feed(
        sources=["supabase"],
        data_dir=tmp_path / "data",
        reports_dir=tmp_path / "reports",
        imports_dir=tmp_path / "imports",
        limit=None,
        existing_feed_path=existing,
        supabase_config_path=tmp_path / "missing-supabase.json",
    )

    counts = payload["counts"]
    assert counts["selected"] == 1
    assert counts["selected_existing_preserved"] == 1
    assert counts["selected_from_current_sources"] == 0
    assert counts["selected_includes_existing"] is True
    assert counts["existing_feed_items"] == 1
    assert counts["generated_candidate_total"] == 0
    assert counts["generated_unique_candidate_total"] == 0
    assert counts["by_source"]["supabase"] == 0
    assert payload["source_errors"] == [
        {"source": "supabase", "error": "not_configured:local_config_file_missing"}
    ]


def test_supabase_add_dry_run_writes_no_config_and_derives_ref(tmp_path: Path) -> None:
    config = tmp_path / "imports" / "supabase-projects.local.json"

    result = runner.invoke(
        app,
        [
            "supabase-add",
            "https://abc123.supabase.co",
            "FORGE_SUPABASE_ABC123_READ_KEY",
            "--config",
            str(config),
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["schema_version"] == "forge.supabase_project_config.v1"
    assert payload["dry_run"] is True
    assert payload["execution_policy"] == "dry_run_no_writes"
    assert payload["project_ref"] == "abc123"
    assert payload["status"] == "would_append"
    assert payload["changed"] is True
    assert not config.exists()


def test_supabase_add_apply_writes_minimal_no_secret_project_config(
    tmp_path: Path,
) -> None:
    config = tmp_path / "imports" / "supabase-projects.local.json"

    result = runner.invoke(
        app,
        [
            "supabase-add",
            "abc123",
            "FORGE_SUPABASE_ABC123_READ_KEY",
            "--config",
            str(config),
            "--apply",
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["dry_run"] is False
    assert payload["execution_policy"] == "local_config_write_no_key_material"
    assert payload["status"] == "append"
    assert config.exists()
    on_disk = json.loads(config.read_text(encoding="utf-8"))
    assert on_disk["projects"] == [
        {
            "project_ref": "abc123",
            "key_env": "FORGE_SUPABASE_ABC123_READ_KEY",
            "limit": 100000,
            "status": "configured",
        }
    ]
    assert "url" not in on_disk["projects"][0]
    assert "tables" not in on_disk["projects"][0]
    assert "target_columns" not in on_disk["projects"][0]


def test_supabase_add_upgrades_pending_entry_without_replace(tmp_path: Path) -> None:
    config = tmp_path / "imports" / "supabase-projects.local.json"
    config.parent.mkdir(parents=True)
    config.write_text(
        json.dumps(
            {
                "projects": [
                    {
                        "project_ref": "abc123",
                        "key_env": "FORGE_SUPABASE_OLD_READ_KEY",
                        "limit": 100000,
                        "status": "pending_key",
                        "discovered_from": "report_family:one",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "supabase-add",
            "abc123",
            "FORGE_SUPABASE_ABC123_READ_KEY",
            "--config",
            str(config),
            "--limit",
            "5000",
            "--apply",
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["status"] == "update"
    on_disk = json.loads(config.read_text(encoding="utf-8"))
    assert on_disk["projects"][0]["key_env"] == "FORGE_SUPABASE_ABC123_READ_KEY"
    assert on_disk["projects"][0]["limit"] == 5000
    assert on_disk["projects"][0]["status"] == "configured"
    assert on_disk["projects"][0]["discovered_from"] == "report_family:one"


def test_supabase_add_preserves_configured_entry_unless_replace(
    tmp_path: Path,
) -> None:
    config = tmp_path / "imports" / "supabase-projects.local.json"
    config.parent.mkdir(parents=True)
    config.write_text(
        json.dumps(
            {
                "projects": [
                    {
                        "project_ref": "abc123",
                        "key_env": "FORGE_SUPABASE_OLD_READ_KEY",
                        "limit": 1000,
                        "status": "configured",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    no_replace = runner.invoke(
        app,
        [
            "supabase-add",
            "abc123",
            "FORGE_SUPABASE_NEW_READ_KEY",
            "--config",
            str(config),
            "--apply",
            "--json",
        ],
    )

    assert no_replace.exit_code == 0, no_replace.output
    no_replace_payload = json.loads(no_replace.output)
    assert no_replace_payload["status"] == "exists"
    on_disk = json.loads(config.read_text(encoding="utf-8"))
    assert on_disk["projects"][0]["key_env"] == "FORGE_SUPABASE_OLD_READ_KEY"

    replace = runner.invoke(
        app,
        [
            "supabase-add",
            "abc123",
            "FORGE_SUPABASE_NEW_READ_KEY",
            "--config",
            str(config),
            "--replace",
            "--apply",
            "--json",
        ],
    )

    assert replace.exit_code == 0, replace.output
    replace_payload = json.loads(replace.output)
    assert replace_payload["status"] == "update"
    on_disk = json.loads(config.read_text(encoding="utf-8"))
    assert on_disk["projects"][0]["key_env"] == "FORGE_SUPABASE_NEW_READ_KEY"


def test_supabase_add_rejects_key_values_and_bad_refs(tmp_path: Path) -> None:
    config = tmp_path / "imports" / "supabase-projects.local.json"

    pasted_key = runner.invoke(
        app,
        [
            "supabase-add",
            "abc123",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.fake",
            "--config",
            str(config),
            "--json",
        ],
    )
    assert pasted_key.exit_code == 2
    assert "key_env_invalid" in pasted_key.output
    assert not config.exists()

    bad_ref = runner.invoke(
        app,
        [
            "supabase-add",
            "../abc123",
            "FORGE_SUPABASE_ABC123_READ_KEY",
            "--config",
            str(config),
            "--json",
        ],
    )
    assert bad_ref.exit_code == 2
    assert "project_ref_invalid" in bad_ref.output
    assert not config.exists()


def test_input_add_dry_run_writes_no_queue(tmp_path: Path) -> None:
    imports_dir = tmp_path / "imports"

    result = runner.invoke(
        app,
        [
            "input-add",
            "--connector",
            "abusech_threatfox",
            "--file",
            "threatfox.json",
            "--imports-dir",
            str(imports_dir),
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["schema_version"] == "forge.source_input_config.v1"
    assert payload["dry_run"] is True
    assert payload["execution_policy"] == "dry_run_no_writes"
    assert payload["config_path"] == str(imports_dir / "threatfox-inputs.local.json")
    assert payload["connector_id"] == "abusech_threatfox"
    assert payload["input_kind"] == "cti_marker"
    assert payload["value"] == "threatfox.json"
    assert payload["status"] == "would_append"
    assert not (imports_dir / "threatfox-inputs.local.json").exists()


def test_input_add_apply_writes_source_queue_and_dedupes(tmp_path: Path) -> None:
    imports_dir = tmp_path / "imports"
    imports_dir.mkdir()
    (imports_dir / "pd-cloud-export.json").write_text("{}", encoding="utf-8")

    first = runner.invoke(
        app,
        [
            "input-add",
            "--connector",
            "projectdiscovery_cloud",
            "--file",
            str(imports_dir / "pd-cloud-export.json"),
            "--imports-dir",
            str(imports_dir),
            "--engagement",
            "1001",
            "--apply",
            "--json",
        ],
    )

    assert first.exit_code == 0, first.output
    first_payload = json.loads(first.output)
    assert first_payload["execution_policy"] == "local_queue_write_no_secret_material"
    assert first_payload["status"] == "append"
    assert first_payload["value"] == "pd-cloud-export.json"
    queue_path = imports_dir / "projectdiscovery-cloud-imports.local.json"
    queue = json.loads(queue_path.read_text(encoding="utf-8"))
    assert queue["schema_version"] == "forge.source_inputs.v1"
    assert queue["connector_id"] == "projectdiscovery_cloud"
    assert queue["input_kind"] == "discovery_artifact"
    assert queue["inputs"][0]["value"] == "pd-cloud-export.json"
    assert queue["inputs"][0]["engagement_id"] == 1001
    assert queue["inputs"][0]["priority"] == 85
    assert queue["inputs"][0]["source_groups"] == ["operator:input-add"]

    second = runner.invoke(
        app,
        [
            "input-add",
            "--connector",
            "projectdiscovery_cloud",
            "--file",
            "pd-cloud-export.json",
            "--imports-dir",
            str(imports_dir),
            "--engagement",
            "1001",
            "--apply",
            "--json",
        ],
    )

    assert second.exit_code == 0, second.output
    second_payload = json.loads(second.output)
    assert second_payload["status"] == "exists"
    queue = json.loads(queue_path.read_text(encoding="utf-8"))
    assert len(queue["inputs"]) == 1


def test_input_add_supports_validation_target_and_absolute_external_path(
    tmp_path: Path,
) -> None:
    imports_dir = tmp_path / "imports"
    artifact = tmp_path / "burp-results.xml"
    artifact.write_text("<issues />", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "input-add",
            "--connector",
            "burp_dast_xml",
            "--file",
            str(artifact),
            "--imports-dir",
            str(imports_dir),
            "--target",
            "https://app.example",
            "--apply",
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["input_kind"] == "validation_artifact"
    assert payload["value"] == str(artifact)
    assert payload["target"] == "https://app.example"
    queue = json.loads(
        (imports_dir / "burp-dast-imports.local.json").read_text(encoding="utf-8")
    )
    assert queue["inputs"][0]["value"] == str(artifact)
    assert queue["inputs"][0]["target"] == "https://app.example"


def test_input_add_rejects_unknown_connector_control_files_and_secret_values(
    tmp_path: Path,
) -> None:
    imports_dir = tmp_path / "imports"

    unknown = runner.invoke(
        app,
        [
            "input-add",
            "--connector",
            "unknown_connector",
            "--file",
            "artifact.json",
            "--imports-dir",
            str(imports_dir),
            "--json",
        ],
    )
    assert unknown.exit_code == 2
    assert "unsupported_connector:unknown_connector" in unknown.output

    control = runner.invoke(
        app,
        [
            "input-add",
            "--connector",
            "abusech_threatfox",
            "--file",
            "threatfox-inputs.local.json",
            "--imports-dir",
            str(imports_dir),
            "--json",
        ],
    )
    assert control.exit_code == 2
    assert "artifact_rejected:local_control_file_reference" in control.output

    secret = runner.invoke(
        app,
        [
            "input-add",
            "--connector",
            "abusech_threatfox",
            "--file",
            "sk-or-v1-do-not-store-this",
            "--imports-dir",
            str(imports_dir),
            "--json",
        ],
    )
    assert secret.exit_code == 2
    assert "artifact_must_be_local_path_not_secret_value" in secret.output
    assert not any(imports_dir.glob("*.local.json"))


def test_cti_refresh_dry_run_does_not_call_network_or_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    imports_dir = tmp_path / "imports"
    imports_dir.mkdir()
    (imports_dir / "threatfox-observations.local.json").write_text(
        json.dumps({"schema_version": "forge.cti_observations.local.v1", "data": []}),
        encoding="utf-8",
    )

    def fail_post(*_args, **_kwargs):
        raise AssertionError("dry-run must not call ThreatFox")

    monkeypatch.setattr(automation_cycle_module.httpx, "post", fail_post)

    result = runner.invoke(
        app,
        [
            "cti-refresh",
            "--provider",
            "threatfox",
            "--imports-dir",
            str(imports_dir),
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["schema_version"] == "forge.public_cti_refresh.v1"
    assert payload["execution_policy"] == "dry_run_no_network_or_writes"
    assert payload["downloaded_count"] == 0
    assert payload["written"] is False
    assert payload["requires_key_env"] is True
    assert payload["key_env"] == "FORGE_THREATFOX_AUTH_KEY"
    assert payload["queue_update"]["status"] == "would_append"
    saved = json.loads(
        (imports_dir / "threatfox-observations.local.json").read_text(encoding="utf-8")
    )
    assert saved["data"] == []
    assert not (imports_dir / "threatfox-inputs.local.json").exists()


def test_cti_refresh_apply_fetches_threatfox_artifact_and_queues_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    imports_dir = tmp_path / "imports"
    monkeypatch.setenv("FORGE_THREATFOX_AUTH_KEY", "free-test-auth-key")

    class FakeResponse:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict:
            return {
                "query_status": "ok",
                "data": [
                    {
                        "id": "1",
                        "ioc": "alpha.example",
                        "ioc_type": "domain",
                        "confidence_level": 80,
                    },
                    {
                        "id": "2",
                        "ioc": "https://beta.example/path",
                        "ioc_type": "url",
                        "confidence_level": 75,
                    },
                ],
            }

    requests: list[dict] = []

    def fake_post(url, *, headers, json, timeout):
        requests.append(
            {"url": url, "headers": headers, "json": json, "timeout": timeout}
        )
        return FakeResponse()

    monkeypatch.setattr(automation_cycle_module.httpx, "post", fake_post)

    result = runner.invoke(
        app,
        [
            "cti-refresh",
            "--provider",
            "threatfox",
            "--imports-dir",
            str(imports_dir),
            "--days",
            "2",
            "--limit",
            "1",
            "--engagement",
            "1001",
            "--key-env",
            "FORGE_THREATFOX_AUTH_KEY",
            "--apply",
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["execution_policy"] == (
        "public_provider_read_local_artifact_and_queue_write"
    )
    assert payload["downloaded_count"] == 1
    assert requests == [
        {
            "url": automation_cycle_module.THREATFOX_RECENT_IOCS_URL,
            "headers": {"Auth-Key": "free-test-auth-key"},
            "json": {"query": "get_iocs", "days": 2},
            "timeout": 30.0,
        }
    ]
    artifact = imports_dir / "threatfox-observations.local.json"
    saved = json.loads(artifact.read_text(encoding="utf-8"))
    assert saved["schema_version"] == "forge.cti_observations.local.v1"
    assert saved["provider"] == "abusech_threatfox"
    assert saved["collection_method"] == "public_api_recent_iocs"
    assert [item["ioc"] for item in saved["data"]] == ["alpha.example"]
    queue = json.loads(
        (imports_dir / "threatfox-inputs.local.json").read_text(encoding="utf-8")
    )
    assert queue["inputs"][0]["value"] == "threatfox-observations.local.json"
    assert queue["inputs"][0]["engagement_id"] == 1001
    assert payload["queue_update"]["status"] == "append"


def test_cti_refresh_apply_defaults_to_threatfox_key_env(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    imports_dir = tmp_path / "imports"
    monkeypatch.setenv("FORGE_THREATFOX_AUTH_KEY", "free-test-auth-key")

    class FakeResponse:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict:
            return {
                "query_status": "ok",
                "data": [
                    {
                        "id": "1",
                        "ioc": "default-env.example",
                        "ioc_type": "domain",
                    }
                ],
            }

    requests: list[dict] = []

    def fake_post(url, *, headers, json, timeout):
        requests.append(
            {"url": url, "headers": headers, "json": json, "timeout": timeout}
        )
        return FakeResponse()

    monkeypatch.setattr(automation_cycle_module.httpx, "post", fake_post)

    result = runner.invoke(
        app,
        [
            "cti-refresh",
            "--provider",
            "threatfox",
            "--imports-dir",
            str(imports_dir),
            "--engagement",
            "1001",
            "--apply",
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["key_env"] == "FORGE_THREATFOX_AUTH_KEY"
    assert payload["downloaded_count"] == 1
    assert requests[0]["headers"] == {"Auth-Key": "free-test-auth-key"}


def test_cti_refresh_dry_run_supports_urlhaus_without_network(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    imports_dir = tmp_path / "imports"
    imports_dir.mkdir()

    def fail_get(*_args, **_kwargs):
        raise AssertionError("dry-run must not call URLhaus")

    monkeypatch.setattr(automation_cycle_module.httpx, "get", fail_get)

    result = runner.invoke(
        app,
        [
            "cti-refresh",
            "--provider",
            "urlhaus",
            "--imports-dir",
            str(imports_dir),
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["execution_policy"] == "dry_run_no_network_or_writes"
    assert payload["provider"] == "urlhaus"
    assert payload["source_url"] == automation_cycle_module.URLHAUS_RECENT_CSV_URL_REDACTED
    assert payload["key_env"] == "FORGE_URLHAUS_AUTH_KEY"
    assert payload["queue_update"]["connector_id"] == "abusech_urlhaus"
    assert payload["queue_update"]["value"] == "urlhaus-observations.local.json"
    assert not (imports_dir / "urlhaus-inputs.local.json").exists()


def test_cti_refresh_apply_fetches_urlhaus_artifact_and_queues_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    imports_dir = tmp_path / "imports"
    monkeypatch.setenv("FORGE_URLHAUS_AUTH_KEY", "free-urlhaus-auth-key")

    class FakeResponse:
        text = (
            "# URLhaus recent CSV\n"
            "id,dateadded,url,url_status,threat,tags,urlhaus_link,reporter\n"
            "1,2026-08-29 00:00:00,https://malware.example/payload.exe,online,"
            "malware_download,test,https://urlhaus.abuse.ch/url/1/,analyst\n"
            "2,2026-08-29 00:01:00,https://second.example/dropper,online,"
            "malware_download,test,https://urlhaus.abuse.ch/url/2/,analyst\n"
        )

        def raise_for_status(self) -> None:
            return None

    requests: list[dict[str, object]] = []

    def fake_get(url, *, timeout):
        requests.append({"url": url, "timeout": timeout})
        return FakeResponse()

    monkeypatch.setattr(automation_cycle_module.httpx, "get", fake_get)

    result = runner.invoke(
        app,
        [
            "cti-refresh",
            "--provider",
            "urlhaus",
            "--imports-dir",
            str(imports_dir),
            "--limit",
            "1",
            "--engagement",
            "1001",
            "--apply",
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["execution_policy"] == (
        "public_provider_read_local_artifact_and_queue_write"
    )
    assert payload["provider"] == "urlhaus"
    assert payload["source_url"] == automation_cycle_module.URLHAUS_RECENT_CSV_URL_REDACTED
    assert payload["downloaded_count"] == 1
    assert requests == [
        {
            "url": automation_cycle_module.URLHAUS_RECENT_CSV_URL_TEMPLATE.format(
                auth_key="free-urlhaus-auth-key"
            ),
            "timeout": 30.0,
        }
    ]
    artifact = imports_dir / "urlhaus-observations.local.json"
    saved = json.loads(artifact.read_text(encoding="utf-8"))
    assert saved["provider"] == "abusech_urlhaus"
    assert saved["source_url"] == automation_cycle_module.URLHAUS_RECENT_CSV_URL_REDACTED
    assert saved["collection_method"] == "public_api_recent_urls"
    assert saved["data"][0]["ioc"] == "https://malware.example/payload.exe"
    queue = json.loads(
        (imports_dir / "urlhaus-inputs.local.json").read_text(encoding="utf-8")
    )
    assert queue["inputs"][0]["value"] == "urlhaus-observations.local.json"
    assert queue["inputs"][0]["engagement_id"] == 1001
    assert payload["queue_update"]["connector_id"] == "abusech_urlhaus"


def test_cti_refresh_apply_requires_key_env_value_without_writes(tmp_path: Path) -> None:
    imports_dir = tmp_path / "imports"

    result = runner.invoke(
        app,
        [
            "cti-refresh",
            "--provider",
            "threatfox",
            "--imports-dir",
            str(imports_dir),
            "--apply",
            "--json",
        ],
    )

    assert result.exit_code == 2
    assert "key_env_unset:FORGE_THREATFOX_AUTH_KEY" in result.output
    assert not (imports_dir / "threatfox-observations.local.json").exists()
    assert not (imports_dir / "threatfox-inputs.local.json").exists()


def test_cti_refresh_apply_no_result_writes_no_empty_queue(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    imports_dir = tmp_path / "imports"
    monkeypatch.setenv("FORGE_THREATFOX_AUTH_KEY", "free-test-auth-key")

    class FakeResponse:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict:
            return {"query_status": "no_result", "data": []}

    monkeypatch.setattr(
        automation_cycle_module.httpx,
        "post",
        lambda *_args, **_kwargs: FakeResponse(),
    )

    result = runner.invoke(
        app,
        [
            "cti-refresh",
            "--provider",
            "threatfox",
            "--key-env",
            "FORGE_THREATFOX_AUTH_KEY",
            "--imports-dir",
            str(imports_dir),
            "--apply",
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["execution_policy"] == "public_provider_read_no_iocs_no_writes"
    assert payload["downloaded_count"] == 0
    assert payload["written"] is False
    assert payload["queue_update"] is None
    assert not (imports_dir / "threatfox-observations.local.json").exists()
    assert not (imports_dir / "threatfox-inputs.local.json").exists()


def test_cti_refresh_http_failure_writes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    imports_dir = tmp_path / "imports"
    monkeypatch.setenv("FORGE_THREATFOX_AUTH_KEY", "free-test-auth-key")

    def fail_post(*_args, **_kwargs):
        raise RuntimeError("network down")

    monkeypatch.setattr(automation_cycle_module.httpx, "post", fail_post)

    result = runner.invoke(
        app,
        [
            "cti-refresh",
            "--provider",
            "threatfox",
            "--key-env",
            "FORGE_THREATFOX_AUTH_KEY",
            "--imports-dir",
            str(imports_dir),
            "--apply",
            "--json",
        ],
    )

    assert result.exit_code == 2
    assert "threatfox_http:RuntimeError" in result.output
    assert not (imports_dir / "threatfox-observations.local.json").exists()
    assert not (imports_dir / "threatfox-inputs.local.json").exists()


def test_cti_refresh_rejects_keyed_or_unimplemented_public_sources(
    tmp_path: Path,
) -> None:
    result = runner.invoke(
        app,
        [
            "cti-refresh",
            "--provider",
            "misp",
            "--imports-dir",
            str(tmp_path / "imports"),
            "--json",
        ],
    )

    assert result.exit_code == 2
    assert "unsupported_public_cti_provider:misp" in result.output


def test_feed_build_missing_and_malformed_sources_fail_soft(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir(parents=True)
    (data_dir / "engagements").mkdir()
    broken_db = data_dir / "engagements" / "99.db"
    broken_db.write_bytes(b"this is not sqlite")
    reports_dir = tmp_path / "reports"
    _make_dashboard_report(reports_dir, "goodfam", {"hosts": ["fine.example"]})
    (reports_dir / "dashboard" / "data" / "corrupt.json").write_text(
        "{not json", encoding="utf-8"
    )

    payload = build_target_feed(
        sources=["db", "reports"],
        data_dir=data_dir,
        reports_dir=reports_dir,
        imports_dir=tmp_path / "nope",
        limit=None,
        existing_feed_path=None,
    )

    assert payload["counts"]["by_source"]["db"] == 0
    assert payload["counts"]["by_source"]["reports"] >= 1
    error_sources = {err["source"] for err in payload["source_errors"]}
    assert "db" in error_sources
    assert "reports" in error_sources


def test_feed_build_reports_skips_dashboard_aggregate_without_error(tmp_path: Path) -> None:
    reports_dir = tmp_path / "reports"
    data_dir = reports_dir / "dashboard" / "data"
    data_dir.mkdir(parents=True)
    (data_dir / "engagements.json").write_text(
        json.dumps({"items": [{"target": "aggregate-only.example"}]}),
        encoding="utf-8",
    )
    _make_dashboard_report(reports_dir, "detailfam", {"hosts": ["detail.example"]})

    payload = build_target_feed(
        sources=["reports"],
        data_dir=tmp_path / "data",
        reports_dir=reports_dir,
        imports_dir=tmp_path / "imports",
        limit=None,
        existing_feed_path=None,
    )

    assert payload["source_errors"] == []
    values = {item["target_value"] for item in payload["items"]}
    assert "detail.example" in values
    assert "aggregate-only.example" not in values


def test_feed_build_reports_scan_current_corpus_sized_family_count(
    tmp_path: Path,
) -> None:
    reports_dir = tmp_path / "reports"
    for index in range(520):
        _make_dashboard_report(
            reports_dir,
            f"family_{index:03d}",
            {"hosts": [f"family-{index}.example"]},
        )

    payload = build_target_feed(
        sources=["reports"],
        data_dir=tmp_path / "data",
        reports_dir=reports_dir,
        imports_dir=tmp_path / "imports",
        limit=None,
        existing_feed_path=None,
    )

    assert payload["source_errors"] == []
    assert payload["counts"]["by_source"]["reports"] == 520
    assert (
        payload["counts"]["by_source_group"]["report_family:family_519"] == 1
    )
    assert "family-519.example" in {
        item["canonical_value"] for item in payload["items"]
    }


def test_feed_build_connector_source_ignores_local_config_files(tmp_path: Path) -> None:
    imports_dir = tmp_path / "imports"
    imports_dir.mkdir(parents=True)
    (imports_dir / "supabase-projects.local.json").write_text(
        json.dumps(
            {
                "projects": [],
                "_example_project": {
                    "url": "https://abc123.supabase.co",
                    "domain": "should-not-import.example",
                },
            }
        ),
        encoding="utf-8",
    )
    (imports_dir / "autostart.local.json").write_text(
        json.dumps({"feed_sources": ["all"], "target": "skip-autostart.example"}),
        encoding="utf-8",
    )
    (imports_dir / "target-feed.json").write_text(
        json.dumps({"items": [{"target_value": "skip-existing.example"}]}),
        encoding="utf-8",
    )
    (imports_dir / "projectdiscovery-cloud-imports.local.json").write_text(
        json.dumps({"inputs": [{"value": "skip-local-registry.example"}]}),
        encoding="utf-8",
    )
    (imports_dir / "connector-output.json").write_text(
        json.dumps({"targets": ["keep.example"]}),
        encoding="utf-8",
    )

    payload = build_target_feed(
        sources=["connectors"],
        data_dir=tmp_path / "data",
        reports_dir=tmp_path / "reports",
        imports_dir=imports_dir,
        limit=None,
        existing_feed_path=None,
    )

    assert payload["counts"]["by_source"]["connectors"] == 1
    assert payload["items"][0]["canonical_value"] == "keep.example"
    assert payload["items"][0]["source_group"] == "connector_file:connector-output.json"


def test_feed_build_connector_source_harvests_text_csv_xml_gzip_and_zip(
    tmp_path: Path,
) -> None:
    imports_dir = tmp_path / "imports"
    imports_dir.mkdir()
    (imports_dir / "runzero-assets.csv").write_text(
        "hostname,ip\ncsv-feed.example,198.51.100.10\n",
        encoding="utf-8",
    )
    (imports_dir / "burp-results.xml").write_text(
        "<issue><host>xml-feed.example</host></issue>",
        encoding="utf-8",
    )
    with gzip.open(imports_dir / "censys-hosts.json.gz", "wt", encoding="utf-8") as handle:
        handle.write('{"services":[{"host":"gzip-feed.example"}]}')
    with zipfile.ZipFile(imports_dir / "pd-cloud-export.zip", "w") as archive:
        archive.writestr("assets.json", '{"targets":["zip-feed.example"]}')

    payload = build_target_feed(
        sources=["connectors"],
        data_dir=tmp_path / "data",
        reports_dir=tmp_path / "reports",
        imports_dir=imports_dir,
        limit=None,
        existing_feed_path=None,
    )

    values = {item["canonical_value"] for item in payload["items"]}
    assert {
        "csv-feed.example",
        "198.51.100.10",
        "xml-feed.example",
        "gzip-feed.example",
        "zip-feed.example",
    } <= values
    assert payload["counts"]["by_source_group"]["connector_file:runzero-assets.csv"] == 2
    assert payload["counts"]["by_source_group"]["connector_file:burp-results.xml"] == 1


def test_feed_build_cti_source_ignores_source_input_queue_files(tmp_path: Path) -> None:
    imports_dir = tmp_path / "imports"
    imports_dir.mkdir()
    (imports_dir / "threatfox-inputs.local.json").write_text(
        json.dumps({"inputs": [{"value": "skip-queue.example"}]}),
        encoding="utf-8",
    )
    (imports_dir / "threatfox-observations.local.json").write_text(
        json.dumps({"iocs": ["keep-observation.example"]}),
        encoding="utf-8",
    )

    payload = build_target_feed(
        sources=["cti"],
        data_dir=tmp_path / "data",
        reports_dir=tmp_path / "reports",
        imports_dir=imports_dir,
        limit=None,
        existing_feed_path=None,
    )

    assert [item["canonical_value"] for item in payload["items"]] == [
        "keep-observation.example"
    ]
    assert payload["items"][0]["source_group"] == (
        "cti_file:threatfox-observations.local.json"
    )


def test_feed_build_discovery_ignores_empty_scaffolds_and_queue_controls(
    tmp_path: Path,
) -> None:
    imports_dir = tmp_path / "imports"
    imports_dir.mkdir()
    (imports_dir / "threatfox-observations.local.json").write_text(
        json.dumps({"schema_version": "forge.cti_observations.local.v1", "data": []}),
        encoding="utf-8",
    )
    (imports_dir / "projectdiscovery-cloud-imports.local.json").write_text(
        json.dumps({"inputs": []}),
        encoding="utf-8",
    )
    (imports_dir / "real-projectdiscovery-export.json").write_text(
        json.dumps({"targets": ["pd-real.example"]}),
        encoding="utf-8",
    )

    payload = build_target_feed(
        sources=["connectors", "cti"],
        data_dir=tmp_path / "data",
        reports_dir=tmp_path / "reports",
        imports_dir=imports_dir,
        limit=None,
        existing_feed_path=None,
    )

    discovered_values = {item["value"] for item in payload["new_discovered_inputs"]}
    assert "threatfox-observations.local.json" not in discovered_values
    assert "projectdiscovery-cloud-imports.local.json" not in discovered_values
    assert "real-projectdiscovery-export.json" in discovered_values


def test_feed_build_dry_run_reports_discovered_supabase_projects_without_config_write(
    tmp_path: Path,
) -> None:
    reports_dir = tmp_path / "reports"
    _make_dashboard_report(
        reports_dir,
        "supabase_refs",
        {
            "urls": [
                "https://abc123.supabase.co/rest/v1/assets?id=eq.1",
                "https://def456.supabase.co/storage/v1/object/public/logo.png",
            ]
        },
    )
    config = tmp_path / "imports" / "supabase-projects.local.json"

    payload = build_target_feed(
        sources=["reports", "supabase"],
        data_dir=tmp_path / "data",
        reports_dir=reports_dir,
        imports_dir=tmp_path / "imports",
        limit=None,
        existing_feed_path=None,
        apply=False,
        supabase_config_path=config,
    )

    assert not config.exists()
    discovered = {
        (item["project_ref"], item["key_env"])
        for item in payload["discovered_supabase_projects"]
    }
    assert discovered == {
        ("abc123", "FORGE_SUPABASE_ABC123_READ_KEY"),
        ("def456", "FORGE_SUPABASE_DEF456_READ_KEY"),
    }
    assert payload["supabase_project_config_update"] == {
        "config_path": str(config),
        "applied": False,
        "appended_count": 0,
        "pending_key_count": 2,
    }


def test_feed_build_apply_appends_discovered_supabase_projects_to_local_config(
    tmp_path: Path,
) -> None:
    reports_dir = tmp_path / "reports"
    _make_dashboard_report(
        reports_dir,
        "supabase_refs",
        {"urls": ["https://abc123.supabase.co/rest/v1/assets?id=eq.1"]},
    )
    config = tmp_path / "imports" / "supabase-projects.local.json"
    config.parent.mkdir(parents=True)
    config.write_text(
        json.dumps({"projects": [{"project_ref": "knownref", "key_env": "KNOWN_KEY"}]}),
        encoding="utf-8",
    )

    payload = build_target_feed(
        sources=["reports"],
        data_dir=tmp_path / "data",
        reports_dir=reports_dir,
        imports_dir=tmp_path / "imports",
        limit=None,
        existing_feed_path=None,
        apply=True,
        supabase_config_path=config,
    )

    updated = json.loads(config.read_text(encoding="utf-8"))
    projects = {project["project_ref"]: project for project in updated["projects"]}
    assert set(projects) == {"knownref", "abc123"}
    assert projects["abc123"]["key_env"] == "FORGE_SUPABASE_ABC123_READ_KEY"
    assert projects["abc123"]["limit"] == 100000
    assert projects["abc123"]["status"] == "pending_key"
    assert "report_family:supabase_refs" in projects["abc123"]["discovered_from"]
    assert payload["supabase_project_config_update"]["applied"] is True
    assert payload["supabase_project_config_update"]["appended_count"] == 1
    assert payload["new_discovered_supabase_projects"] == [
        {
            "project_ref": "abc123",
            "key_env": "FORGE_SUPABASE_ABC123_READ_KEY",
            "status": "pending_key",
        }
    ]


def test_feed_build_dry_run_reports_discovered_input_registry_without_write(
    tmp_path: Path,
) -> None:
    imports_dir = tmp_path / "imports"
    imports_dir.mkdir()
    (imports_dir / "burp-results.xml").write_text("<issues />", encoding="utf-8")
    (imports_dir / "pd-cloud-export.json").write_text("{}", encoding="utf-8")
    (imports_dir / "runzero-assets.csv").write_text("id,name\n1,host\n", encoding="utf-8")
    reports_dir = tmp_path / "reports"
    _make_dashboard_report(
        reports_dir,
        "input_hints",
        {
            "urls": ["https://abc123.supabase.co/rest/v1/assets?id=eq.1"],
            "targets": ["artifact-hints.example"],
        },
    )

    payload = build_target_feed(
        sources=["reports", "connectors"],
        data_dir=tmp_path / "data",
        reports_dir=reports_dir,
        imports_dir=imports_dir,
        limit=None,
        existing_feed_path=None,
        apply=False,
        supabase_config_path=imports_dir / "supabase-projects.local.json",
    )

    assert not (imports_dir / "discovered-inputs.local.json").exists()
    discovered = {
        (item["input_kind"], item["connector_id"], item["value"])
        for item in payload["discovered_inputs"]
    }
    assert (
        "supabase_project",
        "supabase_table_import",
        "abc123",
    ) in discovered
    assert (
        "discovery_artifact",
        "projectdiscovery_cloud",
        "pd-cloud-export.json",
    ) in discovered
    assert (
        "validation_artifact",
        "burp_dast_xml",
        "burp-results.xml",
    ) in discovered
    assert (
        "discovery_artifact",
        "runzero_asset_export",
        "runzero-assets.csv",
    ) in discovered
    next_actions = {
        (item["connector_id"], item["value"]): item["next_action"]
        for item in payload["discovered_inputs"]
    }
    assert next_actions[("projectdiscovery_cloud", "pd-cloud-export.json")] == (
        "forge connectors import-discovery --connector projectdiscovery_cloud "
        "--report-file <path> --dry-run --limit 1000 --json"
    )
    assert next_actions[("runzero_asset_export", "runzero-assets.csv")] == (
        "forge connectors import-discovery --connector runzero_asset_export "
        "--report-file <path> --dry-run --limit 1000 --json"
    )
    assert payload["discovered_input_registry_update"] == {
        "config_path": str(imports_dir / "discovered-inputs.local.json"),
        "applied": False,
        "appended_count": 0,
        "pending_count": len(payload["new_discovered_inputs"]),
    }
    update_paths = {
        Path(str(item["config_path"])).name: item
        for item in payload["source_input_registry_updates"]
    }
    assert update_paths["projectdiscovery-cloud-imports.local.json"] == {
        "config_path": str(imports_dir / "projectdiscovery-cloud-imports.local.json"),
        "applied": False,
        "appended_count": 0,
        "pending_count": 1,
    }
    assert update_paths["burp-dast-imports.local.json"] == {
        "config_path": str(imports_dir / "burp-dast-imports.local.json"),
        "applied": False,
        "appended_count": 0,
        "pending_count": 1,
    }


def test_feed_build_apply_appends_discovered_input_registry(
    tmp_path: Path,
) -> None:
    imports_dir = tmp_path / "imports"
    imports_dir.mkdir()
    (imports_dir / "threatfox-observations.local.json").write_text(
        json.dumps({"iocs": ["ioc.example"]}),
        encoding="utf-8",
    )
    registry = imports_dir / "discovered-inputs.local.json"
    registry.write_text(
        json.dumps(
            {
                "schema_version": "forge.discovered_inputs.v1",
                "inputs": [
                    {
                        "input_kind": "validation_artifact",
                        "connector_id": "burp_dast_xml",
                        "value": "burp-results.xml",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    (imports_dir / "burp-results.xml").write_text("<issues />", encoding="utf-8")

    payload = build_target_feed(
        sources=["cti", "connectors"],
        data_dir=tmp_path / "data",
        reports_dir=tmp_path / "reports",
        imports_dir=imports_dir,
        limit=None,
        existing_feed_path=None,
        apply=True,
        supabase_config_path=imports_dir / "supabase-projects.local.json",
    )

    updated = json.loads(registry.read_text(encoding="utf-8"))
    keys = {
        (item.get("input_kind"), item.get("connector_id"), item.get("value"))
        for item in updated["inputs"]
    }
    assert (
        "validation_artifact",
        "burp_dast_xml",
        "burp-results.xml",
    ) in keys
    assert (
        "cti_marker",
        "abusech_threatfox",
        "threatfox-observations.local.json",
    ) in keys
    assert payload["discovered_input_registry_update"]["applied"] is True
    assert payload["discovered_input_registry_update"]["appended_count"] == 1
    assert payload["source_input_registry_updates"] == [
        {
            "config_path": str(imports_dir / "threatfox-inputs.local.json"),
            "applied": True,
            "appended_count": 1,
            "pending_count": 0,
        }
    ]
    specific = json.loads(
        (imports_dir / "threatfox-inputs.local.json").read_text(encoding="utf-8")
    )
    assert specific["connector_id"] == "abusech_threatfox"
    assert [
        item["value"]
        for item in specific["inputs"]
    ] == ["threatfox-observations.local.json"]
    assert payload["counts"]["by_source"]["connectors"] == 0


def test_feed_build_reports_omitted_local_input_files_after_scan_cap(
    tmp_path: Path,
) -> None:
    imports_dir = tmp_path / "imports"
    imports_dir.mkdir()
    for index in range(205):
        (imports_dir / f"pd-cloud-{index:03}.json").write_text(
            json.dumps({"assets": [{"host": f"host-{index}.example"}]}),
            encoding="utf-8",
        )

    payload = build_target_feed(
        sources=["connectors"],
        data_dir=tmp_path / "data",
        reports_dir=tmp_path / "reports",
        imports_dir=imports_dir,
        limit=None,
        existing_feed_path=None,
        apply=False,
        supabase_config_path=imports_dir / "supabase-projects.local.json",
    )

    assert payload["source_scan_limits"]["connectors"] == {
        "scanned_count": 200,
        "matched_count": 200,
        "omitted_count": 5,
        "limit": 200,
    }
    assert payload["discovered_input_scan_limits"] == {
        "scanned_count": 200,
        "matched_count": 200,
        "omitted_count": 5,
        "limit": 200,
    }
    discovered_pd = [
        item
        for item in payload["discovered_inputs"]
        if item["connector_id"] == "projectdiscovery_cloud"
    ]
    assert len(discovered_pd) == 200


def test_feed_build_apply_writes_source_specific_input_registries(
    tmp_path: Path,
) -> None:
    imports_dir = tmp_path / "imports"
    imports_dir.mkdir()
    (imports_dir / "pd-cloud-export.json").write_text("{}", encoding="utf-8")
    (imports_dir / "censys-hosts.json").write_text("{}", encoding="utf-8")
    (imports_dir / "runzero-assets.csv").write_text("id,name\n1,host\n", encoding="utf-8")
    (imports_dir / "asset-delta.json").write_text("{}", encoding="utf-8")
    (imports_dir / "burp-results.xml").write_text("<issues />", encoding="utf-8")

    payload = build_target_feed(
        sources=["connectors"],
        data_dir=tmp_path / "data",
        reports_dir=tmp_path / "reports",
        imports_dir=imports_dir,
        limit=None,
        existing_feed_path=None,
        apply=True,
        supabase_config_path=imports_dir / "supabase-projects.local.json",
    )

    update_paths = {
        Path(str(item["config_path"])).name
        for item in payload["source_input_registry_updates"]
    }
    assert update_paths == {
        "asset-delta-imports.local.json",
        "burp-dast-imports.local.json",
        "censys-imports.local.json",
        "projectdiscovery-cloud-imports.local.json",
        "runzero-imports.local.json",
    }
    expected = {
        "asset-delta-imports.local.json": "asset_delta_import",
        "burp-dast-imports.local.json": "burp_dast_xml",
        "censys-imports.local.json": "censys_lookup",
        "projectdiscovery-cloud-imports.local.json": "projectdiscovery_cloud",
        "runzero-imports.local.json": "runzero_asset_export",
    }
    for filename, connector_id in expected.items():
        payload_on_disk = json.loads((imports_dir / filename).read_text(encoding="utf-8"))
        assert payload_on_disk["connector_id"] == connector_id
        assert payload_on_disk["inputs"]


def test_feed_build_db_source_skips_master_sequence_db(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    _make_engagement_db(data_dir, 42, [("numeric.example", "domain")])
    master = data_dir / "engagements" / "master.db"
    conn = sqlite3.connect(master)
    try:
        conn.execute("CREATE TABLE engagement_id_sequence (id INTEGER PRIMARY KEY)")
        conn.commit()
    finally:
        conn.close()

    payload = build_target_feed(
        sources=["db"],
        data_dir=data_dir,
        reports_dir=tmp_path / "reports",
        imports_dir=tmp_path / "imports",
        limit=None,
        existing_feed_path=None,
    )

    assert payload["source_errors"] == []
    assert payload["counts"]["by_source"]["db"] == 1
    assert payload["items"][0]["canonical_value"] == "numeric.example"


def test_feed_build_supabase_selects_configured_columns_with_env_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    observed: dict[str, object] = {}

    class _Response:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> list[dict[str, str]]:
            return [
                {
                    "domain": "Portal.Example",
                    "url": "https://app.example/path?secret=drop",
                    "ignored": "skip.example",
                },
                {"email": "Ops@Example.com"},
            ]

    def _fake_get(url: str, *, headers: dict[str, str], timeout: float) -> _Response:
        observed["url"] = url
        observed["headers"] = headers
        observed["timeout"] = timeout
        return _Response()

    config = tmp_path / "imports" / "supabase-projects.local.json"
    config.parent.mkdir(parents=True)
    config.write_text(
        json.dumps(
            {
                "projects": [
                    {
                        "project_ref": "abc123",
                        "url": "https://abc123.supabase.co",
                        "key_env": "FORGE_SUPABASE_ABC123_READ_KEY",
                        "tables": ["targets"],
                        "target_columns": ["domain", "url", "email"],
                        "limit": 2,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("FORGE_SUPABASE_ABC123_READ_KEY", "test-read-key")
    monkeypatch.setattr("forge.automation_target_feed.httpx.get", _fake_get)

    payload = build_target_feed(
        sources=["supabase"],
        data_dir=tmp_path / "data",
        reports_dir=tmp_path / "reports",
        imports_dir=tmp_path / "imports",
        limit=None,
        existing_feed_path=None,
        supabase_config_path=config,
    )

    assert observed["url"] == (
        "https://abc123.supabase.co/rest/v1/targets"
        "?select=domain,url,email&limit=2&offset=0"
    )
    assert observed["headers"] == {
        "apikey": "test-read-key",
        "Authorization": "Bearer test-read-key",
        "Accept": "application/json",
    }
    typed_items = {
        (item["target_type"], item["canonical_value"]) for item in payload["items"]
    }
    assert ("domain", "portal.example") in typed_items
    assert ("url", "https://app.example/path") in typed_items
    assert ("email", "ops@example.com") in typed_items
    assert all("skip.example" not in item["canonical_value"] for item in payload["items"])
    assert payload["counts"]["by_source"]["supabase"] == 3
    assert payload["counts"]["by_source_group"]["supabase:abc123:targets"] == 2
    assert all(
        item["source_group"] == "supabase:abc123:targets"
        for item in payload["items"]
    )


def test_feed_build_supabase_secret_ref_uses_selected_data_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data_dir = tmp_path / "selected-data"
    monkeypatch.setenv("FORGE_ENGAGEMENT_KEY", "0123456789abcdef0123456789abcdef")
    con = get_engagement_db(data_dir / "engagements" / "1001.db")
    try:
        con.execute(
            """
            INSERT INTO engagements (id, name, scope_json, status, operator)
            VALUES (1001, 'Supabase Feed Secret', '["abc123.supabase.co"]', 'ACTIVE', 'unit')
            """
        )
        store_connector_secret(
            con,
            engagement_id=1001,
            connector_id="supabase_table_import",
            secret_name="READ_KEY",
            secret_value="selected-data-read-key",
            secret_ref="env:FORGE_SUPABASE_PROJECT_READ_KEY",
            operator="unit-test",
        )
        con.commit()
    finally:
        con.close()

    observed: dict[str, object] = {}

    class _Response:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> list[dict[str, str]]:
            return [{"domain": "SecretRef.Example"}]

    def _fake_get(url: str, *, headers: dict[str, str], timeout: float) -> _Response:
        observed["url"] = url
        observed["headers"] = headers
        observed["timeout"] = timeout
        return _Response()

    config = tmp_path / "imports" / "supabase-projects.local.json"
    config.parent.mkdir(parents=True)
    config.write_text(
        json.dumps(
            {
                "projects": [
                    {
                        "project_ref": "abc123",
                        "url": "https://abc123.supabase.co",
                        "key_secret_ref": (
                            "forge-secret://1001/supabase_table_import/READ_KEY"
                        ),
                        "tables": ["targets"],
                        "target_columns": ["domain"],
                        "limit": 2,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr("forge.automation_target_feed.httpx.get", _fake_get)

    payload = build_target_feed(
        sources=["supabase"],
        data_dir=data_dir,
        reports_dir=tmp_path / "reports",
        imports_dir=tmp_path / "imports",
        limit=None,
        existing_feed_path=None,
        supabase_config_path=config,
    )

    assert observed["headers"] == {
        "apikey": "selected-data-read-key",
        "Authorization": "Bearer selected-data-read-key",
        "Accept": "application/json",
    }
    assert observed["url"] == (
        "https://abc123.supabase.co/rest/v1/targets?select=domain&limit=2&offset=0"
    )
    assert payload["source_errors"] == []
    assert payload["items"][0]["canonical_value"] == "secretref.example"


def test_feed_build_supabase_derives_url_and_discovers_all_tables_and_columns(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    observed_urls: list[str] = []

    class _Response:
        def __init__(self, payload: object) -> None:
            self._payload = payload

        def raise_for_status(self) -> None:
            return None

        def json(self) -> object:
            return self._payload

    def _fake_get(url: str, *, headers: dict[str, str], timeout: float) -> _Response:
        assert headers["apikey"] == "test-read-key"
        assert timeout == 15.0
        observed_urls.append(url)
        if url == "https://abc123.supabase.co/rest/v1/":
            return _Response(
                {
                    "paths": {
                        "/assets": {},
                        "/observations": {},
                        "/rpc/private_fn": {},
                    }
                }
            )
        if url == "https://abc123.supabase.co/rest/v1/assets?select=*&limit=1000&offset=0":
            return _Response(
                [
                    {
                        "id": 1,
                        "name": "Portal",
                        "username": "Alice",
                        "nested": {
                            "urls": ["https://app.example/path?token=drop"],
                            "owner": "ops@example.com",
                        },
                    }
                ]
            )
        if url == (
            "https://abc123.supabase.co/rest/v1/observations"
            "?select=*&limit=1000&offset=0"
        ):
            return _Response([{"notes": "api.example"}])
        raise AssertionError(f"unexpected URL {url}")

    config = tmp_path / "supabase-projects.local.json"
    config.write_text(
        json.dumps(
            {
                "projects": [
                    {
                        "project_ref": "abc123",
                        "key_env": "FORGE_SUPABASE_ABC123_READ_KEY",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("FORGE_SUPABASE_ABC123_READ_KEY", "test-read-key")
    monkeypatch.setattr("forge.automation_target_feed.httpx.get", _fake_get)

    payload = build_target_feed(
        sources=["supabase"],
        data_dir=tmp_path / "data",
        reports_dir=tmp_path / "reports",
        imports_dir=tmp_path / "imports",
        limit=None,
        existing_feed_path=None,
        supabase_config_path=config,
    )

    assert observed_urls == [
        "https://abc123.supabase.co/rest/v1/",
        "https://abc123.supabase.co/rest/v1/assets?select=*&limit=1000&offset=0",
        "https://abc123.supabase.co/rest/v1/observations?select=*&limit=1000&offset=0",
    ]
    typed_items = {
        (item["target_type"], item["canonical_value"], item["source_group"])
        for item in payload["items"]
    }
    assert ("url", "https://app.example/path", "supabase:abc123:assets") in typed_items
    assert ("email", "ops@example.com", "supabase:abc123:assets") in typed_items
    assert ("username", "@alice", "supabase:abc123:assets") in typed_items
    assert ("domain", "api.example", "supabase:abc123:observations") in typed_items
    assert payload["counts"]["by_source"]["supabase"] == 4
    assert payload["counts"]["by_source_group"]["supabase:abc123:assets"] == 1
    assert payload["counts"]["by_source_group"]["supabase:abc123:observations"] == 1
    assert payload["supabase_table_discovery"] == [
        {
            "project_ref": "abc123",
            "url": "https://abc123.supabase.co",
            "status": "discovered",
            "requested_all_tables": True,
            "requested_all_columns": True,
            "configured_tables": ["*"],
            "configured_tables_count": 1,
            "discovered_tables_count": 2,
            "scanned_tables": ["assets", "observations"],
            "scanned_tables_count": 2,
            "scanned_table_rows": {"assets": 1, "observations": 1},
            "scanned_table_pages": {"assets": 1, "observations": 1},
            "row_limit_per_table": 100000,
            "max_tables_per_project": 1000,
            "max_rows_per_project": 100000,
            "max_candidates_per_project": 100000,
            "omitted_table_count": 0,
            "omitted_reason": "",
            "errors": [],
        }
    ]


def test_feed_build_supabase_all_tables_reports_blocked_discovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    observed_urls: list[str] = []

    class _Response:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> object:
            return {"swagger": "2.0"}

    def _fake_get(url: str, *, headers: dict[str, str], timeout: float) -> _Response:
        assert headers["apikey"] == "test-read-key"
        assert timeout == 15.0
        observed_urls.append(url)
        return _Response()

    config = tmp_path / "supabase-projects.local.json"
    config.write_text(
        json.dumps(
            {
                "projects": [
                    {
                        "project_ref": "abc123",
                        "key_env": "FORGE_SUPABASE_ABC123_READ_KEY",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("FORGE_SUPABASE_ABC123_READ_KEY", "test-read-key")
    monkeypatch.setattr("forge.automation_target_feed.httpx.get", _fake_get)

    payload = build_target_feed(
        sources=["supabase"],
        data_dir=tmp_path / "data",
        reports_dir=tmp_path / "reports",
        imports_dir=tmp_path / "imports",
        limit=None,
        existing_feed_path=None,
        supabase_config_path=config,
    )

    assert observed_urls == ["https://abc123.supabase.co/rest/v1/"]
    assert payload["items"] == []
    assert payload["source_errors"] == [
        {"source": "supabase", "error": "abc123:discover_tables:paths_missing"}
    ]
    assert payload["supabase_table_discovery"] == [
        {
            "project_ref": "abc123",
            "url": "https://abc123.supabase.co",
            "status": "blocked_table_discovery",
            "requested_all_tables": True,
            "requested_all_columns": True,
            "configured_tables": ["*"],
            "configured_tables_count": 1,
            "discovered_tables_count": 0,
            "scanned_tables": [],
            "scanned_tables_count": 0,
            "scanned_table_rows": {},
            "scanned_table_pages": {},
            "row_limit_per_table": 100000,
            "max_tables_per_project": 1000,
            "max_rows_per_project": 100000,
            "max_candidates_per_project": 100000,
            "omitted_table_count": 0,
            "omitted_reason": "",
            "errors": ["abc123:discover_tables:paths_missing"],
            "next_action": (
                "Ensure the supplied key can read the project REST OpenAPI root "
                "or add explicit table names in imports/supabase-projects.local.json."
            ),
        }
    ]


def test_feed_build_supabase_missing_config_fails_soft(tmp_path: Path) -> None:
    payload = build_target_feed(
        sources=["supabase"],
        data_dir=tmp_path / "data",
        reports_dir=tmp_path / "reports",
        imports_dir=tmp_path / "imports",
        limit=None,
        existing_feed_path=None,
        supabase_config_path=tmp_path / "missing.json",
    )

    assert payload["counts"]["by_source"]["supabase"] == 0
    assert payload["source_errors"] == [
        {
            "source": "supabase",
            "error": "not_configured:local_config_file_missing",
        }
    ]


def test_feed_build_supabase_unset_key_env_does_not_call_http(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "supabase-projects.local.json"
    config.write_text(
        json.dumps(
            {
                "projects": [
                    {
                        "project_ref": "abc123",
                        "url": "https://abc123.supabase.co",
                        "key_env": "FORGE_SUPABASE_ABC123_READ_KEY",
                        "tables": ["targets"],
                        "target_columns": ["domain"],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    def _fail_get(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("unset Supabase key must not make HTTP requests")

    monkeypatch.delenv("FORGE_SUPABASE_ABC123_READ_KEY", raising=False)
    monkeypatch.setattr("forge.automation_target_feed.httpx.get", _fail_get)

    payload = build_target_feed(
        sources=["supabase"],
        data_dir=tmp_path / "data",
        reports_dir=tmp_path / "reports",
        imports_dir=tmp_path / "imports",
        limit=None,
        existing_feed_path=None,
        supabase_config_path=config,
    )

    assert payload["items"] == []
    assert payload["source_errors"] == [
        {
            "source": "supabase",
            "error": "abc123:key_env_unset:FORGE_SUPABASE_ABC123_READ_KEY",
        }
    ]
    assert payload["supabase_table_discovery"] == [
        {
            "project_ref": "abc123",
            "url": "https://abc123.supabase.co",
            "status": "blocked_key",
            "requested_all_tables": False,
            "requested_all_columns": False,
            "configured_tables": ["targets"],
            "configured_tables_count": 1,
            "discovered_tables_count": 0,
            "scanned_tables": [],
            "scanned_tables_count": 0,
            "scanned_table_rows": {},
            "scanned_table_pages": {},
            "row_limit_per_table": 100000,
            "max_tables_per_project": 1000,
            "max_rows_per_project": 100000,
            "max_candidates_per_project": 100000,
            "omitted_table_count": 0,
            "omitted_reason": "",
            "errors": ["key_env_unset:FORGE_SUPABASE_ABC123_READ_KEY"],
        }
    ]


def test_feed_build_supabase_paginates_and_caps_table_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    observed_urls: list[str] = []

    class _Response:
        def __init__(self, rows: list[dict[str, str]]) -> None:
            self._rows = rows

        def raise_for_status(self) -> None:
            return None

        def json(self) -> list[dict[str, str]]:
            return self._rows

    def _fake_get(url: str, *, headers: dict[str, str], timeout: float) -> _Response:
        observed_urls.append(url)
        if url.endswith("&offset=0"):
            return _Response([{"domain": f"page1-{index}.example"} for index in range(1000)])
        if url.endswith("&offset=1000"):
            return _Response([{"domain": "page2.example"}])
        raise AssertionError(f"unexpected URL {url}")

    config = tmp_path / "supabase-projects.local.json"
    config.write_text(
        json.dumps(
            {
                "projects": [
                    {
                        "project_ref": "abc123",
                        "url": "https://abc123.supabase.co",
                        "key_env": "FORGE_SUPABASE_ABC123_READ_KEY",
                        "tables": ["targets"],
                        "target_columns": ["domain"],
                        "limit": 50000,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("FORGE_SUPABASE_ABC123_READ_KEY", "test-read-key")
    monkeypatch.setattr("forge.automation_target_feed.httpx.get", _fake_get)

    payload = build_target_feed(
        sources=["supabase"],
        data_dir=tmp_path / "data",
        reports_dir=tmp_path / "reports",
        imports_dir=tmp_path / "imports",
        limit=None,
        existing_feed_path=None,
        supabase_config_path=config,
    )

    assert observed_urls == [
        "https://abc123.supabase.co/rest/v1/targets?select=domain&limit=1000&offset=0",
        "https://abc123.supabase.co/rest/v1/targets?select=domain&limit=1000&offset=1000",
    ]
    assert payload["counts"]["by_source"]["supabase"] == 1001
    assert payload["counts"]["by_source_group"]["supabase:abc123:targets"] == 1001
    assert payload["supabase_table_discovery"][0]["scanned_table_rows"] == {
        "targets": 1001
    }
    assert payload["supabase_table_discovery"][0]["scanned_table_pages"] == {
        "targets": 2
    }


def test_feed_build_supabase_harvests_no_more_than_configured_row_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    observed_urls: list[str] = []

    class _Response:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> list[dict[str, str]]:
            return [{"domain": f"over-{index}.example"} for index in range(5)]

    def _fake_get(url: str, *, headers: dict[str, str], timeout: float) -> _Response:
        observed_urls.append(url)
        return _Response()

    config = tmp_path / "supabase-projects.local.json"
    config.write_text(
        json.dumps(
            {
                "projects": [
                    {
                        "project_ref": "abc123",
                        "url": "https://abc123.supabase.co",
                        "key_env": "FORGE_SUPABASE_ABC123_READ_KEY",
                        "tables": ["targets"],
                        "target_columns": ["domain"],
                        "limit": 3,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("FORGE_SUPABASE_ABC123_READ_KEY", "test-read-key")
    monkeypatch.setattr("forge.automation_target_feed.httpx.get", _fake_get)

    payload = build_target_feed(
        sources=["supabase"],
        data_dir=tmp_path / "data",
        reports_dir=tmp_path / "reports",
        imports_dir=tmp_path / "imports",
        limit=None,
        existing_feed_path=None,
        supabase_config_path=config,
    )

    assert observed_urls == [
        "https://abc123.supabase.co/rest/v1/targets?select=domain&limit=3&offset=0"
    ]
    assert payload["counts"]["by_source"]["supabase"] == 3
    assert payload["counts"]["by_source_group"]["supabase:abc123:targets"] == 3
    assert {item["canonical_value"] for item in payload["items"]} == {
        "over-0.example",
        "over-1.example",
        "over-2.example",
    }
    assert payload["source_errors"] == [
        {"source": "supabase", "error": "abc123:targets:row_limit_reached:3"}
    ]
    assert payload["supabase_table_discovery"][0]["scanned_table_rows"] == {
        "targets": 3
    }
    assert payload["supabase_table_discovery"][0]["scanned_table_pages"] == {
        "targets": 1
    }


def test_feed_build_supabase_project_budgets_stop_extra_tables(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    observed_urls: list[str] = []

    class _Response:
        def __init__(self, payload: object) -> None:
            self._payload = payload

        def raise_for_status(self) -> None:
            return None

        def json(self) -> object:
            return self._payload

    def _fake_get(url: str, *, headers: dict[str, str], timeout: float) -> _Response:
        observed_urls.append(url)
        if url == "https://abc123.supabase.co/rest/v1/":
            return _Response({"paths": {"/assets": {}, "/observations": {}, "/users": {}}})
        if url == "https://abc123.supabase.co/rest/v1/assets?select=*&limit=1&offset=0":
            return _Response([{"domain": "one.example"}])
        raise AssertionError(f"unexpected URL {url}")

    config = tmp_path / "supabase-projects.local.json"
    config.write_text(
        json.dumps(
            {
                "projects": [
                    {
                        "project_ref": "abc123",
                        "key_env": "FORGE_SUPABASE_ABC123_READ_KEY",
                        "max_tables": 2,
                        "max_rows": 1,
                        "max_candidates": 10,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("FORGE_SUPABASE_ABC123_READ_KEY", "test-read-key")
    monkeypatch.setattr("forge.automation_target_feed.httpx.get", _fake_get)

    payload = build_target_feed(
        sources=["supabase"],
        data_dir=tmp_path / "data",
        reports_dir=tmp_path / "reports",
        imports_dir=tmp_path / "imports",
        limit=None,
        existing_feed_path=None,
        supabase_config_path=config,
    )

    assert observed_urls == [
        "https://abc123.supabase.co/rest/v1/",
        "https://abc123.supabase.co/rest/v1/assets?select=*&limit=1&offset=0",
    ]
    assert payload["counts"]["by_source"]["supabase"] == 1
    assert payload["source_errors"] == [
        {"source": "supabase", "error": "abc123:project_table_limit_reached:2:1"},
        {"source": "supabase", "error": "abc123:assets:row_limit_reached:1"},
        {"source": "supabase", "error": "abc123:project_row_limit_reached:1:1"},
    ]
    discovery = payload["supabase_table_discovery"][0]
    assert discovery["max_tables_per_project"] == 2
    assert discovery["max_rows_per_project"] == 1
    assert discovery["max_candidates_per_project"] == 10
    assert discovery["scanned_tables"] == ["assets"]
    assert discovery["scanned_table_rows"] == {"assets": 1}
    assert discovery["omitted_table_count"] == 2
    assert discovery["omitted_reason"] == "project_row_limit_reached"


def test_feed_build_supabase_uses_greedy_default_limit_for_minimal_project(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    observed_urls: list[str] = []

    class _Response:
        def __init__(self, payload: object) -> None:
            self._payload = payload

        def raise_for_status(self) -> None:
            return None

        def json(self) -> object:
            return self._payload

    def _fake_get(url: str, *, headers: dict[str, str], timeout: float) -> _Response:
        observed_urls.append(url)
        if url == "https://abc123.supabase.co/rest/v1/":
            return _Response({"paths": {"/targets": {}}})
        if url == "https://abc123.supabase.co/rest/v1/targets?select=*&limit=1000&offset=0":
            return _Response([{"domain": "one.example"}])
        raise AssertionError(f"unexpected URL {url}")

    config = tmp_path / "supabase-projects.local.json"
    config.write_text(
        json.dumps(
            {
                "projects": [
                    {
                        "project_ref": "abc123",
                        "key_env": "FORGE_SUPABASE_ABC123_READ_KEY",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("FORGE_SUPABASE_ABC123_READ_KEY", "test-read-key")
    monkeypatch.setattr("forge.automation_target_feed.httpx.get", _fake_get)

    payload = build_target_feed(
        sources=["supabase"],
        data_dir=tmp_path / "data",
        reports_dir=tmp_path / "reports",
        imports_dir=tmp_path / "imports",
        limit=None,
        existing_feed_path=None,
        supabase_config_path=config,
    )

    assert observed_urls == [
        "https://abc123.supabase.co/rest/v1/",
        "https://abc123.supabase.co/rest/v1/targets?select=*&limit=1000&offset=0",
    ]
    assert payload["counts"]["by_source"]["supabase"] == 1
