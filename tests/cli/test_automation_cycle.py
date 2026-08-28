from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import typer
from typer.testing import CliRunner

from forge.automation_cli import register_automation_commands
from forge.automation_cycle import automation_cycle, automation_status, doctor_fix_safe


def test_automation_status_reports_ready_and_blocked_queue_items(tmp_path: Path) -> None:
    imports_dir = tmp_path / "imports"
    imports_dir.mkdir()
    (imports_dir / "pd-cloud-export.json").write_text("{}", encoding="utf-8")
    (imports_dir / "projectdiscovery-cloud-imports.local.json").write_text(
        json.dumps(
            {
                "inputs": [
                    {"value": "pd-cloud-export.json", "status": "pending"},
                    {"value": "missing.json", "status": "pending"},
                ]
            }
        ),
        encoding="utf-8",
    )

    payload = automation_status(
        imports_dir=imports_dir,
        output=imports_dir / "target-feed.json",
        data_dir=tmp_path / "data",
        engagement=1001,
    )

    assert payload["schema_version"] == "forge.automation_status.v1"
    assert payload["execution_policy"] == "read_only_status_no_commands_executed"
    assert payload["queues"]["total"] == 2
    assert payload["queues"]["ready"] == 1
    assert payload["queues"]["blocked"] == 1
    assert payload["scan_policy"]["multi_source_target_threshold"] == 2
    assert payload["ready_inputs"][0]["command"][:6] == [
        "forge",
        "connectors",
        "import-discovery",
        "--engagement",
        "1001",
        "--connector",
    ]
    assert payload["blocked_inputs"][0]["reason"].startswith("local_artifact_missing")


def test_automation_status_ignores_empty_scaffolds_and_control_references(
    tmp_path: Path,
) -> None:
    imports_dir = tmp_path / "imports"
    imports_dir.mkdir()
    (imports_dir / "threatfox-observations.local.json").write_text(
        json.dumps({"schema_version": "forge.cti_observations.local.v1", "data": []}),
        encoding="utf-8",
    )
    (imports_dir / "real-threatfox.json").write_text(
        json.dumps({"data": [{"ioc": "bad.example"}]}),
        encoding="utf-8",
    )
    (imports_dir / "threatfox-inputs.local.json").write_text(
        json.dumps(
            {
                "inputs": [
                    {"value": "threatfox-observations.local.json", "status": "pending"},
                    {"value": "threatfox-inputs.local.json", "status": "pending"},
                    {"value": "real-threatfox.json", "status": "pending"},
                ]
            }
        ),
        encoding="utf-8",
    )

    payload = automation_status(
        imports_dir=imports_dir,
        output=imports_dir / "target-feed.json",
        data_dir=tmp_path / "data",
        engagement=None,
    )

    assert payload["queues"]["total"] == 3
    assert payload["queues"]["ignored"] == 2
    assert payload["queues"]["blocked"] == 1
    assert {item["reason"] for item in payload["ignored_inputs"]} == {
        "empty_local_scaffold",
        "local_control_file_reference",
    }
    assert payload["blocked_inputs"][0]["value"] == "real-threatfox.json"
    assert payload["blocked_inputs"][0]["reason"] == "engagement_required"


def test_automation_status_summarizes_existing_target_feed_scanability(
    tmp_path: Path,
) -> None:
    imports_dir = tmp_path / "imports"
    imports_dir.mkdir()
    feed_path = imports_dir / "target-feed.json"
    feed_path.write_text(
        json.dumps(
            {
                "schema_version": "target-feed.v1",
                "items": [
                    {
                        "target_type": "domain",
                        "target_value": "shared.example",
                        "source_groups": ["db", "report_family:shared"],
                        "source_count": 2,
                        "priority": 90,
                        "scan_eligible": True,
                        "scan_eligibility_reason": "eligible",
                    },
                    {
                        "target_type": "ip",
                        "target_value": "0.0.0.0",
                        "source_groups": ["db", "report_family:noise"],
                        "source_count": 2,
                        "priority": 10,
                        "scan_eligible": False,
                        "scan_eligibility_reason": "non_global_ip",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )

    payload = automation_status(
        imports_dir=imports_dir,
        output=feed_path,
        data_dir=tmp_path / "data",
        engagement=None,
    )

    scan = payload["target_feed_scan"]
    assert scan["exists"] is True
    assert scan["total_count"] == 2
    assert scan["eligible_count"] == 1
    assert scan["ineligible_count"] == 1
    assert scan["high_priority_count"] == 1
    assert scan["ineligible_reasons"] == {"non_global_ip": 1}
    assert scan["top_targets"][0]["target_value"] == "shared.example"


def test_automation_cycle_dry_run_plans_feed_and_queue_without_writes(
    tmp_path: Path,
) -> None:
    imports_dir = tmp_path / "imports"
    reports_dir = tmp_path / "reports"
    imports_dir.mkdir()
    (imports_dir / "burp-results.xml").write_text("<issues />", encoding="utf-8")
    (imports_dir / "burp-dast-imports.local.json").write_text(
        json.dumps({"inputs": [{"value": "burp-results.xml", "status": "pending"}]}),
        encoding="utf-8",
    )

    payload = automation_cycle(
        apply=False,
        engagement=1001,
        output=imports_dir / "target-feed.json",
        source=["connectors"],
        data_dir=tmp_path / "data",
        reports_dir=reports_dir,
        imports_dir=imports_dir,
    )

    assert payload["execution_policy"] == "dry_run_no_writes_or_live_commands_executed"
    assert payload["feed_written"] is False
    assert payload["target_feed_scan"]["exists"] is True
    assert payload["target_feed_scan"]["eligible_count"] == 0
    assert (
        payload["scan_policy"]["new_targets"]
        == "scan_immediately_when_cycle_runs_with_apply_live_and_roe_gates_pass"
    )
    assert not (imports_dir / "target-feed.json").exists()
    assert payload["queue_runs"][0]["status"] == "planned"
    queue = json.loads(
        (imports_dir / "burp-dast-imports.local.json").read_text(encoding="utf-8")
    )
    assert queue["inputs"][0]["status"] == "pending"


def test_automation_cycle_classifies_inbox_into_source_queues(tmp_path: Path) -> None:
    imports_dir = tmp_path / "imports"
    inbox = imports_dir / "inbox"
    inbox.mkdir(parents=True)
    (inbox / "runzero-assets.csv").write_text("id,name\n1,host\n", encoding="utf-8")

    dry_run = automation_cycle(
        apply=False,
        engagement=1001,
        output=imports_dir / "target-feed.json",
        source=["connectors"],
        data_dir=tmp_path / "data",
        reports_dir=tmp_path / "reports",
        imports_dir=imports_dir,
    )

    assert dry_run["inbox"]["discovered_count"] == 1
    assert dry_run["inbox"]["queue_update_plan"] == [
        {
            "config_path": str(imports_dir / "runzero-imports.local.json"),
            "applied": False,
            "pending_count": 1,
            "appended_count": 0,
        }
    ]
    assert not (imports_dir / "runzero-imports.local.json").exists()

    applied = automation_cycle(
        apply=True,
        engagement=1001,
        output=imports_dir / "target-feed.json",
        source=["connectors"],
        data_dir=tmp_path / "data",
        reports_dir=tmp_path / "reports",
        imports_dir=imports_dir,
        command_runner=lambda _command, _cwd: {"returncode": 0, "stdout": "{}", "stderr": ""},
    )

    assert applied["inbox"]["queue_updates"] == [
        {
            "config_path": str(imports_dir / "runzero-imports.local.json"),
            "applied": True,
            "pending_count": 0,
            "appended_count": 1,
        }
    ]
    queue = json.loads(
        (imports_dir / "runzero-imports.local.json").read_text(encoding="utf-8")
    )
    assert queue["inputs"][0]["connector_id"] == "runzero_asset_export"
    assert queue["inputs"][0]["value"] == str(Path("inbox") / "runzero-assets.csv")


def test_automation_cycle_apply_runs_ready_queue_and_marks_imported(
    tmp_path: Path,
) -> None:
    imports_dir = tmp_path / "imports"
    reports_dir = tmp_path / "reports"
    imports_dir.mkdir()
    (imports_dir / "threatfox.json").write_text(
        json.dumps({"iocs": ["example.com"]}),
        encoding="utf-8",
    )
    queue_path = imports_dir / "threatfox-inputs.local.json"
    queue_path.write_text(
        json.dumps({"inputs": [{"value": "threatfox.json", "status": "pending"}]}),
        encoding="utf-8",
    )
    commands: list[list[str]] = []

    def _runner(command: list[str], _cwd: Path) -> dict[str, object]:
        commands.append(command)
        return {"returncode": 0, "stdout": "{\"status\":\"completed\"}", "stderr": ""}

    payload = automation_cycle(
        apply=True,
        engagement=1001,
        output=imports_dir / "target-feed.json",
        source=["cti"],
        data_dir=tmp_path / "data",
        reports_dir=reports_dir,
        imports_dir=imports_dir,
        command_runner=_runner,
    )

    assert payload["execution_policy"] == "apply_local_feed_and_queue_imports"
    assert payload["feed_written"] is True
    assert commands == [
        [
            "forge",
            "connectors",
            "import-cti",
            "--engagement",
            "1001",
            "--connector",
            "abusech_threatfox",
            "--report-file",
            str(imports_dir / "threatfox.json"),
            "--promote-targets",
            "--json",
        ]
    ]
    queue = json.loads(queue_path.read_text(encoding="utf-8"))
    assert queue["inputs"][0]["status"] == "imported"
    assert queue["inputs"][0]["last_processed_at"]


def test_automation_cycle_failed_queue_item_gets_retry_backoff(
    tmp_path: Path,
) -> None:
    imports_dir = tmp_path / "imports"
    reports_dir = tmp_path / "reports"
    imports_dir.mkdir()
    (imports_dir / "threatfox.json").write_text(
        json.dumps({"iocs": ["example.com"]}),
        encoding="utf-8",
    )
    queue_path = imports_dir / "threatfox-inputs.local.json"
    queue_path.write_text(
        json.dumps({"inputs": [{"value": "threatfox.json", "status": "pending"}]}),
        encoding="utf-8",
    )

    def _runner(command: list[str], _cwd: Path) -> dict[str, object]:
        return {"returncode": 9, "stdout": "", "stderr": "temporary parse failure"}

    payload = automation_cycle(
        apply=True,
        engagement=1001,
        output=imports_dir / "target-feed.json",
        source=["cti"],
        data_dir=tmp_path / "data",
        reports_dir=reports_dir,
        imports_dir=imports_dir,
        command_runner=_runner,
    )

    assert payload["queue_runs"][0]["status"] == "failed"
    queue = json.loads(queue_path.read_text(encoding="utf-8"))
    item = queue["inputs"][0]
    assert item["status"] == "failed"
    assert item["failure_count"] == 1
    assert item["last_returncode"] == 9
    assert item["retry_after_at"]
    assert item["last_error"] == "temporary parse failure"

    blocked = automation_status(imports_dir=imports_dir, engagement=1001)["blocked_inputs"]
    assert blocked[0]["reason"].startswith("retry_backoff_active:")


def test_automation_status_blocks_queue_item_after_retry_limit(
    tmp_path: Path,
) -> None:
    imports_dir = tmp_path / "imports"
    imports_dir.mkdir()
    (imports_dir / "threatfox.json").write_text("{}", encoding="utf-8")
    retry_after = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(
        timespec="seconds"
    )
    (imports_dir / "threatfox-inputs.local.json").write_text(
        json.dumps(
            {
                "inputs": [
                    {
                        "value": "threatfox.json",
                        "status": "failed",
                        "failure_count": 5,
                        "retry_after_at": retry_after,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    payload = automation_status(imports_dir=imports_dir, engagement=1001)

    assert payload["queues"]["ready"] == 0
    assert payload["blocked_inputs"][0]["reason"] == "retry_limit_reached:5"


def test_automation_cycle_live_reuses_built_feed_without_guarded_rebuild(
    tmp_path: Path,
    monkeypatch,
) -> None:
    imports_dir = tmp_path / "imports"
    reports_dir = tmp_path / "reports"
    imports_dir.mkdir()
    seen: dict[str, object] = {}

    def fake_guarded_autostart(**kwargs):
        seen.update(kwargs)
        return {
            "schema_version": "forge.automation_guarded_autostart.v1",
            "status": "ready",
            "commands": {
                "autopilot_dry_run": ["forge-autopilot.bat", "--skip-feed-build", "--dry-run"],
                "autopilot_apply": ["forge-autopilot.bat", "--skip-feed-build"],
            },
        }

    monkeypatch.setattr(
        "forge.automation_cycle.run_guarded_autostart",
        fake_guarded_autostart,
    )

    payload = automation_cycle(
        apply=True,
        live=True,
        engagement=1001,
        output=imports_dir / "target-feed.json",
        source=["connectors"],
        data_dir=tmp_path / "data",
        reports_dir=reports_dir,
        imports_dir=imports_dir,
        docker_probe_mode="compose-dependency",
        command_runner=lambda _command, _cwd: {"returncode": 0, "stdout": "{}", "stderr": ""},
    )

    assert payload["execution_policy"] == "apply_with_live_guarded_autostart"
    assert payload["feed_written"] is True
    assert seen["skip_feed_build"] is True
    assert seen["docker_probe_mode"] == "compose-dependency"
    assert payload["autostart"]["commands"]["autopilot_dry_run"][1] == "--skip-feed-build"


def test_automation_cycle_live_consumes_ready_queue_before_guarded_autostart(
    tmp_path: Path,
    monkeypatch,
) -> None:
    imports_dir = tmp_path / "imports"
    reports_dir = tmp_path / "reports"
    imports_dir.mkdir()
    (imports_dir / "threatfox.json").write_text(
        json.dumps({"iocs": ["example.com"]}),
        encoding="utf-8",
    )
    queue_path = imports_dir / "threatfox-inputs.local.json"
    queue_path.write_text(
        json.dumps({"inputs": [{"value": "threatfox.json", "status": "pending"}]}),
        encoding="utf-8",
    )
    events: list[str] = []

    def _runner(_command: list[str], _cwd: Path) -> dict[str, object]:
        events.append("queue")
        return {"returncode": 0, "stdout": "{\"status\":\"completed\"}", "stderr": ""}

    def fake_guarded_autostart(**_kwargs):
        events.append("guarded")
        return {
            "schema_version": "forge.automation_guarded_autostart.v1",
            "status": "ready",
            "commands": {
                "autopilot_dry_run": ["forge-autopilot.bat", "--skip-feed-build", "--dry-run"],
                "autopilot_apply": ["forge-autopilot.bat", "--skip-feed-build"],
            },
        }

    monkeypatch.setattr(
        "forge.automation_cycle.run_guarded_autostart",
        fake_guarded_autostart,
    )

    payload = automation_cycle(
        apply=True,
        live=True,
        engagement=1001,
        output=imports_dir / "target-feed.json",
        source=["cti"],
        data_dir=tmp_path / "data",
        reports_dir=reports_dir,
        imports_dir=imports_dir,
        command_runner=_runner,
    )

    assert payload["execution_policy"] == "apply_with_live_guarded_autostart"
    assert [run["status"] for run in payload["queue_runs"]] == ["completed"]
    assert payload["autostart"]["status"] == "ready"
    assert events == ["queue", "guarded"]
    queue = json.loads(queue_path.read_text(encoding="utf-8"))
    assert queue["inputs"][0]["status"] == "imported"


def test_doctor_fix_safe_creates_and_repairs_local_files(tmp_path: Path) -> None:
    imports_dir = tmp_path / "imports"
    imports_dir.mkdir()
    broken = imports_dir / "burp-dast-imports.local.json"
    broken.write_text("{not-json", encoding="utf-8")

    payload = doctor_fix_safe(imports_dir=imports_dir)

    assert payload["schema_version"] == "forge.doctor_safe_fix.v1"
    assert (imports_dir / "inbox").is_dir()
    assert (imports_dir / "supabase-projects.local.json").is_file()
    assert (
        json.loads((imports_dir / "discovered-inputs.local.json").read_text(encoding="utf-8"))[
            "schema_version"
        ]
        == "forge.discovered_inputs.v1"
    )
    assert json.loads(broken.read_text(encoding="utf-8"))["inputs"] == []
    assert broken.with_suffix(".json.bak").is_file()
    assert payload["selected_count"] >= 2


def test_doctor_fix_safe_prunes_ignored_queue_placeholders(tmp_path: Path) -> None:
    imports_dir = tmp_path / "imports"
    imports_dir.mkdir()
    (imports_dir / "threatfox-observations.local.json").write_text(
        json.dumps({"schema_version": "forge.cti_observations.local.v1", "observations": []}),
        encoding="utf-8",
    )
    (imports_dir / "real-threatfox.json").write_text(
        json.dumps({"data": [{"ioc": "bad.example"}]}),
        encoding="utf-8",
    )
    queue_path = imports_dir / "threatfox-inputs.local.json"
    queue_path.write_text(
        json.dumps(
            {
                "inputs": [
                    {"value": "threatfox-observations.local.json", "status": "pending"},
                    {"value": "threatfox-inputs.local.json", "status": "pending"},
                    {"value": "real-threatfox.json", "status": "pending"},
                ]
            }
        ),
        encoding="utf-8",
    )
    registry_path = imports_dir / "discovered-inputs.local.json"
    registry_path.write_text(
        json.dumps(
            {
                "schema_version": "forge.discovered_inputs.v1",
                "inputs": [
                    {"value": "threatfox-observations.local.json", "status": "accepted"},
                    {"value": "threatfox-inputs.local.json", "status": "accepted"},
                    {"value": "real-threatfox.json", "status": "accepted"},
                ],
            }
        ),
        encoding="utf-8",
    )

    payload = doctor_fix_safe(imports_dir=imports_dir)

    assert any(item["id"] == "prune_ignored_queue_items" for item in payload["actions"])
    queue = json.loads(queue_path.read_text(encoding="utf-8"))
    assert [item["value"] for item in queue["inputs"]] == ["real-threatfox.json"]
    registry = json.loads(registry_path.read_text(encoding="utf-8"))
    assert [item["value"] for item in registry["inputs"]] == ["real-threatfox.json"]


def test_automation_cycle_cli_registers_status_and_cycle(tmp_path: Path) -> None:
    app = typer.Typer()
    automation_app = typer.Typer()
    register_automation_commands(automation_app)
    app.add_typer(automation_app, name="automation")
    runner = CliRunner()

    status_result = runner.invoke(
        app,
        [
            "automation",
            "status",
            "--imports-dir",
            str(tmp_path / "imports"),
            "--data-dir",
            str(tmp_path / "data"),
            "--json",
        ],
    )
    assert status_result.exit_code == 0, status_result.output
    assert json.loads(status_result.output)["schema_version"] == "forge.automation_status.v1"

    cycle_result = runner.invoke(
        app,
        [
            "automation",
            "cycle",
            "--imports-dir",
            str(tmp_path / "imports"),
            "--reports-dir",
            str(tmp_path / "reports"),
            "--data-dir",
            str(tmp_path / "data"),
            "--source",
            "connectors",
            "--json",
        ],
    )
    assert cycle_result.exit_code == 0, cycle_result.output
    assert json.loads(cycle_result.output)["schema_version"] == "forge.automation_cycle.v1"
