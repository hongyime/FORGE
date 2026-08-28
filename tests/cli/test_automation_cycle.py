from __future__ import annotations

import json
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
