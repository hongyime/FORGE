from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import typer
from typer.testing import CliRunner

import forge.automation_cycle as automation_cycle_module
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
    assert "forge automation cycle --apply --engagement N --json" in payload[
        "next_actions"
    ]
    assert (
        "forge automation cycle --apply --live --docker-probe-mode "
        "compose-dependency --engagement N --json"
    ) in payload["next_actions"]
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


def test_automation_status_uses_default_engagement_env_for_queue_readiness(
    tmp_path: Path,
    monkeypatch,
) -> None:
    imports_dir = tmp_path / "imports"
    imports_dir.mkdir()
    (imports_dir / "threatfox.json").write_text(
        json.dumps({"iocs": ["example.com"]}),
        encoding="utf-8",
    )
    (imports_dir / "threatfox-inputs.local.json").write_text(
        json.dumps({"inputs": [{"value": "threatfox.json", "status": "pending"}]}),
        encoding="utf-8",
    )
    monkeypatch.setenv("FORGE_DEFAULT_ENGAGEMENT_ID", "1001")

    payload = automation_status(imports_dir=imports_dir)

    assert payload["engagement"]["effective"] == 1001
    assert payload["queues"]["ready"] == 1
    assert payload["ready_inputs"][0]["engagement_id"] == 1001


def test_automation_status_uses_autostart_engagement_for_queue_readiness(
    tmp_path: Path,
    monkeypatch,
) -> None:
    imports_dir = tmp_path / "imports"
    imports_dir.mkdir()
    (imports_dir / "autostart.local.json").write_text(
        json.dumps({"engagement_id": 1002}),
        encoding="utf-8",
    )
    (imports_dir / "urlhaus.json").write_text(
        json.dumps({"urls": ["https://queued.example/path"]}),
        encoding="utf-8",
    )
    (imports_dir / "urlhaus-inputs.local.json").write_text(
        json.dumps({"inputs": [{"value": "urlhaus.json", "status": "pending"}]}),
        encoding="utf-8",
    )
    monkeypatch.delenv("FORGE_DEFAULT_ENGAGEMENT_ID", raising=False)

    payload = automation_status(imports_dir=imports_dir)

    assert payload["paths"]["autostart_config"] == str(imports_dir / "autostart.local.json")
    assert payload["engagement"]["effective"] == 1002
    assert payload["queues"]["ready"] == 1
    assert payload["ready_inputs"][0]["engagement_id"] == 1002


def test_automation_status_summarizes_existing_target_feed_scanability(
    tmp_path: Path,
) -> None:
    imports_dir = tmp_path / "imports"
    imports_dir.mkdir()
    (imports_dir / "autostart.local.json").write_text(
        json.dumps({"min_start_source_count": 2}),
        encoding="utf-8",
    )
    feed_path = imports_dir / "target-feed.json"
    feed_path.write_text(
        json.dumps(
            {
                "schema_version": "target-feed.v1",
                "items": [
                    {
                        "target_type": "domain",
                        "target_value": "single.example",
                        "source_groups": ["connector:single"],
                        "source_count": 1,
                        "priority": 100,
                        "scan_eligible": True,
                        "scan_eligibility_reason": "eligible",
                    },
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
    assert scan["total_count"] == 3
    assert scan["eligible_count"] == 2
    assert scan["startable_count"] == 1
    assert scan["eligible_below_start_threshold_count"] == 1
    assert scan["min_start_source_count"] == 2
    assert scan["ineligible_count"] == 1
    assert scan["high_priority_count"] == 2
    assert scan["ineligible_reasons"] == {"non_global_ip": 1}
    assert scan["top_targets"][0]["target_value"] == "single.example"
    assert scan["top_startable_targets"][0]["target_value"] == "shared.example"
    assert payload["scan_policy"]["min_start_source_count"] == 2
    assert payload["autostart_probe"]["status"] == "blocked"
    assert payload["next_actions"] == [
        "forge automation self-heal-plan --json --docker-probe-mode compose-dependency",
        "resolve autostart blockers before running cycle --apply --live",
    ]


def test_automation_status_summarizes_due_monitoring_without_running_it(
    tmp_path: Path, monkeypatch
) -> None:
    calls: list[dict[str, object]] = []

    def fake_due_plan(data_dir: Path, *, limit: int | None = None) -> dict[str, object]:
        calls.append({"data_dir": data_dir, "limit": limit})
        return {
            "total_due_count": 101,
            "planned_policy_count": 0,
            "limited_policy_count": 101,
            "default_execution_limit": 50,
            "estimated_capped_invocations": 3,
            "oldest_due_age_seconds": 90000,
            "stale_backlog": {"enabled": True, "oldest_overdue_days": 1.04},
            "policy_summary": {"mode_counts": {"passive": 101}},
            "action_plan": [
                {"command": ["forge", "monitoring", "due-plan", "--json"]},
                {
                    "command": [
                        "forge",
                        "monitoring",
                        "run-due",
                        "--dry-run",
                        "--limit",
                        "50",
                        "--json",
                    ]
                },
            ],
            "errors": [],
        }

    monkeypatch.setattr(
        automation_cycle_module, "monitoring_due_plan_for_data_dir", fake_due_plan
    )

    payload = automation_status(
        imports_dir=tmp_path / "imports",
        output=tmp_path / "imports" / "target-feed.json",
        data_dir=tmp_path / "data",
    )

    assert calls == [{"data_dir": tmp_path / "data", "limit": 0}]
    assert payload["monitoring_due"]["execution_policy"] == (
        "read_only_monitoring_due_summary_no_commands_executed"
    )
    assert payload["monitoring_due"]["status"] == "stale_due"
    assert payload["monitoring_due"]["total_due_count"] == 101
    assert payload["monitoring_due"]["estimated_capped_invocations"] == 3
    assert payload["monitoring_due"]["next_actions"][0] == [
        "forge",
        "monitoring",
        "due-plan",
        "--json",
    ]


def test_automation_status_reports_autostart_probe_blockers(
    tmp_path: Path,
    monkeypatch,
) -> None:
    imports_dir = tmp_path / "imports"
    imports_dir.mkdir()
    (imports_dir / "autostart.local.json").write_text(
        json.dumps({"enabled": True, "apply_enabled": True}),
        encoding="utf-8",
    )

    def fake_guarded_autostart(**kwargs):
        assert kwargs["apply"] is False
        assert kwargs["skip_feed_build"] is True
        assert kwargs["docker_probe_mode"] == "compose-dependency"
        return {
            "status": "blocked",
            "execution_policy": "dry_run_no_autostart_or_live_commands_executed",
            "blockers": ["docker_tool_mount_missing_runtime_tools:nuclei"],
        }

    monkeypatch.setattr(
        "forge.automation_cycle.run_guarded_autostart",
        fake_guarded_autostart,
    )

    payload = automation_status(
        imports_dir=imports_dir,
        output=imports_dir / "target-feed.json",
        data_dir=tmp_path / "data",
        engagement=1001,
    )

    assert payload["autostart_probe"] == {
        "status": "blocked",
        "execution_policy": "dry_run_no_autostart_or_live_commands_executed",
        "config_path": str(imports_dir / "autostart.local.json"),
        "blockers": ["docker_tool_mount_missing_runtime_tools:nuclei"],
    }
    assert payload["next_actions"] == [
        "forge automation self-heal-plan --json --docker-probe-mode compose-dependency",
        "resolve autostart blockers before running cycle --apply --live",
    ]


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
    assert payload["target_feed_scan"]["startable_count"] == 0
    assert payload["target_feed_scan"]["min_start_source_count"] == 1
    assert (
        payload["scan_policy"]["new_targets"]
        == "scan_immediately_when_cycle_runs_with_apply_live_and_roe_gates_pass"
    )
    assert payload["scan_policy"]["min_start_source_count"] == 1
    assert not (imports_dir / "target-feed.json").exists()
    assert payload["queue_runs"][0]["status"] == "planned"
    queue = json.loads(
        (imports_dir / "burp-dast-imports.local.json").read_text(encoding="utf-8")
    )
    assert queue["inputs"][0]["status"] == "pending"


def test_automation_cycle_includes_monitoring_due_summary(
    tmp_path: Path, monkeypatch
) -> None:
    def fake_due_plan(_data_dir: Path, *, limit: int | None = None) -> dict[str, object]:
        assert limit == 0
        return {
            "total_due_count": 0,
            "planned_policy_count": 0,
            "limited_policy_count": 0,
            "default_execution_limit": 50,
            "estimated_capped_invocations": 0,
            "oldest_due_age_seconds": 0,
            "stale_backlog": {},
            "policy_summary": {},
            "action_plan": [],
            "errors": [],
        }

    monkeypatch.setattr(
        automation_cycle_module, "monitoring_due_plan_for_data_dir", fake_due_plan
    )

    payload = automation_cycle(
        apply=False,
        engagement=1001,
        output=tmp_path / "imports" / "target-feed.json",
        source=["connectors"],
        data_dir=tmp_path / "data",
        reports_dir=tmp_path / "reports",
        imports_dir=tmp_path / "imports",
    )

    assert payload["monitoring_due"]["status"] == "idle"
    assert payload["monitoring_due"]["total_due_count"] == 0
    assert payload["monitoring_due"]["execution_policy"] == (
        "read_only_monitoring_due_summary_no_commands_executed"
    )


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


def test_automation_cycle_queue_limit_defers_extra_ready_items(tmp_path: Path) -> None:
    imports_dir = tmp_path / "imports"
    reports_dir = tmp_path / "reports"
    imports_dir.mkdir()
    inputs: list[dict[str, str]] = []
    for index in range(3):
        artifact = imports_dir / f"threatfox-{index}.json"
        artifact.write_text(
            json.dumps({"iocs": [f"queued-{index}.example"]}),
            encoding="utf-8",
        )
        inputs.append({"value": artifact.name, "status": "pending"})
    queue_path = imports_dir / "threatfox-inputs.local.json"
    queue_path.write_text(json.dumps({"inputs": inputs}), encoding="utf-8")
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
        queue_limit=2,
        command_runner=_runner,
    )

    assert payload["queue_execution"] == {
        "queue_limit": 2,
        "ready_count": 3,
        "selected_count": 2,
        "deferred_count": 1,
        "execution_order": "priority_desc_then_connector_then_value",
    }
    assert len(commands) == 2
    assert [run["status"] for run in payload["queue_runs"]] == ["completed", "completed"]
    assert payload["deferred_ready_inputs"][0]["reason"] == "queue_limit_reached:2"
    queue = json.loads(queue_path.read_text(encoding="utf-8"))
    assert [item["status"] for item in queue["inputs"]] == [
        "imported",
        "imported",
        "pending",
    ]


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


def test_automation_cycle_rebuilds_feed_after_successful_queue_import_before_live(
    tmp_path: Path,
    monkeypatch,
) -> None:
    imports_dir = tmp_path / "imports"
    reports_dir = tmp_path / "reports"
    imports_dir.mkdir()
    (imports_dir / "threatfox.json").write_text(
        json.dumps({"iocs": ["fresh.example"]}),
        encoding="utf-8",
    )
    (imports_dir / "threatfox-inputs.local.json").write_text(
        json.dumps({"inputs": [{"value": "threatfox.json", "status": "pending"}]}),
        encoding="utf-8",
    )
    events: list[str] = []

    def fake_build_target_feed(**kwargs):
        events.append("feed")
        selected = 1 if events.count("feed") == 1 else 2
        return {
            "schema_version": "target-feed.v1",
            "counts": {
                "selected": selected,
                "total": selected,
                "source_errors": [],
            },
            "source_errors": [],
            "discovered_input_registry_update": {},
            "source_input_registry_updates": [],
            "items": [
                {
                    "target_type": "domain",
                    "target_value": "fresh.example",
                    "canonical_value": "fresh.example",
                    "target_key": "domain:fresh.example",
                    "source_kind": "cti_observation",
                    "source_group": "cti_file:threatfox.json",
                    "source_groups": ["cti_file:threatfox.json"],
                    "source_count": selected,
                    "priority": 90,
                    "scan_eligible": True,
                    "scan_eligibility_reason": "eligible",
                    "confidence": 0.5,
                    "first_seen_at": "2026-08-29T00:00:00+00:00",
                    "provenance": "cti_file:threatfox.json",
                }
            ],
        }

    def fake_write_target_feed(_payload, _output_path):
        events.append("write")

    def _runner(_command: list[str], _cwd: Path) -> dict[str, object]:
        events.append("queue")
        return {"returncode": 0, "stdout": "{\"status\":\"completed\"}", "stderr": ""}

    def fake_guarded_autostart(**kwargs):
        events.append("guarded")
        assert kwargs["skip_feed_build"] is True
        return {
            "schema_version": "forge.automation_guarded_autostart.v1",
            "status": "ready",
            "commands": {},
        }

    monkeypatch.setattr(
        automation_cycle_module, "build_target_feed", fake_build_target_feed
    )
    monkeypatch.setattr(
        automation_cycle_module, "write_target_feed", fake_write_target_feed
    )
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

    assert events == ["feed", "write", "queue", "feed", "write", "guarded"]
    assert payload["feed_rebuilt_after_queue_imports"] is True
    assert payload["feed"]["counts"]["selected"] == 2
    assert payload["autostart"]["status"] == "ready"


def test_automation_cycle_uses_autostart_engagement_for_ready_queues(
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
    autostart_config = imports_dir / "autostart.local.json"
    autostart_config.write_text(json.dumps({"engagement_id": 1002}), encoding="utf-8")
    commands: list[list[str]] = []

    def _runner(command: list[str], _cwd: Path) -> dict[str, object]:
        commands.append(command)
        return {"returncode": 0, "stdout": "{\"status\":\"completed\"}", "stderr": ""}

    payload = automation_cycle(
        apply=True,
        output=imports_dir / "target-feed.json",
        source=["cti"],
        data_dir=tmp_path / "data",
        reports_dir=reports_dir,
        imports_dir=imports_dir,
        autostart_config=autostart_config,
        command_runner=_runner,
    )

    assert payload["engagement"]["effective"] == 1002
    assert commands[0][commands[0].index("--engagement") + 1] == "1002"
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
    cycle_payload = json.loads(cycle_result.output)
    assert cycle_payload["schema_version"] == "forge.automation_cycle.v1"
    assert cycle_payload["target_feed_scan"]["min_start_source_count"] == 1
