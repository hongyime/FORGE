from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from forge.reporting.quality_audit import (
    collect_long_run_review_plan,
    collect_policy_flag_review_plan,
    collect_report_quality_audit,
    collect_stale_report_repair_plan,
    run_stale_report_repair_plan,
)


def _write_dashboard_fixture(reports_dir: Path) -> None:
    data_dir = reports_dir / "dashboard" / "data"
    detail_dir = data_dir / "engagements"
    detail_dir.mkdir(parents=True)
    (reports_dir / "dashboard" / "engagements" / "engagement-1001-acme").mkdir(
        parents=True
    )
    (reports_dir / "dashboard" / "index.html").write_text("<html></html>", encoding="utf-8")
    (
        reports_dir
        / "dashboard"
        / "engagements"
        / "engagement-1001-acme"
        / "index.html"
    ).write_text("<html></html>", encoding="utf-8")
    (reports_dir / "engagement_1001_report_20260820T010101.md").write_text(
        "# Report", encoding="utf-8"
    )
    (reports_dir / "engagement_1001_report_20260820T010101.json").write_text(
        "{}", encoding="utf-8"
    )
    (reports_dir / "engagement_1001_stats.json").write_text(
        "{}", encoding="utf-8"
    )
    (detail_dir / "engagement-1001-acme.json").write_text(
        json.dumps(
            {
                "sections": {
                    "recent_audit_log": [
                        {
                            "Action": "dashboard_review_refresh_failed",
                            "Target": "acme.example",
                            "Result": "reason=completed error=[Errno 22] Invalid argument",
                        }
                    ]
                }
            }
        ),
        encoding="utf-8",
    )
    (data_dir / "engagements.json").write_text(
        json.dumps(
            {
                "generated_at": "2026-08-20 10:00:00",
                "items": [
                    {
                        "id": "1001",
                        "slug": "engagement-1001-acme",
                        "name": "acme",
                        "primary_seed": "acme.example",
                        "detail_data": "data/engagements/engagement-1001-acme.json",
                        "target_resume_candidate": {"reason": "pending_recursive_work"},
                        "run_summary": {
                            "status": "failed",
                            "run_kind": "kill_chain",
                            "seed_value": "acme.example",
                            "current_iteration": 1,
                            "max_iterations": 3,
                            "resume_enabled": True,
                            "attack_mode": True,
                            "destructive_actions_allowed": False,
                            "post_exploitation_allowed": False,
                            "error": "elapsed_s=3100.5 max iterations exhausted",
                        },
                        "report_summary": {
                            "provider": "llama_cpp",
                            "rendered_provider": "template",
                            "fallback_reason": "GGUF model not found: C:/model.gguf",
                            "export_count": 2,
                        },
                    }
                ],
            }
        ),
        encoding="utf-8",
    )


def test_collect_report_quality_audit_summarizes_dashboard_breakpoints(
    tmp_path: Path,
) -> None:
    reports_dir = tmp_path / "reports"
    _write_dashboard_fixture(reports_dir)

    payload = collect_report_quality_audit(
        reports_dir=reports_dir,
        long_run_seconds=2700,
        top_limit=5,
    )

    assert payload["schema_version"] == "forge.report_quality_audit.v1"
    assert payload["engagement_count"] == 1
    assert payload["report_file_count"] == 6
    assert payload["root_report_file_count"] == 2
    assert payload["dashboard_html_count"] == 2
    assert payload["report_family_count"] == 1
    assert payload["run_status_counts"] == {"failed": 1}
    assert payload["fallback_reason_counts"] == {"gguf_model_missing": 1}
    assert payload["policy_counts"]["attack_yes"] == 1
    assert payload["policy_counts"]["resume_yes"] == 1
    assert payload["policy_counts"]["destructive_no"] == 1
    assert payload["policy_counts"]["post_ex_no"] == 1
    assert payload["resume_review_count"] == 1
    assert payload["long_run_count"] == 1
    assert payload["failed_run_count"] == 1
    assert payload["dashboard_refresh_failure_count"] == 1
    assert payload["historical_dashboard_refresh_failure_count"] == 0
    assert payload["top_long_runs"][0]["elapsed_seconds"] == 3100.5
    action_by_id = {item["id"]: item for item in payload["operator_action_plan"]}
    assert action_by_id["review_resume_plan"]["commands"] == [
        ["forge", "targets", "resume-plan", "--json", "--redact-paths", "--limit", "1"]
    ]
    assert "resume-run" not in json.dumps(action_by_id["review_resume_plan"])
    assert action_by_id["review_long_runs"]["total_count"] == 1
    assert action_by_id["review_long_runs"]["follow_up_commands"] == [
        ["forge", "report", "long-run-plan", "--json", "--limit", "1"]
    ]
    assert action_by_id["review_policy_flags"]["counts"] == {
        "destructive_no": 1,
        "post_ex_no": 1,
    }
    assert action_by_id["review_policy_flags"]["sample_count"] == 1
    assert action_by_id["review_policy_flags"]["samples"][0]["flags"] == [
        "destructive_no",
        "post_ex_no",
    ]
    assert action_by_id["review_policy_flags"]["follow_up_commands"] == [
        ["forge", "report", "policy-plan", "--json", "--limit", "1"]
    ]
    assert "latest run metadata" in action_by_id["review_policy_flags"]["summary"]


def test_collect_report_quality_audit_separates_stale_dashboard_failures(
    tmp_path: Path,
) -> None:
    reports_dir = tmp_path / "reports"
    _write_dashboard_fixture(reports_dir)
    detail_path = (
        reports_dir
        / "dashboard"
        / "data"
        / "engagements"
        / "engagement-1001-acme.json"
    )
    detail_payload = json.loads(detail_path.read_text(encoding="utf-8"))
    detail_payload["sections"]["recent_audit_log"][0]["When"] = "2026-08-19 09:00:00"
    detail_path.write_text(json.dumps(detail_payload), encoding="utf-8")

    payload = collect_report_quality_audit(reports_dir=reports_dir, top_limit=5)

    assert payload["dashboard_generated_at"] == "2026-08-20 10:00:00"
    assert payload["dashboard_refresh_failure_count"] == 0
    assert payload["dashboard_refresh_failures"] == []
    assert payload["historical_dashboard_refresh_failure_count"] == 1
    assert payload["historical_dashboard_refresh_failures"][0]["when"] == (
        "2026-08-19 09:00:00"
    )


def test_collect_report_quality_audit_reports_latest_fallbacks_separately(
    tmp_path: Path,
    monkeypatch,
) -> None:
    reports_dir = tmp_path / "reports"
    _write_dashboard_fixture(reports_dir)
    monkeypatch.setattr(
        "forge.reporting.quality_audit._default_gguf_model_available",
        lambda: False,
    )
    detail_path = (
        reports_dir
        / "dashboard"
        / "data"
        / "engagements"
        / "engagement-1001-acme.json"
    )
    detail_payload = json.loads(detail_path.read_text(encoding="utf-8"))
    detail_payload["report_history"] = [
        {
            "family_stem": "engagement_1001_stats",
            "artifact_name": "engagement_1001_stats.json",
        },
        {
            "rendered_provider": "template",
            "generated_at": "2026-08-20 11:00:00",
            "fallback_reason": "quota exceeded",
        },
        {
            "rendered_provider": "template",
            "generated_at": "2026-08-19 11:00:00",
            "fallback_reason": "GGUF model not found: C:/model.gguf",
        },
    ]
    detail_path.write_text(json.dumps(detail_payload), encoding="utf-8")

    payload = collect_report_quality_audit(reports_dir=reports_dir, top_limit=5)

    assert payload["fallback_reason_counts"] == {
        "gguf_model_missing": 1,
        "provider_quota_or_rate_limit": 1,
    }
    assert payload["latest_fallback_reason_counts"] == {
        "provider_quota_or_rate_limit": 1
    }
    assert payload["latest_fallback_reports"] == [
        {
            "id": "1001",
            "slug": "engagement-1001-acme",
            "name": "acme",
            "seed": "acme.example",
            "family_stem": "",
            "artifact_name": "",
            "generated_at": "2026-08-20 11:00:00",
            "render_backend": "template",
            "fallback_class": "provider_quota_or_rate_limit",
            "repair_status": "regenerate_latest_report",
            "fallback_reason": "quota exceeded",
            "report_generate_command": [
                "forge",
                "report",
                "generate",
                "--engagement",
                "1001",
                "--provider",
                "auto",
                "--yes",
            ],
        }
    ]
    assert payload["report_backend_counts"] == {"template": 2}
    assert payload["latest_report_backend_counts"] == {"template": 1}


def test_collect_report_quality_audit_marks_stale_gguf_fallbacks_when_model_exists(
    tmp_path: Path,
    monkeypatch,
) -> None:
    reports_dir = tmp_path / "reports"
    _write_dashboard_fixture(reports_dir)
    monkeypatch.setattr(
        "forge.reporting.quality_audit._default_gguf_model_available",
        lambda: True,
    )

    payload = collect_report_quality_audit(reports_dir=reports_dir, top_limit=5)

    assert payload["latest_fallback_reports"][0]["fallback_class"] == "gguf_model_missing"
    assert payload["latest_fallback_reports"][0]["repair_status"] == (
        "stale_after_model_available"
    )
    assert payload["latest_fallback_reports"][0]["report_generate_command"] == [
        "forge",
        "report",
        "generate",
        "--engagement",
        "1001",
        "--provider",
        "auto",
        "--yes",
    ]
    action_by_id = {item["id"]: item for item in payload["operator_action_plan"]}
    assert action_by_id["regenerate_stale_reports"]["commands"] == [
        [
            "forge",
            "report",
            "generate",
            "--engagement",
            "1001",
            "--provider",
            "auto",
            "--yes",
        ]
    ]
    assert action_by_id["regenerate_stale_reports"]["execution_policy"] == (
        "plan_only_no_commands_executed"
    )
    assert action_by_id["regenerate_stale_reports"]["batch_run_command"] == [
        "forge",
        "report",
        "stale-run",
        "--limit",
        "1",
        "--provider",
        "auto",
        "--json",
    ]


def test_collect_report_quality_audit_shows_omitted_stale_report_commands(
    tmp_path: Path,
    monkeypatch,
) -> None:
    reports_dir = tmp_path / "reports"
    _write_dashboard_fixture(reports_dir)
    monkeypatch.setattr(
        "forge.reporting.quality_audit._default_gguf_model_available",
        lambda: True,
    )
    overview_path = reports_dir / "dashboard" / "data" / "engagements.json"
    overview = json.loads(overview_path.read_text(encoding="utf-8"))
    template_item = overview["items"][0]
    overview["items"] = [
        {
            **template_item,
            "id": str(1001 + index),
            "slug": f"engagement-{1001 + index}-acme-{index}",
            "name": f"acme-{index}",
            "primary_seed": f"acme-{index}.example",
            "detail_data": f"data/engagements/engagement-{1001 + index}-acme-{index}.json",
        }
        for index in range(3)
    ]
    overview_path.write_text(json.dumps(overview), encoding="utf-8")
    detail_template = json.loads(
        (
            reports_dir
            / "dashboard"
            / "data"
            / "engagements"
            / "engagement-1001-acme.json"
        ).read_text(encoding="utf-8")
    )
    for index in range(3):
        detail_path = (
            reports_dir
            / "dashboard"
            / "data"
            / "engagements"
            / f"engagement-{1001 + index}-acme-{index}.json"
        )
        detail_path.write_text(json.dumps(detail_template), encoding="utf-8")

    payload = collect_report_quality_audit(reports_dir=reports_dir, top_limit=2)

    action_by_id = {item["id"]: item for item in payload["operator_action_plan"]}
    action = action_by_id["regenerate_stale_reports"]
    assert action["total_count"] == 3
    assert action["sample_limit"] == 2
    assert action["sample_count"] == 2
    assert action["omitted_count"] == 1
    assert len(action["commands"]) == 2
    assert action["follow_up_commands"] == [
        ["forge", "report", "stale-plan", "--json", "--limit", "3"],
        ["forge", "report", "stale-run", "--dry-run", "--json", "--limit", "3"],
    ]


def test_collect_stale_report_repair_plan_is_read_only_command_plan(
    tmp_path: Path,
    monkeypatch,
) -> None:
    reports_dir = tmp_path / "reports"
    _write_dashboard_fixture(reports_dir)
    monkeypatch.setattr(
        "forge.reporting.quality_audit._default_gguf_model_available",
        lambda: True,
    )

    payload = collect_stale_report_repair_plan(reports_dir=reports_dir, limit=1)

    assert payload["schema_version"] == "forge.report_stale_repair_plan.v1"
    assert payload["execution_policy"] == "plan_only_no_commands_executed"
    assert payload["status"] == "ready"
    assert payload["total_count"] == 1
    assert payload["sample_limit"] == 1
    assert payload["sample_count"] == 1
    assert payload["omitted_count"] == 0
    assert payload["commands"] == [
        [
            "forge",
            "report",
            "generate",
            "--engagement",
            "1001",
            "--provider",
            "auto",
            "--yes",
        ]
    ]


def test_collect_long_run_review_plan_is_read_only_review_plan(tmp_path: Path) -> None:
    reports_dir = tmp_path / "reports"
    _write_dashboard_fixture(reports_dir)

    payload = collect_long_run_review_plan(
        reports_dir=reports_dir,
        long_run_seconds=2700,
        limit=1,
    )

    assert payload["schema_version"] == "forge.report_long_run_review_plan.v1"
    assert payload["execution_policy"] == "plan_only_no_commands_executed"
    assert payload["status"] == "review"
    assert payload["total_count"] == 1
    assert payload["sample_limit"] == 1
    assert payload["sample_count"] == 1
    assert payload["omitted_count"] == 0
    assert payload["commands"] == []
    assert payload["samples"][0]["id"] == "1001"
    assert payload["samples"][0]["elapsed_seconds"] == 3100.5
    assert "never starts runs" in payload["review_guidance"]


def test_collect_policy_flag_review_plan_explains_latest_run_metadata(
    tmp_path: Path,
) -> None:
    reports_dir = tmp_path / "reports"
    _write_dashboard_fixture(reports_dir)

    payload = collect_policy_flag_review_plan(reports_dir=reports_dir, limit=1)

    assert payload["schema_version"] == "forge.report_policy_flag_review_plan.v1"
    assert payload["execution_policy"] == "plan_only_no_commands_executed"
    assert payload["status"] == "explain"
    assert payload["counts"] == {"destructive_no": 1, "post_ex_no": 1}
    assert payload["total_count"] == 2
    assert payload["sample_count"] == 1
    assert payload["omitted_count"] == 0
    assert payload["commands"] == []
    assert payload["samples"][0]["id"] == "1001"
    assert payload["samples"][0]["flags"] == ["destructive_no", "post_ex_no"]
    assert "latest run summaries" in payload["explanation"]


def test_report_quality_audit_cli_outputs_json(tmp_path: Path) -> None:
    from forge.cli import app  # noqa: PLC0415

    reports_dir = tmp_path / "reports"
    _write_dashboard_fixture(reports_dir)
    result = CliRunner().invoke(
        app,
        [
            "report",
            "quality-audit",
            "--reports-dir",
            str(reports_dir),
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["engagement_count"] == 1
    assert payload["fallback_reason_counts"]["gguf_model_missing"] == 1
    assert payload["latest_fallback_reason_counts"]["gguf_model_missing"] == 1
    assert payload["latest_fallback_reports"][0]["fallback_reason"] == (
        "GGUF model not found; configure an LLM provider/model or regenerate after local model setup."
    )
    assert "C:/model.gguf" not in json.dumps(payload["latest_fallback_reports"])


def test_report_quality_audit_cli_prints_operator_action_plan(tmp_path: Path) -> None:
    from forge.cli import app  # noqa: PLC0415

    reports_dir = tmp_path / "reports"
    _write_dashboard_fixture(reports_dir)
    result = CliRunner().invoke(
        app,
        [
            "report",
            "quality-audit",
            "--reports-dir",
            str(reports_dir),
        ],
    )

    assert result.exit_code == 0, result.output
    assert "operator action plan" in result.output
    assert "review_resume_plan" in result.output
    assert "forge targets resume-plan --json --redact-paths --limit 1" in result.output
    assert "resume-run" not in result.output


def test_report_quality_audit_cli_prints_follow_up_commands(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from forge.cli import app  # noqa: PLC0415

    reports_dir = tmp_path / "reports"
    _write_dashboard_fixture(reports_dir)
    monkeypatch.setattr(
        "forge.reporting.quality_audit._default_gguf_model_available",
        lambda: True,
    )
    overview_path = reports_dir / "dashboard" / "data" / "engagements.json"
    overview = json.loads(overview_path.read_text(encoding="utf-8"))
    overview["items"].append({**overview["items"][0], "id": "1002"})
    overview_path.write_text(json.dumps(overview), encoding="utf-8")
    result = CliRunner().invoke(
        app,
        [
            "report",
            "quality-audit",
            "--reports-dir",
            str(reports_dir),
            "--top",
            "1",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "follow_up=forge report stale-plan --json --limit 2" in result.output
    assert (
        "follow_up=forge report stale-run --dry-run --json --limit 2"
        in result.output
    )


def test_report_stale_plan_cli_outputs_json(tmp_path: Path, monkeypatch) -> None:
    from forge.cli import app  # noqa: PLC0415

    reports_dir = tmp_path / "reports"
    _write_dashboard_fixture(reports_dir)
    monkeypatch.setattr(
        "forge.reporting.quality_audit._default_gguf_model_available",
        lambda: True,
    )
    result = CliRunner().invoke(
        app,
        [
            "report",
            "stale-plan",
            "--reports-dir",
            str(reports_dir),
            "--limit",
            "1",
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["schema_version"] == "forge.report_stale_repair_plan.v1"
    assert payload["execution_policy"] == "plan_only_no_commands_executed"
    assert payload["commands"][0] == [
        "forge",
        "report",
        "generate",
        "--engagement",
        "1001",
        "--provider",
        "auto",
        "--yes",
    ]


def test_report_stale_plan_cli_prints_human_plan(tmp_path: Path, monkeypatch) -> None:
    from forge.cli import app  # noqa: PLC0415

    reports_dir = tmp_path / "reports"
    _write_dashboard_fixture(reports_dir)
    monkeypatch.setattr(
        "forge.reporting.quality_audit._default_gguf_model_available",
        lambda: True,
    )
    result = CliRunner().invoke(
        app,
        [
            "report",
            "stale-plan",
            "--reports-dir",
            str(reports_dir),
            "--limit",
            "1",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "Stale report repair plan:" in result.output
    assert "execution_policy=plan_only_no_commands_executed" in result.output
    assert "forge report generate --engagement 1001 --provider auto --yes" in result.output
    assert "quality-audit" not in result.output


def test_run_stale_report_repair_plan_dry_run_is_bounded(
    tmp_path: Path,
    monkeypatch,
) -> None:
    reports_dir = tmp_path / "reports"
    _write_dashboard_fixture(reports_dir)
    monkeypatch.setattr(
        "forge.reporting.quality_audit._default_gguf_model_available",
        lambda: True,
    )

    payload = run_stale_report_repair_plan(
        reports_dir=reports_dir,
        limit=1,
        provider="template",
        max_loops=0,
        dry_run=True,
    )

    assert payload["schema_version"] == "forge.report_stale_repair_run.v1"
    assert payload["execution_policy"] == "dry_run_no_commands_executed"
    assert payload["selected_count"] == 1
    assert payload["attempted_count"] == 0
    assert payload["skipped_count"] == 1
    assert payload["items"][0]["status"] == "dry_run"
    assert payload["items"][0]["command"] == [
        "forge",
        "report",
        "generate",
        "--engagement",
        "1001",
        "--provider",
        "template",
        "--yes",
        "--max-loops",
        "0",
    ]


def test_run_stale_report_repair_plan_executes_with_injected_generator(
    tmp_path: Path,
    monkeypatch,
) -> None:
    reports_dir = tmp_path / "reports"
    _write_dashboard_fixture(reports_dir)
    monkeypatch.setattr(
        "forge.reporting.quality_audit._default_gguf_model_available",
        lambda: True,
    )
    calls: list[dict[str, object]] = []

    def fake_generate_report(**kwargs):
        calls.append(dict(kwargs))
        return tmp_path / "reports" / "regenerated.md"

    payload = run_stale_report_repair_plan(
        reports_dir=reports_dir,
        limit=1,
        provider="auto",
        max_loops=None,
        generate_report=fake_generate_report,
    )

    assert payload["execution_policy"] == "bounded_sequential_report_generation"
    assert payload["attempted_count"] == 1
    assert payload["succeeded_count"] == 1
    assert payload["failed_count"] == 0
    assert calls == [
        {
            "engagement_id": "1001",
            "provider": "auto",
            "max_loops": None,
            "assume_yes": True,
        }
    ]
    assert payload["items"][0]["report_path"].endswith("regenerated.md")


def test_report_stale_run_cli_outputs_dry_run_json(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from forge.cli import app  # noqa: PLC0415

    reports_dir = tmp_path / "reports"
    _write_dashboard_fixture(reports_dir)
    monkeypatch.setattr(
        "forge.reporting.quality_audit._default_gguf_model_available",
        lambda: True,
    )
    result = CliRunner().invoke(
        app,
        [
            "report",
            "stale-run",
            "--reports-dir",
            str(reports_dir),
            "--limit",
            "1",
            "--provider",
            "template",
            "--max-loops",
            "0",
            "--dry-run",
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["schema_version"] == "forge.report_stale_repair_run.v1"
    assert payload["execution_policy"] == "dry_run_no_commands_executed"
    assert payload["items"][0]["status"] == "dry_run"
    assert payload["items"][0]["command"][-2:] == ["--max-loops", "0"]


def test_report_long_run_plan_cli_outputs_json(tmp_path: Path) -> None:
    from forge.cli import app  # noqa: PLC0415

    reports_dir = tmp_path / "reports"
    _write_dashboard_fixture(reports_dir)
    result = CliRunner().invoke(
        app,
        [
            "report",
            "long-run-plan",
            "--reports-dir",
            str(reports_dir),
            "--long-run-seconds",
            "2700",
            "--limit",
            "1",
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["schema_version"] == "forge.report_long_run_review_plan.v1"
    assert payload["execution_policy"] == "plan_only_no_commands_executed"
    assert payload["commands"] == []
    assert payload["samples"][0]["id"] == "1001"


def test_report_long_run_plan_cli_prints_human_plan(tmp_path: Path) -> None:
    from forge.cli import app  # noqa: PLC0415

    reports_dir = tmp_path / "reports"
    _write_dashboard_fixture(reports_dir)
    result = CliRunner().invoke(
        app,
        [
            "report",
            "long-run-plan",
            "--reports-dir",
            str(reports_dir),
            "--long-run-seconds",
            "2700",
            "--limit",
            "1",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "Long-run review plan:" in result.output
    assert "execution_policy=plan_only_no_commands_executed" in result.output
    assert "sample=engagement=1001 status=failed elapsed=3100.5" in result.output
    assert "resume-run" not in result.output


def test_report_policy_plan_cli_outputs_json(tmp_path: Path) -> None:
    from forge.cli import app  # noqa: PLC0415

    reports_dir = tmp_path / "reports"
    _write_dashboard_fixture(reports_dir)
    result = CliRunner().invoke(
        app,
        [
            "report",
            "policy-plan",
            "--reports-dir",
            str(reports_dir),
            "--limit",
            "1",
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["schema_version"] == "forge.report_policy_flag_review_plan.v1"
    assert payload["execution_policy"] == "plan_only_no_commands_executed"
    assert payload["counts"] == {"destructive_no": 1, "post_ex_no": 1}
    assert payload["commands"] == []
    assert payload["samples"][0]["flags"] == ["destructive_no", "post_ex_no"]


def test_report_policy_plan_cli_prints_human_plan(tmp_path: Path) -> None:
    from forge.cli import app  # noqa: PLC0415

    reports_dir = tmp_path / "reports"
    _write_dashboard_fixture(reports_dir)
    result = CliRunner().invoke(
        app,
        [
            "report",
            "policy-plan",
            "--reports-dir",
            str(reports_dir),
            "--limit",
            "1",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "Policy flag review plan:" in result.output
    assert "execution_policy=plan_only_no_commands_executed" in result.output
    assert "flags=destructive_no,post_ex_no" in result.output
    assert "resume-run" not in result.output


def test_report_quality_audit_cli_accepts_top_limit_alias(tmp_path: Path) -> None:
    from forge.cli import app  # noqa: PLC0415

    reports_dir = tmp_path / "reports"
    _write_dashboard_fixture(reports_dir)
    result = CliRunner().invoke(
        app,
        [
            "report",
            "quality-audit",
            "--reports-dir",
            str(reports_dir),
            "--top-limit",
            "0",
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["long_run_count"] == 1
    assert payload["top_long_runs"] == []
