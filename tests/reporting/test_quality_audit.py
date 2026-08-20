from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from forge.reporting.quality_audit import collect_report_quality_audit


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
    assert payload["top_long_runs"][0]["elapsed_seconds"] == 3100.5


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
