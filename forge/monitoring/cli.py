from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from forge.config import ForgeConfig
from forge.monitoring.runner import (
    deliver_monitoring_alerts_for_data_dir,
    monitoring_due_plan_for_data_dir,
    monitoring_status_for_data_dir,
    run_due_monitoring_for_data_dir,
    run_monitoring_worker,
)

console = Console(stderr=True)


def register_monitoring_commands(app: typer.Typer) -> None:
    @app.command("status")
    def status(
        data_dir: Optional[Path] = typer.Option(
            None,
            "--data-dir",
            help="FORGE data directory. Defaults to FORGE_DATA_DIR.",
        ),
        now: Optional[str] = typer.Option(
            None,
            "--now",
            help="Override scheduler clock for deterministic status checks/tests.",
        ),
        json_output: bool = typer.Option(
            False,
            "--json",
            help="Print machine-readable JSON.",
        ),
    ) -> None:
        cfg = ForgeConfig.load()
        root = data_dir or cfg.data_dir
        result = monitoring_status_for_data_dir(root, now=now)
        if json_output:
            typer.echo(json.dumps(result, sort_keys=True))
            return
        console.print(
            "[bold]Monitoring status[/bold] "
            f"dbs={result['db_count']} ready_dbs={result['schema_ready_db_count']} "
            f"engagements={result['engagement_count']} "
            f"policies={result['policy_count']} enabled={result['enabled_policy_count']} "
            f"due={result['due_policy_count']} open_alerts={result['open_alert_count']} "
            f"unrouted_alerts={result['unrouted_alert_count']} "
            f"failed_deliveries={result['failed_delivery_count']} "
            f"suppressed_deliveries={result['suppressed_delivery_count']} "
            f"active_suppressions={result['active_suppression_count']} "
            f"errors={len(result['errors'])}"
        )

    @app.command("due-plan")
    def due_plan(
        data_dir: Optional[Path] = typer.Option(
            None,
            "--data-dir",
            help="FORGE data directory. Defaults to FORGE_DATA_DIR.",
        ),
        now: Optional[str] = typer.Option(
            None,
            "--now",
            help="Override scheduler clock for deterministic plan checks/tests.",
        ),
        limit: int = typer.Option(
            50,
            "--limit",
            min=0,
            help="Maximum due policy rows to include in the plan.",
        ),
        json_output: bool = typer.Option(
            False,
            "--json",
            help="Print machine-readable JSON.",
        ),
    ) -> None:
        cfg = ForgeConfig.load()
        root = data_dir or cfg.data_dir
        result = monitoring_due_plan_for_data_dir(root, now=now, limit=limit)
        if json_output:
            typer.echo(json.dumps(result, sort_keys=True))
            return
        console.print(
            "[bold]Monitoring due plan[/bold] "
            f"dbs={result['db_count']} ready_dbs={result['schema_ready_db_count']} "
            f"engagements={result['engagement_count']} due={result['due_policy_count']} "
            f"planned={result['planned_policy_count']} "
            f"limited={result['limited_policy_count']} "
            f"errors={len(result['errors'])}"
        )

    @app.command("run-due")
    def run_due(
        data_dir: Optional[Path] = typer.Option(
            None,
            "--data-dir",
            help="FORGE data directory. Defaults to FORGE_DATA_DIR.",
        ),
        now: Optional[str] = typer.Option(
            None,
            "--now",
            help="Override scheduler clock for deterministic runs/tests.",
        ),
        operator: str = typer.Option(
            "monitoring-scheduler",
            "--operator",
            help="Operator name stored in monitoring audit rows.",
        ),
        json_output: bool = typer.Option(
            False,
            "--json",
            help="Print machine-readable JSON.",
        ),
    ) -> None:
        cfg = ForgeConfig.load()
        root = data_dir or cfg.data_dir
        result = run_due_monitoring_for_data_dir(root, now=now, operator=operator)
        if json_output:
            typer.echo(json.dumps(result, sort_keys=True))
            return
        console.print(
            "[bold]Monitoring due run[/bold] "
            f"dbs={result['db_count']} engagements={result['engagement_count']} "
            f"runs={result['run_count']} changes={result['change_count']} "
            f"alerts={result['alert_count']} errors={len(result['errors'])}"
        )

    @app.command("deliver-alerts")
    def deliver_alerts(
        data_dir: Optional[Path] = typer.Option(
            None,
            "--data-dir",
            help="FORGE data directory. Defaults to FORGE_DATA_DIR.",
        ),
        jsonl_path: Optional[Path] = typer.Option(
            None,
            "--jsonl-path",
            help="Local JSONL alert sink. Defaults to <data-dir>/monitoring_alerts.jsonl.",
        ),
        stdout_delivery: bool = typer.Option(
            False,
            "--stdout",
            help="Also write alert payloads to stdout.",
        ),
        webhook_url: Optional[str] = typer.Option(
            None,
            "--webhook-url",
            help="Optional generic webhook URL for JSON POST delivery.",
        ),
        operator: str = typer.Option(
            "monitoring-delivery",
            "--operator",
            help="Operator name stored in delivery metadata.",
        ),
        json_output: bool = typer.Option(
            False,
            "--json",
            help="Print machine-readable delivery summary.",
        ),
    ) -> None:
        cfg = ForgeConfig.load()
        root = data_dir or cfg.data_dir
        channels = ["jsonl"]
        if stdout_delivery:
            channels.append("stdout")
        if webhook_url:
            channels.append("webhook")
        result = deliver_monitoring_alerts_for_data_dir(
            root,
            channels=channels,
            jsonl_path=jsonl_path,
            webhook_url=webhook_url,
            operator=operator,
        )
        if json_output:
            typer.echo(json.dumps(result, sort_keys=True))
            return
        console.print(
            "[bold]Monitoring alert delivery[/bold] "
            f"dbs={result['db_count']} engagements={result['engagement_count']} "
            f"delivered={result['delivery_count']} failures={result['failure_count']} "
            f"skipped={result['skipped_count']} unrouted={result['unrouted_count']} "
            f"errors={len(result['errors'])}"
        )

    @app.command("worker")
    def worker(
        data_dir: Optional[Path] = typer.Option(
            None,
            "--data-dir",
            help="FORGE data directory. Defaults to FORGE_DATA_DIR.",
        ),
        poll_seconds: int = typer.Option(
            60,
            "--poll-seconds",
            min=1,
            help="Seconds between due-policy scans.",
        ),
        iterations: Optional[int] = typer.Option(
            None,
            "--iterations",
            min=1,
            help="Stop after this many scans. Omit for long-running service mode.",
        ),
        now: Optional[str] = typer.Option(
            None,
            "--now",
            help="Override scheduler clock for deterministic runs/tests.",
        ),
        operator: str = typer.Option(
            "monitoring-worker",
            "--operator",
            help="Operator name stored in monitoring audit rows.",
        ),
        deliver_jsonl: Optional[Path] = typer.Option(
            None,
            "--deliver-jsonl",
            help="Deliver open alerts to this local JSONL file after each scan.",
        ),
        deliver_stdout: bool = typer.Option(
            False,
            "--deliver-stdout",
            help="Deliver open alert payloads to stdout after each scan.",
        ),
        webhook_url: Optional[str] = typer.Option(
            None,
            "--webhook-url",
            help="Optional generic webhook URL for alert JSON POST delivery after each scan.",
        ),
        json_output: bool = typer.Option(
            False,
            "--json",
            help="Print machine-readable JSON after the worker stops.",
        ),
    ) -> None:
        cfg = ForgeConfig.load()
        root = data_dir or cfg.data_dir
        if not json_output:
            bound = f" iterations={iterations}" if iterations is not None else " until interrupted"
            console.print(
                "[bold]Monitoring worker[/bold] "
                f"data_dir={root} poll={poll_seconds}s{bound}"
            )
        result = run_monitoring_worker(
            root,
            poll_seconds=poll_seconds,
            iterations=iterations,
            now=now,
            operator=operator,
            delivery_channels=(
                ("jsonl",) if deliver_jsonl else ()
            )
            + (("stdout",) if deliver_stdout else ())
            + (("webhook",) if webhook_url else ()),
            jsonl_path=deliver_jsonl,
            webhook_url=webhook_url,
        )
        if json_output:
            typer.echo(json.dumps(result, sort_keys=True))
            return
        console.print(
            "[bold]Monitoring worker stopped[/bold] "
            f"reason={result['stopped_reason']} ticks={result['tick_count']} "
            f"runs={result['run_count']} changes={result['change_count']} "
            f"alerts={result['alert_count']} unrouted={result['delivery_unrouted_count']} "
            f"errors={result['error_count']}"
        )
