from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from forge.automation_cycle import automation_cycle, automation_status
from forge.automation_policy import (
    automation_defaults_review,
    automation_run_plan,
    command_surface_review,
    forge_automation_policy,
)
from forge.automation_self_heal import (
    DEFAULT_AUTOSTART_CONFIG,
    DEFAULT_AUTOSTART_CONFIG_PATH,
    automation_self_heal_plan,
    run_guarded_autostart,
)
from forge.automation_target_feed import build_target_feed, write_target_feed

console = Console(stderr=True)


def register_automation_commands(app: typer.Typer) -> None:
    @app.command("policy")
    def policy(
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        payload = forge_automation_policy()
        if json_output:
            typer.echo(json.dumps(payload, sort_keys=True))
            return
        console.print("[bold]Automation policy[/bold]")
        console.print(f"wildcard_execution={payload['validation']['allow_wildcard_execution']}")
        console.print(f"broad_scope={payload['validation']['broad_scope_allowed']}")
        console.print(f"status={payload['validation']['status']}")

    @app.command("run")
    def run(
        apply: bool = typer.Option(
            False,
            "--apply",
            help="Record apply intent in the plan. This planner does not launch live actions.",
        ),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        payload = automation_run_plan(apply=apply)
        if json_output:
            typer.echo(json.dumps(payload, sort_keys=True))
            return
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Step")
        table.add_column("Enabled")
        table.add_column("Action")
        for step in payload["steps"]:
            table.add_row(str(step["id"]), str(step["enabled"]), str(step["action"]))
        console.print(table)

    @app.command("command-review")
    def command_review(
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        payload = command_surface_review()
        if json_output:
            typer.echo(json.dumps(payload, sort_keys=True))
            return
        console.print(
            "[bold]Command surface[/bold] "
            f"groups={payload['group_count']} commands={payload['command_count']}"
        )
        for item in payload["recommendations"]:
            console.print(f"- {item['priority']}: {item['recommendation']}")

    @app.command("defaults")
    def defaults(
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        payload = automation_defaults_review(
            autostart_defaults=DEFAULT_AUTOSTART_CONFIG,
            autostart_config_path=str(DEFAULT_AUTOSTART_CONFIG_PATH),
        )
        if json_output:
            typer.echo(json.dumps(payload, sort_keys=True))
            return
        console.print("[bold]Automation defaults[/bold]")
        console.print(f"autostart_config={payload['autostart']['config_path']}")
        for item in payload["tunables"]:
            console.print(f"- {item['id']}: default={item.get('default')}")

    @app.command("status")
    def status(
        json_output: bool = typer.Option(False, "--json"),
        engagement: int | None = typer.Option(
            None,
            "--engagement",
            "-e",
            help="Engagement used to decide which queued local imports are ready.",
        ),
        output: Path = typer.Option(
            Path("imports") / "target-feed.json",
            "--output",
            help="Feed output path to summarize.",
        ),
        imports_dir: Path = typer.Option(
            Path("imports"),
            "--imports-dir",
            help="Imports dir holding local queues and artifacts.",
        ),
        data_dir: Path | None = typer.Option(
            None,
            "--data-dir",
            help="Forge data dir holding engagements/*.db (default ForgeConfig).",
        ),
    ) -> None:
        payload = automation_status(
            imports_dir=imports_dir,
            output=output,
            data_dir=data_dir,
            engagement=engagement,
        )
        if json_output:
            typer.echo(json.dumps(payload, sort_keys=True))
            return
        console.print(
            "[bold]Automation status[/bold] "
            f"feed_exists={payload['feed']['exists']} "
            f"queue_ready={payload['queues']['ready']} "
            f"queue_blocked={payload['queues']['blocked']}"
        )
        for action in payload["next_actions"]:
            console.print(f"- {action}")

    @app.command("cycle")
    def cycle(
        apply: bool = typer.Option(
            False,
            "--apply",
            help="Write feed and consume ready local queues. Default dry-run writes nothing.",
        ),
        live: bool = typer.Option(
            False,
            "--live",
            help="Also invoke guarded-autostart; live work still requires ROE/resource gates.",
        ),
        engagement: int | None = typer.Option(
            None,
            "--engagement",
            "-e",
            help="Engagement used for queued local imports.",
        ),
        output: Path = typer.Option(
            Path("imports") / "target-feed.json",
            "--output",
            help="Feed output path.",
        ),
        source: list[str] = typer.Option(
            ["all"],
            "--source",
            help="Repeatable source selector: all, db, reports, cti, connectors, supabase.",
        ),
        supabase_config: Path | None = typer.Option(
            Path("imports") / "supabase-projects.local.json",
            "--supabase-config",
            help="Local untracked Supabase read-only project config.",
        ),
        data_dir: Path | None = typer.Option(
            None,
            "--data-dir",
            help="Forge data dir holding engagements/*.db (default ForgeConfig).",
        ),
        reports_dir: Path | None = typer.Option(
            None,
            "--reports-dir",
            help="Reports artifact dir (default ./reports).",
        ),
        imports_dir: Path = typer.Option(
            Path("imports"),
            "--imports-dir",
            help="Imports dir holding queues and artifacts.",
        ),
        limit: int | None = typer.Option(
            None,
            "--limit",
            help="Cap the number of feed items emitted.",
        ),
        autostart_config: Path = typer.Option(
            DEFAULT_AUTOSTART_CONFIG_PATH,
            "--autostart-config",
            help="Ignored local autostart config path for --live.",
        ),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        payload = automation_cycle(
            apply=apply,
            live=live,
            engagement=engagement,
            output=output,
            source=list(source),
            data_dir=data_dir,
            reports_dir=reports_dir,
            imports_dir=imports_dir,
            limit=limit,
            supabase_config=supabase_config,
            autostart_config=autostart_config,
        )
        if json_output:
            typer.echo(json.dumps(payload, sort_keys=True))
            return
        console.print(
            "[bold]Automation cycle[/bold] "
            f"policy={payload['execution_policy']} "
            f"feed_written={payload['feed_written']} "
            f"queue_runs={len(payload['queue_runs'])}"
        )

    @app.command("feed-build")
    def feed_build(
        output: Path = typer.Option(
            Path("imports") / "target-feed.json",
            "--output",
            help="Feed output path (default imports/target-feed.json).",
        ),
        apply: bool = typer.Option(
            False,
            "--apply",
            help="Write the merged feed. Default is a dry-run that writes nothing.",
        ),
        json_output: bool = typer.Option(False, "--json"),
        source: list[str] = typer.Option(
            ["all"],
            "--source",
            help="Repeatable source selector: all, db, reports, cti, connectors, supabase.",
        ),
        supabase_config: Path | None = typer.Option(
            Path("imports") / "supabase-projects.local.json",
            "--supabase-config",
            help="Local untracked Supabase read-only project config.",
        ),
        data_dir: Path | None = typer.Option(
            None,
            "--data-dir",
            help="Forge data dir holding engagements/*.db (default ForgeConfig).",
        ),
        reports_dir: Path | None = typer.Option(
            None,
            "--reports-dir",
            help="Reports artifact dir (default ./reports).",
        ),
        imports_dir: Path | None = typer.Option(
            None,
            "--imports-dir",
            help="Imports dir holding CTI/connector JSON payloads (default ./imports).",
        ),
        limit: int | None = typer.Option(
            None,
            "--limit",
            help="Cap the number of feed items emitted.",
        ),
    ) -> None:
        from forge.config import ForgeConfig

        cfg_data_dir = Path(data_dir) if data_dir else ForgeConfig.load().data_dir
        try:
            payload = build_target_feed(
                sources=list(source),
                data_dir=cfg_data_dir,
                reports_dir=reports_dir or Path("reports"),
                imports_dir=imports_dir or Path("imports"),
                limit=limit,
                existing_feed_path=output,
                apply=apply,
                supabase_config_path=supabase_config,
            )
        except ValueError as exc:
            console.print(f"[red]feed-build rejected:[/red] {exc}")
            raise typer.Exit(code=2) from exc
        if json_output:
            typer.echo(json.dumps(payload, sort_keys=True))
        else:
            counts = payload["counts"]
            mode = "apply" if payload["apply_requested"] else "dry-run"
            console.print(
                f"[bold]Target feed ({mode})[/bold] total={counts['total']} "
                f"duplicates={counts['omitted_duplicate']} "
                f"new_vs_existing={counts['new_vs_existing']}"
            )
            for err in payload["source_errors"]:
                console.print(f"- {err['source']}: {err['error']}")
        if apply:
            write_target_feed(payload, output)
            if not json_output:
                console.print(f"written={output}")

    @app.command("self-heal-plan")
    def self_heal_plan(
        json_output: bool = typer.Option(False, "--json"),
        probe_docker: bool = typer.Option(
            False,
            "--probe-docker",
            help="Run a read-only docker compose ps probe. Default only checks config files.",
        ),
        docker_probe_mode: str = typer.Option(
            "host-compose",
            "--docker-probe-mode",
            help="Docker probe mode: host-compose, compose-dependency, or disabled.",
        ),
        min_free_memory_mb: int = typer.Option(
            1024,
            "--min-free-memory-mb",
            help="Minimum free memory before live auto-start work is considered safe.",
        ),
        min_free_disk_gb: int = typer.Option(
            5,
            "--min-free-disk-gb",
            help="Minimum free disk before live auto-start work is considered safe.",
        ),
        max_parallel: int = typer.Option(
            2,
            "--max-parallel",
            help="Recommended autopilot resume parallelism for generated commands.",
        ),
    ) -> None:
        payload = automation_self_heal_plan(
            min_free_memory_mb=min_free_memory_mb,
            min_free_disk_gb=min_free_disk_gb,
            max_parallel=max_parallel,
            probe_docker=probe_docker,
            docker_probe_mode=docker_probe_mode,
        )
        if json_output:
            typer.echo(json.dumps(payload, sort_keys=True))
            return
        console.print(
            "[bold]Automation self-heal plan[/bold] "
            f"status={payload['status']} blockers={len(payload['blockers'])}"
        )
        for blocker in payload["blockers"]:
            console.print(f"- {blocker}")

    @app.command("guarded-autostart")
    def guarded_autostart(
        config: Path = typer.Option(
            DEFAULT_AUTOSTART_CONFIG_PATH,
            "--config",
            help="Ignored local autostart config path.",
        ),
        apply: bool = typer.Option(
            False,
            "--apply",
            help="Run guarded autopilot only when local config also has apply_enabled=true.",
        ),
        json_output: bool = typer.Option(False, "--json"),
        docker_probe_mode: str | None = typer.Option(
            None,
            "--docker-probe-mode",
            help="Override config Docker probe mode: host-compose, compose-dependency, or disabled.",
        ),
    ) -> None:
        payload = run_guarded_autostart(
            config_path=config,
            apply=apply,
            docker_probe_mode=docker_probe_mode,
        )
        if json_output:
            typer.echo(json.dumps(payload, sort_keys=True))
            return
        console.print(
            "[bold]Guarded autostart[/bold] "
            f"status={payload['status']} mode={payload['mode']} blockers={len(payload['blockers'])}"
        )
        for blocker in payload["blockers"]:
            console.print(f"- {blocker}")
