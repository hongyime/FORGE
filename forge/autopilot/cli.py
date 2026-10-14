"""Typer CLI wiring for ``forge autopilot``."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from forge.autopilot.defaults import AutopilotDefaults
from forge.autopilot.loop import ForgeAutopilot
from forge.utils.kill_chain_options import normalize_kill_chain_parallel_fanout


console = Console(stderr=True)


def register_autopilot_commands(app: typer.Typer) -> None:
    """Register the ``forge autopilot`` command group.

    Default behavior with no flags:

    - Default mode is **apply** (live). The autopilot always has a
      baked-in ROE handle via :class:`AutopilotDefaults` so operators
      who ``git clone && setup && autopilot`` get a working loop
      without any flags.
    - Pass ``--dry-run`` to rehearse without writes.
    - ``FORGE_SAFE_MODE=1`` still forces dry-run as an operator safety
      override.
    """

    @app.callback(invoke_without_command=True)
    def _default(
        ctx: typer.Context,
        dry_run: bool = typer.Option(
            False,
            "--dry-run",
            help="Force dry-run mode. No writes, no live outbound work.",
        ),
        apply: bool = typer.Option(
            True,
            "--apply/--no-apply",
            help=(
                "Default. Runs the full live loop. Pass --no-apply or "
                "--dry-run to rehearse without writes."
            ),
        ),
        once: bool = typer.Option(
            True,
            "--once/--loop",
            help=(
                "Run a single pass (default) or loop indefinitely with "
                "the configured cooldown between iterations."
            ),
        ),
        iterations: Optional[int] = typer.Option(
            None,
            "--iterations",
            "-n",
            help="Explicit iteration count. Implies --loop when >1.",
        ),
        roe_id: Optional[str] = typer.Option(
            None,
            "--roe-id",
            envvar="FORGE_ROE_ID",
            help=(
                "Rules-of-engagement reference recorded with live runs. "
                "Defaults to the AutopilotDefaults value (ROE-1) when "
                "unset so the autopilot always has a non-empty handle."
            ),
        ),
        scope_manifest: Optional[Path] = typer.Option(
            None,
            "--scope-manifest",
            envvar="FORGE_SCOPE_MANIFEST",
            help="Path to a scope manifest JSON. Autodetected if omitted.",
        ),
        data_dir: Optional[Path] = typer.Option(
            None,
            "--data-dir",
            envvar="FORGE_DATA_DIR",
            help="Forge data directory. Defaults to ForgeConfig.",
        ),
        imports_dir: Optional[Path] = typer.Option(
            None,
            "--imports-dir",
            help="Imports directory holding feed/queue files.",
        ),
        reports_dir: Optional[Path] = typer.Option(
            None,
            "--reports-dir",
            help="Reports directory for the dashboard and sidecar JSON.",
        ),
        feed_file: Optional[Path] = typer.Option(
            None,
            "--feed-file",
            help="Target feed path. Default: imports/target-feed.json.",
        ),
        only_phase: Optional[str] = typer.Option(
            None,
            "--only-phase",
            help="Run one phase once. Defaults to dry-run; --apply opts into execution.",
        ),
        fixture_file: Optional[Path] = typer.Option(
            None,
            "--fixture-file",
            help="Phase-tagged JSON fixture used by --only-phase.",
        ),
        allow_live: bool = typer.Option(
            False,
            "--allow-live",
            help="Allow live feed/scan connectors with --only-phase and explicit --apply.",
        ),
        max_iter: Optional[int] = typer.Option(
            None,
            "--max-iter",
            help="Kill-chain max iterations per started target.",
        ),
        max_runtime_minutes: Optional[int] = typer.Option(
            None,
            "--max-runtime-minutes",
            help="Soft kill-chain runtime budget per target (default: 120 minutes).",
        ),
        parallel_fanout: Optional[int] = typer.Option(
            None,
            "--parallel-fanout",
            help="Kill-chain workers per target (default: 6, bounded to 1-8).",
        ),
        start_limit: Optional[int] = typer.Option(
            None,
            "--start-limit",
            help="Maximum new kill-chain runs launched by one cycle.",
        ),
        import_limit: Optional[int] = typer.Option(
            None,
            "--import-limit",
            "--limit",
            help=(
                "Maximum feed items imported per cycle (default: 25000; "
                "--limit is an alias)."
            ),
        ),
        resume_limit: Optional[int] = typer.Option(
            None,
            "--resume-limit",
            help="Maximum resume candidates processed per cycle.",
        ),
        max_parallel: Optional[int] = typer.Option(
            None,
            "--max-parallel",
            help="Resume parallelism cap.",
        ),
        monitor_limit: Optional[int] = typer.Option(
            None,
            "--monitor-limit",
            help="Maximum due monitoring policies run per cycle.",
        ),
        cooldown_minutes: Optional[int] = typer.Option(
            None,
            "--cooldown-minutes",
            help="Sleep interval between loop iterations.",
        ),
        min_start_source_count: Optional[int] = typer.Option(
            None,
            "--min-start-source-count",
            help=(
                "Minimum independent source count required before --start "
                "may launch a live kill-chain run."
            ),
        ),
        feed_source: list[str] = typer.Option(
            [],
            "--feed-source",
            help=(
                "Repeatable feed source selector: all, db, reports, cti, "
                "connectors, supabase. Default: all."
            ),
        ),
        skip_feed_build: bool = typer.Option(
            False,
            "--skip-feed-build",
            help="Skip the auto-seed phase entirely.",
        ),
        skip_feed_fetch: bool = typer.Option(
            False,
            "--skip-feed-fetch",
            help="Skip the free-feed fetch phase entirely.",
        ),
        skip_connected_services_scan: bool = typer.Option(
            False,
            "--skip-connected-services-scan",
            help="Skip the connected-services scan phase.",
        ),
        skip_auto_scope: bool = typer.Option(
            False,
            "--skip-auto-scope",
            help="Skip the auto-scope expansion phase.",
        ),
        feed_build: bool = typer.Option(
            False,
            "--feed-build",
            help=(
                "Backward-compat alias — the autopilot already runs "
                "feed-build by default. Passing this flag is a no-op."
            ),
        ),
        skip_import: bool = typer.Option(
            False, "--skip-import", help="Skip the auto-engage phase.",
        ),
        skip_resume: bool = typer.Option(
            False, "--skip-resume", help="Skip the auto-resume phase.",
        ),
        skip_monitoring: bool = typer.Option(
            False, "--skip-monitoring", help="Skip the auto-monitor phase.",
        ),
        skip_dashboard: bool = typer.Option(
            False, "--skip-dashboard", help="Skip the auto-dashboard phase.",
        ),
        continue_on_failure: bool = typer.Option(
            False,
            "--continue-on-failure",
            help=(
                "Backward-compat flag — the autopilot already continues "
                "past phase failures. Passing this is a no-op."
            ),
        ),
        break_stale_lock: bool = typer.Option(
            False,
            "--break-stale-lock",
            help=(
                "Backward-compat flag — the autopilot already uses "
                "break_stale_lock=True in the resume phase."
            ),
        ),
        describe: bool = typer.Option(
            False,
            "--describe",
            help="Print the resolved autopilot config and exit without running.",
        ),
        json_output: bool = typer.Option(
            False, "--json", help="Print machine-readable JSON.",
        ),
    ) -> None:
        """Run the FORGE autopilot — self-running automation loop.

        Default mode is **apply** (live). ``AutopilotDefaults`` provides
        a baked-in ROE handle so operators who ``git clone && setup``
        get a working loop immediately with ``forge autopilot``.

        Explicit flags:

        - ``--dry-run`` → rehearse without writes (wins over ``--apply``).
        - ``--no-apply`` → equivalent rehearsal shorthand.
        - ``FORGE_SAFE_MODE=1`` → forces dry-run as a safety override.
        - ``--loop`` or ``--iterations N`` → continuous operation.
        - ``--only-phase NAME`` → run one phase once, in dry-run unless
          ``--apply`` is explicitly supplied.
        - ``--allow-live`` → opt into live feed/scan connectors with explicit
          ``--apply``; it never enables engagement starts by itself.
        """
        if ctx.invoked_subcommand is not None:
            return

        if only_phase is not None and only_phase not in ForgeAutopilot._PHASE_DISPATCH:
            valid = ", ".join(ForgeAutopilot._PHASE_DISPATCH)
            raise typer.BadParameter(
                f"invalid phase '{only_phase}'. Valid phases: {valid}",
                param_hint="--only-phase",
            )
        if only_phase is None and fixture_file is not None:
            raise typer.BadParameter("--fixture-file requires --only-phase")
        if only_phase is None and allow_live:
            raise typer.BadParameter("--allow-live requires --only-phase")
        if only_phase is not None and (not once or (iterations is not None and iterations > 1)):
            raise typer.BadParameter(
                "--only-phase runs once; remove --loop or use --iterations 1"
            )
        apply_was_explicit = (
            ctx.get_parameter_source("apply").name == "COMMANDLINE"
        )
        if only_phase is not None and allow_live and (not apply_was_explicit or not apply):
            raise typer.BadParameter("--allow-live requires an explicit --apply")

        # ``--dry-run`` always wins. ``--apply`` is the default so the
        # combination is not treated as an operator conflict; dry-run
        # simply overrides the default live run.

        _ = feed_build  # noqa: SLF001 — backward-compat alias; feed-build always runs
        _ = continue_on_failure  # noqa: SLF001 — autopilot already continues on failure
        _ = break_stale_lock  # noqa: SLF001 — autopilot already uses break_stale_lock

        defaults = _build_defaults(
            max_iter=max_iter,
            max_runtime_minutes=max_runtime_minutes,
            parallel_fanout=parallel_fanout,
            start_limit=start_limit,
            import_limit=import_limit,
            resume_limit=resume_limit,
            max_parallel=max_parallel,
            monitor_limit=monitor_limit,
            cooldown_minutes=cooldown_minutes,
            min_start_source_count=min_start_source_count,
            feed_sources=feed_source,
        )

        skip_phases: set[str] = set()
        if skip_feed_fetch:
            skip_phases.add("feed_fetch")
        if skip_connected_services_scan:
            skip_phases.add("connected_services_scan")
        if skip_feed_build:
            skip_phases.add("feed_build")
        if skip_auto_scope:
            skip_phases.add("auto_scope")
        if skip_import:
            skip_phases.add("import_targets")
        if skip_resume:
            skip_phases.add("resume_candidates")
        if skip_monitoring:
            skip_phases.add("monitoring")
        if skip_dashboard:
            skip_phases.add("dashboard")

        autopilot = ForgeAutopilot(
            data_dir=data_dir,
            imports_dir=imports_dir,
            reports_dir=reports_dir,
            feed_file=feed_file,
            roe_id=roe_id,
            scope_manifest=scope_manifest,
            defaults=defaults,
            skip_phases=skip_phases,
        )

        if describe:
            snapshot = autopilot.describe()
            if only_phase is not None:
                snapshot["selected_phase"] = only_phase
            if only_phase == "dashboard" and fixture_file is not None:
                snapshot["fixture_note"] = "ignored:dashboard_has_no_fixture_inputs"
            if json_output:
                typer.echo(json.dumps(snapshot, indent=2, sort_keys=True))
            else:
                _print_description(snapshot)
            return

        resolved_dry_run = _resolve_dry_run_arg(
            apply=(apply if only_phase is None or apply_was_explicit else False),
            dry_run=dry_run,
            autopilot=autopilot,
        )

        if only_phase is not None:
            try:
                payload = autopilot.run_single_phase(
                    only_phase,
                    dry_run=resolved_dry_run,
                    fixture_file=fixture_file,
                    allow_live=allow_live,
                )
            except ValueError as exc:
                raise typer.BadParameter(str(exc)) from exc
            if json_output:
                typer.echo(json.dumps(payload, indent=2, sort_keys=True, default=str))
                return
            _print_summary(payload)
            return

        resolved_iterations = _resolve_iterations(once=once, iterations=iterations)
        payload = autopilot.run(
            dry_run=resolved_dry_run,
            iterations=resolved_iterations,
        )

        if json_output:
            typer.echo(json.dumps(payload, indent=2, sort_keys=True, default=str))
            return

        _print_summary(payload)


def _build_defaults(
    *,
    max_iter: Optional[int],
    max_runtime_minutes: Optional[int],
    parallel_fanout: Optional[int],
    start_limit: Optional[int],
    import_limit: Optional[int],
    resume_limit: Optional[int],
    max_parallel: Optional[int],
    monitor_limit: Optional[int],
    cooldown_minutes: Optional[int],
    min_start_source_count: Optional[int] = None,
    feed_sources: Optional[list[str]] = None,
) -> AutopilotDefaults:
    base = AutopilotDefaults()
    if feed_sources:
        sources: tuple[str, ...] = tuple(dict.fromkeys(feed_sources))
    else:
        sources = base.feed_sources
    return AutopilotDefaults(
        import_limit=import_limit if import_limit is not None else base.import_limit,
        start_limit=start_limit if start_limit is not None else base.start_limit,
        min_start_source_count=(
            min_start_source_count
            if min_start_source_count is not None
            else base.min_start_source_count
        ),
        max_iter=max_iter if max_iter is not None else base.max_iter,
        max_runtime_minutes=(
            max_runtime_minutes
            if max_runtime_minutes is not None
            else base.max_runtime_minutes
        ),
        parallel_fanout=(
            normalize_kill_chain_parallel_fanout(
                parallel_fanout
                if parallel_fanout is not None
                else base.parallel_fanout
            )
        ),
        resume_limit=resume_limit if resume_limit is not None else base.resume_limit,
        max_parallel=max_parallel if max_parallel is not None else base.max_parallel,
        monitor_limit=monitor_limit if monitor_limit is not None else base.monitor_limit,
        cooldown_minutes=(
            cooldown_minutes
            if cooldown_minutes is not None
            else base.cooldown_minutes
        ),
        feed_sources=sources,
        min_free_memory_mb=base.min_free_memory_mb,
        min_free_disk_gb=base.min_free_disk_gb,
    )


def _resolve_dry_run_arg(
    *,
    apply: bool,
    dry_run: bool,
    autopilot: ForgeAutopilot,
) -> Optional[bool]:
    """Translate CLI flags into the ``dry_run`` kwarg passed to the loop.

    ``None`` means "let the autopilot decide" (apply by default).
    ``True`` forces dry-run; ``False`` forces apply.
    """
    if dry_run:
        return True
    if apply:
        if autopilot.safe_mode:
            console.print(
                "[yellow]FORGE_SAFE_MODE=1 is set;[/yellow] "
                "autopilot stays in dry-run mode."
            )
            return True
        if not autopilot.has_roe:
            raise typer.BadParameter(
                "--apply requires FORGE_ROE_ID or --roe-id to be set"
            )
        return False
    # ``--no-apply`` without ``--dry-run`` still rehearses.
    return True


def _resolve_iterations(*, once: bool, iterations: Optional[int]) -> int:
    if iterations is not None and iterations > 0:
        return int(iterations)
    if once:
        return 1
    # --loop with no explicit count: run a large bounded loop so the
    # process still terminates eventually. Operators who need an
    # unbounded daemon should wrap this in systemd / Task Scheduler.
    return 24


def _print_description(snapshot: dict[str, object]) -> None:
    console.print("[bold]FORGE Autopilot[/bold]")
    console.print(f"data_dir={snapshot['data_dir']}")
    console.print(f"imports_dir={snapshot['imports_dir']}")
    console.print(f"reports_dir={snapshot['reports_dir']}")
    console.print(f"feed_file={snapshot['feed_file']}")
    console.print(f"roe_id_present={snapshot['roe_id_present']}")
    console.print(f"scope_manifest={snapshot['scope_manifest']}")
    console.print(f"safe_mode={snapshot['safe_mode']}")
    console.print(f"default_execution_mode={snapshot['default_execution_mode']}")
    if snapshot.get("selected_phase"):
        console.print(f"selected_phase={snapshot['selected_phase']}")
    if snapshot.get("fixture_note"):
        console.print(f"fixture_note={snapshot['fixture_note']}")


#: Mapping from internal autopilot phase ids to user-friendly labels
#: used in ``forge autopilot --describe`` output and summary printing.
_PHASE_DISPLAY_LABELS = {
    "feed_fetch": "Threat intel refresh",
    "connected_services_scan": "Service scan",
    "feed_build": "Target feed",
    "auto_scope": "Scope expansion",
    "import_targets": "Target import",
    "resume_candidates": "Resume paused runs",
    "monitoring": "Monitoring policies",
    "dashboard": "Dashboard refresh",
}


def _phase_display_name(name: str) -> str:
    return _PHASE_DISPLAY_LABELS.get(name, name)


def _print_summary(payload: dict[str, object]) -> None:
    status = payload.get("status", "?")
    mode = payload.get("mode", "?")
    color = {
        "ok": "green",
        "blocked": "yellow",
        "skipped": "yellow",
        "error": "red",
    }.get(str(status), "white")
    console.print(
        f"[bold]Autopilot[/bold] mode=[{color}]{mode}[/{color}] "
        f"status=[{color}]{status}[/{color}] "
        f"iterations={payload.get('iterations_run', 1)}"
    )
    phases = payload.get("phases") or []
    if isinstance(phases, list):
        for phase in phases:
            if not isinstance(phase, dict):
                continue
            phase_status = phase.get("status", "?")
            phase_color = {
                "ok": "green",
                "blocked": "yellow",
                "skipped": "yellow",
                "error": "red",
            }.get(str(phase_status), "white")
            name = phase.get("name", "?")
            label = _phase_display_name(str(name))
            detail = phase.get("detail", "")
            console.print(
                f"- {label}: [{phase_color}]{phase_status}[/{phase_color}] {detail}"
            )


__all__ = ["register_autopilot_commands"]
