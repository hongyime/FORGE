"""Artifact enrichment status CLI commands — ``forge artifacts`` sub-app.

Provides ``forge artifacts status`` for operator-facing artifact-queue
inspection: queue-state counts, parser lineage breakdown, and failure
taxonomy — the three pillars of Track #3 (backlog #3).

Design invariants:
* Read-only. Never mutates the engagement DB.
* Secrets / raw metadata_json never surface in CLI output — only the
  sanitized fields that ``artifact_queue_routes`` already exposes.
* Works offline (no network calls, no LLM). Requires only the engagement
  SQLite DB at the configured FORGE_DATA_DIR.
"""

from __future__ import annotations

import json
import sqlite3
from collections import Counter
from pathlib import Path
from typing import Optional

import typer

from forge.cli import artifacts_app, console


@artifacts_app.command("status")
def artifacts_status(
    engagement: str = typer.Option(
        ..., "--engagement", "-e", help="Engagement ID."
    ),
    state: Optional[str] = typer.Option(
        None,
        "--state",
        help=(
            "Filter by queue state: pending, processing, complete, "
            "failed, skipped. Omit for all states."
        ),
    ),
    limit: int = typer.Option(
        200,
        "--limit",
        help="Max artifact rows to fetch for the detail tables (default 200).",
    ),
    top_failures: int = typer.Option(
        10,
        "--top-failures",
        help="Show top N failure reasons in the taxonomy table (default 10).",
    ),
    output_json: bool = typer.Option(
        False,
        "--json",
        help="Emit machine-readable JSON instead of rich text tables.",
    ),
) -> None:
    """Artifact enrichment status: queue counts, parser lineage, failure taxonomy.

    Reads directly from the engagement's ``artifact_queue`` table and
    displays an operator-facing summary in three sections:

    1. **Queue State** — pending / processing / complete / failed / skipped
       counts so the operator can see where the pipeline stands.

    2. **Parser Lineage** — rows grouped by ``artifact_type`` (parser name)
       with per-parser state breakdowns so the operator can see which parsers
       are busy, stalling, or erroring.

    3. **Failure Taxonomy** — the top-N failure reasons from ``error_msg``
       fields on failed rows, grouped to surface systemic issues quickly
       without leaking sensitive path or credential detail.

    Use ``--json`` for automation / dashboard ingestion.
    """
    from forge.config import ForgeConfig  # noqa: PLC0415
    from forge.db.direct_connect import direct_connect  # noqa: PLC0415
    from forge.webui.artifact_queue_routes import (  # noqa: PLC0415
        ArtifactQueueRouteError,
        artifact_queue_status_payload,
    )

    cfg = ForgeConfig.load()
    db_path = cfg.engagement_db_path(engagement)

    if not db_path.exists():
        if output_json:
            typer.echo(json.dumps({"error": f"Engagement DB not found: {db_path}"}))
        else:
            console.print(f"[red]Engagement DB not found:[/red] {db_path}")
        raise typer.Exit(code=1)

    engagement_id = int(engagement)

    try:
        con = direct_connect(db_path)
    except Exception as exc:  # noqa: BLE001
        if output_json:
            typer.echo(json.dumps({"error": f"Cannot open DB: {exc}"}))
        else:
            console.print(f"[red]Cannot open engagement DB:[/red] {exc}")
        raise typer.Exit(code=1)

    try:
        payload = artifact_queue_status_payload(
            con,
            engagement_id=engagement_id,
            limit=limit,
            offset=0,
            state=state,
        )
    except ArtifactQueueRouteError as exc:
        if output_json:
            typer.echo(json.dumps({"error": str(exc)}))
        else:
            console.print(f"[red]Artifact status error:[/red] {exc}")
        raise typer.Exit(code=1)
    finally:
        con.close()

    # ----------------------------------------------------------------------- #
    # Build parser lineage and failure taxonomy from the artifact rows         #
    # ----------------------------------------------------------------------- #
    artifacts = payload.get("items") or payload.get("artifacts") or []
    counts = payload.get("counts", {})

    # Parser lineage: count per (parser, state) pair
    parser_states: dict[str, Counter] = {}
    for item in artifacts:
        parser = str(item.get("parser") or "unknown")
        item_state = str(item.get("state") or "unknown")
        if parser not in parser_states:
            parser_states[parser] = Counter()
        parser_states[parser][item_state] += 1

    # Failure taxonomy: group by first 120 chars of error_msg
    failure_messages: list[str] = [
        str(item.get("error_msg") or "")[:120].strip()
        for item in artifacts
        if item.get("state") == "failed"
    ]
    failure_counter = Counter(msg for msg in failure_messages if msg)
    top_failure_taxonomy = failure_counter.most_common(top_failures)

    # ----------------------------------------------------------------------- #
    # Also query parser lineage across ALL rows (not just the fetched page)    #
    # ----------------------------------------------------------------------- #
    full_lineage: dict[str, dict[str, int]] = {}
    try:
        con2 = direct_connect(db_path)
        con2.row_factory = sqlite3.Row
        lineage_rows = con2.execute(
            "SELECT artifact_type, status, COUNT(*) AS n "
            "FROM artifact_queue WHERE engagement_id = ? "
            "GROUP BY artifact_type, status",
            (engagement_id,),
        ).fetchall()
        con2.close()
        for row in lineage_rows:
            pt = str(row["artifact_type"] or "unknown")
            st = str(row["status"] or "unknown")
            n = int(row["n"] or 0)
            if pt not in full_lineage:
                full_lineage[pt] = {}
            full_lineage[pt][st] = full_lineage[pt].get(st, 0) + n
    except Exception:  # noqa: BLE001
        pass  # Fall back to page-based lineage only

    # ----------------------------------------------------------------------- #
    # JSON output                                                              #
    # ----------------------------------------------------------------------- #
    if output_json:
        out = {
            "engagement_id": engagement_id,
            "counts": counts,
            "parser_lineage": full_lineage or {
                p: dict(c) for p, c in parser_states.items()
            },
            "failure_taxonomy": [
                {"reason": reason, "count": count}
                for reason, count in top_failure_taxonomy
            ],
            "pagination": payload.get("pagination", {}),
            "filter": payload.get("filter", {}),
        }
        typer.echo(json.dumps(out, indent=2))
        return

    # ----------------------------------------------------------------------- #
    # Rich text output                                                         #
    # ----------------------------------------------------------------------- #
    total = counts.get("total", 0)
    pending = counts.get("pending", 0)
    processing = counts.get("processing", 0)
    complete = counts.get("complete", 0)
    failed = counts.get("failed", 0)
    skipped = counts.get("skipped", 0)

    console.print(f"\n[bold blue]Artifact Enrichment Status[/bold blue]  engagement={engagement}")
    console.print(f"  [bold]Total:[/bold]       {total}")
    console.print(f"  [green]Complete:[/green]    {complete}")
    console.print(f"  [yellow]Pending:[/yellow]     {pending}")
    console.print(f"  [cyan]Processing:[/cyan]  {processing}")
    console.print(f"  [red]Failed:[/red]      {failed}")
    if skipped:
        console.print(f"  [dim]Skipped:[/dim]     {skipped}")

    # Parser lineage
    lineage_data = full_lineage or {p: dict(c) for p, c in parser_states.items()}
    if lineage_data:
        console.print("\n[bold]Parser Lineage[/bold]")
        state_order = ["parsed", "downloaded", "queued", "failed", "skipped"]
        console.print(
            f"  {'Parser':<30} {'Complete':>9} {'Processing':>11} {'Pending':>8} {'Failed':>8} {'Skipped':>8}"
        )
        console.print("  " + "-" * 80)
        for parser_name in sorted(lineage_data):
            row = lineage_data[parser_name]
            p_complete = row.get("parsed", 0)
            p_processing = row.get("downloaded", 0)
            p_pending = row.get("queued", 0)
            p_failed = row.get("failed", 0)
            p_skipped = row.get("skipped", 0)
            console.print(
                f"  {parser_name:<30} {p_complete:>9} {p_processing:>11} {p_pending:>8} {p_failed:>8} {p_skipped:>8}"
            )

    # Failure taxonomy
    if top_failure_taxonomy:
        console.print(f"\n[bold]Failure Taxonomy[/bold] (top {top_failures})")
        console.print(f"  {'Count':>7}  {'Reason'}")
        console.print("  " + "-" * 80)
        for reason, count in top_failure_taxonomy:
            reason_display = reason if reason else "(empty)"
            console.print(f"  {count:>7}  {reason_display}")
    elif failed > 0:
        console.print(
            "\n[yellow]Failure taxonomy unavailable:[/yellow] "
            "failed rows exist but error details are not in the current page. "
            "Try --limit with a higher value or filter with --state failed."
        )

    console.print()
