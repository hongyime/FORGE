"""Explore item CLI commands — #12 Neo4j Cypher, #13 Nemesis, #16 Tier-zero.

These commands are wired onto existing sub-apps (graph_app, artifacts_app)
via the cli_legacy_decorators import chain.  They are all read-only and
never execute outbound network requests.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer

from forge.cli import artifacts_app, console, graph_app


# ---------------------------------------------------------------------------
# Explore #12 — Neo4j / OpenGraph Cypher export
# ---------------------------------------------------------------------------

@graph_app.command("cypher-export")
def graph_cypher_export(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    graph_json: str = typer.Option(
        ...,
        "--graph-json",
        help="Path to a JSON graph payload from 'forge graph build --format json'.",
    ),
    output: str = typer.Option(
        "forge_graph.cypher",
        "--output",
        "-o",
        help="Output .cypher file path.",
    ),
) -> None:
    """Export the FORGE attack graph to Neo4j Cypher CREATE statements (Explore #12).

    Reads the JSON payload produced by ``forge graph build --format json``
    and converts it to Cypher MERGE statements importable with
    ``cypher-shell --file forge_graph.cypher``.

    All sensitive metadata is stripped before export.
    """
    from forge.graph.neo4j_export import graph_to_cypher  # noqa: PLC0415

    src = Path(graph_json.strip())
    if not src.exists():
        console.print(f"[red]Graph JSON not found:[/red] {src}")
        raise typer.Exit(code=1)

    try:
        payload = json.loads(src.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        console.print(f"[red]Cannot read graph JSON:[/red] {exc}")
        raise typer.Exit(code=1)

    statements = graph_to_cypher(payload)
    out = Path(output.strip())
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(statements), encoding="utf-8")

    console.print(f"[green]Cypher export written:[/green] {out}")
    console.print(f"  {len(statements)} statements")
    console.print(
        "  Import: [dim]cypher-shell -u neo4j -p <pass> --file " + str(out) + "[/dim]"
    )


# ---------------------------------------------------------------------------
# Explore #16 — Attack Path Management / Tier-zero scoring
# ---------------------------------------------------------------------------

@graph_app.command("tier-zero")
def graph_tier_zero(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    top_n: int = typer.Option(10, "--top", help="Max tier-zero nodes to show."),
    output_json: bool = typer.Option(False, "--json"),
) -> None:
    """Identify tier-zero assets and attack-path prioritisation (Explore #16).

    Reads the asset graph from the engagement DB, scores every node by
    inbound attack-path count, and reports the top-N tier-zero candidates
    with remediation hints.

    Use ``forge graph sync-assets -e <N>`` first to populate the graph.
    """
    from forge.config import ForgeConfig  # noqa: PLC0415
    from forge.graph.tier_zero import compute_tier_zero  # noqa: PLC0415

    cfg = ForgeConfig.load()
    db_path = cfg.engagement_db_path(engagement)
    engagement_id = int(engagement)

    report = compute_tier_zero(engagement_id=engagement_id, db_path=db_path, top_n=top_n)

    if output_json:
        typer.echo(json.dumps(report.to_dict(), indent=2))
        return

    console.print(f"\n[bold blue]Tier-Zero Exposure[/bold blue]  engagement={engagement}")
    console.print(f"  {report.summary}\n")

    if not report.tier_zero_nodes:
        console.print(
            "  [yellow]No tier-zero nodes found.[/yellow] "
            "Run: forge graph sync-assets -e <N>"
        )
        return

    console.print(f"  [bold]Top {min(top_n, len(report.tier_zero_nodes))} tier-zero nodes:[/bold]")
    for i, node in enumerate(report.tier_zero_nodes, 1):
        console.print(
            f"  {i:>2}. [red]{node['label']:<40}[/red]  "
            f"[dim]{node['node_type']}  paths={node['inbound_paths']}[/dim]"
        )
        console.print(f"       [dim]{node['remediation_hint'][:80]}...[/dim]")
    console.print()


# ---------------------------------------------------------------------------
# Explore #13 — Nemesis-compatible artifact handoff
# ---------------------------------------------------------------------------

@artifacts_app.command("nemesis-export")
def artifacts_nemesis_export(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    output: str = typer.Option(
        "nemesis_bundle.json",
        "--output",
        "-o",
        help="Output JSON bundle path.",
    ),
    limit: int = typer.Option(500, "--limit", help="Max rows per section."),
) -> None:
    """Export sanitized engagement evidence in Nemesis-compatible JSON (Explore #13).

    Nemesis is a post-exploitation evidence management framework. This command
    exports findings, artifacts, and credential metadata from the engagement DB
    into a JSON bundle the operator can ingest into Nemesis.

    Secret material is redacted; scope-manifest paths are excluded.

    Usage::

        forge artifacts nemesis-export -e 1001 --output nemesis_bundle.json
        nemesis-cli ingest --file nemesis_bundle.json
    """
    from forge.config import ForgeConfig  # noqa: PLC0415
    from forge.graph.nemesis_export import build_nemesis_bundle  # noqa: PLC0415

    cfg = ForgeConfig.load()
    db_path = cfg.engagement_db_path(engagement)
    engagement_id = int(engagement)

    bundle = build_nemesis_bundle(
        engagement_id=engagement_id,
        db_path=db_path,
        limit=limit,
    )

    out = Path(output.strip())
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(bundle, indent=2), encoding="utf-8")

    summary = bundle.get("summary", {})
    console.print(f"[green]Nemesis bundle written:[/green] {out}")
    console.print(
        f"  findings={summary.get('findings', 0)}  "
        f"files={summary.get('files', 0)}  "
        f"credentials={summary.get('credentials', 0)}  "
        f"paths={summary.get('paths', 0)}"
    )
    if "error" in bundle:
        console.print(f"  [yellow]Warning:[/yellow] {bundle['error']}")
    console.print("  Import: [dim]nemesis-cli ingest --file " + str(out) + "[/dim]")
