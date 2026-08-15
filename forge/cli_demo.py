"""Demo/proof-pack CLI commands."""

from __future__ import annotations

from pathlib import Path

import typer

from forge.cli import console, demo_app
from forge.demo import DEFAULT_DEMO_ENGAGEMENT_ID, generate_demo_proof_pack


@demo_app.command("proof-pack")
def demo_proof_pack(
    engagement: int = typer.Option(
        DEFAULT_DEMO_ENGAGEMENT_ID,
        "--engagement",
        "-e",
        help="Stable demo engagement id to create.",
    ),
    reports_dir: str = typer.Option(
        "reports",
        "--reports-dir",
        "-o",
        help="Directory for generated report, graph, dashboard, and manifest artifacts.",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        help="Regenerate the demo DB and demo artifacts for this engagement id.",
    ),
) -> None:
    """Create a repeatable local/no-key demo engagement proof pack."""

    result = generate_demo_proof_pack(
        engagement_id=int(engagement),
        reports_dir=Path(reports_dir),
        force=bool(force),
    )
    console.print("[bold green]Demo proof pack generated[/bold green]")
    console.print(f"  engagement: {result.engagement_id}")
    console.print(f"  db: {result.db_path}")
    console.print(f"  report: {result.report_path}")
    console.print(f"  dashboard: {result.dashboard_path}")
    console.print(f"  audit bundle: {result.audit_bundle_path}")
    console.print(f"  manifest: {result.manifest_path}")
    console.print(
        "  graph artifacts: "
        + ", ".join(path.name for path in result.graph_artifacts if path.exists())
    )
    console.print(
        "  standards artifacts: "
        + ", ".join(path.name for path in result.standards_artifacts if path.exists())
    )
