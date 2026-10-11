"""Attack-path CLI commands (backlog Explore #16).

Exposes two read-only operator commands under the ``forge graph`` sub-app:

* ``forge graph attack-paths --engagement N --source SID --target SID --json``
* ``forge graph tier-zero --engagement N --top N --json``

Both commands open the engagement DB read-only, read the already-sanitised
attack graph, and emit a JSON payload compatible with the dashboard and
automation surfaces. Neither command touches the network, mutates the DB,
or persists new artifacts.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

import typer

__all__ = ["register_attack_path_commands"]


def _load_graph_manager(engagement: str) -> Any:
    """Open the engagement DB and build an AttackPathManager."""
    from forge.config import ForgeConfig  # noqa: PLC0415
    from forge.graph.attack_paths import AttackPathManager  # noqa: PLC0415

    cfg = ForgeConfig.load()
    db_path = Path(cfg.engagement_db_path(engagement))
    return AttackPathManager(db_path=db_path, engagement_id=int(engagement))


def register_attack_path_commands(graph_app: typer.Typer) -> None:
    """Register attack-path commands on an existing ``graph`` Typer app."""
    from forge.cli import console  # noqa: PLC0415

    @graph_app.command("attack-paths")
    def graph_attack_paths(
        engagement: str = typer.Option(..., "--engagement", "-e"),
        source: Optional[str] = typer.Option(  # noqa: UP007 -- typer needs eval'd annotation
            None,
            "--source",
            help=(
                "Source node id (e.g. 'EXT::engagement-1001' or "
                "'HOST::10.0.0.5'). Defaults to every EXTERNAL entry point."
            ),
        ),
        target: Optional[str] = typer.Option(  # noqa: UP007
            None,
            "--target",
            help=(
                "Target node id (e.g. 'IMP::engagement-1001'). Defaults to "
                "every tier-zero node discovered in the engagement graph."
            ),
        ),
        max_depth: int = typer.Option(
            10,
            "--max-depth",
            help="Maximum path length to enumerate (default 10, max 50).",
        ),
        top: int = typer.Option(
            25,
            "--top",
            help="Maximum ranked paths to print (default 25, max 100).",
        ),
        json_output: bool = typer.Option(
            False,
            "--json",
            help="Print machine-readable JSON output.",
        ),
    ) -> None:
        """Discover and rank attack paths in the engagement graph (read-only)."""
        try:
            manager = _load_graph_manager(engagement)
        except Exception as exc:  # noqa: BLE001
            raise typer.BadParameter(str(exc)) from exc

        paths = manager.compute_paths(
            source=source,
            target=target,
            max_depth=max_depth,
        )
        ranked = manager.rank_paths(paths)
        limit = max(1, min(100, int(top or 25)))
        selected = ranked[:limit]

        payload: dict[str, Any] = {
            "schema": "forge.graph.attack_paths.v1",
            "execution_policy": "read_only",
            "engagement_id": int(engagement),
            "source": source,
            "target": target,
            "max_depth": int(max_depth),
            "total_count": len(ranked),
            "selected_count": len(selected),
            "omitted_count": max(0, len(ranked) - len(selected)),
            "paths": [path.to_dict() for path in selected],
        }
        if json_output:
            typer.echo(json.dumps(payload, sort_keys=True))
            return

        console.print(
            "[bold]Attack paths[/bold] "
            f"engagement={engagement} paths={payload['total_count']} "
            f"shown={payload['selected_count']}"
        )
        for path in selected[:10]:
            arrow = " -> ".join(path.nodes)
            console.print(
                f"- weight={path.weight:.1f} length={path.length} "
                f"tier_zero={path.reaches_tier_zero} path={arrow}"
            )

    @graph_app.command("tier-zero")
    def graph_tier_zero(
        engagement: str = typer.Option(..., "--engagement", "-e"),
        top: int = typer.Option(
            10,
            "--top",
            help="Maximum tier-zero rows to print (default 10, max 100).",
        ),
        json_output: bool = typer.Option(
            False,
            "--json",
            help="Print machine-readable JSON output.",
        ),
    ) -> None:
        """Report tier-zero assets and the engagement exposure score."""
        try:
            manager = _load_graph_manager(engagement)
        except Exception as exc:  # noqa: BLE001
            raise typer.BadParameter(str(exc)) from exc

        tier_zero = manager.get_tier_zero_assets()
        limit = max(1, min(100, int(top or 10)))
        selected = tier_zero[:limit]
        exposure = manager.get_exposure_score()
        choke_points = [choke.to_dict() for choke in manager.get_choke_points(top_n=limit)]

        payload: dict[str, Any] = {
            "schema": "forge.graph.tier_zero.v1",
            "execution_policy": "read_only",
            "engagement_id": int(engagement),
            "total_count": len(tier_zero),
            "selected_count": len(selected),
            "omitted_count": max(0, len(tier_zero) - len(selected)),
            "tier_zero": selected,
            "choke_points": choke_points,
            "exposure_score": exposure,
        }
        if json_output:
            typer.echo(json.dumps(payload, sort_keys=True))
            return

        console.print(
            f"[bold]Tier-zero exposure[/bold] score={exposure['score']}/100 "
            f"total={payload['total_count']} shown={payload['selected_count']} "
            f"choke_points={len(choke_points)}"
        )
        for entry in selected:
            console.print(
                f"- score={entry['score']:>5}  "
                f"{entry['label']} ({entry['node_type']})  "
                f"reasons={','.join(entry['reasons'][:3])}"
            )
