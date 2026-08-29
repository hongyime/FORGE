"""Attack-path graph CLI commands — Phase 4 graph sub-app.

Extracted from forge/cli.py for modularity. All @graph_app.command functions live here.
"""

from __future__ import annotations

import json
import sqlite3
import sys
from typing import Any, Optional

import typer


def __getattr__(name: str) -> Any:
    if name == "graph_build":
        def _pending_graph_build(*_args: Any, **_kwargs: Any) -> None:
            raise RuntimeError("graph_build is not initialized yet")

        return _pending_graph_build
    raise AttributeError(name)


from forge.cli import graph_app, console
from forge.cli_helpers import _direct_cli_load_scope_lists, _direct_cli_require_roe
from forge.db.direct_connect import direct_connect
from forge.db.migrations import run_migrations
from forge.db.validation import validate_canonical_schema
from forge.graph.attribution import import_asset_attribution_file
from forge.graph.assets import (
    entity_id_for_key,
    list_asset_graph,
    resolve_ownership_conflict,
    sync_engagement_asset_graph,
    upsert_asset_entity,
    upsert_ownership_claim,
)

ownership_app = typer.Typer(help="Asset ownership claim helpers", no_args_is_help=True)
graph_app.add_typer(ownership_app, name="ownership")
attribution_app = typer.Typer(help="Asset attribution import helpers", no_args_is_help=True)
graph_app.add_typer(attribution_app, name="attribution")


def _open_graph_db(engagement: str) -> sqlite3.Connection:
    from forge.config import ForgeConfig  # noqa: PLC0415

    cfg = ForgeConfig.load()
    db_path = cfg.engagement_db_path(engagement)
    con = direct_connect(db_path)
    con.row_factory = sqlite3.Row
    run_migrations(con)
    validate_canonical_schema(con)
    return con


@graph_app.command("sync-assets")
def graph_sync_assets(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Print machine-readable sync summary.",
    ),
) -> None:
    """Build or refresh the canonical Forge asset graph tables."""
    con = _open_graph_db(engagement)
    try:
        result = sync_engagement_asset_graph(con, int(engagement))
    finally:
        con.close()
    if json_output:
        console.print(json.dumps(result, sort_keys=True))
        return
    console.print(
        "[bold]Asset graph synced[/bold] "
        f"nodes={result['node_count']} edges={result['edge_count']} "
        f"ownership_claims={result['ownership_claim_count']}"
    )


@ownership_app.command("list")
def graph_ownership_list(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    entity_key: Optional[str] = typer.Option(
        None,
        "--entity-key",
        help="Optional canonical entity key to filter.",
    ),
    limit: int = typer.Option(
        100,
        "--limit",
        help="Maximum nodes and ownership claims to return.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Print machine-readable ownership summary.",
    ),
) -> None:
    """List canonical asset graph nodes and ownership claims."""
    con = _open_graph_db(engagement)
    try:
        result = list_asset_graph(con, int(engagement), entity_key=entity_key, limit=limit)
    finally:
        con.close()
    if json_output:
        console.print(json.dumps(result, sort_keys=True))
        return
    path_summary = result.get("attack_path_summary") if isinstance(result, dict) else {}
    if not isinstance(path_summary, dict):
        path_summary = {}
    console.print(
        "[bold]Asset graph[/bold] "
        f"nodes={len(result['nodes'])} edges={len(result['edges'])} "
        f"ownership_claims={len(result['ownership_claims'])} "
        f"ownership_conflicts={len(result.get('ownership_conflicts', []))} "
        f"paths={int(path_summary.get('path_count') or 0)} "
        f"choke_points={int(path_summary.get('choke_point_count') or 0)}"
    )
    for claim in result["ownership_claims"][:10]:
        console.print(
            f"- {claim['owner_display'] or claim['owner_ref']} "
            f"({claim['owner_kind']}, {claim['claim_type']}, "
            f"{claim['confidence']:.2f}, {claim['status']})"
        )


@ownership_app.command("set")
def graph_ownership_set(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    entity_key: str = typer.Option(..., "--entity-key", help="Canonical entity key."),
    owner: str = typer.Option(..., "--owner", help="Owner reference, team slug, or email."),
    owner_kind: str = typer.Option(
        "team",
        "--owner-kind",
        help="Owner kind: team, person, email, workspace, organization, third_party, cloud_account, service, unknown.",
    ),
    owner_display: Optional[str] = typer.Option(
        None,
        "--owner-display",
        help="Human-readable owner label.",
    ),
    entity_type: str = typer.Option(
        "other",
        "--entity-type",
        help="Entity type to use if the entity key does not exist yet.",
    ),
    confidence: float = typer.Option(
        1.0,
        "--confidence",
        min=0.0,
        max=1.0,
        help="Claim confidence from 0.0 to 1.0.",
    ),
    source: str = typer.Option(
        "operator",
        "--source",
        help="Ownership claim source label.",
    ),
    created_by: str = typer.Option(
        "operator",
        "--created-by",
        help="Operator recorded on the ownership claim.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Print machine-readable ownership claim summary.",
    ),
) -> None:
    """Create or update an explicit ownership claim for a graph entity."""
    con = _open_graph_db(engagement)
    try:
        entity_id = entity_id_for_key(con, int(engagement), entity_key)
        if entity_id is None:
            entity_id = upsert_asset_entity(
                con,
                engagement_id=int(engagement),
                entity_key=entity_key,
                entity_type=entity_type,
                label=entity_key,
                source_table="operator",
                source_id=0,
                confidence=confidence,
                metadata={"source": source},
            )
        claim_id = upsert_ownership_claim(
            con,
            engagement_id=int(engagement),
            entity_id=entity_id,
            owner_ref=owner,
            owner_kind=owner_kind,
            owner_display=owner_display,
            claim_type="explicit",
            confidence=confidence,
            source=source,
            status="active",
            evidence={"entity_key": entity_key},
            created_by=created_by,
        )
        con.commit()
    finally:
        con.close()
    result = {
        "schema_version": "forge.asset_graph.ownership_set.v1",
        "execution_policy": "writes_asset_graph_ownership_claim",
        "engagement_id": int(engagement),
        "entity_key": entity_key,
        "entity_id": int(entity_id),
        "claim_id": int(claim_id),
        "owner": owner,
        "total_count": 1,
        "selected_count": 1,
        "omitted_count": 0,
    }
    if json_output:
        console.print(json.dumps(result, sort_keys=True))
        return
    console.print(
        "[bold]Ownership claim set[/bold] "
        f"entity={entity_key} owner={owner} claim_id={claim_id}"
    )


@ownership_app.command("resolve")
def graph_ownership_resolve(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    entity_key: str = typer.Option(..., "--entity-key", help="Canonical entity key."),
    owner: Optional[str] = typer.Option(
        None,
        "--owner",
        help="Owner reference to keep active. Use this or --claim-id.",
    ),
    owner_kind: Optional[str] = typer.Option(
        None,
        "--owner-kind",
        help="Optional owner kind filter when selecting by --owner.",
    ),
    claim_id: Optional[int] = typer.Option(
        None,
        "--claim-id",
        help="Specific ownership claim ID to keep active.",
    ),
    superseded_status: str = typer.Option(
        "superseded",
        "--superseded-status",
        help="Status for competing active owner claims: superseded or rejected.",
    ),
    reason: str = typer.Option(
        "",
        "--reason",
        help="Operator-visible reason stored in sanitized claim evidence.",
    ),
    resolved_by: str = typer.Option(
        "operator",
        "--resolved-by",
        help="Operator recorded in sanitized resolution evidence.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Print machine-readable resolution summary.",
    ),
) -> None:
    """Resolve an ownership conflict by selecting the active owner claim."""
    con = _open_graph_db(engagement)
    try:
        result = resolve_ownership_conflict(
            con,
            engagement_id=int(engagement),
            entity_key=entity_key,
            claim_id=claim_id,
            owner_ref=owner or "",
            owner_kind=owner_kind or "",
            superseded_status=superseded_status,
            reason=reason,
            resolved_by=resolved_by,
        )
        con.commit()
    finally:
        con.close()
    if json_output:
        console.print(json.dumps(result, sort_keys=True))
        return
    console.print(
        "[bold]Ownership conflict resolved[/bold] "
        f"entity={result['entity_key']} owner={result['selected_owner']} "
        f"superseded={len(result['superseded_claim_ids'])}"
    )


@attribution_app.command("import")
def graph_attribution_import(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    file: str = typer.Option(
        ...,
        "--file",
        "-f",
        help="JSON or CSV attribution records file.",
    ),
    source: str = typer.Option(
        "operator_attribution",
        "--source",
        help="Source label stored with imported claims.",
    ),
    created_by: str = typer.Option(
        "operator",
        "--created-by",
        help="Operator recorded on imported claims.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Print machine-readable import summary.",
    ),
) -> None:
    """Import asset attribution, subsidiary, third-party, and cloud-account claims."""
    con = _open_graph_db(engagement)
    try:
        result = import_asset_attribution_file(
            con,
            engagement_id=int(engagement),
            path=file,
            source=source,
            created_by=created_by,
        )
        con.commit()
    finally:
        con.close()
    if json_output:
        console.print(json.dumps(result, sort_keys=True))
        return
    console.print(
        "[bold]Asset attribution imported[/bold] "
        f"processed={result['processed_count']} imported={result['imported_count']} "
        f"errors={result['error_count']} entities={result['entity_count']} "
        f"relationships={result['relationship_count']} claims={result['ownership_claim_count']}"
    )


@graph_app.command("build")
def graph_build(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    fmt: str = typer.Option(
        "json",
        "--format",
        help="Output format: mermaid | dot | json | maltego | all",
    ),
    output_dir: Optional[str] = typer.Option(
        None,
        "--output-dir",
        "-o",
        help="Directory to write output files (default: current directory).",
    ),
    min_severity: str = typer.Option(
        "LOW",
        "--min-severity",
        help="Exclude findings below this threshold: CRITICAL | HIGH | MEDIUM | LOW",
    ),
    critical_path_only: bool = typer.Option(
        False,
        "--critical-path-only",
        help="Emit only nodes and edges on the critical attack path.",
    ),
    snapshot: bool = typer.Option(
        False,
        "--snapshot",
        help="Write the graph to attack_graph_snapshots table for Phase 6 consumption.",
    ),
    max_nodes: int = typer.Option(
        150,
        "--max-nodes",
        help="Auto-prune low-severity leaf nodes if graph exceeds this count.",
    ),
) -> None:
    """Build a directed attack graph from all Phase 4 findings (Module 4-H).

    Reads engagement DB (read-only). Emits Mermaid flowchart, Graphviz DOT,
    structured JSON, GraphML import artifacts, and native Maltego `.mtgx`
    workspace archives. No network access at any point.
    """
    from forge.config import ForgeConfig  # noqa: PLC0415
    from forge.graph.export import export_attack_graph  # noqa: PLC0415

    cfg = ForgeConfig.load()
    db_path = cfg.engagement_db_path(engagement)
    export_attack_graph(
        engagement_id=int(engagement),
        db_path=db_path,
        output_dir=output_dir,
        fmt=fmt,
        min_severity=min_severity,
        critical_path_only=critical_path_only,
        snapshot=snapshot,
        max_nodes=max_nodes,
        emit=console.print,
    )


_cli_module = sys.modules.get("forge.cli")
if _cli_module is not None:
    setattr(_cli_module, "graph_build", graph_build)
