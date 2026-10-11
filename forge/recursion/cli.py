"""forge/recursion/cli.py — Recursion intents CLI (Wave 2 #20).

Operator-facing commands:

    forge recursion intents list --engagement N [--status open|...|all] [--limit N] [--json]
    forge recursion intents add --engagement N --target-seed SEED --rationale TEXT
                                [--source-fact-id ID] [--seed-type TYPE]
                                [--intent-id ID] [--status open|...] [--json]

Read-only ``list`` by default; ``add`` is the only write surface. The
scheduler is not rewritten by this ticket (Wave 2 #20 is explicitly a
view + audit upgrade). Status transitions (``claimed``, ``completed``,
``abandoned``) are only writable through ``add`` for historical records
until a future automation ticket owns transitions.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Optional

import typer
from rich.console import Console

from forge.config import ForgeConfig
from forge.db.direct_connect import direct_connect
from forge.db.migrations import run_migrations
from forge.db.validation import validate_canonical_schema
from forge.recursion.store import (
    ALLOWED_STATUSES,
    IntentStoreError,
    add_intent,
    count_intents,
    list_intents,
)

__all__ = ["register_recursion_commands"]

_console = Console(stderr=True)


def _open_db(engagement: str) -> sqlite3.Connection:
    cfg = ForgeConfig.load()
    con = direct_connect(cfg.engagement_db_path(str(engagement)))
    con.row_factory = sqlite3.Row
    run_migrations(con)
    validate_canonical_schema(con)
    return con


def register_recursion_commands(app: typer.Typer) -> None:
    intents_app = typer.Typer(
        name="intents",
        help="Fact/Intent/Hint recursion intents (Wave 2 #20).",
        no_args_is_help=True,
    )

    @intents_app.command("list")
    def intents_list(
        engagement: str = typer.Option(
            ...,
            "--engagement",
            "-e",
            help="Engagement ID whose recursion intents should be listed.",
        ),
        status: Optional[str] = typer.Option(
            None,
            "--status",
            help=(
                "Filter by intent status "
                "(open, claimed, completed, abandoned, or all). Default: all."
            ),
        ),
        limit: int = typer.Option(
            500,
            "--limit",
            min=0,
            max=10_000,
            help="Maximum rows to return (bounded 0..10000).",
        ),
        json_output: bool = typer.Option(
            False,
            "--json",
            help="Emit machine-readable JSON.",
        ),
    ) -> None:
        """List recursion intents for an engagement (read-only)."""
        con = _open_db(engagement)
        try:
            try:
                intents = list_intents(
                    con,
                    engagement_id=engagement,
                    status=status,
                    limit=limit,
                )
            except IntentStoreError as exc:
                raise typer.BadParameter(str(exc)) from exc
            total_matching = count_intents(
                con,
                engagement_id=engagement,
                status=status,
            )
        finally:
            con.close()

        omitted_count = max(0, total_matching - len(intents))
        payload = {
            "schema_version": "forge.recursion.intents.v1",
            "engagement_id": str(engagement),
            "status_filter": (status or "all").strip().lower() or "all",
            "limit": int(limit),
            "total_count": int(total_matching),
            "selected_count": len(intents),
            "omitted_count": int(omitted_count),
            "intents": intents,
        }

        if json_output:
            typer.echo(json.dumps(payload, sort_keys=True, default=str))
            return

        _console.print(
            "[bold]Recursion intents[/bold] "
            f"engagement={engagement} total={total_matching} "
            f"shown={len(intents)} status={payload['status_filter']}"
        )
        for intent in intents:
            seed_type = intent.get("seed_type") or "-"
            rationale = intent.get("rationale") or ""
            _console.print(
                f"- {intent['intent_id']} status={intent['status']} "
                f"target={intent['target_seed']} seed_type={seed_type} "
                f"created_at={intent.get('created_at')} rationale={rationale!r}"
            )

    @intents_app.command("add")
    def intents_add(
        engagement: str = typer.Option(
            ...,
            "--engagement",
            "-e",
            help="Engagement ID the intent is scoped to.",
        ),
        target_seed: str = typer.Option(
            ...,
            "--target-seed",
            help="Proposed next seed value (domain, URL, email, etc.).",
        ),
        rationale: str = typer.Option(
            "",
            "--rationale",
            help="Operator-authored reason for recording the intent.",
        ),
        source_fact_id: Optional[str] = typer.Option(
            None,
            "--source-fact-id",
            help="Opaque pointer to the Fact row that spawned this intent.",
        ),
        seed_type: Optional[str] = typer.Option(
            None,
            "--seed-type",
            help="Optional classifier hint matching the canonical seed types.",
        ),
        intent_id: Optional[str] = typer.Option(
            None,
            "--intent-id",
            help="Explicit intent_id (defaults to a UUIDv4 hex).",
        ),
        status: str = typer.Option(
            "open",
            "--status",
            help=f"Initial status; one of {sorted(ALLOWED_STATUSES)}.",
        ),
        json_output: bool = typer.Option(
            False,
            "--json",
            help="Emit the persisted row as JSON.",
        ),
    ) -> None:
        """Record a new recursion intent."""
        con = _open_db(engagement)
        try:
            try:
                created = add_intent(
                    con,
                    target_seed=target_seed,
                    rationale=rationale,
                    source_fact_id=source_fact_id,
                    seed_type=seed_type,
                    engagement_id=engagement,
                    intent_id=intent_id,
                    status=status,
                )
            except IntentStoreError as exc:
                raise typer.BadParameter(str(exc)) from exc
            con.commit()
        except Exception:
            con.rollback()
            raise
        finally:
            con.close()

        payload = {
            "schema_version": "forge.recursion.intents.v1",
            "engagement_id": str(engagement),
            "intent": created,
        }

        if json_output:
            typer.echo(json.dumps(payload, sort_keys=True, default=str))
            return

        _console.print(
            "[bold]Added recursion intent[/bold] "
            f"intent_id={created['intent_id']} status={created['status']} "
            f"target={created['target_seed']}"
        )

    app.add_typer(intents_app)
