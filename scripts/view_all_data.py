from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.table import Table
from rich.text import Text

from forge.config import ForgeConfig

console = Console()


DECRYPT_ALLOWED = False


def _decrypt_value(value: object) -> object:
    if not isinstance(value, str):
        return value
    if not value.startswith("FORGE-ENC-v1:"):
        return value
    if not DECRYPT_ALLOWED:
        return "<REDACTED>"
    try:
        from forge.opsec.crypto import decrypt_string

        return decrypt_string(value)
    except Exception:
        return value


def _format_value(value: object) -> str:
    resolved = _decrypt_value(value)
    if resolved is None:
        return "NULL"
    if isinstance(resolved, (dict, list)):
        return json.dumps(resolved, ensure_ascii=False)
    text = str(resolved)
    if len(text) > 240:
        return text[:237] + "..."
    return text


def _list_tables(con: sqlite3.Connection) -> list[str]:
    rows = con.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ).fetchall()
    return [str(r[0]) for r in rows]


def _render_rows(db_label: str, table_name: str, rows: list[sqlite3.Row], max_rows: Optional[int]) -> None:
    if not rows:
        return
    display_rows = rows if max_rows is None else rows[:max_rows]
    rich_table = Table(title=f"{db_label} :: {table_name}", show_lines=False)
    for col in rows[0].keys():
        rich_table.add_column(Text(str(col)))
    for row in display_rows:
        rich_table.add_row(*[Text(_format_value(row[col])) for col in row.keys()])
    console.print(rich_table)
    if max_rows is not None and len(rows) > max_rows:
        console.print(
            f"[yellow]Showing {max_rows}/{len(rows)} rows for {table_name}. "
            "Use --all to show everything.[/yellow]"
        )


def _view_db(db_path: Path, max_rows: Optional[int]) -> None:
    if not db_path.exists():
        console.print(f"[red]Missing DB:[/red] {db_path}")
        return
    console.rule(f"[bold cyan]{db_path}[/bold cyan]")
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        tables = _list_tables(con)
        if not tables:
            console.print("[yellow]No tables found.[/yellow]")
            return
        summary = Table(title=f"Table Counts :: {db_path.name}")
        summary.add_column("Table")
        summary.add_column("Rows", justify="right")
        for table_name in tables:
            count = con.execute(f"SELECT COUNT(*) AS n FROM {table_name}").fetchone()["n"]
            summary.add_row(Text(table_name), Text(str(count)))
        console.print(summary)
        for table_name in tables:
            rows = con.execute(f"SELECT * FROM {table_name}").fetchall()
            _render_rows(db_path.name, table_name, rows, max_rows)
    finally:
        con.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="View all FORGE DB tables with optional decryption")
    parser.add_argument("--all", action="store_true", help="Show all rows in every table")
    parser.add_argument("--limit", type=int, default=25, help="Rows per table when --all is not used")
    parser.add_argument("--decrypt", action="store_true", help="Attempt to decrypt and display sensitive data (OPSEC WARNING)")
    args = parser.parse_args()

    if args.decrypt:
        import questionary
        confirm = questionary.confirm(
            "WARNING: --decrypt will output plaintext secrets to the console. "
            "These may be captured by terminal history or screen sharing. Proceed?"
        ).ask()
        if not confirm:
            console.print("[red]Aborted.[/red]")
            return
        global DECRYPT_ALLOWED
        DECRYPT_ALLOWED = True

    cfg = ForgeConfig.load()
    db_paths: list[Path] = [cfg.kb_path, cfg.nvd_path, cfg.exploitdb_path]
    engagement_dir = cfg.data_dir / "engagements"
    if engagement_dir.exists():
        db_paths.extend(sorted(engagement_dir.glob("*.db")))

    max_rows = None if args.all else max(1, args.limit)
    console.print(f"[bold]Data root:[/bold] {cfg.data_dir}")
    for db_path in db_paths:
        _view_db(db_path, max_rows=max_rows)


if __name__ == "__main__":
    main()
