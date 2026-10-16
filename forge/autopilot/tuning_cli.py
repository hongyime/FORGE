"""Operator approval flow: PENDING RAISE → Bryan (via Muse) approves → next cycle applies and consumes approval."""
from pathlib import Path
from datetime import UTC, datetime
import typer
from forge.autopilot.events import tuning_decisions_for_data_dir
from forge.autopilot.scheduler import ensure_scheduler_schema, scheduler_db_path
from forge.autopilot.tuning_apply import create_tuning_approval
from forge.db.direct_connect import direct_connect


def register_tuning_commands(app: typer.Typer) -> None:
    @app.command("approve")
    def approve(action: str = typer.Option(..., "--action"), slot_delta: int = typer.Option(..., "--slot-delta"), target_delta: int = typer.Option(..., "--target-delta"), approver: str = typer.Option("Bryan", "--approver"), expires_hours: float = typer.Option(24, "--expires-hours"), data_dir: Path = typer.Option(None, "--data-dir")) -> None:
        """Approve an exact pending RAISE; next cycle applies it and consumes approval."""
        if action != "RAISE" or expires_hours <= 0:
            raise typer.BadParameter("only RAISE can be approved; expiry must be positive")
        ident, expiry = create_tuning_approval(data_dir or Path.home()/".forge"/"data", action=action, slot_delta=slot_delta, target_delta=target_delta, approver=approver, expires_hours=expires_hours)
        typer.echo(f"Approval {ident} expires {expiry}")

    @app.command("pending")
    def pending(data_dir: Path = typer.Option(None, "--data-dir")) -> None:
        """Show latest proposed RAISE and open approvals."""
        root = data_dir or Path.home()/".forge"/"data"
        decisions = tuning_decisions_for_data_dir(root)
        latest = next((d for d in decisions if d.get("action") == "RAISE"), None)
        typer.echo(f"Latest RAISE: {latest}" if latest else "No proposed RAISE")
        con=direct_connect(scheduler_db_path(root))
        try:
            ensure_scheduler_schema(con)
            now = datetime.now(UTC).isoformat().replace("+00:00", "Z")
            for row in con.execute("SELECT id,action,slot_delta,target_delta,approver,expires_at FROM tuning_approvals WHERE consumed_at IS NULL AND expires_at > ? ORDER BY id DESC", (now,)):
                typer.echo(f"Open approval: {row[0]} {row[1]} slots={row[2]} targets={row[3]} approver={row[4]} expires={row[5]}")
        finally: con.close()
