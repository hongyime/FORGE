"""Clean command registration for the Forge CLI."""

from __future__ import annotations

import typer


def run_clean_command(*, engagement: str, confirm: bool) -> None:
    """Securely wipe all on-disk artifacts for an engagement."""

    if not confirm:
        import questionary  # noqa: PLC0415

        ok = questionary.confirm(
            f"Permanently destroy all artifacts for engagement {engagement!r}?"
        ).ask()
        if not ok:
            raise typer.Exit()

    from forge.opsec.cleanup import run_clean  # noqa: PLC0415

    run_clean(engagement_id=engagement)


def register_clean_command(app: typer.Typer) -> None:
    """Register the root clean command on the Forge app."""

    @app.command("clean")
    def clean_command(
        engagement: str = typer.Option(..., "--engagement", "-e"),
        confirm: bool = typer.Option(
            False,
            "--confirm",
            help="Skip interactive confirmation prompt.",
        ),
    ) -> None:
        """
        Securely wipe all on-disk artifacts for an engagement.

        Shreds payload files, credential caches, exfiltration staging, and
        removes the engagement DB. Irreversible.
        """
        run_clean_command(engagement=engagement, confirm=confirm)


__all__ = ["register_clean_command", "run_clean_command"]
