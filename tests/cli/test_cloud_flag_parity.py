"""Regression tests for `--project-ref` / `--project-id` CLI alias parity.

P2/P3 audit item #3: `cloud supabase` accepted only `--project-ref` while
`cloud firebase` accepted only `--project-id`, forcing operators to remember
which flag went with which provider. Both commands should now accept both
flags so muscle memory works across providers.

Note: Typer/Click ``--help`` only renders the primary declaration for each
Option, so we introspect the compiled Click Command params directly instead
of grepping help text.
"""

from __future__ import annotations

from typing import Iterable

import click
import typer.main

from forge import cli


def _click_command_for(subcommand: str) -> click.Command:
    """Compile ``cloud_app`` and return the concrete Click subcommand."""
    click_group = typer.main.get_command(cli.cloud_app)
    assert isinstance(click_group, click.Group), type(click_group)
    resolved = click_group.get_command(click.Context(click_group), subcommand)
    assert resolved is not None, f"no cloud subcommand named {subcommand!r}"
    return resolved


def _flag_names(cmd: click.Command) -> Iterable[str]:
    for param in cmd.params:
        if isinstance(param, click.Option):
            yield from param.opts
            yield from param.secondary_opts


def test_cloud_supabase_accepts_both_project_flags() -> None:
    cmd = _click_command_for("supabase")
    flags = set(_flag_names(cmd))
    assert "--project-ref" in flags
    assert "--project-id" in flags, (
        "supabase should accept --project-id as alias for --project-ref "
        f"(parity with `cloud firebase`). Got: {sorted(flags)}"
    )


def test_cloud_firebase_accepts_both_project_flags() -> None:
    cmd = _click_command_for("firebase")
    flags = set(_flag_names(cmd))
    assert "--project-id" in flags
    assert "--project-ref" in flags, (
        "firebase should accept --project-ref as alias for --project-id "
        f"(parity with `cloud supabase`). Got: {sorted(flags)}"
    )
