"""Kill-chain command registration for the Forge CLI."""

from __future__ import annotations

from collections.abc import Callable
from typing import TypeVar

import typer

CommandHandler = TypeVar("CommandHandler", bound=Callable[..., object])


def register_kill_chain_command(app: typer.Typer, handler: CommandHandler) -> CommandHandler:
    """Register the root kill-chain command without owning its implementation."""

    app.command("kill-chain")(handler)
    return handler


__all__ = ["register_kill_chain_command"]
