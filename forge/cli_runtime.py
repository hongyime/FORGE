"""Runtime guard helpers for the Forge CLI entrypoint."""

from __future__ import annotations

import os
from collections.abc import Callable, MutableMapping
from typing import Any

from rich.console import Console


class CliRuntimeError(RuntimeError):
    """CLI startup runtime failure that should map to a non-zero Typer exit."""


def deny_outbound_socket(*_args: Any, **_kwargs: Any) -> Any:
    raise OSError("FORGE_OFFLINE_STRICT: outbound network calls are disabled.")


def install_offline_socket_guard(socket_module: Any | None = None) -> None:
    if socket_module is None:
        import socket as socket_module  # noqa: PLC0415

    socket_module.socket = deny_outbound_socket


def clear_proxy_when_no_tor(
    *,
    no_tor: bool,
    env: MutableMapping[str, str] | None = None,
) -> bool:
    if not no_tor:
        return False
    target_env = os.environ if env is None else env
    target_env.pop("FORGE_PROXY", None)
    return True


def should_start_tor(
    cfg: Any,
    *,
    offline_strict: bool,
    no_tor: bool,
) -> bool:
    return bool(cfg.is_tor_requested and not (offline_strict or cfg.offline_strict) and not no_tor)


def _default_tor_manager_factory() -> Any:
    from forge.opsec.tor import TorManager  # noqa: PLC0415

    return TorManager()


def bootstrap_tor_if_needed(
    cfg: Any,
    *,
    offline_strict: bool,
    no_tor: bool,
    console: Console,
    tor_manager_factory: Callable[[], Any] | None = None,
    register_stop: Callable[[Callable[[], Any]], Any] | None = None,
) -> bool:
    if not should_start_tor(cfg, offline_strict=offline_strict, no_tor=no_tor):
        return False
    factory = tor_manager_factory or _default_tor_manager_factory
    if register_stop is None:
        import atexit  # noqa: PLC0415

        register_stop = atexit.register
    tor = factory()
    if tor.start():
        register_stop(tor.stop)
        return True
    console.print("[bold red]OPSEC ERROR:[/bold red] Failed to bootstrap Tor daemon.")
    raise CliRuntimeError("Failed to bootstrap Tor daemon.")


def configure_cli_runtime(
    cfg: Any,
    *,
    offline_strict: bool,
    no_tor: bool,
    console: Console,
) -> None:
    effective_offline_strict = bool(offline_strict or cfg.offline_strict)
    if effective_offline_strict:
        install_offline_socket_guard()
    clear_proxy_when_no_tor(no_tor=no_tor)
    bootstrap_tor_if_needed(
        cfg,
        offline_strict=offline_strict,
        no_tor=no_tor,
        console=console,
    )


__all__ = [
    "CliRuntimeError",
    "bootstrap_tor_if_needed",
    "clear_proxy_when_no_tor",
    "configure_cli_runtime",
    "deny_outbound_socket",
    "install_offline_socket_guard",
    "should_start_tor",
]
