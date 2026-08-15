from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest
from rich.console import Console

from forge.cli_runtime import (
    CliRuntimeError,
    bootstrap_tor_if_needed,
    clear_proxy_when_no_tor,
    deny_outbound_socket,
    install_offline_socket_guard,
    should_start_tor,
)


@dataclass(frozen=True)
class _Cfg:
    is_tor_requested: bool = False
    offline_strict: bool = False


class _SocketModule:
    def socket(self) -> object:
        return object()


class _Tor:
    def __init__(self, starts: bool) -> None:
        self.starts = starts
        self.stop_registered = False

    def start(self) -> bool:
        return self.starts

    def stop(self) -> None:
        self.stop_registered = True


def test_offline_socket_guard_installs_denying_socket_factory() -> None:
    socket_module = _SocketModule()

    install_offline_socket_guard(socket_module)

    with pytest.raises(OSError, match="FORGE_OFFLINE_STRICT"):
        socket_module.socket()
    with pytest.raises(OSError, match="FORGE_OFFLINE_STRICT"):
        deny_outbound_socket()


def test_clear_proxy_when_no_tor_only_mutates_process_env_when_requested() -> None:
    env = {"FORGE_PROXY": "socks5://127.0.0.1:9050", "KEEP": "1"}

    assert clear_proxy_when_no_tor(no_tor=False, env=env) is False
    assert env["FORGE_PROXY"] == "socks5://127.0.0.1:9050"
    assert clear_proxy_when_no_tor(no_tor=True, env=env) is True
    assert env == {"KEEP": "1"}


def test_should_start_tor_preserves_offline_and_no_tor_gates() -> None:
    assert should_start_tor(_Cfg(is_tor_requested=False), offline_strict=False, no_tor=False) is False
    assert should_start_tor(_Cfg(is_tor_requested=True), offline_strict=False, no_tor=False) is True
    assert should_start_tor(_Cfg(is_tor_requested=True), offline_strict=True, no_tor=False) is False
    assert (
        should_start_tor(
            _Cfg(is_tor_requested=True, offline_strict=True),
            offline_strict=False,
            no_tor=False,
        )
        is False
    )
    assert should_start_tor(_Cfg(is_tor_requested=True), offline_strict=False, no_tor=True) is False


def test_bootstrap_tor_if_needed_registers_stop_only_after_success() -> None:
    tor = _Tor(starts=True)
    registered: list[Any] = []

    assert bootstrap_tor_if_needed(
        _Cfg(is_tor_requested=True),
        offline_strict=False,
        no_tor=False,
        console=Console(record=True, color_system=None),
        tor_manager_factory=lambda: tor,
        register_stop=registered.append,
    ) is True

    assert registered == [tor.stop]


def test_bootstrap_tor_if_needed_maps_failed_start_to_runtime_error() -> None:
    console = Console(record=True, color_system=None)

    with pytest.raises(CliRuntimeError, match="Failed to bootstrap Tor daemon"):
        bootstrap_tor_if_needed(
            _Cfg(is_tor_requested=True),
            offline_strict=False,
            no_tor=False,
            console=console,
            tor_manager_factory=lambda: _Tor(starts=False),
            register_stop=lambda _callback: None,
        )

    assert "Failed to bootstrap Tor daemon" in console.export_text()
