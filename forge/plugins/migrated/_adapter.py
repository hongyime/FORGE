"""
forge/plugins/migrated/_adapter.py — Shared adapter helpers for migrated plugins.

Provides a defensive wrapper that lazily imports an existing phase module and
invokes the first available public entry point, returning a uniform
``PluginResult`` envelope. This module is internal to the ``migrated``
sub-package and is not part of the public plugin API.

Requirements: 4.7, 11.4
"""

from __future__ import annotations

import asyncio
import importlib
import time
from typing import Any, Iterable

from forge.plugins.base import PluginResult

# Conventional entry-point function names probed in order. Phase modules in
# this codebase rarely standardise on a single name, so we try the most likely
# candidates and fall through to a stub result if none are found.
_DEFAULT_CANDIDATES: tuple[str, ...] = (
    "run",
    "main",
    "execute",
    "invoke",
)


def _select_callable(module: Any, candidates: Iterable[str]) -> Any | None:
    for name in candidates:
        fn = getattr(module, name, None)
        if callable(fn):
            return fn
    return None


async def invoke_phase(
    module_path: str,
    params: dict[str, object],
    *,
    candidates: Iterable[str] = _DEFAULT_CANDIDATES,
) -> PluginResult:
    """Lazily import a phase module and invoke its primary entry point.

    The wrapped phase function is executed via ``asyncio.to_thread`` to avoid
    blocking the event loop. All exceptions raised by the import or the call
    are converted into a failed ``PluginResult``.

    Args:
        module_path: Dotted import path of the phase module to wrap.
        params: Parameters forwarded as keyword arguments to the entry point.
        candidates: Entry-point names probed in priority order.

    Returns:
        ``PluginResult`` with ``success=True`` and the captured return value
        under ``output['result']`` on success; ``success=False`` with the
        error message on failure. When no entry point is found a successful
        stub result is returned with a ``note`` field so callers can detect
        the adapter shell.
    """
    started = time.perf_counter()
    try:
        module = importlib.import_module(module_path)
    except Exception as exc:  # pragma: no cover - defensive
        return PluginResult(
            success=False,
            output={},
            error=f"import {module_path} failed: {exc}",
            duration_ms=(time.perf_counter() - started) * 1000.0,
        )

    fn = _select_callable(module, candidates)
    if fn is None:
        return PluginResult(
            success=True,
            output={"note": "stub adapter", "module": module_path},
            duration_ms=(time.perf_counter() - started) * 1000.0,
        )

    try:
        if asyncio.iscoroutinefunction(fn):
            result = await fn(**params)
        else:
            result = await asyncio.to_thread(_call_safe, fn, params)
    except Exception as exc:
        return PluginResult(
            success=False,
            output={},
            error=f"{module_path}: {type(exc).__name__}: {exc}",
            duration_ms=(time.perf_counter() - started) * 1000.0,
        )

    duration_ms = (time.perf_counter() - started) * 1000.0
    return PluginResult(
        success=True,
        output={"result": _coerce(result)},
        duration_ms=duration_ms,
    )


def _call_safe(fn: Any, params: dict[str, object]) -> Any:
    """Invoke ``fn`` with kwargs, falling back to no-arg call on TypeError."""
    try:
        return fn(**params)
    except TypeError:
        # Phase entry points may take positional or no kwargs; degrade
        # gracefully to a no-arg invocation rather than crash the wrapper.
        try:
            return fn()
        except TypeError as exc:
            raise RuntimeError(f"incompatible signature: {exc}") from exc


def _coerce(value: Any) -> Any:
    """Coerce arbitrary phase return values to JSON-friendly primitives."""
    if value is None:
        return None
    if isinstance(value, (str, int, float, bool, list, dict)):
        return value
    # Pydantic v2 models
    if hasattr(value, "model_dump"):
        try:
            return value.model_dump()
        except Exception:  # pragma: no cover - defensive
            pass
    return repr(value)
