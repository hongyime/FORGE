"""Regression: --basic and --enhanced port scans share the same async engine.

P2/P3 audit item #7: the audit warned that --basic's scan path was
sequential/blocking while --enhanced's was async, calling the drift a
"foot-gun". Both call sites are now funnelled through
:func:`forge.phase1.port_scanner._scan_host_ports_sync`, which wraps the
single async primitive :func:`_scan_host_async`.

If either public entry point stops using the shared helper this test
fails, so the two modes can never diverge in fan-out shape again.
"""

from __future__ import annotations

import ast
import inspect

import forge.phase1.port_scanner as port_scanner


def _extract_call_names(func) -> set[str]:
    """Return the set of function-call names invoked in ``func``'s body."""
    source = inspect.getsource(func)
    # Strip leading indentation so ast.parse succeeds on a method body.
    source = inspect.cleandoc(source)
    tree = ast.parse(source)
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, ast.Name):
                names.add(f.id)
            elif isinstance(f, ast.Attribute):
                # e.g. asyncio.run -> "run"
                names.add(f.attr)
    return names


def test_scan_engagement_basic_uses_shared_helper() -> None:
    calls = _extract_call_names(port_scanner.scan_engagement)
    assert "_scan_host_ports_sync" in calls, (
        "scan_engagement (--basic) must delegate host scanning to "
        "_scan_host_ports_sync so it stays in sync with --enhanced."
    )
    assert "_scan_host_async" not in calls, (
        "scan_engagement should NOT call _scan_host_async directly; that "
        "call belongs behind _scan_host_ports_sync so both modes stay "
        "harmonised."
    )


def test_scan_engagement_enhanced_uses_shared_helper() -> None:
    calls = _extract_call_names(port_scanner.scan_engagement_enhanced)
    assert "_scan_host_ports_sync" in calls, (
        "scan_engagement_enhanced (--enhanced) must delegate host "
        "scanning to _scan_host_ports_sync so it stays in sync with "
        "--basic."
    )
    assert "_scan_host_async" not in calls, (
        "scan_engagement_enhanced should NOT call _scan_host_async "
        "directly; that call belongs behind _scan_host_ports_sync."
    )


def test_scan_host_ports_sync_delegates_to_async_primitive() -> None:
    source = inspect.getsource(port_scanner._scan_host_ports_sync)
    assert "_scan_host_async" in source, (
        "_scan_host_ports_sync must be a thin wrapper over the async "
        "primitive; otherwise --basic and --enhanced would silently "
        "diverge in fan-out shape."
    )
    assert "asyncio.run" in source, (
        "_scan_host_ports_sync must run the async primitive via "
        "asyncio.run so callers stay in the sync ORM-write pattern."
    )


def test_shared_helper_returns_expected_ports_on_localhost() -> None:
    """Sanity: helper actually scans and returns something sensible.

    Uses port 65533 (extremely likely to be closed) and a non-routable
    RFC-2544 test address (198.18.0.1) with a tiny timeout; the call must
    return an empty list without raising.
    """
    result = port_scanner._scan_host_ports_sync("198.18.0.1", [65533], timeout=0.05)
    assert isinstance(result, list)
