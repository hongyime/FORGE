"""
tests/chaos/test_plugin_error_exc.py - Coverage for the ``PluginResult.error_exc`` field.

Requirement 3.13 of ``.kiro/specs/audit-cleanup-and-chaos/requirements.md``
says the chaos harness's ``scenario_plugin_sigkill`` MUST assert that the
executor returns a failure envelope carrying a typed subclass of
``ForgeError`` (or, on POSIX signal-driven exits, ``ProcessLookupError``).

Historically ``PluginResult`` only carried a ``str`` FQN in
``error_class``, which the harness resolved via ``importlib`` and then
did ``issubclass`` on. That is strictly weaker than the requirement: any
labelling bug in the executor would satisfy the check while the actual
exception class was wrong.

``PluginResult`` now also carries ``error_exc`` — the concrete Python
exception INSTANCE the executor observed (or constructed on the
non-zero-exit branch). This module unit-tests the two invariants that
matter:

    1. ``_parse_process_result`` populates ``error_exc`` with a
       ``ProcessLookupError`` on negative POSIX returncodes and with a
       ``PluginSubprocessKilledError`` (a ``ForgeError`` subclass) on
       every other non-zero exit.
    2. The exec-loop's ``except Exception`` branch propagates the
       ORIGINAL raised exception through ``error_exc`` unchanged, so a
       backend that raises ``FileNotFoundError`` from
       ``asyncio.create_subprocess_exec`` surfaces that same instance
       to the caller.

Neither test spawns a real subprocess: (1) uses the fact that
``_parse_process_result`` is a pure decoder that takes returncode /
stdout / stderr as parameters, and (2) monkey-patches the executor's
dispatcher to raise a specific exception. Marker: ``chaos_unit`` so
these run in the default ``pytest`` invocation alongside the other
safety-layer unit tests.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from forge.audit.logger import AuditLogger  # noqa: E402
from forge.core.errors import (  # noqa: E402
    ForgeError,
    PluginSubprocessKilledError,
)
from forge.plugins.base import (  # noqa: E402
    ExecutionMode,
    PluginMetadata,
    PluginResult,
    RiskLevel,
)
from forge.plugins.executor import PluginExecutor  # noqa: E402

pytestmark = pytest.mark.chaos_unit


# ---------------------------------------------------------------------------
# _parse_process_result invariants (Requirement 3.13)
# ---------------------------------------------------------------------------


def _make_executor() -> PluginExecutor:
    """Instantiate an executor with an in-memory audit logger.

    ``AuditLogger()`` with no args writes only to its in-memory ring,
    which keeps this test pure — no filesystem I/O, no DB.
    """
    return PluginExecutor(audit=AuditLogger())


def test_parse_process_result_negative_returncode_carries_process_lookup_error() -> None:
    """A negative returncode on POSIX MUST surface as ``ProcessLookupError``.

    Requirement 10 of chaos-harness-hardening: ``returncode < 0`` on
    POSIX is a signal-driven exit and MUST be reported using the
    ``ProcessLookupError`` sentinel. On Windows the executor treats
    every non-zero exit as ``PluginSubprocessKilledError`` because
    Windows does not surface signals via returncode; this test skips
    on Windows for that reason.
    """
    if sys.platform == "win32":
        pytest.skip("Windows does not use ProcessLookupError for negative returncodes")

    executor = _make_executor()
    result = executor._parse_process_result(
        tool_name="chaos_test",
        returncode=-9,  # SIGKILL on POSIX
        stdout=b"",
        stderr=b"terminated",
    )
    assert result.success is False
    assert isinstance(result.error_exc, ProcessLookupError), (
        f"expected ProcessLookupError instance, got "
        f"{type(result.error_exc).__name__}"
    )
    # The string ``error_class`` MUST match the instance so the JSON
    # transport and the in-process field stay in agreement.
    assert result.error_class == "builtins.ProcessLookupError"


def test_parse_process_result_positive_returncode_carries_forge_error() -> None:
    """A positive non-zero returncode MUST surface as ``PluginSubprocessKilledError``.

    On both POSIX and Windows, a non-zero, non-negative returncode is a
    subprocess-killed event that the executor tags with the typed
    ``PluginSubprocessKilledError`` (a ``ForgeError`` subclass).
    """
    executor = _make_executor()
    result = executor._parse_process_result(
        tool_name="chaos_test",
        returncode=1,
        stdout=b"",
        stderr=b"exited abnormally",
    )
    assert result.success is False
    assert isinstance(result.error_exc, PluginSubprocessKilledError), (
        f"expected PluginSubprocessKilledError instance, got "
        f"{type(result.error_exc).__name__}"
    )
    # ForgeError subclass check — the load-bearing invariant for the
    # chaos harness's scenario 3.
    assert isinstance(result.error_exc, ForgeError)
    assert result.error_class == "forge.core.errors.PluginSubprocessKilledError"


def test_parse_process_result_success_leaves_error_exc_none() -> None:
    """A clean zero-exit / empty-stdout path MUST leave ``error_exc=None``.

    The success contract is unchanged from before the ``error_exc``
    field existed. Regression guard: a bug that populated ``error_exc``
    on success would confuse callers that do
    ``if result.error_exc is not None: ...`` for failure detection.
    """
    executor = _make_executor()
    result = executor._parse_process_result(
        tool_name="chaos_test",
        returncode=0,
        stdout=b"",
        stderr=b"",
    )
    assert result.success is True
    assert result.error_exc is None
    assert result.error_class is None


def test_parse_process_result_json_decode_error_carries_instance() -> None:
    """Non-JSON stdout on a zero-exit MUST carry a ``json.JSONDecodeError`` instance.

    The executor's JSON-parse branch is the second failure mode the
    scenario_plugin_sigkill invariant covers indirectly (a subprocess
    that exits 0 but emits garbage). Verify the instance is preserved
    so future scenarios can rely on it.
    """
    import json as _json

    executor = _make_executor()
    result = executor._parse_process_result(
        tool_name="chaos_test",
        returncode=0,
        stdout=b"not valid json {{{",
        stderr=b"",
    )
    assert result.success is False
    assert isinstance(result.error_exc, _json.JSONDecodeError)
    assert result.error_class == "json.JSONDecodeError"


# ---------------------------------------------------------------------------
# error_exc excluded from JSON serialisation
# ---------------------------------------------------------------------------


def test_plugin_result_model_dump_excludes_error_exc() -> None:
    """``error_exc`` MUST NOT appear in ``model_dump()`` output.

    The exception instance is a live Python object and cannot be
    serialised to JSON. Audit records and the chaos results artefact
    both round-trip via ``model_dump`` (or ``model_dump_json``), so
    including ``error_exc`` in the dump would either crash the
    serializer or produce a nonsense repr in the artefact. The field
    is explicitly excluded via ``Field(..., exclude=True)`` in
    ``forge/plugins/base.py``; this test guards against a future
    change that forgets that annotation.
    """
    exc = PluginSubprocessKilledError("test")
    result = PluginResult(
        success=False,
        output={},
        error="test",
        error_class="forge.core.errors.PluginSubprocessKilledError",
        error_exc=exc,
    )
    dumped = result.model_dump()
    assert "error_exc" not in dumped
    # But the in-memory attribute IS the exception.
    assert result.error_exc is exc


# ---------------------------------------------------------------------------
# execute() branch: original exception preserved through error_exc
# ---------------------------------------------------------------------------


class _AlwaysRaisesPlugin:
    """Duck-typed plugin whose ``execute`` raises a specific exception.

    Uses ``ExecutionMode.IN_PROCESS`` so the executor's ``_dispatch``
    invokes the plugin's own ``execute`` method directly (no subprocess
    spawn, no HTTP, no docker). The exception raised inside ``execute``
    hits the ``except Exception`` branch in ``PluginExecutor.execute``
    which builds the failure envelope with ``error_exc=exc``.
    """

    def __init__(self, exc: BaseException) -> None:
        self._exc = exc
        self._metadata = PluginMetadata(
            name="chaos_always_raises",
            version="1.0.0",
            capabilities=["chaos-raise"],
            execution_mode=ExecutionMode.IN_PROCESS,
            timeout_seconds=5,
            risk_level=RiskLevel.LOW,
        )

    @property
    def metadata(self) -> PluginMetadata:
        return self._metadata

    async def execute(self, params: dict[str, object]) -> PluginResult:
        raise self._exc

    async def health_check(self) -> bool:
        return True


def test_executor_execute_preserves_original_exception_instance() -> None:
    """A ``FileNotFoundError`` from ``execute`` MUST land in ``error_exc`` unchanged.

    This is the ``except Exception`` branch of ``PluginExecutor.execute``.
    Previously that branch discarded the exception after audit; the
    ``error_exc`` field now carries the original instance so callers can
    do structural checks on it. Regression guard for the promise made
    in ``PluginResult``'s docstring.
    """
    marker = FileNotFoundError("cannot find nmap on PATH")
    plugin = _AlwaysRaisesPlugin(marker)
    executor = _make_executor()

    async def _run() -> PluginResult:
        return await executor.execute(plugin, params={})

    try:
        result = asyncio.run(_run())
    finally:
        # Executor holds an HTTP client; close it so the loop can exit
        # cleanly on Windows (see the asyncio-shutdown warnings on
        # test_property_12_plugin_timeout under win32).
        asyncio.run(executor.close())

    assert result.success is False
    assert result.error_exc is marker, (
        "expected the original exception INSTANCE to be preserved, "
        f"got {result.error_exc!r}"
    )
    # ``error_class`` (string, for JSON transport) must agree.
    assert result.error_class == "builtins.FileNotFoundError"


def test_executor_execute_preserves_forge_error_instance() -> None:
    """A ``ForgeError`` subclass from ``execute`` MUST land in ``error_exc`` unchanged.

    The load-bearing case for the chaos harness's scenario 3: a plugin
    that raises a typed platform error surfaces via the failure
    envelope with a ForgeError instance in ``error_exc``, which the
    scenario checks with ``isinstance(..., ForgeError)``.
    """
    marker = PluginSubprocessKilledError("child killed externally")
    plugin = _AlwaysRaisesPlugin(marker)
    executor = _make_executor()

    async def _run() -> PluginResult:
        return await executor.execute(plugin, params={})

    try:
        result = asyncio.run(_run())
    finally:
        asyncio.run(executor.close())

    assert result.success is False
    assert result.error_exc is marker
    assert isinstance(result.error_exc, ForgeError)
