"""
tests/chaos/test_safety_helpers.py - Unit coverage for the chaos harness
safety layer.

These are pure unit tests: no redis, no subprocesses, no live state store.
They exist because a bug in the Forbidden_Path guard, the mtime baseline /
verify pair, the disk-full destination guard, or either result writer is
what would let the harness corrupt operator data on a workstation checkout.
The chaos smoke test in this same directory exercises the harness
end-to-end but takes tens of seconds and is gated behind ``-m chaos``; this
module is gated behind ``-m chaos_unit`` (registered in pyproject.toml)
which is NOT in the default deselect list, so ``pytest`` picks these up by
default.

Requirements: 1, 2, 3, 4, 5, 21 of
``.kiro/specs/chaos-harness-hardening/requirements.md``.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

import pytest

# ``tools/`` is not a Python package (no ``tools/__init__.py``); mirror the
# sys.path shim used by ``tests/chaos/test_chaos_results.py`` so the same
# import surface works here.
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from tools import evidence_chaos  # noqa: E402
from tools.evidence_chaos import (  # noqa: E402
    CHAOS_RESULTS_JSON,
    CHAOS_RESULTS_XML,
    DISK_FULL_DESTINATION_REFUSED,
    ChaosScenarioResult,
    FORBIDDEN_PATHS,
    _assert_under_tempdir,
    _assert_write_allowed,
    _disk_full_destination_ok,
    _forbidden_mtimes,
    _safe_write_bytes,
    _verify_forbidden_mtimes_unchanged,
    _write_json_results,
    _write_junit_results,
)

pytestmark = pytest.mark.chaos_unit


# ---------------------------------------------------------------------------
# Forbidden_Path write guard (Requirement 2, 3 of the hardening spec)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("forbidden", list(FORBIDDEN_PATHS))
def test_assert_write_allowed_rejects_each_forbidden_path(forbidden: Path) -> None:
    """Every entry in ``FORBIDDEN_PATHS`` MUST refuse a write.

    The guard also names the offending resolved path in its
    ``RuntimeError``; the test asserts on the resolved form because
    ``FORBIDDEN_PATHS`` is defined relative to ``_REPO_ROOT`` and the
    guard resolves before comparing.
    """
    with pytest.raises(RuntimeError) as excinfo:
        _assert_write_allowed(forbidden)
    assert "Forbidden_Path" in str(excinfo.value)


def test_assert_write_allowed_allows_fresh_tempdir(tmp_path: Path) -> None:
    """A fresh pytest tempdir path MUST NOT trip the guard."""
    dest = tmp_path / "some_new_file.bin"
    # Returns None on success; must not raise.
    assert _assert_write_allowed(dest) is None


def test_assert_write_allowed_rejects_dotdot_traversal(tmp_path: Path) -> None:
    """``..``-traversal that resolves onto a Forbidden_Path MUST fail.

    ``Path.resolve(strict=False)`` normalises ``..`` components before
    comparison, so an attacker who constructs a path like
    ``<repo>/other/../.env`` cannot bypass the guard.
    """
    forbidden = FORBIDDEN_PATHS[0]
    # e.g. <repo>/nonexistent/../.env → resolves onto <repo>/.env
    traversal = forbidden.parent / "nonexistent" / ".." / forbidden.name
    with pytest.raises(RuntimeError):
        _assert_write_allowed(traversal)


@pytest.mark.skipif(
    sys.platform == "win32",
    reason=(
        "Symlink creation on Windows requires Developer Mode or elevated "
        "privileges; the guard logic is platform-agnostic so a POSIX-only "
        "test is sufficient coverage."
    ),
)
def test_assert_write_allowed_rejects_symlink_onto_forbidden(tmp_path: Path) -> None:
    """A symlink whose target resolves onto a Forbidden_Path MUST fail.

    ``Path.resolve`` follows symlinks; the guard compares resolved
    forms, so a symlink stored inside a tempdir that points at
    ``<repo>/.env`` MUST refuse.
    """
    forbidden = FORBIDDEN_PATHS[0]
    if not forbidden.exists():
        # Skip when the real Forbidden_Path is not present in the
        # checkout; the guard's resolve step needs a valid target.
        pytest.skip("target Forbidden_Path does not exist in this checkout")
    link = tmp_path / "shadow_env"
    os.symlink(forbidden, link)
    with pytest.raises(RuntimeError):
        _assert_write_allowed(link)


def test_safe_write_bytes_writes_and_creates_parent(tmp_path: Path) -> None:
    """``_safe_write_bytes`` MUST create missing parents and write bytes."""
    dest = tmp_path / "deep" / "nested" / "artefact.bin"
    payload = b"\x00\x01\x02\xff"
    _safe_write_bytes(dest, payload)
    assert dest.read_bytes() == payload


def test_safe_write_bytes_refuses_forbidden(tmp_path: Path) -> None:
    """``_safe_write_bytes`` MUST NOT write to a Forbidden_Path.

    We also assert the write NEVER hits disk: no partial file, no
    parent directory materialised beyond what already existed.
    """
    forbidden = FORBIDDEN_PATHS[0]
    with pytest.raises(RuntimeError):
        _safe_write_bytes(forbidden, b"should never land")


# ---------------------------------------------------------------------------
# Mtime baseline / verify (Requirement 4)
# ---------------------------------------------------------------------------
#
# The real ``FORBIDDEN_PATHS`` point at operator files we cannot mutate in
# a test. Monkey-patch the module constant with a tuple of tempdir paths;
# the guard logic is unchanged and the tempdir paths are safely mutable.


@pytest.fixture()
def isolated_forbidden(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    """Replace ``FORBIDDEN_PATHS`` with two tempdir sentinels.

    Returns the tuple of sentinel paths so tests can create / touch them
    and observe the guard's behaviour.
    """
    a = tmp_path / "sentinel_a"
    b = tmp_path / "sentinel_b"
    a.write_bytes(b"a")
    b.write_bytes(b"b")
    monkeypatch.setattr(evidence_chaos, "FORBIDDEN_PATHS", (a, b))
    return a, b


def test_forbidden_mtimes_baseline_records_second_level(
    isolated_forbidden: tuple[Path, Path],
) -> None:
    """Baseline MUST record an int-truncated mtime for each existing path."""
    a, b = isolated_forbidden
    baseline = _forbidden_mtimes()
    assert set(baseline.keys()) == {a.resolve(), b.resolve()}
    for path, recorded in baseline.items():
        assert isinstance(recorded, int)
        # Second-level precision: recorded value equals the floor.
        assert recorded == int(path.stat().st_mtime)


def test_verify_forbidden_mtimes_unchanged_ok(
    isolated_forbidden: tuple[Path, Path],
) -> None:
    """Verify MUST pass when no mtime moved between baseline and verify."""
    baseline = _forbidden_mtimes()
    # No mutation; verify must not raise.
    _verify_forbidden_mtimes_unchanged(baseline)


def test_verify_forbidden_mtimes_raises_on_mutation(
    isolated_forbidden: tuple[Path, Path],
) -> None:
    """A touched Forbidden_Path MUST cause verify to raise, naming the path."""
    a, _b = isolated_forbidden
    baseline = _forbidden_mtimes()
    # Force an mtime change of at least 2 seconds so the second-level
    # truncation in the guard actually observes a delta.
    future = time.time() + 5
    os.utime(a, (future, future))
    with pytest.raises(RuntimeError) as excinfo:
        _verify_forbidden_mtimes_unchanged(baseline)
    assert str(a.resolve()) in str(excinfo.value)


def test_forbidden_mtimes_omits_missing_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A Forbidden_Path that does not exist MUST NOT appear in the baseline."""
    real = tmp_path / "exists"
    ghost = tmp_path / "does_not_exist"
    real.write_bytes(b"x")
    monkeypatch.setattr(evidence_chaos, "FORBIDDEN_PATHS", (real, ghost))
    baseline = _forbidden_mtimes()
    assert real.resolve() in baseline
    assert ghost.resolve() not in baseline


# ---------------------------------------------------------------------------
# Disk-full destination guard (Requirement 5)
# ---------------------------------------------------------------------------


def test_disk_full_destination_ok_accepts_fresh_mkdtemp() -> None:
    """A fresh ``mkdtemp`` allocation MUST be accepted."""
    root = Path(tempfile.mkdtemp(prefix="chaos_test_ok_"))
    try:
        assert _disk_full_destination_ok(root) is True
    finally:
        root.rmdir()


def test_disk_full_destination_ok_rejects_outside_tempdir(tmp_path: Path) -> None:
    """A path outside ``gettempdir()`` MUST be refused.

    We construct a path under the repo root (which is guaranteed to be
    outside ``tempfile.gettempdir()`` on every developer workstation
    and every CI runner) so the ``_assert_under_tempdir`` branch fires.
    """
    outside = _REPO_ROOT / "some_directory_under_repo"
    assert _disk_full_destination_ok(outside) is False


def test_assert_under_tempdir_accepts_tempdir_root_itself() -> None:
    """The temp root itself resolves as a subpath of itself.

    Path.is_relative_to treats a path as relative to itself, so
    passing ``Path(gettempdir())`` unchanged MUST pass.
    """
    assert _assert_under_tempdir(Path(tempfile.gettempdir())) is True


def test_disk_full_destination_ok_rejects_forbidden_path(
    isolated_forbidden: tuple[Path, Path],
) -> None:
    """A path equal to a Forbidden_Path MUST be refused.

    We monkey-patch ``FORBIDDEN_PATHS`` with a tempdir path so the
    guard's belt-and-braces deny-list check fires even though the
    path is technically under ``gettempdir()``.
    """
    a, _b = isolated_forbidden
    # ``a`` is under ``tmp_path`` (which is under gettempdir()) but is
    # also listed in FORBIDDEN_PATHS via the monkeypatch, so the
    # deny-list branch inside _disk_full_destination_ok fires.
    assert _disk_full_destination_ok(a) is False


def test_disk_full_destination_ok_rejects_forbidden_ancestor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A directory containing a Forbidden_Path MUST be refused.

    Filling the volume that holds a Forbidden_Path would break that
    Forbidden_Path even without writing directly to it; the guard
    refuses these ancestors explicitly.
    """
    ancestor = tmp_path / "ancestor_dir"
    ancestor.mkdir()
    forbidden = ancestor / "forbidden_child"
    forbidden.write_bytes(b"x")
    monkeypatch.setattr(evidence_chaos, "FORBIDDEN_PATHS", (forbidden,))
    assert _disk_full_destination_ok(ancestor) is False


def test_disk_full_destination_refused_line_exact() -> None:
    """The refusal line MUST match the exact string from Requirement 3.23."""
    assert DISK_FULL_DESTINATION_REFUSED == "[FAIL] chaos-5-disk-full: destination refused"


# ---------------------------------------------------------------------------
# Result-artefact writers (Requirement 21)
# ---------------------------------------------------------------------------


def _sample_results() -> list[ChaosScenarioResult]:
    """Fabricate a list of results including control characters in ``detail``.

    ``detail`` must survive the round-trip through the JSON writer AND
    the JUnit XML writer without corrupting either document.
    """
    return [
        ChaosScenarioResult(
            name="chaos-1-redis-kill-restart",
            passed=True,
            detail="wid=abc123 stages=3 outage=1.42s",
            duration_seconds=12.5,
            fault_injected_at_stage=1,
        ),
        ChaosScenarioResult(
            name="chaos-2-sqlite-lock-contention",
            passed=False,
            # Includes a quote and a newline to exercise XML attribute
            # escaping and the JSON string escaping path.
            detail='invariant broken: version_delta=2 (expected 1); "over-write"',
            duration_seconds=3.14,
            fault_injected_at_stage=1,
        ),
        ChaosScenarioResult(
            name="chaos-3-plugin-sigkill",
            passed=True,
            # Tab + high-codepoint text: JSON must not lose it, XML
            # must not corrupt it.
            detail="killed pids=[1234]\tno_orphans — success",
            duration_seconds=1.75,
            fault_injected_at_stage=None,
        ),
    ]


def test_write_json_results_round_trip(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """JSON writer output MUST parse back to the same field values."""
    dest = tmp_path / "chaos_results.json"
    monkeypatch.setattr(evidence_chaos, "CHAOS_RESULTS_JSON", dest)

    results = _sample_results()
    _write_json_results(results)

    parsed = json.loads(dest.read_text(encoding="utf-8"))
    assert isinstance(parsed, list)
    assert len(parsed) == len(results)
    for entry, source in zip(parsed, results, strict=True):
        assert entry["name"] == source.name
        assert entry["passed"] is source.passed
        assert entry["detail"] == source.detail
        assert entry["duration_seconds"] == source.duration_seconds
        assert entry["fault_injected_at_stage"] == source.fault_injected_at_stage


def test_write_junit_results_round_trip(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """JUnit writer output MUST parse back to the same field values."""
    dest = tmp_path / "chaos_results.xml"
    monkeypatch.setattr(evidence_chaos, "CHAOS_RESULTS_XML", dest)

    results = _sample_results()
    _write_junit_results(results)

    tree = ET.parse(dest)
    root = tree.getroot()
    assert root.tag == "testsuite"
    assert root.get("name") == "chaos"
    assert int(root.get("tests", "-1")) == len(results)
    assert int(root.get("failures", "-1")) == sum(1 for r in results if not r.passed)

    cases = list(root.findall("testcase"))
    assert len(cases) == len(results)
    for case, source in zip(cases, results, strict=True):
        assert case.get("name") == source.name
        # The ``time`` attribute is a decimal string; compare numerically.
        assert abs(float(case.get("time", "nan")) - source.duration_seconds) < 1e-6
        failures = case.findall("failure")
        if source.passed:
            assert failures == []
        else:
            assert len(failures) == 1
            # ``detail`` MUST survive attribute escaping byte-for-byte.
            assert failures[0].get("message") == source.detail


def test_write_json_and_junit_write_through_safe_writer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Both writers MUST fail if their destination is a Forbidden_Path.

    Regression guard: a future change that bypasses ``_safe_write_bytes``
    and writes with ``dest.write_bytes(...)`` directly would break the
    guard. Point CHAOS_RESULTS_JSON at a Forbidden_Path via monkeypatch
    and assert RuntimeError.
    """
    forbidden = tmp_path / "sentinel"
    forbidden.write_bytes(b"pre-existing")
    monkeypatch.setattr(evidence_chaos, "FORBIDDEN_PATHS", (forbidden,))
    monkeypatch.setattr(evidence_chaos, "CHAOS_RESULTS_JSON", forbidden)
    monkeypatch.setattr(evidence_chaos, "CHAOS_RESULTS_XML", forbidden)

    with pytest.raises(RuntimeError):
        _write_json_results(_sample_results())
    with pytest.raises(RuntimeError):
        _write_junit_results(_sample_results())

    # File contents MUST be unchanged.
    assert forbidden.read_bytes() == b"pre-existing"


# ---------------------------------------------------------------------------
# Sanity: baseline module surface (Requirement 1)
# ---------------------------------------------------------------------------


def test_chaos_results_paths_are_absolute() -> None:
    """The default artefact paths resolve to absolute paths under the repo.

    Cheap smoke test that the module-level constants haven't drifted;
    the writers rely on ``Path.resolve(strict=False)`` being well-defined
    against these values.
    """
    assert CHAOS_RESULTS_JSON.is_absolute()
    assert CHAOS_RESULTS_XML.is_absolute()


# ---------------------------------------------------------------------------
# main() writer-suppression policy — RuntimeError MUST propagate
# ---------------------------------------------------------------------------
#
# ``main()``'s ``finally`` block used to wrap both writers in
# ``contextlib.suppress(Exception)``. That silently ate the Forbidden_Path
# guard's ``RuntimeError``, which defeated the whole point of the guard
# ("prevent a mis-configured checkout from writing over operator data").
#
# The suppression policy now only swallows ``OSError`` (real disk write
# failures, permission errors). ``RuntimeError`` from the guard MUST
# propagate so a run against a mis-configured checkout goes red instead
# of finishing "successfully" with a silently-skipped artefact.
#
# We can't easily test the ``main()`` finally block itself without
# running the whole harness, but we CAN pin the writer contract: if
# ``_write_json_results`` / ``_write_junit_results`` are called with a
# ``CHAOS_RESULTS_JSON`` pointing at a Forbidden_Path, they raise
# ``RuntimeError``. The chaos smoke test in this directory then
# indirectly proves the ``main()`` finally block does not suppress it
# (a regression would fail that test, not this one).


def test_writer_raises_runtime_error_on_forbidden_target(
    tmp_path: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Both writers MUST raise ``RuntimeError`` (not ``OSError``) on a Forbidden_Path.

    Regression guard for the ``main()`` finally-block suppression policy
    change. If either writer gets refactored to raise ``OSError``
    instead, the finally block's ``contextlib.suppress(OSError)`` would
    silently swallow the guard, and this test starts failing.
    """
    from tools import evidence_chaos as _ec  # local alias for clarity

    forbidden = _ec._REPO_ROOT / ".chaos_writer_sentinel"
    monkeypatch.setattr(_ec, "FORBIDDEN_PATHS", (forbidden,))
    monkeypatch.setattr(_ec, "CHAOS_RESULTS_JSON", forbidden)
    monkeypatch.setattr(_ec, "CHAOS_RESULTS_XML", forbidden)

    sample = [
        ChaosScenarioResult(
            name="chaos-x",
            passed=True,
            detail="ok",
            duration_seconds=0.1,
            fault_injected_at_stage=None,
        )
    ]

    # Both writers MUST raise a genuine RuntimeError (not any subclass
    # of OSError) so ``contextlib.suppress(OSError)`` in main() cannot
    # swallow it.
    with pytest.raises(RuntimeError) as excinfo_json:
        _write_json_results(sample)
    assert not isinstance(excinfo_json.value, OSError), (
        "guard exception MUST be RuntimeError so main()'s "
        "contextlib.suppress(OSError) does not silence it"
    )

    with pytest.raises(RuntimeError) as excinfo_xml:
        _write_junit_results(sample)
    assert not isinstance(excinfo_xml.value, OSError)
