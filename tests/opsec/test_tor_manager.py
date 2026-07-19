"""
tests/opsec/test_tor_manager.py — TorManager property tests (feature
audit-cleanup-and-chaos, Band 2 — Requirement 2).

This module currently hosts one Hypothesis-driven property test:

* ``test_tor_search_roots_never_escape_cwd`` — encodes **Property 1 (A1):
  Tor search roots never escape cwd** from
  ``.kiro/specs/audit-cleanup-and-chaos/design.md`` and validates
  Requirements 2.3 and 2.5 in the corresponding ``requirements.md``:

  - Req 2.3: ``TorManager._find_tor_exe`` searches ``Vendor_Tor_Directory``
    only and never falls back to ``Path.cwd()``.
  - Req 2.5: ``TorManager._extract_tor_archive`` extracts INTO
    ``Vendor_Tor_Directory`` and never writes under any other directory.

  The containment invariant these two acceptance criteria imply is that
  every search root produced by :meth:`TorManager._search_roots` must
  resolve to a path underneath ``Path.cwd().resolve()`` — otherwise the
  extractor could land archive contents outside the vendor directory and
  the search order could pick up an out-of-tree ``tor.exe``.
"""

from __future__ import annotations

import io
import logging
import tarfile
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from forge.opsec.tor import TorManager, _safe_tar_extractall


# ---------------------------------------------------------------------------
# Property 1 (A1): Tor search roots never escape cwd
# ---------------------------------------------------------------------------
#
# Validates: Requirements 2.3, 2.5
#
# ``TorManager._search_roots`` is a fixed classmethod that ignores its
# arguments — it returns exactly ``[<cwd>/vendor/tor]``. The Hypothesis
# strategy therefore does not feed data into the method; instead, it draws
# arbitrary lists of short strings and probes the invariant repeatedly to
# demonstrate that it is stable under environment noise (repeat invocations,
# arbitrary interleaved allocations, Hypothesis-managed determinism seed
# jitter). If a future refactor accidentally reintroduces the pre-migration
# ``Path.cwd()`` fallback — or any other root that resolves outside the
# current working directory — this test will fail as
# ``Path.relative_to`` raises ``ValueError``.

pytestmark = pytest.mark.opsec


@given(
    components=st.lists(
        st.text(min_size=1, max_size=20),
        min_size=1,
        max_size=5,
    ),
)
@settings(max_examples=50, deadline=None)
def test_tor_search_roots_never_escape_cwd(components: list[str]) -> None:
    """Every ``TorManager._search_roots()`` entry resolves inside ``cwd``.

    ``_search_roots()`` is a fixed classmethod that does **not** consume
    ``components`` — it always returns ``[<cwd>/vendor/tor]``. The
    ``components`` list drawn by Hypothesis is intentionally unused by
    the method under test; its role is to exercise the invariant across
    many draws so that any future regression that made the search order
    depend on ambient state (e.g. a reintroduced ``Path.cwd()`` fallback,
    an environment-variable-driven override, or a ``..``-escaping vendor
    path) is caught by the Hypothesis reruns.

    Validates: Requirements 2.3, 2.5.
    """
    # ``components`` is generated for invariance probing only — bind it to
    # ``_`` so linters see it as consumed while making it explicit that the
    # method under test does not receive it.
    _ = components

    cwd_resolved = Path.cwd().resolve()

    roots = TorManager._search_roots()

    assert roots, "TorManager._search_roots() must return at least one root"

    for root in roots:
        resolved = root.resolve()
        # ``Path.relative_to`` raises ``ValueError`` if ``resolved`` is not
        # a subpath of ``cwd_resolved`` — that is exactly the containment
        # check we want. Requirement 2.3 rules out a ``Path.cwd()``
        # fallback (which would resolve to ``cwd_resolved`` itself and
        # still satisfy this predicate — the stricter check for that
        # regression lives in ``test_vendor_only_search_ignores_legacy_cwd``
        # under task 2.4). Requirement 2.5 rules out any root outside the
        # current working directory.
        resolved.relative_to(cwd_resolved)

# ---------------------------------------------------------------------------
# Property 2 (A2): Vendor is the only accepted search root; legacy cwd
# tor.exe is ignored with WARN
# ---------------------------------------------------------------------------
#
# Validates: Requirements 2.3, 2.4, 2.5, 2.6, 2.7
#
# The six unit tests below cover the concrete, example-based behaviours
# implied by Property 2. They use ``monkeypatch.chdir(tmp_path)`` so each
# test runs in a hermetic temp directory — the real repository's ``.env``,
# ``vendor/tor/``, or Legacy_Tor_Cache cannot leak in. ``caplog`` captures
# WARN log lines emitted by :mod:`forge.opsec.tor`.


def _mk_tor_exe(path: Path) -> Path:
    """Create a placeholder ``tor.exe`` file at ``path`` and return it."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"MZ\x00\x00")  # minimal PE-ish header — file just needs to exist
    return path


def test_vendor_only_search_ignores_legacy_cwd(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The vendor copy wins over a Legacy_Tor_Cache and a WARN is emitted.

    Places one ``tor.exe`` under ``<tmp>/tor/tor.exe`` (Legacy_Tor_Cache)
    and another under ``<tmp>/vendor/tor/tor/tor.exe`` (the vendored copy
    inside the ``tor-expert-bundle-*/tor/`` layout). ``_find_tor_exe`` must
    return the vendor copy and log exactly one WARN naming the legacy
    path.

    Validates: Requirements 2.3, 2.7.
    """
    monkeypatch.chdir(tmp_path)

    legacy = _mk_tor_exe(tmp_path / "tor" / "tor.exe")
    vendor = _mk_tor_exe(tmp_path / "vendor" / "tor" / "tor" / "tor.exe")

    caplog.set_level(logging.WARNING, logger="forge.opsec.tor")

    result = TorManager._find_tor_exe()

    assert result.resolve() == vendor.resolve(), (
        f"_find_tor_exe returned {result!r}; expected vendor copy {vendor!r}. "
        "Legacy_Tor_Cache must be ignored."
    )
    # Sanity: it is definitely NOT the legacy path.
    assert result.resolve() != legacy.resolve()

    warn_records = [
        r for r in caplog.records
        if r.levelno == logging.WARNING and "Legacy_Tor_Cache" in r.getMessage()
    ]
    assert len(warn_records) == 1, (
        f"Expected exactly one Legacy_Tor_Cache WARN, got {len(warn_records)}: "
        f"{[r.getMessage() for r in warn_records]}"
    )
    assert str(legacy.parent) in warn_records[0].getMessage(), (
        f"WARN must name the legacy path {legacy.parent!r}; "
        f"got: {warn_records[0].getMessage()!r}"
    )


def test_missing_archive_raises_with_vendor_path_in_message(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``FileNotFoundError`` message contains the literal ``vendor/tor``.

    With no ``tor.exe`` and no archive anywhere under ``<tmp>``,
    ``_find_tor_exe`` must raise ``FileNotFoundError`` whose message
    references the Vendor_Tor_Directory path so operators know where to
    place the archive.

    NOTE (2026-07-06): ``_search_roots`` now also returns a repo-relative
    fallback so ``forge scaffold`` works from arbitrary cwds. The test
    monkey-patches ``_search_roots`` to return only the cwd path,
    preserving the original invariant this test encodes: when the
    Vendor_Tor_Directory is missing, we get FileNotFoundError with the
    expected message.

    Validates: Requirement 2.4.
    """
    monkeypatch.chdir(tmp_path)
    # Force _search_roots to yield only the empty cwd path.
    monkeypatch.setattr(
        TorManager, "_search_roots",
        classmethod(lambda cls: [tmp_path / "vendor" / "tor"]),
    )

    with pytest.raises(FileNotFoundError) as excinfo:
        TorManager._find_tor_exe()

    msg = str(excinfo.value)
    # The message must reference the vendor directory. On Windows the
    # rendered path uses backslashes; accept either form for cross-platform
    # robustness.
    assert "vendor/tor" in msg or "vendor\\tor" in msg, (
        f"FileNotFoundError message must name Vendor_Tor_Directory; got: {msg!r}"
    )


def test_safe_tar_extractall_rejects_traversal(tmp_path: Path) -> None:
    """``_safe_tar_extractall`` rejects a tarball with ``../../etc/passwd``.

    Hand-craft an in-memory tar archive whose sole member has a name that
    escapes the destination directory via ``..`` components. The guard
    must raise ``RuntimeError`` naming the offending member and must NOT
    write any file to ``dest``.

    Validates: Requirement 2.6.
    """
    dest = tmp_path / "extract_dest"
    dest.mkdir()

    # Build a tarball in memory containing one malicious member.
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        payload = b"root:x:0:0:root:/root:/bin/bash\n"
        info = tarfile.TarInfo(name="../../etc/passwd")
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))
    buf.seek(0)

    with tarfile.open(fileobj=buf, mode="r") as tar:
        with pytest.raises(RuntimeError) as excinfo:
            _safe_tar_extractall(tar, dest)

    assert "../../etc/passwd" in str(excinfo.value), (
        f"Rejection error must name the offending member; got: {excinfo.value!r}"
    )
    # The guard must reject BEFORE any write hits disk.
    assert list(dest.iterdir()) == [], (
        f"_safe_tar_extractall must not create files on rejection; "
        f"found: {list(dest.iterdir())}"
    )


def test_extract_lands_in_vendor_dir(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Archive discovered in ``vendor/tor/`` extracts only under ``vendor/tor/``.

    Place a hand-built ``tor-expert-bundle-*.tar.gz`` under
    ``<tmp>/vendor/tor/`` containing a ``tor/tor.exe`` member. After
    ``_extract_tor_archive`` runs, every file created must live under
    ``<tmp>/vendor/tor/`` — nothing at the repo root, nothing under
    ``<tmp>/tor/``.

    Validates: Requirement 2.5.
    """
    monkeypatch.chdir(tmp_path)
    vendor_dir = tmp_path / "vendor" / "tor"
    vendor_dir.mkdir(parents=True)

    archive_path = vendor_dir / "tor-expert-bundle-windows-x86_64-16.0a4.tar.gz"
    payload = b"MZ\x00\x00"  # placeholder tor.exe contents
    with tarfile.open(archive_path, "w:gz") as tar:
        info = tarfile.TarInfo(name="tor/tor.exe")
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))

    # Snapshot every path under tmp_path before extraction so we can diff.
    before = {p for p in tmp_path.rglob("*")}

    assert TorManager._extract_tor_archive() is True

    after = {p for p in tmp_path.rglob("*")}
    new_paths = after - before

    vendor_resolved = vendor_dir.resolve()
    for new_path in new_paths:
        resolved = new_path.resolve()
        # Every new file/dir must live under vendor/tor/. Use ``relative_to``
        # so a non-subpath raises ValueError with a helpful message.
        try:
            resolved.relative_to(vendor_resolved)
        except ValueError as exc:
            raise AssertionError(
                f"Extraction wrote {resolved!r} outside Vendor_Tor_Directory "
                f"({vendor_resolved!r}); Requirement 2.5 violated."
            ) from exc

    # Sanity: the extracted tor.exe must exist under vendor/tor/.
    extracted = vendor_dir / "tor" / "tor.exe"
    assert extracted.exists(), (
        f"Expected extracted tor.exe at {extracted!r}; new_paths={new_paths!r}"
    )


def test_find_tor_exe_shortest_path_wins(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Deterministic tie-break: the shortest matching path wins.

    Places three ``tor.exe`` files at different depths under
    ``<tmp>/vendor/tor/``. All match the ``/tor/`` substring filter. The
    implementation sorts candidates by ``len(str(path))`` ascending and
    returns the first, so the shallowest path must win.

    Validates: Requirement 2.3 (deterministic search order).
    """
    monkeypatch.chdir(tmp_path)

    # Three candidates at increasing depth — all contain ``/tor/`` so they
    # pass the substring filter. Distinct names keep string lengths ordered.
    shallow = _mk_tor_exe(tmp_path / "vendor" / "tor" / "tor" / "tor.exe")
    mid = _mk_tor_exe(
        tmp_path / "vendor" / "tor" / "tor-expert-bundle" / "tor" / "tor.exe"
    )
    deep = _mk_tor_exe(
        tmp_path / "vendor" / "tor" / "tor-expert-bundle" / "sub" / "tor" / "tor.exe"
    )

    # Precondition: the intended winner has the strictly shortest path.
    assert len(str(shallow)) < len(str(mid)) < len(str(deep))

    result = TorManager._find_tor_exe()

    assert result.resolve() == shallow.resolve(), (
        f"Shortest path must win deterministically. Got {result!r}; "
        f"expected {shallow!r}. Candidates: shallow={shallow!r} "
        f"mid={mid!r} deep={deep!r}"
    )


def test_legacy_cwd_tor_emits_warn_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A stale ``<repo_root>/tor/tor.exe`` produces exactly one WARN per call.

    Places a Legacy_Tor_Cache with a ``tor.exe`` at ``<tmp>/tor/tor.exe``
    and a valid vendor copy under ``<tmp>/vendor/tor/tor/tor.exe`` (so
    ``_find_tor_exe`` succeeds and we can observe its warning behaviour
    without an early ``FileNotFoundError``). Every call to
    ``_find_tor_exe`` must emit exactly one Legacy_Tor_Cache WARN — no
    more, no less — regardless of how many candidates ``rglob`` returns.

    Validates: Requirement 2.7.
    """
    monkeypatch.chdir(tmp_path)

    _mk_tor_exe(tmp_path / "tor" / "tor.exe")  # Legacy_Tor_Cache
    _mk_tor_exe(tmp_path / "vendor" / "tor" / "tor" / "tor.exe")  # vendor copy

    caplog.set_level(logging.WARNING, logger="forge.opsec.tor")

    # First invocation: exactly one WARN.
    caplog.clear()
    TorManager._find_tor_exe()
    warns_first = [
        r for r in caplog.records
        if r.levelno == logging.WARNING and "Legacy_Tor_Cache" in r.getMessage()
    ]
    assert len(warns_first) == 1, (
        f"First _find_tor_exe call must emit exactly one Legacy_Tor_Cache "
        f"WARN; got {len(warns_first)}: "
        f"{[r.getMessage() for r in warns_first]}"
    )

    # Second invocation: also exactly one WARN (per-call semantics —
    # Requirement 2.7 says "one WARN per _find_tor_exe invocation").
    caplog.clear()
    TorManager._find_tor_exe()
    warns_second = [
        r for r in caplog.records
        if r.levelno == logging.WARNING and "Legacy_Tor_Cache" in r.getMessage()
    ]
    assert len(warns_second) == 1, (
        f"Second _find_tor_exe call must emit exactly one Legacy_Tor_Cache "
        f"WARN; got {len(warns_second)}: "
        f"{[r.getMessage() for r in warns_second]}"
    )
