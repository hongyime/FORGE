"""Regression test for the ``FeedCandidate.__init__()`` signature bug.

The ``FeedCandidate`` dataclass in ``forge/automation_target_feed.py`` has a
required ``canonical_value`` field. A callsite inside the ``secrets_auto_feed``
block omitted it, producing::

    FeedCandidate.__init__() missing 1 required positional argument: 'canonical_value'

...which was swallowed by a surrounding ``try/except Exception`` and only surfaced
as ``source_errors`` in guarded-autostart cycle logs.

This test walks the AST of ``automation_target_feed.py`` and asserts every
``FeedCandidate(...)`` call passes ``canonical_value``. A regression at any
callsite fails the test with a specific line number.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
TARGET_MODULE = REPO_ROOT / "forge" / "automation_target_feed.py"


def _feed_candidate_calls() -> list[ast.Call]:
    """Return every ``FeedCandidate(...)`` call node in the module."""
    tree = ast.parse(TARGET_MODULE.read_text(encoding="utf-8"))
    return [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "FeedCandidate"
    ]


@pytest.mark.unit
def test_every_feed_candidate_call_passes_canonical_value() -> None:
    """Every ``FeedCandidate()`` call in automation_target_feed.py must supply canonical_value.

    Reproduces the runtime bug seen in the guarded-autostart cycle log:
    ``FeedCandidate.__init__() missing 1 required positional argument: 'canonical_value'``.
    """
    calls = _feed_candidate_calls()
    assert calls, (
        f"No FeedCandidate() calls found in {TARGET_MODULE} — has the module moved?"
    )
    missing: list[int] = []
    for call in calls:
        kwargs = {kw.arg for kw in call.keywords if kw.arg is not None}
        if "canonical_value" not in kwargs:
            missing.append(call.lineno)
    assert not missing, (
        f"FeedCandidate() calls at line(s) {missing} in {TARGET_MODULE.name} do not pass "
        f"the required 'canonical_value' keyword. Runtime raises TypeError; the surrounding "
        f"try/except silently swallows it and only surfaces as a source_errors entry in "
        f"guarded-autostart cycle logs."
    )
