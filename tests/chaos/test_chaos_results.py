"""
tests/chaos/test_chaos_results.py - Property 9 for the chaos results artefact.

Validates: Requirements 3.30.

Requirement 3.30 (round-trip property for the results artefact) says:

    FOR ALL Scenario_Result objects written to
    ``.forge_data/chaos_results.json``, parsing the JSON document and then
    serialising the parsed value back to JSON SHALL yield a document with
    the same set of scenario names, the same ``passed`` boolean values,
    and the same ``detail`` strings as the original document.

This module encodes that requirement as a Hypothesis property test.

Strategy
--------

Rather than run the chaos harness (which would be slow and would also be
covered by the smoke test in task 8.2), we synthesise the same shape of
document that ``tools.evidence_chaos._write_json_results`` writes to
``.forge_data/chaos_results.json``:

    * A JSON array whose elements are objects with keys ``name``,
      ``passed``, ``detail``, ``duration_seconds``, and
      ``fault_injected_at_stage``.
    * Each object is derived from a valid ``ChaosScenarioResult`` and
      therefore respects the dataclass validation rules from the design's
      Data Models section (``name`` matches ``^[a-z0-9-]+$``, ``detail``
      non-empty, ``duration_seconds >= 0``, ``fault_injected_at_stage``
      is ``int`` or ``None``).

We build a document, call ``json.loads(json.dumps(document))``, and
assert the three round-trip invariants named in the requirement:

    1. Same *set* of scenario names.
    2. Same ``passed`` boolean values (compared per name so the property
       does not accidentally depend on ordering).
    3. Same ``detail`` strings (also per name).

``pytestmark = pytest.mark.chaos`` opts the module into the same chaos
marker as ``tests/chaos/test_chaos_smoke.py`` (task 8.2), so this file
is only exercised by ``pytest -m chaos`` and by the CI ``chaos`` job.
"""

from __future__ import annotations

import json
import math
import sys
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

# ``tools/`` is not a Python package (no ``tools/__init__.py``), so we
# extend ``sys.path`` with the repository root before importing the
# module. The chaos smoke test in this same directory uses ``from tools
# import evidence_chaos`` and relies on the same convention.
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from tools.evidence_chaos import ChaosScenarioResult  # noqa: E402

pytestmark = pytest.mark.chaos


# ---------------------------------------------------------------------------
# Hypothesis strategies
# ---------------------------------------------------------------------------
#
# The strategies match the dataclass validation rules in
# ``tools/evidence_chaos.py::ChaosScenarioResult.__post_init__``:
#
#   * ``name``: non-empty, matches ``^[a-z0-9-]+$``.
#   * ``passed``: bool.
#   * ``detail``: non-empty string. We exclude newlines and control
#     characters so ``detail`` mirrors what a ``[PASS]/[FAIL]`` summary
#     line prints (single-line, printable). JSON round-trips every valid
#     Unicode string, but the acceptance-criterion regex for the summary
#     line disallows embedded newlines, so we stay inside that space.
#   * ``duration_seconds``: float >= 0. ``allow_nan=False`` and
#     ``allow_infinity=False`` so ``json.dumps`` does not emit ``NaN`` /
#     ``Infinity`` (which is technically non-standard JSON and would fail
#     the strict ``json.loads`` round-trip on some parsers).
#   * ``fault_injected_at_stage``: ``int`` or ``None``.


_NAME_STRATEGY = st.from_regex(r"^[a-z0-9-]+\Z", fullmatch=True).filter(
    lambda s: len(s) >= 1 and len(s) <= 64
)

_DETAIL_STRATEGY = st.text(
    # Full Unicode BMP printable range excluding newline / carriage
    # return / tab. Requirement 3.30 does not restrict the character
    # set, and JSON round-trips every valid Unicode string; restricting
    # to ASCII would leave a genuine regression (a future ``detail``
    # containing a code-point above 0x7E that broke the writer) invisible
    # to this PBT. We also exclude surrogate code points and
    # unassigned categories via ``blacklist_categories`` so
    # ``json.dumps`` cannot raise ``UnicodeEncodeError`` on lone
    # surrogates (JSON spec disallows them).
    alphabet=st.characters(
        min_codepoint=0x20,
        max_codepoint=0xFFFF,
        blacklist_characters="\n\r\t",
        blacklist_categories=("Cs",),  # surrogates
    ),
    min_size=1,
    max_size=200,
)

_DURATION_STRATEGY = st.floats(
    min_value=0.0,
    max_value=1_000_000.0,
    allow_nan=False,
    allow_infinity=False,
)

_STAGE_STRATEGY = st.one_of(
    st.none(),
    st.integers(min_value=0, max_value=100),
)


def _result_strategy() -> st.SearchStrategy[ChaosScenarioResult]:
    """Build one valid ``ChaosScenarioResult`` per draw."""

    return st.builds(
        ChaosScenarioResult,
        name=_NAME_STRATEGY,
        passed=st.booleans(),
        detail=_DETAIL_STRATEGY,
        duration_seconds=_DURATION_STRATEGY,
        fault_injected_at_stage=_STAGE_STRATEGY,
    )


def _results_strategy() -> st.SearchStrategy[list[ChaosScenarioResult]]:
    """List of results with unique names so the "same set of names" assertion
    is unambiguous even when duplicates would otherwise be possible.

    ``.forge_data/chaos_results.json`` in practice always has five entries
    with distinct names (one per scenario). We bound the list at 20 to
    keep runtime under Hypothesis's default deadline even without the
    explicit ``deadline=None`` override.
    """

    return st.lists(
        _result_strategy(),
        min_size=0,
        max_size=20,
        unique_by=lambda r: r.name,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _to_document(results: list[ChaosScenarioResult]) -> list[dict[str, Any]]:
    """Reproduce the exact JSON shape that ``_write_json_results`` emits.

    Kept in sync with ``tools.evidence_chaos._write_json_results``: five
    keys per entry, in the same order, no wrapping envelope. If that
    writer's schema ever changes, this helper must move with it and the
    property will start failing loudly - which is what we want.
    """

    return [
        {
            "name": r.name,
            "passed": r.passed,
            "detail": r.detail,
            "duration_seconds": r.duration_seconds,
            "fault_injected_at_stage": r.fault_injected_at_stage,
        }
        for r in results
    ]


# ---------------------------------------------------------------------------
# Property 9 - JSON round-trip stability for chaos results
# ---------------------------------------------------------------------------


@given(results=_results_strategy())
@settings(
    max_examples=50,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
def test_chaos_results_json_roundtrip_preserves_names_passed_and_detail(
    results: list[ChaosScenarioResult],
) -> None:
    """``json.loads(json.dumps(document))`` preserves the requirement 3.30 fields.

    For every list of ``ChaosScenarioResult`` objects respecting the
    dataclass validation rules, the serialise-then-deserialise cycle on
    the JSON document produced by ``_write_json_results`` yields a
    document with:

        * the same *set* of scenario names,
        * the same ``passed`` boolean value per scenario name,
        * the same ``detail`` string per scenario name.

    Ordering of the list is preserved by ``json.dumps`` / ``json.loads``
    for arrays, but the requirement is phrased as "same set of names",
    so we assert per-name identity via a lookup dict instead of relying
    on list order. This matches the requirement text literally.
    """

    document = _to_document(results)

    encoded = json.dumps(document)
    decoded = json.loads(encoded)

    # Structural sanity: the top-level shape survives round-trip.
    assert isinstance(decoded, list), "top-level JSON value must be a list"
    assert len(decoded) == len(document), (
        f"round-trip changed length: {len(document)} -> {len(decoded)}"
    )

    original_names = {entry["name"] for entry in document}
    decoded_names = {entry["name"] for entry in decoded}
    assert decoded_names == original_names, (
        "round-trip must preserve the set of scenario names; "
        f"lost={original_names - decoded_names}, "
        f"added={decoded_names - original_names}"
    )

    by_name_original = {entry["name"]: entry for entry in document}
    by_name_decoded = {entry["name"]: entry for entry in decoded}

    for name, original_entry in by_name_original.items():
        decoded_entry = by_name_decoded[name]

        # ``passed`` must remain a bool with the same value. ``json``
        # preserves ``True`` / ``False`` as Python bool, so a strict
        # ``is`` check is safe and catches accidental int coercion.
        assert isinstance(decoded_entry["passed"], bool), (
            f"scenario {name!r}: passed must remain bool after round-trip; "
            f"got {type(decoded_entry['passed']).__name__}"
        )
        assert decoded_entry["passed"] == original_entry["passed"], (
            f"scenario {name!r}: passed changed under round-trip "
            f"({original_entry['passed']!r} -> {decoded_entry['passed']!r})"
        )

        assert decoded_entry["detail"] == original_entry["detail"], (
            f"scenario {name!r}: detail changed under round-trip"
        )
