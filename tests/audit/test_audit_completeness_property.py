"""
tests/audit/test_audit_completeness_property.py — Property test for audit log completeness.

Validates Property 22 (Requirements 7.1): for any sequence of N AuditEntry
instances logged through AuditLogger.log(), all N entries SHALL appear in the
resulting log in the same order — no events are dropped.

Diverse AuditEntry inputs are generated via Hypothesis: varying event_type,
agent_role, tool_name, input_params shape (including nested dicts and
secret-like keys), success/failure flags, and durations.

Note: AuditLogger redacts secret-like keys in ``input_params`` on append. The
completeness property therefore compares the structural identity of each
persisted entry against its input on every field except ``input_params``,
while still asserting that ``input_params`` is present iff it was provided
and that its top-level key set is preserved.
"""

from __future__ import annotations

import asyncio

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from forge.audit.logger import AuditLogger
from forge.audit.models import AuditEntry, AuditEventType


# ── Hypothesis strategies ─────────────────────────────────────────────────────

# Keep text small to keep examples readable and runs fast.
_text = st.text(min_size=0, max_size=20)
_nonempty_text = st.text(min_size=1, max_size=20)

# Primitive values that are JSON-serialisable and round-trip cleanly through
# Pydantic's ``dict[str, object]`` typing.
_primitive_values: st.SearchStrategy[object] = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-(2**31), max_value=2**31 - 1),
    st.floats(allow_nan=False, allow_infinity=False, width=32),
    st.text(min_size=0, max_size=20),
)

# Param keys include benign names *and* secret-like names so we exercise the
# redaction code path inside log() while still asserting the key set is
# preserved.
_param_keys = st.one_of(
    st.sampled_from(
        [
            "host",
            "port",
            "target",
            "url",
            "command",
            "password",
            "api_key",
            "secret_token",
            "user_credential",
            "session_key",
            "MIXEDCASEpassword",
        ]
    ),
    st.text(
        alphabet=st.characters(
            min_codepoint=ord("a"), max_codepoint=ord("z")
        ),
        min_size=1,
        max_size=10,
    ),
)


def _params_strategy() -> st.SearchStrategy[dict[str, object]]:
    """Build flat or nested input_params dicts with up to 5 top-level keys."""
    leaf = _primitive_values
    nested = st.dictionaries(_param_keys, leaf, min_size=0, max_size=3)
    return st.dictionaries(
        keys=_param_keys,
        values=st.one_of(leaf, nested),
        min_size=0,
        max_size=5,
    )


_audit_entry_strategy = st.builds(
    AuditEntry,
    correlation_id=_nonempty_text,
    event_type=st.sampled_from(list(AuditEventType)),
    agent_role=st.one_of(st.none(), _nonempty_text),
    tool_name=st.one_of(st.none(), _nonempty_text),
    input_params=st.one_of(st.none(), _params_strategy()),
    output_summary=st.one_of(st.none(), _text),
    duration_ms=st.one_of(
        st.none(),
        st.floats(
            min_value=0.0,
            max_value=1e9,
            allow_nan=False,
            allow_infinity=False,
        ),
    ),
    success=st.booleans(),
    error_detail=st.one_of(st.none(), _text),
)


# ── Property test ─────────────────────────────────────────────────────────────


def _entries_match_except_params(persisted: AuditEntry, original: AuditEntry) -> bool:
    """Return True if every field except input_params is identical."""
    return (
        persisted.timestamp_utc == original.timestamp_utc
        and persisted.correlation_id == original.correlation_id
        and persisted.event_type == original.event_type
        and persisted.agent_role == original.agent_role
        and persisted.tool_name == original.tool_name
        and persisted.output_summary == original.output_summary
        and persisted.duration_ms == original.duration_ms
        and persisted.success == original.success
        and persisted.error_detail == original.error_detail
    )


class TestAuditLogCompleteness:
    """Property 22 — every logged entry is retained in order."""

    @settings(
        max_examples=150,
        deadline=None,
        suppress_health_check=[HealthCheck.too_slow],
    )
    @given(entries=st.lists(_audit_entry_strategy, min_size=0, max_size=25))
    def test_no_entries_are_dropped(self, entries: list[AuditEntry]) -> None:
        """For any sequence of N AuditEntry values, exactly N appear in the log
        in the same order, and non-redacted fields survive intact.
        """
        logger = AuditLogger()

        async def _drive() -> None:
            for entry in entries:
                await logger.log(entry)

        asyncio.run(_drive())

        persisted = logger.entries

        # 1. Count is preserved — no events dropped.
        assert len(persisted) == len(entries), (
            f"AuditLogger dropped events: logged {len(entries)} but stored "
            f"{len(persisted)}"
        )

        # 2. Order is preserved and every non-redacted field round-trips.
        for i, (got, expected) in enumerate(zip(persisted, entries)):
            assert _entries_match_except_params(got, expected), (
                f"Persisted entry {i} differs from input on a non-redacted "
                f"field. got={got!r} expected={expected!r}"
            )

            # 3. input_params presence and top-level key set are preserved
            #    (values may be redacted; that is a separate property).
            if expected.input_params is None:
                assert got.input_params is None
            else:
                assert got.input_params is not None
                assert set(got.input_params.keys()) == set(
                    expected.input_params.keys()
                )

    @pytest.mark.asyncio
    async def test_empty_sequence_yields_empty_log(self) -> None:
        """Sanity baseline: zero logged entries produce an empty log."""
        logger = AuditLogger()
        assert logger.entries == []
