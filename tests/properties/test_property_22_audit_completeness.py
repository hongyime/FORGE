"""
Property 22: Audit log completeness.

Validates Requirements 7.1: every event must be appended to the audit log
with its event_type, correlation_id, and timestamp preserved, and the
sequence of recorded events must match the order in which they were logged.

For any sequence of N AuditEntry objects logged via AuditLogger.log, the
AuditLogger.entries list must contain exactly N records, in order, with
the originating event_type, correlation_id, and timestamp_utc preserved.

Hypothesis strategies generate diverse AuditEntry instances spanning all
AuditEventType values plus a representative range of correlation IDs,
timestamps, agent roles, tool names, durations, and success flags.
"""

from __future__ import annotations

import asyncio

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from forge.audit import AuditEntry, AuditEventType, AuditLogger


# ---------------------------------------------------------------------------
# Hypothesis strategies
# ---------------------------------------------------------------------------

# Span every AuditEventType value so the property covers the full enum.
_event_type_strategy = st.sampled_from(list(AuditEventType))

# Correlation IDs are arbitrary non-empty strings in production usage; we
# generate a wide range including unicode to ensure preservation is exact.
_correlation_id_strategy = st.text(min_size=1, max_size=64)

# Timestamps are UTC epoch seconds. Allow a generous but finite range so
# floating-point equality holds without representation surprises.
_timestamp_strategy = st.floats(
    min_value=0.0,
    max_value=4_102_444_800.0,  # year 2100
    allow_nan=False,
    allow_infinity=False,
    width=64,
)

_optional_str = st.one_of(st.none(), st.text(max_size=32))

_optional_duration = st.one_of(
    st.none(),
    st.floats(
        min_value=0.0,
        max_value=600_000.0,
        allow_nan=False,
        allow_infinity=False,
        width=64,
    ),
)

# input_params: dictionary with simple, JSON-friendly values.
_input_params_strategy = st.one_of(
    st.none(),
    st.dictionaries(
        keys=st.text(min_size=1, max_size=16),
        values=st.one_of(
            st.text(max_size=32),
            st.integers(min_value=-1000, max_value=1000),
            st.booleans(),
            st.none(),
        ),
        max_size=4,
    ),
)


@st.composite
def audit_entries(draw: st.DrawFn) -> AuditEntry:
    """Generate a diverse AuditEntry instance."""
    return AuditEntry(
        timestamp_utc=draw(_timestamp_strategy),
        correlation_id=draw(_correlation_id_strategy),
        event_type=draw(_event_type_strategy),
        agent_role=draw(_optional_str),
        tool_name=draw(_optional_str),
        input_params=draw(_input_params_strategy),
        output_summary=draw(_optional_str),
        duration_ms=draw(_optional_duration),
        success=draw(st.booleans()),
        error_detail=draw(_optional_str),
    )


# ---------------------------------------------------------------------------
# Property
# ---------------------------------------------------------------------------


@settings(
    max_examples=200,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
@given(entries=st.lists(audit_entries(), min_size=0, max_size=50))
def test_audit_log_completeness(entries: list[AuditEntry]) -> None:
    """Property 22: audit log preserves length, order, and key fields."""
    logger = AuditLogger()

    async def _log_all() -> None:
        for entry in entries:
            await logger.log(entry)

    asyncio.run(_log_all())

    recorded = logger.entries

    # Length: exactly N records for N logged events.
    assert len(recorded) == len(entries), f"expected {len(entries)} entries, got {len(recorded)}"

    # Order plus preservation of event_type, correlation_id, and timestamp.
    for original, stored in zip(entries, recorded, strict=True):
        assert stored.event_type == original.event_type
        assert stored.correlation_id == original.correlation_id
        assert stored.timestamp_utc == original.timestamp_utc


def test_audit_log_completeness_covers_every_event_type() -> None:
    """Sanity check: a single pass covers every AuditEventType in order."""
    logger = AuditLogger()
    originals = [
        AuditEntry(
            timestamp_utc=float(idx),
            correlation_id=f"corr-{idx}",
            event_type=event_type,
        )
        for idx, event_type in enumerate(AuditEventType)
    ]

    async def _log_all() -> None:
        for entry in originals:
            await logger.log(entry)

    asyncio.run(_log_all())

    recorded = logger.entries
    assert len(recorded) == len(originals)
    for original, stored in zip(originals, recorded, strict=True):
        assert stored.event_type == original.event_type
        assert stored.correlation_id == original.correlation_id
        assert stored.timestamp_utc == original.timestamp_utc
