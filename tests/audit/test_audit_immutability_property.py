"""
tests/audit/test_audit_immutability_property.py — Property tests for audit log
immutability (Property 23).

Validates: Requirement 7.2 — "THE Audit_Log SHALL be append-only; the Platform
SHALL NOT provide any interface to modify or delete audit records during an
engagement."

Properties verified:
  P1. AuditLogger exposes no public method/attribute name that suggests modify
      or delete semantics. The only documented entry points are ``log()``
      (append) and the ``entries`` property (read).
  P2. ``logger.entries`` returns a *defensive copy*: mutating the returned list
      (clear, append, pop, sort, reverse) does not affect the logger's
      internal state observed on subsequent reads.
  P3. The logger grows monotonically: for any sequence of successful ``log()``
      calls, ``len(logger.entries)`` is non-decreasing and equals the number
      of calls executed so far.
  P4. Logged entries are preserved on subsequent reads. The non-redacted fields
      of any entry passed to ``log()`` continue to appear (in order, by value)
      in every later snapshot of ``entries``.

Conventions follow ``tests/audit/test_telemetry.py``: pytest-asyncio (auto
mode), Pydantic models, no production-code mutation. Hypothesis is used for
input generation; ``asyncio.run`` drives the async ``log()`` API inside each
synchronous Hypothesis test body so that examples are deterministic.
"""

from __future__ import annotations

import asyncio
import inspect

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from forge.audit.logger import AuditLogger
from forge.audit.models import AuditEntry, AuditEventType

# ── Hypothesis strategies ─────────────────────────────────────────────────────

# Use a small fixed pool of safe (non-secret-like) parameter keys so that the
# logger's redaction pass leaves ``input_params`` unchanged. Redaction is
# verified separately under Property 24 (task 3.5); here we want to compare
# entries by value before/after ``log()`` without redaction interference.
_SAFE_KEYS = ["foo", "bar", "baz", "qux", "alpha", "beta", "gamma", "value", "data", "name"]

_param_values = st.one_of(
    st.text(max_size=20),
    st.integers(min_value=-(10**6), max_value=10**6),
    st.floats(allow_nan=False, allow_infinity=False, width=32),
    st.booleans(),
    st.none(),
)

_input_params = st.one_of(
    st.none(),
    st.dictionaries(st.sampled_from(_SAFE_KEYS), _param_values, max_size=4),
)

audit_entries = st.builds(
    AuditEntry,
    correlation_id=st.text(min_size=1, max_size=20),
    event_type=st.sampled_from(list(AuditEventType)),
    agent_role=st.one_of(st.none(), st.text(min_size=1, max_size=15)),
    tool_name=st.one_of(st.none(), st.text(min_size=1, max_size=15)),
    input_params=_input_params,
    output_summary=st.one_of(st.none(), st.text(max_size=30)),
    duration_ms=st.one_of(
        st.none(),
        st.floats(min_value=0.0, max_value=1e6, allow_nan=False, allow_infinity=False),
    ),
    success=st.booleans(),
    error_detail=st.one_of(st.none(), st.text(max_size=30)),
)


# ── P1: No public modify/delete API ───────────────────────────────────────────

class TestPublicApiSurface:
    """Property 23.P1 — surface-level immutability contract."""

    # Names that would imply destructive or in-place mutation semantics on a
    # collection-like API. ``log`` (append-only) and ``redact_secrets`` (pure
    # transform helper) are intentionally not in this list.
    _FORBIDDEN = (
        "delete",
        "remove",
        "clear",
        "pop",
        "edit",
        "modify",
        "replace",
        "truncate",
        "drop",
        "purge",
        "reset",
        "rollback",
        "overwrite",
        "set_entries",
        "set_entry",
        "update_entry",
        "del_entry",
    )

    def test_class_exposes_no_modify_or_delete_methods(self) -> None:
        public_names = [n for n in dir(AuditLogger) if not n.startswith("_")]
        for name in public_names:
            lowered = name.lower()
            for forbidden in self._FORBIDDEN:
                assert forbidden not in lowered, (
                    f"AuditLogger exposes public member '{name}' whose name "
                    f"contains '{forbidden}'; this would violate the "
                    f"append-only contract (Requirement 7.2)."
                )

    def test_instance_exposes_no_modify_or_delete_methods(self) -> None:
        logger = AuditLogger()
        public_names = [n for n in dir(logger) if not n.startswith("_")]
        for name in public_names:
            lowered = name.lower()
            for forbidden in self._FORBIDDEN:
                assert forbidden not in lowered, (
                    f"AuditLogger instance exposes '{name}' (matches "
                    f"'{forbidden}'); this would violate Requirement 7.2."
                )

    def test_entries_property_has_no_setter(self) -> None:
        """Assignment to ``logger.entries`` must not be possible.

        ``entries`` is declared as a read-only property; assigning to it raises
        AttributeError. This guarantees external code cannot replace the
        underlying storage wholesale.
        """
        logger = AuditLogger()
        with pytest.raises(AttributeError):
            logger.entries = []  # type: ignore[misc]

    def test_entries_descriptor_is_a_property_without_fset(self) -> None:
        descriptor = inspect.getattr_static(AuditLogger, "entries")
        assert isinstance(descriptor, property)
        assert descriptor.fset is None, (
            "entries property defines a setter; this would allow callers to "
            "swap out the audit log, violating Requirement 7.2."
        )
        assert descriptor.fdel is None, (
            "entries property defines a deleter; deleting the audit log would "
            "violate Requirement 7.2."
        )


# ── P2: Defensive copy ────────────────────────────────────────────────────────

class TestDefensiveCopy:
    """Property 23.P2 — ``.entries`` returns an isolated snapshot."""

    @settings(max_examples=50, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    @given(entries=st.lists(audit_entries, max_size=8))
    def test_mutating_returned_list_does_not_affect_logger(
        self, entries: list[AuditEntry]
    ) -> None:
        async def run() -> None:
            logger = AuditLogger()
            for e in entries:
                await logger.log(e)

            snapshot = logger.entries
            expected_len = len(snapshot)

            # Try every common in-place mutation on the snapshot.
            snapshot.clear()
            snapshot.append(
                AuditEntry(correlation_id="poison", event_type=AuditEventType.ERROR)
            )
            snapshot.extend(
                [AuditEntry(correlation_id="poison2", event_type=AuditEventType.ERROR)]
            )
            snapshot.reverse()
            try:
                snapshot.pop()
            except IndexError:
                pass

            # Logger state must be unaffected by any of the above.
            after = logger.entries
            assert len(after) == expected_len, (
                "Mutating the list returned by .entries leaked into the "
                "logger's internal state (Requirement 7.2)."
            )
            assert all(e.correlation_id != "poison" for e in after)
            assert all(e.correlation_id != "poison2" for e in after)

        asyncio.run(run())

    def test_entries_returns_distinct_object_each_call(self) -> None:
        logger = AuditLogger()
        a = logger.entries
        b = logger.entries
        # A fresh list each access guarantees no aliasing of internal storage.
        assert a is not b


# ── P3: Monotonic growth ──────────────────────────────────────────────────────

class TestMonotonicGrowth:
    """Property 23.P3 — every successful ``log()`` increases length by 1."""

    @settings(max_examples=50, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    @given(entries=st.lists(audit_entries, max_size=12))
    def test_length_strictly_increases_per_successful_log(
        self, entries: list[AuditEntry]
    ) -> None:
        async def run() -> None:
            logger = AuditLogger()
            assert logger.entries == []
            prev = 0
            for i, e in enumerate(entries, start=1):
                await logger.log(e)
                curr = len(logger.entries)
                assert curr >= prev, (
                    f"len(entries) decreased after log() call #{i}: "
                    f"{prev} -> {curr}"
                )
                assert curr == i, (
                    f"len(entries) == {curr} after {i} successful log() calls; "
                    f"expected {i}."
                )
                prev = curr
            assert len(logger.entries) == len(entries)

        asyncio.run(run())


# ── P4: Content preservation ──────────────────────────────────────────────────

# Fields that must be byte-for-byte preserved by the logger. ``input_params``
# is excluded only because the logger applies redaction; the strategy above
# already uses non-secret keys so even input_params values must match. We
# include input_params here on that basis.
_PRESERVED_FIELDS = (
    "timestamp_utc",
    "correlation_id",
    "event_type",
    "agent_role",
    "tool_name",
    "input_params",
    "output_summary",
    "duration_ms",
    "success",
    "error_detail",
)


class TestContentPreservation:
    """Property 23.P4 — logged content survives all subsequent reads."""

    @settings(max_examples=50, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    @given(entries=st.lists(audit_entries, min_size=1, max_size=8))
    def test_logged_entries_appear_in_order_and_unchanged(
        self, entries: list[AuditEntry]
    ) -> None:
        async def run() -> None:
            logger = AuditLogger()
            for e in entries:
                await logger.log(e)

            # Take two independent snapshots; both must reflect the same
            # ordered, unmodified content.
            snap_a = logger.entries
            snap_b = logger.entries
            assert len(snap_a) == len(entries)
            assert len(snap_b) == len(entries)

            for original, stored_a, stored_b in zip(entries, snap_a, snap_b, strict=True):
                for field in _PRESERVED_FIELDS:
                    assert getattr(stored_a, field) == getattr(original, field), (
                        f"Field '{field}' was altered between log() and read."
                    )
                    assert getattr(stored_b, field) == getattr(original, field), (
                        f"Field '{field}' differs between two reads of .entries."
                    )

        asyncio.run(run())

    @settings(max_examples=30, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    @given(entries=st.lists(audit_entries, min_size=1, max_size=6))
    def test_earlier_entries_remain_after_more_logs(
        self, entries: list[AuditEntry]
    ) -> None:
        """Appending new entries does not perturb earlier ones."""

        async def run() -> None:
            logger = AuditLogger()

            seen_so_far: list[AuditEntry] = []
            for e in entries:
                await logger.log(e)
                seen_so_far.append(e)
                snapshot = logger.entries
                assert len(snapshot) == len(seen_so_far)
                # Every previously-logged entry is still present at the same
                # index with the same content.
                for idx, original in enumerate(seen_so_far):
                    stored = snapshot[idx]
                    for field in _PRESERVED_FIELDS:
                        assert getattr(stored, field) == getattr(original, field), (
                            f"Entry at index {idx} field '{field}' changed "
                            f"after subsequent log() calls (Requirement 7.2)."
                        )

        asyncio.run(run())
