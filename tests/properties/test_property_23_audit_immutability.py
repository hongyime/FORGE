"""
tests/properties/test_property_23_audit_immutability.py — Property 23.

Validates Requirement 7.2: "THE Audit_Log SHALL be append-only; the Platform
SHALL NOT provide any interface to modify or delete audit records during an
engagement."

Three properties are checked:

  P1. ``AuditLogger.entries`` returns a *defensive copy*. Any in-place mutation
      of the returned list (append, extend, pop, clear, slice assignment,
      reverse, sort, ``del``) leaves the logger's internal store untouched.

  P2. The public surface of ``AuditLogger`` exposes no method, attribute, or
      descriptor whose name implies modify/delete semantics, and the
      ``entries`` property has neither setter nor deleter.

  P3. After any sequence of ``log()`` calls interleaved with mutation attempts
      against snapshots returned by ``.entries``, every later read of
      ``.entries`` still returns *all* original records, in order, with their
      content byte-for-byte intact.

Conventions follow the existing audit property tests under ``tests/audit/``:
hypothesis with bounded strategies, ``asyncio.run`` to drive the async
``log()`` API from synchronous Hypothesis test bodies, and small
``max_examples`` budgets so the suite stays under the project's CI deadline.
"""

from __future__ import annotations

import asyncio
import inspect
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from forge.audit.logger import AuditLogger
from forge.audit.models import AuditEntry, AuditEventType


# ── Strategies ────────────────────────────────────────────────────────────────

# Use only non-secret-like keys so redaction (Requirement 7.3, Property 24) is
# a no-op here and entries can be compared by value before/after ``log()``.
_SAFE_KEYS = ("foo", "bar", "baz", "qux", "alpha", "beta", "value", "data")

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

# Fields that must be preserved exactly across every read of ``.entries``.
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


def _entry_signature(entry: AuditEntry) -> tuple[Any, ...]:
    """Stable, comparable representation of an AuditEntry."""
    return tuple(getattr(entry, f) for f in _PRESERVED_FIELDS)


# Mutation strategies that may be applied to a snapshot returned by
# ``.entries``. Each takes a list and mutates it in-place.
def _mut_clear(xs: list[AuditEntry]) -> None:
    xs.clear()


def _mut_append(xs: list[AuditEntry]) -> None:
    xs.append(AuditEntry(correlation_id="poison-append", event_type=AuditEventType.ERROR))


def _mut_extend(xs: list[AuditEntry]) -> None:
    xs.extend([AuditEntry(correlation_id="poison-extend", event_type=AuditEventType.ERROR)] * 2)


def _mut_pop(xs: list[AuditEntry]) -> None:
    if xs:
        xs.pop()


def _mut_pop_front(xs: list[AuditEntry]) -> None:
    if xs:
        xs.pop(0)


def _mut_slice_assign(xs: list[AuditEntry]) -> None:
    xs[:] = [AuditEntry(correlation_id="poison-slice", event_type=AuditEventType.ERROR)]


def _mut_del_all(xs: list[AuditEntry]) -> None:
    del xs[:]


def _mut_reverse(xs: list[AuditEntry]) -> None:
    xs.reverse()


def _mut_sort(xs: list[AuditEntry]) -> None:
    xs.sort(key=lambda e: e.correlation_id)


_MUTATIONS = (
    _mut_clear,
    _mut_append,
    _mut_extend,
    _mut_pop,
    _mut_pop_front,
    _mut_slice_assign,
    _mut_del_all,
    _mut_reverse,
    _mut_sort,
)

mutation_strategy = st.sampled_from(_MUTATIONS)


# ── P1: Defensive copy ────────────────────────────────────────────────────────


class TestEntriesReturnsDefensiveCopy:
    """Property 23.P1 — ``.entries`` returns an isolated snapshot."""

    def test_entries_is_a_distinct_object_each_call(self) -> None:
        logger = AuditLogger()
        first = logger.entries
        second = logger.entries
        assert first is not second, (
            ".entries returned the same list object on consecutive reads; "
            "internal storage may be aliased and mutations would leak."
        )

    @settings(
        max_examples=50,
        deadline=None,
        suppress_health_check=[HealthCheck.too_slow],
    )
    @given(
        entries=st.lists(audit_entries, max_size=8),
        mutations=st.lists(mutation_strategy, min_size=1, max_size=6),
    )
    def test_mutating_returned_list_does_not_affect_internal_store(
        self,
        entries: list[AuditEntry],
        mutations: list[Any],
    ) -> None:
        async def run() -> None:
            logger = AuditLogger()
            for e in entries:
                await logger.log(e)

            expected_signatures = [_entry_signature(e) for e in logger.entries]
            expected_len = len(expected_signatures)

            snapshot = logger.entries
            for mutate in mutations:
                mutate(snapshot)

            after = logger.entries
            assert len(after) == expected_len, (
                "Mutating .entries leaked into the logger's internal store: "
                f"length changed from {expected_len} to {len(after)} "
                "(Requirement 7.2)."
            )
            assert [_entry_signature(e) for e in after] == expected_signatures, (
                "Mutating .entries altered the content visible on the next "
                "read; .entries must return a defensive copy (Requirement 7.2)."
            )
            assert all("poison" not in (e.correlation_id or "") for e in after), (
                "Snapshot mutation injected a poisoned entry into the store."
            )

        asyncio.run(run())


# ── P2: No public modify/delete API ───────────────────────────────────────────


class TestNoPublicModifyOrDeleteApi:
    """Property 23.P2 — surface-level append-only contract."""

    # Substrings that, if present in any *public* member name, would imply
    # destructive or in-place mutation semantics. ``log`` (append-only writer)
    # and ``redact_secrets`` (pure helper) are intentionally not listed.
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

    def test_class_exposes_no_modify_or_delete_member_names(self) -> None:
        public_names = [n for n in dir(AuditLogger) if not n.startswith("_")]
        for name in public_names:
            lowered = name.lower()
            for forbidden in self._FORBIDDEN:
                assert forbidden not in lowered, (
                    f"AuditLogger exposes public member '{name}' whose name "
                    f"contains '{forbidden}'; this would violate the "
                    "append-only contract (Requirement 7.2)."
                )

    def test_instance_exposes_no_modify_or_delete_member_names(self) -> None:
        logger = AuditLogger()
        public_names = [n for n in dir(logger) if not n.startswith("_")]
        for name in public_names:
            lowered = name.lower()
            for forbidden in self._FORBIDDEN:
                assert forbidden not in lowered, (
                    f"AuditLogger instance exposes '{name}' (matches "
                    f"'{forbidden}'); this would violate Requirement 7.2."
                )

    def test_entries_property_has_no_setter_or_deleter(self) -> None:
        descriptor = inspect.getattr_static(AuditLogger, "entries")
        assert isinstance(descriptor, property), "entries must be exposed as a read-only property."
        assert descriptor.fset is None, (
            "entries property defines a setter; callers could swap out the "
            "audit log wholesale (Requirement 7.2)."
        )
        assert descriptor.fdel is None, (
            "entries property defines a deleter; deleting the audit log "
            "would violate Requirement 7.2."
        )

    def test_entries_assignment_is_rejected(self) -> None:
        logger = AuditLogger()
        with pytest.raises(AttributeError):
            logger.entries = []  # type: ignore[misc]


# ── P3: Records survive mutation attempts across log() sequences ──────────────


class TestRecordsSurviveMutationAttempts:
    """Property 23.P3 — every original record remains, in order, after any
    interleaved sequence of ``log()`` calls and snapshot mutations.
    """

    @settings(
        max_examples=50,
        deadline=None,
        suppress_health_check=[HealthCheck.too_slow],
    )
    @given(
        entries=st.lists(audit_entries, min_size=1, max_size=8),
        mutations=st.lists(mutation_strategy, max_size=8),
    )
    def test_all_records_intact_after_log_then_mutate(
        self,
        entries: list[AuditEntry],
        mutations: list[Any],
    ) -> None:
        async def run() -> None:
            logger = AuditLogger()
            for e in entries:
                await logger.log(e)

            # Capture the canonical content as the logger sees it (after any
            # internal redaction). This is the ground truth that subsequent
            # reads must continue to return.
            canonical = [_entry_signature(e) for e in logger.entries]
            assert len(canonical) == len(entries)

            # Apply an arbitrary sequence of in-place mutations to fresh
            # snapshots. Each snapshot is independent; the logger must not
            # be perturbed by any of them.
            for mutate in mutations:
                snap = logger.entries
                mutate(snap)

            # After the entire mutation campaign, the logger still returns
            # all original records, in order, byte-for-byte.
            after = logger.entries
            assert [_entry_signature(e) for e in after] == canonical, (
                "After mutation attempts on snapshots returned by .entries, "
                "the logger's records changed (Requirement 7.2)."
            )

        asyncio.run(run())

    @settings(
        max_examples=30,
        deadline=None,
        suppress_health_check=[HealthCheck.too_slow],
    )
    @given(
        entries=st.lists(audit_entries, min_size=1, max_size=6),
        mutations=st.lists(mutation_strategy, max_size=4),
    )
    def test_records_intact_when_mutations_interleave_with_log_calls(
        self,
        entries: list[AuditEntry],
        mutations: list[Any],
    ) -> None:
        """Mutating a snapshot mid-sequence must not affect later log() reads."""

        async def run() -> None:
            logger = AuditLogger()
            seen_signatures: list[tuple[Any, ...]] = []

            for i, e in enumerate(entries):
                await logger.log(e)
                # Capture immediately so we record the post-redaction form.
                seen_signatures.append(_entry_signature(logger.entries[-1]))

                # Between log() calls, mutate a snapshot if a mutation is
                # available for this step.
                if i < len(mutations):
                    snap = logger.entries
                    mutations[i](snap)

                # The logger's view must always reflect every record logged
                # so far, in order.
                current = [_entry_signature(x) for x in logger.entries]
                assert current == seen_signatures, (
                    f"After log() #{i + 1} and an interleaved snapshot "
                    "mutation, the logger's records changed "
                    "(Requirement 7.2)."
                )

        asyncio.run(run())
