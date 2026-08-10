"""
tests/properties/test_property_24_audit_redaction.py — Property 24:
Audit secret redaction.

Validates Requirement 7.3: secrets in ``AuditEntry.input_params`` must be
redacted before the entry is persisted by :class:`forge.audit.logger.AuditLogger`.

Sub-properties verified via Hypothesis (using the public ``AuditLogger.log()``
entry point so the test exercises end-to-end behavior):

  1. Any ``input_params`` key whose name matches a secret pattern
     (``password``, ``secret``, ``token``, ``key``, ``credential``, ``api_key``
     — case-insensitive substring match via ``re.search``) has its value
     replaced with the literal string ``"[REDACTED]"`` in the stored entry.
  2. Non-matching keys retain their original values byte-for-byte (deep
     equality, including nested non-secret structures).
  3. Nested dictionaries are recursively redacted: secret keys at any depth
     are replaced; non-secret keys at any depth are preserved; the dict tree
     shape (key sets at every level) is preserved.
  4. The original input dictionary passed to ``log()`` is not mutated. The
     caller's dict, including any nested dicts it transitively contains,
     compares equal to a pre-call deep copy after ``log()`` returns.

The redaction patterns are duplicated locally as a contract reference rather
than imported, so the test fails loudly if the production list ever drifts
from the documented contract in the requirements.
"""

from __future__ import annotations

import copy
import re
import string
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from forge.audit.logger import AuditLogger
from forge.audit.models import AuditEntry, AuditEventType


# ── Contract reference ────────────────────────────────────────────────────────

# Mirror of forge.audit.logger.AuditLogger._REDACT_PATTERNS. Kept independent
# from the implementation so this test asserts the documented contract rather
# than re-running production logic.
_SECRET_PATTERNS: tuple[str, ...] = (
    "password",
    "secret",
    "token",
    "key",
    "credential",
    "api_key",
)

REDACTED = "[REDACTED]"


def _is_secret_key(key: str) -> bool:
    """Reference oracle: does ``key`` match any secret pattern (case-insensitive)?"""
    return any(re.search(p, key, re.IGNORECASE) for p in _SECRET_PATTERNS)


# ── Hypothesis strategies ─────────────────────────────────────────────────────
#
# Keys are restricted to ASCII letters, digits, and underscore. That alphabet
# is sufficient to express realistic parameter names (and produce both secret
# and non-secret variants) while avoiding control characters or surrogates
# that would obscure the property under test.

_KEY_ALPHABET = string.ascii_letters + string.digits + "_"


def _secret_key_strategy() -> st.SearchStrategy[str]:
    """Generate keys that contain at least one secret pattern as a substring,
    with random surrounding characters and arbitrary case applied to the
    secret pattern itself (so we cover ``Password``, ``API_KEY``, ``myToken``,
    ``client_secret``, etc.)."""

    def _build(
        pattern: str,
        prefix: str,
        suffix: str,
        case_seed: list[bool],
    ) -> str:
        cased_chars: list[str] = []
        for i, ch in enumerate(pattern):
            flag = case_seed[i] if i < len(case_seed) else False
            cased_chars.append(ch.upper() if flag else ch.lower())
        return prefix + "".join(cased_chars) + suffix

    return st.builds(
        _build,
        st.sampled_from(_SECRET_PATTERNS),
        st.text(alphabet=_KEY_ALPHABET, min_size=0, max_size=8),
        st.text(alphabet=_KEY_ALPHABET, min_size=0, max_size=8),
        st.lists(st.booleans(), min_size=0, max_size=12),
    )


def _safe_key_strategy() -> st.SearchStrategy[str]:
    """Generate keys that do NOT match any secret pattern (case-insensitive)."""
    return st.text(alphabet=_KEY_ALPHABET, min_size=1, max_size=16).filter(
        lambda k: not _is_secret_key(k)
    )


# Leaf values — JSON-like primitives plus small lists. Lists use only flat
# scalars to keep counterexamples readable; nested dict structure is
# introduced separately via ``st.recursive`` below.
_leaf_value: st.SearchStrategy[Any] = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-(10**9), max_value=10**9),
    st.floats(allow_nan=False, allow_infinity=False, width=32),
    st.text(max_size=32),
    st.lists(
        st.one_of(
            st.none(),
            st.booleans(),
            st.integers(min_value=-1000, max_value=1000),
            st.text(max_size=16),
        ),
        max_size=4,
    ),
)


def _params_strategy() -> st.SearchStrategy[dict[str, Any]]:
    """Recursive dict strategy mixing secret and non-secret keys at every
    level. Children may themselves be dicts, exercising the recursive
    redaction path."""
    key = st.one_of(_secret_key_strategy(), _safe_key_strategy())

    return st.recursive(
        # Base case: dict[str, leaf]
        st.dictionaries(key, _leaf_value, min_size=0, max_size=4),
        # Recursive step: allow nested dicts as values
        lambda children: st.dictionaries(
            key,
            st.one_of(_leaf_value, children),
            min_size=0,
            max_size=4,
        ),
        max_leaves=8,
    )


# ── Recursive assertion helpers ───────────────────────────────────────────────


def _assert_redacted(actual: dict[str, Any], original: dict[str, Any]) -> None:
    """Assert ``actual`` is the correctly redacted form of ``original``.

    Encodes sub-properties 1, 2, and 3:

    * Key set at every level is preserved (no keys added or removed).
    * Secret-like keys map to the literal string ``"[REDACTED]"``.
    * Non-secret keys preserve their original values; nested dicts recurse
      with the same rules.
    """
    assert set(actual.keys()) == set(original.keys()), (
        f"redaction must not add or remove keys "
        f"(expected {set(original.keys())!r}, got {set(actual.keys())!r})"
    )
    for k, original_value in original.items():
        actual_value = actual[k]
        if _is_secret_key(k):
            assert actual_value == REDACTED, (
                f"secret-like key {k!r} was not redacted "
                f"(got {actual_value!r}, expected {REDACTED!r})"
            )
        elif isinstance(original_value, dict):
            assert isinstance(actual_value, dict), (
                f"nested dict for non-secret key {k!r} should remain a dict "
                f"(got type {type(actual_value).__name__})"
            )
            _assert_redacted(actual_value, original_value)
        else:
            assert actual_value == original_value, (
                f"non-secret key {k!r} value was modified: {original_value!r} -> {actual_value!r}"
            )


# ── Property tests ────────────────────────────────────────────────────────────


class TestProperty24AuditSecretRedaction:
    """Property 24 — ``AuditLogger.log()`` redacts secrets in ``input_params``
    without mutating the caller's dict."""

    @settings(
        max_examples=200,
        deadline=None,
        suppress_health_check=[HealthCheck.too_slow],
    )
    @given(params=_params_strategy())
    async def test_logged_entry_redacts_secrets_recursively(self, params: dict[str, Any]) -> None:
        """Sub-properties 1, 2, 3: an entry passed through ``log()`` is
        persisted with secret-like keys (at any depth, any case, substring
        match) replaced by ``"[REDACTED]"`` and non-secret keys preserved."""
        logger = AuditLogger()
        correlation_id = "corr-property-24"
        entry = AuditEntry(
            correlation_id=correlation_id,
            event_type=AuditEventType.TOOL_INVOCATION,
            tool_name="property_24_test",
            input_params=params,
        )

        await logger.log(entry)

        # Exactly one entry was appended, with the expected correlation id.
        assert len(logger.entries) == 1
        stored = logger.entries[0]
        assert stored.correlation_id == correlation_id
        assert stored.input_params is not None

        # The persisted ``input_params`` is the redacted form of the input.
        _assert_redacted(stored.input_params, params)

    @settings(
        max_examples=200,
        deadline=None,
        suppress_health_check=[HealthCheck.too_slow],
    )
    @given(params=_params_strategy())
    async def test_log_does_not_mutate_caller_input(self, params: dict[str, Any]) -> None:
        """Sub-property 4: ``log()`` must not mutate the caller's dict.

        We deep-copy ``params`` before calling ``log()`` and assert the
        original is byte-for-byte equal to the snapshot afterwards. The
        deep copy is essential — a shallow copy would not detect mutation
        of nested dicts.
        """
        snapshot = copy.deepcopy(params)

        logger = AuditLogger()
        entry = AuditEntry(
            correlation_id="corr-no-mutation",
            event_type=AuditEventType.TOOL_INVOCATION,
            tool_name="property_24_no_mutation",
            input_params=params,
        )

        await logger.log(entry)

        assert params == snapshot, (
            "AuditLogger.log() mutated the caller's input_params dict; "
            "redaction must produce a new dict tree without modifying input."
        )

    @settings(
        max_examples=100,
        deadline=None,
        suppress_health_check=[HealthCheck.too_slow],
    )
    @given(params=_params_strategy())
    async def test_stored_entry_is_independent_of_caller_dict(self, params: dict[str, Any]) -> None:
        """The stored ``input_params`` is a distinct object from the caller's
        dict (and from any of its nested dicts). This is what makes the
        no-mutation guarantee robust against the caller mutating their
        dict after ``log()`` returns: the persisted record cannot change.

        We confirm independence by mutating ``params`` post-log and checking
        the stored entry is unaffected.
        """
        logger = AuditLogger()
        entry = AuditEntry(
            correlation_id="corr-independence",
            event_type=AuditEventType.TOOL_INVOCATION,
            tool_name="property_24_independence",
            input_params=params,
        )

        await logger.log(entry)

        stored = logger.entries[0]
        assert stored.input_params is not None
        snapshot_of_stored = copy.deepcopy(stored.input_params)

        # Mutate the caller's dict tree post-log.
        params["__post_log_injection__"] = "tampered"
        for v in list(params.values()):
            if isinstance(v, dict):
                v["__post_log_injection__"] = "tampered"

        # The stored entry must be unchanged.
        assert stored.input_params == snapshot_of_stored, (
            "Mutating the caller's dict after log() altered the persisted "
            "AuditEntry; log() must store an independent copy."
        )


# ── Targeted regression cases ─────────────────────────────────────────────────
#
# These pin the four sub-properties with hand-crafted inputs so a failure is
# easy to diagnose without re-deriving a Hypothesis counterexample.


class TestProperty24RegressionCases:
    """Concrete regressions for the four documented sub-properties."""

    async def test_top_level_secret_keys_redacted_and_safe_keys_preserved(
        self,
    ) -> None:
        """Sub-properties 1 and 2 at the top level."""
        logger = AuditLogger()
        params: dict[str, Any] = {
            "password": "p@ss",
            "secret": "shh",
            "token": "abc",
            "key": "k",
            "credential": "creds",
            "api_key": "ak",
            "Password": "mixed-case",
            "user_password": "substring",
            "myToken": "camel",
            "username": "alice",
            "host": "example.com",
            "port": 22,
        }
        entry = AuditEntry(
            correlation_id="corr-top-level",
            event_type=AuditEventType.TOOL_INVOCATION,
            input_params=params,
        )

        await logger.log(entry)
        stored = logger.entries[0].input_params
        assert stored is not None

        for k in (
            "password",
            "secret",
            "token",
            "key",
            "credential",
            "api_key",
            "Password",
            "user_password",
            "myToken",
        ):
            assert stored[k] == REDACTED, f"{k!r} should be redacted"

        assert stored["username"] == "alice"
        assert stored["host"] == "example.com"
        assert stored["port"] == 22

    async def test_nested_dicts_redacted_recursively(self) -> None:
        """Sub-property 3: redaction descends into nested dicts at every depth."""
        logger = AuditLogger()
        params: dict[str, Any] = {
            "outer": {
                "password": "p",
                "deeper": {
                    "API_KEY": "x",
                    "name": "ok",
                    "deepest": {"client_secret": "s", "label": "fine"},
                },
                "name": "outer-name",
            },
            "host": "example.com",
        }
        entry = AuditEntry(
            correlation_id="corr-nested",
            event_type=AuditEventType.TOOL_INVOCATION,
            input_params=params,
        )

        await logger.log(entry)
        stored = logger.entries[0].input_params
        assert stored is not None

        assert stored["outer"]["password"] == REDACTED
        assert stored["outer"]["deeper"]["API_KEY"] == REDACTED
        assert stored["outer"]["deeper"]["name"] == "ok"
        assert stored["outer"]["deeper"]["deepest"]["client_secret"] == REDACTED
        assert stored["outer"]["deeper"]["deepest"]["label"] == "fine"
        assert stored["outer"]["name"] == "outer-name"
        assert stored["host"] == "example.com"

    async def test_log_does_not_mutate_caller_input_concrete(self) -> None:
        """Sub-property 4 with a hand-crafted nested dict.

        After ``log()``, the original ``params`` (including its nested dicts)
        must compare deeply equal to its pre-call snapshot.
        """
        logger = AuditLogger()
        params: dict[str, Any] = {
            "password": "p",
            "nested": {"api_key": "k", "label": "ok"},
            "host": "example.com",
        }
        snapshot = copy.deepcopy(params)

        entry = AuditEntry(
            correlation_id="corr-no-mutation-concrete",
            event_type=AuditEventType.TOOL_INVOCATION,
            input_params=params,
        )
        await logger.log(entry)

        assert params == snapshot, (
            "log() must not mutate the caller's input_params dict; "
            f"expected {snapshot!r}, got {params!r}"
        )
        # Caller's secret value is still its plaintext — only the stored
        # AuditEntry should carry the redacted form.
        assert params["password"] == "p"
        assert params["nested"]["api_key"] == "k"


# ── Sanity check: contract patterns are exactly the implementation's ─────────


def test_redaction_patterns_match_implementation_contract() -> None:
    """Guard against drift between the test's contract reference and the
    production redaction pattern list. If this fails, either the contract
    in Requirement 7.3 changed (update ``_SECRET_PATTERNS`` in this module)
    or the implementation drifted from the requirement."""
    # NOTE: hardening 2026-05-26 renamed the attribute to _REDACT_KEY_PATTERNS
    # (clearer name) and added _VALUE_PATTERNS for value-based detection.
    # The historical key list is preserved as a strict subset of the new list.
    impl_patterns = tuple(AuditLogger._REDACT_KEY_PATTERNS)
    assert set(_SECRET_PATTERNS).issubset(impl_patterns), (
        "AuditLogger._REDACT_KEY_PATTERNS dropped a documented Property 24 "
        f"key pattern: contract={_SECRET_PATTERNS!r}, impl={impl_patterns!r}"
    )


# Re-export pytest so that pytest-asyncio's auto mode (configured in
# pyproject.toml) is unambiguously available; keeps static analyzers happy
# even though no fixture is referenced explicitly.
_ = pytest
