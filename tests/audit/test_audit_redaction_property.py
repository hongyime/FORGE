"""
tests/audit/test_audit_redaction_property.py — Property-based tests for the
audit logger's secret redaction behavior.

Validates Requirement 7.3 (Property 24 — Audit secret redaction).

Source under test: forge/audit/logger.py
  - AuditLogger._REDACT_PATTERNS
  - AuditLogger.redact_secrets()
  - AuditLogger.log() — applies redaction to AuditEntry.input_params

Properties verified:
  1. Any input_params key matching a secret pattern (case-insensitive substring
     of "password", "secret", "token", "key", "credential", "api_key") is
     replaced with the literal string "[REDACTED]" in the stored AuditEntry.
  2. The same rule applies recursively inside nested dicts.
  3. Mixed-case key variations are matched (e.g. "Password", "API_KEY",
     "myToken").
  4. Substring matches trigger redaction (e.g. "user_password",
     "session_token", "client_secret").
  5. Non-secret keys preserve their original (deeply equal) values, including
     nested non-secret structures.
  6. The set of keys is preserved — redaction never adds or removes keys, only
     replaces values for matching keys.
"""

from __future__ import annotations

import asyncio
import re
import string
import uuid
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from forge.audit.logger import AuditLogger
from forge.audit.models import AuditEntry, AuditEventType


# ── Helpers ────────────────────────────────────────────────────────────────────

# Mirror of forge.audit.logger.AuditLogger._REDACT_PATTERNS.
# Kept as a separate constant so the test asserts the *contract*, not the impl.
_SECRET_PATTERNS: tuple[str, ...] = (
    "password",
    "secret",
    "token",
    "key",
    "credential",
    "api_key",
)


def _is_secret_key(key: str) -> bool:
    """Reference oracle: does the key match any secret pattern (case-insensitive)?"""
    return any(re.search(p, key, re.IGNORECASE) for p in _SECRET_PATTERNS)


# ── Hypothesis strategies ──────────────────────────────────────────────────────

# Letters/digits/underscore are sufficient to express realistic key names and
# avoid surrogate / control character issues that would obscure the property
# being tested.
_KEY_ALPHABET = string.ascii_letters + string.digits + "_"


def _secret_key_strategy() -> st.SearchStrategy[str]:
    """Generate keys that contain at least one secret pattern as a substring,
    with random surrounding characters and arbitrary case."""

    def _build(
        pattern: str, prefix: str, suffix: str, case_seed: list[bool]
    ) -> str:
        # Apply random case to the secret pattern itself so we cover
        # "Password", "TOKEN", "ApI_KeY", "myToken", etc.
        cased = "".join(
            ch.upper() if flag else ch.lower()
            for ch, flag in zip(pattern, case_seed, strict=False)
        )
        # case_seed may be shorter than pattern; pad with original case.
        if len(cased) < len(pattern):
            cased = cased + pattern[len(cased) :]
        return prefix + cased + suffix

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


# Leaf values: simple JSON-ish primitives. We avoid generating dicts as leaves
# here because nested dict structure is built by the recursive strategy below.
_leaf_value = st.one_of(
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
    """Recursive dict strategy mixing secret and non-secret keys at every level.

    Children may themselves be dicts to exercise the recursive redaction path.
    """
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


# ── Reference implementation (oracle) ──────────────────────────────────────────


def _expected_redaction(params: dict[str, Any]) -> dict[str, Any]:
    """Pure reference implementation of the redaction contract.

    Built independently from the production code so the property test
    cross-checks behavior rather than re-running the same logic.
    """
    out: dict[str, Any] = {}
    for k, v in params.items():
        if _is_secret_key(k):
            out[k] = "[REDACTED]"
        elif isinstance(v, dict):
            out[k] = _expected_redaction(v)
        else:
            out[k] = v
    return out


def _assert_redacted(actual: dict[str, Any], original: dict[str, Any]) -> None:
    """Assert that `actual` is the correctly redacted form of `original`.

    - Key set is preserved.
    - Secret keys map to the literal string "[REDACTED]".
    - Non-secret keys preserve values; nested dicts recurse.
    """
    assert set(actual.keys()) == set(original.keys()), (
        "redaction must not add or remove keys"
    )
    for k, original_value in original.items():
        actual_value = actual[k]
        if _is_secret_key(k):
            assert actual_value == "[REDACTED]", (
                f"secret-like key {k!r} was not redacted (got {actual_value!r})"
            )
        elif isinstance(original_value, dict):
            assert isinstance(actual_value, dict), (
                f"nested dict for non-secret key {k!r} should remain a dict"
            )
            _assert_redacted(actual_value, original_value)
        else:
            assert actual_value == original_value, (
                f"non-secret key {k!r} value was modified: "
                f"{original_value!r} -> {actual_value!r}"
            )


# ── Property tests ─────────────────────────────────────────────────────────────


class TestRedactSecretsProperty:
    """Property-based tests for AuditLogger.redact_secrets()."""

    @settings(
        max_examples=200,
        deadline=None,
        suppress_health_check=[HealthCheck.too_slow],
    )
    @given(params=_params_strategy())
    def test_redact_secrets_matches_contract(
        self, params: dict[str, Any]
    ) -> None:
        """For arbitrary nested dicts, redact_secrets() matches the contract:
        every secret-like key (top-level or nested, any case, substring match)
        becomes "[REDACTED]" while non-secret keys are preserved."""
        logger = AuditLogger()
        result = logger.redact_secrets(params)

        _assert_redacted(result, params)
        # Cross-check against the independent reference implementation.
        assert result == _expected_redaction(params)

    @settings(
        max_examples=200,
        deadline=None,
        suppress_health_check=[HealthCheck.too_slow],
    )
    @given(params=_params_strategy())
    def test_redact_secrets_is_idempotent(
        self, params: dict[str, Any]
    ) -> None:
        """Applying redaction twice yields the same result as applying it once."""
        logger = AuditLogger()
        once = logger.redact_secrets(params)
        twice = logger.redact_secrets(once)
        assert once == twice


class TestAuditEntryRedactionProperty:
    """Redaction is applied when AuditLogger.log() persists an entry."""

    @settings(
        max_examples=100,
        deadline=None,
        suppress_health_check=[HealthCheck.too_slow],
    )
    @given(params=_params_strategy())
    @pytest.mark.asyncio
    async def test_logged_entry_has_redacted_input_params(
        self, params: dict[str, Any]
    ) -> None:
        """An AuditEntry passed through log() ends up stored with redacted
        input_params matching the redaction contract."""
        logger = AuditLogger()
        correlation_id = f"corr-{uuid.uuid4()}"
        entry = AuditEntry(
            correlation_id=correlation_id,
            event_type=AuditEventType.TOOL_INVOCATION,
            tool_name="redaction_property_test",
            input_params=params,
        )

        await logger.log(entry)

        stored = next(
            e for e in logger.entries if e.correlation_id == correlation_id
        )
        assert stored.input_params is not None
        _assert_redacted(stored.input_params, params)


# ── Targeted examples (the explicit cases called out in the task) ──────────────


class TestRedactSecretsExamples:
    """Concrete examples covering every requirement bullet."""

    def test_top_level_keys_redacted(self) -> None:
        logger = AuditLogger()
        params: dict[str, Any] = {
            "password": "p@ss",
            "secret": "shh",
            "token": "abc",
            "key": "k",
            "credential": "creds",
            "api_key": "ak",
            "username": "alice",
        }
        result = logger.redact_secrets(params)

        for k in ("password", "secret", "token", "key", "credential", "api_key"):
            assert result[k] == "[REDACTED]", f"{k} should be redacted"
        assert result["username"] == "alice"

    def test_nested_keys_redacted(self) -> None:
        logger = AuditLogger()
        params: dict[str, Any] = {
            "outer": {
                "password": "p",
                "deeper": {"api_key": "x", "name": "ok"},
                "name": "outer-name",
            }
        }
        result = logger.redact_secrets(params)
        assert result["outer"]["password"] == "[REDACTED]"
        assert result["outer"]["deeper"]["api_key"] == "[REDACTED]"
        assert result["outer"]["deeper"]["name"] == "ok"
        assert result["outer"]["name"] == "outer-name"

    def test_mixed_case_keys_redacted(self) -> None:
        logger = AuditLogger()
        params: dict[str, Any] = {
            "Password": "p",
            "API_KEY": "k",
            "myToken": "t",
            "Secret": "s",
        }
        result = logger.redact_secrets(params)
        for k in ("Password", "API_KEY", "myToken", "Secret"):
            assert result[k] == "[REDACTED]"

    def test_substring_matches_redacted(self) -> None:
        logger = AuditLogger()
        params: dict[str, Any] = {
            "user_password": "p",
            "session_token": "t",
            "client_secret": "s",
            "private_key": "pk",
            "user_credential": "c",
        }
        result = logger.redact_secrets(params)
        for k in params:
            assert result[k] == "[REDACTED]"

    def test_non_secret_keys_preserved(self) -> None:
        logger = AuditLogger()
        params: dict[str, Any] = {
            "username": "alice",
            "host": "example.com",
            "port": 22,
            "tags": ["a", "b"],
            "meta": {"role": "admin", "active": True},
        }
        result = logger.redact_secrets(params)
        assert result == params

    @pytest.mark.asyncio
    async def test_log_redacts_input_params_in_stored_entry(self) -> None:
        """End-to-end: log() persists a redacted copy in entries."""
        logger = AuditLogger()
        entry = AuditEntry(
            correlation_id="corr-example",
            event_type=AuditEventType.TOOL_INVOCATION,
            tool_name="example_tool",
            input_params={
                "password": "p",
                "nested": {"API_KEY": "k", "ok": 1},
                "host": "example.com",
            },
        )
        await logger.log(entry)

        stored = logger.entries[-1]
        assert stored.input_params is not None
        assert stored.input_params["password"] == "[REDACTED]"
        assert stored.input_params["nested"] == {
            "API_KEY": "[REDACTED]",
            "ok": 1,
        }
        assert stored.input_params["host"] == "example.com"


# Belt-and-suspenders sanity check that the test module's reference oracle
# and the production implementation agree on a hand-crafted case before any
# property runs. This makes failures in the property tests easier to diagnose.
def test_oracle_matches_implementation_for_known_case() -> None:
    logger = AuditLogger()
    params: dict[str, Any] = {
        "Password": "x",
        "user_token": "t",
        "nested": {"api_key": "k", "label": "ok"},
        "label": "fine",
    }
    assert logger.redact_secrets(params) == _expected_redaction(params)


# Ensure asyncio is imported (used implicitly by pytest-asyncio fixtures);
# kept here so static analyzers don't flag the import as unused even if pytest
# auto mode handles the loop.
_ = asyncio
