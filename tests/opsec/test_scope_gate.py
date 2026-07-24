from __future__ import annotations

import pytest

from forge.opsec.scope_gate import ScopeViolationError, assert_in_scope


def test_opsec_scope_gate_denies_empty_scope() -> None:
    with pytest.raises(ScopeViolationError):
        assert_in_scope("example.com", [])


def test_opsec_scope_gate_denies_missing_scope() -> None:
    with pytest.raises(ScopeViolationError):
        assert_in_scope("example.com", None)


def test_opsec_scope_gate_bare_domain_is_exact_only() -> None:
    assert_in_scope("example.com", ["example.com"])

    with pytest.raises(ScopeViolationError):
        assert_in_scope("api.example.com", ["example.com"])


def test_opsec_scope_gate_wildcard_excludes_apex() -> None:
    assert_in_scope("api.example.com", ["*.example.com"])
    assert_in_scope("deep.api.example.com", ["*.example.com"])

    with pytest.raises(ScopeViolationError):
        assert_in_scope("example.com", ["*.example.com"])


def test_opsec_scope_gate_apex_and_wildcard_cover_both() -> None:
    scope = ["example.com", "*.example.com"]

    assert_in_scope("example.com", scope)
    assert_in_scope("api.example.com", scope)
