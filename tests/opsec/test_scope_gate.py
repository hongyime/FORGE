from __future__ import annotations

import json
import sqlite3

import pytest

from forge.opsec.scope_gate import (
    ScopeViolationError,
    assert_in_scope,
    assert_url_in_scope,
    email_address_in_scope,
    load_scope_from_db,
)


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


def test_opsec_scope_gate_url_scope_entry_authorizes_host() -> None:
    scope = ["https://portal.example.com/app"]

    assert_in_scope("https://portal.example.com/app/login", scope)
    assert_in_scope("portal.example.com", scope)

    with pytest.raises(ScopeViolationError):
        assert_in_scope("api.example.com", scope)


def test_opsec_assert_url_in_scope_rejects_same_host_path_drift() -> None:
    scope = ["https://portal.example.com/app/"]

    assert_url_in_scope("https://portal.example.com/app/login", scope)

    with pytest.raises(ScopeViolationError):
        assert_url_in_scope("https://portal.example.com/admin", scope)


def test_opsec_assert_url_in_scope_allows_explicit_other_domain_scope() -> None:
    scope = ["acme.example", "https://portal.acme.example/app/"]

    assert_url_in_scope("https://acme.example", scope)
    assert_url_in_scope("https://portal.acme.example/app/login", scope)

    with pytest.raises(ScopeViolationError):
        assert_url_in_scope("https://portal.acme.example/admin", scope)


def test_email_address_scope_handles_exact_domain_wildcard_and_ignores_urls() -> None:
    scope = [
        "alice@example.com",
        "example.org",
        "*.corp.example",
        "https://portal.example.net/app",
    ]

    assert email_address_in_scope("alice@example.com", scope)
    assert email_address_in_scope("bob@example.org", scope)
    assert email_address_in_scope("carol@hr.corp.example", scope)
    assert not email_address_in_scope("dave@corp.example", scope)
    assert not email_address_in_scope("eve@portal.example.net", scope)


def test_load_scope_from_db_flattens_manifest_object(tmp_path) -> None:  # noqa: ANN001
    db_path = tmp_path / "engagement.db"
    con = sqlite3.connect(db_path)
    try:
        con.execute("CREATE TABLE engagements (id INTEGER PRIMARY KEY, scope_json TEXT)")
        con.execute(
            "INSERT INTO engagements (id, scope_json) VALUES (?, ?)",
            (
                1001,
                json.dumps(
                    {
                        "domains": ["example.com", "*.example.com"],
                        "ip_ranges": ["203.0.113.0/24"],
                        "urls": ["https://portal.example.com/app"],
                        "authorized_seeds": ["security@example.com", "+15551234567"],
                    }
                ),
            ),
        )
        con.commit()
    finally:
        con.close()

    assert load_scope_from_db(str(db_path), 1001) == [
        "example.com",
        "*.example.com",
        "203.0.113.0/24",
        "https://portal.example.com/app",
        "security@example.com",
        "+15551234567",
    ]
