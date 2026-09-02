"""U6.4 — Session Enumeration Scope Check regression tests.

Covers the seven mandated scenarios plus engagement_id/manifest guards
and confirms scope details never leak into raised error messages.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from forge.collection.sessions.scope_check import (
    SessionEnumerationScopeError,
    audit_session_enumeration,
    check_target_in_scope,
    enumerate_sessions_scoped,
    validate_target_format,
)


SCOPE = {
    "ip_ranges": ["10.0.0.0/24", "192.168.1.50"],
    "hostnames": ["host.corp.local", "*.example.com"],
}


@pytest.fixture()
def db_path(tmp_path: Path) -> Path:
    p = tmp_path / "engagement.db"
    con = sqlite3.connect(str(p))
    con.execute(
        """
        CREATE TABLE audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER,
            phase TEXT,
            module TEXT,
            action TEXT NOT NULL,
            target TEXT,
            result TEXT,
            operator TEXT,
            logged_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    con.commit()
    con.close()
    return p


def _audit_rows(db_path: Path) -> list[tuple[str, str, str]]:
    con = sqlite3.connect(str(db_path))
    try:
        return [
            (row[0], row[1], row[2])
            for row in con.execute(
                "SELECT action, target, result FROM audit_log ORDER BY id"
            ).fetchall()
        ]
    finally:
        con.close()


# -- target format --------------------------------------------------------


class TestTargetFormat:
    def test_ipv4_ok(self) -> None:
        assert validate_target_format("10.0.0.5") == "ipv4"

    def test_ipv6_ok(self) -> None:
        assert validate_target_format("2001:db8::1") == "ipv6"

    def test_hostname_ok(self) -> None:
        assert validate_target_format("host.corp.local") == "hostname"

    @pytest.mark.parametrize("bad", ["", "   ", "not a host!", "-bad.example.com"])
    def test_bad_target_rejected(self, bad: str) -> None:
        with pytest.raises(SessionEnumerationScopeError) as exc:
            validate_target_format(bad)
        assert exc.value.reason == "invalid_target"

    def test_non_string_rejected(self) -> None:
        with pytest.raises(SessionEnumerationScopeError) as exc:
            validate_target_format(12345)  # type: ignore[arg-type]
        assert exc.value.reason == "invalid_target"


# -- scope decision (pure) ------------------------------------------------


class TestScopeDecision:
    def test_ip_in_cidr_allowed(self) -> None:
        assert check_target_in_scope("10.0.0.7", SCOPE) is True

    def test_ip_exact_allowed(self) -> None:
        assert check_target_in_scope("192.168.1.50", SCOPE) is True

    def test_ip_out_of_scope_rejected(self) -> None:
        assert check_target_in_scope("172.16.0.1", SCOPE) is False

    def test_hostname_exact_allowed(self) -> None:
        assert check_target_in_scope("host.corp.local", SCOPE) is True

    def test_hostname_case_insensitive(self) -> None:
        assert check_target_in_scope("HOST.CORP.LOCAL", SCOPE) is True

    def test_wildcard_matches_subdomain(self) -> None:
        assert check_target_in_scope("api.example.com", SCOPE) is True
        assert check_target_in_scope("a.b.example.com", SCOPE) is True

    def test_wildcard_does_not_match_apex(self) -> None:
        assert check_target_in_scope("example.com", SCOPE) is False

    def test_hostname_out_of_scope_rejected(self) -> None:
        assert check_target_in_scope("evil.other.com", SCOPE) is False

    def test_missing_ip_ranges_rejected(self) -> None:
        with pytest.raises(SessionEnumerationScopeError) as exc:
            check_target_in_scope("10.0.0.1", {"hostnames": []})
        assert exc.value.reason == "invalid_scope_manifest"

    def test_missing_hostnames_rejected(self) -> None:
        with pytest.raises(SessionEnumerationScopeError) as exc:
            check_target_in_scope("host.corp.local", {"ip_ranges": []})
        assert exc.value.reason == "invalid_scope_manifest"


# -- audit log ------------------------------------------------------------


class TestAuditLog:
    def test_audit_row_written(self, db_path: Path) -> None:
        audit_session_enumeration(
            db_path, 42, "10.0.0.5", "session_enumeration_started", "allowed"
        )
        rows = _audit_rows(db_path)
        assert rows == [("session_enumeration_started", "10.0.0.5", "allowed")]

    def test_audit_failure_is_silent(self, tmp_path: Path) -> None:
        missing = tmp_path / "nope.db"
        # Should NOT raise even though the DB has no audit_log table.
        audit_session_enumeration(
            missing, 1, "x", "session_enumeration_started", "allowed"
        )


# -- enumerate_sessions_scoped end-to-end ---------------------------------


class TestEnumerateScoped:
    def test_engagement_id_validated_first(self, db_path: Path) -> None:
        # Out-of-scope target AND invalid engagement_id: engagement error must win.
        with pytest.raises(SessionEnumerationScopeError) as exc:
            enumerate_sessions_scoped(
                target="bogus!!!",
                engagement_id=0,
                scope_manifest=SCOPE,
                db_path=db_path,
            )
        assert exc.value.reason == "invalid_engagement_id"
        # Nothing audited — engagement_id gate is BEFORE any audit write.
        assert _audit_rows(db_path) == []

    def test_ip_in_scope_enumerates(self, db_path: Path) -> None:
        calls: list[str] = []

        def fake(target: str) -> dict[str, object]:
            calls.append(target)
            return {"ok": True, "sessions": [{"user": "alice"}]}

        out = enumerate_sessions_scoped(
            target="10.0.0.5",
            engagement_id=7,
            scope_manifest=SCOPE,
            db_path=db_path,
            enumerator=fake,
        )
        assert out["ok"] is True
        assert calls == ["10.0.0.5"]
        rows = _audit_rows(db_path)
        assert rows == [
            ("session_enumeration_started", "10.0.0.5", "allowed"),
            ("session_enumeration_completed", "10.0.0.5", "success"),
        ]

    def test_hostname_in_scope_enumerates(self, db_path: Path) -> None:
        out = enumerate_sessions_scoped(
            target="host.corp.local",
            engagement_id=7,
            scope_manifest=SCOPE,
            db_path=db_path,
            enumerator=lambda t: {"ok": True, "target": t},
        )
        assert out["ok"] is True
        actions = [(a, r) for (a, _t, r) in _audit_rows(db_path)]
        assert actions == [
            ("session_enumeration_started", "allowed"),
            ("session_enumeration_completed", "success"),
        ]

    def test_wildcard_hostname_matches_subdomain(self, db_path: Path) -> None:
        called = {"n": 0}

        def fake(_t: str) -> dict[str, object]:
            called["n"] += 1
            return {"ok": True}

        enumerate_sessions_scoped(
            target="api.example.com",
            engagement_id=7,
            scope_manifest=SCOPE,
            db_path=db_path,
            enumerator=fake,
        )
        assert called["n"] == 1

    def test_ip_out_of_scope_rejected(self, db_path: Path) -> None:
        called = {"n": 0}

        def fake(_t: str) -> dict[str, object]:
            called["n"] += 1
            return {"ok": True}

        with pytest.raises(SessionEnumerationScopeError) as exc:
            enumerate_sessions_scoped(
                target="172.16.0.9",
                engagement_id=7,
                scope_manifest=SCOPE,
                db_path=db_path,
                enumerator=fake,
            )
        assert exc.value.reason == "out_of_scope"
        assert called["n"] == 0
        rows = _audit_rows(db_path)
        assert rows == [
            ("session_enumeration_started", "172.16.0.9", "out_of_scope"),
            ("session_enumeration_completed", "172.16.0.9", "rejected"),
        ]

    def test_hostname_out_of_scope_rejected(self, db_path: Path) -> None:
        with pytest.raises(SessionEnumerationScopeError) as exc:
            enumerate_sessions_scoped(
                target="evil.other.com",
                engagement_id=7,
                scope_manifest=SCOPE,
                db_path=db_path,
            )
        assert exc.value.reason == "out_of_scope"
        rows = _audit_rows(db_path)
        assert (
            "session_enumeration_started",
            "evil.other.com",
            "out_of_scope",
        ) in rows
        assert (
            "session_enumeration_completed",
            "evil.other.com",
            "rejected",
        ) in rows

    def test_invalid_target_rejected_before_enumeration(self, db_path: Path) -> None:
        called = {"n": 0}

        def fake(_t: str) -> dict[str, object]:
            called["n"] += 1
            return {"ok": True}

        with pytest.raises(SessionEnumerationScopeError) as exc:
            enumerate_sessions_scoped(
                target="not a host!!",
                engagement_id=7,
                scope_manifest=SCOPE,
                db_path=db_path,
                enumerator=fake,
            )
        assert exc.value.reason == "invalid_target"
        assert called["n"] == 0

    def test_error_message_does_not_leak_scope(self, db_path: Path) -> None:
        with pytest.raises(SessionEnumerationScopeError) as exc:
            enumerate_sessions_scoped(
                target="172.16.0.9",
                engagement_id=7,
                scope_manifest=SCOPE,
                db_path=db_path,
            )
        message = str(exc.value)
        for leak in ("10.0.0.0/24", "192.168.1.50", "corp.local", "example.com"):
            assert leak not in message

    def test_no_bypass_for_test_engagement(self, db_path: Path) -> None:
        # Regardless of engagement_id value, out-of-scope must still reject.
        for eid in (1, 9999, 4242):
            with pytest.raises(SessionEnumerationScopeError) as exc:
                enumerate_sessions_scoped(
                    target="172.16.0.9",
                    engagement_id=eid,
                    scope_manifest=SCOPE,
                    db_path=db_path,
                )
            assert exc.value.reason == "out_of_scope"

    def test_invalid_scope_manifest_rejected(self, db_path: Path) -> None:
        with pytest.raises(SessionEnumerationScopeError) as exc:
            enumerate_sessions_scoped(
                target="10.0.0.5",
                engagement_id=7,
                scope_manifest={"ip_ranges": ["10.0.0.0/24"]},  # missing hostnames
                db_path=db_path,
            )
        assert exc.value.reason == "invalid_scope_manifest"
