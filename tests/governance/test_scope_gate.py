"""
tests/governance/test_scope_gate.py — Unit tests for the engagement scope gate.

Covers domain (exact + wildcard), IP (CIDR membership), and URL (prefix +
host) classification, plus environment-variable construction and the
SCOPE_DECISION audit emission contract.

Validates Requirements 8.1 and 8.2.
"""

from __future__ import annotations

import asyncio

import pytest

from forge.audit.logger import AuditLogger
from forge.audit.models import AuditEventType
from forge.governance import EngagementScope, ScopeGate, ScopeViolationError


# ── Construction / from_env ──────────────────────────────────────────────────


class TestFromEnv:
    """ScopeGate.from_env parses FORGE_SCOPE_JSON."""

    def test_missing_env_yields_empty_scope(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("FORGE_SCOPE_JSON", raising=False)
        gate = ScopeGate.from_env()
        assert gate.scope.domains == []
        assert gate.scope.ip_ranges == []
        assert gate.scope.urls == []
        # An empty scope denies everything.
        assert gate.is_in_scope("example.com") is False

    def test_blank_env_yields_empty_scope(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("FORGE_SCOPE_JSON", "   ")
        gate = ScopeGate.from_env()
        assert gate.scope.domains == []

    def test_valid_env_parses(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(
            "FORGE_SCOPE_JSON",
            '{"domains": ["example.com"], "ip_ranges": ["10.0.0.0/8"]}',
        )
        gate = ScopeGate.from_env()
        assert gate.scope.domains == ["example.com"]
        assert gate.scope.ip_ranges == ["10.0.0.0/8"]
        assert gate.is_in_scope("example.com") is True
        assert gate.is_in_scope("10.1.2.3") is True

    def test_malformed_json_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("FORGE_SCOPE_JSON", "{not json")
        with pytest.raises(ValueError):
            ScopeGate.from_env()

    def test_non_object_json_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("FORGE_SCOPE_JSON", '["example.com"]')
        with pytest.raises(ValueError):
            ScopeGate.from_env()


# ── Domain matching ──────────────────────────────────────────────────────────


class TestDomainMatching:
    """Exact + wildcard domain checks (case-insensitive)."""

    def test_exact_match(self) -> None:
        gate = ScopeGate(EngagementScope(domains=["example.com"]))
        assert gate.is_in_scope("example.com") is True
        assert gate.is_in_scope("EXAMPLE.com") is True  # case-insensitive
        assert gate.is_in_scope("notexample.com") is False
        assert gate.is_in_scope("example.org") is False

    def test_exact_match_does_not_cover_subdomains(self) -> None:
        """Bare 'example.com' must NOT match 'a.example.com'."""
        gate = ScopeGate(EngagementScope(domains=["example.com"]))
        assert gate.is_in_scope("a.example.com") is False

    def test_wildcard_matches_subdomains(self) -> None:
        gate = ScopeGate(EngagementScope(domains=["*.example.com"]))
        assert gate.is_in_scope("a.example.com") is True
        assert gate.is_in_scope("deep.a.example.com") is True
        assert gate.is_in_scope("DEEP.A.example.COM") is True

    def test_wildcard_excludes_apex(self) -> None:
        """'*.example.com' matches subdomains only, not example.com itself."""
        gate = ScopeGate(EngagementScope(domains=["*.example.com"]))
        assert gate.is_in_scope("example.com") is False

    def test_wildcard_does_not_match_overlapping_suffix(self) -> None:
        gate = ScopeGate(EngagementScope(domains=["*.example.com"]))
        # Naive endswith would mistakenly match "evilexample.com".
        assert gate.is_in_scope("evilexample.com") is False
        assert gate.is_in_scope("aexample.com") is False

    def test_wildcard_plus_apex(self) -> None:
        """Listing both '*.example.com' and 'example.com' covers both."""
        gate = ScopeGate(EngagementScope(domains=["example.com", "*.example.com"]))
        assert gate.is_in_scope("example.com") is True
        assert gate.is_in_scope("a.example.com") is True

    def test_unrelated_domain_rejected(self) -> None:
        gate = ScopeGate(EngagementScope(domains=["example.com"]))
        assert gate.is_in_scope("evil.com") is False


# ── IP matching ──────────────────────────────────────────────────────────────


class TestIpMatching:
    """CIDR membership for IPv4 + IPv6 targets."""

    def test_ipv4_in_range(self) -> None:
        gate = ScopeGate(EngagementScope(ip_ranges=["10.0.0.0/24"]))
        assert gate.is_in_scope("10.0.0.1") is True
        assert gate.is_in_scope("10.0.0.255") is True

    def test_ipv4_out_of_range(self) -> None:
        gate = ScopeGate(EngagementScope(ip_ranges=["10.0.0.0/24"]))
        assert gate.is_in_scope("10.0.1.1") is False
        assert gate.is_in_scope("192.168.1.1") is False

    def test_ipv6_in_range(self) -> None:
        gate = ScopeGate(EngagementScope(ip_ranges=["2001:db8::/32"]))
        assert gate.is_in_scope("2001:db8::1") is True

    def test_ipv6_out_of_range(self) -> None:
        gate = ScopeGate(EngagementScope(ip_ranges=["2001:db8::/32"]))
        assert gate.is_in_scope("2001:dead::1") is False

    def test_invalid_cidr_ignored(self) -> None:
        # Invalid CIDR is logged and skipped; valid one still works.
        gate = ScopeGate(EngagementScope(ip_ranges=["bogus", "10.0.0.0/24"]))
        assert gate.is_in_scope("10.0.0.5") is True


# ── URL matching ─────────────────────────────────────────────────────────────


class TestUrlMatching:
    """URL parsing, host check, and prefix check."""

    def test_url_host_in_domain_scope(self) -> None:
        gate = ScopeGate(EngagementScope(domains=["example.com"]))
        assert gate.is_in_scope("https://example.com/login") is True
        assert gate.is_in_scope("http://example.com:8080/x") is True

    def test_url_host_not_in_domain_scope(self) -> None:
        gate = ScopeGate(EngagementScope(domains=["example.com"]))
        assert gate.is_in_scope("https://evil.com/admin") is False

    def test_url_with_wildcard_domain(self) -> None:
        gate = ScopeGate(EngagementScope(domains=["*.example.com"]))
        assert gate.is_in_scope("https://api.example.com/v1") is True
        assert gate.is_in_scope("https://example.com/") is False

    def test_url_with_ip_host(self) -> None:
        gate = ScopeGate(EngagementScope(ip_ranges=["10.0.0.0/8"]))
        assert gate.is_in_scope("http://10.1.2.3/health") is True
        assert gate.is_in_scope("http://192.0.2.1/health") is False

    def test_url_prefix_required_when_urls_listed(self) -> None:
        """When ``urls`` is non-empty same-host URLs must match a prefix."""
        gate = ScopeGate(
            EngagementScope(
                domains=["example.com"],
                urls=["https://example.com/api/"],
            )
        )
        assert gate.is_in_scope("https://example.com/api/v1/users") is True
        # Host is allowed but path falls outside the listed prefix.
        assert gate.is_in_scope("https://example.com/login") is False

    def test_url_prefix_only_narrows_its_own_host(self) -> None:
        gate = ScopeGate(
            EngagementScope(
                domains=["acme.example", "portal.acme.example"],
                urls=["https://portal.acme.example/app"],
            )
        )
        assert gate.is_in_scope("https://acme.example") is True
        assert gate.is_in_scope("https://portal.acme.example/app/home") is True
        assert gate.is_in_scope("https://portal.acme.example/admin") is False

    def test_malformed_url_rejected(self) -> None:
        gate = ScopeGate(EngagementScope(domains=["example.com"]))
        # No host component → not in scope.
        assert gate.is_in_scope("http:///") is False


# ── validate() raises and audits ─────────────────────────────────────────────


class TestValidateAndAudit:
    """validate() raises on out-of-scope and emits SCOPE_DECISION entries."""

    def test_validate_passes_for_in_scope_target(self) -> None:
        gate = ScopeGate(EngagementScope(domains=["example.com"]))
        # Should not raise.
        gate.validate("example.com")

    def test_validate_raises_for_out_of_scope_target(self) -> None:
        scope = EngagementScope(domains=["example.com"])
        gate = ScopeGate(scope)
        with pytest.raises(ScopeViolationError) as excinfo:
            gate.validate("evil.com")
        assert excinfo.value.target == "evil.com"
        assert excinfo.value.scope is scope

    def test_audit_entry_emitted_on_allow(self) -> None:
        logger = AuditLogger()
        gate = ScopeGate(EngagementScope(domains=["example.com"]), audit_logger=logger)
        gate.validate("example.com", correlation_id="corr-allow")

        scope_entries = [e for e in logger.entries if e.event_type == AuditEventType.SCOPE_DECISION]
        assert len(scope_entries) == 1
        entry = scope_entries[0]
        assert entry.correlation_id == "corr-allow"
        assert entry.success is True
        assert entry.input_params == {"target": "example.com"}
        assert "allow" in (entry.output_summary or "")

    def test_audit_entry_emitted_on_deny(self) -> None:
        logger = AuditLogger()
        gate = ScopeGate(EngagementScope(domains=["example.com"]), audit_logger=logger)
        with pytest.raises(ScopeViolationError):
            gate.validate("evil.com", correlation_id="corr-deny")

        scope_entries = [e for e in logger.entries if e.event_type == AuditEventType.SCOPE_DECISION]
        assert len(scope_entries) == 1
        entry = scope_entries[0]
        assert entry.correlation_id == "corr-deny"
        assert entry.success is False
        assert entry.error_detail == "out_of_scope"
        assert entry.input_params == {"target": "evil.com"}

    def test_audit_emission_inside_event_loop(self) -> None:
        """validate() called from a running loop schedules the audit log."""
        logger = AuditLogger()
        gate = ScopeGate(EngagementScope(domains=["example.com"]), audit_logger=logger)

        async def _drive() -> None:
            gate.validate("example.com", correlation_id="corr-loop")
            # Allow the scheduled task to run.
            await asyncio.sleep(0)

        asyncio.run(_drive())
        scope_entries = [e for e in logger.entries if e.event_type == AuditEventType.SCOPE_DECISION]
        assert any(e.correlation_id == "corr-loop" for e in scope_entries)

    def test_audit_disabled_when_no_logger(self) -> None:
        """No logger → no audit calls, but validate() still works."""
        gate = ScopeGate(EngagementScope(domains=["example.com"]))
        gate.validate("example.com")  # must not raise
        with pytest.raises(ScopeViolationError):
            gate.validate("evil.com")


# ── Edge cases ───────────────────────────────────────────────────────────────


class TestEdgeCases:
    def test_empty_target_rejected(self) -> None:
        gate = ScopeGate(EngagementScope(domains=["example.com"]))
        assert gate.is_in_scope("") is False

    def test_empty_scope_denies_everything(self) -> None:
        gate = ScopeGate(EngagementScope())
        assert gate.is_in_scope("example.com") is False
        assert gate.is_in_scope("10.0.0.1") is False
        assert gate.is_in_scope("https://example.com/") is False

    def test_trailing_dot_treated_equivalently(self) -> None:
        """FQDNs with a trailing dot still match."""
        gate = ScopeGate(EngagementScope(domains=["example.com"]))
        assert gate.is_in_scope("example.com.") is True
