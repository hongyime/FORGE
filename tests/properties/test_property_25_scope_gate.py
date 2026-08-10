"""
tests/properties/test_property_25_scope_gate.py
Property 25: Scope gate enforcement
Validates Requirements 8.1, 8.2.

When any agent or plugin attempts an outbound operation, the Scope Gate
validates the target against the EngagementScope BEFORE permitting
execution.  If the target is outside the scope, the gate blocks the
operation, logs the violation to the audit log, and raises
:class:`ScopeViolationError`.

The test asserts these invariants:

  1. Static invariant - ScopeViolationError is raised exactly when
     is_in_scope returns False.

  2. Dynamic invariant (domains) - for any well-formed exact domain in the
     scope, validate(domain) succeeds; for any random foreign domain not
     covered by the scope, validate raises ScopeViolationError.

  3. Dynamic invariant (wildcards) - for "*.example.com" wildcard entries:
     all subdomains pass; the apex example.com fails (unless explicitly
     listed); semantically-similar lookalikes (evilexample.com) fail.

  4. Dynamic invariant (CIDR) - for any IP literal inside a configured
     CIDR, validate succeeds; outside, it raises.

  5. Dynamic invariant (audit completeness) - every validate() call emits
     EXACTLY ONE SCOPE_DECISION audit entry with correlation_id propagated
     and success flag matching the allow/deny outcome.

  6. Dynamic invariant (empty scope denies all) - an EngagementScope with
     no domains/ips/urls denies every target.
"""

from __future__ import annotations

import ipaddress
import string
from typing import Any

import pytest
from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st

from forge.audit.logger import AuditLogger
from forge.audit.models import AuditEventType
from forge.core.errors import ScopeViolationError
from forge.governance import EngagementScope, ScopeGate


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------


_LABEL_CHAR = st.sampled_from(string.ascii_lowercase + string.digits)
_label = st.text(alphabet=_LABEL_CHAR, min_size=1, max_size=8)


def _domain() -> st.SearchStrategy[str]:
    """Generate well-formed registrable domain names."""
    return st.tuples(_label, _label).map(lambda t: f"{t[0]}.{t[1]}")


def _subdomain_of(parent: str) -> st.SearchStrategy[str]:
    return _label.map(lambda lbl: f"{lbl}.{parent}")


def _foreign_domain(scope_domains: list[str]) -> st.SearchStrategy[str]:
    """Generate domains NOT covered by the given scope."""

    def _is_foreign(d: str) -> bool:
        for entry in scope_domains:
            entry_clean = entry.lower().rstrip(".").rstrip()
            if entry_clean.startswith("*."):
                suffix = entry_clean[2:]
                if d == suffix or d.endswith("." + suffix):
                    return False
            elif d == entry_clean:
                return False
        return True

    return _domain().filter(_is_foreign)


def _ipv4_in(network: str) -> st.SearchStrategy[str]:
    net = ipaddress.IPv4Network(network)
    if net.num_addresses < 2:
        # Single host network - just yield the network address
        return st.just(str(net.network_address))
    # Avoid network/broadcast addresses for clarity
    lo = int(net.network_address) + 1
    hi = int(net.broadcast_address) - 1
    return st.integers(min_value=lo, max_value=hi).map(lambda v: str(ipaddress.IPv4Address(v)))


def _ipv4_outside(network: str) -> st.SearchStrategy[str]:
    net = ipaddress.IPv4Network(network)
    return (
        st.integers(min_value=1, max_value=2**32 - 2)
        .map(lambda v: str(ipaddress.IPv4Address(v)))
        .filter(lambda ip: ipaddress.IPv4Address(ip) not in net)
    )


# ---------------------------------------------------------------------------
# Static invariant - is_in_scope <=> validate raises
# ---------------------------------------------------------------------------


class TestIsInScopeAgreesWithValidate:
    """validate() raises iff is_in_scope() returns False."""

    @given(
        scope_domains=st.lists(_domain(), min_size=0, max_size=4, unique=True),
        target=_domain(),
    )
    @settings(max_examples=40, deadline=None)
    def test_in_scope_target_does_not_raise(self, scope_domains: list[str], target: str) -> None:
        gate = ScopeGate(EngagementScope(domains=scope_domains))
        if gate.is_in_scope(target):
            gate.validate(target)  # must not raise
        else:
            with pytest.raises(ScopeViolationError):
                gate.validate(target)


# ---------------------------------------------------------------------------
# Domain matching - exact + wildcard
# ---------------------------------------------------------------------------


class TestDomainScope:
    """Exact and wildcard domain rules."""

    @given(parent=_domain())
    @settings(max_examples=30, deadline=None)
    def test_exact_match_passes(self, parent: str) -> None:
        gate = ScopeGate(EngagementScope(domains=[parent]))
        gate.validate(parent)  # must not raise

    @given(
        parent=_domain(),
        # Generate a fresh subdomain that's guaranteed different from the apex
        sub_label=st.text(alphabet=_LABEL_CHAR, min_size=1, max_size=8),
    )
    @settings(max_examples=30, deadline=None)
    def test_exact_match_does_not_cover_subdomains(self, parent: str, sub_label: str) -> None:
        gate = ScopeGate(EngagementScope(domains=[parent]))
        target = f"{sub_label}.{parent}"
        assume(target != parent)
        with pytest.raises(ScopeViolationError):
            gate.validate(target)

    @given(parent=_domain(), sub_label=st.text(alphabet=_LABEL_CHAR, min_size=1, max_size=8))
    @settings(max_examples=30, deadline=None)
    def test_wildcard_matches_subdomains(self, parent: str, sub_label: str) -> None:
        target = f"{sub_label}.{parent}"
        assume(target != parent)
        gate = ScopeGate(EngagementScope(domains=[f"*.{parent}"]))
        gate.validate(target)  # must not raise

    @given(parent=_domain())
    @settings(max_examples=30, deadline=None)
    def test_wildcard_excludes_apex(self, parent: str) -> None:
        gate = ScopeGate(EngagementScope(domains=[f"*.{parent}"]))
        with pytest.raises(ScopeViolationError):
            gate.validate(parent)

    @given(parent=_domain(), prefix=st.text(alphabet=_LABEL_CHAR, min_size=1, max_size=6))
    @settings(max_examples=30, deadline=None)
    def test_wildcard_does_not_match_overlapping_suffix(self, parent: str, prefix: str) -> None:
        # "evilexample.com" must NOT match "*.example.com"
        gate = ScopeGate(EngagementScope(domains=[f"*.{parent}"]))
        # construct a domain that ends with parent but isn't a true subdomain
        lookalike = f"{prefix}{parent}"
        assume(lookalike != parent)
        assume(not lookalike.endswith("." + parent))
        with pytest.raises(ScopeViolationError):
            gate.validate(lookalike)


# ---------------------------------------------------------------------------
# IP / CIDR matching
# ---------------------------------------------------------------------------


class TestIpScope:
    """CIDR membership."""

    @given(target=_ipv4_in("10.0.0.0/24"))
    @settings(max_examples=30, deadline=None)
    def test_ip_inside_cidr_passes(self, target: str) -> None:
        gate = ScopeGate(EngagementScope(ip_ranges=["10.0.0.0/24"]))
        gate.validate(target)

    @given(target=_ipv4_outside("10.0.0.0/24"))
    @settings(max_examples=30, deadline=None)
    def test_ip_outside_cidr_raises(self, target: str) -> None:
        gate = ScopeGate(EngagementScope(ip_ranges=["10.0.0.0/24"]))
        with pytest.raises(ScopeViolationError):
            gate.validate(target)


# ---------------------------------------------------------------------------
# Empty scope denies everything
# ---------------------------------------------------------------------------


class TestEmptyScopeDeniesAll:
    """An empty scope has no allow-list - every target raises."""

    @given(target=st.one_of(_domain(), st.ip_addresses(v=4).map(str)))
    @settings(max_examples=30, deadline=None)
    def test_empty_scope_denies_arbitrary_target(self, target: str) -> None:
        gate = ScopeGate(EngagementScope())
        with pytest.raises(ScopeViolationError):
            gate.validate(target)


# ---------------------------------------------------------------------------
# Audit emission contract
# ---------------------------------------------------------------------------


class TestAuditContract:
    """Every validate() call emits exactly one SCOPE_DECISION entry."""

    @given(
        scope_domains=st.lists(_domain(), min_size=1, max_size=3, unique=True),
        target=_domain(),
        correlation=st.text(alphabet=string.ascii_lowercase, min_size=1, max_size=12),
    )
    @settings(max_examples=20, deadline=None)
    def test_one_audit_entry_per_validate_call(
        self,
        scope_domains: list[str],
        target: str,
        correlation: str,
    ) -> None:
        audit = AuditLogger()
        gate = ScopeGate(EngagementScope(domains=scope_domains), audit_logger=audit)

        try:
            gate.validate(target, correlation_id=correlation)
            allowed = True
        except ScopeViolationError:
            allowed = False

        scope_entries = [e for e in audit.entries if e.event_type == AuditEventType.SCOPE_DECISION]
        assert len(scope_entries) == 1, (
            f"validate() must emit exactly one SCOPE_DECISION entry; got {len(scope_entries)}"
        )
        entry = scope_entries[0]
        assert entry.correlation_id == correlation
        assert entry.success is allowed
        assert entry.input_params == {"target": target}
        if allowed:
            assert "allow" in (entry.output_summary or "")
            assert entry.error_detail is None
        else:
            assert "deny" in (entry.output_summary or "")
            assert entry.error_detail == "out_of_scope"


# ---------------------------------------------------------------------------
# Concrete sequence
# ---------------------------------------------------------------------------


class TestConcreteSequence:
    """Hand-crafted scenario covering all three target types."""

    def test_full_allow_deny_sequence(self) -> None:
        audit = AuditLogger()
        scope = EngagementScope(
            domains=["example.com", "*.example.com"],
            ip_ranges=["10.0.0.0/24", "2001:db8::/32"],
            urls=["https://example.com/api/"],
        )
        gate = ScopeGate(scope, audit_logger=audit)

        # Allowed
        gate.validate("example.com")
        gate.validate("api.example.com")
        gate.validate("10.0.0.5")
        gate.validate("2001:db8::dead")
        gate.validate("https://example.com/api/v1/users")

        # Denied
        for bad in (
            "evil.com",
            "evilexample.com",
            "10.0.1.5",
            "2001:dead::1",
            "https://example.com/login",
        ):
            with pytest.raises(ScopeViolationError):
                gate.validate(bad)

        # 10 audit entries total (5 allows + 5 denies)
        scope_entries = [e for e in audit.entries if e.event_type == AuditEventType.SCOPE_DECISION]
        assert len(scope_entries) == 10
        allows = [e for e in scope_entries if e.success]
        denies = [e for e in scope_entries if not e.success]
        assert len(allows) == 5
        assert len(denies) == 5
