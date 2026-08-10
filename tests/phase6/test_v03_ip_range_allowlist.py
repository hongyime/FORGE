"""Tests for the V-03 per-engagement IP allowlist widening.

P2/P3 audit item #2: prior to this fix, V-03 only exempted IPs that
appeared literally in ``hosts.ip_address``. When an engagement scope
declared a CIDR range like ``10.0.0.0/24`` and the report body cited
``10.0.0.10-14`` (legitimate engagement hosts that never happened to
be persisted into the hosts table), V-03 spammed 20-31 warnings.

The validator now also accepts ``approved_ip_ranges``. The synthesizer
extracts CIDR-shaped entries from ``ctx.scope`` via
``_scope_entries_as_ip_ranges`` and threads them through.
"""

from __future__ import annotations

from forge.phase6.llm_validator import (
    _parse_approved_ip_ranges,
    _v03_no_internal_ips,
    validate_report,
    ValidationResult,
)
from forge.phase6.report_synthesizer import _scope_entries_as_ip_ranges


def _run_v03(text: str, **kwargs) -> ValidationResult:
    result = ValidationResult()
    _v03_no_internal_ips(text, kwargs.pop("approved_ips", None), result, False, **kwargs)
    return result


def test_v03_flags_unapproved_internal_ip_without_range() -> None:
    result = _run_v03("Compromised host: 10.0.0.10 was pivoted.", approved_ips=[])
    assert any("[V-03] Internal IP '10.0.0.10'" in w for w in result.warnings)


def test_v03_exempts_ip_covered_by_cidr_range() -> None:
    result = _run_v03(
        "Compromised host: 10.0.0.10 was pivoted.",
        approved_ips=[],
        approved_ip_ranges=["10.0.0.0/24"],
    )
    assert result.warnings == []


def test_v03_range_covers_broad_scope() -> None:
    text = " ".join(f"10.0.0.{n}" for n in (10, 11, 12, 13, 14))
    result = _run_v03(
        text,
        approved_ips=[],
        approved_ip_ranges=["10.0.0.0/8"],
    )
    assert result.warnings == [], f"10.0.0.0/8 must exempt every 10.x.y.z IP; got {result.warnings}"


def test_v03_still_flags_ip_outside_range() -> None:
    result = _run_v03(
        "Internal jumpbox at 172.16.5.5 exfil'd data.",
        approved_ips=[],
        approved_ip_ranges=["10.0.0.0/8"],
    )
    assert any("172.16.5.5" in w for w in result.warnings)


def test_v03_literal_ip_still_exempted_alongside_ranges() -> None:
    result = _run_v03(
        "Host 192.168.1.55 was scanned; jumpbox at 10.0.0.10.",
        approved_ips=["192.168.1.55"],
        approved_ip_ranges=["10.0.0.0/24"],
    )
    assert result.warnings == []


def test_v03_malformed_cidr_is_dropped_not_raised() -> None:
    # Empty strings, garbage, and non-network hostnames should not crash.
    result = _run_v03(
        "10.0.0.10 seen",
        approved_ips=[],
        approved_ip_ranges=["", "not-a-cidr", "example.com", "10.0.0.0/24"],
    )
    assert result.warnings == []


def test_validate_report_accepts_approved_ip_ranges_kwarg() -> None:
    # Executive summary section header + HIGH label so V-02 passes.
    report = (
        "# Executive Summary\n"
        "Overall Risk: HIGH — assessment of internal segment 10.0.0.0/24.\n"
        "Compromise chain: 10.0.0.10 -> 10.0.0.11 -> 10.0.0.14 pivot.\n"
        "See the following mandatory sections for detail.\n"
    )
    result = validate_report(
        raw_text=report,
        overall_risk="HIGH",
        approved_internal_ips=None,
        approved_ip_ranges=["10.0.0.0/24"],
    )
    # V-03 must not appear; other validators may flag missing sections.
    v03_warnings = [w for w in result.warnings if "[V-03]" in w]
    assert v03_warnings == [], f"expected zero V-03 warnings, got {v03_warnings}"


def test_scope_entries_as_ip_ranges_keeps_only_networks() -> None:
    scope = [
        "example.com",
        "*.example.com",
        "https://portal.example.com/",
        "10.0.0.0/24",
        "192.168.0.0/16",
        "not-a-cidr",
        "",
        "203.0.113.42",  # single-host CIDR is valid
    ]
    result = _scope_entries_as_ip_ranges(scope)
    assert "10.0.0.0/24" in result
    assert "192.168.0.0/16" in result
    assert "203.0.113.42" in result
    assert "example.com" not in result
    assert "not-a-cidr" not in result
    assert "" not in result


def test_scope_entries_helper_handles_none_input() -> None:
    assert _scope_entries_as_ip_ranges(None) == []
    assert _scope_entries_as_ip_ranges([]) == []


def test_parse_approved_ip_ranges_returns_ipnetwork_objects() -> None:
    import ipaddress

    parsed = _parse_approved_ip_ranges(["10.0.0.0/24", "192.168.1.0/26"])
    assert len(parsed) == 2
    assert all(isinstance(net, (ipaddress.IPv4Network, ipaddress.IPv6Network)) for net in parsed)
