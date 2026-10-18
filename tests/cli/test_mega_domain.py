from __future__ import annotations

import threading

import pytest

import forge.onboard.mega_domain as mega_domain_module
from forge.onboard.mega_domain import (
    LARGE_SUBDOMAIN_COUNT,
    NEVER_START_APEXES,
    OLD_AGE_YEARS,
    _LARGE_SUBDOMAIN_COUNT,
    _OLD_AGE_YEARS,
    crtsh_first_seen_age_years,
    domain_age_years,
    estimate_subdomain_count,
    mega_domain_decision,
    mega_domain_signals,
)
from forge.targets_import import _coerce_feed_item, target_scan_eligible


def test_rdap_and_crtsh_signal_producers_parse_mock_payloads() -> None:
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc)
    registration = (now.replace(year=now.year - 15)).isoformat()
    cert_old = (now.replace(year=now.year - 8)).isoformat()
    cert_new = (now.replace(year=now.year - 2)).isoformat()
    responses = {
        "rdap.org": {"events": [{"eventAction": "registration", "eventDate": registration}]},
        "crt.sh": [
            {"not_before": cert_new, "name_value": "www.example.test\n*.api.example.test"},
            {"not_before": cert_old, "name_value": "www.example.test\nmail.example.test"},
        ],
    }

    def mocked_fetch(url: str, timeout: float):
        assert timeout > 0
        return responses["rdap.org"] if "rdap.org" in url else responses["crt.sh"]

    assert domain_age_years("example.test", fetch_json=mocked_fetch) == pytest.approx(15, abs=0.02)
    assert crtsh_first_seen_age_years("example.test", fetch_json=mocked_fetch) == pytest.approx(8, abs=0.02)
    assert estimate_subdomain_count("example.test", fetch_json=mocked_fetch) == 3


def test_mega_domain_signals_fetch_age_and_surface_concurrently(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    barrier = threading.Barrier(2)

    def age(_domain: str) -> float:
        barrier.wait(timeout=2)
        return 12.0

    def surface(_domain: str) -> int:
        barrier.wait(timeout=2)
        return 700

    monkeypatch.setattr(mega_domain_module, "_domain_age_with_fallback", age)
    monkeypatch.setattr(mega_domain_module, "estimate_subdomain_count", surface)

    assert mega_domain_signals("example.test") == (12.0, 700)


@pytest.mark.parametrize(
    ("age", "surface", "expected"),
    [(15, 600, True), (15, 20, False), (2, 600, False), (None, None, False)],
)
def test_mega_domain_combined_signal_decision(age, surface, expected) -> None:
    assert mega_domain_decision("ordinary.example", age_years=age, estimated_subdomains=surface)[0] is expected


def test_never_start_apex_skipped() -> None:
    """Never-start curated apexes are skipped with reason 'never_start_list'."""
    assert mega_domain_decision("google.com") == (True, "never_start_list")
    assert mega_domain_decision("github.com") == (True, "never_start_list")
    assert mega_domain_decision("amazon.com") == (True, "never_start_list")

    # Case insensitivity, whitespace trimming, and trailing dot normalization
    assert mega_domain_decision("  GOOGLE.COM.  ") == (True, "never_start_list")
    assert mega_domain_decision("GitHub.com.") == (True, "never_start_list")

    # Custom never-start set override
    assert mega_domain_decision(
        "custom-mega.org",
        never_start={"custom-mega.org", "another.net"},
    ) == (True, "never_start_list")

    # Exact apex match: subdomains of never-start apexes are not apex matches
    assert mega_domain_decision("subdomain.google.com") == (False, "eligible")


@pytest.mark.parametrize(
    "apex",
    ["gmail.com", "icloud.com", "discord.com", "supabase.com", "chatgpt.com", "claude.com"],
)
def test_new_never_start_apexes_skipped(apex: str) -> None:
    assert mega_domain_decision(apex) == (True, "never_start_list")


def test_new_never_start_apex_subdomain_is_not_skipped_by_list() -> None:
    assert mega_domain_decision("mail.gmail.com") == (False, "eligible")


def test_old_and_large_skipped() -> None:
    """Domains that are both OLD (>= 10 years) and LARGE (>= 500 subdomains) are skipped."""
    assert mega_domain_decision(
        "corp-enterprise.net",
        age_years=10,
        estimated_subdomains=500,
    ) == (True, "old_and_large")

    assert mega_domain_decision(
        "massive-legacy.com",
        age_years=15.5,
        estimated_subdomains=2000,
    ) == (True, "old_and_large")


def test_old_and_small_engaged() -> None:
    """Obscure old domains with small attack surfaces must NOT be skipped."""
    assert mega_domain_decision(
        "obscure-archive.org",
        age_years=15,
        estimated_subdomains=50,
    ) == (False, "eligible")

    # Threshold boundary: exactly 499 subdomains (< 500) at 10 years
    assert mega_domain_decision(
        "obscure-archive.org",
        age_years=10,
        estimated_subdomains=499,
    ) == (False, "eligible")


def test_young_engaged() -> None:
    """Young domains (< 10 years) must NOT be skipped, even if large."""
    assert mega_domain_decision(
        "new-fast-startup.io",
        age_years=1,
        estimated_subdomains=5000,
    ) == (False, "eligible")

    assert mega_domain_decision(
        "rising-service.dev",
        age_years=9.9,
        estimated_subdomains=10000,
    ) == (False, "eligible")

    assert mega_domain_decision(
        "fresh-landing.ai",
        age_years=0.5,
        estimated_subdomains=10,
    ) == (False, "eligible")


def test_unknown_age_large_surface_not_skipped() -> None:
    """Unknown age (None) alone must NOT cause a skip, even with large surface."""
    assert mega_domain_decision(
        "large-unknown-age.net",
        age_years=None,
        estimated_subdomains=50000,
    ) == (False, "eligible")


def test_unknown_surface_old_age_not_skipped() -> None:
    """Unknown surface (None) alone must NOT cause a skip, even with old age."""
    assert mega_domain_decision(
        "vintage-unknown-surface.org",
        age_years=20,
        estimated_subdomains=None,
    ) == (False, "eligible")


def test_both_signals_unknown_not_skipped() -> None:
    """When both age and surface are unknown (default), domain is not skipped."""
    assert mega_domain_decision("standard-candidate.com") == (False, "eligible")
    assert mega_domain_decision(
        "standard-candidate.com",
        age_years=None,
        estimated_subdomains=None,
    ) == (False, "eligible")


def test_empty_or_whitespace_domain_not_skipped() -> None:
    """Empty or whitespace strings return eligible rather than error."""
    assert mega_domain_decision("") == (False, "eligible")
    assert mega_domain_decision("   ") == (False, "eligible")


def test_threshold_constants_consistency() -> None:
    """Verify tunable constants match required default thresholds."""
    assert OLD_AGE_YEARS == 10
    assert LARGE_SUBDOMAIN_COUNT == 500
    assert _OLD_AGE_YEARS == 10
    assert _LARGE_SUBDOMAIN_COUNT == 500


def test_never_start_apexes_curated_list() -> None:
    """Verify NEVER_START_APEXES contains the required 10 obvious mega apexes."""
    required = {
        "google.com",
        "github.com",
        "microsoft.com",
        "amazon.com",
        "apple.com",
        "facebook.com",
        "cloudflare.com",
        "youtube.com",
        "wikipedia.org",
        "twitter.com",
    }
    assert required.issubset(NEVER_START_APEXES)
    for apex in NEVER_START_APEXES:
        assert apex == apex.lower(), f"{apex} must be lowercase"
        assert not apex.startswith("."), f"{apex} must not start with dot"
        assert "." in apex, f"{apex} must be a domain"


def test_target_scan_eligible_skips_never_start_apex() -> None:
    """target_scan_eligible marks never-start apexes ineligible with mega_domain reason."""
    eligible, reason = target_scan_eligible("domain", "google.com")
    assert eligible is False
    assert "mega_domain" in reason
    assert "never_start_list" in reason
    assert reason == "mega_domain_never_start_list"

    eligible, reason = target_scan_eligible("domain", "github.com")
    assert eligible is False
    assert reason == "mega_domain_never_start_list"

    # Also works for URL targets hosting a never-start apex
    eligible, reason = target_scan_eligible("url", "https://amazon.com/homepage")
    assert eligible is False
    assert reason == "mega_domain_never_start_list"


def test_target_scan_eligible_does_not_skip_ordinary_domain_when_signals_unknown() -> None:
    """target_scan_eligible does NOT skip ordinary domains when age/surface are unknown."""
    eligible, reason = target_scan_eligible("domain", "target-company.example")
    assert eligible is True
    assert reason == "eligible"

    eligible, reason = target_scan_eligible("subdomain", "api.target-company.example")
    assert eligible is True
    assert reason == "eligible"

    eligible, reason = target_scan_eligible("url", "https://target-company.example/login")
    assert eligible is True
    assert reason == "eligible"


def test_target_scan_eligible_respects_injected_signals() -> None:
    """target_scan_eligible accepts injected age_years and estimated_subdomains."""
    # OLD + LARGE is skipped
    eligible, reason = target_scan_eligible(
        "domain",
        "legacy-monolith.com",
        age_years=12,
        estimated_subdomains=800,
    )
    assert eligible is False
    assert "mega_domain" in reason
    assert "old_and_large" in reason
    assert reason == "mega_domain_old_and_large"

    # OLD + SMALL is eligible
    eligible, reason = target_scan_eligible(
        "domain",
        "legacy-small.com",
        age_years=12,
        estimated_subdomains=50,
    )
    assert eligible is True
    assert reason == "eligible"

    # YOUNG is eligible even if large
    eligible, reason = target_scan_eligible(
        "domain",
        "young-growing.com",
        age_years=2,
        estimated_subdomains=2000,
    )
    assert eligible is True
    assert reason == "eligible"


def test_feed_item_coercion_integrates_mega_domain() -> None:
    """_coerce_feed_item properly records scan eligibility for mega-domains."""
    # Never-start apex in feed item
    item_mega = _coerce_feed_item(
        {
            "target_type": "domain",
            "target_value": "google.com",
            "priority": 50,
        }
    )
    assert item_mega is not None
    assert item_mega.scan_eligible is False
    assert "mega_domain" in item_mega.scan_eligibility_reason
    # Scan ineligible reduces raw priority to at most 10
    assert item_mega.priority <= 10

    # Ordinary domain in feed item
    item_normal = _coerce_feed_item(
        {
            "target_type": "domain",
            "target_value": "normal-corp.net",
            "priority": 50,
        }
    )
    assert item_normal is not None
    assert item_normal.scan_eligible is True
    assert item_normal.scan_eligibility_reason == "eligible"
    assert item_normal.priority == 50

    # Feed item with explicit age/surface signals
    item_injected_old_large = _coerce_feed_item(
        {
            "target_type": "domain",
            "target_value": "large-old-firm.org",
            "age_years": 15,
            "estimated_subdomains": 1200,
            "priority": 60,
        }
    )
    assert item_injected_old_large is not None
    assert item_injected_old_large.scan_eligible is False
    assert item_injected_old_large.scan_eligibility_reason == "mega_domain_old_and_large"
