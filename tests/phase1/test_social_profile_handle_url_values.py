from __future__ import annotations

from forge.engagement_orchestrator import EngagementSynthesisEngine


def test_social_profile_handles_parse_url_values_in_handle_fields() -> None:
    assert EngagementSynthesisEngine._social_profile_handles(
        {"handle": "https://www.youtube.com/@acmeops"},
        platform="youtube",
    ) == ["acmeops"]
    assert EngagementSynthesisEngine._social_profile_handles(
        {"username": "https://github.com/acmeops"},
        platform="github",
    ) == ["acmeops"]
    assert EngagementSynthesisEngine._social_profile_handles(
        {"custom_url": "linkedin://in/alice-example"},
        platform="linkedin",
    ) == ["alice-example"]


def test_social_profile_handle_url_values_keep_reserved_routes_filtered() -> None:
    assert (
        EngagementSynthesisEngine._social_profile_handles(
            {"handle": "https://github.com/settings/profile"},
            platform="github",
        )
        == []
    )
    assert (
        EngagementSynthesisEngine._social_profile_handles(
            {"username": "https://www.youtube.com/feed/subscriptions"},
            platform="youtube",
        )
        == []
    )
