from __future__ import annotations

from forge.utils.intel.social_profile_hosts import (
    epieos_host_matches,
    epieos_is_federated_instance_candidate_host,
    epieos_is_mastodon_like_host,
    epieos_is_supported_profile_host,
    epieos_profile_alias_host_matches,
)

_PLATFORM_HOSTS = {
    "github": ("github.com",),
    "linkedin": ("linkedin.com",),
    "mastodon": (),
    "stackoverflow": ("stackoverflow.com", "stackexchange.com"),
}


def test_epieos_host_matches_exact_and_subdomain() -> None:
    assert epieos_host_matches("www.github.com", "github.com")
    assert epieos_host_matches("gist.github.com", "github.com")
    assert not epieos_host_matches("evilgithub.com", "github.com")


def test_epieos_profile_alias_host_matches_known_platforms() -> None:
    assert epieos_profile_alias_host_matches(
        "github",
        "https://github.com/acme",
        _PLATFORM_HOSTS,
    )
    assert not epieos_profile_alias_host_matches(
        "github",
        "https://linkedin.com/in/acme",
        _PLATFORM_HOSTS,
    )
    assert epieos_profile_alias_host_matches(
        "stackoverflow",
        "https://serverfault.com/users/1/acme",
        _PLATFORM_HOSTS,
    )


def test_epieos_supported_and_federated_host_guards() -> None:
    assert epieos_is_supported_profile_host("github.com", _PLATFORM_HOSTS)
    assert epieos_is_mastodon_like_host("mastodon.acme.example")
    assert epieos_is_federated_instance_candidate_host(
        "social.acme.example",
        _PLATFORM_HOSTS,
    )
    assert not epieos_is_federated_instance_candidate_host(
        "github.com",
        _PLATFORM_HOSTS,
    )
