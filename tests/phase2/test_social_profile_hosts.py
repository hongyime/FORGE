from __future__ import annotations

from forge.utils.intel.social_profile_hosts import (
    epieos_host_matches,
    epieos_is_federated_instance_candidate_host,
    epieos_is_mastodon_like_host,
    epieos_is_supported_profile_host,
    epieos_profile_alias_host_matches,
    epieos_stack_exchange_nested_user_payload,
    profile_url_hostname,
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


def test_epieos_profile_alias_host_matches_scheme_less_profile_urls() -> None:
    assert profile_url_hostname("github.com/acme") == "github.com"
    assert profile_url_hostname("www.github.com/acme") == "github.com"
    assert epieos_profile_alias_host_matches("github", "github.com/acme", _PLATFORM_HOSTS)
    assert epieos_profile_alias_host_matches("github", "www.github.com/acme", _PLATFORM_HOSTS)


def test_epieos_profile_alias_host_rejects_colon_scheme_identifiers() -> None:
    assert profile_url_hostname("mailto:alice@github.com") == ""
    assert profile_url_hostname("urn:github:alice") == ""
    assert not epieos_profile_alias_host_matches("github", "mailto:alice@github.com", _PLATFORM_HOSTS)
    assert not epieos_profile_alias_host_matches("github", "urn:github:alice", _PLATFORM_HOSTS)


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


def test_epieos_stack_exchange_nested_user_payload_preserves_parent_site() -> None:
    payload = epieos_stack_exchange_nested_user_payload(
        "stackoverflow",
        {"site": "serverfault.com"},
        "user",
        {"user_id": "13579", "username": "alice-stack"},
    )

    assert payload == {
        "platform": "stackoverflow",
        "site": "serverfault.com",
        "user_id": "13579",
        "username": "alice-stack",
    }


def test_epieos_stack_exchange_nested_user_payload_rejects_bad_shapes() -> None:
    assert (
        epieos_stack_exchange_nested_user_payload(
            "github",
            {"site": "serverfault.com"},
            "user",
            {"user_id": "13579", "username": "alice-stack"},
        )
        is None
    )
    assert (
        epieos_stack_exchange_nested_user_payload(
            "stackoverflow",
            {},
            "profile",
            {"user_id": "13579", "username": "alice-stack"},
        )
        is None
    )
    assert (
        epieos_stack_exchange_nested_user_payload(
            "stackoverflow",
            {},
            "user",
            {"user_id": "not-numeric", "username": "alice-stack"},
        )
        is None
    )
    assert (
        epieos_stack_exchange_nested_user_payload(
            "stackoverflow",
            {},
            "user",
            {
                "site": "not-stackexchange.example",
                "user_id": "13579",
                "username": "alice-stack",
            },
        )
        is None
    )
