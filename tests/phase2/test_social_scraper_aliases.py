from __future__ import annotations

from forge.utils.intel.social_scraper import _parse_epieos_response


def test_epieos_twitter_x_aliases_reconstruct_handle_profile_urls() -> None:
    rows = _parse_epieos_response(
        {
            "twitter_x": {"username": "acmeops"},
            "x_twitter": {"handle": "@research_ops"},
        }
    )

    by_platform = {row["platform"]: row for row in rows}

    assert by_platform["twitter_x"]["profile_url"] == "https://x.com/acmeops"
    assert by_platform["twitter_x"]["username"] == "acmeops"
    assert by_platform["x_twitter"]["profile_url"] == "https://x.com/research_ops"
    assert by_platform["x_twitter"]["username"] == "research_ops"


def test_epieos_twitter_x_aliases_keep_host_and_reserved_path_guards() -> None:
    rows = _parse_epieos_response(
        {
            "twitter_x": {"url": "https://example.com/not-x", "username": "ignored"},
            "x_twitter": {"username": "home"},
        }
    )

    assert rows == []


def test_epieos_profile_aliases_accept_scheme_less_known_profile_urls() -> None:
    rows = _parse_epieos_response(
        {
            "github": {
                "profileUrl": "github.com/acmeops",
                "username": "acmeops",
            },
        }
    )

    assert rows == [
        {
            "source": "epieos",
            "platform": "github",
            "profile_url": "github.com/acmeops",
            "url": "github.com/acmeops",
            "verified": False,
            "handle": "acmeops",
            "username": "acmeops",
        }
    ]


def test_epieos_linkedin_non_web_profile_alias_falls_back_to_public_identifier() -> None:
    rows = _parse_epieos_response(
        {
            "linkedin": {
                "profileUrl": "urn:li:fsd_profile:alice-example",
                "publicIdentifier": "alice-example",
            },
        }
    )

    assert rows == [
        {
            "source": "epieos",
            "platform": "linkedin",
            "profile_url": "https://www.linkedin.com/in/alice-example",
            "url": "https://www.linkedin.com/in/alice-example",
            "verified": False,
            "handle": "alice-example",
            "username": "alice-example",
        }
    ]


def test_epieos_linkedin_web_profile_host_mismatch_still_blocks_fallback() -> None:
    rows = _parse_epieos_response(
        {
            "linkedin": {
                "profileUrl": "https://notlinkedin.com/in/alice",
                "publicIdentifier": "alice-example",
            },
        }
    )

    assert rows == []
