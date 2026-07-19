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
