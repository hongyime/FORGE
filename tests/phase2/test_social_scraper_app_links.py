from __future__ import annotations

from forge.utils.intel.social_scraper import _parse_epieos_response


def test_epieos_preserves_app_link_aliases_for_recursive_synthesis() -> None:
    results = _parse_epieos_response(
        {
            "email": "alice@example.com",
            "linkedin": {
                "publicIdentifier": "app-link-alice",
                "appUrl": "linkedin://in/app-link-alice",
                "deepLink": "twitter://user?screen_name=appblue",
                "mobileLinks": [
                    {"nativeUrl": "instagram://user?username=igramalice"},
                    {"universalLink": "https://www.linkedin.com/in/universal-alice"},
                ],
            },
        }
    )

    linkedin = next((row for row in results if row["platform"] == "linkedin"), None)

    assert linkedin is not None
    assert linkedin["profile_url"] == "https://www.linkedin.com/in/app-link-alice"
    assert linkedin["username"] == "app-link-alice"
    assert {item["value"] for item in linkedin["urls"]} == {
        "linkedin://in/app-link-alice",
        "twitter://user?screen_name=appblue",
        "instagram://user?username=igramalice",
        "https://www.linkedin.com/in/universal-alice",
    }
