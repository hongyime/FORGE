from __future__ import annotations

from forge.engagement_orchestrator import EngagementSynthesisEngine


def test_social_profile_url_parser_supports_link_in_bio_and_marketplace_routes() -> None:
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://linktr.ee/acmehub"}
        )
        == "linktree"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://linktr.ee/acmehub"
        )
        == "acmehub"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://linktr.ee/pricing"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://allmylinks.com/acmeaml"}
        )
        == "allmylinks"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://allmylinks.com/acmeaml"
        )
        == "acmeaml"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://allmylinks.com/settings/account"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://bio.site/acmebiosite"}
        )
        == "biosite"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://bio.site/acmebiosite"
        )
        == "acmebiosite"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://bio.site/login"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://opencollective.com/acmecollective"}
        )
        == "opencollective"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://opencollective.com/acmecollective"
        )
        == "acmecollective"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://opencollective.com/discover"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://liberapay.com/acmelibera/"}
        )
        == "liberapay"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://liberapay.com/acmelibera/"
        )
        == "acmelibera"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://liberapay.com/explore"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://www.patreon.com/acmepatron"}
        )
        == "patreon"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://www.patreon.com/acmepatron"
        )
        == "acmepatron"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://www.patreon.com/c/acmepatron"
        )
        == "acmepatron"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://www.patreon.com/join"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://ko-fi.com/acmekofi"}
        )
        == "kofi"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://ko-fi.com/acmekofi"
        )
        == "acmekofi"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://ko-fi.com/home"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://www.buymeacoffee.com/acmecoffee"}
        )
        == "buymeacoffee"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://www.buymeacoffee.com/acmecoffee"
        )
        == "acmecoffee"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://www.buymeacoffee.com/explore"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://calendly.com/acmeops/intro-call"}
        )
        == "calendly"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://calendly.com/acmeops/intro-call"
        )
        == "acmeops"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://calendly.com/pricing"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://cal.com/acmeops/security-review"}
        )
        == "calcom"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://cal.com/acmeops/security-review"
        )
        == "acmeops"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://cal.com/apps"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://api.cal.com/v1/event-types"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://www.producthunt.com/@acmebuilder"}
        )
        == "producthunt"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://www.producthunt.com/@acmebuilder"
        )
        == "acmebuilder"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://www.producthunt.com/users/acmebuilder"
        )
        == "acmebuilder"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://www.producthunt.com/products/acme"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://api.producthunt.com/v2/users"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://wellfound.com/u/acmefounder"}
        )
        == "wellfound"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://wellfound.com/u/acmefounder"
        )
        == "acmefounder"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://wellfound.com/company/acme-startup"
        )
        == ""
    )
    assert EngagementSynthesisEngine._social_profile_is_company_profile(
        {"profile_url": "https://wellfound.com/company/acme-startup"},
        source_label="epieos",
        platform="wellfound",
    )
    assert (
        EngagementSynthesisEngine._social_profile_company_name(
            {"profile_url": "https://wellfound.com/company/acme-startup"},
            source_label="epieos",
            platform="wellfound",
        )
        == "Acme Startup"
    )
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://angel.co/u/acmeangel"}
        )
        == "angellist"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://angel.co/u/acmeangel"
        )
        == "acmeangel"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://angel.co/company/acme-angels"
        )
        == ""
    )
    assert EngagementSynthesisEngine._social_profile_is_company_profile(
        {"profile_url": "https://angel.co/company/acme-angels"},
        source_label="epieos",
        platform="angellist",
    )
    assert (
        EngagementSynthesisEngine._social_profile_company_name(
            {"profile_url": "https://angel.co/company/acme-angels"},
            source_label="epieos",
            platform="angellist",
        )
        == "Acme Angels"
    )
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://www.indiehackers.com/acmefounder"}
        )
        == "indiehackers"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://www.indiehackers.com/acmefounder"
        )
        == "acmefounder"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://www.indiehackers.com/post/growth-tactics"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://www.polywork.com/acmeops"}
        )
        == "polywork"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://www.polywork.com/acmeops"
        )
        == "acmeops"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://www.polywork.com/companies/acme"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://contra.com/acmeconsultant"}
        )
        == "contra"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://contra.com/acmeconsultant"
        )
        == "acmeconsultant"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://contra.com/discover/designers"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://adplist.org/mentors/acme-mentor"}
        )
        == "adplist"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://adplist.org/mentors/acme-mentor"
        )
        == "acme-mentor"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://adplist.org/explore"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://beacons.ai/acmebeacon"
        )
        == "acmebeacon"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://beacons.ai/pricing"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://bento.me/acmebento"}
        )
        == "bento"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://bento.me/acmebento"
        )
        == "acmebento"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://bento.me/pricing"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://hoo.be/acmehoo"}
        )
        == "hoobe"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://hoo.be/acmehoo"
        )
        == "acmehoo"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://hoo.be/discover"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://bio.link/acmebio"
        )
        == "acmebio"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://lnk.bio/acmelnk"
        )
        == "acmelnk"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://solo.to/acmesolo"
        )
        == "acmesolo"
    )
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://campsite.bio/acmecamp"}
        )
        == "campsite"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://campsite.bio/acmecamp"
        )
        == "acmecamp"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://campsite.bio/pricing"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://taplink.cc/acmetap"}
        )
        == "taplink"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://taplink.cc/acmetap"
        )
        == "acmetap"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://acmetapws.taplink.ws"
        )
        == "acmetapws"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://taplink.cc/pricing"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://support.taplink.ws"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://msha.ke/go.milkshake"}
        )
        == "milkshake"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://msha.ke/go.milkshake"
        )
        == "go.milkshake"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://msha.ke/login"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://muckrack.com/acmejournalist"}
        )
        == "muckrack"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://muckrack.com/acmejournalist"
        )
        == "acmejournalist"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://muckrack.com/search"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://muckrack.com/media-outlets/acme-news"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://acmecard.carrd.co"
        )
        == "acmecard"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://carrd.co/templates"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://www.tiktok.com/@acmetok"
        )
        == "acmetok"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://www.tiktok.com/tag/security"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://acmenotes.substack.com"
        )
        == "acmenotes"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://app.substack.com"
        )
        == ""
    )
