from __future__ import annotations

from forge.engagement_orchestrator import EngagementSynthesisEngine


def test_social_profile_url_parser_supports_media_gaming_and_federated_routes() -> None:
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://www.mixcloud.com/acmemix/security-briefing/"}
        )
        == "mixcloud"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://www.mixcloud.com/acmemix/security-briefing/"
        )
        == "acmemix"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://www.mixcloud.com/discover/electronic/"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://www.mixcloud.com/settings/account/"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://letterboxd.com/acmefilm/films/reviews/"}
        )
        == "letterboxd"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://letterboxd.com/acmefilm/films/reviews/"
        )
        == "acmefilm"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://letterboxd.com/film/security-briefing/"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://letterboxd.com/search/security/"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://www.pinterest.com/acmepins/security-briefing/"}
        )
        == "pinterest"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://www.pinterest.com/acmepins/security-briefing/"
        )
        == "acmepins"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://www.pinterest.com/pin/1234567890/"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://www.pinterest.com/123456789/"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://tryhackme.com/p/acmethm"}
        )
        == "tryhackme"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://tryhackme.com/p/acmethm"
        )
        == "acmethm"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://tryhackme.com/room/profilesroom"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://steamcommunity.com/id/acmesteam"}
        )
        == "steam"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://steamcommunity.com/id/acmesteam"
        )
        == "acmesteam"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://steamcommunity.com/profiles/76561198000000000"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://www.reddit.com/user/acmeredteam/comments"
        )
        == "acmeredteam"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://www.reddit.com/r/netsec"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://replit.com/@acmerepl/security-lab"}
        )
        == "replit"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://replit.com/@acmerepl/security-lab"
        )
        == "acmerepl"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://replit.com/templates"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://codesandbox.io/u/acmesandbox/sandboxes"}
        )
        == "codesandbox"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://codesandbox.io/u/acmesandbox/sandboxes"
        )
        == "acmesandbox"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://codesandbox.io/s/template"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://devpost.com/acmedevpost"}
        )
        == "devpost"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://devpost.com/acmedevpost"
        )
        == "acmedevpost"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://devpost.com/hackathons"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://discord.gg/acmeops"}
        )
        == "discord"
    )
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://discord.com/users/123456789012345678"}
        )
        == "discord"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://discord.gg/acmeops"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://discord.com/users/123456789012345678"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://read.cv/acmeread"}
        )
        == "readcv"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://read.cv/acmeread"
        )
        == "acmeread"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://read.cv/jobs"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://about.me/acmeprofile"
        )
        == "acmeprofile"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://about.me/support"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://scholar.google.com/citations?user=qc6CJjYAAAAJ"}
        )
        == "google_scholar"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://scholar.google.com/citations?user=qc6CJjYAAAAJ"
        )
        == "qc6CJjYAAAAJ"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://scholar.google.com/citations?view_op=search_authors"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://www.academia.edu/AcmeAcademic"}
        )
        == "academia"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://www.academia.edu/AcmeAcademic"
        )
        == "AcmeAcademic"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://www.academia.edu/people/search"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://www.semanticscholar.org/author/Alice-Example/123"}
        )
        == "semantic_scholar"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://www.semanticscholar.org/author/Alice-Example/123"
        )
        == "Alice-Example"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://www.semanticscholar.org/paper/123"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://zenodo.org/users/acmezenodo"}
        )
        == "zenodo"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://zenodo.org/users/acmezenodo"
        )
        == "acmezenodo"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://zenodo.org/records/123"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://figshare.com/authors/Alice_Example/123456"}
        )
        == "figshare"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://figshare.com/authors/Alice_Example/123456"
        )
        == "Alice_Example"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://figshare.com/articles/dataset/example/123456"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://www.instagram.com/rootinsta/reels/"}
        )
        == "instagram"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://www.instagram.com/rootinsta/reels/"
        )
        == "rootinsta"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://www.instagram.com/stories/rootstory/445566/"
        )
        == "rootstory"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://www.instagram.com/reels/audio/123456789/"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://www.instagram.com/reel/C0example/"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://bitbucket.org/acmeworkspace/platform-repo"}
        )
        == "bitbucket"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://bitbucket.org/acmeworkspace/platform-repo"
        )
        == "acmeworkspace"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://bitbucket.org/product/features"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://hub.docker.com/u/acmedocker"}
        )
        == "dockerhub"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://hub.docker.com/u/acmedocker"
        )
        == "acmedocker"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://hub.docker.com/r/acmeimage/api"
        )
        == "acmeimage"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://hub.docker.com/search?q=security"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://hub.docker.com/r/library/nginx"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://mastodon.social/@acmefed/112233"}
        )
        == "mastodon"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://mastodon.social/@acmefed/112233"
        )
        == "acmefed"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://infosec.exchange/users/acmeblue"
        )
        == "acmeblue"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://infosec.exchange/@acmeops"
        )
        == "acmeops"
    )
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://mastodon.online/@acmeonline/112233"}
        )
        == "mastodon"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://mastodon.online/@acmeonline/112233"
        )
        == "acmeonline"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url("https://mas.to/users/acmemas")
        == "acmemas"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url("https://mstdn.party/web/acmeparty")
        == "acmeparty"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://mastodon.social/about"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url("https://mastodon.online/about")
        == ""
    )
