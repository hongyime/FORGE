from __future__ import annotations

from forge.engagement_orchestrator import EngagementSynthesisEngine


def test_social_profile_url_parser_supports_gravatar_vanity_profiles_but_skips_hash_endpoints() -> (
    None
):
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://gravatar.com/acmeavatar"}
        )
        == "gravatar"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://gravatar.com/acmeavatar"
        )
        == "acmeavatar"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://gravatar.com/5f4dcc3b5aa765d61d8327deb882cf99"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://gravatar.com/5f4dcc3b5aa765d61d8327deb882cf99.json"
        )
        == ""
    )


def test_social_profile_url_parser_supports_spotify_user_profiles_only() -> None:
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://open.spotify.com/user/acmespotify"}
        )
        == "spotify"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://open.spotify.com/user/acmespotify"
        )
        == "acmespotify"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://spotify.com/user/acme.spotify"
        )
        == "acme.spotify"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://open.spotify.com/artist/1234567890"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://open.spotify.com/playlist/1234567890"
        )
        == ""
    )


def test_social_profile_url_parser_supports_strava_athlete_and_pro_profiles_only() -> None:
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://www.strava.com/athletes/12345678"}
        )
        == "strava"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://www.strava.com/athletes/12345678"
        )
        == "12345678"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://www.strava.com/pros/alice-athlete"
        )
        == "alice-athlete"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://www.strava.com/clubs/acme-cycling"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://www.strava.com/routes/123456"
        )
        == ""
    )


def test_social_profile_url_parser_supports_quora_profile_routes_only() -> None:
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://www.quora.com/profile/Alice-Example-1"}
        )
        == "quora"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://www.quora.com/profile/Alice-Example-1"
        )
        == "Alice-Example-1"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://www.quora.com/What-is-OSINT"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://www.quora.com/topic/Open-Source-Intelligence"
        )
        == ""
    )


def test_social_profile_url_parser_supports_creator_photo_profiles_only() -> None:
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://unsplash.com/@alicephotos"}
        )
        == "unsplash"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://unsplash.com/@alicephotos"
        )
        == "alicephotos"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://unsplash.com/photos/abcdef"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://500px.com/p/alicephoto"}
        )
        == "500px"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://500px.com/p/alicephoto"
        )
        == "alicephoto"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://500px.com/photo/123456/security"
        )
        == ""
    )


def test_social_profile_url_parser_supports_artstation_profiles_only() -> None:
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://www.artstation.com/aliceartist"}
        )
        == "artstation"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://www.artstation.com/aliceartist"
        )
        == "aliceartist"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://aliceartist.artstation.com/projects/security-briefing"
        )
        == "aliceartist"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://www.artstation.com/artwork/abc123"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://www.artstation.com/marketplace/p/security-asset"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://help.artstation.com/s/article/360056653492"
        )
        == ""
    )


def test_social_profile_url_parser_supports_deviantart_profiles_only() -> None:
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://www.deviantart.com/aliceartist"}
        )
        == "deviantart"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://www.deviantart.com/aliceartist"
        )
        == "aliceartist"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://alicelegacy.deviantart.com/gallery"
        )
        == "alicelegacy"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://www.deviantart.com/users/login"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://www.deviantart.com/tag/security"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://help.deviantart.com"
        )
        == ""
    )


def test_social_profile_url_parser_supports_matrix_user_ids_only() -> None:
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://matrix.to/#/@matrixblue:matrix.acme.example"}
        )
        == "matrix"
    )
    assert (
        EngagementSynthesisEngine._social_profile_platform_label_candidate("Matrix.org") == "matrix"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://matrix.to/#/@matrixblue:matrix.acme.example"
        )
        == "matrixblue"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "matrix:u/@uri-blue:matrix.acme.example"
        )
        == "uri-blue"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://matrix.to/#/#public-room:matrix.acme.example"
        )
        == ""
    )


def test_social_profile_parser_supports_federated_acct_identifiers() -> None:
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "acct:fedblue@social.acme.example"}
        )
        == "activitypub"
    )
    assert (
        EngagementSynthesisEngine._social_profile_platform_label_candidate("Fediverse")
        == "activitypub"
    )
    assert (
        EngagementSynthesisEngine._federated_account_handle_candidate(
            "acct:fedblue@social.acme.example"
        )
        == "fedblue"
    )
    assert (
        EngagementSynthesisEngine._federated_account_handle_candidate(
            "@nestedfed@mastodon.acme.example"
        )
        == "nestedfed"
    )
    assert (
        EngagementSynthesisEngine._federated_account_handle_candidate(
            "https://social.acme.example/.well-known/webfinger?resource=acct%3Awebfingerfed%40social.acme.example"
        )
        == "webfingerfed"
    )
    assert (
        EngagementSynthesisEngine._federated_account_handle_candidate("acct:ab@social.acme.example")
        == ""
    )
    assert EngagementSynthesisEngine._federated_account_host_entries(
        "acct:fedblue@social.acme.example",
        platform="mastodon",
    ) == [("social.acme.example", "subdomain"), ("acme.example", "domain")]
    assert (
        EngagementSynthesisEngine._federated_account_host_entries(
            "acct:publicuser@mastodon.social",
            platform="mastodon",
        )
        == []
    )


def test_social_profile_platform_profile_hosts_expand_mastodon_identity_url_aliases() -> None:
    hosts = EngagementSynthesisEngine._social_profile_platform_profile_hosts(
        {
            "profile_url": "https://social.example.net/@custommasto/112233",
            "sameAs": [
                "https://mstdn.acme.example/@mirror",
                "https://github.com/notmastodon",
            ],
            "identifier": {"url": "https://community.example.org/users/schemaactor"},
            "identifiers": [
                "https://mstdn.second.example.net/web/secondactor",
                "not-a-url",
            ],
        },
        platform="mastodon",
    )

    assert hosts == {
        "social.example.net",
        "example.net",
        "mstdn.acme.example",
        "acme.example",
        "community.example.org",
        "example.org",
        "mstdn.second.example.net",
    }
    assert "github.com" not in hosts


def test_social_profile_parser_supports_nostr_public_identity_links() -> None:
    npub_direct = "npub1" + "q" * 58
    npub_url = "npub1" + "p" * 58
    nprofile_url = "nprofile1" + "z" * 72

    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": f"nostr:{npub_direct}"}
        )
        == "nostr"
    )
    assert (
        EngagementSynthesisEngine._social_profile_platform_label_candidate("Nostr Protocol")
        == "nostr"
    )
    assert (
        EngagementSynthesisEngine._normalize_nostr_public_identity_candidate(f"nostr:{npub_direct}")
        == npub_direct
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            f"https://njump.me/{npub_direct}"
        )
        == npub_direct
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            f"https://primal.net/p/{npub_url}"
        )
        == npub_url
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            f"https://nostrudel.ninja/#/u/{nprofile_url}"
        )
        == nprofile_url
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://primal.net/settings"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._social_profile_handle_allowed_for_platform("nostr", "settings")
        is False
    )


def test_social_profile_url_parser_treats_youtube_short_links_as_evidence_only() -> None:
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://youtu.be/rootvideoid"}
        )
        == "youtube"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://www.youtube.com/@rootchannel"
        )
        == "rootchannel"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://youtu.be/rootvideoid"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://www.youtube.com/watch?v=rootvideoid"
        )
        == ""
    )


def test_social_profile_url_parser_supports_launchpad_profile_routes_only() -> None:
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://launchpad.net/~acme-maintainer"}
        )
        == "launchpad"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://launchpad.net/~acme-maintainer"
        )
        == "acme-maintainer"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://launchpad.net/projects/acme"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://launchpad.net/ubuntu"
        )
        == ""
    )


def test_social_profile_url_parser_supports_sourceforge_user_profiles_only() -> None:
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://sourceforge.net/u/acme-dev/profile/"}
        )
        == "sourceforge"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://sourceforge.net/u/acme-dev/profile/"
        )
        == "acme-dev"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://sourceforge.net/u/acme-dev/activity/"
        )
        == "acme-dev"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://sourceforge.net/projects/acme"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://sourceforge.net/p/acme/code/"
        )
        == ""
    )


def test_social_profile_url_parser_supports_snapchat_add_routes_only() -> None:
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://www.snapchat.com/add/acmesnap"}
        )
        == "snapchat"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://www.snapchat.com/add/acmesnap"
        )
        == "acmesnap"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://snapchat.com/add/@acme-snap"
        )
        == "acme-snap"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://www.snapchat.com/discover"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://www.snapchat.com/add"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://www.snapchat.com/"
        )
        == ""
    )


def test_social_profile_url_parser_supports_twitter_intent_links_and_skips_github_reserved_paths() -> (
    None
):
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://x.com/intent/user?screen_name=acmeops"}
        )
        == "twitter"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://x.com/intent/user?screen_name=acmeops"
        )
        == "acmeops"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://github.com/octocat/hello-world"
        )
        == "octocat"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://github.com/sponsors/octocat"
        )
        == "octocat"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://github.com/sponsors/explore"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://github.com/settings/profile"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://www.facebook.com/people/Alice-Example/1000123456789/"
        )
        == "Alice-Example"
    )
    assert (
        EngagementSynthesisEngine._social_profile_name(
            {"profile_url": "https://www.facebook.com/people/Alice-Example/1000123456789/"}
        )
        == "Alice Example"
    )
    assert (
        EngagementSynthesisEngine._social_profile_name(
            {"profile_url": "https://www.facebook.com/pages/Acme-Facebook/123456789"}
        )
        == ""
    )
    github_org_profile = {"profile_url": "https://github.com/orgs/acme-red-team/people"}
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            github_org_profile["profile_url"]
        )
        == ""
    )
    assert EngagementSynthesisEngine._social_profile_is_company_profile(
        github_org_profile,
        source_label="html_extract",
        platform="github",
    )
    assert (
        EngagementSynthesisEngine._social_profile_company_name(
            github_org_profile,
            source_label="html_extract",
            platform="github",
        )
        == "Acme Red Team"
    )
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://www.linkedin.com/school/acme-academy/"}
        )
        == "linkedin_company"
    )
    assert EngagementSynthesisEngine._social_profile_is_company_profile(
        {"profile_url": "https://www.linkedin.com/showcase/acme-labs/"},
        source_label="name_search",
        platform="linkedin_company",
    )
    assert (
        EngagementSynthesisEngine._social_profile_company_name(
            {"profile_url": "https://www.linkedin.com/school/acme-academy/"},
            source_label="name_search",
            platform="linkedin_company",
        )
        == "Acme Academy"
    )
    assert (
        EngagementSynthesisEngine._social_profile_company_name(
            {"profile_url": "https://www.linkedin.com/showcase/acme-labs/"},
            source_label="name_search",
            platform="linkedin_company",
        )
        == "Acme Labs"
    )
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "linkedin://company/acme-labs"}
        )
        == "linkedin_company"
    )
    assert EngagementSynthesisEngine._social_profile_is_company_profile(
        {"profile_url": "linkedin://school/acme-academy"},
        source_label="name_search",
        platform="",
    )
    assert (
        EngagementSynthesisEngine._social_profile_company_name(
            {"profile_url": "linkedin://showcase/acme-ai"},
            source_label="name_search",
            platform="",
        )
        == "Acme Ai"
    )
    assert (
        EngagementSynthesisEngine._social_profile_handle_url_candidate(
            "linkedin://in/alice-example"
        )
        == "alice-example"
    )
    assert (
        EngagementSynthesisEngine._social_profile_name_url_candidate(
            "linkedin://profile/alice-example"
        )
        == "Alice Example"
    )
    assert (
        EngagementSynthesisEngine._social_profile_company_name(
            {"profile_url": "https://gitlab.com/groups/acme-blue/-/group_members"},
            source_label="name_search",
            platform="gitlab",
        )
        == "Acme Blue"
    )
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://acme-docs.gitbook.io/security-guide"}
        )
        == "gitbook"
    )
    assert EngagementSynthesisEngine._social_profile_is_company_profile(
        {"profile_url": "https://acme-docs.gitbook.io/security-guide"},
        source_label="name_search",
        platform="gitbook",
    )
    assert (
        EngagementSynthesisEngine._social_profile_company_name(
            {"profile_url": "https://app.gitbook.com/o/acme-docs/s/security-guide"},
            source_label="name_search",
            platform="gitbook",
        )
        == "Acme Docs"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://acme-docs.gitbook.io/security-guide"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://acme-readme.readme.io/reference/auth"}
        )
        == "readmeio"
    )
    assert EngagementSynthesisEngine._social_profile_is_company_profile(
        {"profile_url": "https://acme-readme.readme.io/reference/auth"},
        source_label="name_search",
        platform="readmeio",
    )
    assert (
        EngagementSynthesisEngine._social_profile_company_name(
            {"profile_url": "https://acme-readme.readme.io/reference/auth"},
            source_label="name_search",
            platform="readmeio",
        )
        == "Acme Readme"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://acme-readme.readme.io/reference/auth"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://www.figma.com/@acmedesign"}
        )
        == "figma"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://www.figma.com/@acmedesign"
        )
        == "acmedesign"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://www.figma.com/community/file/123456/design-system"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://www.figma.com/file/abc123/design-system"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://www.figma.com/design/abc123/design-system"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://gitlab.com/users/acme-blue/activity"
        )
        == "acme-blue"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://gitlab.com/users/sign_in"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://gist.github.com/acmegist/abcdef1234567890"}
        )
        == "github_gist"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://gist.github.com/acmegist/abcdef1234567890"
        )
        == "acmegist"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://gist.github.com/discover"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://gist.github.com/0123456789abcdef0123456789abcdef"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url("https://t.me/rootrelay")
        == "rootrelay"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://t.me/joinchat/acmeinvite"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://t.me/share/url?url=https%3A%2F%2Facme.example"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._social_profile_handle_url_candidate(
            "tg://resolve?domain=rootrelay"
        )
        == "rootrelay"
    )
    assert (
        EngagementSynthesisEngine._social_profile_handle_url_candidate(
            "telegram://resolve?domain=%40rootrelay"
        )
        == "rootrelay"
    )
    assert (
        EngagementSynthesisEngine._social_profile_handle_url_candidate(
            "tg://resolve?domain=joinchat"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._social_profile_handle_url_candidate(
            "instagram://user?username=instaops"
        )
        == "instaops"
    )
    assert (
        EngagementSynthesisEngine._social_profile_handle_url_candidate(
            "instagram://user?username=login"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._social_profile_handle_url_candidate(
            "twitter://user?screen_name=xops"
        )
        == "xops"
    )
    assert (
        EngagementSynthesisEngine._social_profile_handle_url_candidate(
            "x://user?username=%40xrelay"
        )
        == "xrelay"
    )
    assert (
        EngagementSynthesisEngine._social_profile_handle_url_candidate(
            "twitter://user?screen_name=home"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://keybase.io/rootvault"
        )
        == "rootvault"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://keybase.io/team/rootteam"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url("https://keybase.io/docs")
        == ""
    )
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://app.intigriti.com/researcher/profile/acmeintigriti"}
        )
        == "intigriti"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://app.intigriti.com/researcher/profile/acmeintigriti/activity"
        )
        == "acmeintigriti"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://app.intigriti.com/profile/legacyintigriti"
        )
        == "legacyintigriti"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://app.intigriti.com/programs/acme/detail"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://yeswehack.com/hunters/acmeywh"}
        )
        == "yeswehack"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://yeswehack.com/hunters/acmeywh"
        )
        == "acmeywh"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://yeswehack.com/programs/acme"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://superuser.com/users/24680/alice-su"}
        )
        == "stackexchange"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://superuser.com/users/24680/alice-su"
        )
        == "alice-su"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://serverfault.com/users/13579/alice-sf"
        )
        == "alice-sf"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://askubuntu.com/users/98765/alice-ubuntu"
        )
        == "alice-ubuntu"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://superuser.com/questions/12345/example"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://orcid.org/0000-0002-1825-0097"}
        )
        == "orcid"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://orcid.org/0000-0002-1825-0097"
        )
        == "0000-0002-1825-0097"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://orcid.org/signin"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://www.researchgate.net/profile/Alice-Example"}
        )
        == "researchgate"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://www.researchgate.net/profile/Alice-Example"
        )
        == "Alice-Example"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://www.researchgate.net/publication/123"
        )
        == ""
    )
