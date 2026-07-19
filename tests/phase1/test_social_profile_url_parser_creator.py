from __future__ import annotations

from forge.engagement_orchestrator import EngagementSynthesisEngine


def test_social_profile_url_parser_supports_creator_and_publishing_routes() -> None:
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://www.credly.com/users/alice-ops/badges"}
        )
        == "credly"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://www.credly.com/users/alice-ops/badges"
        )
        == "alice-ops"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://www.credly.com/badges/abcd"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://www.behance.net/aliceops"}
        )
        == "behance"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://www.behance.net/aliceops"
        )
        == "aliceops"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://www.behance.net/galleries"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://dribbble.com/alicedesign"}
        )
        == "dribbble"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://dribbble.com/alicedesign"
        )
        == "alicedesign"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://dribbble.com/shots/popular"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://help.behance.net/hc/en-us"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://support.dribbble.com/hc/en-us"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._social_profile_company_name(
            {"profile_url": "https://huggingface.co/organizations/acme-ml"},
            source_label="name_search",
            platform="huggingface",
        )
        == "Acme Ml"
    )
    assert (
        EngagementSynthesisEngine._social_profile_company_name(
            {"profile_url": "https://www.npmjs.com/org/acme-npm"},
            source_label="name_search",
            platform="npm",
        )
        == "Acme Npm"
    )
    assert (
        EngagementSynthesisEngine._social_profile_company_name(
            {"profile_url": "https://pypi.org/org/acme-py"},
            source_label="name_search",
            platform="pypi",
        )
        == "Acme Py"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://acmeops.medium.com/signal-boost"
        )
        == "acmeops"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://acmeops.medium.com"
        )
        == "acmeops"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://miro.medium.com"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://medium.com/topic/security"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://dev.to/acmedev/posts"
        )
        == "acmedev"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://dev.to/t/security"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://hashnode.com/@acmehash/articles/one"}
        )
        == "hashnode"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://hashnode.com/@acmehash/articles/one"
        )
        == "acmehash"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://hashnode.com/explore"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://www.npmjs.com/~acmenpm"}
        )
        == "npm"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://www.npmjs.com/~acmenpm"
        )
        == "acmenpm"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://www.npmjs.com/package/acme-package"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://pypi.org/user/acmepy/"
        )
        == "acmepy"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://pypi.org/project/acme-package/"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://rubygems.org/profiles/acmeruby"}
        )
        == "rubygems"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://rubygems.org/profiles/acmeruby"
        )
        == "acmeruby"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://rubygems.org/gems/not-a-profile"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://crates.io/users/acmecrates"}
        )
        == "crates"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://crates.io/users/acmecrates"
        )
        == "acmecrates"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://crates.io/crates/not-a-profile"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://packagist.org/users/acmepackagist"}
        )
        == "packagist"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://packagist.org/users/acmepackagist"
        )
        == "acmepackagist"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://packagist.org/packages/acme/package"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://www.nuget.org/profiles/acmenuget"}
        )
        == "nuget"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://www.nuget.org/profiles/acmenuget"
        )
        == "acmenuget"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://www.nuget.org/packages/not-a-profile"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://www.openbugbounty.org/researchers/acmeobb/"}
        )
        == "openbugbounty"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://www.openbugbounty.org/researchers/acmeobb/"
        )
        == "acmeobb"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://www.openbugbounty.org/faq/"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://news.ycombinator.com/user?id=acmehn"}
        )
        == "hackernews"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://news.ycombinator.com/user?id=acmehn"
        )
        == "acmehn"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://news.ycombinator.com/item?id=123456"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://news.ycombinator.com/user?id=news"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://hex.pm/users/acmehex"}
        )
        == "hexpm"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://hex.pm/users/acmehex"
        )
        == "acmehex"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://hex.pm/packages/not-a-profile"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://huggingface.co/acmeml"
        )
        == "acmeml"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://huggingface.co/acmeml/model-one"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://huggingface.co/models"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://www.flickr.com/photos/acmeflickr/1234567890/"}
        )
        == "flickr"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://www.flickr.com/photos/acmeflickr/1234567890/"
        )
        == "acmeflickr"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://www.flickr.com/photos/tags/security/"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://vimeo.com/acmevideo/securitybriefing"}
        )
        == "vimeo"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://vimeo.com/acmevideo/securitybriefing"
        )
        == "acmevideo"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://vimeo.com/123456789"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://vimeo.com/channels/staffpicks"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://player.vimeo.com/video/123456789"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://www.last.fm/user/rj/library"}
        )
        == "lastfm"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://www.last.fm/user/rj/library"
        )
        == "rj"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://www.last.fm/music/Acme"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://acmeband.bandcamp.com/album/security-briefing"}
        )
        == "bandcamp"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://acmeband.bandcamp.com/album/security-briefing"
        )
        == "acmeband"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://bandcamp.com/acmefan/collection"
        )
        == "acmefan"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://bandcamp.com/discover"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://daily.bandcamp.com/features/security"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://www.kaggle.com/acmekaggle/code"}
        )
        == "kaggle"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://www.kaggle.com/acmekaggle/code"
        )
        == "acmekaggle"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://www.kaggle.com/competitions"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://speakerdeck.com/acmespeaker/security-briefing"}
        )
        == "speakerdeck"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://speakerdeck.com/acmespeaker/security-briefing"
        )
        == "acmespeaker"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://speakerdeck.com/explore"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://www.slideshare.net/acmeslides/security-briefing"}
        )
        == "slideshare"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://www.slideshare.net/acmeslides/security-briefing"
        )
        == "acmeslides"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://www.slideshare.net/category/technology"
        )
        == ""
    )
    assert (
        EngagementSynthesisEngine._social_profile_platform_hint(
            {"profile_url": "https://soundcloud.com/acmesound/security-briefing"}
        )
        == "soundcloud"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://soundcloud.com/acmesound/security-briefing"
        )
        == "acmesound"
    )
    assert (
        EngagementSynthesisEngine._extract_social_profile_handle_from_url(
            "https://soundcloud.com/discover"
        )
        == ""
    )
