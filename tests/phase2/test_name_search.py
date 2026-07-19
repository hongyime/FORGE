from __future__ import annotations

import json
import re
import sqlite3
import threading
import time
from pathlib import Path

from forge.db.migrations import run_migrations
from forge.db.schema import apply_schema
from forge.engagement_orchestrator import EngagementSynthesisEngine
from forge.utils.intel import name_search
from forge.utils.intel.name_search import search_name
from forge.utils.intel.phone_lookup import _PHONE_DORK_SUPPLEMENTAL_PROFILE_SITES
from forge.utils.intel.social_scraper import _EPIEOS_PLATFORM_PROFILE_HOSTS


_DORK_COVERAGE_EXCLUDED_PROFILE_HOSTS = {
    # Covered by operator/PhoneInfoga base dorks or too broad for supplemental expansion.
    "facebook.com",
    "github.com",
    "gist.github.com",
    "instagram.com",
    "linkedin.com",
    "twitter.com",
    "x.com",
    # Protocol, redirect, or variant hosts covered by canonical profile dorks.
    "bsky.social",
    "gravatar.com",
    "matrix.to",
    "nostr.com",
    "nostrudel.ninja",
    "njump.me",
    "primal.net",
    "iris.to",
    "snort.social",
    "yakihonne.com",
    "spotify.com",
    "taplink.ws",
    "telegram.me",
    "t.me",
    "threads.com",
    "youtu.be",
    # Discord public search by real name/phone is too broad/noisy; preserve only explicit
    # Epieos/HTML profile URL normalization instead of adding supplemental dorks.
    "discord.com",
    "discord.gg",
    "discordapp.com",
    # Broad network root is noisy; targeted Stack Overflow/provider normalization cover this family.
    "stackexchange.com",
}


def _site_filters_from_name_dorks() -> set[str]:
    return {
        match.group(1).lower()
        for query in name_search._name_search_dork_queries("Alice Example")
        for match in re.finditer(r"site:([A-Za-z0-9_.-]+)", query)
    }


def _supported_public_profile_hosts_for_dork_coverage() -> set[str]:
    return {
        host.lower()
        for hosts in _EPIEOS_PLATFORM_PROFILE_HOSTS.values()
        for host in hosts
    } - _DORK_COVERAGE_EXCLUDED_PROFILE_HOSTS


def _bootstrap_engagement_for_synthesis(db_path: Path, engagement_id: int = 1001) -> None:
    con = sqlite3.connect(db_path)
    try:
        apply_schema(con)
        run_migrations(con)
        con.execute(
            """
            INSERT INTO engagements (id, name, scope_json, status, operator)
            VALUES (?, 'Acme Example', '["*.acme.example","https://www.linkedin.com/company/acme-research"]',
                    'ACTIVE', 'delta-one')
            """,
            (engagement_id,),
        )
        con.commit()
    finally:
        con.close()


def test_name_search_dork_queries_cover_supported_recursive_profile_families() -> None:
    queries = name_search._name_search_dork_queries("Alice Example")

    assert queries[0] == '"Alice Example" site:github.com'
    assert queries[-1] == '"Alice Example" profile'
    assert '"Alice Example" site:gist.github.com' in queries
    assert '"Alice Example" (site:hackerone.com OR site:bugcrowd.com)' in queries
    assert (
        '"Alice Example" (site:app.intigriti.com/researcher/profile OR site:intigriti.com/researcher/profile OR site:openbugbounty.org/researchers)'
        in queries
    )
    assert '"Alice Example" site:news.ycombinator.com/user' in queries
    assert '"Alice Example" (site:orcid.org OR site:researchgate.net OR site:credly.com)' in queries
    assert (
        '"Alice Example" (site:scholar.google.com/citations OR site:semanticscholar.org/author OR site:academia.edu)'
        in queries
    )
    assert '"Alice Example" (site:zenodo.org/users OR site:figshare.com/authors)' in queries
    assert '"Alice Example" (site:behance.net OR site:dribbble.com OR site:figma.com/@)' in queries
    assert '"Alice Example" (site:producthunt.com OR site:wellfound.com OR site:angel.co OR site:angellist.com)' in queries
    assert (
        '"Alice Example" (site:indiehackers.com OR site:polywork.com OR site:contra.com OR site:adplist.org/mentors)'
        in queries
    )
    assert '"Alice Example" (site:calendly.com OR site:cal.com OR site:linktr.ee)' in queries
    assert (
        '"Alice Example" (site:beacons.ai OR site:bio.link OR site:bio.site OR site:allmylinks.com OR site:lnk.bio OR site:solo.to)'
        in queries
    )
    assert '"Alice Example" (site:campsite.bio OR site:bento.me OR site:hoo.be OR site:taplink.cc OR site:msha.ke)' in queries
    assert '"Alice Example" (site:carrd.co OR site:muckrack.com OR site:open.spotify.com/user)' in queries
    assert '"Alice Example" (site:sr.ht OR site:huggingface.co)' in queries
    assert '"Alice Example" (site:npmjs.com OR site:pypi.org OR site:stackoverflow.com/users)' in queries
    assert '"Alice Example" (site:medium.com OR site:hashnode.com OR site:substack.com)' in queries
    assert '"Alice Example" (site:kaggle.com OR site:speakerdeck.com OR site:slideshare.net)' in queries
    assert '"Alice Example" (site:launchpad.net/~ OR site:sourceforge.net/u)' in queries
    assert '"Alice Example" (site:replit.com/@ OR site:codesandbox.io/u OR site:devpost.com OR site:read.cv)' in queries
    assert '"Alice Example" (site:codepen.io OR site:hub.docker.com/u OR site:hub.docker.com/r)' in queries
    assert (
        '"Alice Example" (site:rubygems.org/profiles OR site:crates.io/users OR site:packagist.org/users)'
        in queries
    )
    assert '"Alice Example" (site:nuget.org/profiles OR site:hex.pm/users OR site:steamcommunity.com/id)' in queries
    assert '"Alice Example" (site:yeswehack.com/hunters OR site:opencollective.com OR site:liberapay.com)' in queries
    assert '"Alice Example" (site:patreon.com OR site:ko-fi.com OR site:buymeacoffee.com)' in queries
    assert '"Alice Example" (site:youtube.com OR site:tiktok.com OR site:twitch.tv)' in queries
    assert '"Alice Example" (site:pinterest.com OR site:vimeo.com OR site:soundcloud.com)' in queries
    assert '"Alice Example" (site:flickr.com OR site:letterboxd.com OR site:last.fm)' in queries
    assert '"Alice Example" (site:bandcamp.com OR site:mixcloud.com OR site:tryhackme.com)' in queries
    assert '"Alice Example" (site:strava.com/athletes OR site:strava.com/pros)' in queries
    assert '"Alice Example" site:quora.com/profile' in queries
    assert '"Alice Example" (site:unsplash.com/@ OR site:500px.com/p)' in queries
    assert '"Alice Example" site:artstation.com' in queries
    assert '"Alice Example" site:deviantart.com' in queries
    assert '"Alice Example" site:snapchat.com/add' in queries


def test_public_search_dork_hosts_track_supported_profile_hosts() -> None:
    supported_hosts = _supported_public_profile_hosts_for_dork_coverage()
    name_hosts = _site_filters_from_name_dorks()
    phone_hosts = {host.lower() for host in _PHONE_DORK_SUPPLEMENTAL_PROFILE_SITES}

    assert sorted(supported_hosts - name_hosts) == []
    assert sorted(supported_hosts - phone_hosts) == []


def test_search_name_media_profile_dorks_feed_recursive_profiles(
    monkeypatch,
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.db"
    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            CREATE TABLE audit_log (
                id INTEGER PRIMARY KEY,
                engagement_id INTEGER NOT NULL,
                phase TEXT,
                module TEXT,
                action TEXT,
                target TEXT,
                result TEXT,
                operator TEXT
            )
            """
        )
        con.commit()
    finally:
        con.close()

    bodies_by_query = {
        '"Alice Example" (site:kaggle.com OR site:speakerdeck.com OR site:slideshare.net)': (
            "https://www.kaggle.com/alicekaggle/code "
            "https://speakerdeck.com/alicespeaker/security-briefing "
            "https://www.slideshare.net/aliceslides/security-briefing"
        ),
        '"Alice Example" (site:medium.com OR site:hashnode.com OR site:substack.com)': (
            "https://alicemedium.medium.com/signal-boost "
            "https://medium.com/topic/security "
            "https://hashnode.com/@alicehash/articles/one "
            "https://hashnode.com/explore "
            "https://alicesubstack.substack.com/p/dispatch "
            "https://substack.com/@alicenotes "
            "https://substack.com/home"
        ),
        '"Alice Example" (site:launchpad.net/~ OR site:sourceforge.net/u)': (
            "https://launchpad.net/~alicelp "
            "https://launchpad.net/projects/acme "
            "https://sourceforge.net/u/alicesf/profile/ "
            "https://sourceforge.net/projects/acme"
        ),
        '"Alice Example" (site:replit.com/@ OR site:codesandbox.io/u OR site:devpost.com OR site:read.cv)': (
            "https://replit.com/@alicerepl/security-lab "
            "https://replit.com/templates "
            "https://codesandbox.io/u/alicesandbox/sandboxes "
            "https://codesandbox.io/templates "
            "https://devpost.com/alicedevpost "
            "https://devpost.com/hackathons "
            "https://read.cv/aliceread "
            "https://read.cv/jobs"
        ),
        '"Alice Example" (site:codepen.io OR site:hub.docker.com/u OR site:hub.docker.com/r)': (
            "https://codepen.io/alicepen/pen/security "
            "https://codepen.io/pen "
            "https://hub.docker.com/u/alicedocker "
            "https://hub.docker.com/r/aliceimage/api "
            "https://hub.docker.com/search?q=security "
            "https://hub.docker.com/r/library/nginx"
        ),
        '"Alice Example" (site:rubygems.org/profiles OR site:crates.io/users OR site:packagist.org/users)': (
            "https://rubygems.org/profiles/aliceruby "
            "https://rubygems.org/gems/not-a-profile "
            "https://crates.io/users/alicecrates "
            "https://crates.io/crates/not-a-profile "
            "https://packagist.org/users/alicepackagist "
            "https://packagist.org/packages/acme/not-a-profile"
        ),
        '"Alice Example" (site:nuget.org/profiles OR site:hex.pm/users OR site:steamcommunity.com/id)': (
            "https://www.nuget.org/profiles/alicenuget "
            "https://www.nuget.org/packages/not-a-profile "
            "https://hex.pm/users/alicehex "
            "https://hex.pm/packages/not-a-profile "
            "https://steamcommunity.com/id/alicesteam "
            "https://steamcommunity.com/profiles/76561198000000000"
        ),
        '"Alice Example" (site:yeswehack.com/hunters OR site:opencollective.com OR site:liberapay.com)': (
            "https://yeswehack.com/hunters/aliceywh "
            "https://yeswehack.com/programs/acme "
            "https://opencollective.com/alicecollective "
            "https://opencollective.com/discover "
            "https://liberapay.com/alicelibera/ "
            "https://liberapay.com/explore"
        ),
        '"Alice Example" (site:app.intigriti.com/researcher/profile OR site:intigriti.com/researcher/profile OR site:openbugbounty.org/researchers)': (
            "https://app.intigriti.com/researcher/profile/aliceinti/activity "
            "https://www.intigriti.com/researcher/profile/alicecanonical "
            "https://app.intigriti.com/programs/acme/detail "
            "https://www.openbugbounty.org/researchers/aliceobb/ "
            "https://www.openbugbounty.org/faq/"
        ),
        '"Alice Example" site:news.ycombinator.com/user': (
            "https://news.ycombinator.com/user?id=alicehn "
            "https://news.ycombinator.com/item?id=123456 "
            "https://news.ycombinator.com/user?id=news"
        ),
        '"Alice Example" (site:patreon.com OR site:ko-fi.com OR site:buymeacoffee.com)': (
            "https://www.patreon.com/alicepatreon "
            "https://www.patreon.com/join "
            "https://ko-fi.com/alicekofi "
            "https://ko-fi.com/home "
            "https://www.buymeacoffee.com/alicecoffee "
            "https://www.buymeacoffee.com/explore"
        ),
        '"Alice Example" (site:beacons.ai OR site:bio.link OR site:bio.site OR site:allmylinks.com OR site:lnk.bio OR site:solo.to)': (
            "https://beacons.ai/alicebeacon "
            "https://bio.link/alicebio "
            "https://bio.site/alicebiosite "
            "https://bio.site/login "
            "https://allmylinks.com/aliceaml "
            "https://allmylinks.com/settings "
            "https://lnk.bio/alicelnk "
            "https://solo.to/alicesolo"
        ),
        '"Alice Example" (site:campsite.bio OR site:bento.me OR site:hoo.be OR site:taplink.cc OR site:msha.ke)': (
            "https://campsite.bio/alicecamp "
            "https://campsite.bio/pricing "
            "https://bento.me/alicebento "
            "https://bento.me/pricing "
            "https://hoo.be/alicehoo "
            "https://hoo.be/discover "
            "https://taplink.cc/alicetap "
            "https://taplink.cc/pricing "
            "https://msha.ke/go.alicemilk "
            "https://msha.ke/login"
        ),
        '"Alice Example" (site:carrd.co OR site:muckrack.com OR site:open.spotify.com/user)': (
            "https://alicecard.carrd.co "
            "https://carrd.co/templates "
            "https://muckrack.com/alicemuck "
            "https://muckrack.com/search "
            "https://open.spotify.com/user/alicespotify "
            "https://open.spotify.com/artist/123456"
        ),
        '"Alice Example" (site:indiehackers.com OR site:polywork.com OR site:contra.com OR site:adplist.org/mentors)': (
            "https://www.indiehackers.com/alicefounder "
            "https://www.indiehackers.com/post/growth-tactics "
            "https://www.polywork.com/aliceops "
            "https://www.polywork.com/companies/acme "
            "https://contra.com/aliceconsultant "
            "https://contra.com/discover/designers "
            "https://adplist.org/mentors/alice-mentor "
            "https://adplist.org/explore"
        ),
        '"Alice Example" (site:youtube.com OR site:tiktok.com OR site:twitch.tv)': (
            "https://www.youtube.com/@aliceops "
            "https://www.tiktok.com/@alicetok "
            "https://www.twitch.tv/alicestream"
        ),
        '"Alice Example" (site:pinterest.com OR site:vimeo.com OR site:soundcloud.com)': (
            "https://www.pinterest.com/alicepins/security "
            "https://vimeo.com/alicevideo/security "
            "https://soundcloud.com/alicesound/security"
        ),
        '"Alice Example" (site:flickr.com OR site:letterboxd.com OR site:last.fm)': (
            "https://www.flickr.com/photos/aliceflickr/123 "
            "https://letterboxd.com/alicefilm/films/reviews "
            "https://www.last.fm/user/alicelast"
        ),
        '"Alice Example" (site:bandcamp.com OR site:mixcloud.com OR site:tryhackme.com)': (
            "https://aliceband.bandcamp.com/album/security "
            "https://www.mixcloud.com/alicemix/security "
            "https://tryhackme.com/p/alicethm"
        ),
        '"Alice Example" (site:strava.com/athletes OR site:strava.com/pros)': (
            "https://www.strava.com/athletes/12345678 "
            "https://www.strava.com/clubs/acme-cycling"
        ),
        '"Alice Example" site:quora.com/profile': (
            "https://www.quora.com/profile/Alice-Example-1 "
            "https://www.quora.com/What-is-OSINT"
        ),
        '"Alice Example" (site:unsplash.com/@ OR site:500px.com/p)': (
            "https://unsplash.com/@alicephotos "
            "https://unsplash.com/photos/abcdef "
            "https://500px.com/p/alicephoto "
            "https://500px.com/photo/123456/security"
        ),
        '"Alice Example" site:artstation.com': (
            "https://www.artstation.com/aliceartist "
            "https://aliceportfolio.artstation.com/projects/security-briefing "
            "https://www.artstation.com/artwork/abc123 "
            "https://www.artstation.com/marketplace/p/security-asset"
        ),
        '"Alice Example" site:deviantart.com': (
            "https://www.deviantart.com/alicedeviant/art/security-briefing "
            "https://alicelegacy.deviantart.com/gallery "
            "https://www.deviantart.com/users/login "
            "https://www.deviantart.com/tag/security"
        ),
        '"Alice Example" site:snapchat.com/add': (
            "https://www.snapchat.com/add/alicesnap "
            "https://www.snapchat.com/discover "
            "https://www.snapchat.com/add"
        ),
        '"Alice Example" (site:behance.net OR site:dribbble.com OR site:figma.com/@)': (
            "https://www.behance.net/aliceops "
            "https://dribbble.com/alicedesign "
            "https://www.figma.com/@aliceteam "
            "https://www.figma.com/community/file/123456/design-system"
        ),
    }

    def fake_run_name_dork_batch(queries, **kwargs):  # noqa: ANN001
        del kwargs
        assert queries[-1] == '"Alice Example" profile'
        for expected_query in bodies_by_query:
            assert expected_query in queries
        return [(bodies_by_query.get(query, ""), False) for query in queries]

    monkeypatch.setattr(
        "forge.utils.intel.name_search._run_name_dork_batch",
        fake_run_name_dork_batch,
    )

    result = search_name(
        name="Alice Example",
        engagement_id=1001,
        db_path=db_path,
        max_concurrency=2,
    )

    assert result["kaggle"] == ["alicekaggle"]
    assert result["medium"] == ["alicemedium"]
    assert result["hashnode"] == ["alicehash"]
    assert result["substack"] == ["alicesubstack", "alicenotes"]
    assert result["speakerdeck"] == ["alicespeaker"]
    assert result["slideshare"] == ["aliceslides"]
    assert result["launchpad"] == ["alicelp"]
    assert result["sourceforge"] == ["alicesf"]
    assert result["replit"] == ["alicerepl"]
    assert result["codesandbox"] == ["alicesandbox"]
    assert result["devpost"] == ["alicedevpost"]
    assert result["readcv"] == ["aliceread"]
    assert result["codepen"] == ["alicepen"]
    assert result["dockerhub"] == ["alicedocker", "aliceimage"]
    assert result["rubygems"] == ["aliceruby"]
    assert result["crates"] == ["alicecrates"]
    assert result["packagist"] == ["alicepackagist"]
    assert result["nuget"] == ["alicenuget"]
    assert result["hexpm"] == ["alicehex"]
    assert result["steam"] == ["alicesteam"]
    assert result["yeswehack"] == ["aliceywh"]
    assert result["intigriti"] == ["aliceinti", "alicecanonical"]
    assert result["openbugbounty"] == ["aliceobb"]
    assert result["hackernews"] == ["alicehn"]
    assert result["opencollective"] == ["alicecollective"]
    assert result["liberapay"] == ["alicelibera"]
    assert result["patreon"] == ["alicepatreon"]
    assert result["kofi"] == ["alicekofi"]
    assert result["buymeacoffee"] == ["alicecoffee"]
    assert result["beacons"] == ["alicebeacon"]
    assert result["biolink"] == ["alicebio"]
    assert result["biosite"] == ["alicebiosite"]
    assert result["allmylinks"] == ["aliceaml"]
    assert result["lnkbio"] == ["alicelnk"]
    assert result["soloto"] == ["alicesolo"]
    assert result["campsite"] == ["alicecamp"]
    assert result["bento"] == ["alicebento"]
    assert result["hoobe"] == ["alicehoo"]
    assert result["taplink"] == ["alicetap"]
    assert result["milkshake"] == ["go.alicemilk"]
    assert result["carrd"] == ["alicecard"]
    assert result["muckrack"] == ["alicemuck"]
    assert result["spotify"] == ["alicespotify"]
    assert result["figma"] == ["aliceteam"]
    assert result["indiehackers"] == ["alicefounder"]
    assert result["polywork"] == ["aliceops"]
    assert result["contra"] == ["aliceconsultant"]
    assert result["adplist"] == ["alice-mentor"]
    assert result["youtube"] == ["aliceops"]
    assert result["tiktok"] == ["alicetok"]
    assert result["twitch"] == ["alicestream"]
    assert result["pinterest"] == ["alicepins"]
    assert result["vimeo"] == ["alicevideo"]
    assert result["soundcloud"] == ["alicesound"]
    assert result["flickr"] == ["aliceflickr"]
    assert result["letterboxd"] == ["alicefilm"]
    assert result["lastfm"] == ["alicelast"]
    assert result["bandcamp"] == ["aliceband"]
    assert result["mixcloud"] == ["alicemix"]
    assert result["tryhackme"] == ["alicethm"]
    assert result["strava"] == ["12345678"]
    assert result["quora"] == ["Alice-Example-1"]
    assert result["unsplash"] == ["alicephotos"]
    assert result["500px"] == ["alicephoto"]
    assert result["behance"] == ["aliceops"]
    assert result["dribbble"] == ["alicedesign"]
    assert result["artstation"] == ["aliceartist", "aliceportfolio"]
    assert result["deviantart"] == ["alicedeviant", "alicelegacy"]
    assert result["snapchat"] == ["alicesnap"]


def test_search_name_parallelizes_dorks_but_preserves_query_order(
    monkeypatch,
    tmp_path: Path,
) -> None:
    queries_seen: list[str] = []
    active = 0
    peak = 0
    lock = threading.Lock()

    responses = {
        '"Alice Example" site:github.com': (
            0.05,
            "https://github.com/alice-example",
            False,
        ),
        '"Alice Example" site:linkedin.com': (
            0.03,
            "https://www.linkedin.com/in/alice-example",
            False,
        ),
        '"Alice Example" profile': (
            0.01,
            "https://github.com/bob-sample",
            True,
        ),
    }

    def fake_run_name_dork(
        query: str,
        *,
        proxy=None,
        timeout: float = 12.0,
    ) -> tuple[str, bool]:  # noqa: ANN001
        del proxy, timeout
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        try:
            delay, body, used_fallback = responses.get(query, (0.02, "", False))
            time.sleep(delay)
            queries_seen.append(query)
            return body, used_fallback
        finally:
            with lock:
                active -= 1

    monkeypatch.setattr(
        "forge.utils.intel.name_search._run_name_dork",
        fake_run_name_dork,
    )

    result = search_name(
        name="Alice Example",
        engagement_id=1001,
        db_path=tmp_path / "engagement.db",
        max_concurrency=3,
    )

    assert len(queries_seen) == len(name_search._name_search_dork_queries("Alice Example"))
    assert peak == 3
    assert result["github"] == ["alice-example", "bob-sample"]
    assert result["linkedin"] == ["alice-example"]


def test_search_name_honors_concurrency_cap_of_one(
    monkeypatch,
    tmp_path: Path,
) -> None:
    active = 0
    peak = 0
    lock = threading.Lock()

    def fake_run_name_dork(
        query: str,
        *,
        proxy=None,
        timeout: float = 12.0,
    ) -> tuple[str, bool]:  # noqa: ANN001
        del proxy, timeout
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        try:
            time.sleep(0.02)
            if query == '"Alice Example" site:github.com':
                return "https://github.com/alice-example", False
            return "", False
        finally:
            with lock:
                active -= 1

    monkeypatch.setattr(
        "forge.utils.intel.name_search._run_name_dork",
        fake_run_name_dork,
    )

    result = search_name(
        name="Alice Example",
        engagement_id=1001,
        db_path=tmp_path / "engagement.db",
        max_concurrency=1,
    )

    assert peak == 1
    assert result["github"] == ["alice-example"]


def test_search_name_defaults_to_sequential_public_dorks(
    monkeypatch,
    tmp_path: Path,
) -> None:
    monkeypatch.delenv("FORGE_NAME_SEARCH_MAX_CONCURRENCY", raising=False)
    active = 0
    peak = 0
    lock = threading.Lock()

    def fake_run_name_dork(
        query: str,
        *,
        proxy=None,
        timeout: float = 12.0,
    ) -> tuple[str, bool]:  # noqa: ANN001
        del proxy, timeout
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        try:
            time.sleep(0.01)
            if query == '"Alice Example" site:github.com':
                return "https://github.com/alice-example", False
            return "", False
        finally:
            with lock:
                active -= 1

    monkeypatch.setattr(
        "forge.utils.intel.name_search._run_name_dork",
        fake_run_name_dork,
    )

    result = search_name(
        name="Alice Example",
        engagement_id=1001,
        db_path=tmp_path / "engagement.db",
    )

    assert peak == 1
    assert result["github"] == ["alice-example"]


def test_search_name_default_concurrency_can_be_raised_by_env(monkeypatch) -> None:
    monkeypatch.setenv("FORGE_NAME_SEARCH_MAX_CONCURRENCY", "3")

    assert name_search._name_search_max_concurrency_default() == 3


def test_run_name_dork_applies_search_dork_delay(monkeypatch) -> None:
    monkeypatch.setenv("FORGE_SEARCH_DORK_REQUEST_DELAY_SECONDS", "0.2")
    sleeps: list[float] = []
    monkeypatch.setattr(name_search.time, "sleep", lambda seconds: sleeps.append(float(seconds)))
    monkeypatch.setattr(name_search, "_ddg_html_search", lambda *_args, **_kwargs: "x" * 600)
    monkeypatch.setattr(
        name_search,
        "_bing_html_search",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("fallback not expected")),
    )

    result, used_fallback = name_search._run_name_dork('"Alice Example" profile')

    assert result == "x" * 600
    assert used_fallback is False
    assert len(sleeps) == 1
    assert sleeps[0] >= 0.2


def test_search_name_extracts_broader_profile_handles_and_filters_reserved_routes(
    monkeypatch,
    tmp_path: Path,
) -> None:
    def fake_run_name_dork_batch(
        queries: list[str],
        *,
        proxy=None,
        timeout: float = 12.0,
        max_workers: int = 3,
    ) -> list[tuple[str, bool]]:  # noqa: ANN001
        del queries, proxy, timeout, max_workers
        return [
            (
                " ".join(
                    [
                        "https://gitlab.com/aliceforge",
                        "https://gist.github.com/alicegist/abcdef1234567890",
                        "https://gist.github.com/discover",
                        "https://bitbucket.org/alicebucket/platform-repo",
                        "https://bsky.app/profile/alice.blue",
                        "https://www.threads.net/@alicethread",
                        "https://www.reddit.com/user/alicered/comments",
                        "https://dev.to/alicedev/latest-post",
                        "https://about.me/aliceabout",
                        "https://github.com/settings/profile",
                        "https://medium.com/topic/security",
                        "https://bitbucket.org/product/features",
                    ]
                ),
                False,
            )
        ]

    monkeypatch.setattr(
        "forge.utils.intel.name_search._run_name_dork_batch",
        fake_run_name_dork_batch,
    )

    result = search_name(
        name="Alice Example",
        engagement_id=1001,
        db_path=tmp_path / "engagement.db",
        max_concurrency=2,
    )

    assert result["gitlab"] == ["aliceforge"]
    assert result["github_gist"] == ["alicegist"]
    assert result["bitbucket"] == ["alicebucket"]
    assert result["bluesky"] == ["alice.blue"]
    assert result["threads"] == ["alicethread"]
    assert result["reddit"] == ["alicered"]
    assert result["devto"] == ["alicedev"]
    assert result["aboutme"] == ["aliceabout"]
    assert "github" not in result
    assert "medium" not in result


def test_search_name_persists_social_profiles_and_audit_metadata(
    monkeypatch,
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.db"
    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            CREATE TABLE audit_log (
                id INTEGER PRIMARY KEY,
                engagement_id INTEGER NOT NULL,
                phase TEXT,
                module TEXT,
                action TEXT,
                target TEXT,
                result TEXT,
                operator TEXT
            )
            """
        )
        con.commit()
    finally:
        con.close()

    def fake_run_name_dork_batch(
        queries: list[str],
        *,
        proxy=None,
        timeout: float = 12.0,
        max_workers: int = 3,
    ) -> list[tuple[str, bool]]:  # noqa: ANN001
        del proxy, timeout, max_workers
        return [
            (
                "https://github.com/alice-example "
                "https://www.linkedin.com/in/alice-example "
                "https://medium.com/@alice-writes",
                True,
            ),
        ] + [("", False) for _ in queries[1:]]

    monkeypatch.setattr(
        "forge.utils.intel.name_search._run_name_dork_batch",
        fake_run_name_dork_batch,
    )

    result = search_name(
        name="Alice Example",
        engagement_id=1001,
        db_path=db_path,
        max_concurrency=2,
    )

    assert result["github"] == ["alice-example"]
    assert result["linkedin"] == ["alice-example"]
    assert result["medium"] == ["alice-writes"]

    con = sqlite3.connect(db_path)
    try:
        rows = con.execute(
            """
            SELECT email, source
            FROM social_profiles
            WHERE engagement_id=1001
            ORDER BY source
            """
        ).fetchall()
        assert rows == [
            ("name:Alice Example", "name_search:github:alice-example"),
            ("name:Alice Example", "name_search:linkedin:alice-example"),
            ("name:Alice Example", "name_search:medium:alice-writes"),
        ]

        audit_row = con.execute(
            """
            SELECT target, result, operator
            FROM audit_log
            WHERE engagement_id=1001
            ORDER BY id DESC
            LIMIT 1
            """
        ).fetchone()
        assert audit_row is not None
        assert audit_row[0] == "Alice Example"
        payload = json.loads(str(audit_row[1] or "{}"))
        assert payload["used_ddg_fallback"] is True
        assert audit_row[2] == "kill_chain"
    finally:
        con.close()


def test_search_name_persists_company_profile_rows_for_recursive_synthesis(
    monkeypatch,
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.db"
    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            CREATE TABLE audit_log (
                id INTEGER PRIMARY KEY,
                engagement_id INTEGER NOT NULL,
                phase TEXT,
                module TEXT,
                action TEXT,
                target TEXT,
                result TEXT,
                operator TEXT
            )
            """
        )
        con.commit()
    finally:
        con.close()

    def fake_run_name_dork_batch(
        queries: list[str],
        *,
        proxy=None,
        timeout: float = 12.0,
        max_workers: int = 3,
    ) -> list[tuple[str, bool]]:  # noqa: ANN001
        del proxy, timeout, max_workers
        return [
            (
                " ".join(
                    [
                        "https://www.linkedin.com/company/acme-research",
                        "https://github.com/orgs/acme-red-team/people",
                        "https://www.facebook.com/pages/Acme-Facebook/123456789",
                        "https://wellfound.com/company/acme-foundry",
                        "https://angel.co/company/acme-ventures",
                        "https://www.producthunt.com/products/not-a-profile",
                    ]
                ),
                False,
            ),
        ] + [("", False) for _ in queries[1:]]

    monkeypatch.setattr(
        "forge.utils.intel.name_search._run_name_dork_batch",
        fake_run_name_dork_batch,
    )

    result = search_name(
        name="Alice Example",
        engagement_id=1001,
        db_path=db_path,
        max_concurrency=2,
    )

    assert result == {}

    con = sqlite3.connect(db_path)
    try:
        rows = con.execute(
            """
            SELECT email, source, profile_data
            FROM social_profiles
            WHERE engagement_id=1001
            ORDER BY email, source
            """
        ).fetchall()
        assert [(row[0], row[1]) for row in rows] == [
            ("company:Acme Facebook", "name_search:facebook:Acme-Facebook"),
            ("company:Acme Foundry", "name_search:wellfound:Acme-Foundry"),
            ("company:Acme Red Team", "name_search:github:Acme-Red-Team"),
            ("company:Acme Research", "name_search:linkedin_company:Acme-Research"),
            ("company:Acme Ventures", "name_search:angellist:Acme-Ventures"),
        ]
        profile_payloads = [json.loads(str(row[2] or "{}")) for row in rows]
        assert {
            (payload["platform"], payload["company"], payload["profile_url"])
            for payload in profile_payloads
        } == {
            (
                "facebook",
                "Acme Facebook",
                "https://www.facebook.com/pages/Acme-Facebook/123456789",
            ),
            (
                "github",
                "Acme Red Team",
                "https://github.com/orgs/acme-red-team/people",
            ),
            (
                "wellfound",
                "Acme Foundry",
                "https://wellfound.com/company/acme-foundry",
            ),
            (
                "angellist",
                "Acme Ventures",
                "https://angel.co/company/acme-ventures",
            ),
            (
                "linkedin_company",
                "Acme Research",
                "https://www.linkedin.com/company/acme-research",
            ),
        }

        audit_payload = json.loads(
            str(
                con.execute(
                    """
                    SELECT result
                    FROM audit_log
                    WHERE engagement_id=1001
                    ORDER BY id DESC
                    LIMIT 1
                    """
                ).fetchone()[0]
                or "{}"
            )
        )
        assert audit_payload["profile_hits"] == {}
        assert [
            (hit["platform"], hit["company"])
            for hit in audit_payload["company_profile_hits"]
        ] == [
            ("linkedin_company", "Acme Research"),
            ("github", "Acme Red Team"),
            ("facebook", "Acme Facebook"),
            ("wellfound", "Acme Foundry"),
            ("angellist", "Acme Ventures"),
        ]
    finally:
        con.close()


def test_search_name_company_profiles_feed_synthesis_company_fanout(
    monkeypatch,
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_engagement_for_synthesis(db_path)

    def fake_run_name_dork_batch(
        queries: list[str],
        *,
        proxy=None,
        timeout: float = 12.0,
        max_workers: int = 3,
    ) -> list[tuple[str, bool]]:  # noqa: ANN001
        del proxy, timeout, max_workers
        return [
            (
                " ".join(
                    [
                        "https://www.linkedin.com/company/acme-research",
                        "https://github.com/orgs/acme-red-team/people",
                        "https://wellfound.com/company/acme-foundry",
                        "https://angel.co/company/acme-ventures",
                    ]
                ),
                False,
            )
        ] + [("", False) for _ in queries[1:]]

    monkeypatch.setattr(
        "forge.utils.intel.name_search._run_name_dork_batch",
        fake_run_name_dork_batch,
    )

    result = search_name(
        name="Alice Example",
        engagement_id=1001,
        db_path=db_path,
        max_concurrency=2,
    )

    assert result == {}

    summary = EngagementSynthesisEngine(db_path, 1001, depth_limit=3).run()

    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        seed_rows = {
            (str(row["seed_value"]), str(row["seed_type"])): {
                "source": str(row["source"]),
                "metadata": json.loads(str(row["metadata_json"] or "{}")),
            }
            for row in con.execute(
                """
                SELECT seed_value, seed_type, source, metadata_json
                FROM engagement_seeds
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
        assert ("Acme Research", "company") in seed_rows
        assert ("Acme Red Team", "company") in seed_rows
        assert ("Acme Foundry", "company") in seed_rows
        assert ("Acme Ventures", "company") in seed_rows
        assert seed_rows[("Acme Research", "company")]["source"] == "discovered"
        assert seed_rows[("Acme Red Team", "company")]["source"] == "discovered"
        assert seed_rows[("Acme Foundry", "company")]["source"] == "discovered"
        assert seed_rows[("Acme Ventures", "company")]["source"] == "discovered"
        assert seed_rows[("Acme Research", "company")]["metadata"]["rule"] == "social_profile_anchor"
        assert seed_rows[("Acme Red Team", "company")]["metadata"]["rule"] == "social_profile_anchor"
        assert seed_rows[("Acme Foundry", "company")]["metadata"]["rule"] == "social_profile_anchor"
        assert seed_rows[("Acme Ventures", "company")]["metadata"]["rule"] == "social_profile_anchor"
        assert summary.seeds_inserted >= 4
    finally:
        con.close()


def test_search_name_persists_broader_supported_profile_rows(
    monkeypatch,
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.db"
    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            CREATE TABLE audit_log (
                id INTEGER PRIMARY KEY,
                engagement_id INTEGER NOT NULL,
                phase TEXT,
                module TEXT,
                action TEXT,
                target TEXT,
                result TEXT,
                operator TEXT
            )
            """
        )
        con.commit()
    finally:
        con.close()

    monkeypatch.setattr(
        "forge.utils.intel.name_search._run_name_dork_batch",
        lambda queries, **kwargs: [
            (
                " ".join(
                    [
                        "https://gitlab.com/aliceforge",
                        "https://gist.github.com/alicegist/abcdef1234567890",
                        "https://gist.github.com/discover",
                        "https://bitbucket.org/alicebucket/platform-repo",
                        "https://bsky.app/profile/alice.blue",
                        "https://www.threads.net/@alicethread",
                        "https://www.reddit.com/user/alicered/comments",
                        "https://dev.to/alicedev/latest-post",
                        "https://about.me/aliceabout",
                        "https://www.facebook.com/people/Alice-Example/1000123456789/",
                        "https://alicemedium.medium.com",
                        "https://alicesubstack.substack.com",
                        "https://calendly.com/alicecal/intro",
                        "https://cal.com/alicebook/security",
                        "https://beacons.ai/alicebeacon",
                        "https://bio.link/alicebio",
                        "https://bio.site/alicebiosite",
                        "https://allmylinks.com/aliceaml",
                        "https://lnk.bio/alicelnk",
                        "https://solo.to/alicesolo",
                        "https://campsite.bio/alicecamp",
                        "https://bento.me/alicebento",
                        "https://hoo.be/alicehoo",
                        "https://taplink.cc/alicetap",
                        "https://msha.ke/go.alicemilk",
                        "https://alicecard.carrd.co",
                        "https://muckrack.com/alicemuck",
                        "https://open.spotify.com/user/alicespotify",
                        "https://launchpad.net/~alicelp",
                        "https://sourceforge.net/u/alicesf/profile/",
                        "https://replit.com/@alicerepl/security-lab",
                        "https://codesandbox.io/u/alicesandbox/sandboxes",
                        "https://devpost.com/alicedevpost",
                        "https://read.cv/aliceread",
                        "https://yeswehack.com/hunters/aliceywh",
                        "https://opencollective.com/alicecollective",
                        "https://liberapay.com/alicelibera",
                        "https://www.patreon.com/alicepatreon",
                        "https://ko-fi.com/alicekofi",
                        "https://www.buymeacoffee.com/alicecoffee",
                        "https://www.producthunt.com/@alicebuilder",
                        "https://www.producthunt.com/users/alicehunter",
                        "https://wellfound.com/u/alicefounder",
                        "https://angel.co/u/aliceangel",
                        "https://orcid.org/0000-0002-1825-0097",
                        "https://www.researchgate.net/profile/Alice-Example",
                        "https://scholar.google.com/citations?user=qc6CJjYAAAAJ",
                        "https://scholar.google.com/citations?view_op=search_authors",
                        "https://www.academia.edu/AliceAcademic",
                        "https://www.academia.edu/people/search",
                        "https://www.semanticscholar.org/author/Alice-Example/123",
                        "https://www.semanticscholar.org/paper/123",
                        "https://zenodo.org/users/alicezenodo",
                        "https://zenodo.org/records/123",
                        "https://figshare.com/authors/Alice_Example/123456",
                        "https://figshare.com/articles/dataset/example/123456",
                        "https://www.credly.com/users/alice-ops/badges",
                        "https://www.behance.net/aliceops",
                        "https://dribbble.com/alicedesign",
                        "https://bugcrowd.com/alicebug",
                        "https://hackerone.com/alicehacker",
                        "https://app.intigriti.com/researcher/profile/aliceinti/activity",
                        "https://app.intigriti.com/programs/acme/detail",
                        "https://www.openbugbounty.org/researchers/aliceobb/",
                        "https://www.openbugbounty.org/faq/",
                        "https://news.ycombinator.com/user?id=alicehn",
                        "https://news.ycombinator.com/item?id=123456",
                        "https://news.ycombinator.com/user?id=news",
                        "https://stackoverflow.com/users/12345/alice-stack",
                        "https://security.stackexchange.com/users/67890/alice-security",
                        "https://stackoverflow.com/questions/12345/not-a-profile",
                    ]
                ),
                False,
            )
        ]
        + [("", False) for _ in queries[1:]],
    )

    result = search_name(
        name="Alice Example",
        engagement_id=1001,
        db_path=db_path,
        max_concurrency=2,
    )

    assert result["gitlab"] == ["aliceforge"]
    assert result["github_gist"] == ["alicegist"]
    assert result["bitbucket"] == ["alicebucket"]
    assert result["bluesky"] == ["alice.blue"]
    assert result["threads"] == ["alicethread"]
    assert result["reddit"] == ["alicered"]
    assert result["devto"] == ["alicedev"]
    assert result["aboutme"] == ["aliceabout"]
    assert result["facebook"] == ["Alice-Example"]
    assert result["medium"] == ["alicemedium"]
    assert result["substack"] == ["alicesubstack"]
    assert result["calendly"] == ["alicecal"]
    assert result["calcom"] == ["alicebook"]
    assert result["beacons"] == ["alicebeacon"]
    assert result["biolink"] == ["alicebio"]
    assert result["biosite"] == ["alicebiosite"]
    assert result["allmylinks"] == ["aliceaml"]
    assert result["lnkbio"] == ["alicelnk"]
    assert result["soloto"] == ["alicesolo"]
    assert result["campsite"] == ["alicecamp"]
    assert result["bento"] == ["alicebento"]
    assert result["hoobe"] == ["alicehoo"]
    assert result["taplink"] == ["alicetap"]
    assert result["milkshake"] == ["go.alicemilk"]
    assert result["carrd"] == ["alicecard"]
    assert result["muckrack"] == ["alicemuck"]
    assert result["spotify"] == ["alicespotify"]
    assert result["launchpad"] == ["alicelp"]
    assert result["sourceforge"] == ["alicesf"]
    assert result["replit"] == ["alicerepl"]
    assert result["codesandbox"] == ["alicesandbox"]
    assert result["devpost"] == ["alicedevpost"]
    assert result["readcv"] == ["aliceread"]
    assert result["yeswehack"] == ["aliceywh"]
    assert result["opencollective"] == ["alicecollective"]
    assert result["liberapay"] == ["alicelibera"]
    assert result["patreon"] == ["alicepatreon"]
    assert result["kofi"] == ["alicekofi"]
    assert result["buymeacoffee"] == ["alicecoffee"]
    assert result["producthunt"] == ["alicebuilder", "alicehunter"]
    assert result["wellfound"] == ["alicefounder"]
    assert result["angellist"] == ["aliceangel"]
    assert result["orcid"] == ["0000-0002-1825-0097"]
    assert result["researchgate"] == ["Alice-Example"]
    assert result["google_scholar"] == ["qc6CJjYAAAAJ"]
    assert result["academia"] == ["AliceAcademic"]
    assert result["semantic_scholar"] == ["Alice-Example"]
    assert result["zenodo"] == ["alicezenodo"]
    assert result["figshare"] == ["Alice_Example"]
    assert result["credly"] == ["alice-ops"]
    assert result["behance"] == ["aliceops"]
    assert result["dribbble"] == ["alicedesign"]
    assert result["bugcrowd"] == ["alicebug"]
    assert result["hackernews"] == ["alicehn"]
    assert result["hackerone"] == ["alicehacker"]
    assert result["intigriti"] == ["aliceinti"]
    assert result["openbugbounty"] == ["aliceobb"]
    assert result["stackoverflow"] == ["alice-stack"]
    assert result["stackexchange"] == ["alice-security"]

    con = sqlite3.connect(db_path)
    try:
        rows = con.execute(
            """
            SELECT email, source
            FROM social_profiles
            WHERE engagement_id=1001
            ORDER BY source
            """
        ).fetchall()
        assert rows == [
            ("name:Alice Example", "name_search:aboutme:aliceabout"),
            ("name:Alice Example", "name_search:academia:AliceAcademic"),
            ("name:Alice Example", "name_search:allmylinks:aliceaml"),
            ("name:Alice Example", "name_search:angellist:aliceangel"),
            ("name:Alice Example", "name_search:beacons:alicebeacon"),
            ("name:Alice Example", "name_search:behance:aliceops"),
            ("name:Alice Example", "name_search:bento:alicebento"),
            ("name:Alice Example", "name_search:biolink:alicebio"),
            ("name:Alice Example", "name_search:biosite:alicebiosite"),
            ("name:Alice Example", "name_search:bitbucket:alicebucket"),
            ("name:Alice Example", "name_search:bluesky:alice.blue"),
            ("name:Alice Example", "name_search:bugcrowd:alicebug"),
            ("name:Alice Example", "name_search:buymeacoffee:alicecoffee"),
            ("name:Alice Example", "name_search:calcom:alicebook"),
            ("name:Alice Example", "name_search:calendly:alicecal"),
            ("name:Alice Example", "name_search:campsite:alicecamp"),
            ("name:Alice Example", "name_search:carrd:alicecard"),
            ("name:Alice Example", "name_search:codesandbox:alicesandbox"),
            ("name:Alice Example", "name_search:credly:alice-ops"),
            ("name:Alice Example", "name_search:devpost:alicedevpost"),
            ("name:Alice Example", "name_search:devto:alicedev"),
            ("name:Alice Example", "name_search:dribbble:alicedesign"),
            ("name:Alice Example", "name_search:facebook:Alice-Example"),
            ("name:Alice Example", "name_search:figshare:Alice_Example"),
            ("name:Alice Example", "name_search:github_gist:alicegist"),
            ("name:Alice Example", "name_search:gitlab:aliceforge"),
            ("name:Alice Example", "name_search:google_scholar:qc6CJjYAAAAJ"),
            ("name:Alice Example", "name_search:hackernews:alicehn"),
            ("name:Alice Example", "name_search:hackerone:alicehacker"),
            ("name:Alice Example", "name_search:hoobe:alicehoo"),
            ("name:Alice Example", "name_search:intigriti:aliceinti"),
            ("name:Alice Example", "name_search:kofi:alicekofi"),
            ("name:Alice Example", "name_search:launchpad:alicelp"),
            ("name:Alice Example", "name_search:liberapay:alicelibera"),
            ("name:Alice Example", "name_search:lnkbio:alicelnk"),
            ("name:Alice Example", "name_search:medium:alicemedium"),
            ("name:Alice Example", "name_search:milkshake:go.alicemilk"),
            ("name:Alice Example", "name_search:muckrack:alicemuck"),
            ("name:Alice Example", "name_search:openbugbounty:aliceobb"),
            ("name:Alice Example", "name_search:opencollective:alicecollective"),
            ("name:Alice Example", "name_search:orcid:0000-0002-1825-0097"),
            ("name:Alice Example", "name_search:patreon:alicepatreon"),
            ("name:Alice Example", "name_search:producthunt:alicebuilder"),
            ("name:Alice Example", "name_search:producthunt:alicehunter"),
            ("name:Alice Example", "name_search:readcv:aliceread"),
            ("name:Alice Example", "name_search:reddit:alicered"),
            ("name:Alice Example", "name_search:replit:alicerepl"),
            ("name:Alice Example", "name_search:researchgate:Alice-Example"),
            ("name:Alice Example", "name_search:semantic_scholar:Alice-Example"),
            ("name:Alice Example", "name_search:soloto:alicesolo"),
            ("name:Alice Example", "name_search:sourceforge:alicesf"),
            ("name:Alice Example", "name_search:spotify:alicespotify"),
            ("name:Alice Example", "name_search:stackexchange:alice-security"),
            ("name:Alice Example", "name_search:stackoverflow:alice-stack"),
            ("name:Alice Example", "name_search:substack:alicesubstack"),
            ("name:Alice Example", "name_search:taplink:alicetap"),
            ("name:Alice Example", "name_search:threads:alicethread"),
            ("name:Alice Example", "name_search:wellfound:alicefounder"),
            ("name:Alice Example", "name_search:yeswehack:aliceywh"),
            ("name:Alice Example", "name_search:zenodo:alicezenodo"),
        ]
    finally:
        con.close()
