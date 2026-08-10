from __future__ import annotations

import json
import sqlite3
import sys
import threading
import time
import types
from pathlib import Path
from urllib.parse import quote_plus

from forge.utils.intel import http_pacing, phone_lookup
from forge.utils.intel.phone_lookup import _mine_dork_urls, lookup_phone


def _dork_url(site: str) -> str:
    quoted_phone = quote_plus('"15551234567"')
    return f"https://www.google.com/search?q={quoted_phone}+site%3A{site}"


def test_mine_dork_urls_parallelizes_site_queries_but_preserves_site_order(monkeypatch) -> None:
    delays = {
        "twitter.com": 0.05,
        "instagram.com": 0.01,
        "linkedin.com": 0.03,
    }
    active = 0
    peak = 0
    lock = threading.Lock()

    class _FakeResponse:
        def __init__(self, text: str) -> None:
            self.status_code = 200
            self.text = text

    class _FakeClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
            del args, kwargs

        def __enter__(self) -> "_FakeClient":
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, params: dict[str, str] | None = None) -> _FakeResponse:
            del url
            nonlocal active, peak
            site = str((params or {}).get("q", "")).split("site:", 1)[1]
            with lock:
                active += 1
                peak = max(peak, active)
            try:
                time.sleep(delays[site])
                payloads = {
                    "twitter.com": (
                        "uddg=https%3A%2F%2Ftwitter.com%2Facmeintel"
                        "&uddg=https%3A%2F%2Fresearch.acme.co%2Fteam%3Femail%3Dalpha%40acme.co"
                    ),
                    "instagram.com": ("uddg=https%3A%2F%2Finstagram.com%2Fbravo.ops"),
                    "linkedin.com": ("uddg=https%3A%2F%2Fwww.linkedin.com%2Fin%2Falice-example"),
                }
                return _FakeResponse(payloads[site])
            finally:
                with lock:
                    active -= 1

    monkeypatch.setitem(sys.modules, "httpx", types.SimpleNamespace(Client=_FakeClient))

    result = _mine_dork_urls(
        "+15551234567",
        [
            _dork_url("twitter.com"),
            _dork_url("instagram.com"),
            _dork_url("linkedin.com"),
        ],
        max_dorks=3,
        max_workers=2,
    )

    assert result["sites_searched"] == ["twitter.com", "instagram.com", "linkedin.com"]
    assert "alpha@acme.co" in result["emails_found"]
    assert "acmeintel" in result["usernames_found"]
    assert "bravo.ops" in result["usernames_found"]
    assert "alice-example" in result["usernames_found"]
    assert "https://twitter.com/acmeintel" in result["urls_found"]
    assert peak == 2


def test_mine_dork_urls_honors_worker_cap_of_one(monkeypatch) -> None:
    active = 0
    peak = 0
    lock = threading.Lock()

    class _FakeResponse:
        def __init__(self, text: str) -> None:
            self.status_code = 200
            self.text = text

    class _FakeClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
            del args, kwargs

        def __enter__(self) -> "_FakeClient":
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, params: dict[str, str] | None = None) -> _FakeResponse:
            del url, params
            nonlocal active, peak
            with lock:
                active += 1
                peak = max(peak, active)
            try:
                time.sleep(0.02)
                return _FakeResponse("uddg=https%3A%2F%2Ftwitter.com%2Facmeintel")
            finally:
                with lock:
                    active -= 1

    monkeypatch.setitem(sys.modules, "httpx", types.SimpleNamespace(Client=_FakeClient))

    result = _mine_dork_urls(
        "+15551234567",
        [
            _dork_url("twitter.com"),
            _dork_url("instagram.com"),
            _dork_url("linkedin.com"),
        ],
        max_dorks=3,
        max_workers=1,
    )

    assert result["sites_searched"] == ["twitter.com", "instagram.com", "linkedin.com"]
    assert peak == 1


def test_mine_dork_urls_defaults_to_sequential_public_search(monkeypatch) -> None:
    monkeypatch.delenv("FORGE_PHONE_DORK_MAX_CONCURRENCY", raising=False)
    active = 0
    peak = 0
    lock = threading.Lock()

    class _FakeResponse:
        status_code = 200
        text = "uddg=https%3A%2F%2Ftwitter.com%2Facmeintel"

    class _FakeClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
            del args, kwargs

        def __enter__(self) -> "_FakeClient":
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, params: dict[str, str] | None = None) -> _FakeResponse:
            del url, params
            nonlocal active, peak
            with lock:
                active += 1
                peak = max(peak, active)
            try:
                time.sleep(0.01)
                return _FakeResponse()
            finally:
                with lock:
                    active -= 1

    monkeypatch.setitem(sys.modules, "httpx", types.SimpleNamespace(Client=_FakeClient))

    result = _mine_dork_urls(
        "+15551234567",
        [
            _dork_url("twitter.com"),
            _dork_url("instagram.com"),
            _dork_url("linkedin.com"),
        ],
        max_dorks=3,
    )

    assert result["sites_searched"] == ["twitter.com", "instagram.com", "linkedin.com"]
    assert result["usernames_found"] == ["acmeintel"]
    assert peak == 1


def test_phone_dork_default_concurrency_can_be_raised_by_env(monkeypatch) -> None:
    monkeypatch.setenv("FORGE_PHONE_DORK_MAX_CONCURRENCY", "3")

    assert phone_lookup._phone_dork_max_workers_default() == 3


def test_mine_dork_urls_applies_search_dork_delay(monkeypatch) -> None:
    monkeypatch.setenv("FORGE_SEARCH_DORK_REQUEST_DELAY_SECONDS", "0.4")
    sleeps: list[float] = []
    monkeypatch.setattr(phone_lookup.time, "sleep", lambda seconds: sleeps.append(float(seconds)))

    class _FakeResponse:
        status_code = 200
        text = "uddg=https%3A%2F%2Ftwitter.com%2Facmeintel"

    class _FakeClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
            del args, kwargs

        def __enter__(self) -> "_FakeClient":
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, params: dict[str, str] | None = None) -> _FakeResponse:
            del url, params
            return _FakeResponse()

    monkeypatch.setitem(sys.modules, "httpx", types.SimpleNamespace(Client=_FakeClient))

    result = _mine_dork_urls(
        "+15551234567",
        [_dork_url("twitter.com")],
        max_dorks=1,
        max_workers=1,
    )

    assert result["usernames_found"] == ["acmeintel"]
    assert sleeps == [0.4]


def test_mine_dork_urls_extracts_additional_social_handles_from_profile_urls(monkeypatch) -> None:
    class _FakeResponse:
        def __init__(self, text: str) -> None:
            self.status_code = 200
            self.text = text

    class _FakeClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
            del args, kwargs

        def __enter__(self) -> "_FakeClient":
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, params: dict[str, str] | None = None) -> _FakeResponse:
            del url, params
            return _FakeResponse(
                "&".join(
                    [
                        "uddg=https%3A%2F%2Fbluewriter.medium.com%2Fsignal-boost",
                        "uddg=https%3A%2F%2Fbsky.app%2Fprofile%2Fblue.ops",
                        "uddg=https%3A%2F%2Fdev.to%2Fbluedev%2Flatest-post",
                        "uddg=https%3A%2F%2Fwww.reddit.com%2Fuser%2Fbluered%2Fcomments",
                        "uddg=https%3A%2F%2Fbitbucket.org%2Fbluebucket%2Fplatform-repo",
                        "uddg=https%3A%2F%2Fmastodon.social%2F%40bluefed%2F112233",
                        "uddg=https%3A%2F%2Fwww.threads.net%2F%40blueacme",
                        "uddg=https%3A%2F%2Fmedium.com%2Ftopic%2Fsecurity",
                        "uddg=https%3A%2F%2Fgithub.com%2Fsettings%2Fprofile",
                    ]
                )
            )

    monkeypatch.setitem(sys.modules, "httpx", types.SimpleNamespace(Client=_FakeClient))

    result = _mine_dork_urls(
        "+15551234567",
        [_dork_url("dev.to")],
        max_dorks=1,
        max_workers=1,
    )

    for handle in (
        "bluewriter",
        "blue.ops",
        "bluedev",
        "bluered",
        "bluebucket",
        "bluefed",
        "blueacme",
    ):
        assert handle in result["usernames_found"]
    assert "topic" not in result["usernames_found"]
    assert "settings" not in result["usernames_found"]


def test_mine_dork_urls_supplements_work_profile_sites_without_exceeding_cap(monkeypatch) -> None:
    import sys
    import types

    calls: list[str] = []

    class _FakeResponse:
        def __init__(self, text: str) -> None:
            self.status_code = 200
            self.text = text

    class _FakeClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
            del args, kwargs

        def __enter__(self) -> "_FakeClient":
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, params: dict[str, str] | None = None) -> _FakeResponse:
            del url
            query = str((params or {}).get("q") or "")
            site = query.split("site:", 1)[1]
            calls.append(site)
            responses = {
                "twitter.com": "uddg=https%3A%2F%2Ftwitter.com%2Fphoneops",
                "figma.com": (
                    "uddg=https%3A%2F%2Fwww.figma.com%2F%40phoneblue&"
                    "uddg=https%3A%2F%2Fwww.figma.com%2Fcommunity%2Ffile%2F123%2Fdesign-system"
                ),
                "indiehackers.com": (
                    "uddg=https%3A%2F%2Fwww.indiehackers.com%2Fphonefounder&"
                    "uddg=https%3A%2F%2Fwww.indiehackers.com%2Fpost%2Fgrowth"
                ),
                "polywork.com": (
                    "uddg=https%3A%2F%2Fwww.polywork.com%2Fphoneops&"
                    "uddg=https%3A%2F%2Fwww.polywork.com%2Fcompanies%2Facme"
                ),
            }
            return _FakeResponse(responses.get(site, ""))

    monkeypatch.setitem(sys.modules, "httpx", types.SimpleNamespace(Client=_FakeClient))

    result = _mine_dork_urls(
        "+15551234567",
        [_dork_url("twitter.com")],
        max_dorks=4,
        max_workers=1,
    )

    assert calls == ["twitter.com", "figma.com", "indiehackers.com", "polywork.com"]
    for handle in ("phoneops", "phoneblue", "phonefounder", "phoneops"):
        assert handle in result["usernames_found"]
    assert "community" not in result["usernames_found"]
    assert "post" not in result["usernames_found"]
    assert "companies" not in result["usernames_found"]
    assert result["sites_searched"] == calls


def test_mine_dork_urls_does_not_supplement_when_phoneinfoga_sites_fill_cap(monkeypatch) -> None:
    import sys
    import types

    calls: list[str] = []

    class _FakeResponse:
        status_code = 200
        text = ""

    class _FakeClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
            del args, kwargs

        def __enter__(self) -> "_FakeClient":
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, params: dict[str, str] | None = None) -> _FakeResponse:
            del url
            calls.append(str((params or {}).get("q") or "").split("site:", 1)[1])
            return _FakeResponse()

    monkeypatch.setitem(sys.modules, "httpx", types.SimpleNamespace(Client=_FakeClient))

    result = _mine_dork_urls(
        "+15551234567",
        [_dork_url("twitter.com"), _dork_url("instagram.com"), _dork_url("linkedin.com")],
        max_dorks=3,
        max_workers=1,
    )

    assert calls == ["twitter.com", "instagram.com", "linkedin.com"]
    assert result["sites_searched"] == calls


def test_mine_dork_urls_supplements_recursive_public_profiles_when_cap_allows(
    monkeypatch,
) -> None:
    import sys
    import types

    calls: list[str] = []

    class _FakeResponse:
        def __init__(self, text: str) -> None:
            self.status_code = 200
            self.text = text

    class _FakeClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
            del args, kwargs

        def __enter__(self) -> "_FakeClient":
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, params: dict[str, str] | None = None) -> _FakeResponse:
            del url
            site = str((params or {}).get("q") or "").split("site:", 1)[1]
            calls.append(site)
            responses = {
                "news.ycombinator.com": (
                    "uddg=https%3A%2F%2Fnews.ycombinator.com%2Fuser%3Fid%3Dphonehn&"
                    "uddg=https%3A%2F%2Fnews.ycombinator.com%2Fitem%3Fid%3D123456&"
                    "uddg=https%3A%2F%2Fnews.ycombinator.com%2Fuser%3Fid%3Dnews"
                ),
                "app.intigriti.com": (
                    "uddg=https%3A%2F%2Fapp.intigriti.com%2Fresearcher%2Fprofile%2Fphoneinti%2Factivity&"
                    "uddg=https%3A%2F%2Fapp.intigriti.com%2Fprograms%2Facme%2Fdetail"
                ),
                "intigriti.com": (
                    "uddg=https%3A%2F%2Fwww.intigriti.com%2Fresearcher%2Fprofile%2Fphoneinticanonical&"
                    "uddg=https%3A%2F%2Fwww.intigriti.com%2Fprograms%2Facme%2Fdetail"
                ),
                "openbugbounty.org": (
                    "uddg=https%3A%2F%2Fwww.openbugbounty.org%2Fresearchers%2Fphoneobb%2F&"
                    "uddg=https%3A%2F%2Fwww.openbugbounty.org%2Ffaq%2F"
                ),
                "bugcrowd.com": (
                    "uddg=https%3A%2F%2Fbugcrowd.com%2Fphonebug&"
                    "uddg=https%3A%2F%2Fbugcrowd.com%2Fdirectory"
                ),
                "hackerone.com": (
                    "uddg=https%3A%2F%2Fhackerone.com%2Fphoneh1&"
                    "uddg=https%3A%2F%2Fhackerone.com%2Fprograms"
                ),
                "yeswehack.com": (
                    "uddg=https%3A%2F%2Fyeswehack.com%2Fhunters%2Fphoneywh&"
                    "uddg=https%3A%2F%2Fyeswehack.com%2Fprograms%2Facme"
                ),
                "opencollective.com": (
                    "uddg=https%3A%2F%2Fopencollective.com%2Fphonecollective&"
                    "uddg=https%3A%2F%2Fopencollective.com%2Fdiscover"
                ),
                "liberapay.com": (
                    "uddg=https%3A%2F%2Fliberapay.com%2Fphonelibera%2F&"
                    "uddg=https%3A%2F%2Fliberapay.com%2Fexplore"
                ),
                "patreon.com": (
                    "uddg=https%3A%2F%2Fwww.patreon.com%2Fphonepatreon&"
                    "uddg=https%3A%2F%2Fwww.patreon.com%2Fjoin"
                ),
                "ko-fi.com": (
                    "uddg=https%3A%2F%2Fko-fi.com%2Fphonekofi&uddg=https%3A%2F%2Fko-fi.com%2Fhome"
                ),
                "buymeacoffee.com": (
                    "uddg=https%3A%2F%2Fwww.buymeacoffee.com%2Fphonecoffee&"
                    "uddg=https%3A%2F%2Fwww.buymeacoffee.com%2Fexplore"
                ),
                "producthunt.com": (
                    "uddg=https%3A%2F%2Fwww.producthunt.com%2F%40phonebuilder&"
                    "uddg=https%3A%2F%2Fwww.producthunt.com%2Fproducts%2Facme"
                ),
                "wellfound.com": (
                    "uddg=https%3A%2F%2Fwellfound.com%2Fu%2Fphonefounder&"
                    "uddg=https%3A%2F%2Fwellfound.com%2Fcompany%2Facme"
                ),
                "angel.co": (
                    "uddg=https%3A%2F%2Fangel.co%2Fu%2Fphoneangel&"
                    "uddg=https%3A%2F%2Fangel.co%2Fcompany%2Facme"
                ),
                "angellist.com": (
                    "uddg=https%3A%2F%2Fangellist.com%2Fu%2Fphoneangellist&"
                    "uddg=https%3A%2F%2Fangellist.com%2Fjobs"
                ),
                "calendly.com": (
                    "uddg=https%3A%2F%2Fcalendly.com%2Fphonecal%2Fintro&"
                    "uddg=https%3A%2F%2Fcalendly.com%2Flogin"
                ),
                "cal.com": (
                    "uddg=https%3A%2F%2Fcal.com%2Fphonebook%2Fsecurity&"
                    "uddg=https%3A%2F%2Fcal.com%2Fpricing"
                ),
                "linktr.ee": (
                    "uddg=https%3A%2F%2Flinktr.ee%2Fphonelink&"
                    "uddg=https%3A%2F%2Flinktr.ee%2Fpricing"
                ),
                "beacons.ai": (
                    "uddg=https%3A%2F%2Fbeacons.ai%2Fphonebeacon&"
                    "uddg=https%3A%2F%2Fbeacons.ai%2Fpricing"
                ),
                "bio.link": (
                    "uddg=https%3A%2F%2Fbio.link%2Fphonebio&uddg=https%3A%2F%2Fbio.link%2Fdiscover"
                ),
                "bio.site": (
                    "uddg=https%3A%2F%2Fbio.site%2Fphonebiosite&uddg=https%3A%2F%2Fbio.site%2Flogin"
                ),
                "allmylinks.com": (
                    "uddg=https%3A%2F%2Fallmylinks.com%2Fphoneaml&"
                    "uddg=https%3A%2F%2Fallmylinks.com%2Fsettings"
                ),
                "lnk.bio": (
                    "uddg=https%3A%2F%2Flnk.bio%2Fphonelnk&uddg=https%3A%2F%2Flnk.bio%2Flogin"
                ),
                "solo.to": (
                    "uddg=https%3A%2F%2Fsolo.to%2Fphonesolo&uddg=https%3A%2F%2Fsolo.to%2Fpricing"
                ),
                "campsite.bio": (
                    "uddg=https%3A%2F%2Fcampsite.bio%2Fphonecamp&"
                    "uddg=https%3A%2F%2Fcampsite.bio%2Fpricing"
                ),
                "bento.me": (
                    "uddg=https%3A%2F%2Fbento.me%2Fphonebento&uddg=https%3A%2F%2Fbento.me%2Fpricing"
                ),
                "hoo.be": (
                    "uddg=https%3A%2F%2Fhoo.be%2Fphonehoo&uddg=https%3A%2F%2Fhoo.be%2Fdiscover"
                ),
                "taplink.cc": (
                    "uddg=https%3A%2F%2Ftaplink.cc%2Fphonetap&"
                    "uddg=https%3A%2F%2Ftaplink.cc%2Fpricing"
                ),
                "msha.ke": (
                    "uddg=https%3A%2F%2Fmsha.ke%2Fphone.milk&uddg=https%3A%2F%2Fmsha.ke%2Flogin"
                ),
                "medium.com": (
                    "uddg=https%3A%2F%2Fphonewriter.medium.com%2Fsignal&"
                    "uddg=https%3A%2F%2Fmedium.com%2Ftopic%2Fsecurity"
                ),
                "hashnode.com": (
                    "uddg=https%3A%2F%2Fhashnode.com%2F%40phonehash%2Farticles%2Fone&"
                    "uddg=https%3A%2F%2Fhashnode.com%2Fexplore"
                ),
                "substack.com": (
                    "uddg=https%3A%2F%2Fphonesub.substack.com%2Fp%2Fbriefing&"
                    "uddg=https%3A%2F%2Fsubstack.com%2F%40phonenotes&"
                    "uddg=https%3A%2F%2Fsubstack.com%2Fhome"
                ),
                "dev.to": (
                    "uddg=https%3A%2F%2Fdev.to%2Fphonedev%2Fpost&"
                    "uddg=https%3A%2F%2Fdev.to%2Ft%2Fsecurity"
                ),
                "about.me": (
                    "uddg=https%3A%2F%2Fabout.me%2Fphoneabout&uddg=https%3A%2F%2Fabout.me%2Fsupport"
                ),
                "gitlab.com": (
                    "uddg=https%3A%2F%2Fgitlab.com%2Fphoneforge&"
                    "uddg=https%3A%2F%2Fgitlab.com%2Fusers%2Fsign_in"
                ),
                "bitbucket.org": (
                    "uddg=https%3A%2F%2Fbitbucket.org%2Fphonebucket%2Fplatform-repo&"
                    "uddg=https%3A%2F%2Fbitbucket.org%2Fproduct%2Ffeatures"
                ),
                "codeberg.org": (
                    "uddg=https%3A%2F%2Fcodeberg.org%2Fphoneberg%2Fplatform-repo&"
                    "uddg=https%3A%2F%2Fcodeberg.org%2Fexplore%2Frepos"
                ),
                "gist.github.com": (
                    "uddg=https%3A%2F%2Fgist.github.com%2Fphonegist%2Fabcdef1234567890&"
                    "uddg=https%3A%2F%2Fgist.github.com%2Fdiscover"
                ),
                "sr.ht": (
                    "uddg=https%3A%2F%2Fgit.sr.ht%2F~phonesrht%2Fplatform-repo&"
                    "uddg=https%3A%2F%2Fsr.ht%2Fprojects"
                ),
                "huggingface.co": (
                    "uddg=https%3A%2F%2Fhuggingface.co%2Fphoneml&"
                    "uddg=https%3A%2F%2Fhuggingface.co%2Fmodels"
                ),
                "npmjs.com": (
                    "uddg=https%3A%2F%2Fwww.npmjs.com%2F~phonenpm&"
                    "uddg=https%3A%2F%2Fwww.npmjs.com%2Fpackage%2Fnot-a-profile"
                ),
                "pypi.org": (
                    "uddg=https%3A%2F%2Fpypi.org%2Fuser%2Fphonepy%2F&"
                    "uddg=https%3A%2F%2Fpypi.org%2Fproject%2Fnot-a-profile"
                ),
                "stackoverflow.com": (
                    "uddg=https%3A%2F%2Fstackoverflow.com%2Fusers%2F12345%2Fphonestack&"
                    "uddg=https%3A%2F%2Fstackoverflow.com%2Fquestions%2F12345%2Fexample"
                ),
                "snapchat.com": (
                    "uddg=https%3A%2F%2Fwww.snapchat.com%2Fadd%2Fphonesnap&"
                    "uddg=https%3A%2F%2Fwww.snapchat.com%2Fdiscover&"
                    "uddg=https%3A%2F%2Fwww.snapchat.com%2Fadd"
                ),
                "keybase.io": (
                    "uddg=https%3A%2F%2Fkeybase.io%2Fphonekey&uddg=https%3A%2F%2Fkeybase.io%2Fdocs"
                ),
                "bsky.app": (
                    "uddg=https%3A%2F%2Fbsky.app%2Fprofile%2Fphonebsky&"
                    "uddg=https%3A%2F%2Fbsky.app%2Fprofile"
                ),
                "threads.net": (
                    "uddg=https%3A%2F%2Fwww.threads.net%2F%40phonethreads&"
                    "uddg=https%3A%2F%2Fwww.threads.net%2Fexplore"
                ),
                "reddit.com": (
                    "uddg=https%3A%2F%2Fwww.reddit.com%2Fuser%2Fphonereddit%2F&"
                    "uddg=https%3A%2F%2Fwww.reddit.com%2Fsearch%2F"
                ),
                "orcid.org": (
                    "uddg=https%3A%2F%2Forcid.org%2F0000-0002-1825-0097&"
                    "uddg=https%3A%2F%2Forcid.org%2Fsignin"
                ),
                "researchgate.net": (
                    "uddg=https%3A%2F%2Fwww.researchgate.net%2Fprofile%2Fphoneresearch&"
                    "uddg=https%3A%2F%2Fwww.researchgate.net%2Fjobs"
                ),
                "credly.com": (
                    "uddg=https%3A%2F%2Fwww.credly.com%2Fusers%2Fphonecredly%2Fbadges&"
                    "uddg=https%3A%2F%2Fwww.credly.com%2Forganizations"
                ),
                "scholar.google.com": (
                    "uddg=https%3A%2F%2Fscholar.google.com%2Fcitations%3Fuser%3DPhoneScholar_123&"
                    "uddg=https%3A%2F%2Fscholar.google.com%2Fscholar%3Fq%3Dacme"
                ),
                "semanticscholar.org": (
                    "uddg=https%3A%2F%2Fwww.semanticscholar.org%2Fauthor%2Fphonesemantic%2F123456&"
                    "uddg=https%3A%2F%2Fwww.semanticscholar.org%2Fproduct"
                ),
                "academia.edu": (
                    "uddg=https%3A%2F%2Fwww.academia.edu%2Fphoneacademia&"
                    "uddg=https%3A%2F%2Fwww.academia.edu%2Fanalytics"
                ),
                "zenodo.org": (
                    "uddg=https%3A%2F%2Fzenodo.org%2Fusers%2Fphonezenodo&"
                    "uddg=https%3A%2F%2Fzenodo.org%2Fcommunities"
                ),
                "figshare.com": (
                    "uddg=https%3A%2F%2Ffigshare.com%2Fauthors%2Fphonefigshare%2F123&"
                    "uddg=https%3A%2F%2Ffigshare.com%2Ffeatures"
                ),
                "behance.net": (
                    "uddg=https%3A%2F%2Fwww.behance.net%2Fphonebehance&"
                    "uddg=https%3A%2F%2Fwww.behance.net%2Fsearch"
                ),
                "dribbble.com": (
                    "uddg=https%3A%2F%2Fdribbble.com%2Fphonedribble&"
                    "uddg=https%3A%2F%2Fdribbble.com%2Fshots"
                ),
                "youtube.com": (
                    "uddg=https%3A%2F%2Fwww.youtube.com%2F%40phonevideo&"
                    "uddg=https%3A%2F%2Fwww.youtube.com%2Fwatch%3Fv%3Dabc123"
                ),
                "tiktok.com": (
                    "uddg=https%3A%2F%2Fwww.tiktok.com%2F%40phonetok%2Fvideo%2F123456&"
                    "uddg=https%3A%2F%2Fwww.tiktok.com%2Ftag%2Fsecurity"
                ),
                "twitch.tv": (
                    "uddg=https%3A%2F%2Fwww.twitch.tv%2Fphonestream%2Fvideos&"
                    "uddg=https%3A%2F%2Fwww.twitch.tv%2Fdirectory%2Fcategory%2Fsecurity"
                ),
                "pinterest.com": (
                    "uddg=https%3A%2F%2Fwww.pinterest.com%2Fphonepins%2Fsecurity%2F&"
                    "uddg=https%3A%2F%2Fwww.pinterest.com%2Fpin%2F123456789"
                ),
                "vimeo.com": (
                    "uddg=https%3A%2F%2Fvimeo.com%2Fphonevimeo&"
                    "uddg=https%3A%2F%2Fvimeo.com%2F123456789"
                ),
                "soundcloud.com": (
                    "uddg=https%3A%2F%2Fsoundcloud.com%2Fphonesound%2Fsignal&"
                    "uddg=https%3A%2F%2Fsoundcloud.com%2Fdiscover"
                ),
                "flickr.com": (
                    "uddg=https%3A%2F%2Fwww.flickr.com%2Fphotos%2Fphoneflickr%2F123456&"
                    "uddg=https%3A%2F%2Fwww.flickr.com%2Fsearch"
                ),
                "letterboxd.com": (
                    "uddg=https%3A%2F%2Fletterboxd.com%2Fphonefilm%2F&"
                    "uddg=https%3A%2F%2Fletterboxd.com%2Ffilm%2Fsecurity"
                ),
                "last.fm": (
                    "uddg=https%3A%2F%2Fwww.last.fm%2Fuser%2Fphonelast&"
                    "uddg=https%3A%2F%2Fwww.last.fm%2Fmusic%2Facme"
                ),
                "bandcamp.com": (
                    "uddg=https%3A%2F%2Fphoneband.bandcamp.com%2Falbum%2Fsecurity&"
                    "uddg=https%3A%2F%2Fbandcamp.com%2Fdiscover"
                ),
                "mixcloud.com": (
                    "uddg=https%3A%2F%2Fwww.mixcloud.com%2Fphonemix%2Fsecurity%2F&"
                    "uddg=https%3A%2F%2Fwww.mixcloud.com%2Fdiscover%2Felectronic%2F"
                ),
                "tryhackme.com": (
                    "uddg=https%3A%2F%2Ftryhackme.com%2Fp%2Fphonethm&"
                    "uddg=https%3A%2F%2Ftryhackme.com%2Froom%2Fsecurity"
                ),
                "strava.com": (
                    "uddg=https%3A%2F%2Fwww.strava.com%2Fathletes%2Fphonestrava&"
                    "uddg=https%3A%2F%2Fwww.strava.com%2Fclubs%2Facme"
                ),
                "quora.com": (
                    "uddg=https%3A%2F%2Fwww.quora.com%2Fprofile%2Fphonequora&"
                    "uddg=https%3A%2F%2Fwww.quora.com%2Ftopic%2FSecurity"
                ),
                "unsplash.com": (
                    "uddg=https%3A%2F%2Funsplash.com%2F%40phonephoto&"
                    "uddg=https%3A%2F%2Funsplash.com%2Fexplore"
                ),
                "500px.com": (
                    "uddg=https%3A%2F%2F500px.com%2Fp%2Fphone500px&"
                    "uddg=https%3A%2F%2F500px.com%2Fpopular"
                ),
                "artstation.com": (
                    "uddg=https%3A%2F%2Fphoneartist.artstation.com%2Fprojects%2Fsecurity&"
                    "uddg=https%3A%2F%2Fwww.artstation.com%2Fmarketplace"
                ),
                "deviantart.com": (
                    "uddg=https%3A%2F%2Fphonedevart.deviantart.com%2Fgallery&"
                    "uddg=https%3A%2F%2Fwww.deviantart.com%2Fshop"
                ),
                "carrd.co": (
                    "uddg=https%3A%2F%2Fphonecard.carrd.co%2F&"
                    "uddg=https%3A%2F%2Ftemplates.carrd.co%2F"
                ),
                "muckrack.com": (
                    "uddg=https%3A%2F%2Fmuckrack.com%2Fphonewriter&"
                    "uddg=https%3A%2F%2Fmuckrack.com%2Fjobs"
                ),
                "open.spotify.com": (
                    "uddg=https%3A%2F%2Fopen.spotify.com%2Fuser%2Fphonespotify&"
                    "uddg=https%3A%2F%2Fopen.spotify.com%2Fartist%2F123456"
                ),
                "kaggle.com": (
                    "uddg=https%3A%2F%2Fwww.kaggle.com%2Fphonekaggle&"
                    "uddg=https%3A%2F%2Fwww.kaggle.com%2Fcompetitions%2Facme"
                ),
                "speakerdeck.com": (
                    "uddg=https%3A%2F%2Fspeakerdeck.com%2Fphonespeaker%2Fsecurity&"
                    "uddg=https%3A%2F%2Fspeakerdeck.com%2Fbrowse"
                ),
                "slideshare.net": (
                    "uddg=https%3A%2F%2Fwww.slideshare.net%2Fphoneslides%2Fsecurity&"
                    "uddg=https%3A%2F%2Fwww.slideshare.net%2Ffeatured"
                ),
                "launchpad.net": (
                    "uddg=https%3A%2F%2Flaunchpad.net%2F~phonelaunch&"
                    "uddg=https%3A%2F%2Flaunchpad.net%2Fubuntu"
                ),
                "sourceforge.net": (
                    "uddg=https%3A%2F%2Fsourceforge.net%2Fu%2Fphonesourceforge%2Fprofile%2F&"
                    "uddg=https%3A%2F%2Fsourceforge.net%2Fsoftware%2F"
                ),
                "replit.com": (
                    "uddg=https%3A%2F%2Freplit.com%2F%40phonereplit&"
                    "uddg=https%3A%2F%2Freplit.com%2Ftemplates"
                ),
                "codesandbox.io": (
                    "uddg=https%3A%2F%2Fcodesandbox.io%2Fu%2Fphonebox&"
                    "uddg=https%3A%2F%2Fcodesandbox.io%2Ftemplates"
                ),
                "devpost.com": (
                    "uddg=https%3A%2F%2Fdevpost.com%2Fphonedevpost&"
                    "uddg=https%3A%2F%2Fdevpost.com%2Fhackathons"
                ),
                "read.cv": (
                    "uddg=https%3A%2F%2Fread.cv%2Fphonereadcv&uddg=https%3A%2F%2Fread.cv%2Fexplore"
                ),
                "codepen.io": (
                    "uddg=https%3A%2F%2Fcodepen.io%2Fphonepen%2Fpen%2Fsecurity&"
                    "uddg=https%3A%2F%2Fcodepen.io%2Fpen"
                ),
                "hub.docker.com": (
                    "uddg=https%3A%2F%2Fhub.docker.com%2Fu%2Fphonedocker&"
                    "uddg=https%3A%2F%2Fhub.docker.com%2Fr%2Fphoneimage%2Fapi&"
                    "uddg=https%3A%2F%2Fhub.docker.com%2Fsearch%3Fq%3Dsecurity&"
                    "uddg=https%3A%2F%2Fhub.docker.com%2Fr%2Flibrary%2Fnginx"
                ),
                "rubygems.org": (
                    "uddg=https%3A%2F%2Frubygems.org%2Fprofiles%2Fphoneruby&"
                    "uddg=https%3A%2F%2Frubygems.org%2Fgems%2Fnot-a-profile"
                ),
                "crates.io": (
                    "uddg=https%3A%2F%2Fcrates.io%2Fusers%2Fphonecrates&"
                    "uddg=https%3A%2F%2Fcrates.io%2Fcrates%2Fnot-a-profile"
                ),
                "packagist.org": (
                    "uddg=https%3A%2F%2Fpackagist.org%2Fusers%2Fphonepackagist&"
                    "uddg=https%3A%2F%2Fpackagist.org%2Fpackages%2Facme%2Fnot-a-profile"
                ),
                "nuget.org": (
                    "uddg=https%3A%2F%2Fwww.nuget.org%2Fprofiles%2Fphonenuget&"
                    "uddg=https%3A%2F%2Fwww.nuget.org%2Fpackages%2Fnot-a-profile"
                ),
                "hex.pm": (
                    "uddg=https%3A%2F%2Fhex.pm%2Fusers%2Fphonehex&"
                    "uddg=https%3A%2F%2Fhex.pm%2Fpackages%2Fnot-a-profile"
                ),
                "steamcommunity.com": (
                    "uddg=https%3A%2F%2Fsteamcommunity.com%2Fid%2Fphonesteam&"
                    "uddg=https%3A%2F%2Fsteamcommunity.com%2Fprofiles%2F76561198000000000"
                ),
            }
            return _FakeResponse(responses.get(site, ""))

    monkeypatch.setitem(sys.modules, "httpx", types.SimpleNamespace(Client=_FakeClient))

    result = _mine_dork_urls(
        "+15551234567",
        [_dork_url("twitter.com")],
        max_dorks=103,
        max_workers=1,
    )

    assert calls == [
        "twitter.com",
        "figma.com",
        "indiehackers.com",
        "polywork.com",
        "contra.com",
        "adplist.org",
        "news.ycombinator.com",
        "app.intigriti.com",
        "intigriti.com",
        "openbugbounty.org",
        "bugcrowd.com",
        "hackerone.com",
        "yeswehack.com",
        "opencollective.com",
        "liberapay.com",
        "patreon.com",
        "ko-fi.com",
        "buymeacoffee.com",
        "producthunt.com",
        "wellfound.com",
        "angel.co",
        "angellist.com",
        "calendly.com",
        "cal.com",
        "linktr.ee",
        "beacons.ai",
        "bio.link",
        "bio.site",
        "allmylinks.com",
        "lnk.bio",
        "solo.to",
        "campsite.bio",
        "bento.me",
        "hoo.be",
        "taplink.cc",
        "msha.ke",
        "medium.com",
        "hashnode.com",
        "substack.com",
        "dev.to",
        "about.me",
        "gitlab.com",
        "bitbucket.org",
        "codeberg.org",
        "gist.github.com",
        "sr.ht",
        "huggingface.co",
        "npmjs.com",
        "pypi.org",
        "stackoverflow.com",
        "snapchat.com",
        "keybase.io",
        "bsky.app",
        "threads.net",
        "reddit.com",
        "orcid.org",
        "researchgate.net",
        "credly.com",
        "scholar.google.com",
        "semanticscholar.org",
        "academia.edu",
        "zenodo.org",
        "figshare.com",
        "behance.net",
        "dribbble.com",
        "youtube.com",
        "tiktok.com",
        "twitch.tv",
        "pinterest.com",
        "vimeo.com",
        "soundcloud.com",
        "flickr.com",
        "letterboxd.com",
        "last.fm",
        "bandcamp.com",
        "mixcloud.com",
        "tryhackme.com",
        "strava.com",
        "quora.com",
        "unsplash.com",
        "500px.com",
        "artstation.com",
        "deviantart.com",
        "carrd.co",
        "muckrack.com",
        "open.spotify.com",
        "kaggle.com",
        "speakerdeck.com",
        "slideshare.net",
        "launchpad.net",
        "sourceforge.net",
        "replit.com",
        "codesandbox.io",
        "devpost.com",
        "read.cv",
        "codepen.io",
        "hub.docker.com",
        "rubygems.org",
        "crates.io",
        "packagist.org",
        "nuget.org",
        "hex.pm",
        "steamcommunity.com",
    ]
    assert result["sites_searched"] == calls
    assert "phonehn" in result["usernames_found"]
    assert "phoneinti" in result["usernames_found"]
    assert "phoneinticanonical" in result["usernames_found"]
    assert "phoneobb" in result["usernames_found"]
    assert "phonebug" in result["usernames_found"]
    assert "phoneh1" in result["usernames_found"]
    assert "phoneywh" in result["usernames_found"]
    assert "phonecollective" in result["usernames_found"]
    assert "phonelibera" in result["usernames_found"]
    assert "phonepatreon" in result["usernames_found"]
    assert "phonekofi" in result["usernames_found"]
    assert "phonecoffee" in result["usernames_found"]
    assert "phonebuilder" in result["usernames_found"]
    assert "phonefounder" in result["usernames_found"]
    assert "phoneangel" in result["usernames_found"]
    assert "phoneangellist" in result["usernames_found"]
    assert "phonecal" in result["usernames_found"]
    assert "phonebook" in result["usernames_found"]
    assert "phonelink" in result["usernames_found"]
    assert "phonebeacon" in result["usernames_found"]
    assert "phonebio" in result["usernames_found"]
    assert "phonebiosite" in result["usernames_found"]
    assert "phoneaml" in result["usernames_found"]
    assert "phonelnk" in result["usernames_found"]
    assert "phonesolo" in result["usernames_found"]
    assert "phonecamp" in result["usernames_found"]
    assert "phonebento" in result["usernames_found"]
    assert "phonehoo" in result["usernames_found"]
    assert "phonetap" in result["usernames_found"]
    assert "phone.milk" in result["usernames_found"]
    assert "phonewriter" in result["usernames_found"]
    assert "phonehash" in result["usernames_found"]
    assert "phonesub" in result["usernames_found"]
    assert "phonenotes" in result["usernames_found"]
    assert "phonedev" in result["usernames_found"]
    assert "phoneabout" in result["usernames_found"]
    assert "phoneforge" in result["usernames_found"]
    assert "phonebucket" in result["usernames_found"]
    assert "phoneberg" in result["usernames_found"]
    assert "phonegist" in result["usernames_found"]
    assert "phonesrht" in result["usernames_found"]
    assert "phoneml" in result["usernames_found"]
    assert "phonenpm" in result["usernames_found"]
    assert "phonepy" in result["usernames_found"]
    assert "phonestack" in result["usernames_found"]
    assert "phonesnap" in result["usernames_found"]
    assert "phonekey" in result["usernames_found"]
    assert "phonebsky" in result["usernames_found"]
    assert "phonethreads" in result["usernames_found"]
    assert "phonereddit" in result["usernames_found"]
    assert "0000-0002-1825-0097" in result["usernames_found"]
    assert "phoneresearch" in result["usernames_found"]
    assert "phonecredly" in result["usernames_found"]
    assert "PhoneScholar_123" in result["usernames_found"]
    assert "phonesemantic" in result["usernames_found"]
    assert "phoneacademia" in result["usernames_found"]
    assert "phonezenodo" in result["usernames_found"]
    assert "phonefigshare" in result["usernames_found"]
    assert "phonebehance" in result["usernames_found"]
    assert "phonedribble" in result["usernames_found"]
    assert "phonevideo" in result["usernames_found"]
    assert "phonetok" in result["usernames_found"]
    assert "phonestream" in result["usernames_found"]
    assert "phonepins" in result["usernames_found"]
    assert "phonevimeo" in result["usernames_found"]
    assert "phonesound" in result["usernames_found"]
    assert "phoneflickr" in result["usernames_found"]
    assert "phonefilm" in result["usernames_found"]
    assert "phonelast" in result["usernames_found"]
    assert "phoneband" in result["usernames_found"]
    assert "phonemix" in result["usernames_found"]
    assert "phonethm" in result["usernames_found"]
    assert "phonestrava" in result["usernames_found"]
    assert "phonequora" in result["usernames_found"]
    assert "phonephoto" in result["usernames_found"]
    assert "phone500px" in result["usernames_found"]
    assert "phoneartist" in result["usernames_found"]
    assert "phonedevart" in result["usernames_found"]
    assert "phonecard" in result["usernames_found"]
    assert "phonewriter" in result["usernames_found"]
    assert "phonespotify" in result["usernames_found"]
    assert "phonekaggle" in result["usernames_found"]
    assert "phonespeaker" in result["usernames_found"]
    assert "phoneslides" in result["usernames_found"]
    assert "phonelaunch" in result["usernames_found"]
    assert "phonesourceforge" in result["usernames_found"]
    assert "phonereplit" in result["usernames_found"]
    assert "phonebox" in result["usernames_found"]
    assert "phonedevpost" in result["usernames_found"]
    assert "phonereadcv" in result["usernames_found"]
    assert "phonepen" in result["usernames_found"]
    assert "phonedocker" in result["usernames_found"]
    assert "phoneimage" in result["usernames_found"]
    assert "phoneruby" in result["usernames_found"]
    assert "phonecrates" in result["usernames_found"]
    assert "phonepackagist" in result["usernames_found"]
    assert "phonenuget" in result["usernames_found"]
    assert "phonehex" in result["usernames_found"]
    assert "phonesteam" in result["usernames_found"]
    assert "news" not in result["usernames_found"]
    assert "programs" not in result["usernames_found"]
    assert "faq" not in result["usernames_found"]
    assert "directory" not in result["usernames_found"]
    assert "discover" not in result["usernames_found"]
    assert "explore" not in result["usernames_found"]
    assert "join" not in result["usernames_found"]
    assert "home" not in result["usernames_found"]
    assert "products" not in result["usernames_found"]
    assert "company" not in result["usernames_found"]
    assert "jobs" not in result["usernames_found"]
    assert "add" not in result["usernames_found"]
    assert "login" not in result["usernames_found"]
    assert "pricing" not in result["usernames_found"]
    assert "topic" not in result["usernames_found"]
    assert "explore" not in result["usernames_found"]
    assert "support" not in result["usernames_found"]
    assert "sign_in" not in result["usernames_found"]
    assert "product" not in result["usernames_found"]
    assert "discover" not in result["usernames_found"]
    assert "projects" not in result["usernames_found"]
    assert "models" not in result["usernames_found"]
    assert "package" not in result["usernames_found"]
    assert "questions" not in result["usernames_found"]
    assert "docs" not in result["usernames_found"]
    assert "signin" not in result["usernames_found"]
    assert "organizations" not in result["usernames_found"]
    assert "communities" not in result["usernames_found"]
    assert "features" not in result["usernames_found"]
    assert "shots" not in result["usernames_found"]
    assert "watch" not in result["usernames_found"]
    assert "tag" not in result["usernames_found"]
    assert "directory" not in result["usernames_found"]
    assert "pin" not in result["usernames_found"]
    assert "music" not in result["usernames_found"]
    assert "film" not in result["usernames_found"]
    assert "clubs" not in result["usernames_found"]
    assert "popular" not in result["usernames_found"]
    assert "marketplace" not in result["usernames_found"]
    assert "shop" not in result["usernames_found"]
    assert "templates" not in result["usernames_found"]
    assert "jobs" not in result["usernames_found"]
    assert "artist" not in result["usernames_found"]
    assert "competitions" not in result["usernames_found"]
    assert "browse" not in result["usernames_found"]
    assert "featured" not in result["usernames_found"]
    assert "ubuntu" not in result["usernames_found"]
    assert "software" not in result["usernames_found"]
    assert "hackathons" not in result["usernames_found"]
    assert "search" not in result["usernames_found"]
    assert "library" not in result["usernames_found"]
    assert "gems" not in result["usernames_found"]
    assert "crates" not in result["usernames_found"]
    assert "packages" not in result["usernames_found"]


def test_mine_dork_urls_parses_mixed_encoded_decoded_and_path_site_filters(monkeypatch) -> None:
    import sys
    import types

    calls: list[str] = []

    class _FakeResponse:
        status_code = 200
        text = ""

    class _FakeClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
            del args, kwargs

        def __enter__(self) -> "_FakeClient":
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, params: dict[str, str] | None = None) -> _FakeResponse:
            del url
            calls.append(str((params or {}).get("q") or "").split("site:", 1)[1])
            return _FakeResponse()

    monkeypatch.setitem(sys.modules, "httpx", types.SimpleNamespace(Client=_FakeClient))

    result = _mine_dork_urls(
        "+15551234567",
        [
            "https://www.google.com/search?q=%2215551234567%22+site%3Awww.LinkedIn.com",
            "https://www.google.com/search?q=%2215551234567%22+site:github.com",
            "https://www.google.com/search?q=%2215551234567%22+site%3Aadplist.org%2Fmentors",
            "https://www.google.com/search?q=%2215551234567%22+site%3Agithub.com%2Forgs",
        ],
        max_dorks=3,
        max_workers=1,
    )

    assert calls == ["linkedin.com", "github.com", "adplist.org"]
    assert result["sites_searched"] == calls


def test_check_account_existence_paces_direct_provider_requests(monkeypatch) -> None:
    monkeypatch.setenv("FORGE_IDENTITY_LOOKUP_REQUEST_DELAY_SECONDS", "0.2")
    monkeypatch.setenv("FORGE_IDENTITY_LOOKUP_RATE_LIMIT_BACKOFF_SECONDS", "9")
    monkeypatch.setenv("FORGE_IDENTITY_LOOKUP_MAX_RETRY_AFTER_SECONDS", "1")
    monkeypatch.setenv("FORGE_IDENTITY_LOOKUP_RATE_LIMIT_RETRIES", "1")
    sleeps: list[float] = []
    monkeypatch.setattr(http_pacing.time, "sleep", lambda seconds: sleeps.append(float(seconds)))

    class _FakeResponse:
        def __init__(self, status_code: int, text: str = "", headers: dict | None = None) -> None:
            self.status_code = status_code
            self.text = text
            self.headers = headers or {}

    responses = [
        _FakeResponse(429, headers={"Retry-After": "5"}),
        _FakeResponse(200, 'og:title" content="Join group chat on Telegram"'),
        _FakeResponse(429, headers={"Retry-After": "5"}),
        _FakeResponse(200, "Phone number shared via URL is invalid"),
    ]

    class _FakeClient:
        calls: list[str] = []

        def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
            del args, kwargs

        def __enter__(self) -> "_FakeClient":
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, **kwargs) -> _FakeResponse:
            del kwargs
            self.calls.append(url)
            return responses.pop(0)

    monkeypatch.setitem(sys.modules, "httpx", types.SimpleNamespace(Client=_FakeClient))

    result = phone_lookup._check_account_existence("+15551234567")

    assert result == {"telegram": "UNVERIFIABLE", "whatsapp": "INVALID_FORMAT"}
    assert sleeps == [0.2, 1.0, 0.2, 0.2, 1.0, 0.2]
    assert _FakeClient.calls == [
        "https://t.me/+15551234567",
        "https://t.me/+15551234567",
        "https://wa.me/15551234567",
        "https://wa.me/15551234567",
    ]


def test_lookup_phone_persists_parallel_mined_results_and_audit(
    monkeypatch, tmp_path: Path
) -> None:
    db_path = tmp_path / "engagement.db"
    con = sqlite3.connect(db_path)
    try:
        con.executescript(
            """
            CREATE TABLE emails (
                id INTEGER PRIMARY KEY,
                engagement_id INTEGER,
                email TEXT,
                source TEXT,
                first_seen_at TEXT
            );
            CREATE TABLE audit_log (
                id INTEGER PRIMARY KEY,
                engagement_id INTEGER,
                phase TEXT,
                module TEXT,
                action TEXT,
                target TEXT,
                result TEXT,
                operator TEXT,
                logged_at TEXT
            );
            """
        )
        con.commit()
    finally:
        con.close()

    monkeypatch.setattr(
        "forge.utils.intel.phone_lookup._parse_phone",
        lambda number: {
            "e164": number,
            "international": number,
            "region": "Singapore",
            "carrier": "AcmeTel",
            "line_type": "mobile",
            "valid": True,
        },
    )
    monkeypatch.setattr(
        "forge.utils.intel.phone_lookup._run_phoneinfoga",
        lambda number: {
            "available": True,
            "sample_dorks": {"search": [_dork_url("twitter.com")]},
        },
    )
    monkeypatch.setattr(
        "forge.utils.intel.phone_lookup._check_account_existence",
        lambda number: {"telegram": "REGISTERED"},
    )
    monkeypatch.setattr(
        "forge.utils.intel.phone_lookup._mine_dork_urls",
        lambda number, dork_urls, proxy=None, max_dorks=8, timeout=12.0, max_workers=None: {
            "sites_searched": ["twitter.com"],
            "emails_found": ["ops@acme.co"],
            "usernames_found": ["acmeops"],
            "urls_found": ["https://twitter.com/acmeops"],
        },
    )

    result = lookup_phone("+15551234567", 1001, db_path, include_online=True)

    assert result["persisted"]["emails"] == 1
    assert result["persisted"]["social_profiles"] == 3

    con = sqlite3.connect(db_path)
    try:
        emails = con.execute("SELECT email, source FROM emails WHERE engagement_id=1001").fetchall()
        assert emails == [("ops@acme.co", "phone_dork_mining")]

        social_rows = con.execute(
            """
            SELECT email, source, profile_data
            FROM social_profiles
            WHERE engagement_id=1001
            ORDER BY source
            """
        ).fetchall()
        assert any(
            row[0] == "phone:+15551234567" and row[1] == "phone_dork:acmeops" for row in social_rows
        )
        assert any(row[0] == "phone:+15551234567" and row[1] == "telegram" for row in social_rows)
        assert any(
            row[0] == "phone:+15551234567" and str(row[1]).startswith("phone_dork_url:")
            for row in social_rows
        )
        url_profile = next(
            json.loads(row[2]) for row in social_rows if str(row[1]).startswith("phone_dork_url:")
        )
        assert url_profile["platform"] == "twitter"
        assert url_profile["host"] == "twitter.com"

        audit_count = con.execute(
            "SELECT COUNT(*) FROM audit_log WHERE engagement_id=1001 AND module='phone_lookup'"
        ).fetchone()[0]
        assert audit_count == 1
    finally:
        con.close()


def test_lookup_phone_passes_default_sequential_dork_workers(monkeypatch, tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            CREATE TABLE audit_log (
                id INTEGER PRIMARY KEY,
                engagement_id INTEGER,
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

    observed_workers: list[int | None] = []
    monkeypatch.delenv("FORGE_PHONE_DORK_MAX_CONCURRENCY", raising=False)
    monkeypatch.setattr(
        "forge.utils.intel.phone_lookup._parse_phone",
        lambda number: {"valid": True, "region": "", "carrier": "", "line_type": ""},
    )
    monkeypatch.setattr(
        "forge.utils.intel.phone_lookup._run_phoneinfoga",
        lambda number: {"available": True, "sample_dorks": {"search": [_dork_url("twitter.com")]}},
    )
    monkeypatch.setattr(
        "forge.utils.intel.phone_lookup._check_account_existence",
        lambda number: {},
    )

    def fake_mine(
        number: str,
        dork_urls: list[str],
        proxy=None,
        max_dorks: int = 8,
        timeout: float = 12.0,
        max_workers: int | None = None,
    ) -> dict[str, list[str]]:  # noqa: ANN001
        del number, dork_urls, proxy, max_dorks, timeout
        observed_workers.append(max_workers)
        return {"sites_searched": [], "emails_found": [], "usernames_found": [], "urls_found": []}

    monkeypatch.setattr("forge.utils.intel.phone_lookup._mine_dork_urls", fake_mine)

    lookup_phone("+15551234567", 1001, db_path, include_online=True)

    assert observed_workers == [1]


def test_lookup_phone_passes_explicit_dork_worker_override(monkeypatch, tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            CREATE TABLE audit_log (
                id INTEGER PRIMARY KEY,
                engagement_id INTEGER,
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

    observed_workers: list[int | None] = []
    monkeypatch.setattr(
        "forge.utils.intel.phone_lookup._parse_phone",
        lambda number: {"valid": True, "region": "", "carrier": "", "line_type": ""},
    )
    monkeypatch.setattr(
        "forge.utils.intel.phone_lookup._run_phoneinfoga",
        lambda number: {"available": True, "sample_dorks": {"search": [_dork_url("twitter.com")]}},
    )
    monkeypatch.setattr(
        "forge.utils.intel.phone_lookup._check_account_existence",
        lambda number: {},
    )

    def fake_mine(
        number: str,
        dork_urls: list[str],
        proxy=None,
        max_dorks: int = 8,
        timeout: float = 12.0,
        max_workers: int | None = None,
    ) -> dict[str, list[str]]:  # noqa: ANN001
        del number, dork_urls, proxy, max_dorks, timeout
        observed_workers.append(max_workers)
        return {"sites_searched": [], "emails_found": [], "usernames_found": [], "urls_found": []}

    monkeypatch.setattr("forge.utils.intel.phone_lookup._mine_dork_urls", fake_mine)

    lookup_phone("+15551234567", 1001, db_path, include_online=True, dork_max_workers=3)

    assert observed_workers == [3]
