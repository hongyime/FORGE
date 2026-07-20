"""
tests/phase2/test_social_scraper.py
Canonical path maps to: forge/utils/intel/social_scraper.py  (Module 2-G)

Coverage target: 80%  (PRD §15.1)
All HTTP calls mocked via pytest-mock / patch.
OPSEC invariant: no session reuse across targets; proxy support verified.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch, call

import pytest

from forge.utils.intel import social_scraper
from forge.utils.intel.social_scraper import (
    EpieosClient,
    _epieos_email_values,
    _epieos_phone_values,
    _parse_epieos_response,
    run_social_scraper,
)


# ─── fixtures ────────────────────────────────────────────────────────────────


@pytest.fixture()
def engagement_db(tmp_path: Path) -> Path:
    db = tmp_path / "eng.db"
    con = sqlite3.connect(db)
    con.executescript("""
        CREATE TABLE engagements (
            id INTEGER PRIMARY KEY, name TEXT, scope_json TEXT
        );
        CREATE TABLE emails (
            id INTEGER PRIMARY KEY, engagement_id INTEGER,
            address TEXT, source TEXT, discovered_at TEXT
        );
        CREATE TABLE social_profiles (
            id INTEGER PRIMARY KEY, engagement_id INTEGER,
            email TEXT, platform TEXT, profile_url TEXT,
            display_name TEXT, avatar_url TEXT,
            raw_data_enc TEXT, discovered_at TEXT
        );
        CREATE TABLE audit_log (
            id INTEGER PRIMARY KEY, engagement_id INTEGER,
            phase TEXT, module TEXT, action TEXT, target TEXT,
            result TEXT, operator TEXT, logged_at TEXT
        );
        INSERT INTO engagements VALUES (1, 'test-eng', '["example.com"]');
        INSERT INTO emails VALUES (1,1,'alice@example.com','test','2024-01-01');
        INSERT INTO emails VALUES (2,1,'bob@example.com',  'test','2024-01-01');
    """)
    con.commit()
    con.close()
    return db


def _epieos_payload(email: str = "alice@example.com") -> dict:
    return {
        "email": email,
        "google": {
            "id": "1234567890",
            "name": "Alice Example",
            "profile_url": "https://accounts.google.com/1234567890",
            "avatar": "https://lh3.googleusercontent.com/photo.jpg",
        },
        "instagram": None,
        "twitter": None,
        "linkedin": {
            "profile_url": "https://www.linkedin.com/in/alice-example",
            "name": "Alice Example",
        },
    }


def _rich_epieos_payload(email: str = "alice@example.com") -> dict:
    return {
        "email": email,
        "github": {
            "profile_url": "https://github.com/acmehunter",
            "name": "Alice Example",
            "username": "acmehunter",
            "bio": "Threat researcher",
            "website": "https://research.acme.example/blog",
            "emails": [{"value": "alice.ops@acme.example"}],
            "phone_numbers": [{"value": "+15557654321"}],
            "organization": {"name": "Acme Corp"},
            "avatar": "https://avatars.githubusercontent.com/u/1?v=4",
            "verified": True,
        },
        "linkedin_company": {
            "slug": "acme-corp",
            "name": "Acme Corp",
            "url": "https://www.linkedin.com/company/acme-corp",
            "website": "https://www.acme.example",
        },
    }


def _expanded_provider_epieos_payload(email: str = "alice@example.com") -> dict:
    return {
        "email": email,
        "bitbucket": {
            "workspace": "acmebucket",
            "name": "Acme Bucket",
            "website": "https://bb.acme.example/workspace",
        },
        "bugcrowd": {
            "username": "acmebug",
            "name": "Acme Bugcrowd",
        },
        "github_sponsors": {
            "username": "acmesponsor",
            "name": "Acme Sponsor",
        },
        "codeberg": {
            "username": "acmeberg",
            "name": "Acme Berg",
        },
        "codepen": {
            "username": "acmepen",
            "name": "Acme CodePen",
        },
        "hackerone": {
            "username": "acmehacker",
            "name": "Acme HackerOne",
        },
        "hashnode": {
            "username": "acmehash",
            "name": "Acme Hashnode",
        },
        "intigriti": {
            "username": "acmeintigriti",
            "name": "Acme Intigriti",
        },
        "dockerhub": {
            "namespace": "acmedocker",
            "name": "Acme Docker",
        },
        "sourcehut": {
            "handle": "acmesrht",
            "name": "Acme SourceHut",
        },
        "mastodon": {
            "preferred_username": "acmefed",
            "instance": "mastodon.social",
            "name": "Acme Fed",
            "website": "https://fed.acme.example/@acmefed",
        },
        "reddit": {
            "username": "acmeredteam",
            "name": "Acme Red",
        },
        "replit": {
            "username": "acmerepl",
            "name": "Acme Replit",
        },
        "codesandbox": {
            "username": "acmesandbox",
            "name": "Acme CodeSandbox",
        },
        "devpost": {
            "username": "acmedevpost",
            "name": "Acme Devpost",
        },
        "readcv": {
            "username": "acmeread",
            "name": "Acme ReadCV",
        },
        "telegram": {
            "custom_url": "acmetelegram",
            "name": "Acme Relay",
        },
        "bluesky": {
            "preferred_username": "acme.blue",
            "name": "Acme Blue",
        },
        "youtube": {
            "channel_id": "AcmeChannel",
            "name": "Acme Channel",
        },
        "npm": {
            "username": "acmenpm",
            "name": "Acme NPM",
        },
        "pypi": {
            "username": "acmepy",
            "name": "Acme PyPI",
        },
        "rubygems": {
            "username": "acmeruby",
            "name": "Acme RubyGems",
        },
        "crates": {
            "username": "acmecrates",
            "name": "Acme Crates",
        },
        "packagist": {
            "username": "acmepackagist",
            "name": "Acme Packagist",
        },
        "nuget": {
            "username": "acmenuget",
            "name": "Acme NuGet",
        },
        "openbugbounty": {
            "username": "acmeobb",
            "name": "Acme Open Bug Bounty",
        },
        "hexpm": {
            "username": "acmehex",
            "name": "Acme Hex",
        },
        "stackoverflow": {
            "user_id": "12345",
            "username": "acmestack",
            "name": "Acme Stack",
        },
        "huggingface": {
            "handle": "acmeml",
            "name": "Acme ML",
        },
        "keybase": {
            "username": "acmekeybase",
            "name": "Acme Keybase",
        },
        "medium": {
            "url": "https://bluewriter.medium.com/signal-boost",
            "name": "Blue Writer",
        },
        "facebook": {
            "id": "1000123456789",
            "name": "Acme Facebook",
        },
        "flickr": {
            "username": "acmeflickr",
            "name": "Acme Flickr",
        },
        "vimeo": {
            "username": "acmevideo",
            "name": "Acme Video",
        },
        "kaggle": {
            "username": "acmekaggle",
            "name": "Acme Kaggle",
        },
        "lastfm": {
            "username": "rj",
            "name": "Acme LastFM",
        },
        "bandcamp": {
            "username": "acmeband",
            "name": "Acme Band",
        },
        "linktree": {
            "username": "acmehub",
            "name": "Acme Hub",
        },
        "allmylinks": {
            "username": "acmeaml",
            "name": "Acme AllMyLinks",
        },
        "artstation": {
            "username": "acmeartist",
            "name": "Acme Artist",
        },
        "deviantart": {
            "username": "acmedeviant",
            "name": "Acme Deviant",
        },
        "biosite": {
            "username": "acmebiosite",
            "name": "Acme Bio Site",
        },
        "campsite": {
            "username": "acmecamp",
            "name": "Acme Campsite",
        },
        "taplink": {
            "username": "acmetap",
            "name": "Acme Taplink",
        },
        "milkshake": {
            "username": "go.milkshake",
            "name": "Acme Milkshake",
        },
        "opencollective": {
            "username": "acmecollective",
            "name": "Acme Collective",
        },
        "liberapay": {
            "username": "acmelibera",
            "name": "Acme Libera",
        },
        "patreon": {
            "username": "acmepatron",
            "name": "Acme Patron",
        },
        "kofi": {
            "username": "acmekofi",
            "name": "Acme Ko-fi",
        },
        "buymeacoffee": {
            "username": "acmecoffee",
            "name": "Acme Coffee",
        },
        "calendly": {
            "username": "acmecalendly",
            "name": "Acme Calendly",
        },
        "calcom": {
            "username": "acmecal",
            "name": "Acme Cal",
        },
        "producthunt": {
            "username": "acmebuilder",
            "name": "Acme Builder",
        },
        "wellfound": {
            "username": "acmefounder",
            "name": "Acme Founder",
        },
        "angellist": {
            "username": "acmeangel",
            "name": "Acme Angel",
        },
        "figma": {
            "username": "acmedesign",
            "name": "Acme Design",
        },
        "indiehackers": {
            "username": "acmefounder",
            "name": "Acme Founder",
        },
        "polywork": {
            "username": "acmeops",
            "name": "Acme Ops",
        },
        "contra": {
            "username": "acmeconsultant",
            "name": "Acme Consultant",
        },
        "adplist": {
            "username": "acme-mentor",
            "name": "Acme Mentor",
        },
        "orcid": {
            "username": "0000-0002-1825-0097",
            "name": "Acme ORCID",
        },
        "researchgate": {
            "username": "Acme-Research",
            "name": "Acme Research",
        },
        "google_scholar": {
            "scholar_id": "qc6CJjYAAAAJ",
            "name": "Acme Scholar",
        },
        "gravatar": {
            "username": "acmeavatar",
            "name": "Acme Avatar",
        },
        "academia": {
            "username": "AcmeAcademic",
            "name": "Acme Academia",
        },
        "zenodo": {
            "username": "acmezenodo",
            "name": "Acme Zenodo",
        },
        "credly": {
            "username": "acme-ops",
            "name": "Acme Credly",
        },
        "behance": {
            "username": "acmecreative",
            "name": "Acme Creative",
        },
        "dribbble": {
            "username": "acmedesign",
            "name": "Acme Design",
        },
        "beacons": {
            "handle": "acmebeacon",
            "name": "Acme Beacon",
        },
        "bento": {
            "username": "acmebento",
            "name": "Acme Bento",
        },
        "hoobe": {
            "username": "acmehoo",
            "name": "Acme Hoo",
        },
        "taplink_ws": {
            "profileLink": "https://acmetapws.taplink.ws",
            "name": "Acme Taplink WS",
        },
        "carrd": {
            "slug": "acmecard",
            "name": "Acme Card",
        },
        "twitch": {
            "username": "acmestream",
            "name": "Acme Stream",
        },
        "unsplash": {
            "username": "acmephotos",
            "name": "Acme Photos",
        },
        "500px": {
            "username": "acme500",
            "name": "Acme 500px",
        },
        "substack": {
            "handle": "acmenotes",
            "name": "Acme Notes",
        },
        "speakerdeck": {
            "username": "acmespeaker",
            "name": "Acme Speaker",
        },
        "slideshare": {
            "username": "acmeslides",
            "name": "Acme Slides",
        },
        "soundcloud": {
            "username": "acmesound",
            "name": "Acme Sound",
        },
        "spotify": {
            "username": "acmespotify",
            "name": "Acme Spotify",
        },
        "strava": {
            "username": "12345678",
            "name": "Acme Strava",
        },
        "mixcloud": {
            "username": "acmemix",
            "name": "Acme Mix",
        },
        "letterboxd": {
            "username": "acmefilm",
            "name": "Acme Film",
        },
        "pinterest": {
            "username": "acmepins",
            "name": "Acme Pins",
        },
        "quora": {
            "username": "Acme-Quora-1",
            "name": "Acme Quora",
        },
        "tryhackme": {
            "username": "acmethm",
            "name": "Acme THM",
        },
        "yeswehack": {
            "username": "acmeywh",
            "name": "Acme YesWeHack",
        },
        "snapchat": {
            "username": "acmesnap",
            "name": "Acme Snapchat",
        },
        "steam": {
            "username": "acmesteam",
            "name": "Acme Steam",
        },
    }


def _mock_http(payload: dict, status: int = 200) -> MagicMock:
    m = MagicMock()
    m.status_code = status
    m.json.return_value = payload
    return m


# ═══════════════════════════════════════════════════════════════════════════
# Response parser
# ═══════════════════════════════════════════════════════════════════════════


class TestParseEpieosResponse:
    def test_extracts_google_profile(self):
        results = _parse_epieos_response(_epieos_payload())
        google = next((r for r in results if r["platform"] == "google"), None)
        assert google is not None
        assert google["display_name"] == "Alice Example"

    def test_extracts_linkedin_profile(self):
        results = _parse_epieos_response(_epieos_payload())
        linkedin = next((r for r in results if r["platform"] == "linkedin"), None)
        assert linkedin is not None
        assert "alice-example" in linkedin["profile_url"]

    def test_null_platform_skipped(self):
        results = _parse_epieos_response(_epieos_payload())
        platforms = {r["platform"] for r in results}
        assert "instagram" not in platforms
        assert "twitter" not in platforms

    def test_empty_payload_returns_empty_list(self):
        assert _parse_epieos_response({}) == []

    def test_all_returned_profiles_have_platform_and_url(self):
        results = _parse_epieos_response(_epieos_payload())
        for r in results:
            assert "platform" in r
            assert "profile_url" in r

    def test_root_profile_containers_feed_recursive_profile_rows(self):
        results = _parse_epieos_response(
            {
                "email": "alice@example.com",
                "profiles": [
                    {
                        "platform": "github",
                        "profileUrl": "https://github.com/rootcontainerops",
                        "displayName": "Root GitHub",
                    },
                    {
                        "serviceName": "linkedin",
                        "publicIdentifier": "root-link",
                        "name": "Root Link",
                    },
                ],
                "accounts": {
                    "items": [
                        {
                            "provider": "hackernews",
                            "username": "roothn",
                            "profile": "https://news.ycombinator.com/user?id=roothn",
                        }
                    ]
                },
                "data": {
                    "connected_accounts": {
                        "gitlab": {
                            "username": "rootgitlab",
                        }
                    }
                },
            }
        )

        rows = {row["platform"]: row for row in results}

        assert rows["github"]["profile_url"] == "https://github.com/rootcontainerops"
        assert rows["github"]["username"] == "rootcontainerops"
        assert rows["linkedin"]["profile_url"] == "https://www.linkedin.com/in/root-link"
        assert rows["linkedin"]["username"] == "root-link"
        assert rows["hackernews"]["profile_url"] == "https://news.ycombinator.com/user?id=roothn"
        assert rows["hackernews"]["username"] == "roothn"
        assert rows["gitlab"]["profile_url"] == "https://gitlab.com/rootgitlab"
        assert rows["gitlab"]["username"] == "rootgitlab"

    def test_platform_envelopes_preserve_provider_context(self):
        results = _parse_epieos_response(
            {
                "email": "alice@example.com",
                "github": {
                    "result": {
                        "profileUrl": "https://github.com/envelopedops",
                        "contactEmail": "ops@acme.example",
                        "websiteUrl": "https://ops.acme.example",
                    }
                },
            }
        )

        rows = {row["platform"]: row for row in results}

        assert rows["github"]["profile_url"] == "https://github.com/envelopedops"
        assert rows["github"]["username"] == "envelopedops"
        assert rows["github"]["email"] == "ops@acme.example"
        assert rows["github"]["external_url"] == "https://ops.acme.example"
        assert "result" not in rows

    def test_preserves_richer_identity_fields_for_recursive_synthesis(self):
        results = _parse_epieos_response(_rich_epieos_payload())
        github = next((r for r in results if r["platform"] == "github"), None)
        company = next((r for r in results if r["platform"] == "linkedin_company"), None)

        assert github is not None
        assert github["username"] == "acmehunter"
        assert github["handle"] == "acmehunter"
        assert github["company_name"] == "Acme Corp"
        assert github["email"] == "alice.ops@acme.example"
        assert github["phone"] == "+15557654321"
        assert github["external_url"] == "https://research.acme.example/blog"
        assert github["verified"] is True

        assert company is not None
        assert company["profile_url"] == "https://www.linkedin.com/company/acme-corp"
        assert company["company_name"] == "Acme Corp"
        assert company["external_url"] == "https://www.acme.example"
        assert "username" not in company

    def test_reconstructs_discord_user_and_invite_profile_urls_without_fabricating_handles(self):
        results = _parse_epieos_response(
            {
                "email": "alice@example.com",
                "discord": {
                    "userId": "123456789012345678",
                    "username": "aliceops",
                    "displayName": "Alice Ops",
                },
                "discord_server": {
                    "inviteCode": "acme-blue",
                    "name": "Acme Blue Team",
                },
                "discord_guild": {
                    "profileUrl": "https://discord.com/invite/acme-red",
                    "username": "login",
                },
                "discord_plain": {
                    "platform": "discord",
                    "username": "login",
                    "name": "Reserved Login",
                },
            }
        )

        rows = {row["platform"]: row for row in results}

        assert rows["discord"]["profile_url"] == "https://discord.com/users/123456789012345678"
        assert rows["discord"]["username"] == "aliceops"
        assert rows["discord_server"]["profile_url"] == "https://discord.gg/acme-blue"
        assert "username" not in rows["discord_server"]
        assert rows["discord_guild"]["profile_url"] == "https://discord.com/invite/acme-red"
        assert "username" not in rows["discord_guild"]
        assert "discord_plain" not in rows

    def test_schema_identifier_url_aliases_are_url_validated_for_recursive_synthesis(self):
        results = _parse_epieos_response(
            {
                "email": "alice@example.com",
                "github": {
                    "@id": "https://github.com/schemaidops",
                    "identifier": [
                        {"url": "https://gitlab.com/schemaidops"},
                        "1234567890",
                    ],
                    "identifiers": [
                        "https://bsky.app/profile/schemaid.example.com",
                        "not-a-url",
                    ],
                    "name": "Schema Identifier",
                },
                "linkedin": {
                    "identifier": {
                        "profile_url": "https://www.linkedin.com/in/schema-identifier"
                    },
                    "id": "9876543210",
                },
            }
        )

        github = next((row for row in results if row["platform"] == "github"), None)
        linkedin = next((row for row in results if row["platform"] == "linkedin"), None)

        assert github is not None
        assert github["profile_url"] == "https://github.com/schemaidops"
        assert github["username"] == "schemaidops"
        github_urls = [item["value"] for item in github["urls"]]
        assert "https://gitlab.com/schemaidops" in github_urls
        assert "https://bsky.app/profile/schemaid.example.com" in github_urls
        assert "1234567890" not in github_urls
        assert "not-a-url" not in github_urls

        assert linkedin is not None
        assert linkedin["profile_url"] == "https://www.linkedin.com/in/schema-identifier"
        assert linkedin["username"] == "schema-identifier"

    def test_normalizes_display_form_email_aliases_for_recursive_synthesis(self):
        results = _parse_epieos_response(
            {
                "email": "alice@example.com",
                "github": {
                    "username": "mailaliasops",
                    "mail": "Mail Alias <mail.alias@acme.example>",
                    "primaryEmail": (
                        "Primary Alias <primary.alias@acme.example>, "
                        "secondary.alias@acme.example"
                    ),
                    "work_email": "Work Alias <work.alias@acme.example>",
                    "emails": [
                        {"mailAddress": "List Alias <list.alias@acme.example>"},
                        {"value": "Value Alias <value.alias@acme.example>"},
                    ],
                    "alternateEmail": "https://secret.user@portal.acme.example/path",
                },
            }
        )

        github = next((row for row in results if row["platform"] == "github"), None)

        assert github is not None
        assert github["email"] == "mail.alias@acme.example"
        assert github["emails"] == [
            {"value": "mail.alias@acme.example"},
            {"value": "primary.alias@acme.example"},
            {"value": "secondary.alias@acme.example"},
            {"value": "work.alias@acme.example"},
            {"value": "list.alias@acme.example"},
            {"value": "value.alias@acme.example"},
        ]

    def test_normalizes_display_form_phone_aliases_for_recursive_synthesis(self):
        results = _parse_epieos_response(
            {
                "email": "alice@example.com",
                "github": {
                    "username": "phonealiasops",
                    "e164": "+1 555 101 0001",
                    "formattedPhone": "Office: +1 (555) 101-0002",
                    "work_phone": "Work line <+1 555 101 0003>",
                    "phone_numbers": [
                        {"e164": "+1 555 101 0004"},
                        {"formatted": "Desk: +1 555 101 0005"},
                    ],
                },
            }
        )

        github = next((row for row in results if row["platform"] == "github"), None)

        assert github is not None
        assert github["phone"] == "+15551010001"
        assert github["phone_numbers"] == [
            {"value": "+15551010001"},
            {"value": "+15551010002"},
            {"value": "+15551010003"},
            {"value": "+15551010004"},
            {"value": "+15551010005"},
        ]

    def test_normalizes_google_people_canonical_phone_form_for_recursive_synthesis(
        self,
    ):
        results = _parse_epieos_response(
            {
                "email": "alice@example.com",
                "google": {
                    "profile_url": "https://accounts.google.com/1234567890",
                    "name": "Alice Example",
                    "phoneNumbers": [{"canonicalForm": "+1 (555) 765-4321"}],
                },
            }
        )

        google = next((row for row in results if row["platform"] == "google"), None)

        assert google is not None
        assert google["phone"] == "+15557654321"
        assert google["phone_numbers"] == [{"value": "+15557654321"}]

    def test_combines_snake_case_name_aliases_for_recursive_synthesis(self):
        results = _parse_epieos_response(
            {
                "email": "alice@example.com",
                "github": {
                    "username": "snakecase-alias",
                    "first_name": "Frank",
                    "last_name": "Responder",
                },
            }
        )

        github = next((row for row in results if row["platform"] == "github"), None)

        assert github is not None
        assert github["display_name"] == "Frank Responder"
        assert github["full_name"] == "Frank Responder"
        assert github["name"] == "Frank Responder"

    def test_normalizes_company_aliases_without_stringifying_raw_objects(self):
        results = _parse_epieos_response(
            {
                "email": "alice@example.com",
                "github": {
                    "username": "companyaliasops",
                    "companyName": "Camel Corp",
                },
                "gitlab": {
                    "username": "orglistops",
                    "companies": [
                        {"displayName": "List Corp"},
                        {"name": "Backup Corp"},
                    ],
                },
                "bitbucket": {
                    "workspace": "employerops",
                    "employerName": "Employer Labs",
                },
                "twitter": {
                    "username": "worksforops",
                    "worksFor": {"legalName": "Schema Works LLC"},
                },
                "linkedin": {
                    "username": "memberofops",
                    "memberOf": {"alternateName": "Member Guild"},
                },
                "facebook": {
                    "username": "alumniofops",
                    "alumniOf": [{"name": "Alumni Network"}],
                },
                "codeberg": {
                    "username": "decoyorgops",
                    "organization": {
                        "url": "https://org.acme.example",
                        "email": "org@acme.example",
                        "phone": "+1 555 101 9999",
                    },
                },
            }
        )

        rows = {row["platform"]: row for row in results}

        assert rows["github"]["company_name"] == "Camel Corp"
        assert rows["github"]["organization_name"] == "Camel Corp"
        assert rows["gitlab"]["company_name"] == "List Corp"
        assert rows["bitbucket"]["company_name"] == "Employer Labs"
        assert rows["twitter"]["company_name"] == "Schema Works LLC"
        assert rows["linkedin"]["company_name"] == "Member Guild"
        assert rows["facebook"]["company_name"] == "Alumni Network"
        assert "company_name" not in rows["codeberg"]

    def test_normalizes_work_history_containers_for_recursive_synthesis(self):
        results = _parse_epieos_response(
            {
                "email": "alice@example.com",
                "github": {
                    "username": "careerops",
                    "workExperience": [
                        {
                            "title": "Senior Engineer",
                            "company": {
                                "name": "Career Labs",
                                "url": "https://career.acme.example/about",
                                "email": "jobs@career.acme.example",
                                "telephone": "+1 555 707 0001",
                            },
                            "summary": "Runbook https://work.acme.example/runbook",
                        },
                        {"title": "Decoy Role"},
                    ],
                    "education": [
                        {
                            "school": {
                                "name": "Acme University",
                                "url": "https://university.acme.example",
                            }
                        }
                    ],
                },
            }
        )

        github = next((row for row in results if row["platform"] == "github"), None)

        assert github is not None
        assert github["company_name"] == "Career Labs"
        assert github["organization_name"] == "Career Labs"
        assert github["email"] == "jobs@career.acme.example"
        assert github["emails"] == [{"value": "jobs@career.acme.example"}]
        assert github["phone"] == "+15557070001"
        assert github["phone_numbers"] == [{"value": "+15557070001"}]
        assert {"value": "https://career.acme.example/about"} in github["urls"]
        assert {"value": "https://university.acme.example"} in github["urls"]
        assert github["company_name"] != "Senior Engineer"
        assert github["company_name"] != "Decoy Role"

    def test_preserves_domain_host_aliases_for_recursive_synthesis(self):
        results = _parse_epieos_response(
            {
                "email": "alice@example.com",
                "github": {
                    "username": "domainaliasops",
                    "domains": [
                        "portal.acme.example",
                        {"value": "https://status.acme.example/health"},
                    ],
                    "domainName": "acme.example",
                    "hostnames": [{"hostname": "cdn.acme.example."}],
                    "websiteDomain": "github.com",
                    "verifiedDomains": [
                        "verified.acme.example",
                        {"value": "https://proof.acme.example/.well-known/security.txt"},
                    ],
                    "claimedDomains": [{"domain": "*.claimed.acme.example"}],
                    "associatedDomains": [
                        "applinks:app.acme.co.uk",
                        {"value": "webcredentials:auth.acme.example"},
                    ],
                    "associatedDomain": "pages.dev",
                },
            }
        )

        github = next((row for row in results if row["platform"] == "github"), None)

        assert github is not None
        assert github["domain"] == "portal.acme.example"
        assert github["domains"] == [
            {"value": "portal.acme.example"},
            {"value": "status.acme.example"},
            {"value": "acme.example"},
            {"value": "verified.acme.example"},
            {"value": "proof.acme.example"},
            {"value": "claimed.acme.example"},
            {"value": "pages.dev"},
            {"value": "app.acme.co.uk"},
            {"value": "auth.acme.example"},
            {"value": "cdn.acme.example"},
            {"value": "github.com"},
        ]

    def test_normalizes_extended_handle_aliases_for_recursive_profiles(self):
        results = _parse_epieos_response(
            {
                "email": "alice@example.com",
                "github": {
                    "preferredUsername": "pref-alias",
                    "name": "Preferred Alias",
                },
                "gitlab": {
                    "userHandle": "@user-handle-alias",
                    "name": "User Handle Alias",
                },
                "bitbucket": {
                    "accountName": "account-alias",
                    "name": "Account Alias",
                },
                "twitter": {
                    "displayHandle": "@display-alias",
                    "name": "Display Alias",
                },
                "codeberg": {
                    "profile": {
                        "profileHandle": "nested-profile-alias",
                    },
                    "name": "Nested Alias",
                },
                "github_gist": {
                    "profileName": "discover",
                    "name": "Reserved Gist Route",
                },
            }
        )

        rows = {row["platform"]: row for row in results}

        assert rows["github"]["profile_url"] == "https://github.com/pref-alias"
        assert rows["github"]["username"] == "pref-alias"
        assert rows["gitlab"]["profile_url"] == "https://gitlab.com/user-handle-alias"
        assert rows["gitlab"]["username"] == "user-handle-alias"
        assert rows["bitbucket"]["profile_url"] == "https://bitbucket.org/account-alias"
        assert rows["bitbucket"]["username"] == "account-alias"
        assert rows["twitter"]["profile_url"] == "https://x.com/display-alias"
        assert rows["twitter"]["username"] == "display-alias"
        assert rows["codeberg"]["profile_url"] == "https://codeberg.org/nested-profile-alias"
        assert rows["codeberg"]["username"] == "nested-profile-alias"
        assert "github_gist" not in rows

    def test_preserves_extended_link_aliases_for_recursive_synthesis(self):
        results = _parse_epieos_response(
            {
                "email": "alice@example.com",
                "github": {
                    "username": "linkaliasops",
                    "externalLinks": [
                        {"url": "https://docs.acme.example/runbook"},
                        {"url": "https://github.com/linkaliasops"},
                    ],
                    "contactLinks": [
                        {"href": "https://contact.acme.example/help"},
                    ],
                    "sameAsUrls": [
                        {"profileUrl": "https://www.linkedin.com/in/link-alias"},
                    ],
                    "publicUrls": [
                        "https://public.acme.example/profile",
                    ],
                    "identityUrls": [
                        {"identityUrl": "https://identity.acme.example/u/linkaliasops"},
                    ],
                },
            }
        )

        github = next((row for row in results if row["platform"] == "github"), None)

        assert github is not None
        assert github["profile_url"] == "https://github.com/linkaliasops"
        assert github["external_url"] == "https://docs.acme.example/runbook"
        assert github["urls"] == [
            {"value": "https://docs.acme.example/runbook"},
            {"value": "https://contact.acme.example/help"},
            {"value": "https://www.linkedin.com/in/link-alias"},
            {"value": "https://public.acme.example/profile"},
            {"value": "https://identity.acme.example/u/linkaliasops"},
        ]

    def test_preserves_verified_claimed_proof_link_aliases_for_recursive_synthesis(self):
        results = _parse_epieos_response(
            {
                "email": "alice@example.com",
                "github": {
                    "username": "prooflinkops",
                    "verifiedLinks": [
                        {"url": "https://docs.acme.example/security"},
                    ],
                    "claimedUrls": [
                        "portal.acme.example/status",
                    ],
                    "identityProofs": [
                        {"proofUrl": "https://keybase.io/prooflinkops"},
                    ],
                    "relMeLinks": [
                        {"href": "https://www.linkedin.com/in/proof-linked"},
                    ],
                    "proofs": [
                        {"link": "https://proofs.acme.example/.well-known/proof"},
                    ],
                },
            }
        )

        github = next((row for row in results if row["platform"] == "github"), None)

        assert github is not None
        assert github["profile_url"] == "https://github.com/prooflinkops"
        assert github["external_url"] == "https://docs.acme.example/security"
        assert github["urls"] == [
            {"value": "https://docs.acme.example/security"},
            {"value": "portal.acme.example/status"},
            {"value": "https://proofs.acme.example/.well-known/proof"},
            {"value": "https://keybase.io/prooflinkops"},
            {"value": "https://www.linkedin.com/in/proof-linked"},
        ]

    def test_preserves_dict_valued_account_and_proof_aliases_for_recursive_synthesis(self):
        results = _parse_epieos_response(
            {
                "email": "alice@example.com",
                "github": {
                    "username": "dictproofops",
                    "externalLinks": {
                        "status": "status.acme.example/page",
                    },
                    "verifiedAccounts": {
                        "github": "https://github.com/dict-proof",
                        "linkedin": {"url": "https://www.linkedin.com/in/dict-linked"},
                    },
                    "claimedProfiles": {
                        "docs": "https://docs.acme.example/dict",
                        "keybase": {"proofUrl": "https://keybase.io/dictkey"},
                    },
                },
            }
        )

        github = next((row for row in results if row["platform"] == "github"), None)

        assert github is not None
        assert github["profile_url"] == "https://github.com/dictproofops"
        assert github["external_url"] == "status.acme.example/page"
        assert github["urls"] == [
            {"value": "status.acme.example/page"},
            {"value": "https://github.com/dict-proof"},
            {"value": "https://www.linkedin.com/in/dict-linked"},
            {"value": "https://docs.acme.example/dict"},
            {"value": "https://keybase.io/dictkey"},
        ]

    def test_preserves_account_container_link_aliases_for_recursive_synthesis(self):
        results = _parse_epieos_response(
            {
                "email": "alice@example.com",
                "github": {
                    "username": "accountcontainerops",
                    "accounts": [
                        {"profileUrl": "https://gitlab.com/account-alias"},
                    ],
                    "socialAccounts": [
                        {
                            "links": [
                                {"url": "https://www.linkedin.com/in/social-alias"},
                            ],
                        },
                    ],
                    "connectedAccounts": [
                        {"accountUrl": "https://account-links.acme.example/profile"},
                    ],
                    "externalAccounts": [
                        {
                            "profile": {
                                "webUrl": "https://profiles.acme.example/external",
                            },
                        },
                    ],
                    "linkedAccounts": [
                        {"sameAs": "https://same.acme.example/u/account"},
                    ],
                },
            }
        )

        github = next((row for row in results if row["platform"] == "github"), None)

        assert github is not None
        assert github["profile_url"] == "https://github.com/accountcontainerops"
        assert github["external_url"] == "https://gitlab.com/account-alias"
        assert github["urls"] == [
            {"value": "https://gitlab.com/account-alias"},
            {"value": "https://www.linkedin.com/in/social-alias"},
            {"value": "https://account-links.acme.example/profile"},
            {"value": "https://profiles.acme.example/external"},
            {"value": "https://same.acme.example/u/account"},
        ]

    def test_preserves_plural_url_aliases_for_recursive_synthesis(self):
        results = _parse_epieos_response(
            {
                "email": "alice@example.com",
                "github": {
                    "username": "pluralurlops",
                    "profileUrls": [
                        {"profileUrl": "https://gitlab.com/plural-profile"},
                    ],
                    "externalUrls": [
                        {"url": "https://external.acme.example/status"},
                    ],
                    "webUrls": [
                        "https://web.acme.example/home",
                    ],
                    "websiteUrls": [
                        {"href": "https://website.acme.example/about"},
                    ],
                    "blogUrls": [
                        {"link": "https://blog.acme.example/posts"},
                    ],
                    "homepageUrls": [
                        "https://home.acme.example/",
                    ],
                },
            }
        )

        github = next((row for row in results if row["platform"] == "github"), None)

        assert github is not None
        assert github["profile_url"] == "https://github.com/pluralurlops"
        assert github["external_url"] == "https://gitlab.com/plural-profile"
        assert github["urls"] == [
            {"value": "https://gitlab.com/plural-profile"},
            {"value": "https://external.acme.example/status"},
            {"value": "https://web.acme.example/home"},
            {"value": "https://website.acme.example/about"},
            {"value": "https://blog.acme.example/posts"},
            {"value": "https://home.acme.example/"},
        ]

    def test_preserves_singular_site_homepage_aliases_for_recursive_synthesis(self):
        results = _parse_epieos_response(
            {
                "email": "alice@example.com",
                "github": {
                    "username": "singularurlops",
                    "siteUrl": "https://site.acme.example/about",
                    "homepage_url": "https://home.acme.example/",
                    "homeUrl": "https://home-url.acme.example/start",
                    "account": {
                        "site_url": "https://nested-site.acme.example/profile",
                    },
                },
            }
        )

        github = next((row for row in results if row["platform"] == "github"), None)

        assert github is not None
        assert github["profile_url"] == "https://github.com/singularurlops"
        assert github["external_url"] == "https://site.acme.example/about"
        assert github["urls"] == [
            {"value": "https://site.acme.example/about"},
            {"value": "https://home.acme.example/"},
            {"value": "https://home-url.acme.example/start"},
            {"value": "https://nested-site.acme.example/profile"},
        ]

    def test_reconstructs_matrix_federated_and_nostr_identity_rows_for_recursive_synthesis(self):
        npub = "npub1" + "q" * 58
        results = _parse_epieos_response(
            {
                "email": "alice@example.com",
                "matrix": {
                    "mxid": "@matrixblue:matrix.acme.example",
                    "name": "Matrix Blue",
                },
                "activitypub": {
                    "actorUrl": "https://social.acme.example/users/fedblue",
                    "name": "Fed Blue",
                },
                "webfinger": {
                    "subject": "acct:webfingerblue@wf.acme.example",
                    "name": "WebFinger Blue",
                },
                "nostr": {
                    "npub": npub,
                    "name": "Nostr Blue",
                },
                "matrix_room": {
                    "platform": "matrix",
                    "profileUrl": "https://matrix.to/#/#public-room:matrix.acme.example",
                },
            }
        )

        rows = {row["platform"]: row for row in results}

        assert rows["matrix"]["profile_url"] == "https://matrix.to/#/@matrixblue:matrix.acme.example"
        assert rows["matrix"]["username"] == "matrixblue"
        assert rows["matrix"]["mxid"] == "@matrixblue:matrix.acme.example"
        assert rows["activitypub"]["profile_url"] == "https://social.acme.example/@fedblue"
        assert rows["activitypub"]["username"] == "fedblue"
        assert rows["activitypub"]["acct"] == "acct:fedblue@social.acme.example"
        assert rows["webfinger"]["profile_url"] == "https://wf.acme.example/@webfingerblue"
        assert rows["webfinger"]["username"] == "webfingerblue"
        assert rows["webfinger"]["webfinger"] == "acct:webfingerblue@wf.acme.example"
        assert rows["nostr"]["profile_url"] == f"nostr:{npub}"
        assert rows["nostr"]["username"] == npub
        assert rows["nostr"]["npub"] == npub
        assert "matrix_room" not in rows

    def test_preserves_extended_text_aliases_for_recursive_synthesis(self):
        results = _parse_epieos_response(
            {
                "email": "alice@example.com",
                "github": {
                    "username": "textaliasops",
                    "summary": "Summary contact summary.alias@acme.example",
                    "contactText": "Call +1 (555) 222-3333",
                    "publicDescription": "Docs https://docs.acme.example/profile",
                    "notes": [
                        {"text": "Backup profile https://gitlab.com/textaliasops"},
                    ],
                },
            }
        )

        github = next((row for row in results if row["platform"] == "github"), None)

        assert github is not None
        assert github["profile_url"] == "https://github.com/textaliasops"
        assert github["bio"] == "\n".join(
            [
                "Docs https://docs.acme.example/profile",
                "Summary contact summary.alias@acme.example",
                "Backup profile https://gitlab.com/textaliasops",
                "Call +1 (555) 222-3333",
            ]
        )

    def test_preserves_nested_contact_containers_for_recursive_synthesis(self):
        results = _parse_epieos_response(
            {
                "email": "alice@example.com",
                "github": {
                    "username": "contactcontainerops",
                    "contactInfo": {
                        "emailAddress": "Contact Alias <contact.alias@acme.example>",
                        "phoneNumber": "Desk: +1 (555) 303-0001",
                        "websiteUrl": "https://contact.acme.example/help",
                        "summary": (
                            "Escalation escalation.alias@acme.example "
                            "https://status.acme.example/runbook"
                        ),
                    },
                    "contactDetails": [
                        {"mail": "Details Alias <details.alias@acme.example>"},
                        {"tel": "+1 555 303 0002"},
                        {"url": "https://details.acme.example/runbook"},
                    ],
                    "contactPoint": {
                        "email": "Point Alias <point.alias@acme.example>",
                        "telephone": "+1 (555) 303-0003",
                        "url": "https://point.acme.example/help",
                    },
                    "contactPoints": [
                        {
                            "mail": "Points Alias <points.alias@acme.example>",
                            "tel": "+1 555 303 0004",
                            "websiteUrl": "https://points.acme.example/runbook",
                        },
                    ],
                },
            }
        )

        github = next((row for row in results if row["platform"] == "github"), None)

        assert github is not None
        assert github["profile_url"] == "https://github.com/contactcontainerops"
        assert github["email"] == "contact.alias@acme.example"
        assert github["emails"] == [
            {"value": "contact.alias@acme.example"},
            {"value": "escalation.alias@acme.example"},
            {"value": "details.alias@acme.example"},
            {"value": "point.alias@acme.example"},
            {"value": "points.alias@acme.example"},
        ]
        assert github["phone"] == "+15553030001"
        assert github["phone_numbers"] == [
            {"value": "+15553030001"},
            {"value": "+15553030002"},
            {"value": "+15553030003"},
            {"value": "+15553030004"},
        ]
        assert github["urls"] == [
            {"value": "https://contact.acme.example/help"},
            {"value": "https://details.acme.example/runbook"},
            {"value": "https://point.acme.example/help"},
            {"value": "https://points.acme.example/runbook"},
        ]
        assert github["bio"] == (
            "Escalation escalation.alias@acme.example "
            "https://status.acme.example/runbook"
        )

    def test_preserves_related_person_containers_for_recursive_synthesis(self):
        results = _parse_epieos_response(
            {
                "email": "alice@example.com",
                "github": {
                    "username": "relatedcontainerops",
                    "knows": {
                        "email": "Known Alias <known.alias@acme.example>",
                        "sameAs": "https://github.com/known-alias",
                        "description": "Known profile https://known.acme.example/profile",
                    },
                    "colleagues": [
                        {
                            "mail": "colleague.alias@acme.example",
                            "telephone": "+1 (555) 404-0001",
                            "profileUrl": "https://www.linkedin.com/in/colleague-alias",
                        }
                    ],
                    "teamMembers": [
                        {
                            "emailAddress": "team.alias@acme.example",
                            "username": "team-handle",
                            "url": "https://team.acme.example/member",
                        }
                    ],
                },
            }
        )

        github = next((row for row in results if row["platform"] == "github"), None)

        assert github is not None
        assert github["profile_url"] == "https://github.com/relatedcontainerops"
        assert github["email"] == "known.alias@acme.example"
        assert github["emails"] == [
            {"value": "known.alias@acme.example"},
            {"value": "colleague.alias@acme.example"},
            {"value": "team.alias@acme.example"},
        ]
        assert github["phone"] == "+15554040001"
        assert github["phone_numbers"] == [{"value": "+15554040001"}]
        assert github["accounts"] == [
            {
                "username": "known-alias",
                "profile_url": "https://github.com/known-alias",
            },
            {
                "username": "colleague-alias",
                "profile_url": "https://www.linkedin.com/in/colleague-alias",
            },
            {
                "username": "team-handle",
                "profile_url": "https://team.acme.example/member",
            },
        ]
        assert github["urls"] == [
            {"value": "https://github.com/known-alias"},
            {"value": "https://www.linkedin.com/in/colleague-alias"},
            {"value": "https://team.acme.example/member"},
        ]
        assert github["bio"] == "Known profile https://known.acme.example/profile"

    def test_suppresses_numeric_sip_contacts_as_email_values(self):
        assert _epieos_email_values("sip:+15557654332@voice.acme.example") == []
        assert _epieos_email_values("sips:+15557654333@secure-voice.acme.example") == []
        assert _epieos_email_values("sip:sip.ops@acme.example") == ["sip.ops@acme.example"]

    def test_suppresses_numeric_sip_contacts_in_nested_contact_containers(self):
        results = _parse_epieos_response(
            {
                "email": "alice@example.com",
                "github": {
                    "username": "sipcontactops",
                    "contactInfo": {
                        "emailAddress": "sip:email.ops@acme.example",
                        "phoneNumber": "sip:+15557654332@voice.acme.example",
                    },
                },
            }
        )

        github = next((row for row in results if row["platform"] == "github"), None)

        assert github is not None
        assert github["email"] == "email.ops@acme.example"
        assert github["emails"] == [{"value": "email.ops@acme.example"}]
        assert "+15557654332@voice.acme.example" not in {
            item["value"] for item in github["emails"]
        }

    def test_extracts_phone_query_contact_uri_values(self):
        assert _epieos_phone_values("whatsapp://send?phone=15557654328") == [
            "+15557654328"
        ]
        assert _epieos_phone_values("tg://resolve?phone=%2B15557654329") == [
            "+15557654329"
        ]

    def test_preserves_phone_query_contact_uri_values_in_nested_contact_containers(self):
        results = _parse_epieos_response(
            {
                "email": "alice@example.com",
                "github": {
                    "username": "phonequeryops",
                    "contactInfo": {
                        "phoneNumber": "whatsapp://send?phone=15557654328",
                    },
                    "contactDetails": [
                        {"tel": "tg://resolve?phone=%2B15557654329"},
                    ],
                },
            }
        )

        github = next((row for row in results if row["platform"] == "github"), None)

        assert github is not None
        assert github["phone"] == "+15557654328"
        assert github["phone_numbers"] == [
            {"value": "+15557654328"},
            {"value": "+15557654329"},
        ]

    def test_extracts_http_phone_contact_link_values(self):
        assert _epieos_phone_values("https://wa.me/15557654321") == ["+15557654321"]
        assert _epieos_phone_values("https://api.whatsapp.com/send?phone=15557654323") == [
            "+15557654323"
        ]
        assert _epieos_phone_values("https://t.me/+15557654324") == ["+15557654324"]
        assert _epieos_phone_values("https://telegram.me/15557654325") == ["+15557654325"]

    def test_preserves_http_phone_contact_links_in_nested_contact_containers(self):
        results = _parse_epieos_response(
            {
                "email": "alice@example.com",
                "github": {
                    "username": "httpphoneops",
                    "contactInfo": {
                        "phoneNumber": "https://wa.me/15557654321",
                    },
                    "contactDetails": [
                        {"tel": "https://api.whatsapp.com/send?phone=15557654323"},
                        {"phone": "https://t.me/+15557654324"},
                        {"mobile": "https://telegram.me/15557654325"},
                    ],
                },
            }
        )

        github = next((row for row in results if row["platform"] == "github"), None)

        assert github is not None
        assert github["phone"] == "+15557654321"
        assert github["phone_numbers"] == [
            {"value": "+15557654321"},
            {"value": "+15557654323"},
            {"value": "+15557654324"},
            {"value": "+15557654325"},
        ]

    def test_preserves_phone_contact_links_as_phone_pivots(self):
        results = _parse_epieos_response(
            {
                "email": "alice@example.com",
                "github": {
                    "username": "contactlinkphoneops",
                    "contactLinks": [
                        {"href": "https://wa.me/15557654321"},
                        {"url": "https://api.whatsapp.com/send?phone=15557654323"},
                        {"link": "https://t.me/+15557654324"},
                    ],
                    "contactInfo": {
                        "href": "https://telegram.me/15557654325",
                    },
                },
            }
        )

        github = next((row for row in results if row["platform"] == "github"), None)

        assert github is not None
        assert github["phone"] == "+15557654321"
        assert github["phone_numbers"] == [
            {"value": "+15557654321"},
            {"value": "+15557654323"},
            {"value": "+15557654324"},
            {"value": "+15557654325"},
        ]
        assert github["urls"] == [
            {"value": "https://wa.me/15557654321"},
            {"value": "https://api.whatsapp.com/send?phone=15557654323"},
            {"value": "https://t.me/+15557654324"},
            {"value": "https://telegram.me/15557654325"},
        ]

    def test_preserves_email_contact_links_as_email_pivots(self):
        results = _parse_epieos_response(
            {
                "email": "alice@example.com",
                "github": {
                    "username": "contactlinkemailops",
                    "contactLinks": [
                        {"href": "mailto:linked.ops@acme.example?subject=hello"},
                        {"url": "mailto:?to=query.to@acme.example&cc=query.cc@acme.example"},
                    ],
                    "contactInfo": {
                        "href": "mailto:nested.ops@acme.example",
                    },
                },
            }
        )

        github = next((row for row in results if row["platform"] == "github"), None)

        assert github is not None
        assert github["email"] == "linked.ops@acme.example"
        assert github["emails"] == [
            {"value": "linked.ops@acme.example"},
            {"value": "query.to@acme.example"},
            {"value": "query.cc@acme.example"},
            {"value": "nested.ops@acme.example"},
        ]
        assert github["urls"] == [
            {"value": "mailto:linked.ops@acme.example?subject=hello"},
            {"value": "mailto:?to=query.to@acme.example&cc=query.cc@acme.example"},
            {"value": "mailto:nested.ops@acme.example"},
        ]

    def test_preserves_email_phone_link_aliases_as_url_evidence(self):
        results = _parse_epieos_response(
            {
                "email": "alice@example.com",
                "github": {
                    "username": "linkaliasops",
                    "emailLinks": [
                        {"href": "mailto:email.link@acme.example?subject=hello"},
                    ],
                    "phoneLinks": [
                        {"href": "https://wa.me/15557654321"},
                    ],
                },
            }
        )

        github = next((row for row in results if row["platform"] == "github"), None)

        assert github is not None
        assert github["email"] == "email.link@acme.example"
        assert github["emails"] == [{"value": "email.link@acme.example"}]
        assert github["phone"] == "+15557654321"
        assert github["phone_numbers"] == [{"value": "+15557654321"}]
        assert github["urls"] == [
            {"value": "mailto:email.link@acme.example?subject=hello"},
            {"value": "https://wa.me/15557654321"},
        ]

    def test_extracts_sms_mms_contact_uri_phone_values(self):
        assert _epieos_phone_values("sms:+15557654335,+15557654336?body=hello") == [
            "+15557654335",
            "+15557654336",
        ]
        assert _epieos_phone_values("sms:+15557654341;+15557654342") == [
            "+15557654341",
            "+15557654342",
        ]
        assert _epieos_phone_values("sms:?body=hello&to=%2B15557654340") == [
            "+15557654340"
        ]
        assert _epieos_phone_values("mmsto:+15557654339") == ["+15557654339"]

    def test_preserves_sms_mms_contact_uri_values_in_nested_contact_containers(self):
        results = _parse_epieos_response(
            {
                "email": "alice@example.com",
                "github": {
                    "username": "smscontactops",
                    "contactInfo": {
                        "phoneNumber": "sms:?body=hello&to=%2B15557654340",
                    },
                    "contactDetails": [
                        {"tel": "sms:+15557654341;+15557654342"},
                        {"phone": "mms:+15557654338"},
                        {"mobile": "mmsto:+15557654339"},
                    ],
                },
            }
        )

        github = next((row for row in results if row["platform"] == "github"), None)

        assert github is not None
        assert github["phone"] == "+15557654340"
        assert github["phone_numbers"] == [
            {"value": "+15557654340"},
            {"value": "+15557654341"},
            {"value": "+15557654342"},
            {"value": "+15557654338"},
            {"value": "+15557654339"},
        ]

    def test_reconstructs_linkedin_company_url_from_slug_without_promoting_username(self):
        results = _parse_epieos_response(
            {
                "email": "alice@example.com",
                "linkedin_company": {
                    "slug": "acme-corp",
                    "name": "Acme Corp",
                    "website": "https://www.acme.example",
                },
            }
        )
        company = next((r for r in results if r["platform"] == "linkedin_company"), None)

        assert company is not None
        assert company["profile_url"] == "https://www.linkedin.com/company/acme-corp"
        assert company["company_name"] == "Acme Corp"
        assert company["external_url"] == "https://www.acme.example"
        assert "username" not in company

    def test_reconstructs_org_company_profile_urls_without_username_pivots(self):
        results = _parse_epieos_response(
            {
                "email": "alice@example.com",
                "github_org": {
                    "slug": "acme-red-team",
                    "name": "Acme Red Team",
                    "website": "https://red.acme.example",
                },
                "gitlab_group": {
                    "group_slug": "acme-blue",
                    "name": "Acme Blue",
                },
                "huggingface_org": {
                    "organization": {"slug": "acme-ml", "name": "Acme ML"},
                },
                "docker_org": {
                    "namespace": "acme-docker",
                    "name": "Acme Docker",
                },
                "npm_org": {
                    "org_slug": "acme-npm",
                    "name": "Acme NPM",
                },
                "pypi_org": {
                    "org_slug": "acme-py",
                    "name": "Acme PyPI",
                },
                "facebook_page": {
                    "page_slug": "acme-facebook",
                    "name": "Acme Facebook",
                },
                "wellfound_company": {
                    "slug": "acme-startup",
                    "name": "Acme Startup",
                },
                "angellist_company": {
                    "slug": "acme-angels",
                    "name": "Acme Angels",
                },
            }
        )

        rows = {row["platform"]: row for row in results}
        assert rows["github_org"]["profile_url"] == "https://github.com/orgs/acme-red-team"
        assert rows["gitlab_group"]["profile_url"] == "https://gitlab.com/groups/acme-blue"
        assert (
            rows["huggingface_org"]["profile_url"]
            == "https://huggingface.co/organizations/acme-ml"
        )
        assert rows["docker_org"]["profile_url"] == "https://hub.docker.com/orgs/acme-docker"
        assert rows["npm_org"]["profile_url"] == "https://www.npmjs.com/org/acme-npm"
        assert rows["pypi_org"]["profile_url"] == "https://pypi.org/org/acme-py"
        assert rows["facebook_page"]["profile_url"] == "https://www.facebook.com/pages/acme-facebook"
        assert rows["wellfound_company"]["profile_url"] == "https://wellfound.com/company/acme-startup"
        assert rows["angellist_company"]["profile_url"] == "https://angel.co/company/acme-angels"
        for platform in {
            "angellist_company",
            "docker_org",
            "facebook_page",
            "github_org",
            "gitlab_group",
            "huggingface_org",
            "npm_org",
            "pypi_org",
            "wellfound_company",
        }:
            assert "username" not in rows[platform]
            assert rows[platform]["company_name"].startswith("Acme")

    def test_normalizes_facebook_profile_php_and_linkedin_public_identifier(self):
        results = _parse_epieos_response(
            {
                "email": "alice@example.com",
                "facebook": {
                    "url": "https://www.facebook.com/profile.php?id=1000123456789",
                    "name": "Alice Example",
                },
                "linkedin": {
                    "public_identifier": "alice-example",
                    "name": "Alice Example",
                },
            }
        )

        facebook = next((r for r in results if r["platform"] == "facebook"), None)
        linkedin = next((r for r in results if r["platform"] == "linkedin"), None)

        assert facebook is not None
        assert facebook["profile_url"] == "https://www.facebook.com/people/Alice-Example/1000123456789/"
        assert facebook["username"] == "Alice-Example"
        assert linkedin is not None
        assert linkedin["profile_url"] == "https://www.linkedin.com/in/alice-example"
        assert linkedin["username"] == "alice-example"

    def test_normalizes_provider_specific_handle_aliases_for_recursive_profiles(self):
        results = _parse_epieos_response(
            {
                "email": "alice@example.com",
                "tiktok": {
                    "unique_id": "alicetok",
                    "nickname": "Alice Tok",
                },
                "threads": {
                    "userName": "alicethreads",
                    "name": "Alice Threads",
                },
                "instagram": {
                    "username": "alicegram",
                    "name": "Alice Instagram",
                },
                "mastodon": {
                    "acct": "alicefed@infosec.exchange",
                    "display_name": "Alice Fed",
                },
                "twitter": {
                    "screen_name": "aliceopsx",
                    "name": "Alice X",
                },
                "devto": {
                    "username": "alicewrites",
                    "name": "Alice Writes",
                },
                "hashnode": {
                    "username": "alicehash",
                    "name": "Alice Hashnode",
                },
                "medium": {
                    "username": "alicemed",
                    "name": "Alice Medium",
                },
                "muckrack": {
                    "username": "alicemuck",
                    "name": "Alice Muck",
                },
                "substack": {
                    "username": "aliceletters",
                    "name": "Alice Letters",
                },
                "speakerdeck": {
                    "username": "alicedeck",
                    "name": "Alice Deck",
                },
                "slideshare": {
                    "username": "aliceslides",
                    "name": "Alice Slides",
                },
                "soundcloud": {
                    "username": "alicesound",
                    "name": "Alice Sound",
                },
                "mixcloud": {
                    "username": "alicemix",
                    "name": "Alice Mix",
                },
                "letterboxd": {
                    "username": "alicefilm",
                    "name": "Alice Film",
                },
                "flickr": {
                    "username": "aliceflickr",
                    "name": "Alice Flickr",
                },
                "vimeo": {
                    "username": "alicevideo",
                    "name": "Alice Video",
                },
                "github_gist": {
                    "username": "alicegist",
                    "name": "Alice Gist",
                },
                "codepen": {
                    "username": "alicepen",
                    "name": "Alice CodePen",
                },
                "launchpad": {
                    "username": "alicelp",
                    "name": "Alice Launchpad",
                },
                "sourceforge": {
                    "username": "alicesf",
                    "name": "Alice SourceForge",
                },
            }
        )

        tiktok = next((r for r in results if r["platform"] == "tiktok"), None)
        threads = next((r for r in results if r["platform"] == "threads"), None)
        instagram = next((r for r in results if r["platform"] == "instagram"), None)
        mastodon = next((r for r in results if r["platform"] == "mastodon"), None)
        twitter = next((r for r in results if r["platform"] == "twitter"), None)
        devto = next((r for r in results if r["platform"] == "devto"), None)
        hashnode = next((r for r in results if r["platform"] == "hashnode"), None)
        medium = next((r for r in results if r["platform"] == "medium"), None)
        muckrack = next((r for r in results if r["platform"] == "muckrack"), None)
        substack = next((r for r in results if r["platform"] == "substack"), None)
        speakerdeck = next((r for r in results if r["platform"] == "speakerdeck"), None)
        slideshare = next((r for r in results if r["platform"] == "slideshare"), None)
        soundcloud = next((r for r in results if r["platform"] == "soundcloud"), None)
        spotify = next((r for r in results if r["platform"] == "spotify"), None)
        strava = next((r for r in results if r["platform"] == "strava"), None)
        mixcloud = next((r for r in results if r["platform"] == "mixcloud"), None)
        letterboxd = next((r for r in results if r["platform"] == "letterboxd"), None)
        flickr = next((r for r in results if r["platform"] == "flickr"), None)
        vimeo = next((r for r in results if r["platform"] == "vimeo"), None)
        github_gist = next((r for r in results if r["platform"] == "github_gist"), None)
        codepen = next((r for r in results if r["platform"] == "codepen"), None)
        launchpad = next((r for r in results if r["platform"] == "launchpad"), None)
        sourceforge = next((r for r in results if r["platform"] == "sourceforge"), None)

        assert tiktok is not None
        assert tiktok["profile_url"] == "https://www.tiktok.com/@alicetok"
        assert tiktok["username"] == "alicetok"
        assert threads is not None
        assert threads["profile_url"] == "https://www.threads.com/@alicethreads"
        assert threads["username"] == "alicethreads"
        assert instagram is not None
        assert instagram["profile_url"] == "https://www.instagram.com/alicegram/"
        assert instagram["username"] == "alicegram"
        assert mastodon is not None
        assert mastodon["profile_url"] == "https://infosec.exchange/@alicefed"
        assert mastodon["username"] == "alicefed"
        assert twitter is not None
        assert twitter["profile_url"] == "https://x.com/aliceopsx"
        assert twitter["username"] == "aliceopsx"
        assert devto is not None
        assert devto["profile_url"] == "https://dev.to/alicewrites"
        assert devto["username"] == "alicewrites"
        assert hashnode is not None
        assert hashnode["profile_url"] == "https://hashnode.com/@alicehash"
        assert hashnode["username"] == "alicehash"
        assert medium is not None
        assert medium["profile_url"] == "https://medium.com/@alicemed"
        assert medium["username"] == "alicemed"
        assert muckrack is not None
        assert muckrack["profile_url"] == "https://muckrack.com/alicemuck"
        assert muckrack["username"] == "alicemuck"
        assert substack is not None
        assert substack["profile_url"] == "https://aliceletters.substack.com"
        assert substack["username"] == "aliceletters"
        assert speakerdeck is not None
        assert speakerdeck["profile_url"] == "https://speakerdeck.com/alicedeck"
        assert speakerdeck["username"] == "alicedeck"
        assert slideshare is not None
        assert slideshare["profile_url"] == "https://www.slideshare.net/aliceslides"
        assert slideshare["username"] == "aliceslides"
        assert soundcloud is not None
        assert soundcloud["profile_url"] == "https://soundcloud.com/alicesound"
        assert soundcloud["username"] == "alicesound"
        assert mixcloud is not None
        assert mixcloud["profile_url"] == "https://www.mixcloud.com/alicemix/"
        assert mixcloud["username"] == "alicemix"
        assert letterboxd is not None
        assert letterboxd["profile_url"] == "https://letterboxd.com/alicefilm/"
        assert letterboxd["username"] == "alicefilm"
        assert flickr is not None
        assert flickr["profile_url"] == "https://www.flickr.com/photos/aliceflickr/"
        assert flickr["username"] == "aliceflickr"
        assert vimeo is not None
        assert vimeo["profile_url"] == "https://vimeo.com/alicevideo"
        assert vimeo["username"] == "alicevideo"
        assert github_gist is not None
        assert github_gist["profile_url"] == "https://gist.github.com/alicegist"
        assert github_gist["username"] == "alicegist"
        assert codepen is not None
        assert codepen["profile_url"] == "https://codepen.io/alicepen"
        assert codepen["username"] == "alicepen"
        assert launchpad is not None
        assert launchpad["profile_url"] == "https://launchpad.net/~alicelp"
        assert launchpad["username"] == "alicelp"
        assert sourceforge is not None
        assert sourceforge["profile_url"] == "https://sourceforge.net/u/alicesf/profile/"
        assert sourceforge["username"] == "alicesf"

        reserved_results = _parse_epieos_response(
            {
                "email": "alice@example.com",
                "github": {
                    "username": "search",
                    "name": "Reserved GitHub Route",
                },
                "github_gist": {
                    "username": "discover",
                    "name": "Reserved GitHub Gist Route",
                },
                "gitlab": {
                    "username": "explore",
                    "name": "Reserved GitLab Route",
                },
                "bitbucket": {
                    "workspace": "dashboard",
                    "name": "Reserved Bitbucket Route",
                },
                "codeberg": {
                    "username": "pulls",
                    "name": "Reserved Codeberg Route",
                },
                "codepen": {
                    "username": "pen",
                    "name": "Reserved CodePen Route",
                },
                "instagram": {
                    "username": "reels",
                    "name": "Reserved Instagram Route",
                },
                "tiktok": {
                    "unique_id": "tag",
                    "nickname": "Reserved TikTok Route",
                },
                "devto": {
                    "username": "tags",
                    "name": "Reserved DEV Route",
                },
                "twitter": {
                    "screen_name": "search",
                    "name": "Reserved X Route",
                },
                "hashnode": {
                    "username": "search",
                    "name": "Reserved Hashnode Route",
                },
                "medium": {
                    "username": "topic",
                    "name": "Reserved Medium Route",
                },
                "substack": {
                    "username": "app",
                    "name": "Reserved Substack Host",
                },
                "speakerdeck": {
                    "username": "explore",
                    "name": "Reserved Speaker Deck Route",
                },
                "slideshare": {
                    "username": "category",
                    "name": "Reserved SlideShare Route",
                },
                "soundcloud": {
                    "username": "discover",
                    "name": "Reserved SoundCloud Route",
                },
                "mixcloud": {
                    "username": "settings",
                    "name": "Reserved Mixcloud Route",
                },
                "letterboxd": {
                    "username": "film",
                    "name": "Reserved Letterboxd Route",
                },
                "flickr": {
                    "username": "tags",
                    "name": "Reserved Flickr Route",
                },
                "vimeo": {
                    "username": "channels",
                    "name": "Reserved Vimeo Route",
                },
            }
        )
        assert reserved_results == []
        reserved_direct_provider_results = _parse_epieos_response(
            {
                "email": "alice@example.com",
                "npm": {"username": "packages", "name": "Reserved npm route"},
                "pypi": {"username": "search", "name": "Reserved PyPI route"},
                "rubygems": {"username": "gems", "name": "Reserved RubyGems route"},
                "crates": {"username": "crates", "name": "Reserved crates.io route"},
                "packagist": {"username": "packages", "name": "Reserved Packagist route"},
                "nuget": {"username": "packages", "name": "Reserved NuGet route"},
                "openbugbounty": {
                    "username": "researchers",
                    "name": "Reserved Open Bug Bounty route",
                },
                "hexpm": {"username": "packages", "name": "Reserved Hex route"},
                "huggingface": {"handle": "models", "name": "Reserved Hugging Face route"},
                "linktree": {"username": "pricing", "name": "Reserved Linktree route"},
                "allmylinks": {
                    "username": "settings",
                    "name": "Reserved AllMyLinks route",
                },
                "beacons": {"handle": "discover", "name": "Reserved Beacons route"},
                "bento": {"username": "pricing", "name": "Reserved Bento route"},
                "biolink": {"username": "pricing", "name": "Reserved bio.link route"},
                "biosite": {"username": "login", "name": "Reserved Bio Site route"},
                "lnkbio": {"username": "pricing", "name": "Reserved lnk.bio route"},
                "soloto": {"username": "discover", "name": "Reserved solo.to route"},
                "campsite": {"username": "pricing", "name": "Reserved Campsite.bio route"},
                "taplink": {"username": "pricing", "name": "Reserved Taplink route"},
                "milkshake": {"username": "login", "name": "Reserved Milkshake route"},
                "muckrack": {"username": "search", "name": "Reserved Muck Rack route"},
                "carrd": {"slug": "templates", "name": "Reserved Carrd route"},
                "opencollective": {
                    "username": "discover",
                    "name": "Reserved Open Collective route",
                },
                "liberapay": {"username": "explore", "name": "Reserved Liberapay route"},
                "patreon": {"username": "creators", "name": "Reserved Patreon route"},
                "kofi": {"username": "support", "name": "Reserved Ko-fi route"},
                "buymeacoffee": {
                    "username": "creators",
                    "name": "Reserved Buy Me a Coffee route",
                },
                "calendly": {"username": "login", "name": "Reserved Calendly route"},
                "calcom": {"username": "marketplace", "name": "Reserved Cal.com route"},
                "producthunt": {
                    "username": "products",
                    "name": "Reserved Product Hunt route",
                },
                "figma": {"username": "community", "name": "Reserved Figma route"},
                "indiehackers": {
                    "username": "post",
                    "name": "Reserved IndieHackers route",
                },
                "polywork": {"username": "companies", "name": "Reserved Polywork route"},
                "contra": {"username": "discover", "name": "Reserved Contra route"},
                "adplist": {"username": "mentors", "name": "Reserved ADPList route"},
                "spotify": {"username": "playlist", "name": "Reserved Spotify route"},
                "strava": {"username": "clubs", "name": "Reserved Strava route"},
                "launchpad": {"username": "projects", "name": "Reserved Launchpad route"},
                "sourceforge": {
                    "username": "projects",
                    "name": "Reserved SourceForge route",
                },
                "hoobe": {"username": "discover", "name": "Reserved Hoo.be route"},
                "artstation": {"username": "artwork", "name": "Reserved ArtStation route"},
                "deviantart": {"username": "users", "name": "Reserved DeviantArt route"},
            }
        )
        assert reserved_direct_provider_results == []

    def test_filters_non_profile_work_identity_urls_from_provider_payloads(self):
        results = _parse_epieos_response(
            {
                "email": "alice@example.com",
                "figma": {
                    "url": "https://www.figma.com/community/file/123456/design-system",
                    "name": "Figma Community File",
                },
                "indiehackers": {
                    "url": "https://www.indiehackers.com/post/growth-tactics",
                    "name": "IndieHackers Post",
                },
                "polywork": {
                    "url": "https://www.polywork.com/companies/acme",
                    "name": "Polywork Company",
                },
                "contra": {
                    "url": "https://contra.com/discover/designers",
                    "name": "Contra Discover",
                },
                "adplist": {
                    "url": "https://adplist.org/explore",
                    "name": "ADPList Explore",
                },
            }
        )
        assert results == []

    def test_rejects_profile_url_host_lookalikes(self):
        results = _parse_epieos_response(
            {
                "email": "alice@example.com",
                "github": {
                    "profileUrl": "https://notgithub.com/alice",
                    "name": "Not GitHub",
                },
                "unknown_bad": {
                    "identityUrl": "https://notlinkedin.com/in/alice",
                    "name": "Not LinkedIn",
                },
                "unknown_good": {
                    "identityUrl": "https://github.com/alice-good",
                    "name": "Good GitHub",
                },
            }
        )

        rows = {row["platform"]: row for row in results}

        assert "github" not in rows
        assert "unknown_bad" not in rows
        assert rows["unknown_good"]["profile_url"] == "https://github.com/alice-good"
        assert rows["unknown_good"]["username"] == "alice-good"

    def test_rejects_federated_profiles_on_non_federated_social_hosts(self):
        results = _parse_epieos_response(
            {
                "email": "alice@example.com",
                "activitypub": {
                    "actorUrl": "https://github.com/users/fakefed",
                    "name": "Fake Fed",
                },
                "webfinger": {
                    "subject": "acct:linkedinblue@linkedin.com",
                    "name": "LinkedIn Blue",
                },
                "mastodon": {
                    "url": "https://twitter.com/@twitfed",
                    "name": "Twitter Fed",
                },
                "fediverse": {
                    "actorUrl": "https://adplist.org/users/adplistfed",
                    "name": "ADPList Fed",
                },
                "custom_fed": {
                    "platform": "mastodon",
                    "url": "https://social.example.net/@realfed/112233",
                    "name": "Real Fed",
                },
            }
        )

        rows = {row["platform"]: row for row in results}

        assert "activitypub" not in rows
        assert "webfinger" not in rows
        assert "mastodon" not in rows
        assert "fediverse" not in rows
        assert rows["custom_fed"]["profile_url"] == "https://social.example.net/@realfed"
        assert rows["custom_fed"]["username"] == "realfed"

    def test_recurse_provider_key_arrays_for_profiles(self):
        results = _parse_epieos_response(
            {
                "email": "alice@example.com",
                "github": [
                    {"username": "arrayalice", "name": "Array Alice"},
                    {
                        "platform": "gitlab",
                        "profileUrl": "https://gitlab.com/arraylab",
                        "name": "Array Lab",
                    },
                ],
            }
        )

        rows = {(row["platform"], row["username"]): row for row in results}

        assert rows[("github", "arrayalice")]["profile_url"] == "https://github.com/arrayalice"
        assert rows[("gitlab", "arraylab")]["profile_url"] == "https://gitlab.com/arraylab"

    def test_normalizes_common_provider_url_and_profile_id_aliases(self):
        results = _parse_epieos_response(
            {
                "email": "alice@example.com",
                "github": {
                    "html_url": "https://github.com/aliceops",
                    "name": "Alice GitHub",
                },
                "youtube": {
                    "channelId": "UC1234567890123456789012",
                    "title": "Alice Channel",
                },
                "orcid": {
                    "orcid_id": "0000-0002-1825-0097",
                    "name": "Alice Research",
                },
                "researchgate": {
                    "profileSlug": "Alice-Example",
                    "name": "Alice ResearchGate",
                },
                "credly": {
                    "vanity_url": "alice-ops",
                    "name": "Alice Credly",
                },
                "stackexchange": {
                    "site": "serverfault.com",
                    "user_id": "13579",
                    "username": "alice-sf",
                    "name": "Alice ServerFault",
                },
                "spotify": {
                    "profileLink": "https://open.spotify.com/user/alice.spotify",
                    "name": "Alice Spotify",
                },
                "strava": {
                    "profileLink": "https://www.strava.com/athletes/12345678",
                    "name": "Alice Strava",
                },
                "strava_club": {
                    "platform": "strava",
                    "profileLink": "https://www.strava.com/clubs/acme-cycling",
                    "name": "Not An Athlete Profile",
                },
                "unsplash": {
                    "profileLink": "https://unsplash.com/@alicephotos",
                    "name": "Alice Unsplash",
                },
                "unsplash_photo": {
                    "platform": "unsplash",
                    "profileLink": "https://unsplash.com/photos/abcdef",
                    "name": "Not A Profile Route",
                },
                "fivehundredpx": {
                    "platform": "500px",
                    "profileLink": "https://500px.com/p/alicephoto",
                    "name": "Alice 500px",
                },
                "fivehundredpx_photo": {
                    "platform": "500px",
                    "profileLink": "https://500px.com/photo/123456/security",
                    "name": "Not A 500px Profile Route",
                },
                "artstation": {
                    "profileLink": "https://www.artstation.com/aliceartist",
                    "name": "Alice ArtStation",
                },
                "artstation_site": {
                    "platform": "artstation",
                    "profileLink": "https://aliceportfolio.artstation.com/projects/security-briefing",
                    "name": "Alice ArtStation Portfolio",
                },
                "artstation_artwork": {
                    "platform": "artstation",
                    "profileLink": "https://www.artstation.com/artwork/abc123",
                    "name": "Not A Profile Route",
                },
                "artstation_marketplace": {
                    "platform": "artstation",
                    "profileLink": "https://www.artstation.com/marketplace/p/security-asset",
                    "name": "Not A Profile Route",
                },
                "deviantart": {
                    "profileLink": "https://www.deviantart.com/aliceartist",
                    "name": "Alice DeviantArt",
                },
                "deviantart_legacy": {
                    "platform": "deviantart",
                    "profileLink": "https://alicelegacy.deviantart.com/gallery",
                    "name": "Alice Legacy DeviantArt",
                },
                "deviantart_login": {
                    "platform": "deviantart",
                    "profileLink": "https://www.deviantart.com/users/login",
                    "name": "Not A Profile Route",
                },
                "deviantart_tag": {
                    "platform": "deviantart",
                    "profileLink": "https://www.deviantart.com/tag/security",
                    "name": "Not A Profile Route",
                },
                "quora": {
                    "profileLink": "https://www.quora.com/profile/Alice-Example-1",
                    "name": "Alice Quora",
                },
                "quora_question": {
                    "platform": "quora",
                    "profileLink": "https://www.quora.com/What-is-OSINT",
                    "name": "Not A Profile Route",
                },
                "launchpad": {
                    "profileLink": "https://launchpad.net/~alice-lp",
                    "name": "Alice Launchpad",
                },
                "launchpad_project": {
                    "platform": "launchpad",
                    "profileLink": "https://launchpad.net/projects/example",
                    "name": "Launchpad Project Route",
                },
                "sourceforge": {
                    "profileLink": "https://sourceforge.net/u/alice-sf/profile/",
                    "name": "Alice SourceForge",
                },
                "sourceforge_project": {
                    "platform": "sourceforge",
                    "profileLink": "https://sourceforge.net/projects/example",
                    "name": "SourceForge Project Route",
                },
                "spotify_artist": {
                    "platform": "spotify",
                    "profileLink": "https://open.spotify.com/artist/1234567890",
                    "name": "Not A User Profile",
                },
            }
        )
        custom_youtube_results = _parse_epieos_response(
            {
                "email": "alice@example.com",
                "youtube": {
                    "customUrl": "@aliceops",
                    "title": "Alice Ops",
                },
            }
        )
        reserved_youtube_results = _parse_epieos_response(
            {
                "email": "alice@example.com",
                "youtube": {
                    "customUrl": "watch",
                    "title": "Reserved YouTube Route",
                },
            }
        )
        reserved_devto_results = _parse_epieos_response(
            {
                "email": "alice@example.com",
                "devto": {
                    "url": "https://dev.to/tags/security",
                    "name": "Reserved DEV Tag Route",
                },
            }
        )
        reserved_twitter_results = _parse_epieos_response(
            {
                "email": "alice@example.com",
                "twitter": {
                    "url": "https://x.com/search?q=acme",
                    "name": "Reserved X Search Route",
                },
            }
        )

        github = next((r for r in results if r["platform"] == "github"), None)
        youtube_channel = next((r for r in results if r["platform"] == "youtube"), None)
        youtube_custom = next((r for r in custom_youtube_results if r["platform"] == "youtube"), None)
        orcid = next((r for r in results if r["platform"] == "orcid"), None)
        researchgate = next((r for r in results if r["platform"] == "researchgate"), None)
        credly = next((r for r in results if r["platform"] == "credly"), None)
        stackexchange = next((r for r in results if r["platform"] == "stackexchange"), None)
        spotify = next((r for r in results if r["platform"] == "spotify"), None)
        strava = next((r for r in results if r["platform"] == "strava"), None)
        strava_club = next((r for r in results if r["platform"] == "strava_club"), None)
        unsplash = next((r for r in results if r["platform"] == "unsplash"), None)
        unsplash_photo = next((r for r in results if r["platform"] == "unsplash_photo"), None)
        fivehundredpx = next((r for r in results if r["platform"] == "fivehundredpx"), None)
        fivehundredpx_photo = next((r for r in results if r["platform"] == "fivehundredpx_photo"), None)
        artstation = next((r for r in results if r["platform"] == "artstation"), None)
        artstation_site = next((r for r in results if r["platform"] == "artstation_site"), None)
        artstation_artwork = next((r for r in results if r["platform"] == "artstation_artwork"), None)
        artstation_marketplace = next(
            (r for r in results if r["platform"] == "artstation_marketplace"),
            None,
        )
        deviantart = next((r for r in results if r["platform"] == "deviantart"), None)
        deviantart_legacy = next((r for r in results if r["platform"] == "deviantart_legacy"), None)
        deviantart_login = next((r for r in results if r["platform"] == "deviantart_login"), None)
        deviantart_tag = next((r for r in results if r["platform"] == "deviantart_tag"), None)
        quora = next((r for r in results if r["platform"] == "quora"), None)
        quora_question = next((r for r in results if r["platform"] == "quora_question"), None)
        launchpad = next((r for r in results if r["platform"] == "launchpad"), None)
        launchpad_project = next((r for r in results if r["platform"] == "launchpad_project"), None)
        sourceforge = next((r for r in results if r["platform"] == "sourceforge"), None)
        sourceforge_project = next((r for r in results if r["platform"] == "sourceforge_project"), None)
        spotify_artist = next((r for r in results if r["platform"] == "spotify_artist"), None)

        assert github is not None
        assert github["profile_url"] == "https://github.com/aliceops"
        assert github["username"] == "aliceops"
        assert youtube_channel is not None
        assert youtube_channel["profile_url"] == "https://www.youtube.com/channel/UC1234567890123456789012"
        assert youtube_channel["username"] == "UC1234567890123456789012"
        assert youtube_custom is not None
        assert youtube_custom["profile_url"] == "https://www.youtube.com/@aliceops"
        assert youtube_custom["username"] == "aliceops"
        assert reserved_youtube_results == []
        assert reserved_devto_results == []
        assert reserved_twitter_results == []
        assert spotify_artist is None
        reserved_research_direct_results = _parse_epieos_response(
            {
                "email": "alice@example.com",
                "orcid": {"username": "signin", "name": "Reserved ORCID route"},
                "researchgate": {
                    "username": "publication",
                    "name": "Reserved ResearchGate route",
                },
                "google_scholar": {"username": "citations", "name": "Reserved Scholar route"},
                "academia": {"username": "people", "name": "Reserved Academia route"},
                "zenodo": {"username": "records", "name": "Reserved Zenodo route"},
                "credly": {"username": "badges", "name": "Reserved Credly route"},
                "behance": {"username": "galleries", "name": "Reserved Behance route"},
                "dribbble": {"username": "shots", "name": "Reserved Dribbble route"},
                "wellfound": {"username": "company", "name": "Reserved Wellfound route"},
                "angellist": {"username": "company", "name": "Reserved AngelList route"},
            }
        )
        assert reserved_research_direct_results == []
        assert orcid is not None
        assert orcid["profile_url"] == "https://orcid.org/0000-0002-1825-0097"
        assert orcid["username"] == "0000-0002-1825-0097"
        assert researchgate is not None
        assert researchgate["profile_url"] == "https://www.researchgate.net/profile/Alice-Example"
        assert researchgate["username"] == "Alice-Example"
        assert credly is not None
        assert credly["profile_url"] == "https://www.credly.com/users/alice-ops"
        assert credly["username"] == "alice-ops"
        assert stackexchange is not None
        assert stackexchange["profile_url"] == "https://serverfault.com/users/13579/alice-sf"
        assert stackexchange["username"] == "alice-sf"
        assert spotify is not None
        assert spotify["profile_url"] == "https://open.spotify.com/user/alice.spotify"
        assert spotify["username"] == "alice.spotify"
        assert strava is not None
        assert strava["profile_url"] == "https://www.strava.com/athletes/12345678"
        assert strava["username"] == "12345678"
        assert strava_club is None
        assert unsplash is not None
        assert unsplash["profile_url"] == "https://unsplash.com/@alicephotos"
        assert unsplash["username"] == "alicephotos"
        assert unsplash_photo is None
        assert fivehundredpx is not None
        assert fivehundredpx["profile_url"] == "https://500px.com/p/alicephoto"
        assert fivehundredpx["username"] == "alicephoto"
        assert fivehundredpx_photo is None
        assert artstation is not None
        assert artstation["profile_url"] == "https://www.artstation.com/aliceartist"
        assert artstation["username"] == "aliceartist"
        assert artstation_site is not None
        assert artstation_site["profile_url"] == "https://aliceportfolio.artstation.com/projects/security-briefing"
        assert artstation_site["username"] == "aliceportfolio"
        assert artstation_artwork is None
        assert artstation_marketplace is None
        assert deviantart is not None
        assert deviantart["profile_url"] == "https://www.deviantart.com/aliceartist"
        assert deviantart["username"] == "aliceartist"
        assert deviantart_legacy is not None
        assert deviantart_legacy["profile_url"] == "https://alicelegacy.deviantart.com/gallery"
        assert deviantart_legacy["username"] == "alicelegacy"
        assert deviantart_login is None
        assert deviantart_tag is None
        assert quora is not None
        assert quora["profile_url"] == "https://www.quora.com/profile/Alice-Example-1"
        assert quora["username"] == "Alice-Example-1"
        assert quora_question is None
        assert launchpad is not None
        assert launchpad["profile_url"] == "https://launchpad.net/~alice-lp"
        assert launchpad["username"] == "alice-lp"
        assert launchpad_project is None
        assert sourceforge is not None
        assert sourceforge["profile_url"] == "https://sourceforge.net/u/alice-sf/profile/"
        assert sourceforge["username"] == "alice-sf"
        assert sourceforge_project is None

    def test_normalizes_provider_specific_profile_and_vanity_aliases(self):
        results = _parse_epieos_response(
            {
                "email": "alice@example.com",
                "github": {
                    "profile": "https://github.com/aliceops",
                    "name": "Alice GitHub",
                },
                "linkedin": {
                    "vanityName": "alice-example",
                    "name": "Alice Example",
                },
                "researchgate": {
                    "profile": "Alice-Example",
                    "name": "Alice ResearchGate",
                },
            }
        )

        github = next((r for r in results if r["platform"] == "github"), None)
        linkedin = next((r for r in results if r["platform"] == "linkedin"), None)
        researchgate = next((r for r in results if r["platform"] == "researchgate"), None)

        assert github is not None
        assert github["profile_url"] == "https://github.com/aliceops"
        assert github["username"] == "aliceops"
        assert linkedin is not None
        assert linkedin["profile_url"] == "https://www.linkedin.com/in/alice-example"
        assert linkedin["username"] == "alice-example"
        assert researchgate is not None
        assert researchgate["profile_url"] == "https://www.researchgate.net/profile/Alice-Example"
        assert researchgate["username"] == "Alice-Example"

    def test_normalizes_host_checked_profile_url_aliases(self):
        results = _parse_epieos_response(
            {
                "email": "alice@example.com",
                "gitlab": {
                    "web_url": "https://gitlab.com/alicegit",
                    "name": "Alice GitLab",
                },
                "codeberg": {
                    "profileLink": "codeberg.org/aliceberg",
                    "name": "Alice Codeberg",
                },
                "linkedin": {
                    "permalinkUrl": "https://www.linkedin.com/in/alice-link",
                    "name": "Alice Link",
                },
                "stackoverflow": {
                    "profileLink": "superuser.com/users/24680/alice-su",
                    "name": "Alice SuperUser",
                },
                "google_scholar": {
                    "profileLink": "https://scholar.google.com/citations?user=qc6CJjYAAAAJ",
                    "name": "Alice Scholar",
                },
                "academia": {
                    "profileLink": "https://www.academia.edu/AliceAcademic",
                    "name": "Alice Academia",
                },
                "semantic_scholar": {
                    "profileLink": "https://www.semanticscholar.org/author/Alice-Example/123",
                    "name": "Alice Semantic",
                },
                "zenodo": {
                    "profileLink": "https://zenodo.org/users/alicezenodo",
                    "name": "Alice Zenodo",
                },
                "figshare": {
                    "profileLink": "https://figshare.com/authors/Alice_Example/123456",
                    "name": "Alice Figshare",
                },
                "threads": {
                    "profileLink": "https://www.threads.com/@alice-thread",
                    "name": "Alice Threads",
                },
                "bluesky": {
                    "profileLink": "https://bsky.social/profile/alice.blue",
                    "name": "Alice Blue",
                },
                "github_sameas": {
                    "platform": "github",
                    "sameAs": "https://github.com/same-alias",
                    "name": "Same As Alias",
                },
                "github_sameas_list": {
                    "platform": "github",
                    "sameAs": [
                        {"url": "https://example.com/not-github"},
                        {"url": "https://github.com/list-alias"},
                    ],
                    "name": "Same As List Alias",
                },
                "gitlab_account": {
                    "platform": "gitlab",
                    "account_url": "gitlab.com/account-alias",
                    "name": "Account URL Alias",
                },
                "linkedin_public": {
                    "platform": "linkedin",
                    "publicUrl": "https://www.linkedin.com/in/public-alias",
                    "name": "Public URL Alias",
                },
                "codeberg_identity": {
                    "platform": "codeberg",
                    "identityUrl": "https://codeberg.org/identity-alias",
                    "name": "Identity URL Alias",
                },
                "stackoverflow_uri": {
                    "platform": "stackoverflow",
                    "uri": "superuser.com/users/13579/uri-alias",
                    "name": "URI Alias",
                },
                "twitter": {
                    "profile_link": "https://example.com/not-a-twitter-profile",
                    "name": "Not A Twitter Profile",
                },
                "stackexchange_reserved": {
                    "platform": "stackoverflow",
                    "profileLink": "superuser.com/questions/12345/example",
                    "name": "Not A Profile",
                },
            }
        )
        reserved_code_host_results = _parse_epieos_response(
            {
                "email": "alice@example.com",
                "github": {
                    "html_url": "https://github.com/search?q=acme",
                    "name": "Reserved GitHub Search",
                },
                "gitlab": {
                    "web_url": "https://gitlab.com/explore",
                    "name": "Reserved GitLab Explore",
                },
                "bitbucket": {
                    "profileLink": "https://bitbucket.org/dashboard",
                    "name": "Reserved Bitbucket Dashboard",
                },
                "codeberg": {
                    "profileLink": "https://codeberg.org/pulls",
                    "name": "Reserved Codeberg Pulls",
                },
                "google_scholar": {
                    "profileLink": "https://scholar.google.com/citations?view_op=search_authors",
                    "name": "Reserved Scholar Search",
                },
                "academia": {
                    "profileLink": "https://www.academia.edu/people/search",
                    "name": "Reserved Academia Search",
                },
                "semantic_scholar": {
                    "profileLink": "https://www.semanticscholar.org/paper/123",
                    "name": "Reserved Semantic Paper",
                },
                "zenodo": {
                    "profileLink": "https://zenodo.org/records/123",
                    "name": "Reserved Zenodo Record",
                },
                "figshare": {
                    "profileLink": "https://figshare.com/articles/dataset/example/123456",
                    "name": "Reserved Figshare Article",
                },
            }
        )

        gitlab = next((r for r in results if r["platform"] == "gitlab"), None)
        codeberg = next((r for r in results if r["platform"] == "codeberg"), None)
        linkedin = next((r for r in results if r["platform"] == "linkedin"), None)
        stackoverflow = next((r for r in results if r["platform"] == "stackoverflow"), None)
        google_scholar = next((r for r in results if r["platform"] == "google_scholar"), None)
        gravatar = next((r for r in results if r["platform"] == "gravatar"), None)
        academia = next((r for r in results if r["platform"] == "academia"), None)
        semantic_scholar = next((r for r in results if r["platform"] == "semantic_scholar"), None)
        zenodo = next((r for r in results if r["platform"] == "zenodo"), None)
        figshare = next((r for r in results if r["platform"] == "figshare"), None)
        threads = next((r for r in results if r["platform"] == "threads"), None)
        bluesky = next((r for r in results if r["platform"] == "bluesky"), None)
        github_sameas = next((r for r in results if r["platform"] == "github_sameas"), None)
        github_sameas_list = next(
            (r for r in results if r["platform"] == "github_sameas_list"),
            None,
        )
        gitlab_account = next((r for r in results if r["platform"] == "gitlab_account"), None)
        linkedin_public = next((r for r in results if r["platform"] == "linkedin_public"), None)
        codeberg_identity = next((r for r in results if r["platform"] == "codeberg_identity"), None)
        stackoverflow_uri = next((r for r in results if r["platform"] == "stackoverflow_uri"), None)
        twitter = next((r for r in results if r["platform"] == "twitter"), None)
        stackexchange_reserved = next(
            (r for r in results if r["platform"] == "stackexchange_reserved"),
            None,
        )

        assert gitlab is not None
        assert gitlab["profile_url"] == "https://gitlab.com/alicegit"
        assert gitlab["username"] == "alicegit"
        assert codeberg is not None
        assert codeberg["profile_url"] == "https://codeberg.org/aliceberg"
        assert codeberg["username"] == "aliceberg"
        assert linkedin is not None
        assert linkedin["profile_url"] == "https://www.linkedin.com/in/alice-link"
        assert linkedin["username"] == "alice-link"
        assert stackoverflow is not None
        assert stackoverflow["profile_url"] == "https://superuser.com/users/24680/alice-su"
        assert stackoverflow["username"] == "alice-su"
        assert google_scholar is not None
        assert google_scholar["profile_url"] == "https://scholar.google.com/citations?user=qc6CJjYAAAAJ"
        assert google_scholar["username"] == "qc6CJjYAAAAJ"
        assert academia is not None
        assert academia["profile_url"] == "https://www.academia.edu/AliceAcademic"
        assert academia["username"] == "AliceAcademic"
        assert semantic_scholar is not None
        assert (
            semantic_scholar["profile_url"]
            == "https://www.semanticscholar.org/author/Alice-Example/123"
        )
        assert semantic_scholar["username"] == "Alice-Example"
        assert zenodo is not None
        assert zenodo["profile_url"] == "https://zenodo.org/users/alicezenodo"
        assert zenodo["username"] == "alicezenodo"
        assert figshare is not None
        assert figshare["profile_url"] == "https://figshare.com/authors/Alice_Example/123456"
        assert figshare["username"] == "Alice_Example"
        assert threads is not None
        assert threads["profile_url"] == "https://www.threads.com/@alice-thread"
        assert threads["username"] == "alice-thread"
        assert bluesky is not None
        assert bluesky["profile_url"] == "https://bsky.social/profile/alice.blue"
        assert bluesky["username"] == "alice.blue"
        assert github_sameas is not None
        assert github_sameas["profile_url"] == "https://github.com/same-alias"
        assert github_sameas["username"] == "same-alias"
        assert github_sameas_list is not None
        assert github_sameas_list["profile_url"] == "https://github.com/list-alias"
        assert github_sameas_list["username"] == "list-alias"
        assert gitlab_account is not None
        assert gitlab_account["profile_url"] == "https://gitlab.com/account-alias"
        assert gitlab_account["username"] == "account-alias"
        assert linkedin_public is not None
        assert linkedin_public["profile_url"] == "https://www.linkedin.com/in/public-alias"
        assert linkedin_public["username"] == "public-alias"
        assert codeberg_identity is not None
        assert codeberg_identity["profile_url"] == "https://codeberg.org/identity-alias"
        assert codeberg_identity["username"] == "identity-alias"
        assert stackoverflow_uri is not None
        assert stackoverflow_uri["profile_url"] == "https://superuser.com/users/13579/uri-alias"
        assert stackoverflow_uri["username"] == "uri-alias"
        assert twitter is None
        assert stackexchange_reserved is not None
        assert stackexchange_reserved["profile_url"] == "https://superuser.com/questions/12345/example"
        assert "username" not in stackexchange_reserved
        reserved_code_host_platforms = {row["platform"] for row in reserved_code_host_results}
        assert {"github", "gitlab", "bitbucket", "codeberg"}.issubset(
            reserved_code_host_platforms
        )
        assert not {
            "google_scholar",
            "academia",
            "semantic_scholar",
            "zenodo",
            "figshare",
        } & reserved_code_host_platforms
        assert all("username" not in row for row in reserved_code_host_results)

    def test_constructs_academic_profile_urls_from_author_id_aliases(self):
        results = _parse_epieos_response(
            {
                "email": "alice@example.com",
                "google_scholar": {
                    "user": "qc6CJjYAAAAJ",
                    "name": "Alice Scholar",
                },
                "semantic_scholar": {
                    "author_id": "123456",
                    "username": "Alice-Example",
                    "name": "Alice Semantic",
                },
                "figshare": {
                    "authorId": "789012",
                    "handle": "Alice_Example",
                    "name": "Alice Figshare",
                },
            }
        )
        reserved_results = _parse_epieos_response(
            {
                "semantic_scholar": {
                    "author_id": "123456",
                    "username": "paper",
                    "name": "Reserved Semantic",
                },
                "figshare": {
                    "authorId": "789012",
                    "handle": "articles",
                    "name": "Reserved Figshare",
                },
            }
        )

        google_scholar = next((r for r in results if r["platform"] == "google_scholar"), None)
        semantic_scholar = next((r for r in results if r["platform"] == "semantic_scholar"), None)
        figshare = next((r for r in results if r["platform"] == "figshare"), None)

        assert google_scholar is not None
        assert google_scholar["profile_url"] == "https://scholar.google.com/citations?user=qc6CJjYAAAAJ"
        assert google_scholar["username"] == "qc6CJjYAAAAJ"
        assert semantic_scholar is not None
        assert (
            semantic_scholar["profile_url"]
            == "https://www.semanticscholar.org/author/Alice-Example/123456"
        )
        assert semantic_scholar["username"] == "Alice-Example"
        assert figshare is not None
        assert figshare["profile_url"] == "https://figshare.com/authors/Alice_Example/789012"
        assert figshare["username"] == "Alice_Example"
        assert reserved_results == []

    def test_normalizes_nested_profile_objects_for_recursive_profiles(self):
        results = _parse_epieos_response(
            {
                "email": "alice@example.com",
                "github": {
                    "profile": {
                        "url": "https://github.com/nestedhub",
                    },
                    "name": "Nested GitHub",
                },
                "linkedin": {
                    "profile": {
                        "publicIdentifier": "nested-link",
                    },
                    "name": "Nested Link",
                },
                "researchgate": {
                    "profile": {
                        "profileSlug": "Nested-Research",
                    },
                    "name": "Nested Research",
                },
                "twitter": {
                    "profile": {
                        "url": "https://example.com/not-a-twitter-profile",
                    },
                    "name": "Not Twitter",
                },
                "github_identity": {
                    "platform": "github",
                    "identity": {
                        "html_url": "https://github.com/identityhub",
                    },
                    "name": "Identity GitHub",
                },
                "linkedin_person": {
                    "platform": "linkedin",
                    "person": {
                        "publicIdentifier": "person-link",
                    },
                    "name": "Person Link",
                },
                "researchgate_member": {
                    "platform": "researchgate",
                    "member": {
                        "profileSlug": "Member-Research",
                    },
                    "name": "Member Research",
                },
                "twitter_owner": {
                    "platform": "twitter",
                    "owner": {
                        "url": "https://x.com/ownerops",
                    },
                    "name": "Owner X",
                },
            }
        )

        github = next((r for r in results if r["platform"] == "github"), None)
        linkedin = next((r for r in results if r["platform"] == "linkedin"), None)
        researchgate = next((r for r in results if r["platform"] == "researchgate"), None)
        twitter = next((r for r in results if r["platform"] == "twitter"), None)
        github_identity = next((r for r in results if r["platform"] == "github_identity"), None)
        linkedin_person = next((r for r in results if r["platform"] == "linkedin_person"), None)
        researchgate_member = next(
            (r for r in results if r["platform"] == "researchgate_member"),
            None,
        )
        twitter_owner = next((r for r in results if r["platform"] == "twitter_owner"), None)

        assert github is not None
        assert github["profile_url"] == "https://github.com/nestedhub"
        assert github["username"] == "nestedhub"
        assert linkedin is not None
        assert linkedin["profile_url"] == "https://www.linkedin.com/in/nested-link"
        assert linkedin["username"] == "nested-link"
        assert researchgate is not None
        assert researchgate["profile_url"] == "https://www.researchgate.net/profile/Nested-Research"
        assert researchgate["username"] == "Nested-Research"
        assert twitter is None
        assert github_identity is not None
        assert github_identity["profile_url"] == "https://github.com/identityhub"
        assert github_identity["username"] == "identityhub"
        assert linkedin_person is not None
        assert linkedin_person["profile_url"] == "https://www.linkedin.com/in/person-link"
        assert linkedin_person["username"] == "person-link"
        assert researchgate_member is not None
        assert (
            researchgate_member["profile_url"]
            == "https://www.researchgate.net/profile/Member-Research"
        )
        assert researchgate_member["username"] == "Member-Research"
        assert twitter_owner is not None
        assert twitter_owner["profile_url"] == "https://x.com/ownerops"
        assert twitter_owner["username"] == "ownerops"

    def test_constructs_additional_profile_urls_for_supported_provider_shapes(self):
        results = _parse_epieos_response(_expanded_provider_epieos_payload())

        bitbucket = next((r for r in results if r["platform"] == "bitbucket"), None)
        bugcrowd = next((r for r in results if r["platform"] == "bugcrowd"), None)
        github_sponsors = next((r for r in results if r["platform"] == "github_sponsors"), None)
        codeberg = next((r for r in results if r["platform"] == "codeberg"), None)
        hackerone = next((r for r in results if r["platform"] == "hackerone"), None)
        hashnode = next((r for r in results if r["platform"] == "hashnode"), None)
        intigriti = next((r for r in results if r["platform"] == "intigriti"), None)
        dockerhub = next((r for r in results if r["platform"] == "dockerhub"), None)
        sourcehut = next((r for r in results if r["platform"] == "sourcehut"), None)
        snapchat = next((r for r in results if r["platform"] == "snapchat"), None)
        mastodon = next((r for r in results if r["platform"] == "mastodon"), None)
        reddit = next((r for r in results if r["platform"] == "reddit"), None)
        replit = next((r for r in results if r["platform"] == "replit"), None)
        codesandbox = next((r for r in results if r["platform"] == "codesandbox"), None)
        devpost = next((r for r in results if r["platform"] == "devpost"), None)
        readcv = next((r for r in results if r["platform"] == "readcv"), None)
        telegram = next((r for r in results if r["platform"] == "telegram"), None)
        bluesky = next((r for r in results if r["platform"] == "bluesky"), None)
        youtube = next((r for r in results if r["platform"] == "youtube"), None)
        npm = next((r for r in results if r["platform"] == "npm"), None)
        pypi = next((r for r in results if r["platform"] == "pypi"), None)
        rubygems = next((r for r in results if r["platform"] == "rubygems"), None)
        crates = next((r for r in results if r["platform"] == "crates"), None)
        packagist = next((r for r in results if r["platform"] == "packagist"), None)
        nuget = next((r for r in results if r["platform"] == "nuget"), None)
        openbugbounty = next((r for r in results if r["platform"] == "openbugbounty"), None)
        hexpm = next((r for r in results if r["platform"] == "hexpm"), None)
        stackoverflow = next((r for r in results if r["platform"] == "stackoverflow"), None)
        huggingface = next((r for r in results if r["platform"] == "huggingface"), None)
        keybase = next((r for r in results if r["platform"] == "keybase"), None)
        medium = next((r for r in results if r["platform"] == "medium"), None)
        facebook = next((r for r in results if r["platform"] == "facebook"), None)
        flickr = next((r for r in results if r["platform"] == "flickr"), None)
        vimeo = next((r for r in results if r["platform"] == "vimeo"), None)
        kaggle = next((r for r in results if r["platform"] == "kaggle"), None)
        lastfm = next((r for r in results if r["platform"] == "lastfm"), None)
        bandcamp = next((r for r in results if r["platform"] == "bandcamp"), None)
        linktree = next((r for r in results if r["platform"] == "linktree"), None)
        allmylinks = next((r for r in results if r["platform"] == "allmylinks"), None)
        artstation = next((r for r in results if r["platform"] == "artstation"), None)
        deviantart = next((r for r in results if r["platform"] == "deviantart"), None)
        biosite = next((r for r in results if r["platform"] == "biosite"), None)
        campsite = next((r for r in results if r["platform"] == "campsite"), None)
        taplink = next((r for r in results if r["platform"] == "taplink"), None)
        taplink_ws = next((r for r in results if r["platform"] == "taplink_ws"), None)
        milkshake = next((r for r in results if r["platform"] == "milkshake"), None)
        opencollective = next((r for r in results if r["platform"] == "opencollective"), None)
        liberapay = next((r for r in results if r["platform"] == "liberapay"), None)
        patreon = next((r for r in results if r["platform"] == "patreon"), None)
        kofi = next((r for r in results if r["platform"] == "kofi"), None)
        buymeacoffee = next((r for r in results if r["platform"] == "buymeacoffee"), None)
        calendly = next((r for r in results if r["platform"] == "calendly"), None)
        calcom = next((r for r in results if r["platform"] == "calcom"), None)
        producthunt = next((r for r in results if r["platform"] == "producthunt"), None)
        wellfound = next((r for r in results if r["platform"] == "wellfound"), None)
        angellist = next((r for r in results if r["platform"] == "angellist"), None)
        figma = next((r for r in results if r["platform"] == "figma"), None)
        indiehackers = next((r for r in results if r["platform"] == "indiehackers"), None)
        polywork = next((r for r in results if r["platform"] == "polywork"), None)
        contra = next((r for r in results if r["platform"] == "contra"), None)
        adplist = next((r for r in results if r["platform"] == "adplist"), None)
        orcid = next((r for r in results if r["platform"] == "orcid"), None)
        researchgate = next((r for r in results if r["platform"] == "researchgate"), None)
        google_scholar = next((r for r in results if r["platform"] == "google_scholar"), None)
        gravatar = next((r for r in results if r["platform"] == "gravatar"), None)
        academia = next((r for r in results if r["platform"] == "academia"), None)
        zenodo = next((r for r in results if r["platform"] == "zenodo"), None)
        credly = next((r for r in results if r["platform"] == "credly"), None)
        behance = next((r for r in results if r["platform"] == "behance"), None)
        dribbble = next((r for r in results if r["platform"] == "dribbble"), None)
        beacons = next((r for r in results if r["platform"] == "beacons"), None)
        bento = next((r for r in results if r["platform"] == "bento"), None)
        hoobe = next((r for r in results if r["platform"] == "hoobe"), None)
        carrd = next((r for r in results if r["platform"] == "carrd"), None)
        twitch = next((r for r in results if r["platform"] == "twitch"), None)
        unsplash = next((r for r in results if r["platform"] == "unsplash"), None)
        fivehundredpx = next((r for r in results if r["platform"] == "500px"), None)
        substack = next((r for r in results if r["platform"] == "substack"), None)
        speakerdeck = next((r for r in results if r["platform"] == "speakerdeck"), None)
        slideshare = next((r for r in results if r["platform"] == "slideshare"), None)
        soundcloud = next((r for r in results if r["platform"] == "soundcloud"), None)
        spotify = next((r for r in results if r["platform"] == "spotify"), None)
        strava = next((r for r in results if r["platform"] == "strava"), None)
        mixcloud = next((r for r in results if r["platform"] == "mixcloud"), None)
        letterboxd = next((r for r in results if r["platform"] == "letterboxd"), None)
        pinterest = next((r for r in results if r["platform"] == "pinterest"), None)
        quora = next((r for r in results if r["platform"] == "quora"), None)
        tryhackme = next((r for r in results if r["platform"] == "tryhackme"), None)
        yeswehack = next((r for r in results if r["platform"] == "yeswehack"), None)
        steam = next((r for r in results if r["platform"] == "steam"), None)

        assert bitbucket is not None
        assert bitbucket["profile_url"] == "https://bitbucket.org/acmebucket"
        assert bitbucket["username"] == "acmebucket"

        assert bugcrowd is not None
        assert bugcrowd["profile_url"] == "https://bugcrowd.com/acmebug"
        assert bugcrowd["username"] == "acmebug"

        assert github_sponsors is not None
        assert github_sponsors["profile_url"] == "https://github.com/sponsors/acmesponsor"
        assert github_sponsors["username"] == "acmesponsor"

        assert codeberg is not None
        assert codeberg["profile_url"] == "https://codeberg.org/acmeberg"
        assert codeberg["username"] == "acmeberg"

        assert hackerone is not None
        assert hackerone["profile_url"] == "https://hackerone.com/acmehacker"
        assert hackerone["username"] == "acmehacker"

        assert hashnode is not None
        assert hashnode["profile_url"] == "https://hashnode.com/@acmehash"
        assert hashnode["username"] == "acmehash"

        assert intigriti is not None
        assert intigriti["profile_url"] == "https://app.intigriti.com/researcher/profile/acmeintigriti"
        assert intigriti["username"] == "acmeintigriti"

        assert dockerhub is not None
        assert dockerhub["profile_url"] == "https://hub.docker.com/u/acmedocker"
        assert dockerhub["username"] == "acmedocker"

        assert sourcehut is not None
        assert sourcehut["profile_url"] == "https://sr.ht/~acmesrht"
        assert sourcehut["username"] == "acmesrht"

        assert snapchat is not None
        assert snapchat["profile_url"] == "https://www.snapchat.com/add/acmesnap"
        assert snapchat["username"] == "acmesnap"

        assert mastodon is not None
        assert mastodon["profile_url"] == "https://mastodon.social/@acmefed"
        assert mastodon["username"] == "acmefed"

        assert reddit is not None
        assert reddit["profile_url"] == "https://www.reddit.com/user/acmeredteam"
        assert reddit["username"] == "acmeredteam"

        assert replit is not None
        assert replit["profile_url"] == "https://replit.com/@acmerepl"
        assert replit["username"] == "acmerepl"

        assert codesandbox is not None
        assert codesandbox["profile_url"] == "https://codesandbox.io/u/acmesandbox"
        assert codesandbox["username"] == "acmesandbox"

        assert devpost is not None
        assert devpost["profile_url"] == "https://devpost.com/acmedevpost"
        assert devpost["username"] == "acmedevpost"

        assert readcv is not None
        assert readcv["profile_url"] == "https://read.cv/acmeread"
        assert readcv["username"] == "acmeread"

        assert telegram is not None
        assert telegram["profile_url"] == "https://t.me/acmetelegram"
        assert telegram["username"] == "acmetelegram"

        assert bluesky is not None
        assert bluesky["profile_url"] == "https://bsky.app/profile/acme.blue"
        assert bluesky["username"] == "acme.blue"

        assert youtube is not None
        assert youtube["profile_url"] == "https://www.youtube.com/@AcmeChannel"
        assert youtube["username"] == "AcmeChannel"

        assert npm is not None
        assert npm["profile_url"] == "https://www.npmjs.com/~acmenpm"
        assert npm["username"] == "acmenpm"

        assert pypi is not None
        assert pypi["profile_url"] == "https://pypi.org/user/acmepy/"
        assert pypi["username"] == "acmepy"

        assert rubygems is not None
        assert rubygems["profile_url"] == "https://rubygems.org/profiles/acmeruby"
        assert rubygems["username"] == "acmeruby"

        assert crates is not None
        assert crates["profile_url"] == "https://crates.io/users/acmecrates"
        assert crates["username"] == "acmecrates"

        assert packagist is not None
        assert packagist["profile_url"] == "https://packagist.org/users/acmepackagist"
        assert packagist["username"] == "acmepackagist"

        assert nuget is not None
        assert nuget["profile_url"] == "https://www.nuget.org/profiles/acmenuget"
        assert nuget["username"] == "acmenuget"

        assert openbugbounty is not None
        assert openbugbounty["profile_url"] == "https://www.openbugbounty.org/researchers/acmeobb/"
        assert openbugbounty["username"] == "acmeobb"

        assert hexpm is not None
        assert hexpm["profile_url"] == "https://hex.pm/users/acmehex"
        assert hexpm["username"] == "acmehex"

        assert stackoverflow is not None
        assert stackoverflow["profile_url"] == "https://stackoverflow.com/users/12345/acmestack"
        assert stackoverflow["username"] == "acmestack"

        assert huggingface is not None
        assert huggingface["profile_url"] == "https://huggingface.co/acmeml"
        assert huggingface["username"] == "acmeml"

        assert keybase is not None
        assert keybase["profile_url"] == "https://keybase.io/acmekeybase"
        assert keybase["username"] == "acmekeybase"

        assert medium is not None
        assert medium["profile_url"] == "https://bluewriter.medium.com/signal-boost"
        assert medium["username"] == "bluewriter"

        assert facebook is not None
        assert facebook["profile_url"] == "https://www.facebook.com/people/Acme-Facebook/1000123456789/"
        assert facebook["username"] == "Acme-Facebook"

        assert flickr is not None
        assert flickr["profile_url"] == "https://www.flickr.com/photos/acmeflickr/"
        assert flickr["username"] == "acmeflickr"

        assert vimeo is not None
        assert vimeo["profile_url"] == "https://vimeo.com/acmevideo"
        assert vimeo["username"] == "acmevideo"

        assert kaggle is not None
        assert kaggle["profile_url"] == "https://www.kaggle.com/acmekaggle"
        assert kaggle["username"] == "acmekaggle"

        assert lastfm is not None
        assert lastfm["profile_url"] == "https://www.last.fm/user/rj"
        assert lastfm["username"] == "rj"

        assert bandcamp is not None
        assert bandcamp["profile_url"] == "https://acmeband.bandcamp.com"
        assert bandcamp["username"] == "acmeband"

        assert linktree is not None
        assert linktree["profile_url"] == "https://linktr.ee/acmehub"
        assert linktree["username"] == "acmehub"
        assert allmylinks is not None
        assert allmylinks["profile_url"] == "https://allmylinks.com/acmeaml"
        assert allmylinks["username"] == "acmeaml"
        assert artstation is not None
        assert artstation["profile_url"] == "https://www.artstation.com/acmeartist"
        assert artstation["username"] == "acmeartist"
        assert deviantart is not None
        assert deviantart["profile_url"] == "https://www.deviantart.com/acmedeviant"
        assert deviantart["username"] == "acmedeviant"
        assert biosite is not None
        assert biosite["profile_url"] == "https://bio.site/acmebiosite"
        assert biosite["username"] == "acmebiosite"
        assert campsite is not None
        assert campsite["profile_url"] == "https://campsite.bio/acmecamp"
        assert campsite["username"] == "acmecamp"

        assert taplink is not None
        assert taplink["profile_url"] == "https://taplink.cc/acmetap"
        assert taplink["username"] == "acmetap"

        assert taplink_ws is not None
        assert taplink_ws["profile_url"] == "https://acmetapws.taplink.ws"
        assert taplink_ws["username"] == "acmetapws"

        assert milkshake is not None
        assert milkshake["profile_url"] == "https://msha.ke/go.milkshake"
        assert milkshake["username"] == "go.milkshake"

        assert opencollective is not None
        assert opencollective["profile_url"] == "https://opencollective.com/acmecollective"
        assert opencollective["username"] == "acmecollective"

        assert liberapay is not None
        assert liberapay["profile_url"] == "https://liberapay.com/acmelibera"
        assert liberapay["username"] == "acmelibera"

        assert patreon is not None
        assert patreon["profile_url"] == "https://www.patreon.com/acmepatron"
        assert patreon["username"] == "acmepatron"

        assert kofi is not None
        assert kofi["profile_url"] == "https://ko-fi.com/acmekofi"
        assert kofi["username"] == "acmekofi"

        assert buymeacoffee is not None
        assert buymeacoffee["profile_url"] == "https://www.buymeacoffee.com/acmecoffee"
        assert buymeacoffee["username"] == "acmecoffee"

        assert calendly is not None
        assert calendly["profile_url"] == "https://calendly.com/acmecalendly"
        assert calendly["username"] == "acmecalendly"

        assert calcom is not None
        assert calcom["profile_url"] == "https://cal.com/acmecal"
        assert calcom["username"] == "acmecal"

        assert producthunt is not None
        assert producthunt["profile_url"] == "https://www.producthunt.com/@acmebuilder"
        assert producthunt["username"] == "acmebuilder"

        assert wellfound is not None
        assert wellfound["profile_url"] == "https://wellfound.com/u/acmefounder"
        assert wellfound["username"] == "acmefounder"

        assert angellist is not None
        assert angellist["profile_url"] == "https://angel.co/u/acmeangel"
        assert angellist["username"] == "acmeangel"

        assert figma is not None
        assert figma["profile_url"] == "https://www.figma.com/@acmedesign"
        assert figma["username"] == "acmedesign"

        assert indiehackers is not None
        assert indiehackers["profile_url"] == "https://www.indiehackers.com/acmefounder"
        assert indiehackers["username"] == "acmefounder"

        assert polywork is not None
        assert polywork["profile_url"] == "https://www.polywork.com/acmeops"
        assert polywork["username"] == "acmeops"

        assert contra is not None
        assert contra["profile_url"] == "https://contra.com/acmeconsultant"
        assert contra["username"] == "acmeconsultant"

        assert adplist is not None
        assert adplist["profile_url"] == "https://adplist.org/mentors/acme-mentor"
        assert adplist["username"] == "acme-mentor"

        assert orcid is not None
        assert orcid["profile_url"] == "https://orcid.org/0000-0002-1825-0097"
        assert orcid["username"] == "0000-0002-1825-0097"

        assert researchgate is not None
        assert researchgate["profile_url"] == "https://www.researchgate.net/profile/Acme-Research"
        assert researchgate["username"] == "Acme-Research"

        assert google_scholar is not None
        assert google_scholar["profile_url"] == "https://scholar.google.com/citations?user=qc6CJjYAAAAJ"
        assert google_scholar["username"] == "qc6CJjYAAAAJ"

        assert gravatar is not None
        assert gravatar["profile_url"] == "https://gravatar.com/acmeavatar"
        assert gravatar["username"] == "acmeavatar"

        assert academia is not None
        assert academia["profile_url"] == "https://www.academia.edu/AcmeAcademic"
        assert academia["username"] == "AcmeAcademic"

        assert zenodo is not None
        assert zenodo["profile_url"] == "https://zenodo.org/users/acmezenodo"
        assert zenodo["username"] == "acmezenodo"

        assert credly is not None
        assert credly["profile_url"] == "https://www.credly.com/users/acme-ops"
        assert credly["username"] == "acme-ops"

        assert behance is not None
        assert behance["profile_url"] == "https://www.behance.net/acmecreative"
        assert behance["username"] == "acmecreative"

        assert dribbble is not None
        assert dribbble["profile_url"] == "https://dribbble.com/acmedesign"
        assert dribbble["username"] == "acmedesign"

        assert beacons is not None
        assert beacons["profile_url"] == "https://beacons.ai/acmebeacon"
        assert beacons["username"] == "acmebeacon"

        assert bento is not None
        assert bento["profile_url"] == "https://bento.me/acmebento"
        assert bento["username"] == "acmebento"

        assert hoobe is not None
        assert hoobe["profile_url"] == "https://hoo.be/acmehoo"
        assert hoobe["username"] == "acmehoo"

        assert carrd is not None
        assert carrd["profile_url"] == "https://acmecard.carrd.co"
        assert carrd["username"] == "acmecard"

        assert twitch is not None
        assert twitch["profile_url"] == "https://www.twitch.tv/acmestream"
        assert twitch["username"] == "acmestream"

        assert unsplash is not None
        assert unsplash["profile_url"] == "https://unsplash.com/@acmephotos"
        assert unsplash["username"] == "acmephotos"

        assert fivehundredpx is not None
        assert fivehundredpx["profile_url"] == "https://500px.com/p/acme500"
        assert fivehundredpx["username"] == "acme500"

        assert substack is not None
        assert substack["profile_url"] == "https://acmenotes.substack.com"
        assert substack["username"] == "acmenotes"

        assert speakerdeck is not None
        assert speakerdeck["profile_url"] == "https://speakerdeck.com/acmespeaker"
        assert speakerdeck["username"] == "acmespeaker"

        assert slideshare is not None
        assert slideshare["profile_url"] == "https://www.slideshare.net/acmeslides"
        assert slideshare["username"] == "acmeslides"

        assert soundcloud is not None
        assert soundcloud["profile_url"] == "https://soundcloud.com/acmesound"
        assert soundcloud["username"] == "acmesound"

        assert spotify is not None
        assert spotify["profile_url"] == "https://open.spotify.com/user/acmespotify"
        assert spotify["username"] == "acmespotify"

        assert strava is not None
        assert strava["profile_url"] == "https://www.strava.com/athletes/12345678"
        assert strava["username"] == "12345678"

        assert mixcloud is not None
        assert mixcloud["profile_url"] == "https://www.mixcloud.com/acmemix/"
        assert mixcloud["username"] == "acmemix"

        assert letterboxd is not None
        assert letterboxd["profile_url"] == "https://letterboxd.com/acmefilm/"
        assert letterboxd["username"] == "acmefilm"

        assert pinterest is not None
        assert pinterest["profile_url"] == "https://www.pinterest.com/acmepins/"
        assert pinterest["username"] == "acmepins"

        assert quora is not None
        assert quora["profile_url"] == "https://www.quora.com/profile/Acme-Quora-1"
        assert quora["username"] == "Acme-Quora-1"

        assert tryhackme is not None
        assert tryhackme["profile_url"] == "https://tryhackme.com/p/acmethm"
        assert tryhackme["username"] == "acmethm"

        assert yeswehack is not None
        assert yeswehack["profile_url"] == "https://yeswehack.com/hunters/acmeywh"
        assert yeswehack["username"] == "acmeywh"

        assert steam is not None
        assert steam["profile_url"] == "https://steamcommunity.com/id/acmesteam"
        assert steam["username"] == "acmesteam"
        reserved_security_direct_results = _parse_epieos_response(
            {
                "email": "alice@example.com",
                "bugcrowd": {"username": "directory", "name": "Reserved Bugcrowd route"},
                "hackerone": {"username": "programs", "name": "Reserved HackerOne route"},
                "intigriti": {"username": "programs", "name": "Reserved Intigriti route"},
                "dockerhub": {"namespace": "library", "name": "Reserved Docker Hub namespace"},
                "sourcehut": {"handle": "projects", "name": "Reserved SourceHut route"},
                "reddit": {"username": "popular", "name": "Reserved Reddit route"},
                "replit": {"username": "templates", "name": "Reserved Replit route"},
                "codesandbox": {"username": "templates", "name": "Reserved CodeSandbox route"},
                "devpost": {"username": "hackathons", "name": "Reserved Devpost route"},
                "readcv": {"username": "explore", "name": "Reserved Read.cv route"},
                "kaggle": {"username": "competitions", "name": "Reserved Kaggle route"},
                "twitch": {"username": "directory", "name": "Reserved Twitch route"},
                "unsplash": {"username": "photos", "name": "Reserved Unsplash route"},
                "500px": {"username": "popular", "name": "Reserved 500px route"},
                "pinterest": {"username": "pin", "name": "Reserved Pinterest route"},
                "quora": {"username": "spaces", "name": "Reserved Quora route"},
                "tryhackme": {"username": "room", "name": "Reserved TryHackMe route"},
                "yeswehack": {"username": "programs", "name": "Reserved YesWeHack route"},
                "snapchat": {"username": "discover", "name": "Reserved Snapchat route"},
                "steam": {"username": "app", "name": "Reserved Steam route"},
                "gravatar": {"username": "avatar", "name": "Reserved Gravatar route"},
                "gravatar_hash": {
                    "platform": "gravatar",
                    "username": "5f4dcc3b5aa765d61d8327deb882cf99",
                    "name": "Hash endpoint",
                },
            }
        )
        assert reserved_security_direct_results == []

    def test_explicit_profile_urls_reuse_recursive_handle_rules_and_skip_reserved_routes(self):
        results = _parse_epieos_response(
            {
                "email": "alice@example.com",
                "twitter": {
                    "profile_url": "https://x.com/intent/user?screen_name=acmeops",
                    "name": "Acme Ops",
                },
                "github": {
                    "profile_url": "https://github.com/settings/profile",
                },
                "github_sponsors": {
                    "profile_url": "https://github.com/sponsors/explore",
                },
                "github_sponsors_user": {
                    "platform": "github_sponsors",
                    "profile_url": "https://github.com/sponsors/acmesponsor",
                },
                "bugcrowd": {
                    "url": "https://bugcrowd.com/directory",
                },
                "hackerone": {
                    "url": "https://hackerone.com/programs",
                },
                "hashnode_reserved": {
                    "platform": "hashnode",
                    "url": "https://hashnode.com/explore",
                },
                "hashnode_user": {
                    "platform": "hashnode",
                    "url": "https://hashnode.com/@acmehash/articles/one",
                },
                "mastodon_online_user": {
                    "platform": "mastodon",
                    "url": "https://mastodon.online/@acmeonline/112233",
                },
                "mastodon_masto_reserved": {
                    "platform": "mastodon",
                    "url": "https://mastodon.online/about",
                },
                "mastodon_custom_user": {
                    "platform": "mastodon",
                    "url": "https://chaos.social/@acmechaos/112233",
                },
                "mastodon_custom_users_route": {
                    "platform": "mastodon",
                    "url": "https://techhub.social/users/acmetech",
                },
                "mastodon_unlisted_custom_user": {
                    "platform": "mastodon",
                    "url": "https://social.example.net/@acmefediverse/112233",
                },
                "mastodon_custom_reserved": {
                    "platform": "mastodon",
                    "url": "https://social.coop/about",
                },
                "intigriti": {
                    "url": "https://app.intigriti.com/programs/acme/detail",
                },
                "intigriti_user": {
                    "platform": "intigriti",
                    "url": "https://app.intigriti.com/researcher/profile/acmeintigriti/activity",
                },
                "intigriti_legacy_user": {
                    "platform": "intigriti",
                    "url": "https://app.intigriti.com/profile/legacyintigriti",
                },
                "medium": {
                    "url": "https://medium.com/topic/security",
                },
                "kaggle": {
                    "url": "https://www.kaggle.com/competitions",
                },
                "kaggle_user": {
                    "platform": "kaggle",
                    "url": "https://www.kaggle.com/acmekaggle/code",
                },
                "lastfm": {
                    "url": "https://www.last.fm/music/Acme",
                },
                "lastfm_user": {
                    "platform": "lastfm",
                    "url": "https://www.last.fm/user/rj/library",
                },
                "bandcamp": {
                    "url": "https://bandcamp.com/discover",
                },
                "bandcamp_fan": {
                    "platform": "bandcamp",
                    "url": "https://bandcamp.com/acmefan/collection",
                },
                "bandcamp_artist": {
                    "platform": "bandcamp",
                    "url": "https://acmeband.bandcamp.com/album/security-briefing",
                },
                "bandcamp_reserved_subdomain": {
                    "platform": "bandcamp",
                    "url": "https://daily.bandcamp.com/features/security",
                },
                "flickr": {
                    "url": "https://www.flickr.com/photos/tags/security/",
                },
                "flickr_user": {
                    "platform": "flickr",
                    "url": "https://www.flickr.com/photos/acmeflickr/1234567890/",
                },
                "vimeo": {
                    "url": "https://vimeo.com/123456789",
                },
                "vimeo_reserved": {
                    "platform": "vimeo",
                    "url": "https://vimeo.com/channels/staffpicks",
                },
                "vimeo_user": {
                    "platform": "vimeo",
                    "url": "https://vimeo.com/acmevideo/securitybriefing",
                },
                "npm": {
                    "url": "https://www.npmjs.com/package/acme-package",
                },
                "rubygems": {
                    "url": "https://rubygems.org/gems/not-a-profile",
                },
                "rubygems_user": {
                    "platform": "rubygems",
                    "url": "https://rubygems.org/profiles/acmeruby",
                },
                "crates": {
                    "url": "https://crates.io/crates/not-a-profile",
                },
                "crates_user": {
                    "platform": "crates",
                    "url": "https://crates.io/users/acmecrates",
                },
                "packagist": {
                    "url": "https://packagist.org/packages/acme/package",
                },
                "packagist_user": {
                    "platform": "packagist",
                    "url": "https://packagist.org/users/acmepackagist",
                },
                "nuget": {
                    "url": "https://www.nuget.org/packages/not-a-profile",
                },
                "nuget_user": {
                    "platform": "nuget",
                    "url": "https://www.nuget.org/profiles/acmenuget",
                },
                "openbugbounty": {
                    "url": "https://www.openbugbounty.org/faq/",
                },
                "openbugbounty_user": {
                    "platform": "openbugbounty",
                    "url": "https://www.openbugbounty.org/researchers/acmeobb/",
                },
                "hexpm": {
                    "url": "https://hex.pm/packages/not-a-profile",
                },
                "hexpm_user": {
                    "platform": "hexpm",
                    "url": "https://hex.pm/users/acmehex",
                },
                "huggingface": {
                    "url": "https://huggingface.co/acmeml/model-one",
                },
                "codeberg": {
                    "url": "https://codeberg.org/explore/repos",
                },
                "sourcehut": {
                    "url": "https://git.sr.ht/~acmesrht/project",
                },
                "sourcehut_reserved": {
                    "platform": "sourcehut",
                    "url": "https://sr.ht/projects",
                },
                "snapchat": {
                    "url": "https://www.snapchat.com/discover",
                },
                "snapchat_user": {
                    "platform": "snapchat",
                    "url": "https://www.snapchat.com/add/acmesnap",
                },
                "snapchat_root": {
                    "platform": "snapchat",
                    "url": "https://www.snapchat.com/",
                },
                "telegram": {
                    "platform": "telegram",
                    "url": "https://t.me/share/url?url=https%3A%2F%2Facme.example",
                },
                "telegram_reserved_handle": {
                    "platform": "telegram",
                    "username": "joinchat",
                },
                "telegram_user": {
                    "platform": "telegram",
                    "url": "https://t.me/acmetelegram",
                },
                "keybase": {
                    "platform": "keybase",
                    "url": "https://keybase.io/team/acme",
                },
                "keybase_reserved_handle": {
                    "platform": "keybase",
                    "username": "team",
                },
                "keybase_user": {
                    "platform": "keybase",
                    "url": "https://keybase.io/acmekeybase",
                },
                "dockerhub": {
                    "url": "https://hub.docker.com/r/acmedocker/api",
                },
                "dockerhub_reserved": {
                    "url": "https://hub.docker.com/search?q=security",
                },
                "dockerhub_library": {
                    "url": "https://hub.docker.com/r/library/nginx",
                },
                "instagram_story": {
                    "url": "https://www.instagram.com/stories/acmegram/123456/",
                },
                "instagram_reels": {
                    "url": "https://www.instagram.com/reels/audio/123456/",
                },
                "replit_reserved": {
                    "platform": "replit",
                    "url": "https://replit.com/templates",
                },
                "replit_user": {
                    "platform": "replit",
                    "url": "https://replit.com/@acmerepl/security-lab",
                },
                "codesandbox_reserved": {
                    "platform": "codesandbox",
                    "url": "https://codesandbox.io/s/example",
                },
                "codesandbox_user": {
                    "platform": "codesandbox",
                    "url": "https://codesandbox.io/u/acmesandbox/sandboxes",
                },
                "devpost_reserved": {
                    "platform": "devpost",
                    "url": "https://devpost.com/hackathons",
                },
                "devpost_user": {
                    "platform": "devpost",
                    "url": "https://devpost.com/acmedevpost",
                },
                "readcv_reserved": {
                    "platform": "readcv",
                    "url": "https://read.cv/jobs",
                },
                "readcv_user": {
                    "platform": "readcv",
                    "url": "https://read.cv/acmeread",
                },
                "twitch": {
                    "url": "https://www.twitch.tv/directory/category/security",
                },
                "substack": {
                    "url": "https://substack.com/home",
                },
                "speakerdeck": {
                    "url": "https://speakerdeck.com/explore",
                },
                "speakerdeck_user": {
                    "platform": "speakerdeck",
                    "url": "https://speakerdeck.com/acmespeaker/security-briefing",
                },
                "slideshare": {
                    "url": "https://www.slideshare.net/category/technology",
                },
                "slideshare_user": {
                    "platform": "slideshare",
                    "url": "https://www.slideshare.net/acmeslides/security-briefing",
                },
                "soundcloud": {
                    "url": "https://soundcloud.com/discover",
                },
                "soundcloud_user": {
                    "platform": "soundcloud",
                    "url": "https://soundcloud.com/acmesound/security-briefing",
                },
                "mixcloud": {
                    "url": "https://www.mixcloud.com/discover/electronic/",
                },
                "mixcloud_settings": {
                    "platform": "mixcloud",
                    "url": "https://www.mixcloud.com/settings/account/",
                },
                "mixcloud_user": {
                    "platform": "mixcloud",
                    "url": "https://www.mixcloud.com/acmemix/security-briefing/",
                },
                "letterboxd": {
                    "url": "https://letterboxd.com/film/security-briefing/",
                },
                "letterboxd_search": {
                    "platform": "letterboxd",
                    "url": "https://letterboxd.com/search/security/",
                },
                "letterboxd_user": {
                    "platform": "letterboxd",
                    "url": "https://letterboxd.com/acmefilm/films/reviews/",
                },
                "pinterest": {
                    "url": "https://www.pinterest.com/pin/1234567890/",
                },
                "pinterest_numeric": {
                    "platform": "pinterest",
                    "url": "https://www.pinterest.com/123456789/",
                },
                "pinterest_user": {
                    "platform": "pinterest",
                    "url": "https://www.pinterest.com/acmepins/security-briefing/",
                },
                "tryhackme": {
                    "url": "https://tryhackme.com/room/profilesroom",
                },
                "tryhackme_user": {
                    "platform": "tryhackme",
                    "url": "https://tryhackme.com/p/acmethm",
                },
                "yeswehack": {
                    "url": "https://yeswehack.com/programs/acme",
                },
                "yeswehack_user": {
                    "platform": "yeswehack",
                    "url": "https://yeswehack.com/hunters/acmeywh",
                },
                "steam": {
                    "url": "https://steamcommunity.com/app/730",
                },
                "steam_profile_id": {
                    "platform": "steam",
                    "url": "https://steamcommunity.com/profiles/76561198000000000",
                },
                "steam_user": {
                    "platform": "steam",
                    "url": "https://steamcommunity.com/id/acmesteam",
                },
                "opencollective": {
                    "url": "https://opencollective.com/discover",
                },
                "opencollective_user": {
                    "platform": "opencollective",
                    "url": "https://opencollective.com/acmecollective",
                },
                "liberapay": {
                    "url": "https://liberapay.com/explore",
                },
                "liberapay_user": {
                    "platform": "liberapay",
                    "url": "https://liberapay.com/acmelibera/",
                },
                "calendly": {
                    "url": "https://calendly.com/pricing",
                },
                "calcom": {
                    "url": "https://cal.com/apps",
                },
                "producthunt": {
                    "url": "https://www.producthunt.com/products/acme",
                },
                "producthunt_user": {
                    "url": "https://www.producthunt.com/users/acmebuilder",
                },
                "wellfound": {
                    "url": "https://wellfound.com/company/acme",
                },
                "angellist": {
                    "url": "https://angel.co/company/acme",
                },
                "orcid": {
                    "url": "https://orcid.org/signin",
                },
                "researchgate": {
                    "url": "https://www.researchgate.net/publication/123",
                },
                "credly": {
                    "url": "https://www.credly.com/badges/abcd",
                },
                "behance": {
                    "url": "https://www.behance.net/galleries",
                },
                "dribbble": {
                    "url": "https://dribbble.com/shots/popular",
                },
                "patreon": {
                    "url": "https://www.patreon.com/join",
                },
                "patreon_creator": {
                    "platform": "patreon",
                    "url": "https://www.patreon.com/c/acmepatron",
                },
                "kofi": {
                    "url": "https://ko-fi.com/home",
                },
                "buymeacoffee": {
                    "url": "https://www.buymeacoffee.com/explore",
                },
            }
        )

        twitter = next((r for r in results if r["platform"] == "twitter"), None)
        github = next((r for r in results if r["platform"] == "github"), None)
        github_sponsors = next((r for r in results if r["platform"] == "github_sponsors"), None)
        github_sponsors_user = next((r for r in results if r["platform"] == "github_sponsors_user"), None)
        bugcrowd = next((r for r in results if r["platform"] == "bugcrowd"), None)
        hackerone = next((r for r in results if r["platform"] == "hackerone"), None)
        hashnode_reserved = next((r for r in results if r["platform"] == "hashnode_reserved"), None)
        hashnode_user = next((r for r in results if r["platform"] == "hashnode_user"), None)
        mastodon_online_user = next((r for r in results if r["platform"] == "mastodon_online_user"), None)
        mastodon_masto_reserved = next((r for r in results if r["platform"] == "mastodon_masto_reserved"), None)
        mastodon_custom_user = next((r for r in results if r["platform"] == "mastodon_custom_user"), None)
        mastodon_custom_users_route = next(
            (r for r in results if r["platform"] == "mastodon_custom_users_route"),
            None,
        )
        mastodon_unlisted_custom_user = next(
            (r for r in results if r["platform"] == "mastodon_unlisted_custom_user"),
            None,
        )
        mastodon_custom_reserved = next(
            (r for r in results if r["platform"] == "mastodon_custom_reserved"),
            None,
        )
        intigriti = next((r for r in results if r["platform"] == "intigriti"), None)
        intigriti_user = next((r for r in results if r["platform"] == "intigriti_user"), None)
        intigriti_legacy_user = next(
            (r for r in results if r["platform"] == "intigriti_legacy_user"),
            None,
        )
        medium = next((r for r in results if r["platform"] == "medium"), None)
        kaggle = next((r for r in results if r["platform"] == "kaggle"), None)
        kaggle_user = next((r for r in results if r["platform"] == "kaggle_user"), None)
        lastfm = next((r for r in results if r["platform"] == "lastfm"), None)
        lastfm_user = next((r for r in results if r["platform"] == "lastfm_user"), None)
        bandcamp = next((r for r in results if r["platform"] == "bandcamp"), None)
        bandcamp_fan = next((r for r in results if r["platform"] == "bandcamp_fan"), None)
        bandcamp_artist = next((r for r in results if r["platform"] == "bandcamp_artist"), None)
        bandcamp_reserved_subdomain = next(
            (r for r in results if r["platform"] == "bandcamp_reserved_subdomain"),
            None,
        )
        flickr = next((r for r in results if r["platform"] == "flickr"), None)
        flickr_user = next((r for r in results if r["platform"] == "flickr_user"), None)
        vimeo = next((r for r in results if r["platform"] == "vimeo"), None)
        vimeo_reserved = next((r for r in results if r["platform"] == "vimeo_reserved"), None)
        vimeo_user = next((r for r in results if r["platform"] == "vimeo_user"), None)
        npm = next((r for r in results if r["platform"] == "npm"), None)
        rubygems = next((r for r in results if r["platform"] == "rubygems"), None)
        rubygems_user = next((r for r in results if r["platform"] == "rubygems_user"), None)
        crates = next((r for r in results if r["platform"] == "crates"), None)
        crates_user = next((r for r in results if r["platform"] == "crates_user"), None)
        packagist = next((r for r in results if r["platform"] == "packagist"), None)
        packagist_user = next((r for r in results if r["platform"] == "packagist_user"), None)
        nuget = next((r for r in results if r["platform"] == "nuget"), None)
        nuget_user = next((r for r in results if r["platform"] == "nuget_user"), None)
        openbugbounty = next((r for r in results if r["platform"] == "openbugbounty"), None)
        openbugbounty_user = next((r for r in results if r["platform"] == "openbugbounty_user"), None)
        hexpm = next((r for r in results if r["platform"] == "hexpm"), None)
        hexpm_user = next((r for r in results if r["platform"] == "hexpm_user"), None)
        huggingface = next((r for r in results if r["platform"] == "huggingface"), None)
        codeberg = next((r for r in results if r["platform"] == "codeberg"), None)
        sourcehut = next((r for r in results if r["platform"] == "sourcehut"), None)
        sourcehut_reserved = next((r for r in results if r["platform"] == "sourcehut_reserved"), None)
        snapchat = next((r for r in results if r["platform"] == "snapchat"), None)
        snapchat_user = next((r for r in results if r["platform"] == "snapchat_user"), None)
        snapchat_root = next((r for r in results if r["platform"] == "snapchat_root"), None)
        telegram = next((r for r in results if r["platform"] == "telegram"), None)
        telegram_reserved_handle = next(
            (r for r in results if r["platform"] == "telegram_reserved_handle"),
            None,
        )
        telegram_user = next((r for r in results if r["platform"] == "telegram_user"), None)
        keybase = next((r for r in results if r["platform"] == "keybase"), None)
        keybase_reserved_handle = next(
            (r for r in results if r["platform"] == "keybase_reserved_handle"),
            None,
        )
        keybase_user = next((r for r in results if r["platform"] == "keybase_user"), None)
        dockerhub = next((r for r in results if r["platform"] == "dockerhub"), None)
        dockerhub_reserved = next((r for r in results if r["platform"] == "dockerhub_reserved"), None)
        dockerhub_library = next((r for r in results if r["platform"] == "dockerhub_library"), None)
        instagram_story = next((r for r in results if r["platform"] == "instagram_story"), None)
        instagram_reels = next((r for r in results if r["platform"] == "instagram_reels"), None)
        replit_reserved = next((r for r in results if r["platform"] == "replit_reserved"), None)
        replit_user = next((r for r in results if r["platform"] == "replit_user"), None)
        codesandbox_reserved = next((r for r in results if r["platform"] == "codesandbox_reserved"), None)
        codesandbox_user = next((r for r in results if r["platform"] == "codesandbox_user"), None)
        devpost_reserved = next((r for r in results if r["platform"] == "devpost_reserved"), None)
        devpost_user = next((r for r in results if r["platform"] == "devpost_user"), None)
        readcv_reserved = next((r for r in results if r["platform"] == "readcv_reserved"), None)
        readcv_user = next((r for r in results if r["platform"] == "readcv_user"), None)
        twitch = next((r for r in results if r["platform"] == "twitch"), None)
        substack = next((r for r in results if r["platform"] == "substack"), None)
        speakerdeck = next((r for r in results if r["platform"] == "speakerdeck"), None)
        speakerdeck_user = next((r for r in results if r["platform"] == "speakerdeck_user"), None)
        slideshare = next((r for r in results if r["platform"] == "slideshare"), None)
        slideshare_user = next((r for r in results if r["platform"] == "slideshare_user"), None)
        soundcloud = next((r for r in results if r["platform"] == "soundcloud"), None)
        soundcloud_user = next((r for r in results if r["platform"] == "soundcloud_user"), None)
        mixcloud = next((r for r in results if r["platform"] == "mixcloud"), None)
        mixcloud_settings = next((r for r in results if r["platform"] == "mixcloud_settings"), None)
        mixcloud_user = next((r for r in results if r["platform"] == "mixcloud_user"), None)
        letterboxd = next((r for r in results if r["platform"] == "letterboxd"), None)
        letterboxd_search = next((r for r in results if r["platform"] == "letterboxd_search"), None)
        letterboxd_user = next((r for r in results if r["platform"] == "letterboxd_user"), None)
        pinterest = next((r for r in results if r["platform"] == "pinterest"), None)
        pinterest_numeric = next((r for r in results if r["platform"] == "pinterest_numeric"), None)
        pinterest_user = next((r for r in results if r["platform"] == "pinterest_user"), None)
        tryhackme = next((r for r in results if r["platform"] == "tryhackme"), None)
        tryhackme_user = next((r for r in results if r["platform"] == "tryhackme_user"), None)
        yeswehack = next((r for r in results if r["platform"] == "yeswehack"), None)
        yeswehack_user = next((r for r in results if r["platform"] == "yeswehack_user"), None)
        steam = next((r for r in results if r["platform"] == "steam"), None)
        steam_profile_id = next((r for r in results if r["platform"] == "steam_profile_id"), None)
        steam_user = next((r for r in results if r["platform"] == "steam_user"), None)
        opencollective = next((r for r in results if r["platform"] == "opencollective"), None)
        opencollective_user = next((r for r in results if r["platform"] == "opencollective_user"), None)
        liberapay = next((r for r in results if r["platform"] == "liberapay"), None)
        liberapay_user = next((r for r in results if r["platform"] == "liberapay_user"), None)
        calendly = next((r for r in results if r["platform"] == "calendly"), None)
        calcom = next((r for r in results if r["platform"] == "calcom"), None)
        producthunt = next((r for r in results if r["platform"] == "producthunt"), None)
        producthunt_user = next((r for r in results if r["platform"] == "producthunt_user"), None)
        wellfound = next((r for r in results if r["platform"] == "wellfound"), None)
        angellist = next((r for r in results if r["platform"] == "angellist"), None)
        orcid = next((r for r in results if r["platform"] == "orcid"), None)
        researchgate = next((r for r in results if r["platform"] == "researchgate"), None)
        credly = next((r for r in results if r["platform"] == "credly"), None)
        behance = next((r for r in results if r["platform"] == "behance"), None)
        dribbble = next((r for r in results if r["platform"] == "dribbble"), None)
        patreon = next((r for r in results if r["platform"] == "patreon"), None)
        patreon_creator = next((r for r in results if r["platform"] == "patreon_creator"), None)
        kofi = next((r for r in results if r["platform"] == "kofi"), None)
        buymeacoffee = next((r for r in results if r["platform"] == "buymeacoffee"), None)

        assert twitter is not None
        assert twitter["profile_url"] == "https://x.com/intent/user?screen_name=acmeops"
        assert twitter["username"] == "acmeops"

        assert github is not None
        assert github["profile_url"] == "https://github.com/settings/profile"
        assert "username" not in github
        assert github_sponsors is not None
        assert "username" not in github_sponsors
        assert github_sponsors_user is not None
        assert github_sponsors_user["username"] == "acmesponsor"

        assert bugcrowd is not None
        assert "username" not in bugcrowd
        assert hackerone is not None
        assert "username" not in hackerone
        assert hashnode_reserved is not None
        assert "username" not in hashnode_reserved
        assert hashnode_user is not None
        assert hashnode_user["username"] == "acmehash"
        assert mastodon_online_user is not None
        assert mastodon_online_user["username"] == "acmeonline"
        assert mastodon_masto_reserved is not None
        assert "username" not in mastodon_masto_reserved
        assert mastodon_custom_user is not None
        assert mastodon_custom_user["username"] == "acmechaos"
        assert mastodon_custom_users_route is not None
        assert mastodon_custom_users_route["username"] == "acmetech"
        assert mastodon_unlisted_custom_user is not None
        assert mastodon_unlisted_custom_user["username"] == "acmefediverse"
        assert mastodon_custom_reserved is not None
        assert "username" not in mastodon_custom_reserved
        assert intigriti is not None
        assert "username" not in intigriti
        assert intigriti_user is not None
        assert intigriti_user["username"] == "acmeintigriti"
        assert intigriti_legacy_user is not None
        assert intigriti_legacy_user["username"] == "legacyintigriti"

        assert medium is not None
        assert medium["profile_url"] == "https://medium.com/topic/security"
        assert "username" not in medium
        assert kaggle is not None
        assert "username" not in kaggle
        assert kaggle_user is not None
        assert kaggle_user["username"] == "acmekaggle"
        assert lastfm is not None
        assert "username" not in lastfm
        assert lastfm_user is not None
        assert lastfm_user["username"] == "rj"
        assert bandcamp is not None
        assert "username" not in bandcamp
        assert bandcamp_fan is not None
        assert bandcamp_fan["username"] == "acmefan"
        assert bandcamp_artist is not None
        assert bandcamp_artist["username"] == "acmeband"
        assert bandcamp_reserved_subdomain is not None
        assert "username" not in bandcamp_reserved_subdomain
        assert flickr is not None
        assert "username" not in flickr
        assert flickr_user is not None
        assert flickr_user["username"] == "acmeflickr"
        assert vimeo is not None
        assert "username" not in vimeo
        assert vimeo_reserved is not None
        assert "username" not in vimeo_reserved
        assert vimeo_user is not None
        assert vimeo_user["username"] == "acmevideo"
        assert npm is not None
        assert "username" not in npm
        assert rubygems is not None
        assert "username" not in rubygems
        assert rubygems_user is not None
        assert rubygems_user["username"] == "acmeruby"
        assert crates is not None
        assert "username" not in crates
        assert crates_user is not None
        assert crates_user["username"] == "acmecrates"
        assert packagist is not None
        assert "username" not in packagist
        assert packagist_user is not None
        assert packagist_user["username"] == "acmepackagist"
        assert nuget is not None
        assert "username" not in nuget
        assert nuget_user is not None
        assert nuget_user["username"] == "acmenuget"
        assert openbugbounty is not None
        assert "username" not in openbugbounty
        assert openbugbounty_user is not None
        assert openbugbounty_user["username"] == "acmeobb"
        assert hexpm is not None
        assert "username" not in hexpm
        assert hexpm_user is not None
        assert hexpm_user["username"] == "acmehex"
        assert huggingface is not None
        assert "username" not in huggingface
        assert codeberg is not None
        assert "username" not in codeberg
        assert sourcehut is not None
        assert sourcehut["username"] == "acmesrht"
        assert sourcehut_reserved is not None
        assert "username" not in sourcehut_reserved
        assert snapchat is not None
        assert "username" not in snapchat
        assert snapchat_user is not None
        assert snapchat_user["username"] == "acmesnap"
        assert snapchat_root is not None
        assert "username" not in snapchat_root
        assert telegram is not None
        assert "username" not in telegram
        assert telegram_reserved_handle is None
        assert telegram_user is not None
        assert telegram_user["username"] == "acmetelegram"
        assert keybase is not None
        assert "username" not in keybase
        assert keybase_reserved_handle is None
        assert keybase_user is not None
        assert keybase_user["username"] == "acmekeybase"
        assert dockerhub is not None
        assert dockerhub["username"] == "acmedocker"
        assert dockerhub_reserved is not None
        assert "username" not in dockerhub_reserved
        assert dockerhub_library is not None
        assert "username" not in dockerhub_library
        assert instagram_story is not None
        assert instagram_story["username"] == "acmegram"
        assert instagram_reels is not None
        assert "username" not in instagram_reels
        assert replit_reserved is not None
        assert "username" not in replit_reserved
        assert replit_user is not None
        assert replit_user["username"] == "acmerepl"
        assert codesandbox_reserved is not None
        assert "username" not in codesandbox_reserved
        assert codesandbox_user is not None
        assert codesandbox_user["username"] == "acmesandbox"
        assert devpost_reserved is not None
        assert "username" not in devpost_reserved
        assert devpost_user is not None
        assert devpost_user["username"] == "acmedevpost"
        assert readcv_reserved is not None
        assert "username" not in readcv_reserved
        assert readcv_user is not None
        assert readcv_user["username"] == "acmeread"
        assert twitch is not None
        assert "username" not in twitch
        assert substack is not None
        assert "username" not in substack
        assert speakerdeck is not None
        assert "username" not in speakerdeck
        assert speakerdeck_user is not None
        assert speakerdeck_user["username"] == "acmespeaker"
        assert slideshare is not None
        assert "username" not in slideshare
        assert slideshare_user is not None
        assert slideshare_user["username"] == "acmeslides"
        assert soundcloud is not None
        assert "username" not in soundcloud
        assert soundcloud_user is not None
        assert soundcloud_user["username"] == "acmesound"
        assert mixcloud is not None
        assert "username" not in mixcloud
        assert mixcloud_settings is not None
        assert "username" not in mixcloud_settings
        assert mixcloud_user is not None
        assert mixcloud_user["username"] == "acmemix"
        assert letterboxd is not None
        assert "username" not in letterboxd
        assert letterboxd_search is not None
        assert "username" not in letterboxd_search
        assert letterboxd_user is not None
        assert letterboxd_user["username"] == "acmefilm"
        assert pinterest is not None
        assert "username" not in pinterest
        assert pinterest_numeric is not None
        assert "username" not in pinterest_numeric
        assert pinterest_user is not None
        assert pinterest_user["username"] == "acmepins"
        assert tryhackme is not None
        assert "username" not in tryhackme
        assert tryhackme_user is not None
        assert tryhackme_user["username"] == "acmethm"
        assert yeswehack is not None
        assert "username" not in yeswehack
        assert yeswehack_user is not None
        assert yeswehack_user["username"] == "acmeywh"
        assert steam is not None
        assert "username" not in steam
        assert steam_profile_id is not None
        assert "username" not in steam_profile_id
        assert steam_user is not None
        assert steam_user["username"] == "acmesteam"
        assert opencollective is not None
        assert "username" not in opencollective
        assert opencollective_user is not None
        assert opencollective_user["username"] == "acmecollective"
        assert liberapay is not None
        assert "username" not in liberapay
        assert liberapay_user is not None
        assert liberapay_user["username"] == "acmelibera"
        assert calendly is not None
        assert "username" not in calendly
        assert calcom is not None
        assert "username" not in calcom
        assert producthunt is not None
        assert "username" not in producthunt
        assert producthunt_user is not None
        assert producthunt_user["username"] == "acmebuilder"
        assert wellfound is not None
        assert "username" not in wellfound
        assert wellfound["company_name"] == "Acme"
        assert angellist is not None
        assert "username" not in angellist
        assert angellist["company_name"] == "Acme"
        assert orcid is not None
        assert "username" not in orcid
        assert researchgate is not None
        assert "username" not in researchgate
        assert credly is not None
        assert "username" not in credly
        assert behance is not None
        assert "username" not in behance
        assert dribbble is not None
        assert "username" not in dribbble
        assert patreon is not None
        assert "username" not in patreon
        assert patreon_creator is not None
        assert patreon_creator["username"] == "acmepatron"
        assert kofi is not None
        assert "username" not in kofi
        assert buymeacoffee is not None
        assert "username" not in buymeacoffee

    def test_direct_handle_fields_are_normalized_before_profile_url_construction(self):
        results = _parse_epieos_response(
            {
                "email": "alice@example.com",
                "github": {
                    "custom_url": "https://github.com/acmeurl",
                },
                "twitter": {
                    "username": "alice@example.com",
                    "url": "https://x.com/acmeops",
                },
                "youtube": {
                    "channel_id": "UC1234567890123456789012",
                },
            }
        )

        github = next((r for r in results if r["platform"] == "github"), None)
        twitter = next((r for r in results if r["platform"] == "twitter"), None)
        youtube = next((r for r in results if r["platform"] == "youtube"), None)

        assert github is not None
        assert github["profile_url"] == "https://github.com/acmeurl"
        assert github["username"] == "acmeurl"

        assert twitter is not None
        assert twitter["profile_url"] == "https://x.com/acmeops"
        assert twitter["username"] == "acmeops"

        assert youtube is not None
        assert youtube["profile_url"] == "https://www.youtube.com/channel/UC1234567890123456789012"
        assert youtube["username"] == "UC1234567890123456789012"

    def test_hackernews_profile_rows_normalize_without_provider_calls(self):
        results = _parse_epieos_response(
            {
                "email": "alice@example.com",
                "hackernews": {
                    "username": "acmehn",
                    "name": "Acme HN",
                },
                "hacker_news_explicit": {
                    "platform": "hacker_news",
                    "profileLink": "https://news.ycombinator.com/user?id=explicit-hn",
                    "name": "Explicit HN",
                },
                "hacker_news_item": {
                    "platform": "hacker_news",
                    "profileLink": "https://news.ycombinator.com/item?id=123456",
                    "name": "Item Is Not Profile",
                },
            }
        )

        hackernews = next((r for r in results if r["platform"] == "hackernews"), None)
        explicit = next(
            (r for r in results if r["platform"] == "hacker_news_explicit"),
            None,
        )
        item = next(
            (r for r in results if r["platform"] == "hacker_news_item"),
            None,
        )

        assert hackernews is not None
        assert hackernews["profile_url"] == "https://news.ycombinator.com/user?id=acmehn"
        assert hackernews["username"] == "acmehn"
        assert explicit is not None
        assert explicit["profile_url"] == "https://news.ycombinator.com/user?id=explicit-hn"
        assert explicit["username"] == "explicit-hn"
        assert item is None

    def test_link_in_bio_profile_alias_urls_survive_host_checked_normalization(self):
        results = _parse_epieos_response(
            {
                "email": "alice@example.com",
                "biolink": {
                    "profileLink": "https://bio.link/acmebio",
                    "name": "Acme Bio",
                },
                "biosite": {
                    "profileLink": "https://bio.site/acmebiosite",
                    "name": "Acme Bio Site",
                },
                "allmylinks": {
                    "profileLink": "https://allmylinks.com/acmeaml",
                    "name": "Acme AllMyLinks",
                },
                "lnkbio": {
                    "canonicalUrl": "https://lnk.bio/acmelnk",
                    "name": "Acme Lnk",
                },
                "soloto": {
                    "webUrl": "https://solo.to/acmesolo",
                    "name": "Acme Solo",
                },
                "campsite": {
                    "profileLink": "https://campsite.bio/acmecamp",
                    "name": "Acme Campsite",
                },
                "taplink": {
                    "profileLink": "https://taplink.cc/acmetap",
                    "name": "Acme Taplink",
                },
                "taplink_ws": {
                    "profileLink": "https://acmetapws.taplink.ws",
                    "name": "Acme Taplink WS",
                },
                "milkshake": {
                    "profileLink": "https://msha.ke/go.milkshake",
                    "name": "Acme Milkshake",
                },
                "bento": {
                    "profileLink": "https://bento.me/acmebento",
                    "name": "Acme Bento",
                },
                "hoobe": {
                    "profileLink": "https://hoo.be/acmehoo",
                    "name": "Acme Hoo",
                },
                "biolink_bad": {
                    "platform": "biolink",
                    "profileLink": "https://example.com/not-a-profile",
                    "name": "Host Mismatch",
                },
            }
        )

        biolink = next((r for r in results if r["platform"] == "biolink"), None)
        biosite = next((r for r in results if r["platform"] == "biosite"), None)
        allmylinks = next((r for r in results if r["platform"] == "allmylinks"), None)
        lnkbio = next((r for r in results if r["platform"] == "lnkbio"), None)
        soloto = next((r for r in results if r["platform"] == "soloto"), None)
        campsite = next((r for r in results if r["platform"] == "campsite"), None)
        taplink = next((r for r in results if r["platform"] == "taplink"), None)
        taplink_ws = next((r for r in results if r["platform"] == "taplink_ws"), None)
        milkshake = next((r for r in results if r["platform"] == "milkshake"), None)
        bento = next((r for r in results if r["platform"] == "bento"), None)
        hoobe = next((r for r in results if r["platform"] == "hoobe"), None)
        bad = next((r for r in results if r["platform"] == "biolink_bad"), None)

        assert biolink is not None
        assert biolink["profile_url"] == "https://bio.link/acmebio"
        assert biolink["username"] == "acmebio"
        assert biosite is not None
        assert biosite["profile_url"] == "https://bio.site/acmebiosite"
        assert biosite["username"] == "acmebiosite"
        assert allmylinks is not None
        assert allmylinks["profile_url"] == "https://allmylinks.com/acmeaml"
        assert allmylinks["username"] == "acmeaml"
        assert lnkbio is not None
        assert lnkbio["profile_url"] == "https://lnk.bio/acmelnk"
        assert lnkbio["username"] == "acmelnk"
        assert soloto is not None
        assert soloto["profile_url"] == "https://solo.to/acmesolo"
        assert soloto["username"] == "acmesolo"
        assert campsite is not None
        assert campsite["profile_url"] == "https://campsite.bio/acmecamp"
        assert campsite["username"] == "acmecamp"
        assert taplink is not None
        assert taplink["profile_url"] == "https://taplink.cc/acmetap"
        assert taplink["username"] == "acmetap"
        assert taplink_ws is not None
        assert taplink_ws["profile_url"] == "https://acmetapws.taplink.ws"
        assert taplink_ws["username"] == "acmetapws"
        assert milkshake is not None
        assert milkshake["profile_url"] == "https://msha.ke/go.milkshake"
        assert milkshake["username"] == "go.milkshake"
        assert bento is not None
        assert bento["profile_url"] == "https://bento.me/acmebento"
        assert bento["username"] == "acmebento"
        assert hoobe is not None
        assert hoobe["profile_url"] == "https://hoo.be/acmehoo"
        assert hoobe["username"] == "acmehoo"
        assert bad is None


# ═══════════════════════════════════════════════════════════════════════════
# Session isolation (OPSEC invariant)
# ═══════════════════════════════════════════════════════════════════════════


class TestSessionIsolation:
    def test_fresh_session_per_target(self):
        """
        A new AsyncSession must be created for each target email.
        Sharing sessions across targets allows timing/correlation attacks.
        """
        client = EpieosClient()
        sessions_created: list = []

        original_session = __import__("curl_cffi.requests", fromlist=["AsyncSession"]).AsyncSession

        class TrackingSession:
            def __init__(self, *a, **kw):
                sessions_created.append(self)

            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                pass

            async def get(self, url, **kw):
                m = MagicMock()
                m.status_code = 200
                m.json.return_value = _epieos_payload()
                return m

        with patch("forge.utils.intel.social_scraper.AsyncSession", TrackingSession):
            import asyncio

            asyncio.run(
                client.query_many(["alice@example.com", "bob@example.com", "charlie@example.com"])
            )

        assert len(sessions_created) == 3

    def test_query_many_preserves_submission_order_under_parallel_completion(self):
        client = EpieosClient(max_concurrency=3)
        delays = {
            "alice@example.com": 0.05,
            "bob@example.com": 0.01,
            "charlie@example.com": 0.03,
        }
        seen: list[str] = []

        async def fake_query(email: str, proxy: str | None = None) -> dict:
            del proxy
            await asyncio.sleep(delays[email])
            seen.append(email)
            return _epieos_payload(email)

        with patch("forge.utils.intel.social_scraper._query_epieos", fake_query):
            results = asyncio.run(client.query_many(list(delays.keys())))

        assert list(results.keys()) == list(delays.keys())
        assert set(seen) == set(delays.keys())

    def test_query_many_honors_concurrency_cap(self):
        client = EpieosClient(max_concurrency=2)
        active = 0
        peak = 0

        async def fake_query(email: str, proxy: str | None = None) -> dict:
            del email, proxy
            nonlocal active, peak
            active += 1
            peak = max(peak, active)
            try:
                await asyncio.sleep(0.03)
                return _epieos_payload()
            finally:
                active -= 1

        with patch("forge.utils.intel.social_scraper._query_epieos", fake_query):
            asyncio.run(
                client.query_many(
                    [
                        "alice@example.com",
                        "bob@example.com",
                        "charlie@example.com",
                        "delta@example.com",
                    ]
                )
            )

        assert peak == 2

    def test_query_many_defaults_to_sequential_epieos_lookups(self, monkeypatch):
        monkeypatch.delenv("FORGE_EPIEOS_MAX_CONCURRENCY", raising=False)
        client = EpieosClient()
        active = 0
        peak = 0

        async def fake_query(email: str, proxy: str | None = None) -> dict:
            del email, proxy
            nonlocal active, peak
            active += 1
            peak = max(peak, active)
            try:
                await asyncio.sleep(0.01)
                return _epieos_payload()
            finally:
                active -= 1

        with patch("forge.utils.intel.social_scraper._query_epieos", fake_query):
            asyncio.run(
                client.query_many(
                    [
                        "alice@example.com",
                        "bob@example.com",
                        "charlie@example.com",
                    ]
                )
            )

        assert peak == 1

    def test_epieos_default_concurrency_can_be_raised_by_env(self, monkeypatch):
        monkeypatch.setenv("FORGE_EPIEOS_MAX_CONCURRENCY", "4")

        assert social_scraper._epieos_max_concurrency_default() == 4


# ═══════════════════════════════════════════════════════════════════════════
# Proxy support
# ═══════════════════════════════════════════════════════════════════════════


class TestProxySupport:
    def test_proxy_passed_to_session(self):
        proxy_url = "socks5://127.0.0.1:9050"
        client = EpieosClient(proxy=proxy_url)

        init_kwargs: dict = {}

        class CapturingSession:
            def __init__(self, *a, **kw):
                init_kwargs.update(kw)

            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                pass

            async def get(self, url, **kw):
                m = MagicMock()
                m.status_code = 200
                m.json.return_value = _epieos_payload()
                return m

        with patch("forge.utils.intel.social_scraper.AsyncSession", CapturingSession):
            import asyncio

            asyncio.run(client.query_many(["alice@example.com"]))

        assert proxy_url in str(init_kwargs)

    def test_env_proxy_respected(self, monkeypatch):
        monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example.com:8080")
        client = EpieosClient()
        assert client._proxy == "http://proxy.example.com:8080"


# ═══════════════════════════════════════════════════════════════════════════
# Encryption at rest
# ═══════════════════════════════════════════════════════════════════════════


class TestEncryptionAtRest:
    def test_raw_data_encrypted_before_write(self, engagement_db):
        with (
            patch(
                "forge.utils.intel.social_scraper.EpieosClient.query_many",
                return_value={"alice@example.com": _parse_epieos_response(_epieos_payload())},
            ),
            patch(
                "forge.utils.intel.social_scraper.encrypt_string",
                return_value="ENC:opaque_blob",
            ) as mock_enc,
        ):
            run_social_scraper(engagement_db, 1)

        mock_enc.assert_called()

    def test_stored_raw_data_not_plaintext(self, engagement_db):
        with (
            patch(
                "forge.utils.intel.social_scraper.EpieosClient.query_many",
                return_value={"alice@example.com": _parse_epieos_response(_epieos_payload())},
            ),
            patch(
                "forge.utils.intel.social_scraper.encrypt_string",
                return_value="ENC:opaque_blob",
            ),
        ):
            run_social_scraper(engagement_db, 1)

        con = sqlite3.connect(engagement_db)
        rows = con.execute("SELECT raw_data_enc FROM social_profiles").fetchall()
        con.close()
        for (enc,) in rows:
            if enc:
                assert not enc.startswith("{")  # not raw JSON


# ═══════════════════════════════════════════════════════════════════════════
# run_social_scraper — DB integration
# ═══════════════════════════════════════════════════════════════════════════


class TestRunSocialScraper:
    def test_profiles_written_to_db(self, engagement_db):
        with (
            patch(
                "forge.utils.intel.social_scraper.EpieosClient.query_many",
                return_value={"alice@example.com": _parse_epieos_response(_epieos_payload())},
            ),
            patch("forge.utils.intel.social_scraper.encrypt_string", return_value="ENC:x"),
        ):
            run_social_scraper(engagement_db, 1)

        con = sqlite3.connect(engagement_db)
        count = con.execute("SELECT COUNT(*) FROM social_profiles").fetchone()[0]
        con.close()
        assert count >= 2  # google + linkedin

    def test_scope_gate_enforced(self, engagement_db):
        from forge.opsec.scope_gate import ScopeViolationError

        with pytest.raises(ScopeViolationError):
            run_social_scraper(
                engagement_db,
                1,
                target_emails=["attacker@outofscope.io"],
            )

    def test_dry_run_no_write(self, engagement_db):
        with patch(
            "forge.utils.intel.social_scraper.EpieosClient.query_many",
            return_value={"alice@example.com": _parse_epieos_response(_epieos_payload())},
        ):
            run_social_scraper(engagement_db, 1, dry_run=True)

        con = sqlite3.connect(engagement_db)
        count = con.execute("SELECT COUNT(*) FROM social_profiles").fetchone()[0]
        con.close()
        assert count == 0

    def test_audit_log_written(self, engagement_db):
        with (
            patch(
                "forge.utils.intel.social_scraper.EpieosClient.query_many",
                return_value={"alice@example.com": []},
            ),
            patch("forge.utils.intel.social_scraper.encrypt_string", return_value="ENC:x"),
        ):
            run_social_scraper(engagement_db, 1)

        con = sqlite3.connect(engagement_db)
        count = con.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
        con.close()
        assert count >= 1

    def test_run_social_scraper_passes_default_sequential_concurrency(
        self,
        engagement_db,
        monkeypatch,
    ):
        monkeypatch.delenv("FORGE_EPIEOS_MAX_CONCURRENCY", raising=False)
        observed: list[int | None] = []

        class FakeClient:
            def __init__(self, proxy=None, max_concurrency=None):  # noqa: ANN001
                del proxy
                observed.append(max_concurrency)

            async def query_many(self, emails):  # noqa: ANN001
                return {str(email): [] for email in emails}

        monkeypatch.setattr("forge.utils.intel.social_scraper.EpieosClient", FakeClient)

        run_social_scraper(engagement_db, 1)

        assert observed == [1]

    def test_run_social_scraper_passes_explicit_concurrency_override(
        self,
        engagement_db,
        monkeypatch,
    ):
        observed: list[int | None] = []

        class FakeClient:
            def __init__(self, proxy=None, max_concurrency=None):  # noqa: ANN001
                del proxy
                observed.append(max_concurrency)

            async def query_many(self, emails):  # noqa: ANN001
                return {str(email): [] for email in emails}

        monkeypatch.setattr("forge.utils.intel.social_scraper.EpieosClient", FakeClient)

        run_social_scraper(engagement_db, 1, max_concurrency=3)

        assert observed == [3]

    def test_supports_canonical_email_schema(self, tmp_path: Path):
        db = tmp_path / "eng-canonical.db"
        con = sqlite3.connect(db)
        con.executescript("""
            CREATE TABLE engagements (
                id INTEGER PRIMARY KEY, name TEXT, scope_json TEXT
            );
            CREATE TABLE emails (
                id INTEGER PRIMARY KEY, engagement_id INTEGER,
                email TEXT, source TEXT, first_seen_at TEXT
            );
            CREATE TABLE social_profiles (
                id INTEGER PRIMARY KEY, engagement_id INTEGER,
                email TEXT, source TEXT, profile_data TEXT, queried_at TEXT,
                UNIQUE(engagement_id, email, source)
            );
            CREATE TABLE audit_log (
                id INTEGER PRIMARY KEY, engagement_id INTEGER,
                phase TEXT, module TEXT, action TEXT, target TEXT,
                result TEXT, operator TEXT, logged_at TEXT
            );
            INSERT INTO engagements VALUES (1, 'test-eng', '["example.com"]');
            INSERT INTO emails VALUES (1,1,'alice@example.com','seed','2024-01-01');
        """)
        con.commit()
        con.close()

        with (
            patch(
                "forge.utils.intel.social_scraper.EpieosClient.query_many",
                return_value={"alice@example.com": _parse_epieos_response(_epieos_payload())},
            ),
            patch("forge.utils.intel.social_scraper.encrypt_string", return_value="ENC:x"),
        ):
            run_social_scraper(db, 1)

        con = sqlite3.connect(db)
        count = con.execute("SELECT COUNT(*) FROM social_profiles").fetchone()[0]
        con.close()
        assert count >= 1

    def test_canonical_schema_stores_rich_profile_data_for_synthesis(self, tmp_path: Path):
        db = tmp_path / "eng-rich.db"
        con = sqlite3.connect(db)
        con.executescript("""
            CREATE TABLE engagements (
                id INTEGER PRIMARY KEY, name TEXT, scope_json TEXT
            );
            CREATE TABLE emails (
                id INTEGER PRIMARY KEY, engagement_id INTEGER,
                email TEXT, source TEXT, first_seen_at TEXT
            );
            CREATE TABLE social_profiles (
                id INTEGER PRIMARY KEY, engagement_id INTEGER,
                email TEXT, source TEXT, profile_data TEXT, queried_at TEXT,
                UNIQUE(engagement_id, email, source)
            );
            CREATE TABLE audit_log (
                id INTEGER PRIMARY KEY, engagement_id INTEGER,
                phase TEXT, module TEXT, action TEXT, target TEXT,
                result TEXT, operator TEXT, logged_at TEXT
            );
            INSERT INTO engagements VALUES (1, 'test-eng', '["example.com"]');
            INSERT INTO emails VALUES (1,1,'alice@example.com','seed','2024-01-01');
        """)
        con.commit()
        con.close()

        with (
            patch(
                "forge.utils.intel.social_scraper.EpieosClient.query_many",
                return_value={"alice@example.com": _parse_epieos_response(_rich_epieos_payload())},
            ),
            patch("forge.utils.intel.social_scraper.encrypt_string", side_effect=lambda value: value),
        ):
            run_social_scraper(db, 1)

        con = sqlite3.connect(db)
        try:
            stored = con.execute(
                "SELECT profile_data FROM social_profiles WHERE engagement_id=1 AND email='alice@example.com'"
            ).fetchone()
            assert stored is not None
            payload = json.loads(stored[0])
            github = next((row for row in payload if row["platform"] == "github"), None)
            company = next((row for row in payload if row["platform"] == "linkedin_company"), None)
            assert github is not None
            assert github["username"] == "acmehunter"
            assert github["company_name"] == "Acme Corp"
            assert github["email"] == "alice.ops@acme.example"
            assert company is not None
            assert company["company_name"] == "Acme Corp"
        finally:
            con.close()
