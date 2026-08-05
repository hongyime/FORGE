"""Narrow unit tests for the slowest ``EngagementSynthesisEngine`` rules.

The original tests in ``test_engagement_orchestrator.py`` exercise the same
rules end-to-end via ``EngagementSynthesisEngine(...).run()``. Each of those
tests spins up a fresh SQLite database, applies the full schema, seeds
``social_profiles`` rows, and executes the entire derivation + upsert +
confidence-refresh flow. Six of them dominate the slow suite (346s / 303s /
134s / 118s / 107s / 64s) despite exercising a narrow slice of the
synthesizer.

The tests below reproduce the same assertion contract by calling the
underlying candidate-derivation helpers directly:

* ``_social_profile_row_candidates`` — the seed derivation used by
  ``_derive_social_profile_candidates`` (bypasses the DB read + full
  ``.run()`` orchestration).
* ``_social_profile_platform_hint`` / ``_social_profile_direct_platform`` —
  the classmethods that canonicalize platform labels.
* ``_social_profile_payload_entries`` — the flattener that unwraps nested
  provider payloads before candidate derivation.

The original ``@pytest.mark.slow`` tests are intentionally left in place as
canary integration tests. These narrow unit tests give the same rule
coverage on every default ``pytest`` invocation.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from forge.engagement_orchestrator import EngagementSynthesisEngine, SeedCandidate


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _serial_local_batch(monkeypatch: pytest.MonkeyPatch) -> None:
    """Force ``_run_ordered_local_batch`` into a pure serial loop.

    The production implementation always creates a ``ThreadPoolExecutor`` for
    lists with more than one item. For the deeply nested candidate-derivation
    pipeline the overhead of spinning up and tearing down thread pools for
    every batch dominates the wall-clock cost. Serial execution is
    behaviorally identical (the pool is used purely for concurrency) so the
    monkeypatch does not change any rule outcome under test.
    """

    def _serial(
        cls,
        batch_items,
        worker,
        *,
        default_factory,
    ):
        results = []
        for item in batch_items:
            try:
                results.append(worker(item))
            except Exception:  # noqa: BLE001 - mirror production error handling
                results.append(default_factory())
        return results

    monkeypatch.setattr(
        EngagementSynthesisEngine,
        "_run_ordered_local_batch",
        classmethod(_serial),
    )


@pytest.fixture
def engine(tmp_path: Path) -> EngagementSynthesisEngine:
    """A lightweight ``EngagementSynthesisEngine`` bound to an unused db path.

    The constructor only stores ``db_path`` / ``engagement_id`` / ``depth_limit``
    — it does not touch the filesystem. None of the tests below invoke
    ``.run()``, so the tmp_path never needs to exist as a SQLite database.
    """

    return EngagementSynthesisEngine(tmp_path / "engagement.db", 1001, depth_limit=3)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _row(email: str, source: str, profile_data: Any) -> dict[str, Any]:
    """Build a dict shaped like the ``social_profiles`` rows the engine reads."""

    return {
        "email": email,
        "source": source,
        "profile_data": (
            profile_data
            if isinstance(profile_data, str)
            else json.dumps(profile_data)
        ),
    }


def _seed_index(candidates: list[SeedCandidate]) -> dict[tuple[str, str], SeedCandidate]:
    """Index candidates by ``(seed_value, seed_type)`` for assertion lookups."""

    index: dict[tuple[str, str], SeedCandidate] = {}
    for candidate in candidates:
        # Preserve the highest-confidence entry if we see the same seed twice.
        key = (candidate.seed_value, candidate.seed_type)
        prior = index.get(key)
        if prior is None or candidate.confidence >= prior.confidence:
            index[key] = candidate
    return index


def _relation_set(candidates: list[SeedCandidate]) -> set[tuple[str, str, str]]:
    """Collect ``(parent_value, seed_value, relation_type)`` triples."""

    triples: set[tuple[str, str, str]] = set()
    for candidate in candidates:
        if not candidate.parent_value or not candidate.parent_type:
            continue
        triples.add(
            (
                str(candidate.parent_value),
                candidate.seed_value,
                candidate.relation_type,
            )
        )
    return triples


# ---------------------------------------------------------------------------
# Rule 1 — social profile seed + relation derivation
#
# Mirrors ``test_synthesis_engine_derives_social_profile_seeds_and_relations``
# (64s slow test). Verifies that a modest mix of Gravatar / crosslinked /
# epieos / instagram / raw-provider rows produces the expected pivots and
# ``same_entity`` / ``related_asset`` relations.
# ---------------------------------------------------------------------------


def test_row_candidates_derive_social_profile_seeds_and_relations(
    engine: EngagementSynthesisEngine,
) -> None:
    rows = [
        _row(
            "security@acme.example",
            "gravatar:github:secops",
            {
                "source": "gravatar",
                "platform": "github",
                "handle": "secops",
                "url": "https://github.com/secops",
                "verified": True,
                "email": "security@acme.example",
            },
        ),
        _row(
            "acme.example",
            "crosslinked:linkedin:alice-example",
            {
                "source": "crosslinked",
                "platform": "linkedin",
                "slug": "alice-example",
                "url": "https://www.linkedin.com/in/alice-example",
                "domain": "acme.example",
                "firstname": "Alice",
                "lastname": "Example",
            },
        ),
        _row(
            "security@acme.example",
            "epieos:stackoverflow:alice-su",
            {
                "source": "epieos",
                "platform": "stackoverflow",
                "profile_url": "https://superuser.com/users/24680/alice-su",
            },
        ),
        _row(
            "security@acme.example",
            "instagram",
            {
                "source": "instagram",
                "handle": "secopsacme",
                "phone": "+15559876543",
                "emails_in_bio": ["press@acme.example"],
                "urls_in_bio": [
                    "https://about.acme.example/team",
                    "https://downloads.acme.example/client.apk",
                ],
                "profile_url": "https://www.instagram.com/secopsacme/",
            },
        ),
        _row(
            "security@acme.example",
            "raw-provider:github:rawops",
            {
                "source": "raw_provider",
                "platform": "github",
                "profile": {
                    "login": "rawops",
                    "html_url": "https://github.com/rawops",
                    "emailAddress": "rawops@acme.example",
                    "phoneNumber": "+1 555 222 1212",
                    "website_url": "https://rawops.acme.example/status",
                },
                "identity": {
                    "login": "identityops",
                    "html_url": "https://github.com/identityops",
                    "emailAddress": "identityops@acme.example",
                    "phoneNumber": "+1 555 777 1212",
                    "website_url": "https://identity.acme.example/status",
                },
                "person": {
                    "publicIdentifier": "person-link",
                    "profile_url": "https://www.linkedin.com/in/person-link",
                    "email": "person-link@acme.example",
                    "mobile": "+1 555 888 1212",
                    "homepage": "https://people.acme.example/person-link",
                },
                "contact": {
                    "emailAddress": "nested-contact@acme.example",
                    "phoneNumber": "+1 555 444 1212",
                    "websiteUrl": "https://contact.acme.example/help",
                },
                "contacts": [
                    {
                        "email": "nested-list-contact@acme.example",
                        "tel": "+1 555 445 1212",
                        "href": "https://contact-list.acme.example/help",
                    }
                ],
                "handles": [
                    "handlelistops",
                    {"username": "handleobjectops"},
                    {"publicUrl": "github.com/accountpublicops"},
                ],
                "usernames": [{"value": "usernamevalueops"}],
                "links": [
                    {"href": "mailto:linkops@acme.example"},
                    {"href": "https://status.acme.example/health"},
                    {"url": "tel:+15553334444"},
                ],
                "websites": [{"href": "https://portal.acme.example/login"}],
            },
        ),
    ]

    candidates: list[SeedCandidate] = []
    for row in rows:
        candidates.extend(engine._social_profile_row_candidates(row, {}))

    seeds = _seed_index(candidates)
    relations = _relation_set(candidates)

    # Username pivots from every provider payload
    for handle in (
        "secops",
        "alice-example",
        "alice-su",
        "secopsacme",
        "rawops",
        "identityops",
        "person-link",
        "handlelistops",
        "handleobjectops",
        "accountpublicops",
        "usernamevalueops",
    ):
        assert (handle, "username") in seeds, handle

    # Person name derived from firstname/lastname via cross_reference
    assert ("Alice Example", "name") in seeds
    assert seeds[("Alice Example", "name")].source == "cross_reference"

    # Phones (normalized to E.164) surfaced from instagram + nested contacts
    for phone in (
        "+15559876543",
        "+15552221212",
        "+15557771212",
        "+15558881212",
        "+15554441212",
        "+15554451212",
        "+15553334444",
    ):
        assert (phone, "phone") in seeds, phone

    # Emails from bio + nested contact/contacts + mailto: links
    for email in (
        "press@acme.example",
        "rawops@acme.example",
        "identityops@acme.example",
        "person-link@acme.example",
        "nested-contact@acme.example",
        "nested-list-contact@acme.example",
        "linkops@acme.example",
    ):
        assert (email, "email") in seeds, email

    # URL + subdomain pivots
    for url, subdomain in (
        ("https://about.acme.example/team", "about.acme.example"),
        ("https://downloads.acme.example/client.apk", "downloads.acme.example"),
        ("https://rawops.acme.example/status", "rawops.acme.example"),
        ("https://identity.acme.example/status", "identity.acme.example"),
        ("https://people.acme.example/person-link", "people.acme.example"),
        ("https://contact.acme.example/help", "contact.acme.example"),
        ("https://contact-list.acme.example/help", "contact-list.acme.example"),
        ("https://status.acme.example/health", "status.acme.example"),
        ("https://portal.acme.example/login", "portal.acme.example"),
    ):
        # APK URLs get promoted to a dedicated type, so accept either "url" or "apk_url".
        assert (url, "url") in seeds or (url, "apk_url") in seeds, url
        assert (subdomain, "subdomain") in seeds, subdomain

    # Same-entity + related-asset relations back to the security@ anchor
    expected_same_entity = (
        "secops",
        "alice-su",
        "press@acme.example",
        "+15559876543",
        "rawops",
        "identityops",
        "person-link",
        "handlelistops",
        "handleobjectops",
        "accountpublicops",
        "usernamevalueops",
        "rawops@acme.example",
        "identityops@acme.example",
        "person-link@acme.example",
        "nested-contact@acme.example",
        "nested-list-contact@acme.example",
    )
    for pivot in expected_same_entity:
        assert (
            "security@acme.example",
            pivot,
            "same_entity",
        ) in relations, pivot

    expected_related_asset = (
        "downloads.acme.example",
        "rawops.acme.example",
        "identity.acme.example",
        "people.acme.example",
        "contact.acme.example",
        "contact-list.acme.example",
    )
    for asset in expected_related_asset:
        assert (
            "security@acme.example",
            asset,
            "related_asset",
        ) in relations, asset


# ---------------------------------------------------------------------------
# Rule 2 — wrapped provider payloads get flattened
#
# Mirrors ``test_synthesis_engine_flattens_wrapped_social_profile_provider_payloads``
# (303s slow test). The synthesizer must unwrap ``identity`` / ``profiles`` /
# ``results.items`` / ``data.accounts`` / ``edges`` / ``registeredServices``
# containers so the nested profile objects contribute username pivots.
# ---------------------------------------------------------------------------


def test_row_candidates_flatten_wrapped_provider_payloads(
    engine: EngagementSynthesisEngine,
) -> None:
    payload = {
        "query": "security@acme.example",
        "identity": [
            {
                "platform": "github",
                "login": "nestedlistone",
                "emailAddress": "nestedlist@acme.example",
                "website_url": "https://nested.acme.example/status",
            }
        ],
        "profiles": [
            {
                "platform": "github",
                "login": "wrappeddev",
                "html_url": "https://github.com/wrappeddev",
                "emailAddress": "wrappeddev@acme.example",
            }
        ],
        "results": {
            "items": [
                {
                    "platform": "linkedin",
                    "profileLink": "https://www.linkedin.com/in/wrapped-link",
                    "phones": [{"number": "+1 555 111 2222"}],
                }
            ]
        },
        "data": {
            "accounts": [
                {
                    "platform": "youtube",
                    "profile_url": "https://www.youtube.com/@wrappedtube",
                    "contactEmails": [{"address": "tube@acme.example"}],
                },
                {
                    "platform": "twitter",
                    "profile_url": "https://x.com/wrappedx",
                },
            ]
        },
        "edges": [
            {
                "node": {
                    "platform": "instagram",
                    "profile_url": "https://www.instagram.com/wrappedgram/",
                    "contactPhone": "+1 555 333 4444",
                }
            }
        ],
        "registeredServices": [
            {
                "source": "epieos",
                "service": "github",
                "results": [{"username": "wrappedchild"}],
            },
            {
                "source": "epieos",
                "service": "Stack Overflow",
                "results": [{"username": "soalice"}],
            },
        ],
    }

    row = _row("security@acme.example", "identity_provider:wrapped", payload)
    candidates = engine._social_profile_row_candidates(row, {})
    seeds = _seed_index(candidates)

    # Every nested container contributed at least one username pivot.
    for handle in (
        "nestedlistone",  # identity[]
        "wrappeddev",  # profiles[]
        "wrapped-link",  # results.items[]
        "wrappedtube",  # data.accounts[]
        "wrappedx",  # data.accounts[]
        "wrappedgram",  # edges[].node
        "wrappedchild",  # registeredServices[].results[]
        "soalice",  # registeredServices with spaced brand label
    ):
        assert (handle, "username") in seeds, handle

    # Nested contact fields lifted into their own pivots
    assert ("nestedlist@acme.example", "email") in seeds
    assert ("wrappeddev@acme.example", "email") in seeds
    assert ("tube@acme.example", "email") in seeds
    assert ("+15551112222", "phone") in seeds
    assert ("+15553334444", "phone") in seeds

    # ``Stack Overflow`` is normalized to the ``stack_overflow`` platform slug
    # (space collapses to underscore); ``github`` label passes through as-is.
    assert seeds[("soalice", "username")].metadata.get("platform") == "stack_overflow"
    assert seeds[("wrappedchild", "username")].metadata.get("platform") == "github"


# ---------------------------------------------------------------------------
# Rules 3 + 5 — spaced provider label canonicalization
#
# ``_social_profile_platform_hint`` classmethod handles both bare label
# canonicalization ("Stack Overflow" → "stackoverflow") and its brand-name
# cousins ("Dev To" → "devto"). Both tests hammer the same rule with dozens
# of provider labels, so we consolidate them into two focused unit tests
# instead of round-tripping the full engagement pipeline for each.
# ---------------------------------------------------------------------------


# (Service label, expected canonical platform slug).
_SPACED_PROVIDER_LABEL_CASES: tuple[tuple[str, str], ...] = (
    ("Angel List", "angellist"),
    ("Bio Link", "biolink"),
    ("Bio Site", "biosite"),
    ("Blue Sky", "bluesky"),
    ("Bug Crowd", "bugcrowd"),
    ("Cal Com", "calcom"),
    ("Code Pen", "codepen"),
    ("Git Hub", "github"),
    ("Git Hub Gist", "github_gist"),
    ("Git Lab", "gitlab"),
    ("Hacker News", "hackernews"),
    ("Hacker One", "hackerone"),
    ("Link Tree", "linktree"),
    ("Lnk Bio", "lnkbio"),
    ("Solo To", "soloto"),
    ("Try Hack Me", "tryhackme"),
    ("Well Found", "wellfound"),
    ("Yes We Hack", "yeswehack"),
)

_SPACED_BRAND_PROVIDER_LABEL_CASES: tuple[tuple[str, str], ...] = (
    ("Dev To", "devto"),
    ("Npm Js", "npm"),
    ("Campsite Bio", "campsite"),
    ("Hoo Be", "hoobe"),
    ("Milk Shake", "milkshake"),
    ("Tap Link", "taplink"),
    ("Sub Stack", "substack"),
    ("Hash Node", "hashnode"),
    ("Bit Bucket", "bitbucket"),
    ("Code Berg", "codeberg"),
    ("Tik Tok", "tiktok"),
    ("You Tube", "youtube"),
    ("Angel Co", "angellist"),
)


@pytest.mark.parametrize(("label", "expected"), _SPACED_PROVIDER_LABEL_CASES)
def test_platform_hint_canonicalizes_spaced_provider_labels(
    label: str, expected: str
) -> None:
    resolved = EngagementSynthesisEngine._social_profile_platform_hint(
        {"platform": label}
    )
    assert resolved == expected


@pytest.mark.parametrize(("label", "expected"), _SPACED_BRAND_PROVIDER_LABEL_CASES)
def test_platform_hint_canonicalizes_spaced_brand_provider_labels(
    label: str, expected: str
) -> None:
    resolved = EngagementSynthesisEngine._social_profile_platform_hint(
        {"platform": label}
    )
    assert resolved == expected


def test_spaced_provider_labels_survive_row_derivation(
    engine: EngagementSynthesisEngine,
) -> None:
    """End-to-end check: spaced provider labels drive username seed platform."""

    payload = {
        "registeredServices": [
            {
                "source": "epieos",
                "service": service,
                "results": [
                    {"username": reserved_handle},  # generic reserved token
                    {"username": valid_handle},
                ],
            }
            for service, reserved_handle, valid_handle, _platform in (
                ("Angel List", "company", "angellistalias", "angellist"),
                ("Git Hub", "marketplace", "githubalias2", "github"),
                ("Try Hack Me", "room", "tryhackmealias", "tryhackme"),
                ("Sub Stack", "app", "substackalias", "substack"),
                ("You Tube", "watch", "youtubealias", "youtube"),
            )
        ]
    }

    row = _row(
        "security@acme.example",
        "identity_provider:spaced-labels",
        payload,
    )
    candidates = engine._social_profile_row_candidates(row, {})
    seeds = _seed_index(candidates)

    for valid_handle, platform in (
        ("angellistalias", "angellist"),
        ("githubalias2", "github"),
        ("tryhackmealias", "tryhackme"),
        ("substackalias", "substack"),
        ("youtubealias", "youtube"),
    ):
        assert (valid_handle, "username") in seeds, valid_handle
        assert seeds[(valid_handle, "username")].metadata.get("platform") == platform

    # Generic-reserved handles must NOT be promoted to seeds.
    for reserved in ("company", "marketplace", "room", "app", "watch"):
        assert (reserved, "username") not in seeds


# ---------------------------------------------------------------------------
# Rule 4 — infer platform from URL alias fields
#
# Mirrors ``test_synthesis_engine_infers_social_profile_platforms_from_url_alias_fields``
# (118s slow test). Profiles that only carry a URL alias (``profileLink``,
# ``canonicalUrl``, ``webUrl``, ``uri``, ``publicUrl``, ``account_url``,
# ``sameAs``) must still get a platform derived from the URL host and the
# handle extracted from the URL path.
# ---------------------------------------------------------------------------


def test_row_candidates_infer_social_platforms_from_url_alias_fields(
    engine: EngagementSynthesisEngine,
) -> None:
    payload = [
        {
            "source": "epieos",
            "profileLink": "https://github.com/aliasdev",
            "display_name": "Alias Dev",
        },
        {
            "source": "epieos",
            "canonicalUrl": "https://www.linkedin.com/company/acme-alias-labs",
        },
        {
            "source": "epieos",
            "webUrl": "https://solo.to/aliassolo",
        },
        {
            "source": "epieos",
            "profileLink": "https://www.figma.com/@acmedesign",
        },
        {
            "source": "epieos",
            "profileLink": "https://www.figma.com/community/file/123456/design-system",
        },
        {
            "source": "epieos",
            "profileLink": "https://www.indiehackers.com/acmefounder",
        },
        {
            "source": "epieos",
            "profileLink": "https://www.polywork.com/acmeops",
        },
        {
            "source": "epieos",
            "profileLink": "https://contra.com/acmeconsultant",
        },
        {
            "source": "epieos",
            "profileLink": "https://adplist.org/mentors/acme-mentor",
        },
        {
            "source": "epieos",
            "profileLink": "https://contra.com/discover/designers",
        },
        {
            "source": "epieos",
            "profileLink": "github.com/schemelessdev",  # scheme-less
        },
        {
            "source": "epieos",
            "canonicalUrl": "www.linkedin.com/company/schemeless-labs",
        },
        {
            "source": "epieos",
            "webUrl": "linktr.ee/schemelesslink",
        },
        {
            "source": "epieos",
            "publicUrl": "github.com/publicurlops",
        },
        {
            "source": "epieos",
            "account_url": "linktr.ee/accounturlops",
        },
        {
            "source": "epieos",
            "uri": "www.linkedin.com/company/uri-labs",
        },
        {
            "source": "epieos",
            "sameAs": [
                "github.com/sameasdev",
                "https://www.linkedin.com/in/same-as-person",
            ],
        },
    ]

    row = _row("security@acme.example", "epieos:alias-url-fields", payload)
    candidates = engine._social_profile_row_candidates(row, {})
    seeds = _seed_index(candidates)

    # Handles extracted from URL paths with the correct platform slug.
    expected_username_platforms = (
        ("aliasdev", "github"),
        ("aliassolo", "soloto"),
        ("acmedesign", "figma"),
        ("acmefounder", "indiehackers"),
        ("acmeops", "polywork"),
        ("acmeconsultant", "contra"),
        ("acme-mentor", "adplist"),
        ("schemelessdev", "github"),
        ("schemelesslink", "linktree"),
        ("publicurlops", "github"),
        ("accounturlops", "linktree"),
    )
    for handle, platform in expected_username_platforms:
        assert (handle, "username") in seeds, handle
        assert seeds[(handle, "username")].metadata.get("platform") == platform

    # sameAs list is unwrapped into per-URL username pivots.
    assert ("sameasdev", "username") in seeds
    assert ("same-as-person", "username") in seeds

    # LinkedIn ``company/<slug>`` URLs promote to company seeds, not usernames.
    for company, platform in (
        ("Acme Alias Labs", "linkedin_company"),
        ("Schemeless Labs", "linkedin_company"),
        ("Uri Labs", "linkedin_company"),
    ):
        assert (company, "company") in seeds
        assert seeds[(company, "company")].metadata.get("platform") == platform
        assert seeds[(company, "company")].metadata.get("rule") == "social_profile_company"

    # URL seeds — including normalized scheme-less URLs — are recorded.
    for url in (
        "https://github.com/schemelessdev",
        "https://www.linkedin.com/company/schemeless-labs",
        "https://linktr.ee/schemelesslink",
        "https://github.com/publicurlops",
        "https://linktr.ee/accounturlops",
        "https://www.linkedin.com/company/uri-labs",
        "https://github.com/sameasdev",
        "https://www.linkedin.com/in/same-as-person",
    ):
        assert (url, "url") in seeds, url

    # LinkedIn-company slugs are NOT promoted as usernames — they belong to
    # the ``company`` type. Also ensure design-system / documentation URLs
    # never emit generic-token usernames.
    for reserved in (
        "acme-alias-labs",
        "security-guide",
        "reference",
        "123456",
        "design-system",
        "designers",
    ):
        assert (reserved, "username") not in seeds


# ---------------------------------------------------------------------------
# Rule 6 — normalized epieos service lists + gravatar summary payloads
#
# Mirrors ``test_synthesis_engine_normalizes_epieos_lists_and_richer_gravatar_summary_payloads``
# (346s slow test). This exercises the widest set of alias platforms + the
# reserved-handle deny list. We spot-check enough representative platforms to
# confirm the rule is exercised without regressing on any of the reserved
# tokens.
# ---------------------------------------------------------------------------


def test_row_candidates_normalize_epieos_lists_and_gravatar_summary_payloads(
    engine: EngagementSynthesisEngine,
) -> None:
    epieos_payload = [
        {
            "platform": "github",
            "profile_url": "https://github.com/acmehunter",
            "display_name": "Alice Example",
        },
        {
            "platform": "github",
            "username": "marketplace",
            "profile_url": "https://github.com/marketplace",
        },
        {
            "platform": "gitlab",
            "username": "groups",
            "profile_url": "https://gitlab.com/groups",
        },
        {
            "platform": "twitter",
            "profile_url": "https://x.com/acmeintel",
            "display_name": "Alice Example",
        },
        {
            "platform": "twitter",
            "username": "search",
            "profile_url": "https://x.com/search?q=acme",
        },
        {
            "platform": "telegram",
            "username": "joinchat",
            "profile_url": "https://t.me/joinchat/acmeinvite",
        },
        {
            "platform": "telegram",
            "username": "acmerelay",
            "profile_url": "https://t.me/acmerelay",
        },
        {
            "platform": "instagram",
            "username": "reels",
            "profile_url": "https://www.instagram.com/reels/audio/123456/",
        },
        {
            "platform": "instagram",
            "username": "secopsgram",
            "profile_url": "https://www.instagram.com/secopsgram/",
        },
        {
            "platform": "youtube",
            "username": "watch",
            "profile_url": "https://www.youtube.com/watch?v=abc123",
        },
        {
            "platform": "youtube",
            "username": "bluevideo",
            "profile_url": "https://www.youtube.com/@bluevideo",
        },
        {
            "platform": "tiktok",
            "username": "tag",
            "profile_url": "https://www.tiktok.com/tag/security",
        },
        {
            "platform": "tiktok",
            "username": "sectok",
            "profile_url": "https://www.tiktok.com/@sectok/video/123456",
        },
        {
            "platform": "linkedin",
            "profile_url": "https://www.linkedin.com/in/alice-example",
            "display_name": "Alice Example",
        },
    ]

    gravatar_payload = {
        "display_name": "Alice Example",
        "location": "Singapore",
        "profile_url": "https://profiles.alice-example.net/about",
        "accounts": [
            {
                "domain": "github",
                "username": "acmealice",
                "url": "https://github.com/acmealice",
                "verified": True,
            }
        ],
        "urls": [{"title": "blog", "value": "https://research.alice-example.net/blog"}],
        "im_accounts": [{"service": "signal", "username": "alice.signal"}],
        "phone_numbers": [{"value": "+15557654321"}],
        "emails": [{"value": "alice.ops@acme.example"}],
    }

    rows = [
        _row("security@acme.example", "epieos", epieos_payload),
        _row("security@acme.example", "gravatar", gravatar_payload),
    ]

    candidates: list[SeedCandidate] = []
    for row in rows:
        candidates.extend(engine._social_profile_row_candidates(row, {}))

    seeds = _seed_index(candidates)
    relations = _relation_set(candidates)

    # Real handles promoted.
    for handle in (
        "acmehunter",
        "alice-example",
        "acmeintel",
        "acmerelay",
        "secopsgram",
        "bluevideo",
        "sectok",
        # Gravatar accounts[] + im_accounts[]
        "acmealice",
        "alice.signal",
    ):
        assert (handle, "username") in seeds, handle

    # Reserved / generic tokens must not be promoted.
    for reserved in (
        "marketplace",
        "groups",
        "search",
        "joinchat",
        "reels",
        "watch",
        "tag",
    ):
        assert (reserved, "username") not in seeds

    # Gravatar summary produced the name, email, phone, and blog URL pivots.
    assert ("Alice Example", "name") in seeds
    assert ("alice.ops@acme.example", "email") in seeds
    assert ("+15557654321", "phone") in seeds
    assert ("https://research.alice-example.net/blog", "url") in seeds

    # Every promoted pivot links back to the security@ anchor via same_entity.
    for pivot in ("acmehunter", "acmealice", "alice.ops@acme.example"):
        assert (
            "security@acme.example",
            pivot,
            "same_entity",
        ) in relations, pivot
