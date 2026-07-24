"""
forge/utils/intel/social_scraper.py
Canonical: forge/phase2/epieos.py  —  Module 2-G

Epieos social account linkage: email → Google/Apple/Gravatar/social profiles.

OPSEC (PRD §12.3.7):
  - Every query is logged by Epieos infrastructure — treat as attributed.
  - Session-per-target: fresh AsyncClient per email to prevent session correlation.
  - Proxy isolation: --proxy routes traffic independently from engagement infra.
  - Results AES-256-GCM encrypted at rest (engagement key).
  - Rate: 1 req/s minimum; no bulk/concurrent queries.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from urllib.parse import parse_qs, unquote, urlparse

from forge.utils.intel.audit_log import insert_audit_log
from forge.opsec.scope_gate import email_address_in_scope
from forge.utils.intel.social_profile_hosts import (
    epieos_host_matches as _epieos_host_matches,
    epieos_is_federated_instance_candidate_host as _shared_federated_instance_candidate_host,
    epieos_is_mastodon_like_host as _is_mastodon_like_host,
    epieos_is_stack_exchange_profile_host as _shared_stack_exchange_profile_host,
    epieos_is_supported_profile_host as _shared_supported_profile_host,
    epieos_profile_alias_host_matches as _shared_profile_alias_host_matches,
    epieos_stack_exchange_nested_user_payload as _shared_stack_exchange_nested_user_payload,
)

try:
    from curl_cffi.requests import AsyncSession  # type: ignore[import]
except ImportError:
    AsyncSession = None

_LOG = logging.getLogger(__name__)
try:
    from forge.opsec.crypto import encrypt_string
except Exception:
    encrypt_string = None

_EPIEOS_URL = "https://epieos.com/api/"
_RATE = 1.0
_TIMEOUT = 30
_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

def _int_env(name: str, default: int, *, minimum: int, maximum: int) -> int:
    raw_value = os.environ.get(name, "").strip()
    if not raw_value:
        return default
    try:
        parsed = int(raw_value)
    except ValueError:
        return default
    return max(minimum, min(maximum, parsed))


def _epieos_max_concurrency_default() -> int:
    """Default attributed Epieos lookups to one target at a time."""
    return _int_env(
        "FORGE_EPIEOS_MAX_CONCURRENCY",
        1,
        minimum=1,
        maximum=4,
    )


_EPIEOS_PROFILE_URL_ALIAS_KEYS = (
    "@id",
    "html_url",
    "htmlUrl",
    "profileURL",
    "profile_link",
    "profileLink",
    "profile_href",
    "profileHref",
    "profile_uri",
    "profileUri",
    "profileURI",
    "public_url",
    "publicUrl",
    "publicURL",
    "account_url",
    "accountUrl",
    "accountURL",
    "app_url",
    "appUrl",
    "appURL",
    "app_link",
    "appLink",
    "appLINK",
    "identity_url",
    "identityUrl",
    "identityURL",
    "deep_link",
    "deepLink",
    "deepLINK",
    "deeplink",
    "same_as",
    "sameAs",
    "uri",
    "mobile_url",
    "mobileUrl",
    "mobileURL",
    "native_url",
    "nativeUrl",
    "nativeURL",
    "universal_link",
    "universalLink",
    "universalLINK",
    "web_url",
    "webUrl",
    "permalink",
    "permalink_url",
    "permalinkUrl",
    "canonical_url",
    "canonicalUrl",
    "company_url",
    "companyUrl",
    "companyURL",
    "organization_url",
    "organizationUrl",
    "organizationURL",
    "employer_url",
    "employerUrl",
    "employerURL",
    "school_url",
    "schoolUrl",
    "schoolURL",
    "institution_url",
    "institutionUrl",
    "institutionURL",
    "verified_url",
    "verifiedUrl",
    "verifiedURL",
    "verified_link",
    "verifiedLink",
    "verifiedLINK",
    "claimed_url",
    "claimedUrl",
    "claimedURL",
    "claimed_link",
    "claimedLink",
    "claimedLINK",
    "proof_url",
    "proofUrl",
    "proofURL",
    "proof_link",
    "proofLink",
    "proofLINK",
    "identity_proof",
    "identityProof",
    "identifier",
    "identifiers",
    "rel_me",
    "relMe",
)

_EPIEOS_DISCOVERED_URL_FIELD_KEYS = (
    "urls",
    "links",
    "websites",
    "profiles",
    "bio_links",
    "bioLinks",
    "urls_in_bio",
    "urlsInBio",
    "links_in_bio",
    "linksInBio",
    "social_links",
    "socialLinks",
    "profile_links",
    "profileLinks",
    "profile_urls",
    "profileUrls",
    "external_links",
    "externalLinks",
    "external_urls",
    "externalUrls",
    "contact_links",
    "contactLinks",
    "email_links",
    "emailLinks",
    "phone_links",
    "phoneLinks",
    "same_as",
    "sameAs",
    "same_as_urls",
    "sameAsUrls",
    "public_urls",
    "publicUrls",
    "account_urls",
    "accountUrls",
    "app_urls",
    "appUrls",
    "appURLs",
    "app_links",
    "appLinks",
    "identity_urls",
    "identityUrls",
    "deep_links",
    "deepLinks",
    "deeplinks",
    "mobile_urls",
    "mobileUrls",
    "mobileURLs",
    "mobile_links",
    "mobileLinks",
    "mobileLINKS",
    "native_urls",
    "nativeUrls",
    "nativeURLs",
    "native_links",
    "nativeLinks",
    "nativeLINKS",
    "universal_links",
    "universalLinks",
    "universalLINKS",
    "web_urls",
    "webUrls",
    "website",
    "website_url",
    "websiteUrl",
    "websiteURL",
    "website_urls",
    "websiteUrls",
    "site_url",
    "siteUrl",
    "siteURL",
    "homepage",
    "homepage_url",
    "homepageUrl",
    "homepageURL",
    "home_page",
    "homePage",
    "home_url",
    "homeUrl",
    "homeURL",
    "blog",
    "blog_url",
    "blogUrl",
    "blog_urls",
    "blogUrls",
    "homepage_urls",
    "homepageUrls",
    "company_urls",
    "companyUrls",
    "organization_urls",
    "organizationUrls",
    "employer_urls",
    "employerUrls",
    "school_urls",
    "schoolUrls",
    "institution_urls",
    "institutionUrls",
    "verified_url",
    "verifiedUrl",
    "verifiedURL",
    "verified_link",
    "verifiedLink",
    "verifiedLINK",
    "verified_links",
    "verifiedLinks",
    "verified_urls",
    "verifiedUrls",
    "claimed_url",
    "claimedUrl",
    "claimedURL",
    "claimed_link",
    "claimedLink",
    "claimedLINK",
    "claimed_links",
    "claimedLinks",
    "claimed_urls",
    "claimedUrls",
    "proofs",
    "proof_url",
    "proofUrl",
    "proofURL",
    "proof_link",
    "proofLink",
    "proofLINK",
    "proof_links",
    "proofLinks",
    "proof_urls",
    "proofUrls",
    "identity_proof",
    "identityProof",
    "identity_proofs",
    "identityProofs",
    "verified_accounts",
    "verifiedAccounts",
    "claimed_accounts",
    "claimedAccounts",
    "verified_profiles",
    "verifiedProfiles",
    "claimed_profiles",
    "claimedProfiles",
    "verification_links",
    "verificationLinks",
    "verification_urls",
    "verificationUrls",
    "rel_me",
    "relMe",
    "rel_me_links",
    "relMeLinks",
    "rel_me_urls",
    "relMeUrls",
)

_EPIEOS_ACCOUNT_CONTAINER_KEYS = (
    "accounts",
    "account",
    "social_accounts",
    "socialAccounts",
    "connected_accounts",
    "connectedAccounts",
    "external_accounts",
    "externalAccounts",
    "linked_accounts",
    "linkedAccounts",
    "account_links",
    "accountLinks",
    "identity_links",
    "identityLinks",
    "linked_identities",
    "linkedIdentities",
    "verified_accounts",
    "verifiedAccounts",
    "claimed_accounts",
    "claimedAccounts",
    "verified_profiles",
    "verifiedProfiles",
    "claimed_profiles",
    "claimedProfiles",
    "identities",
)

_EPIEOS_ROOT_PROFILE_CONTAINER_KEYS = (
    "profile",
    "profiles",
    "result",
    "results",
    "record",
    "records",
    "item",
    "items",
    "match",
    "matches",
    "data",
    "social_profiles",
    "socialProfiles",
    *_EPIEOS_ACCOUNT_CONTAINER_KEYS,
)

_EPIEOS_IDENTITY_CLAIM_CONTAINER_KEYS = (
    "claims",
    "userinfo",
    "userInfo",
    "user_info",
)
_EPIEOS_IDENTITY_CLAIM_CONTAINER_KEY_SET = {
    key.lower() for key in _EPIEOS_IDENTITY_CLAIM_CONTAINER_KEYS
}

_EPIEOS_PLATFORM_FIELD_KEYS = (
    "platform",
    "provider",
    "provider_name",
    "providerName",
    "service",
    "service_name",
    "serviceName",
    "source",
    "network",
    "site",
)

_EPIEOS_CONTACT_CONTAINER_KEYS = (
    "contact",
    "contacts",
    "contact_info",
    "contactInfo",
    "contact_details",
    "contactDetails",
    "contact_data",
    "contactData",
    "contact_methods",
    "contactMethods",
    "contact_point",
    "contactPoint",
    "contact_points",
    "contactPoints",
    "point_of_contact",
    "pointOfContact",
    "points_of_contact",
    "pointsOfContact",
)

_EPIEOS_RELATED_PERSON_CONTAINER_KEYS = (
    "knows",
    "colleague",
    "colleagues",
    "coworker",
    "coworkers",
    "employee",
    "employees",
    "founder",
    "founders",
    "staff",
    "team",
    "team_member",
    "teamMember",
    "team_members",
    "teamMembers",
)

_EPIEOS_WORK_HISTORY_CONTAINER_KEYS = (
    "work_experience",
    "workExperience",
    "work_experiences",
    "workExperiences",
    "employment",
    "employments",
    "employment_history",
    "employmentHistory",
    "experience",
    "experiences",
    "position",
    "positions",
    "job",
    "jobs",
    "job_history",
    "jobHistory",
    "career",
    "careers",
    "education",
    "educations",
    "education_history",
    "educationHistory",
    "school",
    "schools",
    "institution",
    "institutions",
)

_EPIEOS_WORK_HISTORY_ORGANIZATION_FIELD_KEYS = (
    "company",
    "companies",
    "company_name",
    "companyName",
    "organization",
    "organizations",
    "organization_name",
    "organizationName",
    "org",
    "orgs",
    "employer",
    "employers",
    "employer_name",
    "employerName",
    "school",
    "schools",
    "school_name",
    "schoolName",
    "institution",
    "institutions",
    "institution_name",
    "institutionName",
)

_EPIEOS_DOMAIN_FIELD_KEYS = (
    "domain",
    "domains",
    "domain_name",
    "domainName",
    "domain_names",
    "domainNames",
    "verified_domain",
    "verifiedDomain",
    "verified_domains",
    "verifiedDomains",
    "claimed_domain",
    "claimedDomain",
    "claimed_domains",
    "claimedDomains",
    "associated_domain",
    "associatedDomain",
    "associated_domains",
    "associatedDomains",
    "host",
    "hosts",
    "hostname",
    "hostName",
    "hostnames",
    "hostNames",
    "fqdn",
    "fqdns",
    "website_domain",
    "websiteDomain",
    "website_domains",
    "websiteDomains",
    "company_domain",
    "companyDomain",
    "company_domains",
    "companyDomains",
    "organization_domain",
    "organizationDomain",
    "organization_domains",
    "organizationDomains",
    "employer_domain",
    "employerDomain",
    "employer_domains",
    "employerDomains",
    "school_domain",
    "schoolDomain",
    "school_domains",
    "schoolDomains",
    "institution_domain",
    "institutionDomain",
    "institution_domains",
    "institutionDomains",
)

_EPIEOS_TEXT_FIELD_KEYS = (
    "bio",
    "biography",
    "about",
    "about_me",
    "aboutMe",
    "description",
    "public_description",
    "publicDescription",
    "profile_description",
    "profileDescription",
    "headline",
    "summary",
    "tagline",
    "intro",
    "blurb",
    "notes",
    *_EPIEOS_CONTACT_CONTAINER_KEYS,
    *_EPIEOS_RELATED_PERSON_CONTAINER_KEYS,
    *_EPIEOS_WORK_HISTORY_CONTAINER_KEYS,
    "contact_text",
    "contactText",
)

_EPIEOS_NESTED_PROFILE_KEYS = (
    "profile",
    "account",
    "user",
    "identity",
    "person",
    "member",
    "author",
    "owner",
    "contact_point",
    "contactPoint",
    "point_of_contact",
    "pointOfContact",
)

_EPIEOS_HANDLE_FIELD_KEYS = (
    "preferred_username",
    "preferredUsername",
    "preferredUserName",
    "username",
    "handle",
    "user_handle",
    "userHandle",
    "account_handle",
    "accountHandle",
    "display_handle",
    "displayHandle",
    "profile_handle",
    "profileHandle",
    "account_name",
    "accountName",
    "profile_name",
    "profileName",
    "screen_name",
    "screenName",
    "unique_id",
    "uniqueId",
    "user_name",
    "userName",
    "vanity_name",
    "vanityName",
    "public_identifier",
    "publicIdentifier",
    "acct",
    "login",
    "slug",
    "namespace",
    "workspace",
    "workspace_slug",
    "custom_url",
    "customUrl",
    "channel_id",
    "channelId",
    "player_name",
    "profile_slug",
    "profileSlug",
    "vanity_url",
    "vanityUrl",
    "orcid",
    "orcid_id",
    "orcidId",
    "shortname",
    "nickname",
)

_EPIEOS_EMAIL_RE = re.compile(r"[a-zA-Z0-9_.+\-]+@[a-zA-Z0-9\-]+(?:\.[a-zA-Z]{2,})+")
_EPIEOS_PHONE_RE = re.compile(r"(?<![\w+])(\+\d[\d().\-\s]{5,}\d)(?!\w)")
_EPIEOS_PHONE_NORMALIZE_RE = re.compile(r"[()\s.\-]+")
_EPIEOS_DOMAIN_RE = re.compile(
    r"^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(?:\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)+$",
    re.IGNORECASE,
)
_EPIEOS_EMAIL_FIELD_KEYS = (
    "email",
    "email_address",
    "emailAddress",
    "mail",
    "mail_address",
    "mailAddress",
    "primary_email",
    "primaryEmail",
    "work_email",
    "workEmail",
    "business_email",
    "businessEmail",
    "personal_email",
    "personalEmail",
    "alternate_email",
    "alternateEmail",
    "alt_email",
    "altEmail",
    "contact_email",
    "contactEmail",
)
_EPIEOS_PHONE_FIELD_KEYS = (
    "phone",
    "phone_number",
    "phoneNumber",
    "canonical_form",
    "canonicalForm",
    "e164",
    "e_164",
    "msisdn",
    "phone_display",
    "phoneDisplay",
    "phone_formatted",
    "phoneFormatted",
    "formatted_phone",
    "formattedPhone",
    "telephone",
    "tel",
    "mobile",
    "mobile_phone",
    "mobilePhone",
    "contact_phone",
    "contactPhone",
    "business_phone",
    "businessPhone",
    "work_phone",
    "workPhone",
    "office_phone",
    "officePhone",
    "whatsapp",
    "whatsapp_number",
    "whatsappNumber",
)

_EPIEOS_TWITTER_PLATFORM_NAMES = {"twitter", "x", "twitter_x", "x_twitter"}

_EPIEOS_PLATFORM_PROFILE_HOSTS = {
    "500px": ("500px.com",),
    "500px.com": ("500px.com",),
    "academia": ("academia.edu",),
    "academia.edu": ("academia.edu",),
    "artstation": ("artstation.com",),
    "artstation.com": ("artstation.com",),
    "aboutme": ("about.me",),
    "about.me": ("about.me",),
    "all_my_links": ("allmylinks.com",),
    "allmylinks": ("allmylinks.com",),
    "allmylinks.com": ("allmylinks.com",),
    "angellist": ("angel.co", "angellist.com"),
    "angellist_company": ("angel.co", "angellist.com"),
    "angel.co": ("angel.co", "angellist.com"),
    "angel_co_company": ("angel.co", "angellist.com"),
    "bandcamp": ("bandcamp.com",),
    "beacons": ("beacons.ai",),
    "bento": ("bento.me",),
    "bento.me": ("bento.me",),
    "bento_me": ("bento.me",),
    "bentome": ("bento.me",),
    "behance": ("behance.net",),
    "biolink": ("bio.link",),
    "bio.link": ("bio.link",),
    "biosite": ("bio.site",),
    "bio.site": ("bio.site",),
    "bitbucket": ("bitbucket.org",),
    "bluesky": ("bsky.app", "bsky.social"),
    "bsky": ("bsky.app", "bsky.social"),
    "bugcrowd": ("bugcrowd.com",),
    "buymeacoffee": ("buymeacoffee.com",),
    "buy_me_a_coffee": ("buymeacoffee.com",),
    "calcom": ("cal.com",),
    "cal.com": ("cal.com",),
    "calendly": ("calendly.com",),
    "campsite": ("campsite.bio",),
    "campsitebio": ("campsite.bio",),
    "campsite.bio": ("campsite.bio",),
    "carrd": ("carrd.co",),
    "codeberg": ("codeberg.org",),
    "codepen": ("codepen.io",),
    "crates": ("crates.io",),
    "cratesio": ("crates.io",),
    "crates_io": ("crates.io",),
    "credly": ("credly.com",),
    "devto": ("dev.to",),
    "dev.to": ("dev.to",),
    "deviantart": ("deviantart.com",),
    "deviantart.com": ("deviantart.com",),
    "discord": ("discord.com", "discord.gg", "discordapp.com"),
    "discord_user": ("discord.com", "discordapp.com"),
    "discord_server": ("discord.com", "discord.gg", "discordapp.com"),
    "discord_guild": ("discord.com", "discord.gg", "discordapp.com"),
    "discord_invite": ("discord.com", "discord.gg", "discordapp.com"),
    "docker": ("hub.docker.com",),
    "docker_org": ("hub.docker.com",),
    "dockerhub": ("hub.docker.com",),
    "dockerhub_org": ("hub.docker.com",),
    "docker_hub": ("hub.docker.com",),
    "docker_hub_org": ("hub.docker.com",),
    "dribbble": ("dribbble.com",),
    "facebook": ("facebook.com",),
    "facebook_page": ("facebook.com",),
    "figshare": ("figshare.com",),
    "flickr": ("flickr.com",),
    "github": ("github.com",),
    "github_gist": ("gist.github.com",),
    "githubgist": ("gist.github.com",),
    "github_org": ("github.com",),
    "github_organization": ("github.com",),
    "github_sponsors": ("github.com",),
    "githubsponsors": ("github.com",),
    "gist": ("gist.github.com",),
    "gitlab": ("gitlab.com",),
    "gitlab_group": ("gitlab.com",),
    "gitlab_org": ("gitlab.com",),
    "gitlab_organization": ("gitlab.com",),
    "google": ("accounts.google.com",),
    "google_scholar": ("scholar.google.com",),
    "googlescholar": ("scholar.google.com",),
    "gravatar": ("gravatar.com",),
    "hackernews": ("news.ycombinator.com",),
    "hacker_news": ("news.ycombinator.com",),
    "hn": ("news.ycombinator.com",),
    "scholar": ("scholar.google.com",),
    "hackerone": ("hackerone.com",),
    "hashnode": ("hashnode.com",),
    "huggingface": ("huggingface.co",),
    "hugging_face": ("huggingface.co",),
    "huggingface_org": ("huggingface.co",),
    "huggingface_organization": ("huggingface.co",),
    "hexpm": ("hex.pm",),
    "hex_pm": ("hex.pm",),
    "hoo.be": ("hoo.be",),
    "hoobe": ("hoo.be",),
    "instagram": ("instagram.com",),
    "intigriti": ("intigriti.com",),
    "kaggle": ("kaggle.com",),
    "keybase": ("keybase.io",),
    "kofi": ("ko-fi.com",),
    "ko-fi": ("ko-fi.com",),
    "ko_fi": ("ko-fi.com",),
    "launchpad": ("launchpad.net",),
    "lastfm": ("last.fm",),
    "last.fm": ("last.fm",),
    "last_fm": ("last.fm",),
    "letterboxd": ("letterboxd.com",),
    "linkedin": ("linkedin.com",),
    "linkedin_company": ("linkedin.com",),
    "linktree": ("linktr.ee",),
    "linktr.ee": ("linktr.ee",),
    "lnkbio": ("lnk.bio",),
    "lnk.bio": ("lnk.bio",),
    "liberapay": ("liberapay.com",),
    "mastodon": (),
    "medium": ("medium.com",),
    "matrix": ("matrix.to",),
    "matrix.org": ("matrix.to",),
    "matrix_org": ("matrix.to",),
    "matrix.to": ("matrix.to",),
    "matrix_to": ("matrix.to",),
    "mixcloud": ("mixcloud.com",),
    "muckrack": ("muckrack.com",),
    "muck_rack": ("muckrack.com",),
    "muckrack.com": ("muckrack.com",),
    "milkshake": ("msha.ke",),
    "mshake": ("msha.ke",),
    "msha": ("msha.ke",),
    "npm": ("npmjs.com",),
    "npm_org": ("npmjs.com",),
    "npmjs": ("npmjs.com",),
    "npmjs_org": ("npmjs.com",),
    "nuget": ("nuget.org",),
    "nostr": (
        "nostr.com",
        "nostrudel.ninja",
        "njump.me",
        "primal.net",
        "iris.to",
        "snort.social",
        "yakihonne.com",
    ),
    "nostr_protocol": (
        "nostr.com",
        "nostrudel.ninja",
        "njump.me",
        "primal.net",
        "iris.to",
        "snort.social",
        "yakihonne.com",
    ),
    "openbugbounty": ("openbugbounty.org",),
    "open_bug_bounty": ("openbugbounty.org",),
    "opencollective": ("opencollective.com",),
    "open_collective": ("opencollective.com",),
    "orcid": ("orcid.org",),
    "packagist": ("packagist.org",),
    "patreon": ("patreon.com",),
    "pinterest": ("pinterest.com",),
    "producthunt": ("producthunt.com",),
    "product_hunt": ("producthunt.com",),
    "quora": ("quora.com",),
    "quora.com": ("quora.com",),
    "pypi": ("pypi.org",),
    "pypi_org": ("pypi.org",),
    "pypi_organization": ("pypi.org",),
    "reddit": ("reddit.com",),
    "readcv": ("read.cv",),
    "read.cv": ("read.cv",),
    "replit": ("replit.com",),
    "codesandbox": ("codesandbox.io",),
    "code_sandbox": ("codesandbox.io",),
    "devpost": ("devpost.com",),
    "researchgate": ("researchgate.net",),
    "research_gate": ("researchgate.net",),
    "semantic_scholar": ("semanticscholar.org",),
    "semanticscholar": ("semanticscholar.org",),
    "rubygems": ("rubygems.org",),
    "ruby_gems": ("rubygems.org",),
    "soloto": ("solo.to",),
    "solo.to": ("solo.to",),
    "speakerdeck": ("speakerdeck.com",),
    "speaker_deck": ("speakerdeck.com",),
    "sourceforge": ("sourceforge.net",),
    "sourceforge_net": ("sourceforge.net",),
    "snap": ("snapchat.com",),
    "snapchat": ("snapchat.com",),
    "slideshare": ("slideshare.net",),
    "slide_share": ("slideshare.net",),
    "soundcloud": ("soundcloud.com",),
    "sound_cloud": ("soundcloud.com",),
    "spotify": ("open.spotify.com", "spotify.com"),
    "strava": ("strava.com",),
    "strava.com": ("strava.com",),
    "sourcehut": ("sr.ht",),
    "srht": ("sr.ht",),
    "sr.ht": ("sr.ht",),
    "stackoverflow": ("stackoverflow.com", "stackexchange.com"),
    "stack_overflow": ("stackoverflow.com", "stackexchange.com"),
    "stackexchange": ("stackoverflow.com", "stackexchange.com"),
    "stack_exchange": ("stackoverflow.com", "stackexchange.com"),
    "steam": ("steamcommunity.com",),
    "steamcommunity": ("steamcommunity.com",),
    "steam_community": ("steamcommunity.com",),
    "substack": ("substack.com",),
    "taplink": ("taplink.cc", "taplink.ws"),
    "taplink_cc": ("taplink.cc",),
    "taplink_ws": ("taplink.ws",),
    "telegram": ("t.me", "telegram.me"),
    "telegramme": ("t.me", "telegram.me"),
    "threads": ("threads.net", "threads.com"),
    "tiktok": ("tiktok.com",),
    "tryhackme": ("tryhackme.com",),
    "thm": ("tryhackme.com",),
    "twitch": ("twitch.tv",),
    "twitter": ("x.com", "twitter.com"),
    "twitter_x": ("x.com", "twitter.com"),
    "unsplash": ("unsplash.com",),
    "unsplash.com": ("unsplash.com",),
    "vimeo": ("vimeo.com",),
    "wellfound": ("wellfound.com",),
    "wellfound_company": ("wellfound.com",),
    "x": ("x.com", "twitter.com"),
    "x_twitter": ("x.com", "twitter.com"),
    "yeswehack": ("yeswehack.com",),
    "youtube": ("youtube.com", "youtu.be"),
    "zenodo": ("zenodo.org",),
}

_EPIEOS_COMPANY_PLATFORM_NAMES = {
    "docker_hub_org",
    "docker_org",
    "dockerhub_org",
    "angel_co_company",
    "angellist_company",
    "facebook_page",
    "github_org",
    "github_organization",
    "gitlab_group",
    "gitlab_org",
    "gitlab_organization",
    "huggingface_org",
    "huggingface_organization",
    "linkedin_company",
    "npm_org",
    "npmjs_org",
    "pypi_org",
    "pypi_organization",
    "wellfound_company",
}
_EPIEOS_MATRIX_PLATFORM_NAMES = {
    "matrix",
    "matrix_org",
    "matrix.org",
    "matrix_to",
    "matrix.to",
}
_EPIEOS_FEDERATED_PLATFORM_NAMES = {
    "activitypub",
    "activity_pub",
    "fediverse",
    "mastodon",
    "webfinger",
}
_EPIEOS_NOSTR_PLATFORM_NAMES = {
    "nostr",
    "nostr_protocol",
}
_EPIEOS_DISCORD_PLATFORM_NAMES = {
    "discord",
    "discordapp",
    "discord_user",
    "discord_server",
    "discord_guild",
    "discord_invite",
}

_INSTAGRAM_RESERVED_PROFILE_PATHS = {
    "about",
    "accounts",
    "api",
    "challenge",
    "developer",
    "direct",
    "directory",
    "emails",
    "explore",
    "legal",
    "oauth",
    "p",
    "press",
    "privacy",
    "reel",
    "reels",
    "s",
    "tv",
}
_KEYBASE_RESERVED_PROFILE_PATHS = {
    "account",
    "blog",
    "business",
    "chat",
    "crypto",
    "devices",
    "docs",
    "download",
    "downloads",
    "files",
    "help",
    "install",
    "kbfs",
    "login",
    "logout",
    "phone-apps",
    "private",
    "public",
    "security",
    "settings",
    "signup",
    "team",
    "teams",
    "wallet",
}
_TELEGRAM_RESERVED_PROFILE_PATHS = {
    "addstickers",
    "c",
    "joinchat",
    "login",
    "s",
    "share",
}
_TIKTOK_RESERVED_PROFILE_HANDLES = {
    "about",
    "business",
    "creators",
    "discover",
    "embed",
    "following",
    "foryou",
    "legal",
    "live",
    "login",
    "music",
    "privacy",
    "safety",
    "search",
    "share",
    "signup",
    "tag",
    "trending",
    "upload",
}
_YOUTUBE_RESERVED_PROFILE_HANDLES = {
    "about",
    "c",
    "channel",
    "clip",
    "creators",
    "embed",
    "feed",
    "gaming",
    "hashtag",
    "jobs",
    "live",
    "logout",
    "music",
    "playlist",
    "podcasts",
    "post",
    "premium",
    "privacy",
    "redirect",
    "results",
    "shorts",
    "signin",
    "terms",
    "upload",
    "user",
    "watch",
}
_DEVTO_RESERVED_PROFILE_PATHS = {
    "_",
    "about",
    "account",
    "api",
    "connect",
    "contact",
    "dashboard",
    "latest",
    "login",
    "new",
    "notifications",
    "pod",
    "privacy",
    "readinglist",
    "search",
    "settings",
    "signin",
    "signup",
    "t",
    "tags",
    "top",
    "videos",
}
_DEVIANTART_RESERVED_PROFILE_HANDLES = {
    "about",
    "browse",
    "challenge",
    "challenges",
    "collections",
    "community",
    "core-membership",
    "daily-deviations",
    "deviants",
    "forum",
    "groups",
    "help",
    "jobs",
    "join",
    "login",
    "marketplace",
    "notifications",
    "popular",
    "prints",
    "privacy",
    "search",
    "settings",
    "shop",
    "tag",
    "tags",
    "users",
}
_DISCORD_RESERVED_PROFILE_HANDLES = {
    "app",
    "apps",
    "brand",
    "channels",
    "company",
    "developers",
    "discovery",
    "download",
    "guild-discovery",
    "invite",
    "login",
    "oauth2",
    "privacy",
    "register",
    "safety",
    "settings",
    "store",
    "terms",
    "users",
}
_DEVIANTART_RESERVED_SUBDOMAINS = {
    "api",
    "assets",
    "backend",
    "blog",
    "cdn",
    "help",
    "images",
    "portfolio",
    "shop",
    "static",
    "support",
    "www",
}
_TWITTER_RESERVED_PROFILE_PATHS = {
    "compose",
    "explore",
    "hashtag",
    "home",
    "i",
    "intent",
    "login",
    "messages",
    "notifications",
    "privacy",
    "search",
    "settings",
    "share",
    "signup",
    "tos",
}
_BITBUCKET_RESERVED_PROFILE_PATHS = {
    "account",
    "dashboard",
    "explore",
    "notifications",
    "plans-and-pricing",
    "product",
    "projects",
    "repositories",
    "search",
    "site",
    "workspace",
}
_CODEBERG_RESERVED_PROFILE_PATHS = {
    "about",
    "api",
    "assets",
    "explore",
    "issues",
    "login",
    "notifications",
    "org",
    "organizations",
    "pulls",
    "repo",
    "repos",
    "search",
    "settings",
    "user",
}
_GITHUB_RESERVED_PROFILE_PATHS = {
    "about",
    "apps",
    "collections",
    "contact",
    "customer-stories",
    "dashboard",
    "developers",
    "enterprise",
    "events",
    "explore",
    "features",
    "issues",
    "login",
    "logout",
    "marketplace",
    "new",
    "notifications",
    "orgs",
    "pricing",
    "pulls",
    "readme",
    "search",
    "security",
    "settings",
    "signup",
    "site",
    "sponsors",
    "team",
    "topics",
    "trending",
    "users",
}
_GITLAB_RESERVED_PROFILE_PATHS = {
    "-",
    "admin",
    "dashboard",
    "explore",
    "groups",
    "help",
    "projects",
    "search",
    "users",
}
_HASHNODE_RESERVED_PROFILE_PATHS = {
    "about",
    "blog",
    "careers",
    "changelog",
    "community",
    "contact",
    "explore",
    "featured",
    "login",
    "onboard",
    "pricing",
    "privacy",
    "search",
    "settings",
    "signup",
    "teams",
    "terms",
}
_MEDIUM_RESERVED_PROFILE_PATHS = {
    "about",
    "archive",
    "creators",
    "following",
    "followers",
    "help",
    "latest",
    "m",
    "me",
    "membership",
    "policy",
    "search",
    "signin",
    "sign-in",
    "signup",
    "sign-up",
    "tag",
    "topic",
    "topics",
    "u",
}
_MEDIUM_RESERVED_SUBDOMAINS = {
    "cdn-images",
    "cdn-images-1",
    "cdn-images-2",
    "miro",
}
_SUBSTACK_RESERVED_PROFILE_PATHS = {
    "about",
    "account",
    "app",
    "browse",
    "discover",
    "help",
    "home",
    "inbox",
    "login",
    "notes",
    "podcasts",
    "privacy",
    "profile",
    "publish",
    "read",
    "search",
    "settings",
    "signin",
    "signup",
}
_SUBSTACK_RESERVED_SUBDOMAINS = {
    "api",
    "app",
    "blog",
    "cdn",
    "help",
    "on",
    "resources",
    "static",
    "status",
    "support",
    "www",
}
_FLICKR_RESERVED_PHOTOS_PATHS = {
    "albums",
    "archive",
    "favorites",
    "faves",
    "friends",
    "map",
    "organize",
    "popular",
    "recent",
    "search",
    "tags",
}
_LETTERBOXD_RESERVED_PROFILE_PATHS = {
    "about",
    "account",
    "actor",
    "actors",
    "admin",
    "api",
    "crew",
    "director",
    "directors",
    "editors",
    "email",
    "films",
    "film",
    "genre",
    "genres",
    "help",
    "journal",
    "legal",
    "list",
    "lists",
    "login",
    "members",
    "news",
    "people",
    "popular",
    "privacy",
    "pro",
    "reviews",
    "search",
    "settings",
    "sign-in",
    "signin",
    "sign-up",
    "signup",
    "tag",
    "tags",
    "tmdb",
    "watchlist",
}
_MIXCLOUD_RESERVED_PROFILE_PATHS = {
    "about",
    "advertise",
    "categories",
    "community",
    "contact",
    "developers",
    "discover",
    "features",
    "help",
    "jobs",
    "join",
    "legal",
    "live",
    "login",
    "notifications",
    "plans",
    "pro",
    "privacy",
    "search",
    "settings",
    "signup",
    "terms",
    "upload",
}
_SLIDESHARE_RESERVED_PROFILE_PATHS = {
    "about",
    "category",
    "clipboards",
    "contact",
    "discover",
    "featured",
    "login",
    "mobile",
    "popular",
    "search",
    "signup",
    "upload",
}
_SOUNDCLOUD_RESERVED_PROFILE_PATHS = {
    "about",
    "charts",
    "discover",
    "for-artists",
    "go",
    "imprint",
    "jobs",
    "login",
    "messages",
    "mobile",
    "pages",
    "people",
    "playlists",
    "premium",
    "pro",
    "search",
    "settings",
    "signup",
    "stream",
    "terms-of-use",
    "upload",
    "you",
}
_SPEAKERDECK_RESERVED_PROFILE_PATHS = {
    "about",
    "browse",
    "c",
    "categories",
    "category",
    "explore",
    "features",
    "login",
    "p",
    "presentations",
    "search",
    "sign_in",
    "signin",
    "signup",
    "speakers",
}
_VIMEO_RESERVED_PROFILE_PATHS = {
    "about",
    "album",
    "blog",
    "categories",
    "channels",
    "features",
    "groups",
    "help",
    "join",
    "log_in",
    "login",
    "manage",
    "ondemand",
    "pricing",
    "search",
    "showcase",
    "staffpicks",
    "stock",
    "upload",
    "video",
    "watch",
}
_LINKTREE_RESERVED_PROFILE_PATHS = {
    "about",
    "admin",
    "blog",
    "discover",
    "explore",
    "help",
    "login",
    "marketplace",
    "pricing",
    "register",
    "signup",
    "sso",
}
_ALLMYLINKS_RESERVED_PROFILE_PATHS = {
    "about",
    "account",
    "blog",
    "contact",
    "explore",
    "help",
    "login",
    "privacy",
    "register",
    "settings",
    "signup",
    "support",
    "terms",
}
_BEACONS_RESERVED_PROFILE_PATHS = {
    "about",
    "auth",
    "blog",
    "brands",
    "creators",
    "discover",
    "explore",
    "login",
    "marketplace",
    "pricing",
    "sign-in",
    "signin",
    "signup",
    "terms",
}
_BENTO_RESERVED_PROFILE_PATHS = {
    "about",
    "app",
    "blog",
    "dashboard",
    "discover",
    "explore",
    "features",
    "help",
    "login",
    "pricing",
    "sign-in",
    "signin",
    "signup",
    "support",
    "templates",
    "terms",
}
_HOO_BE_RESERVED_PROFILE_PATHS = {
    "about",
    "app",
    "blog",
    "careers",
    "creators",
    "discover",
    "explore",
    "help",
    "login",
    "pricing",
    "sign-in",
    "signin",
    "signup",
    "support",
    "terms",
}
_BIO_LINK_RESERVED_PROFILE_PATHS = {
    "about",
    "blog",
    "discover",
    "login",
    "pricing",
    "signup",
}
_BIO_SITE_RESERVED_PROFILE_PATHS = {
    "about",
    "blog",
    "create",
    "discover",
    "help",
    "login",
    "pricing",
    "signup",
}
_LNK_BIO_RESERVED_PROFILE_PATHS = {
    "about",
    "login",
    "pricing",
    "signup",
}
_SOLO_TO_RESERVED_PROFILE_PATHS = {
    "about",
    "discover",
    "login",
    "pricing",
    "signup",
}
_CAMPSITE_BIO_RESERVED_PROFILE_PATHS = {
    "about",
    "admin",
    "app",
    "blog",
    "contact",
    "explore",
    "features",
    "help",
    "landing",
    "login",
    "pricing",
    "pro",
    "register",
    "resources",
    "signup",
    "support",
    "terms",
}
_TAPLINK_RESERVED_PROFILE_PATHS = {
    "about",
    "app",
    "blog",
    "contacts",
    "en",
    "features",
    "guide",
    "help",
    "login",
    "pricing",
    "signup",
    "support",
}
_MILKSHAKE_RESERVED_PROFILE_PATHS = {
    "about",
    "app",
    "blog",
    "download",
    "help",
    "login",
    "privacy",
    "signup",
    "support",
    "terms",
}
_CARRD_RESERVED_PROFILE_PATHS = {
    "about",
    "build",
    "dashboard",
    "docs",
    "login",
    "pricing",
    "signup",
    "sites",
    "templates",
}
_CALENDLY_RESERVED_PROFILE_PATHS = {
    "about",
    "app",
    "blog",
    "contact",
    "docs",
    "enterprise",
    "features",
    "integrations",
    "login",
    "pricing",
    "signup",
    "teams",
}
_CALCOM_RESERVED_PROFILE_PATHS = {
    "about",
    "apps",
    "blog",
    "contact",
    "docs",
    "enterprise",
    "features",
    "login",
    "marketplace",
    "pricing",
    "settings",
    "signup",
    "team",
    "teams",
}
_PRODUCTHUNT_RESERVED_PROFILE_PATHS = {
    "about",
    "advertise",
    "alternatives",
    "categories",
    "community",
    "jobs",
    "launches",
    "login",
    "news",
    "posts",
    "pricing",
    "products",
    "search",
    "signin",
    "signup",
    "topics",
    "trending",
}
_OPEN_COLLECTIVE_RESERVED_PROFILE_PATHS = {
    "about",
    "apply",
    "blog",
    "create",
    "discover",
    "docs",
    "explore",
    "faq",
    "login",
    "pricing",
    "search",
    "signin",
    "signup",
}
_LIBERAPAY_RESERVED_PROFILE_PATHS = {
    "about",
    "account",
    "create",
    "explore",
    "for",
    "login",
    "search",
    "teams",
    "tos",
    "wallet",
}
_PATREON_RESERVED_PROFILE_PATHS = {
    "about",
    "api",
    "c",
    "careers",
    "create",
    "creators",
    "explore",
    "home",
    "join",
    "login",
    "messages",
    "posts",
    "privacy",
    "search",
    "settings",
    "signup",
}
_KOFI_RESERVED_PROFILE_PATHS = {
    "about",
    "account",
    "api",
    "blog",
    "create",
    "explore",
    "home",
    "login",
    "privacy",
    "search",
    "signup",
    "support",
}
_BUYMEACOFFEE_RESERVED_PROFILE_PATHS = {
    "about",
    "api",
    "blog",
    "creators",
    "explore",
    "home",
    "login",
    "privacy",
    "search",
    "signup",
}
_HUGGINGFACE_RESERVED_PROFILE_PATHS = {
    "blog",
    "chat",
    "collections",
    "datasets",
    "docs",
    "enterprise",
    "join",
    "leaderboards",
    "login",
    "models",
    "new",
    "organizations",
    "papers",
    "pricing",
    "settings",
    "spaces",
    "tasks",
}
_NPM_RESERVED_PROFILE_HANDLES = {
    "about",
    "advisories",
    "browse",
    "docs",
    "features",
    "login",
    "org",
    "orgs",
    "package",
    "packages",
    "policies",
    "pricing",
    "products",
    "search",
    "settings",
    "signup",
    "teams",
}
_PYPI_RESERVED_PROFILE_HANDLES = {
    "account",
    "help",
    "manage",
    "project",
    "projects",
    "search",
    "security",
    "simple",
    "user",
}
_RUBYGEMS_RESERVED_PROFILE_HANDLES = {
    "gems",
    "pages",
    "profiles",
    "search",
    "sign_in",
    "sign_up",
    "stats",
}
_CRATES_RESERVED_PROFILE_HANDLES = {
    "categories",
    "crates",
    "keywords",
    "login",
    "me",
    "settings",
    "teams",
    "users",
}
_PACKAGIST_RESERVED_PROFILE_HANDLES = {
    "about",
    "explore",
    "packages",
    "search",
    "users",
}
_NUGET_RESERVED_PROFILE_HANDLES = {
    "downloads",
    "packages",
    "profiles",
    "signin",
    "signup",
    "stats",
    "users",
}
_OPENBUGBOUNTY_RESERVED_PROFILE_HANDLES = {
    "about",
    "blog",
    "faq",
    "login",
    "reports",
    "researchers",
    "search",
    "signup",
}
_HEXPM_RESERVED_PROFILE_HANDLES = {
    "api",
    "docs",
    "packages",
    "pricing",
    "users",
}
_ORCID_PROFILE_ID_RE = re.compile(r"\d{4}-\d{4}-\d{4}-\d{3}[\dXx]")
_GOOGLE_SCHOLAR_USER_ID_RE = re.compile(r"[A-Za-z0-9_-]{6,32}")
_ACADEMIA_RESERVED_PROFILE_HANDLES = {
    "about",
    "analytics",
    "attachments",
    "blog",
    "careers",
    "contact",
    "jobs",
    "login",
    "people",
    "privacy",
    "search",
    "settings",
    "signup",
    "terms",
}
_SEMANTIC_SCHOLAR_RESERVED_PROFILE_HANDLES = {
    "about",
    "api",
    "author",
    "authors",
    "blog",
    "corpus",
    "me",
    "paper",
    "product",
    "reader",
    "search",
}
_ZENODO_RESERVED_PROFILE_HANDLES = {
    "about",
    "account",
    "communities",
    "deposit",
    "help",
    "login",
    "me",
    "oauth",
    "records",
    "search",
    "signup",
    "stats",
    "users",
}
_FIGSHARE_RESERVED_PROFILE_HANDLES = {
    "about",
    "account",
    "articles",
    "authors",
    "browse",
    "categories",
    "features",
    "help",
    "login",
    "search",
    "signup",
}
_RESEARCHGATE_RESERVED_PROFILE_HANDLES = {
    "about",
    "jobs",
    "login",
    "publication",
    "publications",
    "profile",
    "search",
    "signup",
    "topics",
}
_CREDLY_RESERVED_PROFILE_HANDLES = {
    "badges",
    "earner",
    "earners",
    "login",
    "organizations",
    "partners",
    "sign_in",
    "sign_up",
    "users",
}
_BEHANCE_RESERVED_PROFILE_HANDLES = {
    "about",
    "adobe-live",
    "assets",
    "blog",
    "collections",
    "contact",
    "creativeminds",
    "features",
    "galleries",
    "gallery",
    "joblist",
    "jobs",
    "login",
    "onboarding",
    "prosite",
    "search",
    "signup",
}
_DRIBBBLE_RESERVED_PROFILE_HANDLES = {
    "about",
    "account",
    "boosted-shots",
    "designers",
    "features",
    "jobs",
    "login",
    "pro",
    "search",
    "session",
    "shots",
    "signup",
    "stories",
    "teams",
}
_WELLFOUND_RESERVED_PROFILE_HANDLES = {
    "about",
    "companies",
    "company",
    "jobs",
    "login",
    "recruit",
    "remote",
    "search",
    "signup",
    "startups",
    "talent",
}
_ANGELLIST_RESERVED_PROFILE_HANDLES = {
    "about",
    "companies",
    "company",
    "jobs",
    "login",
    "people",
    "recruit",
    "search",
    "signup",
    "startups",
    "talent",
}
_BUGCROWD_RESERVED_PROFILE_HANDLES = {
    "about",
    "directory",
    "engagements",
    "login",
    "programs",
    "researcher",
    "researchers",
    "resources",
    "sign-in",
    "signup",
    "user",
    "users",
}
_HACKERONE_RESERVED_PROFILE_HANDLES = {
    "about",
    "bugs",
    "directory",
    "hackers",
    "leaderboard",
    "login",
    "opportunities",
    "programs",
    "resources",
    "security",
    "signup",
    "users",
}
_INTIGRITI_RESERVED_PROFILE_HANDLES = {
    "companies",
    "login",
    "profile",
    "programs",
    "researcher",
    "researchers",
    "signup",
}
_DOCKERHUB_RESERVED_PROFILE_HANDLES = {
    "_",
    "account",
    "billing",
    "explore",
    "features",
    "library",
    "login",
    "orgs",
    "pricing",
    "repositories",
    "search",
    "settings",
    "signup",
    "teams",
}
_SOURCEHUT_RESERVED_PROFILE_HANDLES = {
    "about",
    "account",
    "billing",
    "dashboard",
    "docs",
    "login",
    "projects",
    "register",
    "security",
    "settings",
    "support",
    "users",
}
_SOURCEFORGE_RESERVED_PROFILE_HANDLES = {
    "account",
    "auth",
    "blog",
    "business",
    "create",
    "directory",
    "help",
    "login",
    "p",
    "projects",
    "software",
    "support",
    "u",
    "user",
    "users",
}
_SNAPCHAT_RESERVED_PROFILE_PATHS = {
    "about",
    "accounts",
    "add",
    "ads",
    "business",
    "download",
    "explore",
    "discover",
    "lens",
    "lenses",
    "login",
    "map",
    "privacy",
    "search",
    "settings",
    "spotlight",
    "stories",
    "support",
    "terms",
}
_LAUNCHPAD_RESERVED_PROFILE_HANDLES = {
    "account",
    "answers",
    "bugs",
    "code",
    "login",
    "people",
    "projects",
    "registry",
    "software",
    "teams",
    "ubuntu",
}
_REDDIT_RESERVED_PROFILE_HANDLES = {
    "about",
    "ads",
    "comments",
    "explore",
    "help",
    "login",
    "popular",
    "r",
    "search",
    "settings",
    "submit",
    "user",
    "users",
}
_REPLIT_RESERVED_PROFILE_HANDLES = {
    "@",
    "account",
    "apps",
    "bounties",
    "careers",
    "community",
    "docs",
    "explore",
    "hosting",
    "login",
    "new",
    "pricing",
    "repls",
    "site",
    "signup",
    "teams",
    "templates",
    "theme",
    "usage",
}
_CODESANDBOX_RESERVED_PROFILE_HANDLES = {
    "api",
    "dashboard",
    "docs",
    "explore",
    "login",
    "new",
    "p",
    "pricing",
    "s",
    "search",
    "signin",
    "signup",
    "templates",
    "u",
}
_CODEPEN_RESERVED_PROFILE_HANDLES = {
    "about",
    "accounts",
    "admin",
    "api",
    "assets",
    "blog",
    "collection",
    "collections",
    "dashboard",
    "docs",
    "features",
    "login",
    "pen",
    "pens",
    "popular",
    "pro",
    "projects",
    "search",
    "settings",
    "signup",
    "teams",
    "topics",
    "trending",
}
_DEVPOST_RESERVED_PROFILE_HANDLES = {
    "about",
    "accounts",
    "api",
    "careers",
    "challenges",
    "customers",
    "hackathons",
    "help",
    "jobs",
    "login",
    "software",
    "teams",
}
_READCV_RESERVED_PROFILE_HANDLES = {
    "about",
    "auth",
    "explore",
    "jobs",
    "login",
    "notifications",
    "onboarding",
    "privacy",
    "search",
    "settings",
    "signup",
    "teams",
}
_FIGMA_RESERVED_PROFILE_HANDLES = {
    "about",
    "api",
    "blog",
    "community",
    "contact",
    "customers",
    "design",
    "developers",
    "downloads",
    "education",
    "enterprise",
    "explore",
    "file",
    "files",
    "help",
    "login",
    "plugins",
    "pricing",
    "proto",
    "prototypes",
    "resource-library",
    "resources",
    "search",
    "signup",
    "teams",
    "templates",
    "whiteboard",
}
_INDIEHACKERS_RESERVED_PROFILE_HANDLES = {
    "about",
    "api",
    "blog",
    "community",
    "companies",
    "contact",
    "dashboard",
    "explore",
    "forum",
    "group",
    "groups",
    "home",
    "interviews",
    "jobs",
    "login",
    "newsletter",
    "newsletters",
    "podcast",
    "post",
    "posts",
    "pricing",
    "product",
    "products",
    "search",
    "sign-in",
    "signin",
    "sign-up",
    "signup",
    "startups",
    "topics",
    "trending",
    "user",
    "users",
}
_POLYWORK_RESERVED_PROFILE_HANDLES = {
    "about",
    "api",
    "blog",
    "companies",
    "company",
    "contact",
    "discover",
    "explore",
    "features",
    "for-companies",
    "hire",
    "jobs",
    "login",
    "pricing",
    "search",
    "signup",
    "talent",
    "teams",
    "user",
    "users",
    "work",
}
_CONTRA_RESERVED_PROFILE_HANDLES = {
    "about",
    "api",
    "blog",
    "clients",
    "companies",
    "company",
    "contact",
    "discover",
    "explore",
    "freelance",
    "freelancers",
    "hire",
    "jobs",
    "login",
    "opportunities",
    "pricing",
    "projects",
    "search",
    "signup",
    "support",
    "talent",
    "user",
    "users",
}
_ADPLIST_RESERVED_PROFILE_HANDLES = {
    "about",
    "api",
    "blog",
    "coaches",
    "community",
    "events",
    "explore",
    "for-companies",
    "login",
    "mentors",
    "pricing",
    "sessions",
    "signup",
    "topics",
    "user",
    "users",
}
_MUCKRACK_RESERVED_PROFILE_HANDLES = {
    "about",
    "blog",
    "contact",
    "customers",
    "demo",
    "for-journalists",
    "help",
    "jobs",
    "login",
    "media-outlets",
    "pricing",
    "rankings",
    "resources",
    "search",
    "signup",
    "trends",
}
_KAGGLE_RESERVED_PROFILE_HANDLES = {
    "account",
    "code",
    "competitions",
    "datasets",
    "docs",
    "jobs",
    "learn",
    "models",
    "organizations",
    "settings",
    "signin",
    "signup",
    "team",
}
_TWITCH_RESERVED_PROFILE_HANDLES = {
    "about",
    "activate",
    "bits",
    "creatorcamp",
    "directory",
    "downloads",
    "drops",
    "inventory",
    "jobs",
    "login",
    "p",
    "search",
    "settings",
    "signup",
    "store",
    "subscriptions",
    "team",
    "teams",
    "turbo",
    "videos",
    "wallet",
}
_UNSPLASH_RESERVED_PROFILE_HANDLES = {
    "about",
    "collections",
    "explore",
    "images",
    "jobs",
    "license",
    "login",
    "photos",
    "plus",
    "search",
    "settings",
    "signup",
    "s",
    "topics",
}
_ARTSTATION_RESERVED_PROFILE_HANDLES = {
    "about",
    "activity",
    "artwork",
    "blogs",
    "channels",
    "challenges",
    "community",
    "contests",
    "discover",
    "jobs",
    "learning",
    "login",
    "marketplace",
    "prints",
    "projects",
    "search",
    "settings",
    "shop",
    "signup",
    "stores",
    "support",
}
_ARTSTATION_RESERVED_SUBDOMAINS = {
    "api",
    "assets",
    "blog",
    "cdn",
    "cdna",
    "help",
    "jobs",
    "learning",
    "magazine",
    "marketplace",
    "static",
    "support",
    "www",
}
_PINTEREST_RESERVED_PROFILE_HANDLES = {
    "about",
    "business",
    "categories",
    "category",
    "explore",
    "ideas",
    "login",
    "messages",
    "notifications",
    "oauth",
    "pin",
    "privacy",
    "search",
    "settings",
    "signup",
    "terms",
    "today",
}
_FIVEHUNDREDPX_RESERVED_PROFILE_HANDLES = {
    "about",
    "discover",
    "editors",
    "groups",
    "jobs",
    "licensing",
    "login",
    "marketplace",
    "photo",
    "photos",
    "p",
    "popular",
    "search",
    "settings",
    "signup",
    "stories",
    "upgrade",
}
_QUORA_RESERVED_PROFILE_HANDLES = {
    "about",
    "business",
    "contact",
    "login",
    "profile",
    "search",
    "settings",
    "spaces",
    "topic",
    "topics",
}
_TRYHACKME_RESERVED_PROFILE_HANDLES = {
    "business",
    "dashboard",
    "hacktivities",
    "login",
    "path",
    "paths",
    "p",
    "room",
    "rooms",
    "signup",
}
_YESWEHACK_RESERVED_PROFILE_HANDLES = {
    "about",
    "hunters",
    "login",
    "programs",
    "signup",
}
_STEAM_RESERVED_PROFILE_HANDLES = {
    "about",
    "actions",
    "app",
    "apps",
    "games",
    "groups",
    "id",
    "login",
    "market",
    "profiles",
    "search",
    "sharedfiles",
    "stats",
}
_SPOTIFY_RESERVED_PROFILE_HANDLES = {
    "album",
    "artist",
    "download",
    "episode",
    "genre",
    "intl",
    "playlist",
    "premium",
    "search",
    "show",
    "track",
    "user",
}
_STRAVA_RESERVED_PROFILE_HANDLES = {
    "about",
    "athletes",
    "clubs",
    "dashboard",
    "features",
    "login",
    "maps",
    "mobile",
    "pros",
    "routes",
    "segments",
    "settings",
    "signup",
    "subscription",
    "terms",
    "upload",
}
_GITHUB_GIST_RESERVED_PROFILE_HANDLES = {
    "auth",
    "discover",
    "forked",
    "github",
    "login",
    "new",
    "raw",
    "search",
    "settings",
    "starred",
}
_GRAVATAR_RESERVED_PROFILE_HANDLES = {
    "avatar",
    "profiles",
    "profile",
    "site",
    "support",
}
_HACKERNEWS_RESERVED_PROFILE_HANDLES = {
    "active",
    "best",
    "classic",
    "front",
    "from",
    "hide",
    "item",
    "jobs",
    "login",
    "news",
    "newcomments",
    "newest",
    "noobstories",
    "past",
    "reply",
    "show",
    "submitted",
    "threads",
    "user",
    "x",
}
_DIRECT_HANDLE_RESERVED_PROFILE_PATHS_BY_PLATFORM = {
    "angel.co": _ANGELLIST_RESERVED_PROFILE_HANDLES,
    "angellist": _ANGELLIST_RESERVED_PROFILE_HANDLES,
    "500px": _FIVEHUNDREDPX_RESERVED_PROFILE_HANDLES,
    "500px.com": _FIVEHUNDREDPX_RESERVED_PROFILE_HANDLES,
    "adplist": _ADPLIST_RESERVED_PROFILE_HANDLES,
    "adp_list": _ADPLIST_RESERVED_PROFILE_HANDLES,
    "adplist.org": _ADPLIST_RESERVED_PROFILE_HANDLES,
    "academia": _ACADEMIA_RESERVED_PROFILE_HANDLES,
    "academia.edu": _ACADEMIA_RESERVED_PROFILE_HANDLES,
    "artstation": _ARTSTATION_RESERVED_PROFILE_HANDLES,
    "artstation.com": _ARTSTATION_RESERVED_PROFILE_HANDLES,
    "all_my_links": _ALLMYLINKS_RESERVED_PROFILE_PATHS,
    "allmylinks": _ALLMYLINKS_RESERVED_PROFILE_PATHS,
    "allmylinks.com": _ALLMYLINKS_RESERVED_PROFILE_PATHS,
    "beacons": _BEACONS_RESERVED_PROFILE_PATHS,
    "beacons_ai": _BEACONS_RESERVED_PROFILE_PATHS,
    "bento": _BENTO_RESERVED_PROFILE_PATHS,
    "bento.me": _BENTO_RESERVED_PROFILE_PATHS,
    "bento_me": _BENTO_RESERVED_PROFILE_PATHS,
    "bentome": _BENTO_RESERVED_PROFILE_PATHS,
    "behance": _BEHANCE_RESERVED_PROFILE_HANDLES,
    "bio.link": _BIO_LINK_RESERVED_PROFILE_PATHS,
    "biolink": _BIO_LINK_RESERVED_PROFILE_PATHS,
    "bio.site": _BIO_SITE_RESERVED_PROFILE_PATHS,
    "biosite": _BIO_SITE_RESERVED_PROFILE_PATHS,
    "bugcrowd": _BUGCROWD_RESERVED_PROFILE_HANDLES,
    "buy_me_a_coffee": _BUYMEACOFFEE_RESERVED_PROFILE_PATHS,
    "buymeacoffee": _BUYMEACOFFEE_RESERVED_PROFILE_PATHS,
    "cal.com": _CALCOM_RESERVED_PROFILE_PATHS,
    "calcom": _CALCOM_RESERVED_PROFILE_PATHS,
    "calendly": _CALENDLY_RESERVED_PROFILE_PATHS,
    "campsite": _CAMPSITE_BIO_RESERVED_PROFILE_PATHS,
    "campsite.bio": _CAMPSITE_BIO_RESERVED_PROFILE_PATHS,
    "campsitebio": _CAMPSITE_BIO_RESERVED_PROFILE_PATHS,
    "carrd": _CARRD_RESERVED_PROFILE_PATHS,
    "codepen": _CODEPEN_RESERVED_PROFILE_HANDLES,
    "code_sandbox": _CODESANDBOX_RESERVED_PROFILE_HANDLES,
    "codesandbox": _CODESANDBOX_RESERVED_PROFILE_HANDLES,
    "contra": _CONTRA_RESERVED_PROFILE_HANDLES,
    "contra.com": _CONTRA_RESERVED_PROFILE_HANDLES,
    "credly": _CREDLY_RESERVED_PROFILE_HANDLES,
    "crates": _CRATES_RESERVED_PROFILE_HANDLES,
    "crates_io": _CRATES_RESERVED_PROFILE_HANDLES,
    "cratesio": _CRATES_RESERVED_PROFILE_HANDLES,
    "deviantart": _DEVIANTART_RESERVED_PROFILE_HANDLES,
    "deviantart.com": _DEVIANTART_RESERVED_PROFILE_HANDLES,
    "discord": _DISCORD_RESERVED_PROFILE_HANDLES,
    "discordapp": _DISCORD_RESERVED_PROFILE_HANDLES,
    "discord_user": _DISCORD_RESERVED_PROFILE_HANDLES,
    "discord_server": _DISCORD_RESERVED_PROFILE_HANDLES,
    "discord_guild": _DISCORD_RESERVED_PROFILE_HANDLES,
    "discord_invite": _DISCORD_RESERVED_PROFILE_HANDLES,
    "devpost": _DEVPOST_RESERVED_PROFILE_HANDLES,
    "docker": _DOCKERHUB_RESERVED_PROFILE_HANDLES,
    "docker_hub": _DOCKERHUB_RESERVED_PROFILE_HANDLES,
    "dockerhub": _DOCKERHUB_RESERVED_PROFILE_HANDLES,
    "dribbble": _DRIBBBLE_RESERVED_PROFILE_HANDLES,
    "figma": _FIGMA_RESERVED_PROFILE_HANDLES,
    "figma.com": _FIGMA_RESERVED_PROFILE_HANDLES,
    "gist": _GITHUB_GIST_RESERVED_PROFILE_HANDLES,
    "github_gist": _GITHUB_GIST_RESERVED_PROFILE_HANDLES,
    "githubgist": _GITHUB_GIST_RESERVED_PROFILE_HANDLES,
    "gravatar": _GRAVATAR_RESERVED_PROFILE_HANDLES,
    "hacker_news": _HACKERNEWS_RESERVED_PROFILE_HANDLES,
    "hackernews": _HACKERNEWS_RESERVED_PROFILE_HANDLES,
    "hn": _HACKERNEWS_RESERVED_PROFILE_HANDLES,
    "hex_pm": _HEXPM_RESERVED_PROFILE_HANDLES,
    "hexpm": _HEXPM_RESERVED_PROFILE_HANDLES,
    "hoo.be": _HOO_BE_RESERVED_PROFILE_PATHS,
    "hoobe": _HOO_BE_RESERVED_PROFILE_PATHS,
    "hackerone": _HACKERONE_RESERVED_PROFILE_HANDLES,
    "hugging_face": _HUGGINGFACE_RESERVED_PROFILE_PATHS,
    "huggingface": _HUGGINGFACE_RESERVED_PROFILE_PATHS,
    "indie_hackers": _INDIEHACKERS_RESERVED_PROFILE_HANDLES,
    "indiehackers": _INDIEHACKERS_RESERVED_PROFILE_HANDLES,
    "indiehackers.com": _INDIEHACKERS_RESERVED_PROFILE_HANDLES,
    "intigriti": _INTIGRITI_RESERVED_PROFILE_HANDLES,
    "kaggle": _KAGGLE_RESERVED_PROFILE_HANDLES,
    "ko-fi": _KOFI_RESERVED_PROFILE_PATHS,
    "ko_fi": _KOFI_RESERVED_PROFILE_PATHS,
    "kofi": _KOFI_RESERVED_PROFILE_PATHS,
    "launchpad": _LAUNCHPAD_RESERVED_PROFILE_HANDLES,
    "liberapay": _LIBERAPAY_RESERVED_PROFILE_PATHS,
    "linktr.ee": _LINKTREE_RESERVED_PROFILE_PATHS,
    "linktree": _LINKTREE_RESERVED_PROFILE_PATHS,
    "lnk.bio": _LNK_BIO_RESERVED_PROFILE_PATHS,
    "lnkbio": _LNK_BIO_RESERVED_PROFILE_PATHS,
    "milkshake": _MILKSHAKE_RESERVED_PROFILE_PATHS,
    "msha": _MILKSHAKE_RESERVED_PROFILE_PATHS,
    "mshake": _MILKSHAKE_RESERVED_PROFILE_PATHS,
    "muckrack": _MUCKRACK_RESERVED_PROFILE_HANDLES,
    "muck_rack": _MUCKRACK_RESERVED_PROFILE_HANDLES,
    "muckrack.com": _MUCKRACK_RESERVED_PROFILE_HANDLES,
    "npm": _NPM_RESERVED_PROFILE_HANDLES,
    "npmjs": _NPM_RESERVED_PROFILE_HANDLES,
    "nuget": _NUGET_RESERVED_PROFILE_HANDLES,
    "open_bug_bounty": _OPENBUGBOUNTY_RESERVED_PROFILE_HANDLES,
    "open_collective": _OPEN_COLLECTIVE_RESERVED_PROFILE_PATHS,
    "openbugbounty": _OPENBUGBOUNTY_RESERVED_PROFILE_HANDLES,
    "opencollective": _OPEN_COLLECTIVE_RESERVED_PROFILE_PATHS,
    "packagist": _PACKAGIST_RESERVED_PROFILE_HANDLES,
    "patreon": _PATREON_RESERVED_PROFILE_PATHS,
    "pinterest": _PINTEREST_RESERVED_PROFILE_HANDLES,
    "quora": _QUORA_RESERVED_PROFILE_HANDLES,
    "quora.com": _QUORA_RESERVED_PROFILE_HANDLES,
    "product_hunt": _PRODUCTHUNT_RESERVED_PROFILE_PATHS,
    "producthunt": _PRODUCTHUNT_RESERVED_PROFILE_PATHS,
    "pypi": _PYPI_RESERVED_PROFILE_HANDLES,
    "polywork": _POLYWORK_RESERVED_PROFILE_HANDLES,
    "polywork.com": _POLYWORK_RESERVED_PROFILE_HANDLES,
    "read.cv": _READCV_RESERVED_PROFILE_HANDLES,
    "readcv": _READCV_RESERVED_PROFILE_HANDLES,
    "reddit": _REDDIT_RESERVED_PROFILE_HANDLES,
    "research_gate": _RESEARCHGATE_RESERVED_PROFILE_HANDLES,
    "researchgate": _RESEARCHGATE_RESERVED_PROFILE_HANDLES,
    "replit": _REPLIT_RESERVED_PROFILE_HANDLES,
    "ruby_gems": _RUBYGEMS_RESERVED_PROFILE_HANDLES,
    "rubygems": _RUBYGEMS_RESERVED_PROFILE_HANDLES,
    "sourcehut": _SOURCEHUT_RESERVED_PROFILE_HANDLES,
    "semantic_scholar": _SEMANTIC_SCHOLAR_RESERVED_PROFILE_HANDLES,
    "semanticscholar": _SEMANTIC_SCHOLAR_RESERVED_PROFILE_HANDLES,
    "semanticscholar.org": _SEMANTIC_SCHOLAR_RESERVED_PROFILE_HANDLES,
    "solo.to": _SOLO_TO_RESERVED_PROFILE_PATHS,
    "soloto": _SOLO_TO_RESERVED_PROFILE_PATHS,
    "taplink": _TAPLINK_RESERVED_PROFILE_PATHS,
    "taplink_cc": _TAPLINK_RESERVED_PROFILE_PATHS,
    "taplink_ws": _TAPLINK_RESERVED_PROFILE_PATHS,
    "sourceforge": _SOURCEFORGE_RESERVED_PROFILE_HANDLES,
    "sourceforge_net": _SOURCEFORGE_RESERVED_PROFILE_HANDLES,
    "snap": _SNAPCHAT_RESERVED_PROFILE_PATHS,
    "snapchat": _SNAPCHAT_RESERVED_PROFILE_PATHS,
    "spotify": _SPOTIFY_RESERVED_PROFILE_HANDLES,
    "strava": _STRAVA_RESERVED_PROFILE_HANDLES,
    "strava.com": _STRAVA_RESERVED_PROFILE_HANDLES,
    "sr.ht": _SOURCEHUT_RESERVED_PROFILE_HANDLES,
    "srht": _SOURCEHUT_RESERVED_PROFILE_HANDLES,
    "steam": _STEAM_RESERVED_PROFILE_HANDLES,
    "steam_community": _STEAM_RESERVED_PROFILE_HANDLES,
    "steamcommunity": _STEAM_RESERVED_PROFILE_HANDLES,
    "thm": _TRYHACKME_RESERVED_PROFILE_HANDLES,
    "tryhackme": _TRYHACKME_RESERVED_PROFILE_HANDLES,
    "twitch": _TWITCH_RESERVED_PROFILE_HANDLES,
    "unsplash": _UNSPLASH_RESERVED_PROFILE_HANDLES,
    "unsplash.com": _UNSPLASH_RESERVED_PROFILE_HANDLES,
    "wellfound": _WELLFOUND_RESERVED_PROFILE_HANDLES,
    "yeswehack": _YESWEHACK_RESERVED_PROFILE_HANDLES,
    "zenodo": _ZENODO_RESERVED_PROFILE_HANDLES,
    "figshare": _FIGSHARE_RESERVED_PROFILE_HANDLES,
}

_SOCIAL_PROFILES_DDL = """
CREATE TABLE IF NOT EXISTS social_profiles (
    id              INTEGER PRIMARY KEY,
    engagement_id   INTEGER NOT NULL REFERENCES engagements(id),
    email           TEXT NOT NULL,
    source          TEXT NOT NULL DEFAULT 'epieos',
    profile_data    TEXT,       -- JSON blob (encrypted at rest in production)
    queried_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(engagement_id, email, source)
);
"""


def _epieos_profile_platform_label(value: Any) -> str:
    text = str(value or "").strip().strip("/").lstrip("@")
    if not text:
        return ""
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", text.lower()).strip("_")


def _epieos_profile_entry_platform(data: dict[str, Any], fallback: str) -> str:
    for key in _EPIEOS_PLATFORM_FIELD_KEYS:
        candidate = _epieos_profile_platform_label(data.get(key))
        if candidate:
            return candidate
    return _epieos_profile_platform_label(fallback)


def _epieos_payload_mapping_has_profile_shape(data: dict[str, Any]) -> bool:
    keys = set(data)
    profile_shape_keys = {
        "avatar",
        "avatar_url",
        "display_name",
        "displayName",
        "full_name",
        "fullName",
        "handle",
        "html_url",
        "htmlUrl",
        "name",
        "profile",
        "profile_url",
        "profileUrl",
        "profileURL",
        "publicIdentifier",
        "screen_name",
        "screenName",
        "slug",
        "url",
        "username",
    }
    return bool(
        keys.intersection(_EPIEOS_PLATFORM_FIELD_KEYS)
        or keys.intersection(_EPIEOS_HANDLE_FIELD_KEYS)
        or keys.intersection(_EPIEOS_PROFILE_URL_ALIAS_KEYS)
        or keys.intersection(profile_shape_keys)
    )


def _epieos_profile_entries_from_container(
    fallback_platform: str,
    value: Any,
    *,
    depth: int = 0,
) -> list[tuple[str, dict[str, Any]]]:
    if depth > 4:
        return []
    entries: list[tuple[str, dict[str, Any]]] = []
    if isinstance(value, dict):
        if _epieos_payload_mapping_has_profile_shape(value):
            entries.append((_epieos_profile_entry_platform(value, fallback_platform), value))
            return entries
        for child_key, child_value in value.items():
            if str(child_key or "").strip().lower() == "email" or _epieos_is_identity_claim_container_key(child_key):
                continue
            child_platform = (
                fallback_platform
                if str(child_key) in _EPIEOS_ROOT_PROFILE_CONTAINER_KEYS
                else str(child_key)
            )
            if isinstance(child_value, dict):
                stack_exchange_user = _shared_stack_exchange_nested_user_payload(
                    fallback_platform,
                    value,
                    child_key,
                    child_value,
                )
                if stack_exchange_user and _epieos_handle(fallback_platform, stack_exchange_user, ""):
                    entries.append(
                        (
                            _epieos_profile_platform_label(fallback_platform),
                            stack_exchange_user,
                        )
                    )
                elif _epieos_payload_mapping_has_profile_shape(child_value):
                    entries.append(
                        (_epieos_profile_entry_platform(child_value, child_platform), child_value)
                    )
                elif str(child_key) in _EPIEOS_ROOT_PROFILE_CONTAINER_KEYS:
                    entries.extend(
                        _epieos_profile_entries_from_container(
                            child_platform,
                            child_value,
                            depth=depth + 1,
                        )
                    )
            elif isinstance(child_value, (list, tuple)):
                entries.extend(
                    _epieos_profile_entries_from_container(
                        child_platform,
                        child_value,
                        depth=depth + 1,
                    )
                )
        return entries
    if isinstance(value, (list, tuple)):
        for item in list(value)[:512]:
            if not isinstance(item, dict):
                continue
            if _epieos_payload_mapping_has_profile_shape(item):
                entries.append((_epieos_profile_entry_platform(item, fallback_platform), item))
            else:
                entries.extend(
                    _epieos_profile_entries_from_container(
                        fallback_platform,
                        item,
                        depth=depth + 1,
                    )
                )
        return entries
    return []


def _epieos_response_profile_entries(payload: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    entries: list[tuple[str, dict[str, Any]]] = []
    for platform, data in payload.items():
        platform_text = str(platform or "").strip()
        if platform_text.lower() == "email":
            continue
        if platform_text in _EPIEOS_ROOT_PROFILE_CONTAINER_KEYS:
            entries.extend(_epieos_profile_entries_from_container(platform_text, data))
            continue
        if isinstance(data, dict):
            entries.append((platform_text, data))
            if not _epieos_payload_mapping_has_profile_shape(data):
                entries.extend(_epieos_profile_entries_from_container(platform_text, data))
            continue
        if isinstance(data, (list, tuple)):
            entries.extend(_epieos_profile_entries_from_container(platform_text, data))
    return entries


def _parse_epieos_response(payload: dict) -> list[dict]:
    if not isinstance(payload, dict):
        return []
    rows: list[dict] = []
    seen_profiles: set[tuple[str, str]] = set()
    for platform, data in _epieos_response_profile_entries(payload):
        provider_platform = _first_non_empty_string(data.get("platform"), platform)
        url = _epieos_profile_url(provider_platform, data)
        if not url:
            continue
        profile_key = (str(platform or "").strip().lower(), str(url or "").strip().lower())
        if profile_key in seen_profiles:
            continue
        seen_profiles.add(profile_key)
        row = {
            "source": "epieos",
            "platform": platform,
            "profile_url": url,
            "url": url,
            "display_name": _epieos_full_name(data),
            "full_name": _epieos_full_name(data),
            "name": _epieos_full_name(data),
            "avatar_url": _first_non_empty_string(
                data.get("avatar_url"),
                data.get("avatar"),
                data.get("picture"),
                data.get("profile_photo"),
            ),
            "bio": _epieos_text_block(data),
            "verified": bool(data.get("verified") or data.get("is_verified")),
        }

        handle = _epieos_handle(provider_platform, data, url)
        if handle:
            row["handle"] = handle
            row["username"] = handle

        related_accounts = _epieos_related_account_entries(provider_platform, data)
        if related_accounts:
            row["accounts"] = related_accounts

        company_name = _epieos_company_name(provider_platform, data)
        if company_name:
            row["company_name"] = company_name
            row["organization_name"] = company_name

        emails = _epieos_email_list(
            data,
            *_EPIEOS_EMAIL_FIELD_KEYS,
            "emails",
            "email_addresses",
            "emailAddresses",
            "contact_emails",
            "contactEmails",
            "contact_links",
            "contactLinks",
            "email_links",
            "emailLinks",
            *_EPIEOS_CONTACT_CONTAINER_KEYS,
            *_EPIEOS_RELATED_PERSON_CONTAINER_KEYS,
            *_EPIEOS_WORK_HISTORY_CONTAINER_KEYS,
            nested_keys=(
                "address",
                "value",
                "url",
                "link",
                "href",
                *_EPIEOS_WORK_HISTORY_ORGANIZATION_FIELD_KEYS,
                *_EPIEOS_EMAIL_FIELD_KEYS,
                "text",
                "body",
                "content",
                "description",
                "summary",
                "note",
                "notes",
                "items",
                "methods",
                "entries",
            ),
            extra_values=[data.get(key) for key in _EPIEOS_EMAIL_FIELD_KEYS],
        )
        if emails:
            row["emails"] = [{"value": email} for email in emails]
            row["email"] = emails[0]
        claim_emails = _epieos_identity_claim_email_values(data)
        if claim_emails:
            emails = list(dict.fromkeys([*emails, *claim_emails]))
            row["emails"] = [{"value": email} for email in emails]
            row["email"] = emails[0]

        phone_numbers = _epieos_phone_list(
            data,
            *_EPIEOS_PHONE_FIELD_KEYS,
            "phones",
            "phone_numbers",
            "phoneNumbers",
            "phone_numbers_in_bio",
            "contact_phones",
            "contactPhones",
            "contact_links",
            "contactLinks",
            "phone_links",
            "phoneLinks",
            *_EPIEOS_CONTACT_CONTAINER_KEYS,
            *_EPIEOS_RELATED_PERSON_CONTAINER_KEYS,
            *_EPIEOS_WORK_HISTORY_CONTAINER_KEYS,
            nested_keys=(
                "value",
                "number",
                "formatted",
                "formatted_number",
                "formattedNumber",
                "url",
                "link",
                "href",
                *_EPIEOS_WORK_HISTORY_ORGANIZATION_FIELD_KEYS,
                *_EPIEOS_PHONE_FIELD_KEYS,
                "text",
                "body",
                "content",
                "description",
                "summary",
                "note",
                "notes",
                "items",
                "methods",
                "entries",
            ),
            extra_values=[data.get(key) for key in _EPIEOS_PHONE_FIELD_KEYS],
        )
        if phone_numbers:
            row["phone_numbers"] = [{"value": phone} for phone in phone_numbers]
            row["phone"] = phone_numbers[0]
        claim_phone_numbers = _epieos_identity_claim_phone_values(data)
        if claim_phone_numbers:
            phone_numbers = list(dict.fromkeys([*phone_numbers, *claim_phone_numbers]))
            row["phone_numbers"] = [{"value": phone} for phone in phone_numbers]
            row["phone"] = phone_numbers[0]

        domain_names = _epieos_domain_list(
            data,
            *_EPIEOS_DOMAIN_FIELD_KEYS,
            *_EPIEOS_WORK_HISTORY_CONTAINER_KEYS,
            nested_keys=(
                "value",
                "url",
                "link",
                "href",
                *_EPIEOS_DOMAIN_FIELD_KEYS,
                *_EPIEOS_WORK_HISTORY_ORGANIZATION_FIELD_KEYS,
                "items",
                "methods",
                "entries",
            ),
            extra_values=[data.get(key) for key in _EPIEOS_DOMAIN_FIELD_KEYS],
        )
        if domain_names:
            row["domains"] = [{"value": domain} for domain in domain_names]
            row["domain"] = domain_names[0]

        normalized_platform = str(provider_platform or "").strip().lower()
        if normalized_platform in _EPIEOS_MATRIX_PLATFORM_NAMES:
            mxid = _epieos_matrix_identity_id(data, url)
            if mxid:
                row["mxid"] = mxid
                row["matrix_id"] = mxid
        elif normalized_platform in _EPIEOS_FEDERATED_PLATFORM_NAMES:
            acct = _epieos_federated_account_id(data, url)
            if acct:
                row["acct"] = acct
                row["webfinger"] = acct
        elif normalized_platform in _EPIEOS_NOSTR_PLATFORM_NAMES:
            npub = _epieos_nostr_identity_id(data, url)
            if npub:
                row["npub"] = npub

        discovered_url_nested_keys = (
            "profile_url",
            "profileUrl",
            "profileURL",
            "url",
            "link",
            "value",
            "href",
            "website",
            "website_url",
            "websiteUrl",
            "websiteURL",
            "site_url",
            "siteUrl",
            "siteURL",
            "external_url",
            "externalUrl",
            "externalURL",
            "blog",
            "blog_url",
            "blogUrl",
            "homepage",
            "homepage_url",
            "homepageUrl",
            "homepageURL",
            "home_page",
            "homePage",
            "home_url",
            "homeUrl",
            "homeURL",
            "items",
            "methods",
            "entries",
            "account",
            "accounts",
            "profile",
            "profiles",
            "identity",
            "identities",
            "links",
            "urls",
            *_EPIEOS_WORK_HISTORY_ORGANIZATION_FIELD_KEYS,
            *_EPIEOS_PROFILE_URL_ALIAS_KEYS,
        )
        discovered_urls = _epieos_string_list(
            data,
            *_EPIEOS_DISCOVERED_URL_FIELD_KEYS,
            fallback_dict_values=True,
            nested_keys=discovered_url_nested_keys,
        )
        discovered_urls.extend(
            _epieos_string_list(
                data,
                *_EPIEOS_CONTACT_CONTAINER_KEYS,
                *_EPIEOS_ACCOUNT_CONTAINER_KEYS,
                *_EPIEOS_RELATED_PERSON_CONTAINER_KEYS,
                *_EPIEOS_WORK_HISTORY_CONTAINER_KEYS,
                nested_keys=discovered_url_nested_keys,
            )
        )
        discovered_urls.extend(
            _epieos_string_list(
                data,
                nested_keys=discovered_url_nested_keys,
                extra_values=[
                    data.get("website"),
                    data.get("external_url"),
                    data.get("externalUrl"),
                    data.get("externalURL"),
                    data.get("blog"),
                    data.get("blog_url"),
                    data.get("blogUrl"),
                    data.get("homepage"),
                    data.get("homepage_url"),
                    data.get("homepageUrl"),
                    data.get("homepageURL"),
                    data.get("home_page"),
                    data.get("homePage"),
                    data.get("home_url"),
                    data.get("homeUrl"),
                    data.get("homeURL"),
                    data.get("site_url"),
                    data.get("siteUrl"),
                    data.get("siteURL"),
                    data.get("company_url"),
                    data.get("companyUrl"),
                    data.get("companyURL"),
                    data.get("organization_url"),
                    data.get("organizationUrl"),
                    data.get("organizationURL"),
                    data.get("employer_url"),
                    data.get("employerUrl"),
                    data.get("employerURL"),
                    data.get("school_url"),
                    data.get("schoolUrl"),
                    data.get("schoolURL"),
                    data.get("institution_url"),
                    data.get("institutionUrl"),
                    data.get("institutionURL"),
                ],
            )
        )
        discovered_urls.extend(_epieos_identity_claim_url_values(data, discovered_url_nested_keys))
        for key in _EPIEOS_PROFILE_URL_ALIAS_KEYS:
            discovered_urls.extend(_epieos_profile_alias_candidate_urls(data.get(key)))
        discovered_urls = list(dict.fromkeys(discovered_urls))
        discovered_urls = [candidate for candidate in discovered_urls if candidate != url]
        if discovered_urls:
            row["urls"] = [{"value": candidate} for candidate in discovered_urls]
            row["external_url"] = discovered_urls[0]

        rows.append(
            {
                key: value
                for key, value in row.items()
                if value is not None and value != "" and value != []
            }
        )
    return rows


def _first_non_empty_string(*values: Any) -> str:
    for value in values:
        text = str(value or "").strip()
        if text:
            return text
    return ""


def _epieos_text_block(data: dict[str, Any]) -> str:
    snippets = _epieos_string_list(
        data,
        *_EPIEOS_TEXT_FIELD_KEYS,
        nested_keys=(
            "text",
            "value",
            "body",
            "content",
            "bio",
            "about",
            "description",
            "headline",
            "summary",
            "contact",
            "contactText",
            "contact_info",
            "contactInfo",
            "contact_details",
            "contactDetails",
            "contact_text",
            "note",
            "notes",
            "items",
            "methods",
            "entries",
            *_EPIEOS_WORK_HISTORY_ORGANIZATION_FIELD_KEYS,
        ),
    )
    return "\n".join(snippets)


def _epieos_full_name(data: dict[str, Any]) -> str:
    explicit = _first_non_empty_string(
        data.get("full_name"),
        data.get("display_name"),
        data.get("name"),
    )
    if explicit:
        return explicit
    first = _first_non_empty_string(
        data.get("firstname"),
        data.get("first_name"),
        data.get("firstName"),
        data.get("given"),
        data.get("given_name"),
        data.get("givenName"),
    )
    last = _first_non_empty_string(
        data.get("lastname"),
        data.get("last_name"),
        data.get("lastName"),
        data.get("family"),
        data.get("family_name"),
        data.get("familyName"),
        data.get("surname"),
    )
    return " ".join(part for part in (first, last) if part).strip()


def _epieos_named_entity_value(value: Any) -> str:
    if isinstance(value, list):
        for item in value:
            candidate = _epieos_named_entity_value(item)
            if candidate:
                return candidate
        return ""
    if isinstance(value, dict):
        for key in (
            "name",
            "display_name",
            "displayName",
            "full_name",
            "fullName",
            "company",
            "company_name",
            "companyName",
            "organization",
            "organization_name",
            "organizationName",
            "employer",
            "employer_name",
            "employerName",
            "legal_name",
            "legalName",
            "alternate_name",
            "alternateName",
            "title",
            "label",
            "value",
        ):
            candidate = _epieos_named_entity_value(value.get(key))
            if candidate:
                return candidate
        return ""
    candidate = str(value or "").strip()
    if not candidate:
        return ""
    if _EPIEOS_EMAIL_RE.fullmatch(candidate.lower()):
        return ""
    if _epieos_phone_values(candidate):
        return ""
    parsed = urlparse(candidate)
    if parsed.scheme.lower() in {"http", "https"} and parsed.hostname:
        return ""
    return candidate


def _epieos_facebook_people_profile_url(data: dict[str, Any], explicit_url: str = "") -> str:
    user_id = _first_non_empty_string(
        data.get("facebook_id"),
        data.get("facebookId"),
        data.get("user_id"),
        data.get("userId"),
        data.get("id"),
    )
    if not user_id and explicit_url:
        parsed = urlparse(str(explicit_url or "").strip())
        hostname = str(parsed.hostname or "").strip().lower()
        path = str(parsed.path or "").strip().lower()
        if hostname.endswith("facebook.com") and path.endswith("/profile.php"):
            user_id = _first_non_empty_string(*(parse_qs(parsed.query).get("id") or []))
    if not re.fullmatch(r"\d{5,32}", user_id):
        return ""
    display_name = _first_non_empty_string(
        data.get("display_name"),
        data.get("name"),
        data.get("full_name"),
    )
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", display_name).strip("-._")
    if not _epieos_normalize_handle_candidate(slug):
        return ""
    return f"https://www.facebook.com/people/{slug}/{user_id}/"


def _epieos_discord_user_id(data: dict[str, Any]) -> str:
    user_id = _first_non_empty_string(
        data.get("discord_user_id"),
        data.get("discordUserId"),
        data.get("discord_id"),
        data.get("discordId"),
        data.get("snowflake"),
        data.get("user_id"),
        data.get("userId"),
        data.get("id"),
    )
    return user_id if re.fullmatch(r"\d{15,22}", user_id) else ""


def _epieos_discord_invite_code(value: Any) -> str:
    candidate = str(value or "").strip().strip("/")
    if not candidate:
        return ""
    parsed = urlparse(candidate if "://" in candidate else f"https://discord.gg/{candidate}")
    hostname = str(parsed.hostname or "").strip().lower()
    if hostname.startswith("www."):
        hostname = hostname[4:]
    path_parts = [part for part in parsed.path.strip("/").split("/") if part]
    if hostname == "discord.gg":
        candidate = path_parts[0] if path_parts else ""
    elif hostname in {"discord.com", "discordapp.com"}:
        if len(path_parts) < 2 or path_parts[0].lower() not in {"invite", "invites"}:
            return ""
        candidate = path_parts[1]
    else:
        candidate = str(value or "").strip().strip("/")
    candidate = candidate.strip()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{2,31}", candidate):
        return ""
    if candidate.lower() in _DISCORD_RESERVED_PROFILE_HANDLES:
        return ""
    return candidate


def _epieos_discord_explicit_profile_url(url: str) -> str:
    raw_url = str(url or "").strip()
    if not raw_url:
        return ""
    parsed = urlparse(raw_url if "://" in raw_url else f"https://{raw_url}")
    hostname = str(parsed.hostname or "").strip().lower()
    if hostname.startswith("www."):
        hostname = hostname[4:]
    path_parts = [part for part in parsed.path.strip("/").split("/") if part]
    if hostname == "discord.gg":
        invite_code = _epieos_discord_invite_code(raw_url)
        return f"https://discord.gg/{invite_code}" if invite_code else ""
    if hostname not in {"discord.com", "discordapp.com"} or not path_parts:
        return ""
    first_path = path_parts[0].lower()
    if first_path == "users" and len(path_parts) >= 2 and re.fullmatch(r"\d{15,22}", path_parts[1]):
        return f"https://discord.com/users/{path_parts[1]}"
    if first_path in {"invite", "invites"} and len(path_parts) >= 2:
        invite_code = _epieos_discord_invite_code(raw_url)
        return f"https://discord.com/invite/{invite_code}" if invite_code else ""
    return ""


def _epieos_discord_profile_url(platform_name: str, data: dict[str, Any]) -> str:
    invite_code = ""
    if platform_name in {"discord_server", "discord_guild", "discord_invite"}:
        invite_code = _epieos_discord_invite_code(
            _first_non_empty_string(
                data.get("invite_code"),
                data.get("inviteCode"),
                data.get("invite"),
                data.get("server_invite"),
                data.get("serverInvite"),
                data.get("guild_invite"),
                data.get("guildInvite"),
                data.get("code"),
                data.get("slug"),
            )
        )
    if not invite_code:
        invite_code = _epieos_discord_invite_code(
            _first_non_empty_string(
                data.get("invite_code"),
                data.get("inviteCode"),
                data.get("server_invite"),
                data.get("serverInvite"),
                data.get("guild_invite"),
                data.get("guildInvite"),
            )
        )
    if invite_code:
        return f"https://discord.gg/{invite_code}"
    user_id = _epieos_discord_user_id(data)
    if user_id:
        return f"https://discord.com/users/{user_id}"
    return ""


def _epieos_normalize_handle_candidate(value: Any) -> str:
    candidate = str(value or "").strip().strip("/").lstrip("@")
    if not candidate:
        return ""
    try:
        from forge.engagement_orchestrator import EngagementSynthesisEngine

        return str(
            EngagementSynthesisEngine._normalize_social_profile_handle_candidate(candidate)
            or ""
        ).strip()
    except Exception:
        if " " in candidate or "/" in candidate:
            return ""
        if not re.match(r"^[A-Za-z0-9._-]{3,64}$", candidate):
            return ""
        return candidate


def _epieos_normalize_google_scholar_user_id_candidate(value: Any) -> str:
    candidate = str(value or "").strip()
    if not candidate:
        return ""
    if not _GOOGLE_SCHOLAR_USER_ID_RE.fullmatch(candidate):
        return ""
    return candidate


def _epieos_normalize_gravatar_handle_candidate(value: Any) -> str:
    candidate = str(value or "").strip().strip("/").lstrip("@")
    if candidate.lower().endswith(".json"):
        candidate = candidate[:-5]
    candidate_lower = candidate.lower()
    if not candidate or candidate_lower in _GRAVATAR_RESERVED_PROFILE_HANDLES:
        return ""
    if re.fullmatch(r"[a-f0-9]{32}", candidate_lower) or re.fullmatch(r"[a-f0-9]{64}", candidate_lower):
        return ""
    return _epieos_normalize_handle_candidate(candidate)


def _epieos_normalize_pinterest_handle_candidate(value: Any) -> str:
    candidate = str(value or "").strip().strip("/").lstrip("@")
    if not candidate:
        return ""
    if not re.fullmatch(r"[A-Za-z0-9_]{3,30}", candidate):
        return ""
    if candidate.isdigit():
        return ""
    return candidate


def _epieos_normalize_vimeo_handle_candidate(value: Any) -> str:
    candidate = str(value or "").strip().strip("/").lstrip("@")
    if not candidate:
        return ""
    if not re.fullmatch(r"[A-Za-z0-9]{3,64}", candidate):
        return ""
    if candidate.isdigit():
        return ""
    return candidate


def _epieos_normalize_lastfm_handle_candidate(value: Any) -> str:
    candidate = str(value or "").strip().strip("/").lstrip("@")
    if not candidate:
        return ""
    if not re.fullmatch(r"[A-Za-z0-9_-]{2,64}", candidate):
        return ""
    return candidate


def _epieos_normalize_bandcamp_handle_candidate(value: Any) -> str:
    candidate = str(value or "").strip().strip("/").lstrip("@")
    if not candidate:
        return ""
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{2,59}", candidate):
        return ""
    if candidate.isdigit():
        return ""
    return candidate


def _epieos_normalize_mixcloud_handle_candidate(value: Any) -> str:
    candidate = str(value or "").strip().strip("/").lstrip("@")
    if not candidate:
        return ""
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{2,63}", candidate):
        return ""
    if candidate.isdigit():
        return ""
    return candidate


def _epieos_normalize_letterboxd_handle_candidate(value: Any) -> str:
    candidate = str(value or "").strip().strip("/").lstrip("@")
    if not candidate:
        return ""
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{1,63}", candidate):
        return ""
    if candidate.isdigit():
        return ""
    return candidate


def _epieos_handle_candidate_url(value: str) -> str:
    candidate = str(value or "").strip()
    if not candidate:
        return ""
    if "://" in candidate:
        return candidate
    first_path = candidate.split("/", 1)[0]
    if "/" in candidate and "." in first_path:
        return f"https://{candidate}"
    return ""


def _epieos_matrix_identity_values(data: dict[str, Any], url: str = "") -> list[Any]:
    values: list[Any] = []
    for key in (
        "matrix_id",
        "matrixId",
        "matrix_user_id",
        "matrixUserId",
        "mxid",
        "user_id",
        "userId",
        "id",
        "handle",
        "username",
        "profile_url",
        "profileUrl",
        "url",
        "link",
        "href",
    ):
        value = data.get(key)
        if value not in (None, ""):
            values.append(value)
    if url:
        values.append(url)
    return values


def _epieos_matrix_identity_parts(value: Any) -> tuple[str, str]:
    try:
        from forge.engagement_orchestrator import EngagementSynthesisEngine

        return EngagementSynthesisEngine._matrix_user_id_parts(value)
    except Exception:
        return "", ""


def _epieos_matrix_identity_id(data: dict[str, Any], url: str = "") -> str:
    for value in _epieos_matrix_identity_values(data, url):
        handle, server = _epieos_matrix_identity_parts(value)
        if handle and server:
            return f"@{handle}:{server}"
    return ""


def _epieos_matrix_profile_url(data: dict[str, Any]) -> str:
    mxid = _epieos_matrix_identity_id(data)
    if not mxid:
        return ""
    return f"https://matrix.to/#/{mxid}"


def _epieos_federated_identity_values(data: dict[str, Any], url: str = "") -> list[Any]:
    values: list[Any] = []
    for key in (
        "acct",
        "account",
        "account_id",
        "accountId",
        "activitypub",
        "activityPub",
        "actor",
        "actor_url",
        "actorUrl",
        "fediverse",
        "fediverse_id",
        "fediverseId",
        "handle",
        "id",
        "preferred_username",
        "preferredUsername",
        "preferredUserName",
        "profile_url",
        "profileUrl",
        "subject",
        "subject_id",
        "subjectId",
        "url",
        "username",
        "webfinger",
        "webfinger_id",
        "webfingerId",
    ):
        value = data.get(key)
        if value not in (None, ""):
            values.append(value)
    if url:
        values.append(url)
    return values


def _epieos_federated_account_parts(value: Any) -> tuple[str, str]:
    try:
        from forge.engagement_orchestrator import EngagementSynthesisEngine

        handle, server = EngagementSynthesisEngine._federated_account_parts(value)
        if handle and server and _epieos_is_federated_instance_candidate_host(server):
            return handle, server
    except Exception:
        pass
    parsed = urlparse(str(value or "").strip())
    if str(parsed.scheme or "").strip().lower() not in {"http", "https"}:
        return "", ""
    hostname = str(parsed.hostname or "").strip().lower().strip(".")
    if hostname.startswith("www."):
        hostname = hostname[4:]
    if not hostname:
        return "", ""
    path_parts = [part for part in parsed.path.strip("/").split("/") if part]
    if not path_parts:
        return "", ""
    candidate = ""
    if path_parts[0].startswith("@"):
        candidate = path_parts[0].lstrip("@")
    elif len(path_parts) >= 2 and path_parts[0].lower() in {"users", "web", "profile", "actor"}:
        candidate = path_parts[1].lstrip("@")
    handle = _epieos_normalize_handle_candidate(candidate)
    if not handle:
        return "", ""
    if not _epieos_is_federated_instance_candidate_host(hostname):
        return "", ""
    return handle, hostname


def _epieos_federated_account_id(data: dict[str, Any], url: str = "") -> str:
    for value in _epieos_federated_identity_values(data, url):
        handle, server = _epieos_federated_account_parts(value)
        if handle and server:
            return f"acct:{handle}@{server}"
    raw_handle = _first_non_empty_string(
        data.get("acct"),
        data.get("preferred_username"),
        data.get("preferredUsername"),
        data.get("preferredUserName"),
        data.get("username"),
        data.get("handle"),
    )
    handle = _epieos_normalize_handle_candidate(raw_handle)
    server = _epieos_mastodon_instance(data, handle)
    if handle and server:
        return f"acct:{handle}@{server}"
    return ""


def _epieos_federated_profile_url(data: dict[str, Any], url: str = "") -> str:
    acct = _epieos_federated_account_id(data, url)
    if not acct:
        return ""
    handle, server = _epieos_federated_account_parts(acct)
    if not handle or not server:
        return ""
    return f"https://{server}/@{handle}"


def _epieos_nostr_identity_values(data: dict[str, Any], url: str = "") -> list[Any]:
    values: list[Any] = []
    for key in (
        "npub",
        "nprofile",
        "nostr",
        "nostr_id",
        "nostrId",
        "public_key",
        "publicKey",
        "pubkey",
        "pubKey",
        "profile_url",
        "profileUrl",
        "url",
        "link",
        "href",
        "handle",
        "username",
        "id",
    ):
        value = data.get(key)
        if value not in (None, ""):
            values.append(value)
    if url:
        values.append(url)
    return values


def _epieos_nostr_identity_id(data: dict[str, Any], url: str = "") -> str:
    try:
        from forge.engagement_orchestrator import EngagementSynthesisEngine
    except Exception:
        return ""
    for value in _epieos_nostr_identity_values(data, url):
        candidate = EngagementSynthesisEngine._nostr_identity_handle_candidate(value)
        if candidate:
            return candidate
    return ""


def _epieos_nostr_profile_url(data: dict[str, Any], url: str = "") -> str:
    npub = _epieos_nostr_identity_id(data, url)
    if not npub:
        return ""
    return f"nostr:{npub}"


def _epieos_profile_alias_url(platform_name: str, data: dict[str, Any]) -> str:
    for key in _EPIEOS_PROFILE_URL_ALIAS_KEYS:
        for candidate in _epieos_profile_alias_candidate_urls(data.get(key)):
            if candidate and _epieos_profile_alias_host_matches(platform_name, candidate):
                return candidate
    for nested in _epieos_nested_profile_dicts(data):
        for key in (
            "profile_url",
            "profileUrl",
            "profileURL",
            "url",
            "link",
            "href",
            "web_url",
            "webUrl",
            *_EPIEOS_PROFILE_URL_ALIAS_KEYS,
        ):
            for candidate in _epieos_profile_alias_candidate_urls(nested.get(key)):
                if candidate and _epieos_profile_alias_host_matches(platform_name, candidate):
                    return candidate
    return ""


def _epieos_profile_alias_candidate_urls(value: Any) -> list[str]:
    raw_values = _epieos_string_list(
        {"value": value},
        "value",
        nested_keys=(
            "profile_url",
            "profileUrl",
            "profileURL",
            "url",
            "link",
            "href",
            "value",
            *_EPIEOS_PROFILE_URL_ALIAS_KEYS,
        ),
    )
    return [
        candidate
        for raw_value in raw_values
        if (candidate := _epieos_handle_candidate_url(raw_value))
    ]


def _epieos_nested_profile_dicts(data: dict[str, Any]) -> list[dict[str, Any]]:
    nested_profiles: list[dict[str, Any]] = []
    for key in _EPIEOS_NESTED_PROFILE_KEYS:
        value = data.get(key)
        if isinstance(value, dict):
            nested_profiles.append(value)
    return nested_profiles


def _epieos_nested_profile_handle_values(data: dict[str, Any]) -> list[Any]:
    values: list[Any] = []
    for nested in _epieos_nested_profile_dicts(data):
        values.extend(nested.get(key) for key in _EPIEOS_HANDLE_FIELD_KEYS)
    return values


def _epieos_related_person_dicts(data: dict[str, Any]) -> list[dict[str, Any]]:
    values: list[dict[str, Any]] = []
    for key in _EPIEOS_RELATED_PERSON_CONTAINER_KEYS:
        candidate = data.get(key)
        if isinstance(candidate, dict):
            values.append(candidate)
            continue
        if isinstance(candidate, list):
            values.extend(item for item in candidate[:256] if isinstance(item, dict))
    return values[:256]


def _epieos_related_account_url(data: dict[str, Any]) -> str:
    for key in (
        "profile_url",
        "profileUrl",
        "profileURL",
        "url",
        "link",
        "href",
        *_EPIEOS_PROFILE_URL_ALIAS_KEYS,
    ):
        for candidate in _epieos_profile_alias_candidate_urls(data.get(key)):
            if candidate:
                return candidate
    return ""


def _epieos_related_account_entries(platform: str, data: dict[str, Any]) -> list[dict[str, str]]:
    values: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for related in _epieos_related_person_dicts(data):
        related_url = _epieos_profile_url(platform, related) or _epieos_related_account_url(related)
        handle = _epieos_handle(platform, related, related_url)
        if not handle:
            continue
        entry = {"username": handle}
        if related_url:
            entry["profile_url"] = related_url
        key = (entry["username"], entry.get("profile_url", ""))
        if key in seen:
            continue
        seen.add(key)
        values.append(entry)
    return values


def _epieos_profile_alias_host_matches(platform_name: str, url: str) -> bool:
    return _shared_profile_alias_host_matches(
        platform_name,
        url,
        _EPIEOS_PLATFORM_PROFILE_HOSTS,
    )


def _epieos_explicit_profile_alias_blocks_fallback(value: str) -> bool:
    candidate_url = _epieos_handle_candidate_url(value)
    if not candidate_url:
        return False
    scheme = str(urlparse(candidate_url).scheme or "").strip().lower()
    return scheme in {"http", "https"}


def _epieos_youtube_channel_id(value: Any) -> str:
    candidate = _epieos_normalize_handle_candidate(value)
    if re.fullmatch(r"UC[A-Za-z0-9_-]{20,32}", candidate):
        return candidate
    return ""


def _epieos_google_scholar_user_id(data: dict[str, Any], explicit_url: str = "") -> str:
    for candidate in (
        data.get("user"),
        data.get("scholar_id"),
        data.get("scholarId"),
        data.get("google_scholar_id"),
        data.get("googleScholarId"),
        data.get("user_id"),
        data.get("userId"),
        data.get("id"),
    ):
        normalized = _epieos_normalize_google_scholar_user_id_candidate(candidate)
        if normalized:
            return normalized
    if explicit_url:
        parsed = urlparse(str(explicit_url or "").strip())
        hostname = str(parsed.hostname or "").strip().lower()
        if hostname.startswith("www."):
            hostname = hostname[4:]
        if hostname == "scholar.google.com":
            for candidate in parse_qs(parsed.query).get("user", []):
                normalized = _epieos_normalize_google_scholar_user_id_candidate(candidate)
                if normalized:
                    return normalized
    return ""


def _epieos_numeric_author_id(data: dict[str, Any], *keys: str) -> str:
    for key in keys:
        candidate = str(data.get(key) or "").strip()
        if re.fullmatch(r"\d{1,32}", candidate):
            return candidate
    return ""


def _epieos_author_slug(data: dict[str, Any], *, separator: str, reserved: set[str]) -> str:
    for raw_value in (
        data.get("author_slug"),
        data.get("authorSlug"),
        data.get("slug"),
        data.get("username"),
        data.get("handle"),
    ):
        raw_text = str(raw_value or "").strip().strip("/")
        if not raw_text:
            continue
        candidate_url = _epieos_handle_candidate_url(raw_text)
        if candidate_url:
            extracted = _epieos_handle_from_profile_url(candidate_url)
            if extracted and extracted.lower() not in reserved:
                return extracted
            continue
        candidate = re.sub(r"[^A-Za-z0-9._-]+", separator, raw_text).strip("._-")
        normalized = _epieos_normalize_handle_candidate(candidate)
        if normalized and normalized.lower() not in reserved:
            return normalized
    return ""


def _epieos_semantic_scholar_profile_url(data: dict[str, Any]) -> str:
    author_id = _epieos_numeric_author_id(
        data,
        "author_id",
        "authorId",
        "semantic_scholar_author_id",
        "semanticScholarAuthorId",
        "ss_author_id",
        "id",
    )
    slug = _epieos_author_slug(
        data,
        separator="-",
        reserved=_SEMANTIC_SCHOLAR_RESERVED_PROFILE_HANDLES,
    )
    if not author_id or not slug:
        return ""
    return f"https://www.semanticscholar.org/author/{slug}/{author_id}"


def _epieos_figshare_profile_url(data: dict[str, Any]) -> str:
    author_id = _epieos_numeric_author_id(
        data,
        "author_id",
        "authorId",
        "figshare_author_id",
        "figshareAuthorId",
        "id",
    )
    slug = _epieos_author_slug(
        data,
        separator="_",
        reserved=_FIGSHARE_RESERVED_PROFILE_HANDLES,
    )
    if not author_id or not slug:
        return ""
    return f"https://figshare.com/authors/{slug}/{author_id}"


def _epieos_humanize_slug(value: Any) -> str:
    slug = str(value or "").strip().strip("/").lstrip("@")
    tokens = [
        token
        for token in re.split(r"[-_]+", slug)
        if token and re.search(r"[A-Za-z]", token)
    ]
    if not tokens:
        return ""
    return " ".join(token[:1].upper() + token[1:] for token in tokens)


def _epieos_company_profile_slug(data: dict[str, Any]) -> str:
    candidates: list[Any] = [
        data.get("slug"),
        data.get("org_slug"),
        data.get("orgSlug"),
        data.get("organization_slug"),
        data.get("organizationSlug"),
        data.get("group_slug"),
        data.get("groupSlug"),
        data.get("page_slug"),
        data.get("pageSlug"),
        data.get("namespace"),
        data.get("workspace"),
        data.get("workspace_slug"),
        data.get("workspaceSlug"),
        data.get("handle"),
        data.get("username"),
        data.get("name"),
    ]
    organization = data.get("organization")
    if isinstance(organization, dict):
        candidates.extend(
            [
                organization.get("slug"),
                organization.get("login"),
                organization.get("handle"),
                organization.get("name"),
            ]
        )
    else:
        candidates.append(organization)

    for raw_candidate in candidates:
        text = str(raw_candidate or "").strip().strip("/").lstrip("@")
        if not text:
            continue
        if "://" in text:
            extracted = _epieos_company_profile_slug_from_url(text)
            if extracted:
                return extracted
            continue
        text = re.sub(
            r"^(orgs|groups|organizations|org|pages)/+",
            "",
            text,
            flags=re.IGNORECASE,
        ).strip("/")
        normalized = _epieos_normalize_handle_candidate(text)
        if normalized:
            return normalized
    return ""


def _epieos_company_profile_slug_from_url(value: str) -> str:
    parsed = urlparse(str(value or "").strip())
    hostname = str(parsed.hostname or "").strip().lower()
    path_parts = [part for part in parsed.path.strip("/").split("/") if part]
    if not hostname or not path_parts:
        return ""
    first_path = path_parts[0].lower()
    slug_index: int | None = None
    if hostname.endswith("github.com") and first_path == "orgs":
        slug_index = 1
    elif hostname.endswith("gitlab.com") and first_path == "groups":
        slug_index = 1
    elif hostname.endswith("huggingface.co") and first_path == "organizations":
        slug_index = 1
    elif hostname == "hub.docker.com" and first_path == "orgs":
        slug_index = 1
    elif hostname.endswith("npmjs.com") and first_path in {"org", "orgs"}:
        slug_index = 1
    elif hostname.endswith("pypi.org") and first_path in {"org", "orgs"}:
        slug_index = 1
    elif hostname.endswith("facebook.com") and first_path == "pages":
        slug_index = 1
    elif hostname.endswith("wellfound.com") and first_path == "company":
        slug_index = 1
    elif hostname in {"angel.co", "angellist.com"} and first_path == "company":
        slug_index = 1
    if slug_index is None or len(path_parts) <= slug_index:
        return ""
    return _epieos_normalize_handle_candidate(path_parts[slug_index])


def _epieos_company_profile_url(platform_name: str, data: dict[str, Any]) -> str:
    if platform_name not in _EPIEOS_COMPANY_PLATFORM_NAMES:
        return ""
    slug = _epieos_company_profile_slug(data)
    if not slug:
        return ""
    if platform_name in {"github_org", "github_organization"}:
        return f"https://github.com/orgs/{slug}"
    if platform_name in {"gitlab_group", "gitlab_org", "gitlab_organization"}:
        return f"https://gitlab.com/groups/{slug}"
    if platform_name in {"huggingface_org", "huggingface_organization"}:
        return f"https://huggingface.co/organizations/{slug}"
    if platform_name in {"docker_org", "dockerhub_org", "docker_hub_org"}:
        return f"https://hub.docker.com/orgs/{slug}"
    if platform_name in {"npm_org", "npmjs_org"}:
        return f"https://www.npmjs.com/org/{slug}"
    if platform_name in {"pypi_org", "pypi_organization"}:
        return f"https://pypi.org/org/{slug}"
    if platform_name == "facebook_page":
        return f"https://www.facebook.com/pages/{slug}"
    if platform_name == "wellfound_company":
        return f"https://wellfound.com/company/{slug}"
    if platform_name in {"angellist_company", "angel_co_company"}:
        return f"https://angel.co/company/{slug}"
    return ""


def _epieos_profile_url(platform: str, data: dict[str, Any]) -> str:
    platform_name = str(platform or "").strip().lower()
    explicit = _first_non_empty_string(
        data.get("profile_url"),
        data.get("profileUrl"),
        data.get("profileURL"),
        data.get("url"),
        data.get("html_url"),
        data.get("htmlUrl"),
        data.get("link"),
    )
    if not explicit:
        explicit = _epieos_profile_alias_url(platform_name, data)
    profile_alias = data.get("profile")
    if (
        not explicit
        and isinstance(profile_alias, str)
        and "://" in profile_alias.strip()
    ):
        explicit = profile_alias.strip()
    if explicit:
        if platform_name in _EPIEOS_DISCORD_PLATFORM_NAMES:
            return _epieos_discord_explicit_profile_url(explicit)
        if platform_name in _EPIEOS_MATRIX_PLATFORM_NAMES and not _epieos_matrix_identity_id(data, explicit):
            return ""
        if platform_name in _EPIEOS_FEDERATED_PLATFORM_NAMES:
            federated_url = _epieos_federated_profile_url(data, explicit)
            if federated_url:
                return federated_url
            explicit_host = str(urlparse(explicit).hostname or "").strip().lower()
            if platform_name == "mastodon" and _is_mastodon_like_host(explicit_host):
                return explicit
            return ""
        if platform_name in _EPIEOS_NOSTR_PLATFORM_NAMES:
            return _epieos_nostr_profile_url(data, explicit)
        if not _epieos_profile_alias_host_matches(platform_name, explicit):
            if _epieos_explicit_profile_alias_blocks_fallback(explicit):
                return ""
        else:
            explicit_host = str(urlparse(explicit).hostname or "").strip().lower()
            if explicit_host.startswith("www."):
                explicit_host = explicit_host[4:]
            if explicit_host == "news.ycombinator.com" and not _epieos_handle_from_profile_url(explicit):
                return ""
            if platform_name == "facebook":
                people_url = _epieos_facebook_people_profile_url(data, explicit)
                if people_url:
                    return people_url
            if platform_name in {"devto", "dev.to"} and not _epieos_handle_from_profile_url(explicit):
                return ""
            if platform_name in _EPIEOS_TWITTER_PLATFORM_NAMES and not _epieos_handle_from_profile_url(explicit):
                return ""
            if (
                platform_name
                in {
                    "500px",
                    "500px.com",
                    "academia",
                    "academia.edu",
                    "adplist",
                    "adp_list",
                    "artstation",
                    "artstation.com",
                    "contra",
                    "contra.com",
                    "figma",
                    "figma.com",
                    "figshare",
                    "github_gist",
                    "githubgist",
                    "gist",
                    "google_scholar",
                    "googlescholar",
                    "codepen",
                    "deviantart",
                    "deviantart.com",
                    "indie_hackers",
                    "indiehackers",
                    "launchpad",
                    "muckrack",
                    "muck_rack",
                    "muckrack.com",
                    "polywork",
                    "polywork.com",
                    "quora",
                    "quora.com",
                    "scholar",
                    "semantic_scholar",
                    "semanticscholar",
                    "sourceforge",
                    "sourceforge_net",
                    "spotify",
                    "strava",
                    "strava.com",
                    "unsplash",
                    "unsplash.com",
                    "zenodo",
                }
                and not _epieos_handle_from_profile_url(explicit)
            ):
                return ""
            return explicit
    if platform_name in _EPIEOS_MATRIX_PLATFORM_NAMES:
        return _epieos_matrix_profile_url(data)
    if platform_name in _EPIEOS_FEDERATED_PLATFORM_NAMES:
        federated_url = _epieos_federated_profile_url(data)
        if federated_url:
            return federated_url
    if platform_name in _EPIEOS_NOSTR_PLATFORM_NAMES:
        return _epieos_nostr_profile_url(data)
    if platform_name in _EPIEOS_DISCORD_PLATFORM_NAMES:
        return _epieos_discord_profile_url(platform_name, data)
    if platform_name == "linkedin_company":
        slug = _first_non_empty_string(
            data.get("slug"),
            data.get("company_slug"),
            data.get("company"),
            data.get("company_name"),
        ).strip().strip("/")
        if slug:
            return f"https://www.linkedin.com/company/{slug}"
        return ""
    company_url = _epieos_company_profile_url(platform_name, data)
    if company_url:
        return company_url
    if platform_name in {"google_scholar", "googlescholar", "scholar"}:
        scholar_user_id = _epieos_google_scholar_user_id(data)
        if scholar_user_id:
            return f"https://scholar.google.com/citations?user={scholar_user_id}"
        return ""
    if platform_name in {"semantic_scholar", "semanticscholar"}:
        return _epieos_semantic_scholar_profile_url(data)
    if platform_name == "figshare":
        return _epieos_figshare_profile_url(data)
    handle = _epieos_handle(platform, data, "")
    if platform_name == "facebook" and not handle:
        people_url = _epieos_facebook_people_profile_url(data)
        if people_url:
            return people_url
    if not handle:
        return ""
    if platform_name in _EPIEOS_TWITTER_PLATFORM_NAMES:
        return f"https://x.com/{handle}"
    if platform_name == "github":
        return f"https://github.com/{handle}"
    if platform_name in {"github_gist", "githubgist", "gist"}:
        return f"https://gist.github.com/{handle}"
    if platform_name == "gravatar":
        normalized = _epieos_normalize_gravatar_handle_candidate(handle)
        if not normalized:
            return ""
        return f"https://gravatar.com/{normalized}"
    if platform_name in {"github_sponsors", "githubsponsors"}:
        return f"https://github.com/sponsors/{handle}"
    if platform_name == "gitlab":
        return f"https://gitlab.com/{handle}"
    if platform_name == "bitbucket":
        return f"https://bitbucket.org/{handle}"
    if platform_name == "bugcrowd":
        return f"https://bugcrowd.com/{handle}"
    if platform_name == "codeberg":
        return f"https://codeberg.org/{handle}"
    if platform_name == "codepen":
        return f"https://codepen.io/{handle}"
    if platform_name == "hackerone":
        return f"https://hackerone.com/{handle}"
    if platform_name in {"hackernews", "hacker_news", "hn"}:
        return f"https://news.ycombinator.com/user?id={handle}"
    if platform_name == "hashnode":
        return f"https://hashnode.com/@{handle}"
    if platform_name in {"docker", "dockerhub", "docker_hub"}:
        return f"https://hub.docker.com/u/{handle}"
    if platform_name in {"sourcehut", "srht", "sr.ht"}:
        return f"https://sr.ht/~{handle}"
    if platform_name in {"sourceforge", "sourceforge_net"}:
        return f"https://sourceforge.net/u/{handle}/profile/"
    if platform_name == "instagram":
        return f"https://www.instagram.com/{handle}/"
    if platform_name == "intigriti":
        return f"https://app.intigriti.com/researcher/profile/{handle}"
    if platform_name == "linkedin":
        return f"https://www.linkedin.com/in/{handle}"
    if platform_name == "facebook":
        return f"https://www.facebook.com/{handle}"
    if platform_name == "flickr":
        return f"https://www.flickr.com/photos/{handle}/"
    if platform_name == "vimeo":
        normalized = _epieos_normalize_vimeo_handle_candidate(handle)
        if not normalized:
            return ""
        return f"https://vimeo.com/{normalized}"
    if platform_name == "kaggle":
        return f"https://www.kaggle.com/{handle}"
    if platform_name == "keybase":
        return f"https://keybase.io/{handle}"
    if platform_name == "launchpad":
        return f"https://launchpad.net/~{handle}"
    if platform_name in {"lastfm", "last.fm", "last_fm"}:
        normalized = _epieos_normalize_lastfm_handle_candidate(handle)
        if not normalized:
            return ""
        return f"https://www.last.fm/user/{normalized}"
    if platform_name in {"opencollective", "open_collective"}:
        return f"https://opencollective.com/{handle}"
    if platform_name == "liberapay":
        return f"https://liberapay.com/{handle}"
    if platform_name == "patreon":
        return f"https://www.patreon.com/{handle}"
    if platform_name == "pinterest":
        normalized = _epieos_normalize_pinterest_handle_candidate(handle)
        if not normalized:
            return ""
        return f"https://www.pinterest.com/{normalized}/"
    if platform_name in {"quora", "quora.com"}:
        return f"https://www.quora.com/profile/{handle}"
    if platform_name in {"kofi", "ko-fi", "ko_fi"}:
        return f"https://ko-fi.com/{handle}"
    if platform_name in {"buymeacoffee", "buy_me_a_coffee"}:
        return f"https://www.buymeacoffee.com/{handle}"
    if platform_name in {"telegram", "telegramme"}:
        return f"https://t.me/{handle}"
    if platform_name == "reddit":
        return f"https://www.reddit.com/user/{handle}"
    if platform_name == "replit":
        return f"https://replit.com/@{handle}"
    if platform_name in {"codesandbox", "code_sandbox"}:
        return f"https://codesandbox.io/u/{handle}"
    if platform_name == "devpost":
        return f"https://devpost.com/{handle}"
    if platform_name in {"readcv", "read.cv"}:
        return f"https://read.cv/{handle}"
    if platform_name in {"devto", "dev.to"}:
        return f"https://dev.to/{handle}"
    if platform_name in {"deviantart", "deviantart.com"}:
        return f"https://www.deviantart.com/{handle}"
    if platform_name in {"huggingface", "hugging_face"}:
        return f"https://huggingface.co/{handle}"
    if platform_name in {"npm", "npmjs"}:
        return f"https://www.npmjs.com/~{handle}"
    if platform_name == "pypi":
        return f"https://pypi.org/user/{handle}/"
    if platform_name in {"rubygems", "ruby_gems"}:
        return f"https://rubygems.org/profiles/{handle}"
    if platform_name in {"crates", "cratesio", "crates_io"}:
        return f"https://crates.io/users/{handle}"
    if platform_name == "packagist":
        return f"https://packagist.org/users/{handle}"
    if platform_name == "nuget":
        return f"https://www.nuget.org/profiles/{handle}"
    if platform_name in {"openbugbounty", "open_bug_bounty"}:
        return f"https://www.openbugbounty.org/researchers/{handle}/"
    if platform_name in {"hexpm", "hex_pm"}:
        return f"https://hex.pm/users/{handle}"
    if platform_name in {"stackoverflow", "stack_overflow"}:
        user_id = _first_non_empty_string(data.get("user_id"), data.get("userId"), data.get("id"))
        host = _epieos_stack_exchange_host(data) or "stackoverflow.com"
        if user_id:
            return f"https://{host}/users/{user_id}/{handle}"
        return ""
    if platform_name in {"stackexchange", "stack_exchange"}:
        user_id = _first_non_empty_string(data.get("user_id"), data.get("userId"), data.get("id"))
        host = _epieos_stack_exchange_host(data) or "stackoverflow.com"
        if user_id:
            return f"https://{host}/users/{user_id}/{handle}"
        return ""
    if platform_name in {"aboutme", "about.me"}:
        return f"https://about.me/{handle}"
    if platform_name in {"500px", "500px.com"}:
        return f"https://500px.com/p/{handle}"
    if platform_name in {"artstation", "artstation.com"}:
        return f"https://www.artstation.com/{handle}"
    if platform_name in {"bluesky", "bsky"}:
        return f"https://bsky.app/profile/{handle}"
    if platform_name == "mastodon":
        instance = _epieos_mastodon_instance(data, handle)
        if instance:
            return f"https://{instance}/@{handle}"
        return ""
    if platform_name == "threads":
        return f"https://www.threads.com/@{handle}"
    if platform_name == "tiktok":
        return f"https://www.tiktok.com/@{handle}"
    if platform_name in {"tryhackme", "thm"}:
        return f"https://tryhackme.com/p/{handle}"
    if platform_name == "yeswehack":
        return f"https://yeswehack.com/hunters/{handle}"
    if platform_name in {"snap", "snapchat"}:
        return f"https://www.snapchat.com/add/{handle}"
    if platform_name == "twitch":
        return f"https://www.twitch.tv/{handle}"
    if platform_name in {"unsplash", "unsplash.com"}:
        return f"https://unsplash.com/@{handle}"
    if platform_name == "spotify":
        return f"https://open.spotify.com/user/{handle}"
    if platform_name in {"strava", "strava.com"}:
        return f"https://www.strava.com/athletes/{handle}"
    if platform_name == "substack":
        return f"https://{handle}.substack.com"
    if platform_name == "youtube":
        channel_id = _epieos_youtube_channel_id(data.get("channel_id") or data.get("channelId"))
        if channel_id and handle == channel_id:
            return f"https://www.youtube.com/channel/{handle}"
        return f"https://www.youtube.com/@{handle}"
    if platform_name == "medium":
        return f"https://medium.com/@{handle}"
    if platform_name in {"linktree", "linktr.ee"}:
        return f"https://linktr.ee/{handle}"
    if platform_name in {"all_my_links", "allmylinks", "allmylinks.com"}:
        return f"https://allmylinks.com/{handle}"
    if platform_name == "orcid":
        return f"https://orcid.org/{handle}"
    if platform_name in {"researchgate", "research_gate"}:
        return f"https://www.researchgate.net/profile/{handle}"
    if platform_name in {"academia", "academia.edu"}:
        return f"https://www.academia.edu/{handle}"
    if platform_name == "zenodo":
        return f"https://zenodo.org/users/{handle}"
    if platform_name == "credly":
        return f"https://www.credly.com/users/{handle}"
    if platform_name == "behance":
        return f"https://www.behance.net/{handle}"
    if platform_name == "dribbble":
        return f"https://dribbble.com/{handle}"
    if platform_name == "calendly":
        return f"https://calendly.com/{handle}"
    if platform_name in {"calcom", "cal.com"}:
        return f"https://cal.com/{handle}"
    if platform_name in {"producthunt", "product_hunt"}:
        return f"https://www.producthunt.com/@{handle}"
    if platform_name == "wellfound":
        return f"https://wellfound.com/u/{handle}"
    if platform_name in {"angellist", "angel.co"}:
        return f"https://angel.co/u/{handle}"
    if platform_name in {"figma", "figma.com"}:
        return f"https://www.figma.com/@{handle}"
    if platform_name in {"indiehackers", "indie_hackers"}:
        return f"https://www.indiehackers.com/{handle}"
    if platform_name in {"polywork", "polywork.com"}:
        return f"https://www.polywork.com/{handle}"
    if platform_name in {"contra", "contra.com"}:
        return f"https://contra.com/{handle}"
    if platform_name in {"adplist", "adp_list"}:
        return f"https://adplist.org/mentors/{handle}"
    if platform_name == "bandcamp":
        normalized = _epieos_normalize_bandcamp_handle_candidate(handle)
        if not normalized:
            return ""
        return f"https://{normalized}.bandcamp.com"
    if platform_name == "beacons":
        return f"https://beacons.ai/{handle}"
    if platform_name in {"bento", "bento.me", "bentome", "bento_me"}:
        return f"https://bento.me/{handle}"
    if platform_name in {"hoobe", "hoo.be"}:
        return f"https://hoo.be/{handle}"
    if platform_name in {"biolink", "bio.link"}:
        return f"https://bio.link/{handle}"
    if platform_name in {"biosite", "bio.site"}:
        return f"https://bio.site/{handle}"
    if platform_name in {"lnkbio", "lnk.bio"}:
        return f"https://lnk.bio/{handle}"
    if platform_name in {"soloto", "solo.to"}:
        return f"https://solo.to/{handle}"
    if platform_name in {"campsite", "campsitebio", "campsite.bio"}:
        return f"https://campsite.bio/{handle}"
    if platform_name in {"taplink", "taplink_cc", "taplink_ws"}:
        return f"https://taplink.cc/{handle}"
    if platform_name in {"milkshake", "mshake", "msha"}:
        return f"https://msha.ke/{handle}"
    if platform_name in {"speakerdeck", "speaker_deck"}:
        return f"https://speakerdeck.com/{handle}"
    if platform_name in {"slideshare", "slide_share"}:
        return f"https://www.slideshare.net/{handle}"
    if platform_name in {"soundcloud", "sound_cloud"}:
        return f"https://soundcloud.com/{handle}"
    if platform_name == "mixcloud":
        normalized = _epieos_normalize_mixcloud_handle_candidate(handle)
        if not normalized:
            return ""
        return f"https://www.mixcloud.com/{normalized}/"
    if platform_name in {"muckrack", "muck_rack", "muckrack.com"}:
        return f"https://muckrack.com/{handle}"
    if platform_name == "letterboxd":
        normalized = _epieos_normalize_letterboxd_handle_candidate(handle)
        if not normalized:
            return ""
        return f"https://letterboxd.com/{normalized}/"
    if platform_name in {"steam", "steamcommunity", "steam_community"}:
        return f"https://steamcommunity.com/id/{handle}"
    if platform_name == "carrd":
        return f"https://{handle}.carrd.co"
    return ""


def _epieos_handle(platform: str, data: dict[str, Any], url: str) -> str:
    platform_name = str(platform or "").strip().lower()
    if platform_name in _EPIEOS_COMPANY_PLATFORM_NAMES:
        return ""
    if platform_name in {"google_scholar", "googlescholar", "scholar"}:
        return _epieos_google_scholar_user_id(data, url)
    if platform_name in _EPIEOS_MATRIX_PLATFORM_NAMES:
        mxid = _epieos_matrix_identity_id(data, url)
        if mxid:
            handle, _server = _epieos_matrix_identity_parts(mxid)
            if handle:
                return handle
        return ""
    if platform_name in _EPIEOS_FEDERATED_PLATFORM_NAMES:
        acct = _epieos_federated_account_id(data, url)
        if acct:
            handle, _server = _epieos_federated_account_parts(acct)
            if handle:
                return handle
        return ""
    if platform_name in _EPIEOS_NOSTR_PLATFORM_NAMES:
        return _epieos_nostr_identity_id(data, url)
    if platform_name in _EPIEOS_DISCORD_PLATFORM_NAMES:
        if platform_name in {"discord_server", "discord_guild", "discord_invite"}:
            return ""
        candidate = _first_non_empty_string(
            data.get("username"),
            data.get("handle"),
            data.get("display_handle"),
            data.get("displayHandle"),
            data.get("name"),
        )
        normalized = _epieos_normalize_handle_candidate(candidate)
        if not normalized or normalized.lower() in _DISCORD_RESERVED_PROFILE_HANDLES:
            return ""
        return normalized
    raw_handles = [data.get(key) for key in _EPIEOS_HANDLE_FIELD_KEYS]
    if platform_name in {"researchgate", "research_gate"}:
        raw_handles.append(data.get("profile"))
    raw_handles.extend(_epieos_nested_profile_handle_values(data))
    for raw_handle in raw_handles:
        raw_text = str(raw_handle or "").strip()
        if not raw_text:
            continue
        candidate_url = _epieos_handle_candidate_url(raw_text)
        if candidate_url:
            extracted = _epieos_handle_from_profile_url(candidate_url)
            if extracted:
                return extracted
            continue
        handle = raw_text.strip().strip("/").lstrip("@")
        if platform_name == "mastodon" and "@" in handle:
            handle = handle.split("@", 1)[0].strip()
        if platform_name == "pinterest":
            normalized = "" if _epieos_direct_handle_is_reserved(platform_name, handle) else _epieos_normalize_pinterest_handle_candidate(handle)
        elif platform_name == "vimeo":
            normalized = "" if handle.lower() in _VIMEO_RESERVED_PROFILE_PATHS else _epieos_normalize_vimeo_handle_candidate(handle)
        elif platform_name in {"lastfm", "last.fm", "last_fm"}:
            normalized = _epieos_normalize_lastfm_handle_candidate(handle)
        elif platform_name == "bandcamp":
            normalized = _epieos_normalize_bandcamp_handle_candidate(handle)
        elif platform_name == "mixcloud":
            normalized = "" if handle.lower() in _MIXCLOUD_RESERVED_PROFILE_PATHS else _epieos_normalize_mixcloud_handle_candidate(handle)
        elif platform_name == "letterboxd":
            normalized = "" if handle.lower() in _LETTERBOXD_RESERVED_PROFILE_PATHS else _epieos_normalize_letterboxd_handle_candidate(handle)
        elif platform_name == "instagram" and handle.lower() in _INSTAGRAM_RESERVED_PROFILE_PATHS:
            normalized = ""
        elif platform_name == "keybase" and handle.lower() in _KEYBASE_RESERVED_PROFILE_PATHS:
            normalized = ""
        elif platform_name in {"telegram", "telegramme"} and handle.lower() in _TELEGRAM_RESERVED_PROFILE_PATHS:
            normalized = ""
        elif platform_name == "tiktok" and handle.lower() in _TIKTOK_RESERVED_PROFILE_HANDLES:
            normalized = ""
        elif platform_name == "youtube" and handle.lower() in _YOUTUBE_RESERVED_PROFILE_HANDLES:
            normalized = ""
        elif platform_name in {"devto", "dev.to"} and handle.lower() in _DEVTO_RESERVED_PROFILE_PATHS:
            normalized = ""
        elif (
            platform_name in _EPIEOS_TWITTER_PLATFORM_NAMES
            and handle.lower() in _TWITTER_RESERVED_PROFILE_PATHS
        ):
            normalized = ""
        elif platform_name == "bitbucket" and handle.lower() in _BITBUCKET_RESERVED_PROFILE_PATHS:
            normalized = ""
        elif platform_name == "codeberg" and handle.lower() in _CODEBERG_RESERVED_PROFILE_PATHS:
            normalized = ""
        elif platform_name == "codepen" and handle.lower() in _CODEPEN_RESERVED_PROFILE_HANDLES:
            normalized = ""
        elif platform_name == "github" and handle.lower() in _GITHUB_RESERVED_PROFILE_PATHS:
            normalized = ""
        elif platform_name == "gitlab" and handle.lower() in _GITLAB_RESERVED_PROFILE_PATHS:
            normalized = ""
        elif platform_name == "gravatar":
            normalized = _epieos_normalize_gravatar_handle_candidate(handle)
        elif platform_name == "hashnode" and handle.lower() in _HASHNODE_RESERVED_PROFILE_PATHS:
            normalized = ""
        elif platform_name == "medium" and (
            handle.lower() in _MEDIUM_RESERVED_PROFILE_PATHS
            or handle.lower() in _MEDIUM_RESERVED_SUBDOMAINS
        ):
            normalized = ""
        elif platform_name == "substack" and (
            handle.lower() in _SUBSTACK_RESERVED_PROFILE_PATHS
            or handle.lower() in _SUBSTACK_RESERVED_SUBDOMAINS
        ):
            normalized = ""
        elif platform_name == "flickr" and handle.lower() in _FLICKR_RESERVED_PHOTOS_PATHS:
            normalized = ""
        elif platform_name in {"slideshare", "slide_share"} and handle.lower() in _SLIDESHARE_RESERVED_PROFILE_PATHS:
            normalized = ""
        elif platform_name in {"soundcloud", "sound_cloud"} and handle.lower() in _SOUNDCLOUD_RESERVED_PROFILE_PATHS:
            normalized = ""
        elif platform_name in {"speakerdeck", "speaker_deck"} and handle.lower() in _SPEAKERDECK_RESERVED_PROFILE_PATHS:
            normalized = ""
        elif platform_name == "vimeo" and handle.lower() in _VIMEO_RESERVED_PROFILE_PATHS:
            normalized = ""
        elif _epieos_direct_handle_is_reserved(platform_name, handle):
            normalized = ""
        else:
            normalized = _epieos_normalize_handle_candidate(handle)
        if normalized:
            return normalized
    parsed = urlparse(url)
    hostname = str(parsed.hostname or "").strip().lower()
    extracted = _epieos_handle_from_profile_url(url)
    if extracted or _epieos_is_supported_profile_host(hostname):
        return extracted
    path_parts = [part for part in parsed.path.strip("/").split("/") if part]
    if not hostname or not path_parts:
        return ""
    normalized_hostname = hostname[4:] if hostname.startswith("www.") else hostname
    if platform_name == "mastodon":
        return _epieos_mastodon_handle_from_path_parts(path_parts)
    if normalized_hostname.endswith(".bandcamp.com"):
        bandcamp_slug = normalized_hostname[: -len(".bandcamp.com")].strip(".")
        reserved_bandcamp_subdomains = {
            "daily",
            "discover",
            "get",
            "help",
            "merch",
            "search",
            "secure",
            "support",
            "tags",
            "www",
        }
        if bandcamp_slug.lower() in reserved_bandcamp_subdomains:
            return ""
        return _epieos_normalize_bandcamp_handle_candidate(bandcamp_slug)
    if normalized_hostname == "bandcamp.com":
        reserved_bandcamp = {
            "about",
            "album",
            "artists",
            "daily",
            "discover",
            "download",
            "fans",
            "fansignup",
            "fan_signup",
            "guide",
            "help",
            "login",
            "merch",
            "music",
            "search",
            "signup",
            "tag",
            "track",
        }
        if path_parts[0].lower() in reserved_bandcamp:
            return ""
        return _epieos_normalize_bandcamp_handle_candidate(path_parts[0])
    if hostname.endswith("linkedin.com") and len(path_parts) >= 2 and path_parts[0] in {"in", "pub", "company"}:
        return path_parts[1].lstrip("@")
    if hostname.endswith("github.com"):
        if hostname == "gist.github.com":
            first_path = path_parts[0].lower()
            if first_path in _GITHUB_GIST_RESERVED_PROFILE_HANDLES:
                return ""
            if len(path_parts) == 1 and re.fullmatch(r"[a-f0-9]{10,64}", first_path):
                return ""
            return _epieos_normalize_handle_candidate(path_parts[0])
        if path_parts[0].lower() in _GITHUB_RESERVED_PROFILE_PATHS:
            return ""
        return path_parts[0].lstrip("@")
    if hostname.endswith("gitlab.com"):
        if path_parts[0].lower() in _GITLAB_RESERVED_PROFILE_PATHS:
            return ""
        return path_parts[0].lstrip("@")
    if hostname.endswith("bitbucket.org"):
        if path_parts[0].lower() in _BITBUCKET_RESERVED_PROFILE_PATHS:
            return ""
        return path_parts[0].lstrip("@")
    if hostname.endswith("codeberg.org"):
        if path_parts[0].lower() in _CODEBERG_RESERVED_PROFILE_PATHS:
            return ""
        return path_parts[0].lstrip("@")
    if hostname.endswith("codepen.io"):
        if path_parts[0].lower() in _CODEPEN_RESERVED_PROFILE_HANDLES:
            return ""
        return _epieos_normalize_handle_candidate(path_parts[0])
    if hostname == "sr.ht" or hostname.endswith(".sr.ht"):
        if path_parts[0].startswith("~"):
            return path_parts[0].lstrip("~@")
        return ""
    if hostname.endswith("sourceforge.net"):
        if len(path_parts) < 2 or path_parts[0].lower() != "u":
            return ""
        if len(path_parts) >= 3 and path_parts[2].lower() not in {"profile", "activity", "wiki"}:
            return ""
        sourceforge_handle = path_parts[1].lstrip("@")
        if sourceforge_handle.lower() in _SOURCEFORGE_RESERVED_PROFILE_HANDLES:
            return ""
        return _epieos_normalize_handle_candidate(sourceforge_handle)
    if hostname.endswith("snapchat.com"):
        if not path_parts:
            return ""
        first_path = path_parts[0].lower()
        if first_path == "add" and len(path_parts) >= 2:
            handle = path_parts[1].lstrip("@")
            if handle.lower() in _SNAPCHAT_RESERVED_PROFILE_PATHS:
                return ""
            return _epieos_normalize_handle_candidate(handle)
        return ""
    if hostname.endswith("instagram.com"):
        return path_parts[0].lstrip("@")
    if hostname.endswith("500px.com"):
        if len(path_parts) >= 2 and path_parts[0].lower() == "p":
            return _epieos_normalize_handle_candidate(path_parts[1])
        return ""
    if hostname.endswith("x.com") or hostname.endswith("twitter.com"):
        if path_parts[0].lower() in _TWITTER_RESERVED_PROFILE_PATHS:
            return ""
        return path_parts[0].lstrip("@")
    if hostname.endswith("facebook.com"):
        return path_parts[0].lstrip("@")
    if hostname.endswith("flickr.com"):
        if len(path_parts) < 2 or path_parts[0].lower() != "photos":
            return ""
        reserved_flickr_photos = {
            "albums",
            "archive",
            "favorites",
            "faves",
            "friends",
            "map",
            "organize",
            "popular",
            "recent",
            "search",
            "tags",
        }
        if path_parts[1].lower() in reserved_flickr_photos:
            return ""
        return _epieos_normalize_handle_candidate(path_parts[1])
    if hostname == "vimeo.com":
        reserved_vimeo = {
            "about",
            "album",
            "blog",
            "categories",
            "channels",
            "features",
            "groups",
            "help",
            "join",
            "log_in",
            "login",
            "manage",
            "ondemand",
            "pricing",
            "search",
            "showcase",
            "staffpicks",
            "stock",
            "upload",
            "video",
            "watch",
        }
        if path_parts[0].lower() in reserved_vimeo:
            return ""
        return _epieos_normalize_vimeo_handle_candidate(path_parts[0])
    if hostname.endswith("kaggle.com"):
        reserved_kaggle = {
            "account",
            "code",
            "competitions",
            "datasets",
            "docs",
            "jobs",
            "learn",
            "models",
            "organizations",
            "settings",
            "signin",
            "signup",
            "team",
        }
        if path_parts[0].lower() not in reserved_kaggle:
            return path_parts[0].lstrip("@")
        return ""
    if hostname.endswith("keybase.io"):
        if path_parts[0].lower() in _KEYBASE_RESERVED_PROFILE_PATHS:
            return ""
        return path_parts[0].lstrip("@")
    if hostname.endswith("launchpad.net"):
        if not path_parts[0].startswith("~"):
            return ""
        launchpad_handle = path_parts[0].lstrip("~@")
        if launchpad_handle.lower() in _LAUNCHPAD_RESERVED_PROFILE_HANDLES:
            return ""
        return _epieos_normalize_handle_candidate(launchpad_handle)
    if hostname.endswith("last.fm"):
        if len(path_parts) >= 2 and path_parts[0].lower() == "user":
            return _epieos_normalize_lastfm_handle_candidate(path_parts[1])
        return ""
    if hostname == "t.me" or hostname.endswith(".t.me") or hostname.endswith("telegram.me"):
        if path_parts[0].lower() in _TELEGRAM_RESERVED_PROFILE_PATHS:
            return ""
        return path_parts[0].lstrip("@")
    if hostname.endswith("reddit.com") and len(path_parts) >= 2 and path_parts[0].lower() in {"u", "user"}:
        return path_parts[1].lstrip("@")
    if hostname.endswith("speakerdeck.com"):
        reserved_speakerdeck = {
            "about",
            "browse",
            "c",
            "categories",
            "category",
            "explore",
            "features",
            "login",
            "p",
            "presentations",
            "search",
            "sign_in",
            "signin",
            "signup",
            "speakers",
        }
        if path_parts[0].lower() not in reserved_speakerdeck:
            return path_parts[0].lstrip("@")
        return ""
    if hostname.endswith("slideshare.net"):
        reserved_slideshare = {
            "about",
            "category",
            "clipboards",
            "contact",
            "discover",
            "featured",
            "login",
            "mobile",
            "popular",
            "search",
            "signup",
            "upload",
        }
        if path_parts[0].lower() not in reserved_slideshare:
            return path_parts[0].lstrip("@")
        return ""
    if hostname.endswith("soundcloud.com"):
        reserved_soundcloud = {
            "about",
            "charts",
            "discover",
            "for-artists",
            "go",
            "imprint",
            "jobs",
            "login",
            "messages",
            "mobile",
            "pages",
            "people",
            "playlists",
            "premium",
            "pro",
            "search",
            "settings",
            "signup",
            "stream",
            "terms-of-use",
            "upload",
            "you",
        }
        if path_parts[0].lower() not in reserved_soundcloud:
            return path_parts[0].lstrip("@")
        return ""
    if hostname in {"open.spotify.com", "spotify.com"}:
        if len(path_parts) >= 2 and path_parts[0].lower() == "user":
            return path_parts[1].lstrip("@")
        return ""
    if hostname.endswith("strava.com"):
        if len(path_parts) >= 2 and path_parts[0].lower() in {"athletes", "pros"}:
            return _epieos_normalize_handle_candidate(path_parts[1])
        return ""
    if hostname.endswith("unsplash.com"):
        if path_parts[0].startswith("@"):
            return _epieos_normalize_handle_candidate(path_parts[0])
        return ""
    if hostname.endswith("pinterest.com"):
        reserved_pinterest = {
            "about",
            "business",
            "categories",
            "category",
            "explore",
            "ideas",
            "login",
            "messages",
            "notifications",
            "oauth",
            "pin",
            "privacy",
            "search",
            "settings",
            "signup",
            "terms",
            "today",
        }
        if path_parts[0].lower() in reserved_pinterest:
            return ""
        return _epieos_normalize_pinterest_handle_candidate(path_parts[0])
    if hostname.endswith("quora.com"):
        if len(path_parts) >= 2 and path_parts[0].lower() == "profile":
            return _epieos_normalize_handle_candidate(path_parts[1])
        return ""
    if hostname.endswith("500px.com"):
        if len(path_parts) >= 2 and path_parts[0].lower() == "p":
            return _epieos_normalize_handle_candidate(path_parts[1])
        return ""
    normalized_hostname = hostname[4:] if hostname.startswith("www.") else hostname
    if normalized_hostname.endswith(".artstation.com"):
        artstation_slug = normalized_hostname[: -len(".artstation.com")].strip(".")
        if artstation_slug and artstation_slug.lower() not in _ARTSTATION_RESERVED_SUBDOMAINS:
            return _epieos_normalize_handle_candidate(artstation_slug)
        return ""
    if normalized_hostname.endswith("artstation.com"):
        if not path_parts:
            return ""
        if path_parts[0].lower() in _ARTSTATION_RESERVED_PROFILE_HANDLES:
            return ""
        return _epieos_normalize_handle_candidate(path_parts[0])
    if normalized_hostname.endswith(".deviantart.com"):
        deviantart_slug = normalized_hostname[: -len(".deviantart.com")].strip(".")
        if deviantart_slug and deviantart_slug.lower() not in _DEVIANTART_RESERVED_SUBDOMAINS:
            return _epieos_normalize_handle_candidate(deviantart_slug)
        return ""
    if normalized_hostname.endswith("deviantart.com"):
        if not path_parts:
            return ""
        if path_parts[0].lower() in _DEVIANTART_RESERVED_PROFILE_HANDLES:
            return ""
        return _epieos_normalize_handle_candidate(path_parts[0])
    if hostname.endswith("steamcommunity.com"):
        if len(path_parts) >= 2 and path_parts[0].lower() == "id":
            return path_parts[1].lstrip("@")
        return ""
    if hostname.endswith("dev.to"):
        if path_parts[0].lower() in _DEVTO_RESERVED_PROFILE_PATHS:
            return ""
        return path_parts[0].lstrip("@")
    if hostname.endswith("npmjs.com") and path_parts[0].startswith("~"):
        return path_parts[0].lstrip("~@")
    if hostname.endswith("pypi.org") and len(path_parts) >= 2 and path_parts[0].lower() == "user":
        return path_parts[1].lstrip("@")
    if hostname.endswith("huggingface.co") and len(path_parts) == 1:
        reserved_huggingface = {
            "blog",
            "chat",
            "collections",
            "datasets",
            "docs",
            "enterprise",
            "join",
            "leaderboards",
            "login",
            "models",
            "new",
            "organizations",
            "papers",
            "pricing",
            "settings",
            "spaces",
            "tasks",
        }
        if path_parts[0].lower() not in reserved_huggingface:
            return path_parts[0].lstrip("@")
        return ""
    if hostname.endswith("about.me"):
        return path_parts[0].lstrip("@")
    if hostname.endswith("threads.net") or hostname.endswith("threads.com"):
        return path_parts[0].lstrip("@")
    if hostname.endswith("tiktok.com") and path_parts[0].startswith("@"):
        return path_parts[0].lstrip("@")
    if hostname.endswith("tryhackme.com"):
        if len(path_parts) >= 2 and path_parts[0].lower() == "p":
            return path_parts[1].lstrip("@")
        return ""
    if hostname.endswith("twitch.tv"):
        reserved_twitch = {
            "about",
            "activate",
            "bits",
            "creatorcamp",
            "directory",
            "downloads",
            "drops",
            "inventory",
            "jobs",
            "login",
            "p",
            "search",
            "settings",
            "signup",
            "store",
            "subscriptions",
            "team",
            "teams",
            "turbo",
            "videos",
            "wallet",
        }
        if path_parts[0].lower() not in reserved_twitch:
            return path_parts[0].lstrip("@")
        return ""
    if hostname.endswith("substack.com"):
        normalized_host = hostname[4:] if hostname.startswith("www.") else hostname
        if normalized_host != "substack.com":
            sub_host = normalized_host[: -len(".substack.com")].strip(".")
            if sub_host and sub_host.lower() not in _SUBSTACK_RESERVED_SUBDOMAINS:
                return sub_host
            return ""
        if path_parts[0].startswith("@"):
            return path_parts[0].lstrip("@")
        if path_parts[0].lower() in _SUBSTACK_RESERVED_PROFILE_PATHS:
            return ""
        return ""
    if hostname.endswith("youtube.com"):
        if path_parts[0].startswith("@"):
            return path_parts[0].lstrip("@")
        if len(path_parts) >= 2 and path_parts[0] in {"channel", "c", "user"}:
            return path_parts[1].lstrip("@")
        return ""
    if hostname.endswith("taplink.cc"):
        if path_parts[0].lower() in _TAPLINK_RESERVED_PROFILE_PATHS:
            return ""
        return _epieos_normalize_handle_candidate(path_parts[0])
    if hostname.endswith("taplink.ws"):
        normalized_host = hostname[4:] if hostname.startswith("www.") else hostname
        if normalized_host == "taplink.ws":
            return ""
        taplink_slug = normalized_host[: -len(".taplink.ws")].strip(".")
        if taplink_slug.lower() in _TAPLINK_RESERVED_PROFILE_PATHS:
            return ""
        return _epieos_normalize_handle_candidate(taplink_slug)
    if hostname.endswith("bio.site"):
        if path_parts[0].lower() in _BIO_SITE_RESERVED_PROFILE_PATHS:
            return ""
        return _epieos_normalize_handle_candidate(path_parts[0])
    if hostname.endswith("allmylinks.com"):
        if path_parts[0].lower() in _ALLMYLINKS_RESERVED_PROFILE_PATHS:
            return ""
        return _epieos_normalize_handle_candidate(path_parts[0])
    if hostname.endswith("bento.me"):
        if path_parts[0].lower() in _BENTO_RESERVED_PROFILE_PATHS:
            return ""
        return _epieos_normalize_handle_candidate(path_parts[0])
    if hostname.endswith("hoo.be"):
        if path_parts[0].lower() in _HOO_BE_RESERVED_PROFILE_PATHS:
            return ""
        return _epieos_normalize_handle_candidate(path_parts[0])
    if hostname.endswith("campsite.bio"):
        if path_parts[0].lower() in _CAMPSITE_BIO_RESERVED_PROFILE_PATHS:
            return ""
        return _epieos_normalize_handle_candidate(path_parts[0])
    if hostname.endswith("msha.ke"):
        if path_parts[0].lower() in _MILKSHAKE_RESERVED_PROFILE_PATHS:
            return ""
        return _epieos_normalize_handle_candidate(path_parts[0])
    if hostname.endswith("muckrack.com"):
        if len(path_parts) != 1:
            return ""
        if path_parts[0].lower() in _MUCKRACK_RESERVED_PROFILE_HANDLES:
            return ""
        return _epieos_normalize_handle_candidate(path_parts[0])
    if hostname.endswith("bsky.app") and len(path_parts) >= 2 and path_parts[0].lower() == "profile":
        return path_parts[1].lstrip("@")
    if hostname.endswith("bsky.social") and len(path_parts) >= 2 and path_parts[0].lower() == "profile":
        return path_parts[1].lstrip("@")
    if hostname.endswith("bsky.social") and path_parts[0].startswith("@"):
        return path_parts[0].lstrip("@")
    if _is_mastodon_like_host(hostname):
        if path_parts[0].startswith("@"):
            return path_parts[0].lstrip("@")
        if len(path_parts) >= 2 and path_parts[0].lower() in {"users", "web"}:
            return path_parts[1].lstrip("@")
        return ""
    if hostname.endswith("medium.com"):
        normalized_host = hostname[4:] if hostname.startswith("www.") else hostname
        if normalized_host != "medium.com":
            sub_host = normalized_host[: -len(".medium.com")].strip(".")
            if sub_host and sub_host.lower() not in _MEDIUM_RESERVED_SUBDOMAINS:
                return sub_host
            return ""
        if path_parts[0].startswith("@"):
            return path_parts[0].lstrip("@")
        if path_parts[0].lower() in _MEDIUM_RESERVED_PROFILE_PATHS:
            return ""
    return ""


def _epieos_handle_from_profile_url(url: str) -> str:
    try:
        from forge.engagement_orchestrator import EngagementSynthesisEngine
    except Exception:
        return ""
    try:
        return str(
            EngagementSynthesisEngine._extract_social_profile_handle_from_url(url)
            or ""
        ).strip()
    except Exception:
        return ""


def _epieos_mastodon_handle_from_path_parts(path_parts: list[str]) -> str:
    if not path_parts:
        return ""
    first_path = str(path_parts[0] or "").strip()
    if first_path.startswith("@"):
        return _epieos_normalize_handle_candidate(first_path.lstrip("@"))
    if len(path_parts) >= 2 and first_path.lower() in {"users", "web"}:
        return _epieos_normalize_handle_candidate(path_parts[1])
    return ""


def _epieos_direct_handle_is_reserved(platform_name: str, handle: str) -> bool:
    platform_text = str(platform_name or "").strip().lower()
    handle_text = str(handle or "").strip().lstrip("@")
    if platform_text == "orcid":
        return not bool(_ORCID_PROFILE_ID_RE.fullmatch(handle_text))
    reserved = _DIRECT_HANDLE_RESERVED_PROFILE_PATHS_BY_PLATFORM.get(platform_text)
    return bool(reserved and handle_text.lower() in reserved)


def _epieos_stack_exchange_host(data: dict[str, Any]) -> str:
    for candidate in (
        data.get("site"),
        data.get("site_url"),
        data.get("siteUrl"),
        data.get("domain"),
        data.get("host"),
        data.get("hostname"),
        data.get("network"),
        data.get("profile_url"),
        data.get("url"),
    ):
        text = str(candidate or "").strip()
        if not text:
            continue
        parsed = urlparse(text if "://" in text else f"https://{text}")
        hostname = str(parsed.hostname or "").strip().lower()
        if hostname.startswith("www."):
            hostname = hostname[4:]
        if _epieos_is_stack_exchange_profile_host(hostname):
            return hostname
    return ""


def _epieos_is_stack_exchange_profile_host(hostname: str) -> bool:
    return _shared_stack_exchange_profile_host(hostname)


def _epieos_mastodon_instance(data: dict[str, Any], handle: str) -> str:
    del handle
    for candidate in (
        data.get("instance"),
        data.get("server"),
        data.get("domain"),
        data.get("host"),
        data.get("profile_url"),
        data.get("url"),
    ):
        text = str(candidate or "").strip()
        if not text:
            continue
        parsed = urlparse(text if "://" in text else f"https://{text}")
        hostname = str(parsed.hostname or "").strip().lower()
        if hostname.startswith("www."):
            hostname = hostname[4:]
        if _epieos_is_federated_instance_candidate_host(hostname):
            return hostname
    raw_handle = _first_non_empty_string(
        data.get("handle"),
        data.get("username"),
        data.get("acct"),
        data.get("preferred_username"),
    )
    if "@" in raw_handle:
        parts = [part.strip() for part in raw_handle.split("@") if part.strip()]
        if len(parts) >= 2:
            return parts[-1].lower()
    return ""


def _epieos_is_supported_profile_host(hostname: str) -> bool:
    return _shared_supported_profile_host(hostname, _EPIEOS_PLATFORM_PROFILE_HOSTS)


def _epieos_is_federated_instance_candidate_host(hostname: str) -> bool:
    return _shared_federated_instance_candidate_host(
        hostname,
        _EPIEOS_PLATFORM_PROFILE_HOSTS,
    )


def _epieos_string_list(
    data: dict[str, Any],
    *keys: str,
    nested_keys: tuple[str, ...],
    extra_values: list[Any] | None = None,
    fallback_dict_values: bool = False,
) -> list[str]:
    values: list[str] = []
    seen: set[str] = set()

    def _append(candidate: Any) -> None:
        text = str(candidate or "").strip()
        if not text or text in seen:
            return
        seen.add(text)
        values.append(text)

    def _consume(value: Any) -> None:
        if isinstance(value, str):
            _append(value)
            return
        if isinstance(value, dict):
            consumed_nested_key = False
            for nested_key in nested_keys:
                if nested_key in value:
                    consumed_nested_key = True
                    _consume(value.get(nested_key))
            if consumed_nested_key:
                return
            if fallback_dict_values:
                for nested_value in value.values():
                    _consume(nested_value)
            return
        if isinstance(value, (list, tuple, set)):
            for item in value:
                _consume(item)

    for key in keys:
        _consume(data.get(key))
    for item in extra_values or []:
        _consume(item)
    return values


def _epieos_is_identity_claim_container_key(value: Any) -> bool:
    normalized = str(value or "").strip().lower()
    return normalized in _EPIEOS_IDENTITY_CLAIM_CONTAINER_KEY_SET


def _epieos_identity_claim_containers(data: dict[str, Any]) -> list[dict[str, Any]]:
    containers: list[dict[str, Any]] = []
    for key in _EPIEOS_IDENTITY_CLAIM_CONTAINER_KEYS:
        value = data.get(key)
        if isinstance(value, dict):
            containers.append(value)
    return containers


def _epieos_identity_claim_email_values(data: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for claims in _epieos_identity_claim_containers(data):
        values.extend(_epieos_claim_email_values(claims))
    return list(dict.fromkeys(values))


def _epieos_identity_claim_phone_values(data: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for claims in _epieos_identity_claim_containers(data):
        values.extend(_epieos_claim_phone_values(claims))
    return list(dict.fromkeys(values))


def _epieos_identity_claim_url_values(data: dict[str, Any], nested_keys: tuple[str, ...]) -> list[str]:
    values: list[str] = []
    for claims in _epieos_identity_claim_containers(data):
        values.extend(_epieos_claim_url_values(claims, nested_keys))
    return list(dict.fromkeys(values))


def _epieos_claim_url_values(value: Any, nested_keys: tuple[str, ...]) -> list[str]:
    if not isinstance(value, dict):
        return []
    return _epieos_string_list(
        value,
        "profile",
        "website",
        "website_url",
        "websiteUrl",
        "websiteURL",
        "homepage",
        "homepage_url",
        "homepageUrl",
        "homepageURL",
        "home_page",
        "homePage",
        "home_url",
        "homeUrl",
        "homeURL",
        "blog",
        "blog_url",
        "blogUrl",
        nested_keys=nested_keys,
    )


def _epieos_claim_email_values(value: Any) -> list[str]:
    if not isinstance(value, dict):
        return []
    return _epieos_email_list(
        value,
        *_EPIEOS_EMAIL_FIELD_KEYS,
        nested_keys=("value", *_EPIEOS_EMAIL_FIELD_KEYS),
    )


def _epieos_claim_phone_values(value: Any) -> list[str]:
    if not isinstance(value, dict):
        return []
    return _epieos_phone_list(
        value,
        *_EPIEOS_PHONE_FIELD_KEYS,
        nested_keys=("value", *_EPIEOS_PHONE_FIELD_KEYS),
    )


def _epieos_email_values(value: Any) -> list[str]:
    text = str(value or "").strip()
    if not text:
        return []
    parsed = urlparse(text)
    if parsed.scheme.lower() in {"http", "https"} and parsed.hostname and parsed.username:
        return []
    if parsed.scheme.lower() in {"sip", "sips", "xmpp"}:
        contact_value = unquote(parsed.path or parsed.netloc or "").strip()
        mailbox = contact_value.split(";", 1)[0].split("/", 1)[0].strip()
        local_part = mailbox.split("@", 1)[0].strip()
        if _epieos_normalize_phone_value(local_part):
            return []
        text = mailbox
    values: list[str] = []
    direct_candidate = text.lower()
    if _EPIEOS_EMAIL_RE.fullmatch(direct_candidate):
        values.append(direct_candidate)
    for match in _EPIEOS_EMAIL_RE.finditer(text):
        values.append(match.group(0).lower())
    return list(dict.fromkeys(values))


def _epieos_email_list(
    data: dict[str, Any],
    *keys: str,
    nested_keys: tuple[str, ...],
    extra_values: list[Any] | None = None,
) -> list[str]:
    raw_values = _epieos_string_list(
        data,
        *keys,
        nested_keys=nested_keys,
        extra_values=extra_values,
    )
    values: list[str] = []
    for raw_value in raw_values:
        values.extend(_epieos_email_values(raw_value))
    return list(dict.fromkeys(values))


def _epieos_normalize_phone_value(value: Any) -> str:
    candidate = str(value or "").strip()
    if not candidate:
        return ""
    candidate = _EPIEOS_PHONE_NORMALIZE_RE.sub("", candidate)
    if candidate.startswith("00") and len(candidate) > 3:
        candidate = f"+{candidate[2:]}"
    if candidate.startswith("+") and re.match(r"^\+\d{6,15}$", candidate):
        return candidate
    return ""


def _epieos_normalize_contact_query_phone(value: Any) -> str:
    candidate = str(value or "").strip()
    if re.fullmatch(r"\d{6,15}", candidate):
        return _epieos_normalize_phone_value(f"+{candidate}")
    return _epieos_normalize_phone_value(candidate)


def _epieos_phone_values(value: Any) -> list[str]:
    text = str(value or "").strip()
    if not text:
        return []
    values: list[str] = []
    parsed = urlparse(text)
    scheme = parsed.scheme.lower()
    hostname = str(parsed.hostname or "").strip().lower()
    if hostname.startswith("www."):
        hostname = hostname[4:]
    if scheme in {"whatsapp", "tg", "telegram"}:
        query_map = parse_qs(parsed.query, keep_blank_values=False)
        for query_key in ("phone", "to", "recipient"):
            for item in query_map.get(query_key, []):
                candidate = _epieos_normalize_contact_query_phone(item)
                if candidate:
                    values.append(candidate)
    if scheme in {"sms", "smsto", "mms", "mmsto"}:
        contact_target = parsed.path or parsed.netloc or ""
        if parsed.params:
            contact_target = f"{contact_target};{parsed.params}"
        for part in re.split(r"[,;]", contact_target):
            candidate = _epieos_normalize_contact_query_phone(part)
            if candidate:
                values.append(candidate)
        query_map = parse_qs(parsed.query, keep_blank_values=False)
        for query_key in ("to", "phone", "recipient"):
            for item in query_map.get(query_key, []):
                for part in re.split(r"[,;]", item):
                    candidate = _epieos_normalize_contact_query_phone(part)
                    if candidate:
                        values.append(candidate)
    if scheme in {"http", "https"}:
        if hostname == "wa.me":
            number = unquote(str(parsed.path or "").strip("/")).strip()
            if re.fullmatch(r"\d{6,15}", number):
                candidate = _epieos_normalize_phone_value(f"+{number}")
                if candidate:
                    values.append(candidate)
        elif hostname.endswith("whatsapp.com"):
            query_map = parse_qs(parsed.query, keep_blank_values=False)
            for item in query_map.get("phone", []):
                candidate = _epieos_normalize_contact_query_phone(item)
                if candidate:
                    values.append(candidate)
        elif hostname in {"t.me", "telegram.me"}:
            number = unquote(str(parsed.path or "").strip("/")).strip()
            if re.fullmatch(r"\+?\d{6,15}", number):
                candidate = _epieos_normalize_contact_query_phone(number)
                if candidate:
                    values.append(candidate)
    direct_candidate = _epieos_normalize_phone_value(text)
    if direct_candidate:
        values.append(direct_candidate)
    for match in _EPIEOS_PHONE_RE.finditer(text):
        candidate = _epieos_normalize_phone_value(match.group(1))
        if candidate:
            values.append(candidate)
    return list(dict.fromkeys(values))


def _epieos_phone_list(
    data: dict[str, Any],
    *keys: str,
    nested_keys: tuple[str, ...],
    extra_values: list[Any] | None = None,
) -> list[str]:
    raw_values = _epieos_string_list(
        data,
        *keys,
        nested_keys=nested_keys,
        extra_values=extra_values,
    )
    values: list[str] = []
    for raw_value in raw_values:
        values.extend(_epieos_phone_values(raw_value))
    return list(dict.fromkeys(values))


def _epieos_domain_values(value: Any) -> list[str]:
    text = str(value or "").strip()
    if not text or "@" in text:
        return []
    prefix, separator, suffix = text.partition(":")
    if separator and prefix.lower() in {"applinks", "webcredentials", "activitycontinuation", "appclips"}:
        text = suffix.strip()
        if not text or "@" in text:
            return []
    candidate = text
    if candidate.startswith("//"):
        candidate = f"https:{candidate}"
    parsed = urlparse(candidate)
    if not parsed.scheme:
        candidate = f"https://{candidate}"
        parsed = urlparse(candidate)
    hostname = str(parsed.hostname or "").strip().lower().strip(".")
    if hostname.startswith("*."):
        hostname = hostname[2:]
    if not hostname or not _EPIEOS_DOMAIN_RE.fullmatch(hostname):
        return []
    return [hostname]


def _epieos_domain_list(
    data: dict[str, Any],
    *keys: str,
    nested_keys: tuple[str, ...],
    extra_values: list[Any] | None = None,
) -> list[str]:
    raw_values = _epieos_string_list(
        data,
        *keys,
        nested_keys=nested_keys,
        extra_values=extra_values,
    )
    values: list[str] = []
    for raw_value in raw_values:
        values.extend(_epieos_domain_values(raw_value))
    return list(dict.fromkeys(values))


def _epieos_company_name(platform: str, data: dict[str, Any]) -> str:
    for key in (
        "company",
        "companies",
        "company_name",
        "companyName",
        "organization",
        "organizations",
        "organization_name",
        "organizationName",
        "org",
        "orgs",
        "employer",
        "employer_name",
        "employerName",
        "employers",
        "works_for",
        "worksFor",
        "member_of",
        "memberOf",
        "alumni_of",
        "alumniOf",
        "affiliation",
        "affiliations",
    ):
        explicit = _epieos_named_entity_value(data.get(key))
        if explicit:
            return explicit
    work_history_name = _epieos_work_history_company_name(data)
    if work_history_name:
        return work_history_name
    platform_name = str(platform or "").strip().lower()
    if platform_name in {"wellfound", "angellist", "angel.co"}:
        for key in ("profile_url", "profileUrl", "profileURL", "url", "html_url", "htmlUrl", "link"):
            slug = _epieos_company_profile_slug_from_url(str(data.get(key) or ""))
            if slug:
                return _epieos_humanize_slug(slug)
    if platform_name in _EPIEOS_COMPANY_PLATFORM_NAMES:
        return _first_non_empty_string(
            data.get("display_name"),
            data.get("name"),
            data.get("full_name"),
            data.get("slug"),
        ) or _epieos_humanize_slug(_epieos_company_profile_slug(data))
    return ""


def _epieos_work_history_company_name(data: dict[str, Any]) -> str:
    for key in _EPIEOS_WORK_HISTORY_CONTAINER_KEYS:
        candidate = _epieos_work_history_company_name_value(data.get(key))
        if candidate:
            return candidate
    return ""


def _epieos_work_history_company_name_value(value: Any) -> str:
    if isinstance(value, list):
        for item in value[:256]:
            candidate = _epieos_work_history_company_name_value(item)
            if candidate:
                return candidate
        return ""
    if isinstance(value, tuple):
        return _epieos_work_history_company_name_value(list(value))
    if not isinstance(value, dict):
        return ""
    for key in _EPIEOS_WORK_HISTORY_ORGANIZATION_FIELD_KEYS:
        candidate = _epieos_named_entity_value(value.get(key))
        if candidate:
            return candidate
    return ""


class EpieosClient:
    def __init__(self, proxy: Optional[str] = None, max_concurrency: int | None = None) -> None:
        self._proxy = proxy or os.environ.get("HTTPS_PROXY") or os.environ.get("HTTP_PROXY")
        self._max_concurrency = (
            _epieos_max_concurrency_default()
            if max_concurrency is None
            else max(1, min(int(max_concurrency or 1), 4))
        )

    async def query_many(self, emails: list[str]) -> dict[str, list[dict]]:
        if not emails:
            return {}

        semaphore = asyncio.Semaphore(self._max_concurrency)

        async def _worker(email: str) -> tuple[str, Optional[dict]]:
            async with semaphore:
                payload = await _query_epieos(email, self._proxy)
                return email, payload

        results: dict[str, list[dict]] = {}
        for email, payload in await asyncio.gather(*(_worker(email) for email in emails)):
            if payload is None:
                continue
            results[email] = _parse_epieos_response(payload)
        return results


async def _query_epieos(email: str, proxy: Optional[str] = None) -> Optional[dict]:
    """
    Fresh session per target — session reuse is a de-anonymisation vector.
    """
    if AsyncSession is None:
        raise ImportError("curl_cffi required: pip install curl_cffi")

    session_kwargs = {"impersonate": "chrome124"}
    if proxy:
        session_kwargs["proxies"] = {"https": proxy}
    async with AsyncSession(**session_kwargs) as client:
        try:
            resp = await client.get(
                _EPIEOS_URL,
                params={"q": email, "type": "email"},
                headers={"User-Agent": _UA},
                timeout=_TIMEOUT,
            )
            resp.raise_for_status()
            return resp.json()
        except Exception as exc:
            _LOG.error("Epieos query failed for %s: %s", email, exc)
            return None


def _scope_check(email: str, scope: list[str]) -> bool:
    return email_address_in_scope(email, scope)


def _find_email_column(con: sqlite3.Connection) -> str:
    cols = {r[1] for r in con.execute("PRAGMA table_info(emails)").fetchall()}
    if "email" in cols:
        return "email"
    if "address" in cols:
        return "address"
    raise sqlite3.OperationalError("emails.email or emails.address column is required")


def run_social_scraper(
    db_path: Path,
    engagement_id: int,
    emails: Optional[list[str]] = None,
    target_emails: Optional[list[str]] = None,
    proxy: Optional[str] = None,
    dry_run: bool = False,
    operator: str = "operator",
    max_concurrency: int | None = None,
) -> int:
    """
    Query Epieos for each in-scope email; write results to social_profiles table.
    Returns count of rows upserted.
    """
    con = sqlite3.connect(db_path)
    con.execute(_SOCIAL_PROFILES_DDL)
    con.commit()

    scope_row = con.execute(
        "SELECT scope_json FROM engagements WHERE id=?", (engagement_id,)
    ).fetchone()
    from forge.opsec.scope_gate import scope_entries_from_payload

    scope = scope_entries_from_payload(json.loads(scope_row[0] or "[]")) if scope_row else []
    email_col = _find_email_column(con)

    emails = emails if emails is not None else target_emails
    if emails is None:
        rows = con.execute(
            f"SELECT {email_col} FROM emails WHERE engagement_id=?", (engagement_id,)
        ).fetchall()
        emails = [r[0] for r in rows]

    for email in emails:
        email = email.lower().strip()
        if not _scope_check(email, scope):
            from forge.opsec.scope_gate import ScopeViolationError

            con.close()
            raise ScopeViolationError(email, scope)

    if dry_run:
        con.close()
        return 0

    ts = datetime.now(timezone.utc).isoformat()
    client = EpieosClient(
        proxy=proxy,
        max_concurrency=(
            _epieos_max_concurrency_default()
            if max_concurrency is None
            else max(1, min(int(max_concurrency or 1), 4))
        ),
    )
    parsed_map = asyncio.run(client.query_many(emails))
    cols = {r[1] for r in con.execute("PRAGMA table_info(social_profiles)").fetchall()}
    written = 0

    for email, profiles in parsed_map.items():
        raw_enc = encrypt_string(json.dumps(profiles)) if encrypt_string else json.dumps(profiles)
        for profile in profiles:
            if {
                "platform",
                "profile_url",
                "display_name",
                "avatar_url",
                "raw_data_enc",
                "discovered_at",
            }.issubset(cols):
                con.execute(
                    """
                    INSERT INTO social_profiles
                        (engagement_id, email, platform, profile_url, display_name, avatar_url, raw_data_enc, discovered_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        engagement_id,
                        email,
                        profile.get("platform", ""),
                        profile.get("profile_url", ""),
                        profile.get("display_name", ""),
                        profile.get("avatar_url", ""),
                        raw_enc,
                        ts,
                    ),
                )
                written += 1
            else:
                con.execute(
                    """
                    INSERT INTO social_profiles
                        (engagement_id, email, source, profile_data, queried_at)
                    VALUES (?, ?, 'epieos', ?, ?)
                    ON CONFLICT(engagement_id, email, source)
                    DO UPDATE SET profile_data=excluded.profile_data,
                                  queried_at=excluded.queried_at
                    """,
                    (engagement_id, email, raw_enc, ts),
                )
                written += 1
        insert_audit_log(
            con,
            engagement_id,
            "epieos_query",
            f"email={email} profiles={len(profiles)}",
            phase="phase2",
            module="epieos",
            ts=ts,
        )

    con.commit()
    con.close()

    _LOG.info("social_scraper: %d rows upserted for engagement %d.", written, engagement_id)
    return written
