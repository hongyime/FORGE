"""Seed-promotion contracts and persistence helpers."""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

_SEED_SOURCE_PRIORITY = {
    "cross_reference": 1,
    "discovered": 2,
    "artifact": 3,
    "scope": 4,
    "operator": 5,
}


@dataclass
class SeedCandidate:
    seed_value: str
    seed_type: str
    source: str
    depth: int
    confidence: float
    parent_value: str | None = None
    parent_type: str | None = None
    relation_type: str = "derived_from"
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class SynthesisSummary:
    seeds_inserted: int = 0
    relations_inserted: int = 0
    promoted_count: int = 0
    corroborated_count: int = 0
    root_domains: list[str] = field(default_factory=list)
    promoted_seeds: list[str] = field(default_factory=list)


def synthesis_summary_log_message(
    summary: SynthesisSummary | None,
    *,
    include_roots: bool = False,
) -> str | None:
    if summary is None:
        return None
    if not (summary.seeds_inserted or summary.relations_inserted):
        return None
    if include_roots:
        return (
            f"seeds+={summary.seeds_inserted} "
            f"relations+={summary.relations_inserted} "
            f"roots={len(summary.root_domains)}"
        )
    return (
        f"seeds+={summary.seeds_inserted} "
        f"relations+={summary.relations_inserted} "
        f"corroborated={summary.corroborated_count}"
    )


SocialProfilePivot = tuple[str, str, str, float, dict[str, Any]]
SocialProfileHostEntry = tuple[str, str]


def safe_json_loads(value: str) -> Any:
    try:
        return json.loads(value)
    except Exception:  # noqa: BLE001
        return None


def preferred_seed_source(existing: str, candidate: str) -> str:
    existing_priority = _SEED_SOURCE_PRIORITY.get(existing, 0)
    candidate_priority = _SEED_SOURCE_PRIORITY.get(candidate, 0)
    return existing if existing_priority >= candidate_priority else candidate


def merge_seed_metadata(existing: Any, candidate: dict[str, Any]) -> dict[str, Any]:
    merged = existing if isinstance(existing, dict) else {}
    if candidate:
        merged = {**merged, **candidate}
    return merged


def seed_lookup_keys(seed_type: str, seed_value: str) -> list[tuple[str, str]]:
    normalized_type = str(seed_type or "").strip()
    normalized_value = str(seed_value or "").strip()
    if not normalized_type or not normalized_value:
        return []
    keys = [(normalized_type, normalized_value)]
    if normalized_type == "username":
        bare_value = normalized_value.lstrip("@")
        if bare_value:
            keys.append((normalized_type, bare_value))
            keys.append((normalized_type, f"@{bare_value}"))
    return list(dict.fromkeys(keys))


def lookup_seed_depth(
    seed_depths: dict[tuple[str, str], int],
    seed_type: str,
    seed_value: str,
) -> int:
    for key in seed_lookup_keys(seed_type, seed_value):
        if key in seed_depths:
            return int(seed_depths[key])
    return 0


def normalize_social_profile_anchor(
    value: str,
    *,
    normalize_phone_seed_value: Callable[[str], str],
    classify_seed_value: Callable[[str], str],
) -> tuple[str, str]:
    text = value.strip()
    lowered = text.lower()
    if lowered.startswith("domain:"):
        normalized = text.split(":", 1)[1].strip().lower().strip(".")
        return normalized, "domain"
    if lowered.startswith("subdomain:"):
        normalized = text.split(":", 1)[1].strip().lower().strip(".")
        return normalized, "subdomain"
    if lowered.startswith("phone:"):
        normalized = normalize_phone_seed_value(text.split(":", 1)[1])
        return normalized, "phone"
    if lowered.startswith("name:"):
        normalized = text.split(":", 1)[1].strip()
        return normalized, "name"
    if lowered.startswith("company:"):
        normalized = text.split(":", 1)[1].strip()
        return normalized, "company"
    if lowered.startswith("instagram:"):
        normalized = text.split(":", 1)[1].strip().lstrip("@")
        return normalized, "username"
    if lowered.startswith("username:"):
        normalized = text.split(":", 1)[1].strip().lstrip("@")
        return normalized, "username"
    if lowered.startswith("email:"):
        normalized = text.split(":", 1)[1].strip().lower()
        return normalized, "email"
    normalized = text.lstrip("@")
    return normalized, classify_seed_value(normalized)


def social_profile_anchor_confidence(anchor_type: str, source_label: str) -> float:
    source_text = str(source_label or "").strip().lower()
    if anchor_type == "email":
        return 0.82
    if anchor_type in {"domain", "subdomain", "url", "apk_url", "cloud_ref"}:
        return 0.74
    if anchor_type == "phone":
        return 0.73 if "phone" in source_text else 0.7
    if anchor_type in {"name", "company"}:
        return 0.72
    if anchor_type == "username":
        return 0.7
    return 0.68


def social_profile_anchor_seed_candidate(
    row: Any,
    seed_depths: dict[tuple[str, str], int],
    *,
    normalize_phone_seed_value: Callable[[str], str],
    classify_seed_value: Callable[[str], str],
) -> SeedCandidate | None:
    anchor_raw = str(row["email"] or "").strip()
    anchor_value, anchor_type = normalize_social_profile_anchor(
        anchor_raw,
        normalize_phone_seed_value=normalize_phone_seed_value,
        classify_seed_value=classify_seed_value,
    )
    if not anchor_value or not anchor_type:
        return None
    if anchor_type not in {
        "apk_url",
        "company",
        "domain",
        "email",
        "ipv4",
        "ipv6",
        "name",
        "phone",
        "subdomain",
        "url",
        "username",
    }:
        return None
    if (
        anchor_type == "username"
        and not anchor_value.startswith("@")
        and ("username", anchor_value) not in seed_depths
        and ("username", f"@{anchor_value}") in seed_depths
    ):
        return None
    source_label = str(row["source"] or "social_profile").strip().lower() or "social_profile"
    existing_depth = lookup_seed_depth(seed_depths, anchor_type, anchor_value)
    return SeedCandidate(
        seed_value=anchor_value,
        seed_type=anchor_type,
        source="discovered",
        depth=max(1, existing_depth or 1),
        confidence=social_profile_anchor_confidence(anchor_type, source_label),
        metadata={
            "rule": "social_profile_anchor",
            "source": source_label,
        },
    )


def social_profile_candidate_batch_entries(
    batch_entry: tuple[int, Any],
) -> list[SeedCandidate]:
    _batch_index, batch = batch_entry
    return [candidate for candidate in batch if isinstance(candidate, SeedCandidate)]


def social_profile_candidate_family_entries(
    family_entry: tuple[int, Any],
) -> list[SeedCandidate]:
    _family_index, family = family_entry
    return [candidate for candidate in family if isinstance(candidate, SeedCandidate)]


def social_profile_candidate_dedupe_family_entries(
    family_entry: tuple[int, Any],
) -> list[tuple[tuple[str, str, str | None, str | None], SeedCandidate]]:
    _family_index, family = family_entry
    prepared_entries: list[tuple[tuple[str, str, str | None, str | None], SeedCandidate]] = []
    for candidate in family:
        if not isinstance(candidate, SeedCandidate):
            continue
        prepared_entries.append(
            (
                (
                    candidate.seed_type,
                    candidate.seed_value,
                    candidate.parent_type,
                    candidate.parent_value,
                ),
                candidate,
            )
        )
    return prepared_entries


def social_profile_profile_candidates_from_pivots(
    pivots: Sequence[SocialProfilePivot],
    *,
    anchor_value: str,
    anchor_type: str,
    base_depth: int,
    depth_limit: int,
) -> list[SeedCandidate]:
    candidates: list[SeedCandidate] = []
    for seed_value, seed_type, relation_type, confidence, metadata in pivots:
        if not seed_value or seed_value == anchor_value:
            continue
        candidates.append(
            SeedCandidate(
                seed_value=seed_value,
                seed_type=seed_type,
                source="cross_reference",
                depth=min(depth_limit, max(1, base_depth) + 1),
                confidence=confidence,
                parent_value=anchor_value,
                parent_type=anchor_type,
                relation_type=relation_type,
                metadata=metadata,
            )
        )
    return candidates


def social_profile_pivot_batch_entries(
    batch_entry: tuple[int, Any],
) -> list[SocialProfilePivot]:
    _batch_index, batch = batch_entry
    return [
        pivot
        for pivot in batch
        if isinstance(pivot, tuple) and len(pivot) == 5 and isinstance(pivot[4], dict)
    ]


def social_profile_pivot_family_entries(
    family_entry: tuple[int, Any],
) -> list[SocialProfilePivot]:
    _family_index, family = family_entry
    return [
        pivot
        for pivot in family
        if isinstance(pivot, tuple) and len(pivot) == 5 and isinstance(pivot[4], dict)
    ]


def social_profile_url_pivot_entry(
    entry: tuple[str, str, float, str],
    *,
    classify_seed_value: Callable[[str], str],
) -> SocialProfilePivot | None:
    url, platform, base_confidence, source_label = entry
    url_type = classify_seed_value(url)
    if url_type not in {"url", "apk_url"}:
        return None
    return (
        url,
        url_type,
        "related_asset",
        max(0.68, base_confidence - 0.02),
        {"rule": "social_profile_url", "platform": platform, "source": source_label},
    )


def social_profile_host_pivot_entry(
    entry: tuple[str, str, str, float, str],
) -> SocialProfilePivot | None:
    host_value, host_type, platform, base_confidence, source_label = entry
    if not host_value or not host_type:
        return None
    return (
        host_value,
        host_type,
        "related_asset",
        max(0.7, base_confidence - 0.01),
        {"rule": "social_profile_host", "platform": platform, "source": source_label},
    )


def social_profile_seed_pivot_entry(
    entry: tuple[str, str, str, float, str, str, str],
) -> SocialProfilePivot | None:
    seed_value, seed_type, relation_type, confidence, rule, platform, source_label = entry
    if not seed_value or not seed_type:
        return None
    return (
        seed_value,
        seed_type,
        relation_type,
        confidence,
        {"rule": rule, "platform": platform, "source": source_label},
    )


def social_profile_handle_pivot_entry(
    entry: tuple[str, str, float, str],
    *,
    handle_allowed_for_platform: Callable[[str, str], bool],
) -> SocialProfilePivot | None:
    handle, platform, base_confidence, source_label = entry
    if len(handle) < 3:
        return None
    if not handle_allowed_for_platform(platform, handle):
        return None
    return (
        handle,
        "username",
        "same_entity",
        min(0.9, base_confidence + 0.02),
        {"rule": "social_profile_handle", "platform": platform, "source": source_label},
    )


def social_profile_platform_hint(
    profile: dict[str, Any],
    *,
    direct_platform: Callable[[dict[str, Any]], str],
    url_hint_values: Callable[[dict[str, Any]], list[Any]],
    platform_hint_candidate: Callable[[Any], str],
    run_ordered_batch: Callable[..., list[Any]],
) -> str:
    platform = direct_platform(profile)
    if platform:
        return platform
    platform_candidates = run_ordered_batch(
        url_hint_values(profile),
        platform_hint_candidate,
        default_factory=str,
    )
    for platform_candidate in platform_candidates:
        if platform_candidate:
            return platform_candidate
    return ""


def social_profile_direct_platform(
    profile: dict[str, Any],
    *,
    platform_alias_keys: Sequence[str],
    platform_label_candidate: Callable[[Any], str],
    run_ordered_batch: Callable[..., list[Any]],
) -> str:
    platform_candidates = run_ordered_batch(
        [profile.get(key) for key in platform_alias_keys],
        platform_label_candidate,
        default_factory=str,
    )
    for platform_candidate in platform_candidates:
        if platform_candidate:
            return platform_candidate
    return ""


def social_profile_platform_label_candidate(
    value: Any,
    *,
    platform_hint_candidate: Callable[[Any], str],
    is_social_platform_host: Callable[[str], bool],
    platform_label_aliases: Mapping[str, str],
) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    url_hint = platform_hint_candidate(text)
    if url_hint:
        return url_hint
    host_text = text.lower().removeprefix("www.").strip("/")
    if is_social_platform_host(host_text):
        host_hint = platform_hint_candidate(f"https://{host_text}/")
        if host_hint:
            return host_hint
    normalized = re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")
    if not normalized or len(normalized) > 64:
        return ""
    return platform_label_aliases.get(normalized, normalized)


def social_profile_platform_hint_candidate(
    candidate: Any,
    *,
    coerce_urlish_candidate: Callable[[Any], str],
    linkedin_app_profile_path_parts: Callable[[Any], list[str]],
    nostr_identity_handle_candidate: Callable[[Any], str],
    is_stack_exchange_network_host: Callable[[str], bool],
    is_mastodon_instance_host: Callable[[str], bool],
) -> str:
    candidate_text = coerce_urlish_candidate(candidate)
    parsed = urlparse(candidate_text)
    linkedin_app_parts = linkedin_app_profile_path_parts(parsed)
    if linkedin_app_parts:
        if linkedin_app_parts[0].lower() in {"company", "school", "showcase"}:
            return "linkedin_company"
        return "linkedin"
    if nostr_identity_handle_candidate(candidate_text):
        return "nostr"
    if str(parsed.scheme or "").strip().lower() == "acct":
        return "activitypub"
    if str(parsed.scheme or "").strip().lower() == "matrix":
        return "matrix"
    if str(parsed.scheme or "").strip().lower() == "nostr":
        return "nostr"
    hostname = str(parsed.hostname or "").strip().lower()
    if not hostname:
        return ""
    if hostname.startswith("www."):
        hostname = hostname[4:]
    if hostname in {
        "nostr.com",
        "nostrudel.ninja",
        "njump.me",
        "primal.net",
        "iris.to",
        "snort.social",
        "yakihonne.com",
    }:
        return "nostr"
    if hostname.endswith("academia.edu"):
        return "academia"
    if hostname.endswith("adplist.org"):
        return "adplist"
    if hostname.endswith("linkedin.com"):
        path_parts = [part for part in parsed.path.strip("/").split("/") if part]
        if path_parts and path_parts[0].lower() in {"company", "school", "showcase"}:
            return "linkedin_company"
        return "linkedin"
    if hostname.endswith("facebook.com"):
        return "facebook"
    if hostname.endswith("bitbucket.org"):
        return "bitbucket"
    if hostname.endswith("bugcrowd.com"):
        return "bugcrowd"
    if hostname.endswith("codeberg.org"):
        return "codeberg"
    if hostname.endswith("codepen.io"):
        return "codepen"
    if hostname.endswith("contra.com"):
        return "contra"
    if hostname in {"discord.com", "discord.gg", "discordapp.com"}:
        return "discord"
    if hostname == "hub.docker.com":
        return "dockerhub"
    if hostname == "gist.github.com":
        return "github_gist"
    if hostname.endswith("github.com"):
        return "github"
    if hostname.endswith("gitbook.com") or hostname.endswith("gitbook.io"):
        return "gitbook"
    if hostname.endswith("gitlab.com"):
        return "gitlab"
    if hostname.endswith("gravatar.com"):
        return "gravatar"
    if hostname == "news.ycombinator.com":
        return "hackernews"
    if hostname == "scholar.google.com":
        return "google_scholar"
    if hostname.endswith("hackerone.com"):
        return "hackerone"
    if hostname.endswith("hashnode.com"):
        return "hashnode"
    if hostname.endswith("instagram.com"):
        return "instagram"
    if hostname.endswith("indiehackers.com"):
        return "indiehackers"
    if hostname.endswith("intigriti.com"):
        return "intigriti"
    if hostname.endswith("kaggle.com"):
        return "kaggle"
    if hostname.endswith("flickr.com"):
        return "flickr"
    if hostname.endswith("last.fm"):
        return "lastfm"
    if hostname == "bandcamp.com" or hostname.endswith(".bandcamp.com"):
        return "bandcamp"
    if hostname == "artstation.com" or hostname.endswith(".artstation.com"):
        return "artstation"
    if hostname.endswith("letterboxd.com"):
        return "letterboxd"
    if hostname.endswith("500px.com"):
        return "500px"
    if hostname.endswith("x.com") or hostname.endswith("twitter.com"):
        return "twitter"
    if hostname.endswith("threads.net") or hostname.endswith("threads.com"):
        return "threads"
    if hostname.endswith("youtube.com") or hostname.endswith("youtu.be"):
        return "youtube"
    if hostname.endswith("linktr.ee"):
        return "linktree"
    if hostname.endswith("allmylinks.com"):
        return "allmylinks"
    if hostname == "orcid.org":
        return "orcid"
    if hostname == "researchgate.net":
        return "researchgate"
    if hostname == "credly.com":
        return "credly"
    if hostname == "behance.net":
        return "behance"
    if hostname == "dribbble.com":
        return "dribbble"
    if hostname.endswith("pinterest.com"):
        return "pinterest"
    if hostname == "calendly.com":
        return "calendly"
    if hostname == "cal.com":
        return "calcom"
    if hostname.endswith("polywork.com"):
        return "polywork"
    if hostname == "producthunt.com":
        return "producthunt"
    if hostname == "wellfound.com":
        return "wellfound"
    if hostname in {"angel.co", "angellist.com"}:
        return "angellist"
    if hostname.endswith("beacons.ai"):
        return "beacons"
    if hostname.endswith("bento.me"):
        return "bento"
    if hostname.endswith("hoo.be"):
        return "hoobe"
    if hostname.endswith("bio.link"):
        return "biolink"
    if hostname.endswith("bio.site"):
        return "biosite"
    if hostname.endswith("lnk.bio"):
        return "lnkbio"
    if hostname.endswith("solo.to"):
        return "soloto"
    if hostname.endswith("campsite.bio"):
        return "campsite"
    if hostname.endswith("taplink.cc") or hostname.endswith("taplink.ws"):
        return "taplink"
    if hostname.endswith("msha.ke"):
        return "milkshake"
    if hostname.endswith("carrd.co"):
        return "carrd"
    if hostname == "sr.ht" or hostname.endswith(".sr.ht"):
        return "sourcehut"
    if hostname.endswith("sourceforge.net"):
        return "sourceforge"
    if hostname.endswith("snapchat.com"):
        return "snapchat"
    if hostname.endswith("bsky.app") or hostname.endswith("bsky.social"):
        return "bluesky"
    if hostname.endswith("dev.to"):
        return "devto"
    if hostname == "deviantart.com" or hostname.endswith(".deviantart.com"):
        return "deviantart"
    if hostname.endswith("npmjs.com"):
        return "npm"
    if hostname.endswith("pypi.org"):
        return "pypi"
    if hostname.endswith("rubygems.org"):
        return "rubygems"
    if hostname.endswith("crates.io"):
        return "crates"
    if hostname.endswith("packagist.org"):
        return "packagist"
    if hostname.endswith("nuget.org"):
        return "nuget"
    if hostname.endswith("openbugbounty.org"):
        return "openbugbounty"
    if hostname.endswith("hex.pm"):
        return "hexpm"
    if hostname.endswith("huggingface.co"):
        return "huggingface"
    if hostname.endswith("tiktok.com"):
        return "tiktok"
    if hostname.endswith("tryhackme.com"):
        return "tryhackme"
    if hostname.endswith("yeswehack.com"):
        return "yeswehack"
    if hostname.endswith("twitch.tv"):
        return "twitch"
    if hostname.endswith("unsplash.com"):
        return "unsplash"
    if hostname == "vimeo.com":
        return "vimeo"
    if hostname.endswith("substack.com"):
        return "substack"
    if hostname.endswith("medium.com"):
        return "medium"
    if hostname == "matrix.to":
        return "matrix"
    if hostname.endswith("muckrack.com"):
        return "muckrack"
    if hostname.endswith("mixcloud.com"):
        return "mixcloud"
    if hostname.endswith("quora.com"):
        return "quora"
    if hostname.endswith("reddit.com"):
        return "reddit"
    if hostname.endswith("readme.io"):
        return "readmeio"
    if hostname.endswith("replit.com"):
        return "replit"
    if hostname.endswith("codesandbox.io"):
        return "codesandbox"
    if hostname.endswith("devpost.com"):
        return "devpost"
    if hostname.endswith("read.cv"):
        return "readcv"
    if hostname.endswith("speakerdeck.com"):
        return "speakerdeck"
    if hostname.endswith("slideshare.net"):
        return "slideshare"
    if hostname.endswith("soundcloud.com"):
        return "soundcloud"
    if hostname in {"open.spotify.com", "spotify.com"}:
        return "spotify"
    if hostname.endswith("strava.com"):
        return "strava"
    if hostname == "semanticscholar.org":
        return "semantic_scholar"
    if hostname == "zenodo.org":
        return "zenodo"
    if hostname.endswith("figma.com"):
        return "figma"
    if hostname.endswith("figshare.com"):
        return "figshare"
    if hostname.endswith("steamcommunity.com"):
        return "steam"
    if hostname.endswith("stackexchange.com"):
        return "stackexchange"
    if hostname.endswith("stackoverflow.com"):
        return "stackoverflow"
    if is_stack_exchange_network_host(hostname):
        return "stackexchange"
    if hostname.endswith("about.me"):
        return "aboutme"
    if hostname.endswith("500px.com"):
        return "500px"
    if hostname.endswith("keybase.io"):
        return "keybase"
    if hostname.endswith("launchpad.net"):
        return "launchpad"
    if hostname.endswith("opencollective.com"):
        return "opencollective"
    if hostname.endswith("liberapay.com"):
        return "liberapay"
    if hostname.endswith("patreon.com"):
        return "patreon"
    if hostname.endswith("ko-fi.com"):
        return "kofi"
    if hostname.endswith("buymeacoffee.com"):
        return "buymeacoffee"
    if hostname.endswith("t.me") or hostname.endswith("telegram.me"):
        return "telegram"
    if is_mastodon_instance_host(hostname):
        return "mastodon"
    return ""


def social_profile_url_hint_values(
    profile: dict[str, Any],
    *,
    url_hint_keys: Sequence[str],
    value_for_item_key: Callable[[tuple[dict[str, Any], str]], Any],
    run_ordered_batch: Callable[..., list[Any]],
) -> list[Any]:
    values = run_ordered_batch(
        [(profile, key) for key in url_hint_keys],
        value_for_item_key,
        default_factory=lambda: None,
    )
    return [value for value in values if value not in (None, "", [], {})]


def social_profile_scalar_url_hint_values(
    profile: dict[str, Any],
    *,
    url_hint_keys: Sequence[str],
    scalar_value_for_item_key: Callable[[tuple[dict[str, Any], str]], Any],
    run_ordered_batch: Callable[..., list[Any]],
) -> list[Any]:
    values = run_ordered_batch(
        [(profile, key) for key in url_hint_keys],
        scalar_value_for_item_key,
        default_factory=lambda: None,
    )
    return [value for value in values if value not in (None, "")]


def social_profile_identity_url_hint_values(
    profile: dict[str, Any],
    *,
    identity_url_hint_keys: Sequence[str],
    value_for_item_key: Callable[[tuple[dict[str, Any], str]], Any],
    run_ordered_batch: Callable[..., list[Any]],
) -> list[Any]:
    values = run_ordered_batch(
        [(profile, key) for key in identity_url_hint_keys],
        value_for_item_key,
        default_factory=lambda: None,
    )
    return [value for value in values if value not in (None, "", [], {})]


def social_profile_url_hint_value_for_item_key(
    item_key: tuple[dict[str, Any], str],
) -> Any:
    item, key = item_key
    if not isinstance(item, dict):
        return None
    return item.get(key)


def social_profile_scalar_url_hint_value_for_item_key(
    item_key: tuple[dict[str, Any], str],
) -> Any:
    item, key = item_key
    if not isinstance(item, dict):
        return None
    value = item.get(key)
    if value in (None, "") or isinstance(value, (dict, list, tuple, set)):
        return None
    return value


def coerce_social_profile_urlish_candidate(
    value: Any,
    *,
    is_social_platform_host: Callable[[str], bool],
    classify_seed_value: Callable[[str], str],
) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    parsed = urlparse(text)
    if parsed.scheme:
        return text
    if text.startswith("//"):
        candidate = f"https:{text}"
        hostname = str(urlparse(candidate).hostname or "").strip().lower()
        if hostname and (
            is_social_platform_host(hostname)
            or classify_seed_value(hostname) in {"domain", "subdomain"}
        ):
            return candidate
        return text
    host_part = re.split(r"[/?#]", text, maxsplit=1)[0].strip().lower().strip(".")
    if host_part and is_social_platform_host(host_part):
        return f"https://{text}"
    if host_part and classify_seed_value(host_part) in {"domain", "subdomain"}:
        return f"https://{text}"
    return text


def social_profile_value_entry(value_entry: tuple[int, str]) -> str | None:
    _value_index, value = value_entry
    if not value:
        return None
    return value


def social_profile_value_batch_entries(batch_entry: tuple[int, Sequence[str]]) -> list[str]:
    _batch_index, batch = batch_entry
    return [value for value in batch if value]


def social_profile_value_family_entries(family_entry: tuple[int, Sequence[str]]) -> list[str]:
    _family_index, family = family_entry
    return [value for value in family if value]


def social_profile_value_group_entries(group_entry: tuple[int, Sequence[Any]]) -> list[str]:
    _group_index, group = group_entry
    return [value for value in group if isinstance(value, str) and value]


def social_profile_handles(
    profile: dict[str, Any],
    *,
    platform: str,
    handle_field_keys: Sequence[str],
    account_list_keys: Sequence[str],
    handle_link_list_keys: Sequence[str],
    url_hint_values: Callable[[dict[str, Any]], list[Any]],
    matrix_identity_values: Callable[[dict[str, Any]], list[Any]],
    federated_identity_values: Callable[[dict[str, Any]], list[Any]],
    collection_entries: Callable[[Any], list[Any]],
    collection_entries_for_keys: Callable[[dict[str, Any], Sequence[str]], list[Any]],
    nested_profile_dicts: Callable[[dict[str, Any]], list[dict[str, Any]]],
    text_values: Callable[[dict[str, Any]], list[Any]],
    handle_candidate: Callable[[Any], str],
    query_id_handle_candidate: Callable[[Any], str],
    handle_url_candidate: Callable[..., str],
    matrix_user_handle_candidate: Callable[[Any], str],
    platform_is_federated: Callable[[str], bool],
    federated_account_handle_candidate: Callable[[Any], str],
    account_handle_candidates: Callable[[Any], list[str]],
    link_handle_candidates: Callable[[Any], list[str]],
    text_handle_candidates: Callable[[Any], list[str]],
    value_entry: Callable[[tuple[int, str]], str | None],
    value_batch_entries: Callable[[tuple[int, Sequence[str]]], list[str]],
    value_family_entries: Callable[[tuple[int, Sequence[str]]], list[str]],
    value_group_entries: Callable[[tuple[int, Sequence[Any]]], list[str]],
    run_ordered_batch: Callable[..., list[Any]],
) -> list[str]:
    values: list[str] = []
    platform_text = str(platform or "").strip().lower()
    query_id_platform = platform_text in {"google_scholar", "googlescholar", "scholar"}
    scholar_id_keys = (
        "scholar_id",
        "scholarId",
        "google_scholar_id",
        "googleScholarId",
        "user_id",
        "userId",
        "id",
    )
    direct_source_values = [
        profile.get(key)
        for key in (scholar_id_keys if query_id_platform else handle_field_keys)
    ]
    direct_handle_candidates = run_ordered_batch(
        direct_source_values,
        query_id_handle_candidate if query_id_platform else handle_candidate,
        default_factory=str,
    )
    direct_handle_entries = run_ordered_batch(
        list(enumerate(direct_handle_candidates)),
        value_entry,
        default_factory=lambda: None,
    )

    direct_url_candidates = run_ordered_batch(
        url_hint_values(profile),
        lambda value: handle_url_candidate(value, platform=platform),
        default_factory=str,
    )
    direct_url_entries = run_ordered_batch(
        list(enumerate(direct_url_candidates)),
        value_entry,
        default_factory=lambda: None,
    )

    matrix_direct_entries: list[str | None] = []
    if platform_text == "matrix":
        matrix_direct_candidates = run_ordered_batch(
            matrix_identity_values(profile),
            matrix_user_handle_candidate,
            default_factory=str,
        )
        matrix_direct_entries = run_ordered_batch(
            list(enumerate(matrix_direct_candidates)),
            value_entry,
            default_factory=lambda: None,
        )

    federated_direct_entries: list[str | None] = []
    if platform_is_federated(platform):
        federated_direct_candidates = run_ordered_batch(
            federated_identity_values(profile),
            federated_account_handle_candidate,
            default_factory=str,
        )
        federated_direct_entries = run_ordered_batch(
            list(enumerate(federated_direct_candidates)),
            value_entry,
            default_factory=lambda: None,
        )

    account_entry_jobs: list[Any] = []
    for key in account_list_keys:
        account_entry_jobs.extend(collection_entries(profile.get(key)))
    account_entry_jobs.extend(nested_profile_dicts(profile))
    account_entry_batches = run_ordered_batch(
        account_entry_jobs,
        account_handle_candidates,
        default_factory=list,
    )
    prepared_account_entry_batches = run_ordered_batch(
        list(enumerate(account_entry_batches)),
        value_batch_entries,
        default_factory=list,
    )
    prepared_account_entry_families = run_ordered_batch(
        list(enumerate(prepared_account_entry_batches)),
        value_family_entries,
        default_factory=list,
    )

    link_entry_jobs = collection_entries_for_keys(profile, handle_link_list_keys)
    link_entry_batches = run_ordered_batch(
        link_entry_jobs,
        link_handle_candidates,
        default_factory=list,
    )
    prepared_link_entry_batches = run_ordered_batch(
        list(enumerate(link_entry_batches)),
        value_batch_entries,
        default_factory=list,
    )
    prepared_link_entry_families = run_ordered_batch(
        list(enumerate(prepared_link_entry_batches)),
        value_family_entries,
        default_factory=list,
    )

    text_link_batches = run_ordered_batch(
        text_values(profile),
        text_handle_candidates,
        default_factory=list,
    )
    prepared_text_link_batches = run_ordered_batch(
        list(enumerate(text_link_batches)),
        value_batch_entries,
        default_factory=list,
    )
    prepared_text_link_families = run_ordered_batch(
        list(enumerate(prepared_text_link_batches)),
        value_family_entries,
        default_factory=list,
    )

    value_groups = [
        direct_handle_entries,
        direct_url_entries,
        matrix_direct_entries,
        federated_direct_entries,
        *prepared_account_entry_families,
        *prepared_link_entry_families,
        *prepared_text_link_families,
    ]
    prepared_value_groups = run_ordered_batch(
        list(enumerate(value_groups)),
        value_group_entries,
        default_factory=list,
    )
    for group in prepared_value_groups:
        values.extend(group)
    return list(dict.fromkeys(values))


def social_profile_account_handle_candidates(
    item: Any,
    *,
    handle_field_keys: Sequence[str],
    link_entry_keys: Sequence[str],
    embedded_container_items: Callable[[dict[str, Any]], list[Any]],
    account_handle_candidate_for_item_key: Callable[[tuple[dict[str, Any], str]], str],
    link_handle_candidate_for_item_key: Callable[[tuple[dict[str, Any], str]], str],
    handle_candidate: Callable[[Any], str],
    handle_url_candidate: Callable[[Any], str],
    value_entry: Callable[[tuple[int, str]], str | None],
    run_ordered_batch: Callable[..., list[Any]],
) -> list[str]:
    values: list[str] = []
    if isinstance(item, dict):
        direct_handle_candidates = run_ordered_batch(
            [(item, inner_key) for inner_key in (*handle_field_keys, "value")],
            account_handle_candidate_for_item_key,
            default_factory=str,
        )
        direct_handle_entries = run_ordered_batch(
            list(enumerate(direct_handle_candidates)),
            value_entry,
            default_factory=lambda: None,
        )
        values.extend(value for value in direct_handle_entries if value)
        direct_link_candidates = run_ordered_batch(
            [(item, inner_key) for inner_key in link_entry_keys],
            link_handle_candidate_for_item_key,
            default_factory=str,
        )
        direct_link_entries = run_ordered_batch(
            list(enumerate(direct_link_candidates)),
            value_entry,
            default_factory=lambda: None,
        )
        values.extend(value for value in direct_link_entries if value)
        embedded_batches = run_ordered_batch(
            embedded_container_items(item),
            lambda child: social_profile_account_handle_candidates(
                child,
                handle_field_keys=handle_field_keys,
                link_entry_keys=link_entry_keys,
                embedded_container_items=embedded_container_items,
                account_handle_candidate_for_item_key=account_handle_candidate_for_item_key,
                link_handle_candidate_for_item_key=link_handle_candidate_for_item_key,
                handle_candidate=handle_candidate,
                handle_url_candidate=handle_url_candidate,
                value_entry=value_entry,
                run_ordered_batch=run_ordered_batch,
            ),
            default_factory=list,
        )
        for batch in embedded_batches:
            values.extend(batch)
        return values
    cleaned = handle_candidate(item)
    if not cleaned:
        cleaned = handle_url_candidate(item)
    if cleaned:
        values.append(cleaned)
    return values


def social_profile_link_handle_candidates(
    item: Any,
    *,
    link_entry_keys: Sequence[str],
    link_handle_candidate_for_item_key: Callable[[tuple[dict[str, Any], str]], str],
    handle_url_candidate: Callable[[Any], str],
    value_entry: Callable[[tuple[int, str]], str | None],
    run_ordered_batch: Callable[..., list[Any]],
) -> list[str]:
    if isinstance(item, dict):
        candidates = run_ordered_batch(
            [(item, inner_key) for inner_key in link_entry_keys],
            link_handle_candidate_for_item_key,
            default_factory=str,
        )
        entries = run_ordered_batch(
            list(enumerate(candidates)),
            value_entry,
            default_factory=lambda: None,
        )
        return [value for value in entries if value]
    cleaned = handle_url_candidate(item)
    if cleaned:
        return [cleaned]
    return []


def social_profile_text_handle_candidates(
    text: Any,
    *,
    text_url_candidates: Callable[[Any], list[str]],
    handle_url_candidate: Callable[[Any], str],
    value_entry: Callable[[tuple[int, str]], str | None],
    run_ordered_batch: Callable[..., list[Any]],
) -> list[str]:
    handle_candidates = run_ordered_batch(
        text_url_candidates(text),
        handle_url_candidate,
        default_factory=str,
    )
    entries = run_ordered_batch(
        list(enumerate(handle_candidates)),
        value_entry,
        default_factory=lambda: None,
    )
    return list(dict.fromkeys(value for value in entries if value))


def social_profile_related_host_batch_entries(batch_entry: tuple[int, Any]) -> list[SocialProfileHostEntry]:
    _batch_index, batch = batch_entry
    return [
        host_entry
        for host_entry in batch
        if isinstance(host_entry, tuple) and len(host_entry) == 2
    ]


def social_profile_related_host_family_entries(family_entry: tuple[int, Any]) -> list[SocialProfileHostEntry]:
    _family_index, family = family_entry
    return [
        host_entry
        for host_entry in family
        if isinstance(host_entry, tuple) and len(host_entry) == 2
    ]


def social_profile_related_host_group_entries(group_entry: tuple[int, Any]) -> list[SocialProfileHostEntry]:
    _group_index, group = group_entry
    return [
        host_entry
        for host_entry in group
        if isinstance(host_entry, tuple) and len(host_entry) == 2
    ]


def social_profile_related_hosts(
    profile: dict[str, Any],
    *,
    urls: Callable[[dict[str, Any]], list[str]],
    related_host_candidates: Callable[[str], list[SocialProfileHostEntry]],
    related_host_batch_entries: Callable[[tuple[int, Any]], list[SocialProfileHostEntry]],
    related_host_family_entries: Callable[[tuple[int, Any]], list[SocialProfileHostEntry]],
    related_host_group_entries: Callable[[tuple[int, Any]], list[SocialProfileHostEntry]],
    run_ordered_batch: Callable[..., list[Any]],
) -> list[SocialProfileHostEntry]:
    values: list[SocialProfileHostEntry] = []
    url_batches = run_ordered_batch(
        urls(profile),
        related_host_candidates,
        default_factory=list,
    )
    prepared_url_batches = run_ordered_batch(
        list(enumerate(url_batches)),
        related_host_batch_entries,
        default_factory=list,
    )
    prepared_url_families = run_ordered_batch(
        list(enumerate(prepared_url_batches)),
        related_host_family_entries,
        default_factory=list,
    )
    prepared_value_groups = run_ordered_batch(
        list(enumerate(prepared_url_families)),
        related_host_group_entries,
        default_factory=list,
    )
    for group in prepared_value_groups:
        values.extend(group)
    return list(dict.fromkeys(values))


def social_profile_domain_hosts(
    profile: dict[str, Any],
    *,
    domain_field_keys: Sequence[str],
    work_history_profile_entries: Callable[[dict[str, Any]], list[Any]],
    nested_profile_dicts: Callable[[dict[str, Any]], list[dict[str, Any]]],
    domain_host_key_candidates: Callable[[tuple[dict[str, Any], str]], list[SocialProfileHostEntry]],
    domain_host_candidates: Callable[[Any], list[SocialProfileHostEntry]],
    related_host_group_entries: Callable[[tuple[int, Any]], list[SocialProfileHostEntry]],
    run_ordered_batch: Callable[..., list[Any]],
) -> list[SocialProfileHostEntry]:
    direct_batches = run_ordered_batch(
        [(profile, key) for key in domain_field_keys],
        domain_host_key_candidates,
        default_factory=list,
    )
    entry_jobs = work_history_profile_entries(profile)
    entry_jobs.extend(nested_profile_dicts(profile))
    entry_batches = run_ordered_batch(
        entry_jobs,
        domain_host_candidates,
        default_factory=list,
    )
    value_groups = [*direct_batches, *entry_batches]
    prepared_value_groups = run_ordered_batch(
        list(enumerate(value_groups)),
        related_host_group_entries,
        default_factory=list,
    )
    values: list[SocialProfileHostEntry] = []
    for group in prepared_value_groups:
        values.extend(group)
    return list(dict.fromkeys(values))


def social_profile_domain_host_key_candidates(
    item_key: tuple[dict[str, Any], str],
    *,
    domain_host_value_candidates: Callable[[Any], list[SocialProfileHostEntry]],
) -> list[SocialProfileHostEntry]:
    item, key = item_key
    if not isinstance(item, dict):
        return []
    return domain_host_value_candidates(item.get(key))


def social_profile_domain_host_candidates(
    item: Any,
    *,
    domain_field_keys: Sequence[str],
    domain_host_key_candidates: Callable[[tuple[dict[str, Any], str]], list[SocialProfileHostEntry]],
    domain_host_value_candidates: Callable[[Any], list[SocialProfileHostEntry]],
    run_ordered_batch: Callable[..., list[Any]],
) -> list[SocialProfileHostEntry]:
    if not isinstance(item, dict):
        return domain_host_value_candidates(item)
    batches = run_ordered_batch(
        [(item, key) for key in domain_field_keys],
        domain_host_key_candidates,
        default_factory=list,
    )
    values: list[SocialProfileHostEntry] = []
    for batch in batches:
        values.extend(batch)
    return list(dict.fromkeys(values))


def social_profile_domain_host_value_candidates(
    value: Any,
    *,
    domain_field_keys: Sequence[str],
    max_entries: int,
    domain_alias_text: Callable[[Any], str],
    coerce_urlish_candidate: Callable[[Any], str],
    classify_seed_value: Callable[[str], str],
    normalize_root_domain: Callable[[str], str],
    is_social_platform_host: Callable[[str], bool],
    is_managed_cloud_provider_host: Callable[[str], bool],
    run_ordered_batch: Callable[..., list[Any]],
) -> list[SocialProfileHostEntry]:
    def _value_candidates(candidate_value: Any) -> list[SocialProfileHostEntry]:
        return social_profile_domain_host_value_candidates(
            candidate_value,
            domain_field_keys=domain_field_keys,
            max_entries=max_entries,
            domain_alias_text=domain_alias_text,
            coerce_urlish_candidate=coerce_urlish_candidate,
            classify_seed_value=classify_seed_value,
            normalize_root_domain=normalize_root_domain,
            is_social_platform_host=is_social_platform_host,
            is_managed_cloud_provider_host=is_managed_cloud_provider_host,
            run_ordered_batch=run_ordered_batch,
        )

    if isinstance(value, dict):
        batches = run_ordered_batch(
            [
                (value, key)
                for key in (
                    "value",
                    "url",
                    "link",
                    "href",
                    *domain_field_keys,
                )
            ],
            lambda item_key: social_profile_domain_host_key_candidates(
                item_key,
                domain_host_value_candidates=_value_candidates,
            ),
            default_factory=list,
        )
        values: list[SocialProfileHostEntry] = []
        for batch in batches:
            values.extend(batch)
        return list(dict.fromkeys(values))
    if isinstance(value, (list, tuple, set)):
        batches = run_ordered_batch(
            list(value)[:max_entries],
            _value_candidates,
            default_factory=list,
        )
        values: list[SocialProfileHostEntry] = []
        for batch in batches:
            values.extend(batch)
        return list(dict.fromkeys(values))
    return social_profile_domain_host_string_candidates(
        value,
        domain_alias_text=domain_alias_text,
        coerce_urlish_candidate=coerce_urlish_candidate,
        classify_seed_value=classify_seed_value,
        normalize_root_domain=normalize_root_domain,
        is_social_platform_host=is_social_platform_host,
        is_managed_cloud_provider_host=is_managed_cloud_provider_host,
    )


def social_profile_domain_alias_text(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    prefix, separator, suffix = text.partition(":")
    if separator and prefix.lower() in {"applinks", "webcredentials", "activitycontinuation", "appclips"}:
        return suffix.strip()
    return text


def social_profile_domain_host_string_candidates(
    value: Any,
    *,
    domain_alias_text: Callable[[Any], str],
    coerce_urlish_candidate: Callable[[Any], str],
    classify_seed_value: Callable[[str], str],
    normalize_root_domain: Callable[[str], str],
    is_social_platform_host: Callable[[str], bool],
    is_managed_cloud_provider_host: Callable[[str], bool],
) -> list[SocialProfileHostEntry]:
    text = domain_alias_text(value)
    if not text:
        return []
    candidate = coerce_urlish_candidate(text)
    parsed = urlparse(candidate)
    hostname = str(parsed.hostname or "").strip().lower().strip(".")
    if hostname.startswith("*."):
        hostname = hostname[2:]
    if not hostname or is_social_platform_host(hostname) or is_managed_cloud_provider_host(hostname):
        return []
    if classify_seed_value(hostname) != "domain":
        return []
    root_domain = normalize_root_domain(hostname)
    if not root_domain or is_social_platform_host(root_domain) or is_managed_cloud_provider_host(root_domain):
        return []
    values: list[SocialProfileHostEntry] = []
    if hostname != root_domain:
        values.append((hostname, "subdomain"))
    values.append((root_domain, "domain"))
    return values


def _valid_social_profile_pivots(entries: Sequence[Any]) -> list[SocialProfilePivot]:
    return [entry for entry in entries if isinstance(entry, tuple)]


def social_profile_pivots(
    profile: dict[str, Any],
    *,
    source_label: str,
    platform: str,
    base_confidence: float,
    company_profile: bool,
    pivot_families: Sequence[str],
    pivot_family: Callable[..., list[SocialProfilePivot]],
    pivot_batch_entries: Callable[[tuple[int, Any]], list[SocialProfilePivot]],
    pivot_family_entries: Callable[[tuple[int, Any]], list[SocialProfilePivot]],
    run_ordered_batch: Callable[..., list[Any]],
) -> list[SocialProfilePivot]:
    pivot_batches = run_ordered_batch(
        pivot_families,
        lambda family: pivot_family(
            family,
            profile=profile,
            source_label=source_label,
            platform=platform,
            base_confidence=base_confidence,
            company_profile=company_profile,
        ),
        default_factory=list,
    )
    prepared_pivot_batches = run_ordered_batch(
        list(enumerate(pivot_batches)),
        pivot_batch_entries,
        default_factory=list,
    )
    prepared_pivot_families = run_ordered_batch(
        list(enumerate(prepared_pivot_batches)),
        pivot_family_entries,
        default_factory=list,
    )
    pivots: list[SocialProfilePivot] = []
    for prepared_family in prepared_pivot_families:
        pivots.extend(prepared_family)
    return pivots


def social_profile_pivot_family(
    family: str,
    *,
    profile: dict[str, Any],
    source_label: str,
    platform: str,
    base_confidence: float,
    company_profile: bool,
    handles: Callable[..., Sequence[str]],
    company_name: Callable[..., str],
    name: Callable[[dict[str, Any]], str],
    emails: Callable[[dict[str, Any]], Sequence[str]],
    phones: Callable[[dict[str, Any]], Sequence[str]],
    urls: Callable[[dict[str, Any]], Sequence[str]],
    platform_profile_hosts: Callable[..., set[str]],
    related_hosts: Callable[[dict[str, Any]], Sequence[tuple[str, str]]],
    matrix_homeserver_hosts: Callable[[dict[str, Any]], Sequence[tuple[str, str]]],
    platform_is_federated: Callable[[str], bool],
    federated_instance_hosts: Callable[..., Sequence[tuple[str, str]]],
    domain_hosts: Callable[[dict[str, Any]], Sequence[tuple[str, str]]],
    should_promote_bluesky_domain_handle: Callable[..., bool],
    classify_seed_value: Callable[[str], str],
    handle_pivot_entry: Callable[[tuple[str, str, float, str]], SocialProfilePivot | None],
    url_pivot_entry: Callable[[tuple[str, str, float, str]], SocialProfilePivot | None],
    host_pivot_entry: Callable[[tuple[str, str, str, float, str]], SocialProfilePivot | None],
    seed_pivot_entry: Callable[[tuple[str, str, str, float, str, str, str]], SocialProfilePivot | None],
    run_ordered_batch: Callable[..., list[Any]],
) -> list[SocialProfilePivot]:
    if family == "handles":
        if company_profile:
            return []
        pivot_entries = run_ordered_batch(
            [
                (handle, platform, base_confidence, source_label)
                for handle in handles(profile, platform=platform)
            ],
            handle_pivot_entry,
            default_factory=lambda: None,
        )
        return _valid_social_profile_pivots(pivot_entries)
    if family == "company":
        company_value = company_name(
            profile,
            source_label=source_label,
            platform=platform,
        )
        if not company_value:
            return []
        return [
            (
                company_value,
                "company",
                "same_entity",
                base_confidence,
                {"rule": "social_profile_company", "platform": platform, "source": source_label},
            )
        ]
    if family == "name":
        full_name = name(profile)
        if not full_name:
            return []
        return [
            (
                full_name,
                "name",
                "same_entity",
                base_confidence,
                {"rule": "social_profile_name", "platform": platform, "source": source_label},
            )
        ]
    if family == "emails":
        pivot_entries = run_ordered_batch(
            [
                (
                    email,
                    "email",
                    "same_entity",
                    min(0.9, base_confidence + 0.03),
                    "social_profile_email",
                    platform,
                    source_label,
                )
                for email in emails(profile)
            ],
            seed_pivot_entry,
            default_factory=lambda: None,
        )
        return _valid_social_profile_pivots(pivot_entries)
    if family == "phones":
        pivot_entries = run_ordered_batch(
            [
                (
                    phone,
                    "phone",
                    "same_entity",
                    min(0.9, base_confidence + 0.02),
                    "social_profile_phone",
                    platform,
                    source_label,
                )
                for phone in phones(profile)
            ],
            seed_pivot_entry,
            default_factory=lambda: None,
        )
        return _valid_social_profile_pivots(pivot_entries)
    if family == "urls":
        pivot_entries = run_ordered_batch(
            [
                (url, platform, base_confidence, source_label)
                for url in urls(profile)
            ],
            url_pivot_entry,
            default_factory=lambda: None,
        )
        return _valid_social_profile_pivots(pivot_entries)
    if family == "hosts":
        platform_hosts = platform_profile_hosts(profile, platform=platform)
        host_entries = [
            (host_value, host_type, platform, base_confidence, source_label)
            for host_value, host_type in related_hosts(profile)
            if host_value not in platform_hosts
        ]
        pivot_entries = run_ordered_batch(
            host_entries,
            host_pivot_entry,
            default_factory=lambda: None,
        )
        return _valid_social_profile_pivots(pivot_entries)
    if family == "matrix_hosts":
        if str(platform or "").strip().lower() != "matrix":
            return []
        pivot_entries = run_ordered_batch(
            [
                (
                    host_value,
                    host_type,
                    "related_asset",
                    max(0.7, base_confidence - 0.01),
                    "social_profile_matrix_homeserver",
                    platform,
                    source_label,
                )
                for host_value, host_type in matrix_homeserver_hosts(profile)
            ],
            seed_pivot_entry,
            default_factory=lambda: None,
        )
        return _valid_social_profile_pivots(pivot_entries)
    if family == "federated_hosts":
        if not platform_is_federated(platform):
            return []
        pivot_entries = run_ordered_batch(
            [
                (
                    host_value,
                    host_type,
                    "related_asset",
                    max(0.7, base_confidence - 0.01),
                    "social_profile_federated_instance",
                    platform,
                    source_label,
                )
                for host_value, host_type in federated_instance_hosts(
                    profile,
                    platform=platform,
                )
            ],
            seed_pivot_entry,
            default_factory=lambda: None,
        )
        return _valid_social_profile_pivots(pivot_entries)
    if family == "domain":
        pivot_entries = run_ordered_batch(
            [
                (
                    domain_value,
                    domain_type,
                    "related_asset",
                    max(0.7, base_confidence - 0.01),
                    "social_profile_domain",
                    platform,
                    source_label,
                )
                for domain_value, domain_type in domain_hosts(profile)
            ],
            seed_pivot_entry,
            default_factory=lambda: None,
        )
        pivots = _valid_social_profile_pivots(pivot_entries)
        if platform == "bluesky":
            for handle in handles(profile, platform=platform):
                domain_handle = handle.lower()
                if classify_seed_value(domain_handle) != "domain":
                    continue
                if not should_promote_bluesky_domain_handle(
                    profile,
                    domain_handle,
                    source_label=source_label,
                ):
                    continue
                pivots.append(
                    (
                        domain_handle,
                        "domain",
                        "related_asset",
                        max(0.7, base_confidence - 0.01),
                        {
                            "rule": "social_profile_domain_handle",
                            "platform": platform,
                            "source": source_label,
                        },
                    )
                )
        return pivots
    return []


def should_promote_bluesky_domain_handle(
    profile: dict[str, Any],
    domain_handle: str,
    *,
    source_label: str,
) -> bool:
    handle = str(domain_handle or "").strip().lower()
    if not handle:
        return False
    explicit_domain = str(profile.get("domain") or "").strip().lower()
    if explicit_domain == handle:
        return True
    for flag_key in (
        "custom_domain",
        "dns_verified",
        "domain_verified",
        "handle_verified",
        "is_custom_domain",
        "is_domain_handle",
        "verified_domain",
    ):
        if bool(profile.get(flag_key)):
            return True
    weak_source = str(source_label or "").strip().lower()
    if any(token in weak_source for token in ("name_search", "phone_dork", "phone_lookup")):
        return False
    return True


def social_profile_payload_entries(
    profile_data: Any,
    *,
    row_source: str,
    max_entries: int,
    candidate_items: Callable[[Any], list[dict[str, Any]]],
    payload_entry: Callable[..., dict[str, Any] | None],
    payload_dedupe_key: Callable[[dict[str, Any]], str],
    run_ordered_batch: Callable[..., list[Any]],
) -> list[dict[str, Any]]:
    payload_items = candidate_items(profile_data)
    if not payload_items:
        return []
    entry_batches = run_ordered_batch(
        payload_items,
        lambda item: payload_entry(item, row_source=row_source),
        default_factory=lambda: None,
    )
    entries: list[dict[str, Any]] = []
    seen: set[str] = set()
    for entry in entry_batches:
        if not isinstance(entry, dict):
            continue
        dedupe_key = payload_dedupe_key(entry)
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        entries.append(entry)
    return entries[:max_entries]


def social_profile_payload_candidate_items(
    profile_data: Any,
    *,
    candidate_items_at_depth: Callable[..., list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    return candidate_items_at_depth(
        profile_data,
        depth=0,
        seen=set(),
        inherited_context={},
    )


def social_profile_payload_candidate_items_at_depth(
    item: Any,
    *,
    depth: int,
    seen: set[int],
    inherited_context: dict[str, Any],
    max_entries: int,
    container_keys: Sequence[str],
    profile_hint_keys: Sequence[str],
    direct_platform: Callable[[dict[str, Any]], str],
    child_candidate_items: Callable[[tuple[Any, int, set[int], dict[str, Any]]], list[dict[str, Any]]],
    run_ordered_batch: Callable[..., list[Any]],
) -> list[dict[str, Any]]:
    if depth > 4 or len(seen) > max_entries * 4:
        return []
    if isinstance(item, list):
        candidates: list[dict[str, Any]] = []
        child_jobs = [
            (child, depth + 1, set(seen), inherited_context)
            for child in item[:max_entries]
        ]
        child_batches = run_ordered_batch(
            child_jobs,
            child_candidate_items,
            default_factory=list,
        )
        for child_candidates in child_batches:
            candidates.extend(child_candidates)
            if len(candidates) >= max_entries:
                break
        return candidates[:max_entries]
    if not isinstance(item, dict):
        return []
    object_id = id(item)
    if object_id in seen:
        return []
    seen.add(object_id)

    profile_item = social_profile_payload_with_inherited_context(
        item,
        inherited_context,
        direct_platform=direct_platform,
    )
    child_context = social_profile_payload_child_context(
        profile_item,
        inherited_context,
        direct_platform=direct_platform,
    )

    candidates: list[dict[str, Any]] = []
    if social_profile_payload_has_profile_hint(
        profile_item,
        profile_hint_keys=profile_hint_keys,
    ):
        candidates.append(profile_item)
    else:
        present_container_keys = {
            key
            for key in container_keys
            if key in profile_item
        }
        if not present_container_keys:
            candidates.append(profile_item)

    child_jobs = [
        (value, depth + 1, set(seen), child_context)
        for key in container_keys
        if isinstance((value := profile_item.get(key)), (dict, list))
    ]
    child_batches = run_ordered_batch(
        child_jobs,
        child_candidate_items,
        default_factory=list,
    )
    for child_candidates in child_batches:
        candidates.extend(child_candidates)
        if len(candidates) >= max_entries:
            break
    return candidates[:max_entries]


def social_profile_payload_child_candidate_items(
    job: tuple[Any, int, set[int], dict[str, Any]],
    *,
    candidate_items_at_depth: Callable[..., list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    child, depth, seen, inherited_context = job
    return candidate_items_at_depth(
        child,
        depth=depth,
        seen=set(seen),
        inherited_context=dict(inherited_context),
    )


def social_profile_payload_with_inherited_context(
    item: dict[str, Any],
    inherited_context: dict[str, Any],
    *,
    direct_platform: Callable[[dict[str, Any]], str],
) -> dict[str, Any]:
    profile_item = dict(item)
    if profile_item.get("source") in (None, "") and inherited_context.get("source") not in (None, ""):
        profile_item["source"] = inherited_context["source"]
    if profile_item.get("platform") in (None, ""):
        platform = inherited_context.get("platform") or direct_platform(profile_item)
        if platform not in (None, ""):
            profile_item["platform"] = platform
    return profile_item


def social_profile_payload_child_context(
    item: dict[str, Any],
    inherited_context: dict[str, Any],
    *,
    direct_platform: Callable[[dict[str, Any]], str],
) -> dict[str, Any]:
    context = dict(inherited_context)
    source = item.get("source")
    if source not in (None, ""):
        context["source"] = source
    platform = item.get("platform") or direct_platform(item)
    if platform not in (None, ""):
        context["platform"] = platform
    return context


def social_profile_payload_has_profile_hint(
    item: dict[str, Any],
    *,
    profile_hint_keys: Sequence[str],
) -> bool:
    for key in profile_hint_keys:
        value = item.get(key)
        if value not in (None, "", [], {}):
            return True
    return False


def social_profile_payload_dedupe_key(entry: dict[str, Any]) -> str:
    try:
        return json.dumps(entry, sort_keys=True, default=str)
    except TypeError:
        return repr(sorted((str(key), str(value)) for key, value in entry.items()))


def social_profile_payload_entry(
    item: Any,
    *,
    row_source: str,
) -> dict[str, Any] | None:
    if not isinstance(item, dict):
        return None
    entry = dict(item)
    if row_source and "source" not in entry:
        entry["source"] = row_source
    return entry


def scope_seed_candidate(
    value: Any,
    *,
    classify_seed_value: Callable[[str], str],
) -> SeedCandidate | None:
    text = str(value or "").strip()
    if not text:
        return None
    cleaned = text[2:] if text.startswith("*.") else text
    seed_type = classify_seed_value(text)
    return SeedCandidate(
        seed_value=cleaned,
        seed_type=seed_type,
        source="scope",
        depth=0,
        confidence=1.0,
    )


def email_domain_is_promotable(
    domain: str,
    eligible_domain_roots: set[str],
    *,
    normalize_root_domain: Callable[[str], str],
) -> bool:
    normalized = str(domain or "").strip().lower().strip(".")
    if not normalized:
        return False
    root = normalize_root_domain(normalized)
    for eligible in eligible_domain_roots:
        allowed = str(eligible or "").strip().lower().strip(".")
        if allowed.startswith("*."):
            allowed = allowed[2:]
        if not allowed:
            continue
        if normalized == allowed or root == allowed or normalized.endswith(f".{allowed}"):
            return True
    return False


def email_seed_candidates_from_row(
    row: Any,
    seed_depths: dict[tuple[str, str], int],
    eligible_domain_roots: set[str] | None = None,
    *,
    depth_limit: int,
    normalize_root_domain: Callable[[str], str],
) -> list[SeedCandidate]:
    email = str(row["email"] or "").lower().strip()
    if "@" not in email:
        return []
    local, domain = email.split("@", 1)
    email_depth = seed_depths.get(("email", email), 0)
    candidates = [
        SeedCandidate(
            seed_value=email,
            seed_type="email",
            source="discovered",
            depth=max(1, email_depth or 1),
            confidence=0.82,
        )
    ]
    username = local.strip(".-_")
    if len(username) >= 3:
        candidates.append(
            SeedCandidate(
                seed_value=username,
                seed_type="username",
                source="cross_reference",
                depth=min(depth_limit, max(1, email_depth) + 1),
                confidence=0.72,
                parent_value=email,
                parent_type="email",
                metadata={"rule": "email_local_part"},
            )
        )
    if email_domain_is_promotable(
        domain,
        eligible_domain_roots or set(),
        normalize_root_domain=normalize_root_domain,
    ):
        candidates.append(
            SeedCandidate(
                seed_value=domain,
                seed_type="domain",
                source="cross_reference",
                depth=min(depth_limit, max(1, email_depth) + 1),
                confidence=0.68,
                parent_value=email,
                parent_type="email",
                relation_type="related_asset",
                metadata={"rule": "email_domain"},
            )
        )
    return candidates


def host_seed_candidates_from_row(
    row: Any,
    seed_depths: dict[tuple[str, str], int],
    *,
    classify_seed_value: Callable[[str], str],
    normalize_root_domain: Callable[[str], str],
    is_placeholder_host_ip: Callable[[str], bool],
    depth_limit: int,
) -> list[SeedCandidate]:
    host_ip = str(row["ip"] or "").strip().lower()
    hostname = str(row["hostname"] or "").lower().strip()
    candidates: list[SeedCandidate] = []
    if host_ip and not is_placeholder_host_ip(host_ip):
        ip_seed_type = classify_seed_value(host_ip)
        if ip_seed_type in {"ipv4", "ipv6"}:
            host_parent_type = classify_seed_value(hostname) if hostname and hostname != host_ip else ""
            ip_depth = seed_depths.get(
                (ip_seed_type, host_ip),
                seed_depths.get((host_parent_type, hostname), 0) if host_parent_type else 0,
            )
            candidates.append(
                SeedCandidate(
                    seed_value=host_ip,
                    seed_type=ip_seed_type,
                    source="discovered",
                    depth=max(1, ip_depth or 1),
                    confidence=0.76,
                    parent_value=hostname if host_parent_type else None,
                    parent_type=host_parent_type or None,
                    relation_type="related_asset",
                    metadata={"rule": "host_ip"},
                )
            )
    if not hostname or hostname == host_ip:
        return candidates
    if "." not in hostname:
        return candidates
    root_domain = normalize_root_domain(hostname)
    host_depth = seed_depths.get(("subdomain", hostname), seed_depths.get(("domain", root_domain), 0))
    candidates.append(
        SeedCandidate(
            seed_value=hostname,
            seed_type="subdomain",
            source="discovered",
            depth=max(1, host_depth or 1),
            confidence=0.78,
        )
    )
    candidates.append(
        SeedCandidate(
            seed_value=root_domain,
            seed_type="domain",
            source="cross_reference",
            depth=min(depth_limit, max(1, host_depth) + 1),
            confidence=0.66,
            parent_value=hostname,
            parent_type="subdomain",
            relation_type="related_asset",
            metadata={"rule": "hostname_root_domain"},
        )
    )
    return candidates


def artifact_seed_candidates_from_row(
    row: Any,
    seed_depths: dict[tuple[str, str], int],
    *,
    normalize_root_domain: Callable[[str], str],
    is_mobile_bundle_url: Callable[[str], bool],
    is_mobile_bundle_path: Callable[[str], bool],
    is_social_platform_host: Callable[[str], bool],
    is_managed_cloud_provider_host: Callable[[str], bool],
    depth_limit: int,
) -> list[SeedCandidate]:
    source_url = str(row["source_url"] or "").strip()
    local_path = str(row["local_path"] or "").strip()
    artifact_type = str(row["artifact_type"] or "").strip().lower()
    parsed = urlparse(source_url) if source_url else urlparse("")
    candidates: list[SeedCandidate] = []
    if source_url and parsed.scheme in {"http", "https"}:
        parent_type = (
            "apk_url"
            if (
                is_mobile_bundle_url(source_url)
                or is_mobile_bundle_path(local_path)
                or artifact_type in {"apk", "ipa"}
            )
            else "url"
        )
        artifact_depth = seed_depths.get((parent_type, source_url), 0)
        candidates.append(
            SeedCandidate(
                seed_value=source_url,
                seed_type=parent_type,
                source="artifact",
                depth=max(1, artifact_depth or 1),
                confidence=0.7,
            )
        )
        if parsed.hostname:
            hostname = str(parsed.hostname or "").strip().lower().strip(".")
            if hostname and not is_social_platform_host(hostname) and not is_managed_cloud_provider_host(hostname):
                root_domain = normalize_root_domain(hostname)
                host_depth = min(depth_limit, max(1, artifact_depth) + 1)
                if hostname != root_domain:
                    candidates.append(
                        SeedCandidate(
                            seed_value=hostname,
                            seed_type="subdomain",
                            source="artifact",
                            depth=host_depth,
                            confidence=0.66,
                            parent_value=source_url,
                            parent_type=parent_type,
                            relation_type="related_asset",
                            metadata={"rule": "artifact_host"},
                        )
                    )
                    candidates.append(
                        SeedCandidate(
                            seed_value=root_domain,
                            seed_type="domain",
                            source="artifact",
                            depth=min(depth_limit, host_depth + 1),
                            confidence=0.6,
                            parent_value=hostname,
                            parent_type="subdomain",
                            relation_type="related_asset",
                            metadata={"rule": "artifact_host_root_domain"},
                        )
                    )
                else:
                    candidates.append(
                        SeedCandidate(
                            seed_value=root_domain,
                            seed_type="domain",
                            source="artifact",
                            depth=host_depth,
                            confidence=0.6,
                            parent_value=source_url,
                            parent_type=parent_type,
                            relation_type="related_asset",
                            metadata={"rule": "artifact_host"},
                        )
                    )
    if is_mobile_bundle_path(local_path) and parsed.scheme not in {"http", "https"}:
        candidates.append(
            SeedCandidate(
                seed_value=local_path,
                seed_type="apk_url",
                source="artifact",
                depth=max(1, seed_depths.get(("apk_url", local_path), 1)),
                confidence=0.74,
            )
        )
    return candidates


def ensure_email_seed_row(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    email: str,
    source: str,
) -> None:
    normalized = str(email or "").strip().lower()
    if "@" not in normalized:
        return
    try:
        con.execute(
            """
            INSERT OR IGNORE INTO emails (engagement_id, email, domain, source)
            VALUES (?, ?, ?, ?)
            """,
            (
                int(engagement_id),
                normalized,
                normalized.split("@", 1)[1],
                source,
            ),
        )
    except sqlite3.OperationalError:
        return


def upsert_seed_candidate(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    candidate: SeedCandidate,
    depth_limit: int,
) -> int:
    if candidate.seed_type == "email":
        ensure_email_seed_row(
            con,
            engagement_id=engagement_id,
            email=candidate.seed_value,
            source=candidate.source,
        )
    parent_id = None
    if candidate.parent_value and candidate.parent_type:
        parent_row = con.execute(
            """
            SELECT id
            FROM engagement_seeds
            WHERE engagement_id=? AND seed_type=? AND seed_value=?
            """,
            (engagement_id, candidate.parent_type, candidate.parent_value),
        ).fetchone()
        if parent_row is not None:
            parent_id = int(parent_row[0])
    existing_row = con.execute(
        """
        SELECT id, source, status, depth, confidence, parent_seed_id, metadata_json
        FROM engagement_seeds
        WHERE engagement_id=? AND seed_type=? AND seed_value=?
        """,
        (engagement_id, candidate.seed_type, candidate.seed_value),
    ).fetchone()
    if existing_row is None:
        con.execute(
            """
            INSERT INTO engagement_seeds
                (engagement_id, seed_value, seed_type, source, status, depth, confidence, parent_seed_id, metadata_json)
            VALUES (?, ?, ?, ?, 'pending', ?, ?, ?, ?)
            """,
            (
                engagement_id,
                candidate.seed_value,
                candidate.seed_type,
                candidate.source,
                candidate.depth,
                candidate.confidence,
                parent_id,
                json.dumps(candidate.metadata or {}, sort_keys=True),
            ),
        )
        row = con.execute("SELECT last_insert_rowid()").fetchone()
        assert row is not None
        return int(row[0])

    existing_id = int(existing_row["id"])
    existing_source = str(existing_row["source"] or "")
    existing_status = str(existing_row["status"] or "pending")
    existing_depth = int(existing_row["depth"] or 0)
    existing_confidence = float(existing_row["confidence"] or 0.0)
    existing_parent = (
        int(existing_row["parent_seed_id"])
        if existing_row["parent_seed_id"] is not None
        else None
    )
    existing_metadata = safe_json_loads(str(existing_row["metadata_json"] or "{}"))
    merged_metadata = merge_seed_metadata(existing_metadata, candidate.metadata)
    con.execute(
        """
        UPDATE engagement_seeds
        SET source=?,
            status=?,
            depth=?,
            confidence=?,
            parent_seed_id=?,
            metadata_json=?,
            updated_at=CURRENT_TIMESTAMP
        WHERE id=? AND engagement_id=?
        """,
        (
            preferred_seed_source(existing_source, candidate.source),
            "pending" if min(existing_depth, candidate.depth) <= depth_limit else existing_status,
            min(existing_depth, candidate.depth),
            max(existing_confidence, candidate.confidence),
            existing_parent if existing_parent is not None else parent_id,
            json.dumps(merged_metadata, sort_keys=True),
            existing_id,
            engagement_id,
        ),
    )
    return existing_id


def insert_seed_relation(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    source_seed_id: int,
    target_seed_id: int,
    relation_type: str,
    confidence: float,
    metadata: dict[str, Any],
) -> bool:
    before = con.total_changes
    con.execute(
        """
        INSERT OR IGNORE INTO seed_relations
            (engagement_id, source_seed_id, target_seed_id, relation_type, confidence, evidence_json)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            engagement_id,
            source_seed_id,
            target_seed_id,
            relation_type,
            confidence,
            json.dumps(metadata or {}),
        ),
    )
    return con.total_changes > before


__all__ = [
    "SeedCandidate",
    "SocialProfileHostEntry",
    "SocialProfilePivot",
    "SynthesisSummary",
    "synthesis_summary_log_message",
    "artifact_seed_candidates_from_row",
    "coerce_social_profile_urlish_candidate",
    "email_domain_is_promotable",
    "email_seed_candidates_from_row",
    "ensure_email_seed_row",
    "host_seed_candidates_from_row",
    "insert_seed_relation",
    "lookup_seed_depth",
    "merge_seed_metadata",
    "normalize_social_profile_anchor",
    "preferred_seed_source",
    "safe_json_loads",
    "scope_seed_candidate",
    "seed_lookup_keys",
    "social_profile_anchor_confidence",
    "social_profile_anchor_seed_candidate",
    "social_profile_account_handle_candidates",
    "social_profile_candidate_batch_entries",
    "social_profile_candidate_dedupe_family_entries",
    "social_profile_candidate_family_entries",
    "social_profile_direct_platform",
    "social_profile_domain_alias_text",
    "social_profile_domain_host_candidates",
    "social_profile_domain_host_key_candidates",
    "social_profile_domain_host_string_candidates",
    "social_profile_domain_host_value_candidates",
    "social_profile_domain_hosts",
    "social_profile_identity_url_hint_values",
    "social_profile_payload_candidate_items",
    "social_profile_payload_candidate_items_at_depth",
    "social_profile_payload_child_candidate_items",
    "social_profile_payload_child_context",
    "social_profile_payload_dedupe_key",
    "social_profile_payload_entries",
    "social_profile_payload_entry",
    "social_profile_payload_has_profile_hint",
    "social_profile_payload_with_inherited_context",
    "social_profile_handle_pivot_entry",
    "social_profile_handles",
    "social_profile_host_pivot_entry",
    "social_profile_link_handle_candidates",
    "social_profile_platform_hint",
    "social_profile_platform_hint_candidate",
    "social_profile_platform_label_candidate",
    "social_profile_pivot_family",
    "social_profile_pivots",
    "social_profile_pivot_batch_entries",
    "social_profile_pivot_family_entries",
    "social_profile_profile_candidates_from_pivots",
    "social_profile_related_host_batch_entries",
    "social_profile_related_host_family_entries",
    "social_profile_related_host_group_entries",
    "social_profile_related_hosts",
    "social_profile_scalar_url_hint_value_for_item_key",
    "social_profile_scalar_url_hint_values",
    "social_profile_seed_pivot_entry",
    "social_profile_text_handle_candidates",
    "social_profile_url_hint_value_for_item_key",
    "social_profile_url_hint_values",
    "social_profile_url_pivot_entry",
    "social_profile_value_batch_entries",
    "social_profile_value_entry",
    "social_profile_value_family_entries",
    "social_profile_value_group_entries",
    "should_promote_bluesky_domain_handle",
    "upsert_seed_candidate",
]
