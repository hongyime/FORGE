from __future__ import annotations

import ipaddress
import json
import re
import socket
from collections.abc import Callable
from typing import Any
from urllib.parse import urlparse

COMPANY_SUFFIXES = {
    "co",
    "company",
    "corp",
    "corporation",
    "group",
    "holdings",
    "inc",
    "incorporated",
    "llc",
    "limited",
    "ltd",
    "plc",
    "pte",
    "pty",
}
SOCIAL_PLATFORM_DOMAINS = (
    "about.me",
    "bitbucket.org",
    "bsky.app",
    "bsky.social",
    "dev.to",
    "facebook.com",
    "threads.com",
    "threads.net",
    "github.com",
    "gitlab.com",
    "gravatar.com",
    "instagram.com",
    "keybase.io",
    "linkedin.com",
    "medium.com",
    "news.ycombinator.com",
    "reddit.com",
    "t.me",
    "telegram.me",
    "twitter.com",
    "x.com",
    "youtube.com",
)
MASTODON_INSTANCE_DOMAINS = (
    "fosstodon.org",
    "hachyderm.io",
    "infosec.exchange",
    "mas.to",
    "mastodon.cloud",
    "mastodon.online",
    "mastodon.social",
    "mstdn.party",
    "mstdn.social",
)
MANAGED_CLOUD_PROVIDER_DOMAINS = (
    "amplifyapp.com",
    "amazonaws.com",
    "appspot.com",
    "blob.core.windows.net",
    "cloudfunctions.net",
    "digitaloceanspaces.com",
    "dfs.core.windows.net",
    "firebaseapp.com",
    "firebasestorage.googleapis.com",
    "firebaseio.com",
    "github.io",
    "gitlab.io",
    "netlify.com",
    "netlify.app",
    "pages.dev",
    "r2.cloudflarestorage.com",
    "r2.dev",
    "storage.cloud.google.com",
    "storage.googleapis.com",
    "supabase.co",
    "vercel.app",
    "web.core.windows.net",
    "web.app",
    "workers.dev",
)
AWS_S3_URL_PATTERNS = (
    re.compile(
        r"https?://([a-z0-9.\-]+)\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com(?:/|$)",
        re.IGNORECASE,
    ),
    re.compile(
        r"https?://s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com/([a-z0-9.\-]{3,63})(?:/|$)",
        re.IGNORECASE,
    ),
    re.compile(
        r"https?://([a-z0-9.\-]+)\.s3-website(?:[.-][a-z0-9-]+)?\.amazonaws\.com(?:/|$)",
        re.IGNORECASE,
    ),
    re.compile(
        r"https?://s3-website(?:[.-][a-z0-9-]+)?\.amazonaws\.com/([a-z0-9.\-]{3,63})(?:/|$)",
        re.IGNORECASE,
    ),
)
DO_SPACES_URL_PATTERNS = (
    re.compile(
        r"https?://([a-z0-9.\-]{3,63})\.([a-z0-9\-]+)\.digitaloceanspaces\.com(?:/|$)",
        re.IGNORECASE,
    ),
    re.compile(
        r"https?://([a-z0-9\-]+)\.digitaloceanspaces\.com/([a-z0-9.\-]{3,63})(?:/|$)",
        re.IGNORECASE,
    ),
)
GCS_URL_PATTERNS = (
    re.compile(
        r"https?://storage\.googleapis\.com/([a-zA-Z0-9._\-]{3,222})(?:/|$)",
        re.IGNORECASE,
    ),
    re.compile(
        r"https?://([a-zA-Z0-9._\-]{3,222})\.storage\.googleapis\.com(?:/|$)",
        re.IGNORECASE,
    ),
    re.compile(
        r"https?://storage\.cloud\.google\.com/([a-zA-Z0-9._\-]{3,222})(?:/|$)",
        re.IGNORECASE,
    ),
    re.compile(
        r"https?://firebasestorage\.googleapis\.com/(?:v0/)?b/([a-zA-Z0-9._\-]{3,222})/o(?:[/?#]|$)",
        re.IGNORECASE,
    ),
)
AZURE_BLOB_URL_PATTERNS = (
    re.compile(
        r"https?://([a-z0-9\-]{3,24})\.blob\.core\.windows\.net/([^/?#]+)",
        re.IGNORECASE,
    ),
)
AZURE_STATIC_WEBSITE_HOST_RE = re.compile(
    r"^([a-z0-9\-]{3,24})(?:\.[a-z0-9\-]+)?\.web\.core\.windows\.net$",
    re.IGNORECASE,
)


def looks_like_company_name(value: str) -> bool:
    tokens = [token.strip(".,") for token in value.strip().split() if token.strip(".,")]
    if len(tokens) < 2:
        return False
    return any(token.lower() in COMPANY_SUFFIXES for token in tokens)


def looks_like_person_name(value: str) -> bool:
    tokens = [token for token in value.strip().split() if token]
    if len(tokens) < 2 or len(tokens) > 4:
        return False
    if any(token.lower().strip(".,") in COMPANY_SUFFIXES for token in tokens):
        return False
    return all(_person_name_token(token) for token in tokens)


def _person_name_token(token: str) -> bool:
    if not token:
        return False
    if not token[0].isalpha():
        return False
    return all(char.isalpha() or char in {"-", "'"} for char in token)


def normalize_root_domain(host: str) -> str:
    labels = [part for part in host.lower().strip(".").split(".") if part]
    if len(labels) >= 2:
        return ".".join(labels[-2:])
    return host.lower().strip(".")


def host_context_json(
    discovery: str,
    *,
    synthetic_ip: bool = False,
    **extra: Any,
) -> str:
    payload: dict[str, Any] = {"discovery": discovery}
    if synthetic_ip:
        payload["synthetic_ip"] = True
    payload.update(extra)
    return json.dumps(payload)


def is_placeholder_host_ip(value: str) -> bool:
    text = str(value or "").strip()
    if not text or text in {"0.0.0.0", "::", "::0"}:
        return True
    try:
        parsed_ip = ipaddress.ip_address(text)
    except ValueError:
        return False
    if parsed_ip.is_unspecified:
        return True
    if parsed_ip.version == 4 and parsed_ip in ipaddress.ip_network("198.18.0.0/15"):
        return True
    return False


def excluded_host_for_seed_routing(hostname: str) -> bool:
    host = hostname.strip().lower().lstrip(".")
    if host.startswith("www."):
        host = host[4:]
    if any(host == domain or host.endswith(f".{domain}") for domain in SOCIAL_PLATFORM_DOMAINS):
        return True
    if (
        any(host == domain or host.endswith(f".{domain}") for domain in MASTODON_INSTANCE_DOMAINS)
        or host.startswith("mastodon.")
        or host.startswith("mstdn.")
    ):
        return True
    return any(host == domain or host.endswith(f".{domain}") for domain in MANAGED_CLOUD_PROVIDER_DOMAINS)


def initial_seed_dedupe_key(seed_entry: dict[str, str]) -> tuple[str, str]:
    entry_type = str(seed_entry.get("seed_type") or "").strip()
    entry_value = str(seed_entry.get("value") or "").strip()
    if entry_type == "username":
        return entry_type, entry_value.lower().lstrip("@")
    if entry_type in {"name", "company"}:
        return entry_type, " ".join(entry_value.casefold().split())
    return entry_type, entry_value.lower()


def dedupe_initial_seed_entries(seed_entries: list[dict[str, str]]) -> list[dict[str, str]]:
    deduped: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for seed_entry in seed_entries:
        key = initial_seed_dedupe_key(seed_entry)
        if not key[1] or key in seen:
            continue
        seen.add(key)
        deduped.append(seed_entry)
    return deduped


def canonical_initial_seed_value(
    seed_value: str,
    seed_type_value: str,
    *,
    canonical_http_url_value: Callable[[str], str | None],
    canonical_cloud_ref_value: Callable[[str], str | None],
) -> str:
    value = str(seed_value or "").strip()
    if seed_type_value == "email":
        return value.lower()
    if seed_type_value == "domain":
        return value.lower().strip(".")
    if seed_type_value in {"ipv4", "ipv6"}:
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            return value.lower()
    if seed_type_value == "cloud_ref":
        return canonical_http_url_value(value) or canonical_cloud_ref_value(value) or value.lower().strip(".")
    if seed_type_value in {"url", "apk_url"}:
        return canonical_http_url_value(value) or value
    return value


def prepare_classified_seed(
    seed_value: str,
    *,
    classify_seed_value: Callable[[str], str],
    canonical_http_url_value: Callable[[str], str | None],
    canonical_cloud_ref_value: Callable[[str], str | None],
) -> dict[str, str]:
    value = str(seed_value or "").strip()
    seed_type_value = classify_seed_value(value)
    return {
        "value": canonical_initial_seed_value(
            value,
            seed_type_value,
            canonical_http_url_value=canonical_http_url_value,
            canonical_cloud_ref_value=canonical_cloud_ref_value,
        ),
        "seed_type": seed_type_value,
    }


def derive_hostname_for_seed(value: str, kind: str, *, allow_email_domain: bool = True) -> str:
    if kind == "domain":
        hostname = value.lower().strip().strip(".")
    elif kind == "subdomain":
        hostname = value.lower().strip().strip(".")
    elif kind in {"url", "apk_url"}:
        parsed = urlparse(value)
        hostname = str(parsed.hostname or "").strip().lower().strip(".")
    elif kind == "email" and allow_email_domain:
        hostname = value.split("@", 1)[1].lower().strip().strip(".")
    else:
        hostname = ""
    if not hostname or "." not in hostname or excluded_host_for_seed_routing(hostname):
        return ""
    return hostname


def derive_domain_for_seed(
    value: str,
    kind: str,
    *,
    allow_email_domain: bool = True,
    reverse_lookup: Callable[[str], tuple[str, list[str], list[str]]] | None = None,
) -> str:
    hostname = derive_hostname_for_seed(
        value,
        kind,
        allow_email_domain=allow_email_domain,
    )
    if hostname:
        return normalize_root_domain(hostname)
    if kind in {"ipv4", "ipv6"}:
        lookup = socket.gethostbyaddr if reverse_lookup is None else reverse_lookup
        try:
            hostname, _aliases, _addresses = lookup(value)
            return normalize_root_domain(hostname) if "." in hostname else ""
        except (socket.herror, socket.gaierror, OSError):
            return ""
    return ""


def prepare_initial_seed_route(seed_entry: dict[str, str]) -> dict[str, Any]:
    seed_value = str(seed_entry["value"])
    entry_type = str(seed_entry["seed_type"])
    return {
        "value": seed_value,
        "seed_type": entry_type,
        "scope_values": [seed_value, f"*.{seed_value}"] if entry_type == "domain" else [seed_value],
        "derived_domain": derive_domain_for_seed(seed_value, entry_type),
        "username_seed": seed_value.lstrip("@") if entry_type == "username" else "",
        "phone_seed": seed_value if entry_type == "phone" else "",
        "name_seed": seed_value if entry_type == "name" else "",
        "company_seed": seed_value if entry_type == "company" else "",
        "ip_seed": seed_value.strip().lower() if entry_type in {"ipv4", "ipv6"} else "",
    }


def extract_cloud_asset_seed_refs(value: str) -> list[tuple[str, str]]:
    parsed = urlparse(str(value or "").strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return []
    url = str(value or "").strip()
    hostname = str(parsed.hostname or "").strip().lower().strip(".")
    refs: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def append(asset_type: str, identifier: str) -> None:
        key = (str(asset_type or "").strip().lower(), str(identifier or "").strip().lower())
        if key[0] and key[1] and key not in seen:
            seen.add(key)
            refs.append(key)

    if hostname.endswith(".supabase.co"):
        project_ref = hostname.split(".supabase.co", 1)[0].strip(".")
        append("supabase", project_ref)
    for firebase_suffix in (".firebaseio.com", ".firebaseapp.com", ".web.app"):
        if hostname.endswith(firebase_suffix):
            project_ref = hostname.split(firebase_suffix, 1)[0].strip(".")
            append("firebase", project_ref)
            break
    for asset_type, pattern in (
        ("amplify", re.compile(r"^([a-z0-9\-]+)\.amplifyapp\.com$", re.IGNORECASE)),
        ("gcp_appspot", re.compile(r"^([a-z0-9\-]+)(?:\.[a-z0-9\-]+)?\.appspot\.com$", re.IGNORECASE)),
        (
            "gcp_cloudfunctions",
            re.compile(r"^[a-z0-9\-]+-([a-z0-9\-]+)\.cloudfunctions\.net$", re.IGNORECASE),
        ),
        ("cloudflare_pages", re.compile(r"^([a-z0-9\-]+)\.pages\.dev$", re.IGNORECASE)),
        (
            "cloudflare_worker",
            re.compile(
                r"^[a-z0-9][a-z0-9\-]*(?:\.[a-z0-9][a-z0-9\-]*)+\.workers\.dev$",
                re.IGNORECASE,
            ),
        ),
        (
            "cloudflare_r2",
            re.compile(
                r"^[a-z0-9][a-z0-9\-]*(?:\.[a-z0-9][a-z0-9\-]*)?\.r2\.(?:dev|cloudflarestorage\.com)$",
                re.IGNORECASE,
            ),
        ),
        ("github_pages", re.compile(r"^[a-z0-9][a-z0-9\-]*\.github\.io$", re.IGNORECASE)),
        (
            "gitlab_pages",
            re.compile(
                r"^[a-z0-9][a-z0-9\-]*(?:\.[a-z0-9][a-z0-9\-]*)*\.gitlab\.io$",
                re.IGNORECASE,
            ),
        ),
        ("netlify", re.compile(r"^([a-z0-9\-]+)\.netlify\.(?:app|com)$", re.IGNORECASE)),
        ("vercel", re.compile(r"^([a-z0-9\-]+)\.vercel\.app$", re.IGNORECASE)),
    ):
        match = pattern.fullmatch(hostname)
        if not match:
            continue
        project_ref = (
            hostname
            if asset_type in {"cloudflare_worker", "cloudflare_r2", "github_pages", "gitlab_pages"}
            else str(match.group(1) or "").strip(".")
        )
        if asset_type == "gcp_cloudfunctions":
            path = str(parsed.path or "").rstrip("/")
            append(asset_type, f"{parsed.scheme}://{hostname}{path}")
        else:
            append(asset_type, project_ref)
        break
    for pattern in AWS_S3_URL_PATTERNS:
        match = pattern.search(url)
        if match:
            append("aws_s3", match.group(1))
            break
    for index, pattern in enumerate(DO_SPACES_URL_PATTERNS):
        match = pattern.search(url)
        if not match:
            continue
        if index == 0:
            bucket, region = match.group(1), match.group(2)
        else:
            region, bucket = match.group(1), match.group(2)
        append("do_spaces", f"{region}/{bucket}")
        break
    for pattern in GCS_URL_PATTERNS:
        match = pattern.search(url)
        if match:
            append("gcs", match.group(1))
            break
    static_site_match = AZURE_STATIC_WEBSITE_HOST_RE.fullmatch(hostname)
    if static_site_match:
        append("azure_blob", f"{static_site_match.group(1)}/$web")
    for pattern in AZURE_BLOB_URL_PATTERNS:
        match = pattern.search(url)
        if match:
            append("azure_blob", f"{match.group(1)}/{match.group(2)}")
            break
    return refs
