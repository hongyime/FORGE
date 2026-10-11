"""Shared regex patterns for seed and secret extraction.

The deep GitHub and Supabase scanners consume this module. Patterns are
grouped so callers can run a single :func:`extract_seeds_from_text` pass
over arbitrary text (READMEs, commit messages, PR bodies, Supabase row
values, workflow YAML, Terraform HCL, ``.env.example`` files, config
JSON, ...) and get a clean, deduped list of ``target-feed.v1``-compatible
seed dicts plus a parallel list of secret hits.

Design constraints:

- The scanners **never** persist raw secret values. :func:`scan_secrets`
  returns only the detector label and a redacted sample. Call sites
  must treat anything with ``is_secret=True`` as a hit, not a seed.
- Pattern evaluation is fully offline. No DNS/WHOIS/network lookups
  are performed here; downstream FORGE workflows do their own
  scope/validation gating.
- Confidence tiers reflect **how unambiguous** the extraction is, not
  how important the seed is. ``high`` = unambiguous (full URL, valid
  IPv4, email, ARN), ``medium`` = structurally valid but requires
  downstream validation (bare domain, cloud account id), ``low`` =
  weak match (generic 12-digit integer that could be AWS or anything,
  bare 20-char lowercase ref that could be Supabase).

The emitted seed shape is forward-compatible with
``forge.targets_import``: every item carries ``target_type`` /
``target_value`` plus a parallel ``type`` / ``value`` for callers that
prefer the shorter keys. ``confidence`` is informational — downstream
feed-build is still the authority on whether a candidate becomes an
engagement.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit


PATTERNS_SCHEMA_VERSION = "forge.onboard.patterns.v1"


# ---------------------------------------------------------------------------
# Core extraction patterns
# ---------------------------------------------------------------------------


#: Primary extractors. Each produces zero or more seed hits via
#: :func:`extract_seeds_from_text`. Patterns are evaluated in iteration
#: order so URLs and ARNs are matched before bare domains / 12-digit
#: integers get a chance to swallow them.
PATTERNS: dict[str, str] = {
    # Full URL with scheme. Matches RFC 3986 unreserved + reserved chars,
    # stops at whitespace, quote marks, or trailing punctuation.
    "url": r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%\-]+",
    # Bare domain with a 2+ char TLD. Downstream scope checks reject
    # IANA reserved / internal TLDs anyway.
    "domain": r"(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,24}",
    # IPv4 dotted quad; octets are revalidated numerically below.
    "ipv4": r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b",
    # IPv6 (full and compressed); verified via ipaddress below.
    "ipv6": r"\b(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}\b",
    # Email address. The upstream RFC regex is overkill; this matches
    # the common case and lets downstream validators do the rest.
    "email": r"[A-Za-z0-9][A-Za-z0-9._%+\-]*@[A-Za-z0-9][A-Za-z0-9.\-]*"
    r"\.[A-Za-z]{2,}",
    # Phone number in E.164 format.
    "phone_e164": r"\+[1-9]\d{6,14}",
    # AWS account id in explicit AWS context. A bare 12-digit integer
    # by itself is too easily confused with phone numbers, invoice
    # numbers, or test fixtures, so we only match when the surrounding
    # text declares the AWS intent.
    "aws_account": r"(?i)(?:aws[_\-]?account[_\-]?id\s*[=:]\s*['\"]?|"
    r"account[_\-]?id\s*[=:]\s*['\"]?|"
    r"cloud_ref:aws_account:|arn:aws:[A-Za-z0-9\-]+:[A-Za-z0-9\-]*:)"
    r"\d{12}",
    # AWS ARN. Captures region and account id as part of the match.
    "aws_arn": r"arn:aws:[A-Za-z0-9\-]+:[A-Za-z0-9\-]*:\d{12}:"
    r"[A-Za-z0-9/_\-:]+",
    # Azure tenant id (RFC 4122 lowercase UUID).
    "azure_tenant": r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
    r"[0-9a-f]{4}-[0-9a-f]{12}\b",
    # GCP project id. Written in explicit cloud context only:
    # ``projects/<id>``, ``project_id = "<id>"``, ``gcp_project:<id>``,
    # or App Engine / Cloud Functions / Cloud Run URL suffixes. A bare
    # 6-30 char lowercase string by itself is too ambiguous to tag.
    "gcp_project": r"(?i)(?:projects/|project[_\-]?id\s*[=:]\s*['\"]?|"
    r"gcp_project:|cloud_ref:gcp_project:)[a-z][a-z0-9\-]{4,28}[a-z0-9]"
    r"|[a-z][a-z0-9\-]{4,28}[a-z0-9](?=\.(?:appspot\.com|cloudfunctions\.net|run\.app)\b)",
    # Supabase project ref in explicit context: either as part of a
    # supabase.co host, embedded in cloud_ref canonical form, or named
    # explicitly in config. 20-char bare lowercase alpha alone is way
    # too ambiguous (English words, test fixtures, etc.).
    "supabase_ref": r"(?i)(?:cloud_ref:supabase:|supabase[_\-]?project[_\-]?ref"
    r"\s*[=:]\s*['\"]?)[a-z]{20}"
    r"|[a-z]{20}(?=\.supabase\.co)",
    # Cloud reference seed type canonical form.
    "cloud_ref": r"cloud_ref:[A-Za-z0-9_]+:[A-Za-z0-9._\-]+",
    # Object-store bucket references.
    "s3_bucket": r"s3://[A-Za-z0-9._\-]+|"
    r"[A-Za-z0-9][A-Za-z0-9._\-]{1,61}\.s3[.\-][A-Za-z0-9.\-]*amazonaws\.com",
    "gcs_bucket": r"gs://[A-Za-z0-9._\-]+|"
    r"storage\.googleapis\.com/[A-Za-z0-9._\-]+",
    "azure_blob": r"\b[A-Za-z0-9]+\.blob\.core\.windows\.net\b",
    # API endpoint hint (path-only, used contextually inside URL hits).
    "api_endpoint": r"(?:/api/|/v[0-9]+/|/graphql|/rest/|/webhook)",
}


#: Hostnames we never promote to the operator target feed. Localhost,
#: GitHub infrastructure, package registries, and well-known CDNs are
#: filtered out. Operators who legitimately own ``example.com`` can
#: still add it manually via :mod:`forge.onboard.target_wizard`.
DENY_LIST_DOMAINS: frozenset[str] = frozenset(
    {
        # Loopback / unspecified
        "localhost",
        "127.0.0.1",
        "0.0.0.0",
        "::1",
        # GitHub infrastructure
        "github.com",
        "www.github.com",
        "raw.githubusercontent.com",
        "objects.githubusercontent.com",
        "api.github.com",
        "github.io",
        "github.blog",
        "codeload.github.com",
        "actions.githubusercontent.com",
        "pages.github.com",
        # Reserved documentation domains
        "example.com",
        "example.org",
        "example.net",
        "test.com",
        "placeholder.com",
        "foo.bar",
        "your-domain.com",
        # Package registries / docs
        "npmjs.org",
        "npmjs.com",
        "registry.npmjs.org",
        "pypi.org",
        "pypi.python.org",
        "files.pythonhosted.org",
        "rubygems.org",
        "crates.io",
        "packagist.org",
        "nuget.org",
        "maven.org",
        "central.sonatype.com",
        "repo.maven.apache.org",
        # Container registries
        "docker.io",
        "docker.com",
        "hub.docker.com",
        "ghcr.io",
        "quay.io",
        "gcr.io",
        "mcr.microsoft.com",
        # Google infra (not a target in itself)
        "googleapis.com",
        "gstatic.com",
        "google.com",
        "www.google.com",
        "google-analytics.com",
        # CDNs / shields / badges
        "cloudflare.com",
        "www.cloudflare.com",
        "fastly.net",
        "jsdelivr.net",
        "unpkg.com",
        "cdnjs.cloudflare.com",
        "shields.io",
        "img.shields.io",
        "badge.fury.io",
        "badgen.net",
        # Common schema / docs
        "schemas.microsoft.com",
        "schemas.openxmlformats.org",
        "www.w3.org",
        "www.rfc-editor.org",
    }
)


#: Secret detectors. Matches here surface via :func:`scan_secrets` as
#: ``{"label": str, "redacted_sample": str, "offset": int}`` entries.
#: The raw matched value is never returned verbatim; only a prefix +
#: suffix sample is retained so operators can grep for the location
#: without re-leaking the credential body.
SECRET_INDICATORS: dict[str, str] = {
    "aws_access_key": r"AKIA[0-9A-Z]{16}",
    "aws_session_key": r"ASIA[0-9A-Z]{16}",
    "github_pat": r"gh[pousr]_[A-Za-z0-9]{30,}",
    "github_oauth": r"gho_[A-Za-z0-9]{36}",
    "github_fine_grained_pat": r"github_pat_[0-9A-Za-z_]{80,}",
    "slack_token": r"xox[baprs]-[A-Za-z0-9\-]{10,}",
    "stripe_key": r"sk_(?:live|test)_[A-Za-z0-9]{24,}",
    "stripe_restricted": r"rk_(?:live|test)_[A-Za-z0-9]{24,}",
    "google_api_key": r"AIza[0-9A-Za-z_\-]{35}",
    "google_oauth": r"ya29\.[0-9A-Za-z_\-]{20,}",
    "jwt_token": r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}"
    r"(?:\.[A-Za-z0-9_\-]+)?",
    "private_key_block": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |"
    r"PGP |PRIVATE )?PRIVATE KEY-----",
    "generic_bearer": r"[Bb]earer\s+[A-Za-z0-9._\-]{20,}",
    "basic_auth_credential": r"https?://[A-Za-z0-9._%+\-]+:[^@\s]{3,}@"
    r"[A-Za-z0-9._\-]+",
    "generic_secret_assignment": r"(?i)(?:api[_\-]?key|secret[_\-]?key|"
    r"access[_\-]?token|auth[_\-]?token|private[_\-]?token|"
    r"password|passwd|credential)\s*[=:]\s*['\"]"
    r"[A-Za-z0-9/+=_\-\.]{16,}['\"]",
    "sendgrid_key": r"SG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}",
    "mailgun_key": r"key-[0-9a-zA-Z]{32}",
    "twilio_sid": r"AC[0-9a-fA-F]{32}",
    "square_access_token": r"EAAA[A-Za-z0-9\-_]{60,}",
    "heroku_api_key": r"[hH]eroku[-_ ]?(?:api)?[-_ ]?key[\"'\s:=]+"
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
}


#: Compiled form of :data:`PATTERNS` for faster repeated extraction.
_COMPILED_PATTERNS: dict[str, re.Pattern[str]] = {
    name: re.compile(pattern) for name, pattern in PATTERNS.items()
}

_COMPILED_SECRETS: dict[str, re.Pattern[str]] = {
    name: re.compile(pattern) for name, pattern in SECRET_INDICATORS.items()
}


#: Ordered iteration over primary patterns. Order matters: URLs claim
#: the full match first so the embedded host doesn't also appear as a
#: bare-domain hit at a different confidence.
_EXTRACTION_ORDER: tuple[str, ...] = (
    "cloud_ref",
    "url",
    "aws_arn",
    "s3_bucket",
    "gcs_bucket",
    "azure_blob",
    "email",
    "ipv4",
    "ipv6",
    "phone_e164",
    "azure_tenant",
    "gcp_project",
    "supabase_ref",
    "aws_account",
    "domain",
)


#: Confidence tier per pattern. See module docstring for semantics.
_CONFIDENCE: dict[str, str] = {
    "url": "high",
    "email": "high",
    "ipv4": "high",
    "ipv6": "high",
    "phone_e164": "high",
    "aws_arn": "high",
    "cloud_ref": "high",
    "s3_bucket": "high",
    "gcs_bucket": "high",
    "azure_blob": "high",
    "domain": "medium",
    "azure_tenant": "medium",
    "aws_account": "low",
    "gcp_project": "low",
    "supabase_ref": "low",
    "api_endpoint": "low",
}


#: Translation from pattern name to :class:`forge.targets_import`
#: canonical seed type. Patterns that are only context hints map to
#: ``None`` and are not emitted as seeds (``api_endpoint`` is a hint
#: inside a URL body, not a seed in its own right).
_SEED_TYPE: dict[str, str | None] = {
    "url": "url",
    "domain": "domain",
    "ipv4": "ipv4",
    "ipv6": "ipv6",
    "email": "email",
    "phone_e164": "phone",
    "aws_account": "cloud_ref",
    "aws_arn": "cloud_ref",
    "azure_tenant": "cloud_ref",
    "gcp_project": "cloud_ref",
    "supabase_ref": "cloud_ref",
    "s3_bucket": "cloud_ref",
    "gcs_bucket": "cloud_ref",
    "azure_blob": "url",
    "cloud_ref": "cloud_ref",
    "api_endpoint": None,
}


# Reserved GCP words that collide with the project-id regex. These
# should never be reported as projects.
_GCP_PROJECT_DENYLIST: frozenset[str] = frozenset(
    {
        "google-apis",
        "google-apis-explorer",
        "google-containers",
        "google-samples",
        "googleapis",
    }
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def extract_seeds_from_text(
    text: str,
    *,
    source_label: str = "",
    deny_domains: Iterable[str] | None = None,
) -> list[dict[str, Any]]:
    """Extract every target seed candidate from ``text``.

    Args:
        text: Arbitrary text (README, commit body, workflow YAML, etc.).
        source_label: Provenance string attached to each emitted seed
            (``"myorg/webapp:readme"`` for example).
        deny_domains: Optional iterable of extra hostnames to exclude
            from URL/domain extraction. :data:`DENY_LIST_DOMAINS` is
            always applied.

    Returns:
        A list of dicts shaped like::

            {
                "target_type": "domain",     # feed-compatible key
                "target_value": "api.example.com",
                "type": "domain",            # short alias
                "value": "api.example.com",
                "confidence": "medium",
                "source_kind": "github_spider",
                "source_group": "github_spider",
                "provenance": "myorg/webapp:readme",
                "first_seen_at": "...",
            }

        Dedup is by ``(target_type, target_value)``. URL hits also emit
        a parallel ``domain`` hit for the URL's host when the host is
        not deny-listed.
    """
    body = str(text or "")
    if not body:
        return []
    deny: frozenset[str] = DENY_LIST_DOMAINS | frozenset(
        _normalize_host(d) for d in (deny_domains or ())
    )
    results: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    now = _now_iso()

    for name in _EXTRACTION_ORDER:
        pattern = _COMPILED_PATTERNS[name]
        for match in pattern.finditer(body):
            raw = match.group(0)
            for payload in _emit_candidates(name, raw, source_label, deny, now):
                key = (payload["target_type"], payload["target_value"])
                if key in seen:
                    continue
                seen.add(key)
                results.append(payload)
    return results


def scan_secrets(
    text: str,
    *,
    source_label: str = "",
) -> list[dict[str, Any]]:
    """Return redacted secret hits for ``text``.

    Each hit carries ``{"label", "redacted_sample", "offset", "source"}``
    where ``redacted_sample`` is at most 12 chars (4-char prefix,
    ``...``, 4-char suffix). The raw matched value is **never** returned.
    """
    body = str(text or "")
    if not body:
        return []
    hits: list[dict[str, Any]] = []
    seen: set[tuple[str, int, int]] = set()
    for label, pattern in _COMPILED_SECRETS.items():
        for match in pattern.finditer(body):
            key = (label, match.start(), match.end())
            if key in seen:
                continue
            seen.add(key)
            hits.append(
                {
                    "label": label,
                    "redacted_sample": _redact_match(match.group(0)),
                    "offset": match.start(),
                    "source": source_label or "",
                }
            )
    return hits


def classify_cloud_reference(value: str) -> dict[str, Any] | None:
    """Try to classify a bare string as a cloud reference.

    Returns ``{"provider", "kind", "canonical_value"}`` or ``None``.
    This is a convenience for callers who have already decided ``value``
    looks like an AWS account / Azure tenant / GCP project id but want
    the canonical ``cloud_ref:<kind>:<id>`` form.
    """
    raw = str(value or "").strip()
    if not raw:
        return None
    # Full ARN — explicit AWS context.
    if re.fullmatch(
        r"arn:aws:[A-Za-z0-9\-]+:[A-Za-z0-9\-]*:\d{12}:[A-Za-z0-9/_\-:]+",
        raw,
    ):
        return {
            "provider": "aws",
            "kind": "aws_arn",
            "canonical_value": raw,
        }
    # Pre-formatted cloud reference.
    if raw.startswith("cloud_ref:"):
        parts = raw.split(":", 2)
        kind = parts[1] if len(parts) >= 2 else "unknown"
        return {
            "provider": kind,
            "kind": kind,
            "canonical_value": raw,
        }
    # Bare 12-digit AWS account id. Low confidence — caller must have
    # already decided this is AWS context (e.g. the column name is
    # ``aws_account_id``). Here we only canonicalize.
    if re.fullmatch(r"\d{12}", raw):
        return {
            "provider": "aws",
            "kind": "aws_account",
            "canonical_value": f"cloud_ref:aws_account:{raw}",
        }
    # Azure tenant uuid (lowercase).
    if re.fullmatch(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        raw,
    ):
        return {
            "provider": "azure",
            "kind": "azure_tenant",
            "canonical_value": f"cloud_ref:azure_tenant:{raw}",
        }
    # Supabase project ref — 20 lowercase letters.
    if re.fullmatch(r"[a-z]{20}", raw):
        return {
            "provider": "supabase",
            "kind": "supabase_project",
            "canonical_value": f"cloud_ref:supabase:{raw}",
        }
    return None


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _emit_candidates(
    name: str,
    raw: str,
    source_label: str,
    deny: frozenset[str],
    now: str,
) -> list[dict[str, Any]]:
    """Translate a raw pattern hit into zero or more seed candidates."""
    seed_type = _SEED_TYPE.get(name)
    if seed_type is None:
        return []
    confidence = _CONFIDENCE.get(name, "medium")

    cleaned = raw.strip()
    cleaned = cleaned.rstrip(".,;:)]}\"'`")

    if name == "url":
        host = _host_from_url(cleaned)
        if not host or host in deny:
            return []
        out: list[dict[str, Any]] = [
            _make_seed("url", cleaned, confidence, source_label, now, host=host),
        ]
        if host not in deny:
            out.append(
                _make_seed(
                    "domain",
                    host,
                    _CONFIDENCE["domain"],
                    source_label,
                    now,
                )
            )
        return out
    if name == "domain":
        host = cleaned.lower().strip(".").lstrip("*.")
        if not host or host in deny:
            return []
        # Guard against domains that would validate as IPs.
        try:
            ipaddress.ip_address(host)
            return []
        except ValueError:
            pass
        return [_make_seed("domain", host, confidence, source_label, now)]
    if name == "ipv4":
        try:
            value = str(ipaddress.IPv4Address(cleaned))
        except ValueError:
            return []
        if value in deny:
            return []
        return [_make_seed("ipv4", value, confidence, source_label, now)]
    if name == "ipv6":
        try:
            value = str(ipaddress.IPv6Address(cleaned))
        except ValueError:
            return []
        if value in deny:
            return []
        return [_make_seed("ipv6", value, confidence, source_label, now)]
    if name == "email":
        return [_make_seed("email", cleaned.lower(), confidence, source_label, now)]
    if name == "phone_e164":
        return [_make_seed("phone", cleaned, confidence, source_label, now)]
    if name == "aws_arn":
        return [_make_seed("cloud_ref", cleaned, confidence, source_label, now)]
    if name == "aws_account":
        # Strip the context prefix to leave the raw 12-digit id.
        text = cleaned
        for prefix_regex in (
            r"^aws[_\-]?account[_\-]?id\s*[=:]\s*['\"]?",
            r"^account[_\-]?id\s*[=:]\s*['\"]?",
            r"^AccountId\s*[=:]\s*['\"]?",
            r"^cloud_ref:aws_account:",
            r"^arn:aws:[A-Za-z0-9\-]+:[A-Za-z0-9\-]*:",
        ):
            match_prefix = re.match(prefix_regex, text, flags=re.IGNORECASE)
            if match_prefix:
                text = text[match_prefix.end() :]
                break
        text = text.strip().rstrip("'\"")
        if not re.fullmatch(r"\d{12}", text):
            return []
        return [
            _make_seed(
                "cloud_ref",
                f"cloud_ref:aws_account:{text}",
                confidence,
                source_label,
                now,
            )
        ]
    if name == "azure_tenant":
        return [
            _make_seed(
                "cloud_ref",
                f"cloud_ref:azure_tenant:{cleaned}",
                confidence,
                source_label,
                now,
            )
        ]
    if name == "gcp_project":
        # Strip the context prefix captured by the regex to leave the
        # raw project id. Supported prefixes: ``projects/<id>``,
        # ``project_id = "<id>"``, ``gcp_project:<id>``,
        # ``cloud_ref:gcp_project:<id>``, and
        # ``<id>.appspot.com``-style URL suffixes (no prefix to strip).
        text = cleaned
        for prefix_regex in (
            r"^projects/",
            r"^project[_\-]?id\s*[=:]\s*['\"]?",
            r"^gcp_project:",
            r"^cloud_ref:gcp_project:",
        ):
            match_prefix = re.match(prefix_regex, text, flags=re.IGNORECASE)
            if match_prefix:
                text = text[match_prefix.end() :]
                break
        text = text.strip().rstrip("'\"")
        if not text or text.lower() in _GCP_PROJECT_DENYLIST:
            return []
        return [
            _make_seed(
                "cloud_ref",
                f"cloud_ref:gcp_project:{text}",
                confidence,
                source_label,
                now,
            )
        ]
    if name == "supabase_ref":
        text = cleaned
        for prefix_regex in (
            r"^cloud_ref:supabase:",
            r"^supabase[_\-]?project[_\-]?ref\s*[=:]\s*['\"]?",
        ):
            match_prefix = re.match(prefix_regex, text, flags=re.IGNORECASE)
            if match_prefix:
                text = text[match_prefix.end() :]
                break
        text = text.strip().rstrip("'\"")
        if not re.fullmatch(r"[a-z]{20}", text):
            return []
        return [
            _make_seed(
                "cloud_ref",
                f"cloud_ref:supabase:{text}",
                confidence,
                source_label,
                now,
            )
        ]
    if name == "s3_bucket":
        return [_make_seed("cloud_ref", _canonical_s3(cleaned), confidence, source_label, now)]
    if name == "gcs_bucket":
        return [_make_seed("cloud_ref", _canonical_gcs(cleaned), confidence, source_label, now)]
    if name == "azure_blob":
        return [
            _make_seed(
                "url",
                f"https://{cleaned}",
                confidence,
                source_label,
                now,
                host=cleaned,
            ),
            _make_seed(
                "domain",
                cleaned,
                _CONFIDENCE["domain"],
                source_label,
                now,
            ),
        ]
    if name == "cloud_ref":
        return [_make_seed("cloud_ref", cleaned, confidence, source_label, now)]
    return []


def _make_seed(
    seed_type: str,
    value: str,
    confidence: str,
    source_label: str,
    now: str,
    *,
    host: str = "",
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "target_type": seed_type,
        "target_value": value,
        "type": seed_type,
        "value": value,
        "confidence": confidence,
        "source_kind": "github_spider",
        "source_group": "github_spider",
        "provenance": source_label,
        "first_seen_at": now,
    }
    if host:
        payload["source_detail"] = host
    else:
        payload["source_detail"] = ""
    return payload


def _host_from_url(url: str) -> str:
    try:
        parsed = urlsplit(url)
    except ValueError:
        return ""
    host = (parsed.hostname or "").lower()
    return host.strip(".")


def _normalize_host(value: str) -> str:
    return str(value or "").strip().lower().strip(".").lstrip("*.")


def _canonical_s3(value: str) -> str:
    text = value.strip()
    if text.startswith("s3://"):
        return f"cloud_ref:aws_s3:{text[len('s3://') :]}"
    host = text.lower()
    bucket = host.split(".", 1)[0]
    return f"cloud_ref:aws_s3:{bucket}"


def _canonical_gcs(value: str) -> str:
    text = value.strip()
    if text.startswith("gs://"):
        return f"cloud_ref:gcs:{text[len('gs://') :]}"
    if text.startswith("storage.googleapis.com/"):
        return f"cloud_ref:gcs:{text[len('storage.googleapis.com/') :]}"
    return f"cloud_ref:gcs:{text}"


def _redact_match(value: str) -> str:
    text = str(value or "")
    if len(text) <= 8:
        return "***"
    return f"{text[:4]}...{text[-4:]}"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


__all__ = [
    "DENY_LIST_DOMAINS",
    "PATTERNS",
    "PATTERNS_SCHEMA_VERSION",
    "SECRET_INDICATORS",
    "classify_cloud_reference",
    "extract_seeds_from_text",
    "scan_secrets",
]
