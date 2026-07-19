"""Helpers for extracting structured validation proof from stored detail text."""

from __future__ import annotations

import json
import re
from typing import Any

_VALIDATED_DETAIL_RE = re.compile(
    r"(?:^|[;\s])(?:validation=)?VALIDATED:([A-Za-z0-9_.-]+)(?::([^;\r\n]+))?",
    re.IGNORECASE,
)
_AWS_ACCOUNT_ID_RE = re.compile(
    r"(?:^|[\s;,])(?:AWS\s+)?AccountId\s*[:=]\s*([0-9]{12})(?:\b|$)",
    re.IGNORECASE,
)
_AWS_STS_METHODS = {"aws_sts_get_caller_identity"}
_LEGACY_CLOUD_READ_METHODS_REQUIRING_PROOF = {
    "firebase_database_node_read",
    "firebase_database_shallow_read",
    "supabase_rest_root",
}
_LOW_SIGNAL_CLOUD_READ_PROOF_MARKERS = (
    "accessible_but_no_data",
    "auth required",
    "bootstrap metadata",
    "catalog metadata",
    "demo",
    "error payload",
    "honeypot",
    "low-signal",
    "metadata-only",
    "no live",
    "no meaningful data",
    "no table data",
    "requires authentication",
    "schema metadata",
    "synthetic",
    "unexpected non-json",
)
_POSTHOG_VALIDATION_HOSTS = {"us.posthog.com", "eu.posthog.com"}
_CLOUD_OBJECT_PLACEHOLDER_MARKERS = {
    "changeme",
    "demo",
    "dummy",
    "example",
    "honeypot",
    "lorem",
    "placeholder",
    "sample",
    "synthetic",
    "test",
}
_CLOUD_OBJECT_LOW_SIGNAL_BASENAMES = {
    ".ds_store",
    ".gitkeep",
    "asset-manifest.json",
    "chart.lock",
    "chart.yaml",
    "cname",
    "desktop.ini",
    "favicon.ico",
    "firebase.json",
    "index.html",
    "kptfile",
    "manifest",
    "openapi.json",
    "package-lock.json",
    "package.json",
    "pnpm-lock.yaml",
    "pyproject.toml",
    "readme.md",
    "robots.txt",
    "service-worker.js",
    "site.webmanifest",
    "sitemap.xml",
    "tailwind.config.js",
    "tsconfig.json",
    "vite.config.ts",
    "yarn.lock",
}
_CLOUD_STATIC_ASSET_EXTENSIONS = {
    ".css",
    ".eot",
    ".gif",
    ".ico",
    ".jpeg",
    ".jpg",
    ".js",
    ".map",
    ".png",
    ".svg",
    ".ttf",
    ".webp",
    ".woff",
    ".woff2",
}
_CLOUD_STATIC_PATH_SEGMENTS = {
    "assets",
    "build",
    "chunks",
    "css",
    "dist",
    "fonts",
    "images",
    "img",
    "js",
    "public",
    "static",
}
_DATADOG_VALIDATION_SITES = {
    "datadoghq.com",
    "datadoghq.eu",
    "us3.datadoghq.com",
    "us5.datadoghq.com",
    "ap1.datadoghq.com",
    "ap2.datadoghq.com",
    "ddog-gov.com",
}
_OPAQUE_PROVIDER_PLACEHOLDER_IDENTIFIERS = {
    "account",
    "admin",
    "administrator",
    "api",
    "app",
    "application",
    "bot",
    "bots",
    "default",
    "demo",
    "example",
    "key",
    "model",
    "models",
    "none",
    "null",
    "org",
    "organization",
    "placeholder",
    "profile",
    "project",
    "sample",
    "service",
    "test",
    "token",
    "unknown",
    "undefined",
    "user",
    "users",
    "workspace",
}
_MODEL_PLACEHOLDER_IDENTIFIERS = _OPAQUE_PROVIDER_PLACEHOLDER_IDENTIFIERS | {
    "models",
}
_OPAQUE_PROVIDER_PLACEHOLDER_TOKENS = {
    "demo",
    "example",
    "none",
    "null",
    "placeholder",
    "sample",
    "test",
    "unknown",
    "undefined",
}
_OPENAI_MODEL_FAMILY_RE = re.compile(
    r"^(?:"
    r"gpt-|chatgpt-|o[1-9](?:[A-Za-z0-9_.-]|$)|"
    r"text-embedding-|dall-e-|tts-|whisper-|omni-moderation-|"
    r"codex-|computer-use-|babbage-|davinci-|sora-|ft:"
    r")",
    re.IGNORECASE,
)
_ANTHROPIC_MODEL_FAMILY_RE = re.compile(r"^claude-", re.IGNORECASE)
_GOOGLE_MODEL_FAMILY_RE = re.compile(
    r"^(?:"
    r"gemini-|text-embedding-|embedding-|imagen-|veo-|lyria-|"
    r"gemma-|learnlm-|nano-banana|aqa(?:$|[-_.])"
    r")",
    re.IGNORECASE,
)
_UUID_OR_32_HEX_RE = re.compile(
    r"(?:[0-9a-f]{32}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
    re.IGNORECASE,
)


def _empty_proof() -> dict[str, Any]:
    return {
        "validation_status": "",
        "validation_method": "",
        "validation_proof": "",
    }


def _looks_sequential_numeric_identifier(value: object) -> bool:
    candidate = re.sub(r"[^0-9]+", "", str(value or "").strip())
    if len(candidate) < 6:
        return False
    digits = [int(char) for char in candidate]
    ascending = all((right - left) % 10 == 1 for left, right in zip(digits, digits[1:]))
    descending = all((left - right) % 10 == 1 for left, right in zip(digits, digits[1:]))
    return ascending or descending


def _looks_repeated_compact_identifier(value: object) -> bool:
    compact = re.sub(r"[^A-Za-z0-9]+", "", str(value or "").strip()).lower()
    return bool(compact) and len(set(compact)) == 1


def _looks_prefixed_repeated_identifier(value: object) -> bool:
    candidate = str(value or "").strip().lower()
    parts = [part for part in re.split(r"[_-]+", candidate) if part]
    if len(parts) < 2:
        return False
    for suffix in (parts[-1], "".join(parts[1:])):
        compact = re.sub(r"[^a-z0-9]+", "", suffix)
        if len(compact) >= 6 and len(set(compact)) == 1:
            return True
    return False


def _has_placeholder_identifier_token(value: object) -> bool:
    parts = [part for part in re.split(r"[_-]+", str(value or "").strip().lower()) if part]
    if len(parts) < 2:
        return False
    return any(part in _OPAQUE_PROVIDER_PLACEHOLDER_TOKENS for part in parts)


def _has_sequential_numeric_identifier_token(value: object) -> bool:
    candidate = str(value or "").strip().lower()
    compact = re.sub(r"[^0-9]+", "", candidate)
    alnum_compact = re.sub(r"[^a-z0-9]+", "", candidate)
    if alnum_compact and alnum_compact.isdigit() and _looks_sequential_numeric_identifier(alnum_compact):
        return True
    if compact and compact == alnum_compact and _looks_sequential_numeric_identifier(compact):
        return True
    parts = [part for part in re.split(r"[_-]+", candidate) if part]
    return any(part.isdigit() and _looks_sequential_numeric_identifier(part) for part in parts)


def _stable_numeric_identifier(value: object, *, min_len: int = 3, max_len: int = 32) -> str:
    candidate = re.sub(r"[^0-9]+", "", str(value or "").strip())
    if not re.fullmatch(rf"[0-9]{{{min_len},{max_len}}}", candidate):
        return ""
    if len(set(candidate)) == 1:
        return ""
    if _looks_sequential_numeric_identifier(candidate):
        return ""
    return candidate


def _stable_provider_identifier(value: object) -> str:
    candidate = re.sub(r"[^A-Za-z0-9_-]+", "", str(value or "").strip())
    if not re.fullmatch(r"[A-Za-z0-9_-]{3,128}", candidate):
        return ""
    if candidate.lower() in _OPAQUE_PROVIDER_PLACEHOLDER_IDENTIFIERS:
        return ""
    if _has_placeholder_identifier_token(candidate):
        return ""
    if _looks_repeated_compact_identifier(candidate):
        return ""
    if _looks_prefixed_repeated_identifier(candidate):
        return ""
    if _has_sequential_numeric_identifier_token(candidate):
        return ""
    return candidate


def _stable_handle_identifier(value: object, *, allow_dot: bool = True) -> str:
    allowed = r"[^A-Za-z0-9_.-]+" if allow_dot else r"[^A-Za-z0-9-]+"
    candidate = re.sub(allowed, "", str(value or "").strip())
    if not candidate or not re.search(r"[A-Za-z0-9]", candidate):
        return ""
    if candidate.lower() in _OPAQUE_PROVIDER_PLACEHOLDER_IDENTIFIERS:
        return ""
    if _has_placeholder_identifier_token(candidate):
        return ""
    compact = re.sub(r"[^A-Za-z0-9]+", "", candidate)
    if len(compact) >= 3 and _looks_repeated_compact_identifier(compact):
        return ""
    return candidate


def _stable_uuid_or_32hex(value: object) -> str:
    candidate = str(value or "").strip().lower()
    if not _UUID_OR_32_HEX_RE.fullmatch(candidate):
        return ""
    if _looks_repeated_compact_identifier(candidate):
        return ""
    if _has_sequential_numeric_identifier_token(candidate):
        return ""
    return candidate


def _stable_model_identifier(
    value: object,
    *,
    require_models_prefix: bool = False,
    provider_family: str | None = None,
) -> str:
    candidate = re.sub(r"[^A-Za-z0-9_./:-]+", "", str(value or "").strip())
    if not candidate:
        return ""
    tail = candidate
    if require_models_prefix:
        if not candidate.startswith("models/"):
            return ""
        tail = candidate.split("/", 1)[1]
    compact = re.sub(r"[^A-Za-z0-9]+", "", tail).lower()
    if len(compact) < 3 or compact in _MODEL_PLACEHOLDER_IDENTIFIERS:
        return ""
    if _looks_repeated_compact_identifier(compact):
        return ""
    if not re.search(r"[A-Za-z]", compact):
        return ""
    family = str(provider_family or "").strip().lower()
    family_value = tail if require_models_prefix else candidate
    if family == "openai" and not _OPENAI_MODEL_FAMILY_RE.match(family_value):
        return ""
    if family == "anthropic" and not _ANTHROPIC_MODEL_FAMILY_RE.match(family_value):
        return ""
    if family == "google" and not _GOOGLE_MODEL_FAMILY_RE.match(family_value):
        return ""
    return candidate[:80]


def _stable_model_sample_from_detail(
    proof: str,
    *,
    require_models_prefix: bool = False,
    provider_family: str | None = None,
) -> str:
    match = re.search(r"\bsample=([A-Za-z0-9_./:,-]+)", str(proof or ""), re.IGNORECASE)
    if not match:
        return ""
    for value in str(match.group(1) or "").split(","):
        model_id = _stable_model_identifier(
            value,
            require_models_prefix=require_models_prefix,
            provider_family=provider_family,
        )
        if model_id:
            return model_id
    return ""


def _stable_mailchimp_datacenter(value: object) -> str:
    candidate = str(value or "").strip().lower()
    if not re.fullmatch(r"us[0-9]{1,2}", candidate):
        return ""
    return candidate


def _stable_mailchimp_health_status(value: object) -> str:
    health = str(value or "").strip()
    compact = re.sub(r"[^a-z0-9]+", "", health.lower())
    if compact != "everythingschimpy":
        return ""
    return health


def _stable_twilio_account_sid(value: object) -> str:
    candidate = str(value or "").strip()
    if not re.fullmatch(r"AC[a-f0-9]{32}", candidate, re.IGNORECASE):
        return ""
    sid_body = candidate[2:].lower()
    if len(set(sid_body)) == 1:
        return ""
    return candidate


def _stable_twilio_account_status(value: object) -> str:
    candidate = str(value or "").strip().lower()
    if candidate != "active":
        return ""
    return candidate


def _extract_xml_tag_values(text: object, tag_name: str) -> list[str]:
    tag = re.escape(str(tag_name or "").strip())
    if not tag:
        return []
    return [
        match.group(1).strip()
        for match in re.finditer(
            rf"<(?:[A-Za-z0-9_-]+:)?{tag}\b[^>]*>(.*?)</(?:[A-Za-z0-9_-]+:)?{tag}>",
            str(text or ""),
            re.IGNORECASE | re.DOTALL,
        )
        if match.group(1).strip()
    ]


def _stable_cloud_object_name(value: object) -> str:
    candidate = str(value or "").strip().strip("/")
    if not candidate or len(candidate) > 180:
        return ""
    if re.search(r"[\x00-\x1f\x7f]", candidate):
        return ""
    parts = [part for part in re.split(r"[\\/]+", candidate.lower()) if part]
    if not parts:
        return ""
    if any(part in _CLOUD_OBJECT_PLACEHOLDER_MARKERS for part in parts):
        return ""
    basename = parts[-1]
    if basename in _CLOUD_OBJECT_LOW_SIGNAL_BASENAMES:
        return ""
    if basename.startswith("._") or basename.startswith("."):
        return ""
    stem = basename.rsplit(".", 1)[0]
    if stem in _CLOUD_OBJECT_PLACEHOLDER_MARKERS:
        return ""
    if any(marker in stem for marker in _CLOUD_OBJECT_PLACEHOLDER_MARKERS):
        return ""
    compact_stem = re.sub(r"[^a-z0-9]+", "", stem)
    if len(compact_stem) >= 6 and (
        _looks_repeated_compact_identifier(compact_stem)
        or _looks_sequential_numeric_identifier(compact_stem)
    ):
        return ""
    extension = f".{basename.rsplit('.', 1)[1]}" if "." in basename else ""
    if extension in _CLOUD_STATIC_ASSET_EXTENSIONS and any(
        part in _CLOUD_STATIC_PATH_SEGMENTS for part in parts[:-1]
    ):
        return ""
    return candidate[:120]


def _cloud_listing_json_names(proof: str) -> list[str]:
    try:
        payload = json.loads(str(proof or ""))
    except Exception:  # noqa: BLE001
        return []
    if not isinstance(payload, dict):
        return []
    items = payload.get("items")
    prefixes = payload.get("prefixes")
    looks_like_gcs_listing = payload.get("kind") == "storage#objects" or isinstance(items, list)
    if not looks_like_gcs_listing and not isinstance(prefixes, list):
        return []
    names: list[str] = []
    if isinstance(items, list):
        for item in items:
            if isinstance(item, dict):
                name = str(item.get("name") or "").strip()
                if name:
                    names.append(name)
    if isinstance(prefixes, list):
        names.extend(str(item or "").strip() for item in prefixes if str(item or "").strip())
    return names


def _cloud_object_listing_proof_is_stable(
    proof: str,
    *,
    xml_tag: str,
    markers: tuple[str, ...],
    allow_gcs_json: bool = False,
) -> bool:
    text = str(proof or "").strip()
    lowered = text.lower()
    if any(marker in lowered for marker in _LOW_SIGNAL_CLOUD_READ_PROOF_MARKERS):
        return False
    if not any(marker in lowered for marker in markers):
        return False
    names = _extract_xml_tag_values(text, xml_tag)
    if allow_gcs_json:
        names.extend(_cloud_listing_json_names(text))
    return any(_stable_cloud_object_name(name) for name in names)


def _stable_currency_summary(value: object) -> str:
    tokens = [
        str(token or "").strip().lower()
        for token in str(value or "").split(",")
        if str(token or "").strip()
    ]
    if not tokens:
        return ""
    stable_tokens: list[str] = []
    seen: set[str] = set()
    for token in tokens:
        currency = re.sub(r"[^a-z]+", "", token)
        if not re.fullmatch(r"[a-z]{3}", currency):
            return ""
        if currency in _OPAQUE_PROVIDER_PLACEHOLDER_IDENTIFIERS:
            return ""
        if _looks_repeated_compact_identifier(currency):
            return ""
        if currency not in seen:
            seen.add(currency)
            stable_tokens.append(currency)
    return ",".join(stable_tokens) if stable_tokens else ""


def _stable_slack_identifier(value: object, prefixes: tuple[str, ...]) -> str:
    candidate = re.sub(r"[^A-Za-z0-9]+", "", str(value or "").strip())
    lowered = candidate.lower()
    if not candidate or lowered in _OPAQUE_PROVIDER_PLACEHOLDER_IDENTIFIERS:
        return ""
    normalized = candidate.upper()
    prefix = next((item.upper() for item in prefixes if normalized.startswith(item.upper())), "")
    if not prefix or not re.fullmatch(rf"{prefix}[A-Z0-9]{{5,32}}", normalized):
        return ""
    suffix = normalized[len(prefix):]
    if len(set(suffix)) == 1:
        return ""
    if suffix.isdigit() and _looks_sequential_numeric_identifier(suffix):
        return ""
    return normalized


def _aws_sts_proof_has_stable_account_id(proof: str) -> bool:
    match = _AWS_ACCOUNT_ID_RE.search(proof)
    if not match:
        return False
    return bool(_stable_numeric_identifier(match.group(1), min_len=12, max_len=12))


def _github_user_proof_is_stable(proof: str) -> bool:
    match = re.search(
        r"github user ok:\s*user_id=([0-9]{2,16})\s+login=([a-z0-9-]+)\b",
        proof,
        re.IGNORECASE,
    )
    if (
        not match
        or not re.search(r"\buser_profile_present=true\b", proof, re.IGNORECASE)
        or not re.search(r"\bprofile_url_matches_login=true\b", proof, re.IGNORECASE)
    ):
        return False
    return bool(
        _stable_numeric_identifier(match.group(1), min_len=2, max_len=16)
        and _stable_handle_identifier(match.group(2), allow_dot=False)
    )


def _gitlab_user_proof_is_stable(proof: str) -> bool:
    match = re.search(
        r"gitlab user ok:\s*user_id=([0-9]{2,16})\s+username=([a-z0-9_.-]+)\b",
        proof,
        re.IGNORECASE,
    )
    if (
        not match
        or not re.search(r"\buser_profile_present=true\b", proof, re.IGNORECASE)
        or not re.search(r"\bprofile_url_matches_login=true\b", proof, re.IGNORECASE)
    ):
        return False
    return bool(
        _stable_numeric_identifier(match.group(1), min_len=2, max_len=16)
        and _stable_handle_identifier(match.group(2))
    )


def _huggingface_user_proof_is_stable(proof: str) -> bool:
    match = re.search(r"hugging face auth ok:\s*user=([a-z0-9_.-]+)\b", proof, re.IGNORECASE)
    if not match or not re.search(r"\buser_profile_present=true\b", proof, re.IGNORECASE):
        return False
    return bool(_stable_handle_identifier(match.group(1)))


def _bot_numeric_proof_is_stable(
    proof: str,
    *,
    label: str,
    min_len: int,
    max_len: int,
) -> bool:
    match = re.search(
        rf"{re.escape(label)}:\s*bot_id=([0-9]{{{min_len},{max_len}}})\b",
        proof,
        re.IGNORECASE,
    )
    if not match or not re.search(r"\bbot_profile_present=true\b", proof, re.IGNORECASE):
        return False
    return bool(_stable_numeric_identifier(match.group(1), min_len=min_len, max_len=max_len))


def _model_list_proof_is_stable(
    proof: str,
    *,
    label: str,
    require_models_prefix: bool = False,
    provider_family: str | None = None,
) -> bool:
    match = re.search(rf"{re.escape(label)}:\s*models=([0-9]+)\b", proof, re.IGNORECASE)
    if not match or int(match.group(1)) <= 0:
        return False
    return bool(
        _stable_model_sample_from_detail(
            proof,
            require_models_prefix=require_models_prefix,
            provider_family=provider_family,
        )
    )


def _datadog_site_proof_is_stable(proof: str) -> bool:
    # Datadog's validate endpoint proves token acceptance, but the endpoint
    # site is caller-selected and not a provider-returned account/key identity.
    del proof
    return False


def _sendgrid_proof_is_stable(proof: str) -> bool:
    if re.search(r"sendgrid profile ok:", proof, re.IGNORECASE):
        hash_match = re.search(r"\bprofile_hash=([a-f0-9]{16,64})\b", proof, re.IGNORECASE)
        return bool(
            hash_match
            and re.search(r"\b(?:email_present|username_present)=true\b", proof, re.IGNORECASE)
            and not _looks_repeated_compact_identifier(hash_match.group(1))
        )
    scopes_match = re.search(r"sendgrid scopes accessible:\s*count=([0-9]+)", proof, re.IGNORECASE)
    scope_hash_match = re.search(r"\bscope_hash=([a-f0-9]{16,64})\b", proof, re.IGNORECASE)
    return bool(
        scopes_match
        and int(scopes_match.group(1)) > 0
        and scope_hash_match
        and not _looks_repeated_compact_identifier(scope_hash_match.group(1))
    )


def _stripe_balance_proof_is_stable(proof: str) -> bool:
    mode_match = re.search(r"\bmode=(live|test|unknown)\b", proof, re.IGNORECASE)
    currency_match = re.search(r"\bcurrencies=([a-z0-9_,.-]+)", proof, re.IGNORECASE)
    balances_match = re.search(r"\bbalances=available:([0-9]+),pending:([0-9]+)\b", proof, re.IGNORECASE)
    if not mode_match or mode_match.group(1).lower() != "live" or not balances_match:
        return False
    return bool(_stable_currency_summary(currency_match.group(1) if currency_match else ""))


def _mailchimp_ping_proof_is_stable(proof: str) -> bool:
    dc_match = re.search(r"\bdc=([a-z]{2}[0-9]{1,2})\b", proof, re.IGNORECASE)
    health_match = re.search(r"\bhealth=([^\r\n]+)", proof, re.IGNORECASE)
    return bool(
        dc_match
        and health_match
        and _stable_mailchimp_datacenter(dc_match.group(1))
        and _stable_mailchimp_health_status(health_match.group(1))
    )


def _twilio_account_proof_is_stable(proof: str) -> bool:
    sid_match = re.search(r"\bsid=(AC[a-z0-9]{32})\b", proof, re.IGNORECASE)
    status_match = re.search(r"\bstatus=([a-z_-]+)\b", proof, re.IGNORECASE)
    return bool(
        sid_match
        and status_match
        and _stable_twilio_account_sid(sid_match.group(1))
        and _stable_twilio_account_status(status_match.group(1))
    )


def _slack_auth_proof_is_stable(proof: str) -> bool:
    actor_match = re.search(r"\b(?:actor_id|user_id|bot_id)=([a-z0-9]+)\b", proof, re.IGNORECASE)
    team_match = re.search(r"\bteam_id=([a-z0-9]+)\b", proof, re.IGNORECASE)
    actor_id = (
        _stable_slack_identifier(actor_match.group(1), ("U", "W", "B"))
        if actor_match
        else ""
    )
    team_id = _stable_slack_identifier(team_match.group(1), ("T", "E")) if team_match else ""
    return bool(actor_id and team_id)


def _azure_shared_key_proof_is_stable(proof: str) -> bool:
    account_match = re.search(r"\baccount=([a-z0-9]{3,24})\b", proof, re.IGNORECASE)
    containers_match = re.search(r"\bcontainers=([0-9]+)\b", proof, re.IGNORECASE)
    if not account_match or not containers_match or int(containers_match.group(1)) <= 0:
        return False
    return bool(_stable_provider_identifier(account_match.group(1)))


def _legacy_cloud_read_proof_is_stable(method: str, proof: str) -> bool:
    normalized_method = str(method or "").strip().lower()
    normalized_proof = str(proof or "").strip().lower()
    if normalized_method not in _LEGACY_CLOUD_READ_METHODS_REQUIRING_PROOF:
        return False
    if not normalized_proof:
        return False
    if any(marker in normalized_proof for marker in _LOW_SIGNAL_CLOUD_READ_PROOF_MARKERS):
        return False
    if normalized_method.startswith("firebase_"):
        return (
            "confirmed live child-node data" in normalized_proof
            or "project reference responded with non-empty data" in normalized_proof
            or "live records observed" in normalized_proof
        )
    if normalized_method == "supabase_rest_root":
        return (
            "supabase rest endpoint returned live data" in normalized_proof
            or "live records observed" in normalized_proof
        )
    return False


def _cloudflare_token_proof_is_stable(proof: str) -> bool:
    match = re.search(
        r"cloudflare token valid:\s*token_id=([a-z0-9_-]{8,32})\b",
        proof,
        re.IGNORECASE,
    )
    if not match or not re.search(r"\bstatus=active\b", proof, re.IGNORECASE):
        return False
    return bool(_stable_provider_identifier(match.group(1)))


def _profile_user_proof_is_stable(
    proof: str,
    *,
    label: str,
    uuid: bool = False,
) -> bool:
    match = re.search(
        rf"{re.escape(label)}:\s*user_id=([a-z0-9_-]{{3,128}})\b",
        proof,
        re.IGNORECASE,
    )
    if not match or not re.search(r"\buser_profile_present=true\b", proof, re.IGNORECASE):
        return False
    if uuid:
        return bool(_stable_uuid_or_32hex(match.group(1)))
    return bool(_stable_provider_identifier(match.group(1)))


def _posthog_user_proof_is_stable(proof: str) -> bool:
    match = re.search(
        r"posthog users me ok:\s*host=([a-z0-9.-]+)\s+user_id=([a-z0-9_-]{3,128})\b",
        proof,
        re.IGNORECASE,
    )
    if not match or not re.search(r"\buser_profile_present=true\b", proof, re.IGNORECASE):
        return False
    host = match.group(1).lower()
    return host in _POSTHOG_VALIDATION_HOSTS and bool(_stable_provider_identifier(match.group(2)))


def _sentry_org_proof_is_stable(proof: str) -> bool:
    match = re.search(
        r"sentry organizations ok:\s*org_id=([0-9]{3,32})\b",
        proof,
        re.IGNORECASE,
    )
    if not match:
        return False
    if not re.search(r"\borg_slug_present=true\b", proof, re.IGNORECASE):
        return False
    if not re.search(r"\borg_slug_stable=true\b", proof, re.IGNORECASE):
        return False
    hash_match = re.search(r"\borg_slug_hash=([a-f0-9]{16,64})\b", proof, re.IGNORECASE)
    if not hash_match or _looks_repeated_compact_identifier(hash_match.group(1)):
        return False
    return bool(_stable_numeric_identifier(match.group(1)))


def _validated_proof_is_reportable(method: str, proof: str) -> bool:
    normalized_method = str(method or "").strip().lower()
    if normalized_method in _AWS_STS_METHODS:
        return _aws_sts_proof_has_stable_account_id(proof)
    if normalized_method == "github_user_api":
        return _github_user_proof_is_stable(proof)
    if normalized_method == "gitlab_current_user_api":
        return _gitlab_user_proof_is_stable(proof)
    if normalized_method == "google_generative_language_models_list":
        return _model_list_proof_is_stable(
            proof,
            label="Google Generative Language models ok",
            require_models_prefix=True,
            provider_family="google",
        )
    if normalized_method == "openai_models_list":
        return _model_list_proof_is_stable(
            proof,
            label="OpenAI models ok",
            provider_family="openai",
        )
    if normalized_method == "anthropic_models_list":
        return _model_list_proof_is_stable(
            proof,
            label="Anthropic models ok",
            provider_family="anthropic",
        )
    if normalized_method == "huggingface_whoami_v2":
        return _huggingface_user_proof_is_stable(proof)
    if normalized_method == "discord_current_user":
        return _bot_numeric_proof_is_stable(
            proof,
            label="Discord bot auth ok",
            min_len=15,
            max_len=22,
        )
    if normalized_method == "telegram_get_me":
        return _bot_numeric_proof_is_stable(
            proof,
            label="Telegram bot auth ok",
            min_len=6,
            max_len=20,
        )
    if normalized_method == "datadog_api_key_validate":
        return _datadog_site_proof_is_stable(proof)
    if normalized_method == "cloudflare_token_verify":
        return _cloudflare_token_proof_is_stable(proof)
    if normalized_method == "vercel_user_get":
        return _profile_user_proof_is_stable(proof, label="Vercel user ok")
    if normalized_method == "netlify_current_user":
        return _profile_user_proof_is_stable(proof, label="Netlify user ok")
    if normalized_method == "notion_users_me":
        return _profile_user_proof_is_stable(proof, label="Notion users me ok", uuid=True)
    if normalized_method == "posthog_users_me":
        return _posthog_user_proof_is_stable(proof)
    if normalized_method == "sentry_list_organizations":
        return _sentry_org_proof_is_stable(proof)
    if normalized_method == "sendgrid_profile_api":
        return _sendgrid_proof_is_stable(proof)
    if normalized_method == "stripe_balance_api":
        return _stripe_balance_proof_is_stable(proof)
    if normalized_method == "twilio_account_api":
        return _twilio_account_proof_is_stable(proof)
    if normalized_method == "mailchimp_ping_api":
        return _mailchimp_ping_proof_is_stable(proof)
    if normalized_method == "slack_auth_test":
        return _slack_auth_proof_is_stable(proof)
    if normalized_method == "azure_blob_list_containers_shared_key":
        return _azure_shared_key_proof_is_stable(proof)
    if normalized_method in {"s3_list_bucket", "do_spaces_list_bucket"}:
        return _cloud_object_listing_proof_is_stable(
            proof,
            xml_tag="Key",
            markers=("<listbucketresult",),
        )
    if normalized_method == "gcs_list_bucket":
        return _cloud_object_listing_proof_is_stable(
            proof,
            xml_tag="Key",
            markers=("<listbucketresult", '"items"', '"kind"', "storage#objects"),
            allow_gcs_json=True,
        )
    if normalized_method == "azure_blob_list_container":
        return _cloud_object_listing_proof_is_stable(
            proof,
            xml_tag="Name",
            markers=("<enumerationresults", "<blobs"),
        )
    if normalized_method in _LEGACY_CLOUD_READ_METHODS_REQUIRING_PROOF:
        return _legacy_cloud_read_proof_is_stable(normalized_method, proof)
    return False


def parse_validated_detail(value: object, *, proof_limit: int = 280) -> dict[str, Any]:
    """Parse ``VALIDATED:<method>:<proof>`` detail into safe structured fields.

    Key scanner rows and deterministic findings historically persisted provider
    proof in free-form detail/evidence strings. Keeping this parser read-only
    lets dashboards and reports expose validation method/proof without changing
    old database schemas.
    """

    text = str(value or "").strip()
    match = _VALIDATED_DETAIL_RE.search(text)
    if not match:
        return _empty_proof()

    method = str(match.group(1) or "").strip()
    proof = str(match.group(2) or "").strip()[:proof_limit]
    if not _validated_proof_is_reportable(method, proof):
        return {
            "validation_status": "UNVERIFIED",
            "validation_method": method,
            "validation_proof": "",
        }
    return {
        "validation_status": "VALIDATED",
        "validation_method": method,
        "validation_proof": proof,
    }
