from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse


_CACHE_LABEL_SUFFIXES = {".amplify-client-config", ".aws-exports"}
_CLIENT_NAMES = {
    "aws-exports.js",
    "aws-exports.ts",
    "aws-exports.mjs",
    "aws-exports.cjs",
    "amplifyconfiguration.json",
    "amplifyconfiguration.yaml",
    "amplifyconfiguration.yml",
    "amplify_outputs.json",
    "amplify_outputs.yaml",
    "amplify_outputs.yml",
}
_PAIR_RE = re.compile(
    r"""["']?(?P<key>[A-Za-z_][A-Za-z0-9_\-]*)["']?\s*(?::|=)\s*(?P<quote>["'])(?P<value>[^"']{1,1024})(?P=quote)"""
)
_APPSYNC_HOST_RE = re.compile(
    r"^(?P<api_id>[a-z0-9]{8,32})\.appsync-api\.(?P<region>[a-z0-9-]+)\.amazonaws\.com$",
    re.IGNORECASE,
)
_USER_POOL_KEYS = ("awsuserpoolsid", "userpoolid", "cognitouserpooldefaultpoolid")
_IDENTITY_POOL_KEYS = ("awscognitoidentitypoolid", "identitypoolid", "cognitoidentitydefaultpoolid")
_APP_CLIENT_KEYS = ("awsuserpoolswebclientid", "userpoolclientid", "appclientid", "cognitouserpooldefaultappclientid")
_URL_KEYS = (
    "awsappsyncgraphqlendpoint",
    "appsyncgraphqlendpoint",
    "graphqlendpoint",
    "dataurl",
    "dataendpoint",
    "oauthwebdomain",
    "webdomain",
)
_BUCKET_KEYS = ("awsuserfiless3bucket", "s3bucket", "s3bucketname", "storagebucketname")
_PINPOINT_KEYS = ("awsmobileanalyticsappid", "pinpointappid", "analyticsappid", "appId")
_STRONG_PREFIXES = ("aws", "cognito", "appsync", "amplify")
_CONTEXT_PREFIXES = ("auth", "data", "analytics")


def amplify_client_config_artifact_label(value: str) -> str:
    name = Path(str(value or "").strip().replace("\\", "/")).name.lower()
    if name in _CLIENT_NAMES or any(name.endswith(suffix) for suffix in _CACHE_LABEL_SUFFIXES):
        return "amplify-client-config"
    return ""


def amplify_client_config_text_candidates(text: str) -> list[str]:
    pairs = [
        (match.start(), _fingerprint(match.group("key")), str(match.group("value") or "").strip())
        for match in _PAIR_RE.finditer(str(text or ""))
    ]
    return _candidate_values(pairs)


def amplify_client_config_candidates(document: Any, *, source_hint: str = "") -> list[str]:
    pairs: list[tuple[int, str, str]] = []

    def walk(value: Any, path: tuple[str, ...] = ()) -> None:
        if isinstance(value, Mapping):
            for raw_key, child in value.items():
                child_path = (*path, _fingerprint(raw_key))
                if isinstance(child, (str, int, float)):
                    pairs.append((len(pairs), "".join(child_path), str(child).strip()))
                walk(child, child_path)
            return
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            for item in list(value)[:256]:
                walk(item, path)

    walk(document)
    return _candidate_values(pairs, trusted=bool(amplify_client_config_artifact_label(source_hint)))


def _candidate_values(pairs: list[tuple[int, str, str]], *, trusted: bool = False) -> list[str]:
    has_amplify_context = bool(pairs) and _looks_like_amplify_pairs(pairs, trusted=trusted)
    if not has_amplify_context:
        return []
    region = _segment(_first(pairs, "awsprojectregion", "awscognitoregion", "awsregion", "region"))
    user_pool = _segment(_first(pairs, *_USER_POOL_KEYS))
    app_client = _segment(_first(pairs, *_APP_CLIENT_KEYS))
    pinpoint_app = _segment(_first(pairs, *_PINPOINT_KEYS))
    candidates: list[str] = []
    seen: set[str] = set()

    def append(value: str) -> None:
        candidate = str(value or "").strip().strip("\"'")
        if candidate and candidate.lower() not in seen:
            seen.add(candidate.lower())
            candidates.append(candidate)

    for _index, key, value in sorted(pairs, key=lambda item: item[0]):
        normalized = str(value or "").strip()
        if not normalized or any(marker in normalized for marker in ("{{", "}}")):
            continue
        if _key_matches(key, *_USER_POOL_KEYS):
            if pool := _segment(normalized):
                append(f"aws-cognito-user-pool://{pool}")
        elif _key_matches(key, *_IDENTITY_POOL_KEYS):
            if pool := _segment(normalized):
                append(f"aws-cognito-identity-pool://{pool}")
        elif _key_matches(key, *_URL_KEYS):
            for candidate in _url_candidates(normalized):
                append(candidate)
                if appsync_ref := _appsync_ref(candidate):
                    append(appsync_ref)
        elif _key_matches(key, *_BUCKET_KEYS) and has_amplify_context:
            if bucket := _bucket_name(normalized):
                append(f"s3://{bucket}")
    if app_client:
        append(f"aws-cognito-app-client://{user_pool}/{app_client}" if user_pool else f"aws-cognito-app-client://{app_client}")
    if pinpoint_app:
        append(f"aws-pinpoint-app://{_segment(region)}/{pinpoint_app}" if region else f"aws-pinpoint-app://{pinpoint_app}")
    return candidates


def _looks_like_amplify_pairs(pairs: list[tuple[int, str, str]], *, trusted: bool = False) -> bool:
    return trusted or any(_strong_identity_or_api_key(key) for _index, key, _value in pairs)


def _strong_identity_or_api_key(key: str) -> bool:
    normalized = _fingerprint(key)
    keys = (*_USER_POOL_KEYS, *_IDENTITY_POOL_KEYS, *_APP_CLIENT_KEYS, *_URL_KEYS, *_PINPOINT_KEYS)
    if normalized.startswith(_STRONG_PREFIXES):
        return _key_matches(normalized, *keys)
    if normalized.startswith(_CONTEXT_PREFIXES):
        return _key_matches(normalized, "userpoolid", "userpoolclientid", "identitypoolid", *_URL_KEYS, *_PINPOINT_KEYS)
    return False


def _first(pairs: list[tuple[int, str, str]], *keys: str) -> str:
    for _index, key, value in sorted(pairs, key=lambda item: item[0]):
        if value and _key_matches(key, *keys):
            return value
    return ""


def _key_matches(key: str, *candidates: str) -> bool:
    normalized = _fingerprint(key)
    wanted = {_fingerprint(candidate) for candidate in candidates}
    return normalized in wanted or any(normalized.endswith(candidate) for candidate in wanted)


def _url_candidates(value: str) -> list[str]:
    raw = str(value or "").strip().strip("\"'")
    if not raw or any(marker in raw for marker in ("${", "$(", "{{", "}}", "<", ">")):
        return []
    if raw.startswith("//"):
        raw = f"https:{raw}"
    if "://" not in raw and "." in raw:
        raw = f"https://{raw}"
    parsed = urlparse(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return []
    try:
        netloc = f"{parsed.hostname.lower()}:{parsed.port}" if parsed.port else parsed.hostname.lower()
    except ValueError:
        return []
    return [urlunparse((parsed.scheme.lower(), netloc, parsed.path or "", "", "", ""))]


def _appsync_ref(value: str) -> str:
    match = _APPSYNC_HOST_RE.fullmatch(str(urlparse(str(value or "").strip()).hostname or "").lower())
    if not match:
        return ""
    return f"aws-appsync-api://{match.group('region').lower()}/{match.group('api_id').lower()}"


def _bucket_name(value: str) -> str:
    candidate = str(value or "").strip().strip("\"'").lower()
    return candidate if re.fullmatch(r"[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]", candidate) else ""


def _segment(value: str) -> str:
    text = str(value or "").strip().strip("\"'").strip("/")
    return "" if not text or len(text) > 512 or re.search(r"\s|{{|}}", text) else text


def _fingerprint(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value or "").strip().lower())
