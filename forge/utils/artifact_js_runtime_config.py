from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from pathlib import Path
from urllib.parse import urljoin, urlparse


_RUNTIME_JS_CONFIG_EXACT_NAMES = frozenset(
    {
        "env-config.cjs",
        "env-config.js",
        "env-config.mjs",
        "env-config.ts",
        "runtime-config.cjs",
        "runtime-config.js",
        "runtime-config.mjs",
        "runtime-config.ts",
        "runtime-env.cjs",
        "runtime-env.js",
        "runtime-env.mjs",
        "runtime-env.ts",
    }
)
_RUNTIME_JS_CONFIG_PUBLIC_PARTS = frozenset(
    {
        "app",
        "assets",
        "build",
        "dist",
        "frontend",
        "public",
        "public_html",
        "static",
        "web",
        "www",
        "wwwroot",
    }
)
_SERVICE_WORKER_JS_EXACT_NAMES = frozenset(
    {
        "firebase-messaging-sw.js",
        "onesignalsdkupdaterworker.js",
        "onesignalsdkworker.js",
    }
)
_SERVICE_WORKER_JS_NAME_PATTERNS = (
    re.compile(r"service-worker(?:[._-][a-z0-9][a-z0-9._-]*)?\.(?:cjs|js|mjs)$"),
    re.compile(r"workbox(?:[._-][a-z0-9][a-z0-9._-]*)?\.(?:cjs|js|mjs)$"),
    re.compile(r"precache-manifest(?:[._-][a-z0-9][a-z0-9._-]*)?\.(?:cjs|js|mjs)$"),
)
_ENV_ASSIGNMENT_PATTERN = re.compile(
    r"""
    (?<![A-Za-z0-9_$])
    ["']?(?P<key>[A-Z][A-Z0-9_]{1,120})["']?
    \s*(?::|=)\s*
    (?P<quote>["'])(?P<value>[^"'\r\n]+)(?P=quote)
    """,
    re.VERBOSE,
)
_IMPORT_SCRIPTS_PATTERN = re.compile(
    r"\bimportScripts\s*\((?P<body>[^)]{0,3000})\)",
    re.IGNORECASE | re.DOTALL,
)
_QUOTED_IMPORT_SCRIPT_VALUE_PATTERN = re.compile(
    r"""(?P<quote>["'])(?P<value>[^"'\s,)]+)(?P=quote)""",
    re.IGNORECASE,
)
_FIREBASE_PROJECT_ASSIGNMENT_PATTERN = re.compile(
    r"""
    ["']?
    (?P<key>
        FIREBASE_PROJECT_ID|firebaseProjectId|firebase_project_id|
        projectId|project_id
    )
    ["']?
    \s*(?::|=)\s*
    (?P<quote>["'])(?P<value>[a-z0-9][a-z0-9-]{1,80})(?P=quote)
    """,
    re.IGNORECASE | re.VERBOSE,
)


def runtime_js_config_artifact_label(value: str) -> str:
    normalized = str(value or "").strip().replace("\\", "/").strip("/").lower()
    if not normalized:
        return ""
    parts = tuple(part for part in normalized.split("/") if part)
    name = Path(normalized).name
    if name in _RUNTIME_JS_CONFIG_EXACT_NAMES:
        return "runtime-js-config"
    if name in {"config.cjs", "config.js", "config.mjs"} and any(
        part in _RUNTIME_JS_CONFIG_PUBLIC_PARTS for part in parts[:-1]
    ):
        return "runtime-js-config"
    if name in _SERVICE_WORKER_JS_EXACT_NAMES or any(
        pattern.fullmatch(name) for pattern in _SERVICE_WORKER_JS_NAME_PATTERNS
    ):
        return "service-worker-js"
    return ""


def runtime_js_env_assignment_entries(
    text: str,
    *,
    derived_candidates: Callable[[dict[str, str]], Iterable[str]],
) -> list[tuple[int, str]]:
    raw_text = str(text or "")
    env_map: dict[str, str] = {}
    entries: list[tuple[int, str]] = []
    for match in _ENV_ASSIGNMENT_PATTERN.finditer(raw_text):
        key = str(match.group("key") or "").strip().upper()
        value = str(match.group("value") or "").strip()
        if not value or not _env_key_is_recursive_candidate(key):
            continue
        env_map[key] = value
        if _env_key_has_direct_endpoint(key):
            entries.append((match.start("value"), value))

    entries.extend(
        (len(raw_text) + index, candidate)
        for index, candidate in enumerate(derived_candidates(env_map))
        if candidate
    )
    return entries


def service_worker_js_candidate_entries(
    text: str,
    *,
    derived_candidates: Callable[[dict[str, str]], Iterable[str]],
    base_url: str = "",
) -> list[tuple[int, str]]:
    raw_text = str(text or "")
    entries: list[tuple[int, str]] = []

    for import_match in _IMPORT_SCRIPTS_PATTERN.finditer(raw_text):
        body = str(import_match.group("body") or "")
        body_offset = import_match.start("body")
        entries.extend(
            (body_offset + value_match.start("value"), resolved)
            for value_match in _QUOTED_IMPORT_SCRIPT_VALUE_PATTERN.finditer(body)
            if (
                resolved := _resolve_import_script_url(
                    str(value_match.group("value") or "").strip(),
                    base_url=base_url,
                )
            )
        )

    for project_match in _FIREBASE_PROJECT_ASSIGNMENT_PATTERN.finditer(raw_text):
        project_id = str(project_match.group("value") or "").strip().lower()
        if not project_id:
            continue
        derived = derived_candidates({"FIREBASE_PROJECT_ID": project_id})
        entries.extend(
            (project_match.start("value") + index, candidate)
            for index, candidate in enumerate(derived)
            if candidate
        )

    return entries


def _resolve_import_script_url(value: str, *, base_url: str = "") -> str:
    raw_value = str(value or "").strip()
    if not raw_value:
        return ""
    parsed = urlparse(raw_value)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        return raw_value
    if parsed.scheme or raw_value.startswith(("#", "//")):
        return ""
    parsed_base = urlparse(str(base_url or "").strip())
    if parsed_base.scheme not in {"http", "https"} or not parsed_base.netloc:
        return ""
    resolved = urljoin(parsed_base.geturl(), raw_value)
    resolved_parts = urlparse(resolved)
    if resolved_parts.scheme not in {"http", "https"} or not resolved_parts.netloc:
        return ""
    return resolved


def _env_key_is_recursive_candidate(key: str) -> bool:
    upper_key = str(key or "").strip().upper()
    if not upper_key:
        return False
    return any(
        marker in upper_key
        for marker in (
            "AMPLIFY",
            "AZURE_BLOB",
            "AZURE_STORAGE",
            "BASE",
            "BUCKET",
            "CLOUDFLARE",
            "DIGITALOCEAN_SPACES",
            "DOMAIN",
            "DO_SPACES",
            "ENDPOINT",
            "FIREBASE",
            "GCS",
            "GOOGLE_STORAGE",
            "HEROKU",
            "HOST",
            "HOSTNAME",
            "NETLIFY",
            "S3",
            "SANITY",
            "SUPABASE",
            "URI",
            "URL",
            "VERCEL",
        )
    )


def _env_key_has_direct_endpoint(key: str) -> bool:
    upper_key = str(key or "").strip().upper()
    if not upper_key:
        return False
    if any(marker in upper_key for marker in ("AUTH", "KEY", "PASSWORD", "SECRET", "TOKEN")):
        return False
    return any(
        marker in upper_key
        for marker in (
            "DOMAIN",
            "ENDPOINT",
            "HOST",
            "HOSTNAME",
            "URI",
            "URL",
        )
    ) or upper_key in {"API_BASE", "BASE"}
