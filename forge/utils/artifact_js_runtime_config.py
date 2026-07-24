from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from pathlib import Path


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
_ENV_ASSIGNMENT_PATTERN = re.compile(
    r"""
    (?<![A-Za-z0-9_$])
    ["']?(?P<key>[A-Z][A-Z0-9_]{1,120})["']?
    \s*(?::|=)\s*
    (?P<quote>["'])(?P<value>[^"'\r\n]+)(?P=quote)
    """,
    re.VERBOSE,
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
