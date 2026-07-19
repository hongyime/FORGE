"""
forge/phase4/cloud_validate.py
Deterministic, non-intrusive cloud validation framework.

This module validates discovered cloud references without attempting
destructive access. It only performs low-impact reachability and
structure checks, then records an explicit validation status for later
report gating.
"""
from __future__ import annotations

import base64
import json
import logging
import os
import re
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable
from urllib.parse import quote, urlparse

import httpx

from forge.db.migrations import run_migrations
from forge.db.schema import apply_schema
from forge.deterministic_findings import DeterministicFindingEngine
from forge.phase4.validation_claims import (
    claim_pending_cloud_asset_rows,
    claim_pending_cloud_key_rows,
    release_validation_asset_claims,
    release_validation_key_claims,
)
from forge.utils.intel.http_pacing import key_validation_get, key_validation_head

_LOG = logging.getLogger(__name__)

_VALID_STATUSES = {
    "UNVALIDATED",
    "VALIDATED",
    "ACCESSIBLE_BUT_NO_DATA",
    "UNVERIFIED",
    "DEAD",
    "HONEYPOT_SUSPECTED",
    "UNSUPPORTED",
}

_CLOUD_SECRET_BACKED_SERVICES = (
    "firebase",
    "supabase",
    "s3",
    "aws_s3",
    "do_spaces",
    "digitalocean_spaces",
    "gcs",
    "google_cloud_storage",
    "azure_blob",
    "azure_blob_storage",
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


def _validation_max_workers_default() -> int:
    """Default live validation batches to one scoped probe at a time."""
    return _int_env(
        "FORGE_VALIDATION_MAX_WORKERS",
        1,
        minimum=1,
        maximum=4,
    )


def _resolve_validation_max_workers(max_workers: int | None) -> int:
    if max_workers is None:
        return _validation_max_workers_default()
    try:
        parsed = int(max_workers or 1)
    except (TypeError, ValueError):
        return _validation_max_workers_default()
    return max(1, min(parsed, 4))


_UUID_OR_32_HEX_RE = re.compile(
    r"(?:[0-9a-f]{32}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
    re.IGNORECASE,
)
_PLACEHOLDER_IDENTIFIERS = {
    "unknown",
    "none",
    "null",
    "undefined",
    "na",
    "n_a",
}
_MODEL_PLACEHOLDER_IDENTIFIERS = _PLACEHOLDER_IDENTIFIERS | {
    "demo",
    "example",
    "model",
    "models",
    "placeholder",
    "sample",
    "test",
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
_OPAQUE_PROVIDER_PLACEHOLDER_IDENTIFIERS = _PLACEHOLDER_IDENTIFIERS | {
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
    "org",
    "organization",
    "placeholder",
    "profile",
    "project",
    "sample",
    "service",
    "test",
    "token",
    "user",
    "users",
    "workspace",
}
_OPAQUE_PROVIDER_PLACEHOLDER_TOKENS = _PLACEHOLDER_IDENTIFIERS | {
    "demo",
    "example",
    "placeholder",
    "sample",
    "test",
}
_POSTHOG_VALIDATION_HOSTS = {"us.posthog.com", "eu.posthog.com"}


def _stable_mailchimp_datacenter(value: object) -> str | None:
    candidate = str(value or "").strip().lower()
    if not re.fullmatch(r"us[0-9]{1,2}", candidate):
        return None
    return candidate


def _stable_mailchimp_health_status(value: object) -> str | None:
    health = str(value or "").strip()
    compact = re.sub(r"[^a-z0-9]+", "", health.lower())
    if compact != "everythingschimpy":
        return None
    return health


def _looks_repeated_compact_identifier(value: object) -> bool:
    compact = re.sub(r"[^A-Za-z0-9]+", "", str(value or "").strip()).lower()
    return bool(compact) and len(set(compact)) == 1


def _looks_prefixed_repeated_identifier(value: object) -> bool:
    """Reject proof IDs where only a static provider prefix prevents repetition."""
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


def _stable_uuid_or_32hex(value: object) -> str:
    candidate = str(value or "").strip().lower()
    if not _UUID_OR_32_HEX_RE.fullmatch(candidate):
        return ""
    if _looks_repeated_compact_identifier(candidate):
        return ""
    if _has_sequential_numeric_identifier_token(candidate):
        return ""
    return candidate


def _stable_provider_identifier(value: object) -> str | None:
    candidate = re.sub(r"[^A-Za-z0-9_-]+", "", str(value or "").strip())
    if not re.fullmatch(r"[A-Za-z0-9_-]{3,128}", candidate):
        return None
    if candidate.lower() in _OPAQUE_PROVIDER_PLACEHOLDER_IDENTIFIERS:
        return None
    if _has_placeholder_identifier_token(candidate):
        return None
    if _looks_repeated_compact_identifier(candidate):
        return None
    if _looks_prefixed_repeated_identifier(candidate):
        return None
    if _has_sequential_numeric_identifier_token(candidate):
        return None
    return candidate


def _stable_numeric_identifier(value: object, *, min_len: int = 3, max_len: int = 32) -> str | None:
    candidate = re.sub(r"[^0-9]+", "", str(value or "").strip())
    if not re.fullmatch(rf"[0-9]{{{min_len},{max_len}}}", candidate):
        return None
    if len(set(candidate)) == 1:
        return None
    if _looks_sequential_numeric_identifier(candidate):
        return None
    return candidate


def _looks_sequential_numeric_identifier(value: object) -> bool:
    candidate = re.sub(r"[^0-9]+", "", str(value or "").strip())
    if len(candidate) < 6:
        return False
    digits = [int(char) for char in candidate]
    ascending = all((right - left) % 10 == 1 for left, right in zip(digits, digits[1:]))
    descending = all((left - right) % 10 == 1 for left, right in zip(digits, digits[1:]))
    return ascending or descending


def _stable_twilio_account_sid(value: object) -> str | None:
    candidate = str(value or "").strip()
    if not re.fullmatch(r"AC[a-f0-9]{32}", candidate, re.IGNORECASE):
        return None
    sid_body = candidate[2:].lower()
    if len(set(sid_body)) == 1:
        return None
    return candidate


def _stable_twilio_account_status(value: object) -> str | None:
    candidate = str(value or "").strip().lower()
    if candidate != "active":
        return None
    return candidate


def _stable_azure_storage_account_name(value: object) -> str | None:
    candidate = str(value or "").strip().lower()
    if not re.fullmatch(r"[a-z0-9]{3,24}", candidate):
        return None
    if candidate in _OPAQUE_PROVIDER_PLACEHOLDER_IDENTIFIERS:
        return None
    if _looks_repeated_compact_identifier(candidate):
        return None
    return candidate


def _stable_stripe_currency_summary(value: object) -> str | None:
    tokens = [
        str(token or "").strip().lower()
        for token in str(value or "").split(",")
        if str(token or "").strip()
    ]
    if not tokens:
        return None
    stable_tokens: list[str] = []
    seen: set[str] = set()
    for token in tokens:
        currency = re.sub(r"[^a-z]+", "", token)
        if not re.fullmatch(r"[a-z]{3}", currency):
            return None
        if currency in _OPAQUE_PROVIDER_PLACEHOLDER_IDENTIFIERS:
            return None
        if _looks_repeated_compact_identifier(currency):
            return None
        if currency not in seen:
            seen.add(currency)
            stable_tokens.append(currency)
    return ",".join(stable_tokens) if stable_tokens else None


def _stable_handle_identifier(value: object, *, allow_dot: bool = True) -> str | None:
    allowed = r"[^A-Za-z0-9_.-]+" if allow_dot else r"[^A-Za-z0-9-]+"
    candidate = re.sub(allowed, "", str(value or "").strip())
    if not candidate or not re.search(r"[A-Za-z0-9]", candidate):
        return None
    if candidate.lower() in _OPAQUE_PROVIDER_PLACEHOLDER_IDENTIFIERS:
        return None
    if _has_placeholder_identifier_token(candidate):
        return None
    compact = re.sub(r"[^A-Za-z0-9]+", "", candidate)
    if len(compact) >= 3 and _looks_repeated_compact_identifier(compact):
        return None
    return candidate


def _stable_model_identifier(
    value: object,
    *,
    require_models_prefix: bool = False,
    provider_family: str | None = None,
) -> str | None:
    candidate = re.sub(r"[^A-Za-z0-9_./:-]+", "", str(value or "").strip())
    if not candidate:
        return None
    tail = candidate
    if require_models_prefix:
        if not candidate.startswith("models/"):
            return None
        tail = candidate.split("/", 1)[1]
    compact = re.sub(r"[^A-Za-z0-9]+", "", tail).lower()
    if len(compact) < 3 or compact in _MODEL_PLACEHOLDER_IDENTIFIERS:
        return None
    if _looks_repeated_compact_identifier(compact):
        return None
    if not re.search(r"[A-Za-z]", compact):
        return None
    family = str(provider_family or "").strip().lower()
    family_value = tail if require_models_prefix else candidate
    if family == "openai" and not _OPENAI_MODEL_FAMILY_RE.match(family_value):
        return None
    if family == "anthropic" and not _ANTHROPIC_MODEL_FAMILY_RE.match(family_value):
        return None
    if family == "google" and not _GOOGLE_MODEL_FAMILY_RE.match(family_value):
        return None
    return candidate[:80]


def _stable_model_sample_from_detail(
    text: str,
    *,
    require_models_prefix: bool = False,
    provider_family: str | None = None,
) -> str | None:
    match = re.search(r"\bsample=([A-Za-z0-9_./:,-]+)", str(text or ""), re.IGNORECASE)
    if not match:
        return None
    for value in str(match.group(1) or "").split(","):
        model_id = _stable_model_identifier(
            value,
            require_models_prefix=require_models_prefix,
            provider_family=provider_family,
        )
        if model_id:
            return model_id
    return None


def _stable_slack_identifier(value: object, prefixes: tuple[str, ...]) -> str | None:
    candidate = re.sub(r"[^A-Za-z0-9]+", "", str(value or "").strip())
    lowered = candidate.lower()
    if not candidate or lowered in _PLACEHOLDER_IDENTIFIERS:
        return None
    normalized = candidate.upper()
    prefix = next((item.upper() for item in prefixes if normalized.startswith(item.upper())), "")
    if not prefix or not re.fullmatch(rf"{prefix}[A-Z0-9]{{5,32}}", normalized):
        return None
    suffix = normalized[len(prefix):]
    if len(set(suffix)) == 1:
        return None
    if suffix.isdigit() and _looks_sequential_numeric_identifier(suffix):
        return None
    return normalized.lower()


@dataclass
class CloudValidationResult:
    asset_type: str
    identifier: str
    validation_status: str
    validation_method: str
    http_status: int | None = None
    evidence: str = ""
    notes: str = ""
    provider_identifier: str = ""

    def to_api_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["provider_identifier"] = self.provider_identifier or self.identifier
        payload["status"] = "success"
        return payload


class BaseCloudValidator:
    asset_type: str = "unknown"

    def validate(self, identifier: str, secret: str | None = None) -> CloudValidationResult:
        raise NotImplementedError

    @staticmethod
    def _parse_json_payload(text: str) -> Any | None:
        try:
            return json.loads(text)
        except Exception:  # noqa: BLE001
            return None

    @staticmethod
    def _looks_synthetic(text: str) -> bool:
        lowered = text.lower()
        suspicious_markers = (
            "dummy",
            "sample",
            "lorem",
            "test data",
            "synthetic",
            "honeypot",
            "placeholder",
            "changeme",
            "example.com",
            "example.net",
            "example.org",
            "example.test",
            "example.invalid",
            "localhost",
            "127.0.0.1",
        )
        repeated = sum(lowered.count(marker) for marker in suspicious_markers)
        if repeated >= 2:
            return True
        return BaseCloudValidator._looks_synthetic_json_payload(text)

    @staticmethod
    def _response_text(response: Any) -> str:
        try:
            return str(getattr(response, "text", "") or "")
        except Exception:  # noqa: BLE001
            return ""

    @staticmethod
    def _looks_html_document(text: str) -> bool:
        lowered = str(text or "").strip().lower()
        if not lowered:
            return False
        return (
            lowered.startswith("<!doctype html")
            or lowered.startswith("<html")
            or "<html" in lowered[:256]
            or "<body" in lowered[:256]
        )

    @staticmethod
    def _looks_like_json_payload(text: str) -> bool:
        return BaseCloudValidator._parse_json_payload(text) is not None

    @staticmethod
    def _xml_root_tag(text: str) -> str:
        match = re.search(r"<\??([A-Za-z0-9:_-]+)", str(text or "").lstrip())
        if not match:
            return ""
        return match.group(1).lower()

    @staticmethod
    def _structured_error_summary(text: str) -> str:
        raw = str(text or "").strip()
        if not raw:
            return ""
        try:
            payload = json.loads(raw)
        except Exception:  # noqa: BLE001
            payload = None
        if payload is not None:
            fragments = BaseCloudValidator._json_error_fragments(payload)
            if fragments:
                return " ".join(fragments[:6]).strip()
        root_tag = BaseCloudValidator._xml_root_tag(raw)
        if root_tag == "error" or "<error" in raw.lower():
            fragments: list[str] = []
            for tag_name in ("Code", "Message", "Detail", "Details", "Reason"):
                fragments.extend(BaseCloudValidator._extract_xml_tag_values(raw, tag_name))
            if fragments:
                return " ".join(fragments[:6]).strip()
            return "error"
        return ""

    @staticmethod
    def _json_error_fragments(value: Any) -> list[str]:
        error_keys = {
            "error",
            "error_code",
            "error_description",
            "message",
            "detail",
            "details",
            "reason",
            "hint",
            "code",
            "status",
            "statuscode",
            "errorcode",
        }

        fragments: list[str] = []

        def _walk(node: Any) -> None:
            if isinstance(node, dict):
                for key, item in node.items():
                    key_text = str(key or "").strip().lower()
                    if key_text in error_keys:
                        if isinstance(item, (dict, list)):
                            fragments.extend(BaseCloudValidator._json_scalar_values(item))
                        else:
                            value_text = str(item or "").strip()
                            if value_text:
                                fragments.append(value_text)
                    if isinstance(item, (dict, list)):
                        _walk(item)
                return
            if isinstance(node, list):
                for item in node:
                    _walk(item)

        _walk(value)
        cleaned: list[str] = []
        seen: set[str] = set()
        for fragment in fragments:
            text_value = str(fragment or "").strip()
            lowered = text_value.lower()
            if not text_value or lowered in seen:
                continue
            seen.add(lowered)
            cleaned.append(text_value)
        return cleaned

    @staticmethod
    def _classify_structured_error_payload(
        text: str,
        *,
        auth_status: str = "UNVERIFIED",
    ) -> tuple[str, str] | None:
        summary = BaseCloudValidator._structured_error_summary(text)
        if not summary:
            return None
        lowered = summary.lower()
        not_found_markers = (
            "not found",
            "does not exist",
            "no such bucket",
            "nosuchbucket",
            "containernotfound",
            "bucket not found",
            "project not found",
            "resource not found",
        )
        auth_markers = (
            "permission denied",
            "permission_denied",
            "access denied",
            "accessdenied",
            "forbidden",
            "unauthorized",
            "authorization",
            "authentication",
            "missing apikey",
            "missing api key",
            "missing authorization",
            "invalid jwt",
            "jwt expired",
            "row level security",
            "rls",
            "public access not permitted",
            "insufficient permissions",
        )
        generic_error_markers = (
            "error",
            "invalid",
            "failed",
            "exception",
            "bad request",
            "unsupported",
        )
        if any(marker in lowered for marker in not_found_markers):
            return (
                "DEAD",
                f"Structured error payload indicated the resource was not found. Summary: {summary}",
            )
        if any(marker in lowered for marker in auth_markers):
            return (
                auth_status,
                f"Structured error payload indicated access was denied rather than exposing live data. Summary: {summary}",
            )
        if any(marker in lowered for marker in generic_error_markers):
            return (
                "UNVERIFIED",
                f"Structured error payload was returned instead of live data. Summary: {summary}",
            )
        return None

    @staticmethod
    def _looks_synthetic_json_payload(text: str) -> bool:
        payload = BaseCloudValidator._parse_json_payload(text)
        if payload is None:
            return False
        scalars = BaseCloudValidator._json_scalar_values(payload)
        normalized = [value.strip().lower() for value in scalars if value.strip()]
        if len(normalized) < 2:
            return False

        placeholder_markers = (
            "dummy",
            "sample",
            "example",
            "localhost",
            "127.0.0.1",
            "placeholder",
            "changeme",
            "synthetic",
            "honeypot",
            "demo",
        )
        placeholder_hits = sum(
            1
            for value in normalized
            if any(marker in value for marker in placeholder_markers)
        )
        unique_values = set(normalized)
        if placeholder_hits >= 2:
            return True
        if len(unique_values) <= 2 and len(normalized) >= 4:
            return True
        if all(
            value in {"true", "false", "null", "none", "0"}
            or any(marker in value for marker in placeholder_markers)
            for value in normalized
        ):
            return True
        return False

    @staticmethod
    def _json_scalar_values(value: Any) -> list[str]:
        scalars: list[str] = []
        if isinstance(value, dict):
            for item in value.values():
                scalars.extend(BaseCloudValidator._json_scalar_values(item))
            return scalars
        if isinstance(value, list):
            for item in value:
                scalars.extend(BaseCloudValidator._json_scalar_values(item))
            return scalars
        if value is None:
            scalars.append("null")
        elif isinstance(value, bool):
            scalars.append("true" if value else "false")
        else:
            scalars.append(str(value))
        return scalars

    @staticmethod
    def _extract_xml_tag_values(text: str, tag_name: str) -> list[str]:
        pattern = rf"<{re.escape(tag_name)}>([^<]+)</{re.escape(tag_name)}>"
        return [
            match.group(1).strip()
            for match in re.finditer(pattern, text, re.IGNORECASE)
            if match.group(1).strip()
        ]

    @staticmethod
    def _looks_synthetic_name_listing(values: list[str]) -> bool:
        if not values:
            return False
        suspicious_markers = (
            "dummy",
            "sample",
            "test",
            "synthetic",
            "honeypot",
            "placeholder",
            "changeme",
            "example",
            "lorem",
        )
        normalized = [value.strip().lower() for value in values if value.strip()]
        marker_hits = sum(
            1
            for value in normalized
            if any(marker in value for marker in suspicious_markers)
        )
        if len(normalized) == 1:
            value = normalized[0]
            single_object_markers = (
                "dummy",
                "sample",
                "test-data",
                "test_data",
                "synthetic",
                "honeypot",
                "placeholder",
                "changeme",
                "example.com",
                "example.org",
                "lorem",
            )
            return any(marker in value for marker in single_object_markers)
        unique_values = set(normalized)
        return marker_hits >= 2 or (len(unique_values) <= 2 and len(normalized) >= 4)

    @staticmethod
    def _is_non_meaningful_object_name(value: str) -> bool:
        raw = str(value or "").strip()
        if not raw:
            return True
        if raw.endswith("/"):
            return True
        normalized = raw.rstrip("/").rsplit("/", 1)[-1].strip().lower()
        if not normalized:
            return True
        placeholder_names = {
            ".empty",
            ".gitkeep",
            ".keep",
            ".placeholder",
            "keep",
            "placeholder.txt",
            "readme",
            "readme.md",
            "readme.txt",
            "license",
            "license.md",
            "license.txt",
            "todo",
            "todo.txt",
        }
        return (
            normalized in placeholder_names
            or BaseCloudValidator._is_common_static_site_object_name(raw)
            or BaseCloudValidator._is_common_repository_metadata_object_name(raw)
            or BaseCloudValidator._is_common_filesystem_metadata_object_name(raw)
            or BaseCloudValidator._is_common_api_documentation_object_name(raw)
        )

    @staticmethod
    def _is_common_filesystem_metadata_object_name(value: str) -> bool:
        raw = str(value or "").strip().lower().rstrip("/")
        if not raw:
            return False
        normalized = raw.rsplit("/", 1)[-1].strip()
        filesystem_metadata_names = {
            ".ds_store",
            ".fseventsd",
            ".localized",
            ".spotlight-v100",
            ".trashes",
            "desktop.ini",
            "ehthumbs.db",
            "thumbs.db",
        }
        if normalized in filesystem_metadata_names:
            return True
        if normalized.startswith("._") and len(normalized) > 2:
            return True
        system_prefixes = (
            "__macosx/",
            ".fseventsd/",
            ".spotlight-v100/",
            ".trashes/",
        )
        return any(raw.startswith(prefix) for prefix in system_prefixes)

    @staticmethod
    def _is_common_repository_metadata_object_name(value: str) -> bool:
        raw = str(value or "").strip().lower().rstrip("/")
        if not raw:
            return False
        normalized = raw.rsplit("/", 1)[-1].strip()
        metadata_names = {
            ".dockerignore",
            ".editorconfig",
            ".eslintignore",
            ".eslintrc",
            ".eslintrc.json",
            ".gitattributes",
            ".gitignore",
            ".go-version",
            ".java-version",
            ".jenv-version",
            ".lua-version",
            ".node-version",
            ".nvmrc",
            ".npmignore",
            ".php-version",
            ".prettierignore",
            ".prettierrc",
            ".prettierrc.json",
            ".python-version",
            ".ruby-gemset",
            ".ruby-version",
            ".sdkmanrc",
            ".terraform-version",
            ".terragrunt-version",
            ".tofu-version",
            ".tool-versions",
            "chart.lock",
            "chart.yaml",
            "chart.yml",
            "authors",
            "authors.md",
            "authors.txt",
            "cargo.lock",
            "cargo.toml",
            "changelog",
            "changelog.md",
            "changelog.txt",
            "changes.md",
            "code_of_conduct.md",
            "codeowners",
            "composer.json",
            "composer.lock",
            "contributing.md",
            "contributors",
            "contributors.md",
            "copying",
            "gemfile",
            "gemfile.lock",
            "go.mod",
            "go.sum",
            "gradle.lockfile",
            "history.md",
            "helmfile.yaml",
            "helmfile.yml",
            "kptfile",
            "kptfile.yaml",
            "kptfile.yml",
            "kustomization.yaml",
            "kustomization.yml",
            "license",
            "license.md",
            "license.txt",
            "notice",
            "notice.txt",
            "npm-shrinkwrap.json",
            "package-lock.json",
            "package.json",
            "babel.config.js",
            "babel.config.json",
            "babel.config.mjs",
            "eslint.config.cjs",
            "eslint.config.js",
            "eslint.config.mjs",
            "jest.config.cjs",
            "jest.config.js",
            "jest.config.mjs",
            "next.config.js",
            "next.config.mjs",
            "postcss.config.cjs",
            "postcss.config.js",
            "postcss.config.mjs",
            "pdm.lock",
            "pipfile",
            "pipfile.lock",
            "pnpm-lock.yaml",
            "poetry.lock",
            "pom.xml",
            "pyproject.toml",
            "readme",
            "readme.md",
            "readme.txt",
            "release-notes.md",
            "requirements.txt",
            "rollup.config.js",
            "rollup.config.mjs",
            "security.md",
            "setup.cfg",
            "setup.py",
            "settings.gradle",
            "skaffold.yaml",
            "skaffold.yml",
            "tailwind.config.cjs",
            "tailwind.config.js",
            "tailwind.config.mjs",
            "tsconfig.json",
            "vite.config.js",
            "vite.config.mjs",
            "vitest.config.js",
            "vitest.config.mjs",
            "webpack.config.js",
            "yarn.lock",
        }
        if normalized in metadata_names:
            return True
        metadata_patterns = (
            re.compile(r"^requirements[-_][\w.-]+\.txt$", re.IGNORECASE),
            re.compile(r"^[\w.-]+\.gemspec$", re.IGNORECASE),
            re.compile(r"^[\w.-]+\.nuspec$", re.IGNORECASE),
            re.compile(r"^build\.gradle(?:\.kts)?$", re.IGNORECASE),
            re.compile(r"^settings\.gradle(?:\.kts)?$", re.IGNORECASE),
            re.compile(r"^tsconfig[\w.-]*\.json$", re.IGNORECASE),
            re.compile(r"^(?:vite|vitest|next|nuxt|astro|svelte|tailwind|postcss|babel|jest|webpack|rollup)\.config\.[cm]?[jt]s$", re.IGNORECASE),
        )
        return any(pattern.fullmatch(normalized) for pattern in metadata_patterns)

    @staticmethod
    def _is_common_api_documentation_object_name(value: str) -> bool:
        raw = str(value or "").strip().lower().rstrip("/")
        if not raw:
            return False
        normalized = raw.rsplit("/", 1)[-1].strip()
        api_doc_names = {
            "api-docs.html",
            "api-reference.html",
            "asyncapi.json",
            "asyncapi.yaml",
            "asyncapi.yml",
            "graphql-introspection.json",
            "graphql-schema.json",
            "graphql-voyager.html",
            "introspection.json",
            "openapi.json",
            "openapi.yaml",
            "openapi.yml",
            "redoc.html",
            "redoc-static.html",
            "schema.gql",
            "schema.graphql",
            "service.wadl",
            "service.wsdl",
            "swagger.json",
            "swagger.yaml",
            "swagger.yml",
            "swagger-ui-bundle.js",
            "swagger-ui-standalone-preset.js",
            "swagger-ui.css",
        }
        if normalized in api_doc_names:
            return True
        api_doc_patterns = (
            re.compile(r"^[\w.-]+\.postman_collection\.json$", re.IGNORECASE),
            re.compile(r"^(?:openapi|swagger|asyncapi)[-_.]v?\d+(?:[-_.]\d+)?\.(?:json|ya?ml)$", re.IGNORECASE),
            re.compile(r"^(?:graphql[-_.])?(?:schema|introspection)\.(?:gql|graphql|json)$", re.IGNORECASE),
            re.compile(r"^(?:redoc|swagger-ui)(?:[-_.][\w.-]+)?\.(?:css|html|js|map|png|svg)$", re.IGNORECASE),
            re.compile(r"^[\w.-]+\.(?:wadl|wsdl)$", re.IGNORECASE),
        )
        if any(pattern.fullmatch(normalized) for pattern in api_doc_patterns):
            return True
        api_doc_prefixes = (
            "api-docs/",
            "docs/api/",
            "docs/graphql/",
            "docs/openapi/",
            "graphql/",
            "openapi/",
            "redoc/",
            "swagger/",
            "swagger-ui/",
        )
        if not any(raw.startswith(prefix) for prefix in api_doc_prefixes):
            return False
        return normalized in api_doc_names or any(
            pattern.fullmatch(normalized) for pattern in api_doc_patterns
        )

    @staticmethod
    def _is_common_static_site_object_name(value: str) -> bool:
        raw = str(value or "").strip().lower().rstrip("/")
        if not raw:
            return False
        normalized = raw.rsplit("/", 1)[-1].strip()
        static_site_names = {
            ".nojekyll",
            "_headers",
            "_redirects",
            "_routes.json",
            "_worker",
            "_worker.js",
            "_worker.mjs",
            "200.html",
            "404.html",
            "about.html",
            "app-ads.txt",
            "ads.txt",
            "ai-plugin.json",
            "ai.txt",
            "apple-developer-merchantid-domain-association",
            "apple-app-site-association",
            "app-build-manifest.json",
            "assetlinks.json",
            "apple-touch-icon.png",
            "asset-manifest.json",
            "build-manifest.json",
            "browserconfig.xml",
            "change-password",
            "crossdomain.xml",
            "did.json",
            "atom.xml",
            "bingsiteauth.xml",
            "favicon.ico",
            "favicon-16x16.png",
            "favicon-32x32.png",
            "favicon.png",
            "facebook-domain-verification.html",
            "feed.xml",
            "first-party-set.json",
            "fly.toml",
            "cname",
            "contact.html",
            "cookie-policy.html",
            "cookies.html",
            "firebase.json",
            "apphosting.yaml",
            "apphosting.yml",
            "host-meta",
            "host-meta.json",
            "heroku-app.json",
            "heroku.yml",
            "heroku.yaml",
            "humans.txt",
            "index.htm",
            "index.html",
            "jwks.json",
            "llms.txt",
            "manifest",
            "manifest.json",
            "manifest.webmanifest",
            "middleware-manifest.json",
            "mta-sts.txt",
            "netlify.toml",
            "nodeinfo",
            "oauth-authorization-server",
            "oauth-protected-resource",
            "openid-configuration",
            "openid-federation",
            "prerender-manifest.json",
            "privacy-policy.html",
            "privacy.html",
            "react-loadable-manifest.json",
            "related-website-set.json",
            "robots.txt",
            "render.yaml",
            "render.yml",
            "railway.json",
            "railway.toml",
            "railway.yaml",
            "railway.yml",
            "routes-manifest.json",
            "rss.xml",
            "safari-pinned-tab.svg",
            "security.txt",
            "server-reference-manifest.json",
            "sellers.json",
            "service-worker.js",
            "ssg-manifest.json",
            "site.webmanifest",
            "sitemap.xml",
            "sitemap_index.xml",
            "staticwebapp.config.json",
            "static.json",
            "sw.js",
            "terms-of-service.html",
            "terms.html",
            "uma2-configuration",
            "vercel.json",
            "vite-manifest.json",
            "vite.svg",
            "wrangler.json",
            "wrangler.jsonc",
            "wrangler.toml",
        }
        if normalized in static_site_names:
            return True

        static_prefixes = (
            "_next/static/",
            "_app/immutable/",
            "_astro/",
            "_nuxt/",
            "build/assets/",
            "dist/assets/",
            "static/js/",
            "static/css/",
            "static/media/",
            ".well-known/acme-challenge/",
            ".well-known/pki-validation/",
        )
        if any(raw.startswith(prefix) for prefix in static_prefixes):
            return True

        well_known_exact = {
            ".well-known/change-password",
            ".well-known/did.json",
            ".well-known/host-meta",
            ".well-known/host-meta.json",
            ".well-known/jwks.json",
            ".well-known/matrix/client",
            ".well-known/matrix/server",
            ".well-known/mta-sts.txt",
            ".well-known/nodeinfo",
            ".well-known/oauth-authorization-server",
            ".well-known/oauth-protected-resource",
            ".well-known/openid-configuration",
            ".well-known/openid-federation",
            ".well-known/related-website-set.json",
            ".well-known/first-party-set.json",
            ".well-known/uma2-configuration",
            ".well-known/webfinger",
        }
        if raw in well_known_exact:
            return True

        conventional_asset_prefixes = (
            "assets/",
            "css/",
            "fonts/",
            "font/",
            "images/",
            "img/",
            "js/",
            "media/",
            "chunks/",
            "public/assets/",
            "public/build/",
            "static/assets/",
            "static/chunks/",
        )
        if any(raw.startswith(prefix) for prefix in conventional_asset_prefixes) and re.fullmatch(
            r"[\w./-]+\.(?:avif|css|eot|gif|ico|jpeg|jpg|js|map|png|svg|ttf|webp|woff2?)$",
            raw,
            re.IGNORECASE,
        ):
            return True

        hashed_asset_patterns = (
            re.compile(
                r"^(?:index|app|main|vendor|chunk|runtime|polyfills|styles?|worker|sw)[-._][a-z0-9]{6,}\.(?:js|css|map)$",
                re.IGNORECASE,
            ),
            re.compile(r"^precache-manifest[\w.-]*\.js$", re.IGNORECASE),
            re.compile(r"^service-worker[\w.-]*\.js$", re.IGNORECASE),
            re.compile(r"^workbox-[\w.-]+\.js$", re.IGNORECASE),
        )
        if any(pattern.fullmatch(normalized) for pattern in hashed_asset_patterns):
            return True

        plain_asset_patterns = (
            re.compile(r"^(?:app|bundle|index|main|runtime|site|styles?|vendor|worker|sw)(?:[-._][\w-]+)?\.(?:js|css|map)$", re.IGNORECASE),
            re.compile(r"^(?:logo|icon|favicon|apple-touch-icon|android-chrome)(?:[-._]?\d+x\d+)?\.(?:png|jpg|jpeg|svg|webp|ico)$", re.IGNORECASE),
            re.compile(r"^(?:fontawesome|inter|roboto|opensans|lato|montserrat|poppins)[-._\w]*\.(?:woff2?|ttf|eot)$", re.IGNORECASE),
        )
        if any(pattern.fullmatch(normalized) for pattern in plain_asset_patterns):
            return True

        site_verification_patterns = (
            re.compile(r"^google[a-z0-9_-]{8,80}\.html$", re.IGNORECASE),
            re.compile(r"^yandex_[a-z0-9_-]{8,80}\.html$", re.IGNORECASE),
            re.compile(r"^baidu_verify_[a-z0-9_-]{6,80}\.html$", re.IGNORECASE),
            re.compile(r"^pinterest-[a-z0-9_-]{6,80}\.html$", re.IGNORECASE),
        )
        if any(pattern.fullmatch(normalized) for pattern in site_verification_patterns):
            return True

        generated_index_patterns = (
            re.compile(r"^(?:post|page|category|tag|author|news|video|image|product|wp)-sitemap(?:\d+)?\.xml$", re.IGNORECASE),
            re.compile(r"^sitemap(?:[-_]\d+|[-_][a-z0-9-]+)?\.xml$", re.IGNORECASE),
            re.compile(r"^(?:feed|rss|atom)(?:[-_][a-z0-9-]+)?\.xml$", re.IGNORECASE),
        )
        if any(pattern.fullmatch(normalized) for pattern in generated_index_patterns):
            return True

        icon_patterns = (
            re.compile(r"^(?:android-chrome|apple-touch-icon|mstile)-\d+x\d+\.(?:png|jpg|jpeg)$", re.IGNORECASE),
            re.compile(r"^apple-touch-icon(?:-precomposed)?\.(?:png|jpg|jpeg)$", re.IGNORECASE),
            re.compile(r"^logo\d{2,4}\.(?:png|jpg|jpeg|svg|webp)$", re.IGNORECASE),
        )
        if any(pattern.fullmatch(normalized) for pattern in icon_patterns):
            return True

        if raw.startswith("assets/") and re.fullmatch(
            r"(?:index|app|main|vendor|chunk|runtime|polyfills|styles?|worker|sw)[-._][a-z0-9]{6,}\.(?:js|css|map|png|svg|jpg|jpeg|webp|woff2?|ttf|eot)$",
            normalized,
            re.IGNORECASE,
        ):
            return True
        return False

    @staticmethod
    def _contains_common_static_site_objects(values: list[str]) -> bool:
        for value in values:
            candidate = str(value or "").strip()
            if BaseCloudValidator._is_common_static_site_object_name(candidate):
                return True
        return False

    @staticmethod
    def _contains_common_repository_metadata_objects(values: list[str]) -> bool:
        for value in values:
            candidate = str(value or "").strip()
            if BaseCloudValidator._is_common_repository_metadata_object_name(candidate):
                return True
        return False

    @staticmethod
    def _contains_common_filesystem_metadata_objects(values: list[str]) -> bool:
        for value in values:
            candidate = str(value or "").strip()
            if BaseCloudValidator._is_common_filesystem_metadata_object_name(candidate):
                return True
        return False

    @staticmethod
    def _contains_common_api_documentation_objects(values: list[str]) -> bool:
        for value in values:
            candidate = str(value or "").strip()
            if BaseCloudValidator._is_common_api_documentation_object_name(candidate):
                return True
        return False

    @staticmethod
    def _low_signal_object_listing_notes(resource_label: str, values: list[str]) -> str:
        notes = f"{resource_label} listing exposed only directory markers or placeholder objects."
        low_signal_kinds: list[str] = []
        if BaseCloudValidator._contains_common_static_site_objects(values):
            low_signal_kinds.append("common static-site assets")
        if BaseCloudValidator._contains_common_repository_metadata_objects(values):
            low_signal_kinds.append("common package/repository metadata or runtime metadata")
        if BaseCloudValidator._contains_common_filesystem_metadata_objects(values):
            low_signal_kinds.append("common filesystem metadata")
        if BaseCloudValidator._contains_common_api_documentation_objects(values):
            low_signal_kinds.append("common API documentation metadata")
        if low_signal_kinds:
            return (
                f"{resource_label} listing exposed only directory markers, placeholder objects, "
                f"or {' or '.join(low_signal_kinds)}."
            )
        return notes

    @staticmethod
    def _meaningful_object_names(values: list[str]) -> list[str]:
        meaningful: list[str] = []
        seen: set[str] = set()
        for value in values:
            candidate = str(value or "").strip()
            if not candidate or BaseCloudValidator._is_non_meaningful_object_name(candidate):
                continue
            if candidate in seen:
                continue
            seen.add(candidate)
            meaningful.append(candidate)
        return meaningful


class ManagedHostingReachabilityValidator(BaseCloudValidator):
    """Read-only reachability proof for managed hosting aliases.

    These validators intentionally never return VALIDATED. A reachable public
    hosting endpoint is useful review evidence, but it is not a data exposure.
    """

    def __init__(self, asset_type: str, host_suffix: str, *, require_qualified_identifier: bool = False) -> None:
        self.asset_type = asset_type
        self._host_suffix = host_suffix
        self._require_qualified_identifier = require_qualified_identifier

    def _target_url(self, identifier: str) -> str:
        raw = str(identifier or "").strip().lower().strip(".")
        if not raw:
            return ""
        if raw.startswith(("http://", "https://")):
            return raw
        if self._require_qualified_identifier and self._host_suffix not in raw:
            return ""
        if "/" in raw:
            return f"https://{raw}"
        if "." in raw:
            return f"https://{raw}"
        return f"https://{raw}.{self._host_suffix}"

    @staticmethod
    def _looks_like_placeholder_hosting_response(text: str) -> bool:
        lowered = str(text or "").lower()
        placeholder_markers = (
            "deployment not found",
            "site not found",
            "page not found",
            "not found",
            "no such app",
            "there's nothing here",
            "nothing here yet",
            "project not found",
        )
        return any(marker in lowered for marker in placeholder_markers)

    def validate(self, identifier: str, secret: str | None = None) -> CloudValidationResult:
        del secret
        url = self._target_url(identifier)
        normalized_identifier = str(identifier or "").strip().lower()
        if not url or not normalized_identifier:
            return CloudValidationResult(
                asset_type=self.asset_type,
                identifier=normalized_identifier,
                validation_status="UNSUPPORTED",
                validation_method=f"{self.asset_type}_http_reachability",
                notes="Managed hosting identifier is empty or unsupported.",
            )

        try:
            with httpx.Client(timeout=8.0, follow_redirects=True) as client:
                if hasattr(client, "head"):
                    resp = key_validation_head(client, url)
                    if int(getattr(resp, "status_code", 0) or 0) in {405, 501}:
                        resp = key_validation_get(client, url)
                else:
                    resp = key_validation_get(client, url)
        except httpx.RequestError as exc:
            return CloudValidationResult(
                asset_type=self.asset_type,
                identifier=normalized_identifier,
                validation_status="DEAD",
                validation_method=f"{self.asset_type}_http_reachability",
                evidence=url,
                notes=f"Managed hosting endpoint was unreachable: {type(exc).__name__}",
            )
        except Exception as exc:  # noqa: BLE001
            return CloudValidationResult(
                asset_type=self.asset_type,
                identifier=normalized_identifier,
                validation_status="UNVERIFIED",
                validation_method=f"{self.asset_type}_http_reachability",
                evidence=url,
                notes=f"Managed hosting reachability check failed: {type(exc).__name__}",
            )

        status_code = int(getattr(resp, "status_code", 0) or 0)
        body = self._response_text(resp)
        headers = getattr(resp, "headers", {}) or {}
        try:
            content_type = str(headers.get("content-type") or headers.get("Content-Type") or "").strip()
        except Exception:  # noqa: BLE001
            content_type = ""
        evidence = f"url={url} status={status_code} content_type={content_type}".strip()
        if status_code == 429:
            return CloudValidationResult(
                asset_type=self.asset_type,
                identifier=normalized_identifier,
                validation_status="UNVERIFIED",
                validation_method=f"{self.asset_type}_http_reachability",
                http_status=status_code,
                evidence=evidence,
                notes="Managed hosting endpoint rate limited validation.",
            )
        if status_code in {404, 410}:
            return CloudValidationResult(
                asset_type=self.asset_type,
                identifier=normalized_identifier,
                validation_status="DEAD",
                validation_method=f"{self.asset_type}_http_reachability",
                http_status=status_code,
                evidence=evidence,
                notes="Managed hosting endpoint returned not found.",
            )
        if self._looks_synthetic(body) or self._looks_like_placeholder_hosting_response(body):
            return CloudValidationResult(
                asset_type=self.asset_type,
                identifier=normalized_identifier,
                validation_status="UNVERIFIED",
                validation_method=f"{self.asset_type}_http_reachability",
                http_status=status_code,
                evidence=evidence,
                notes="Managed hosting endpoint returned placeholder or synthetic content.",
            )
        if 200 <= status_code < 400 or status_code in {401, 403}:
            return CloudValidationResult(
                asset_type=self.asset_type,
                identifier=normalized_identifier,
                validation_status="ACCESSIBLE_BUT_NO_DATA",
                validation_method=f"{self.asset_type}_http_reachability",
                http_status=status_code,
                evidence=evidence,
                notes="Managed hosting endpoint is reachable; no public data exposure was validated.",
            )
        if 500 <= status_code < 600:
            return CloudValidationResult(
                asset_type=self.asset_type,
                identifier=normalized_identifier,
                validation_status="UNVERIFIED",
                validation_method=f"{self.asset_type}_http_reachability",
                http_status=status_code,
                evidence=evidence,
                notes="Managed hosting endpoint returned a server error.",
            )
        return CloudValidationResult(
            asset_type=self.asset_type,
            identifier=normalized_identifier,
            validation_status="UNVERIFIED",
            validation_method=f"{self.asset_type}_http_reachability",
            http_status=status_code,
            evidence=evidence,
            notes="Managed hosting endpoint returned an inconclusive response.",
        )


class CloudflareR2ReachabilityValidator(ManagedHostingReachabilityValidator):
    """Read-only reachability proof for fully-qualified Cloudflare R2 hosts."""

    _ALLOWED_SUFFIXES = ("r2.dev", "r2.cloudflarestorage.com")
    _ROOT_HOSTS = frozenset(_ALLOWED_SUFFIXES)

    def __init__(self) -> None:
        super().__init__("cloudflare_r2", "r2.dev", require_qualified_identifier=True)

    def _target_url(self, identifier: str) -> str:
        raw = str(identifier or "").strip().lower().strip(".")
        if not raw:
            return ""
        parsed = urlparse(raw)
        if parsed.scheme in {"http", "https"} and parsed.netloc:
            host = str(parsed.hostname or "").strip().lower().strip(".")
            if host in self._ROOT_HOSTS or not any(
                host.endswith(f".{suffix}") for suffix in self._ALLOWED_SUFFIXES
            ):
                return ""
            return raw
        if "/" in raw:
            return ""
        host = raw
        if host in self._ROOT_HOSTS or not any(
            host.endswith(f".{suffix}") for suffix in self._ALLOWED_SUFFIXES
        ):
            return ""
        return f"https://{host}"


_AWS_REGION_PATTERN = r"[a-z]{2}(?:-gov)?-[a-z]+-\d"
_AWS_USER_POOL_RE = re.compile(rf"^(?P<region>{_AWS_REGION_PATTERN})_[A-Za-z0-9]+$")


class AwsCognitoUserPoolMetadataValidator(BaseCloudValidator):
    """Passive OIDC discovery check for Cognito user-pool references."""

    asset_type = "aws_cognito_user_pool"

    @staticmethod
    def _aws_domain(region: str) -> str:
        return "amazonaws.com.cn" if region.startswith("cn-") else "amazonaws.com"

    @classmethod
    def _split_pool_id(cls, identifier: str) -> tuple[str, str] | None:
        raw = str(identifier or "").strip()
        match = _AWS_USER_POOL_RE.fullmatch(raw)
        if not match:
            return None
        return match.group("region"), raw

    @classmethod
    def _validate_pool(
        cls,
        *,
        asset_type: str,
        identifier: str,
        method: str,
        evidence_prefix: str = "",
        notes_prefix: str = "",
    ) -> CloudValidationResult:
        normalized = str(identifier or "").strip().lower()
        parsed = cls._split_pool_id(identifier)
        if parsed is None:
            return CloudValidationResult(
                asset_type=asset_type,
                identifier=normalized,
                validation_status="UNSUPPORTED",
                validation_method=method,
                notes=f"{notes_prefix}Cognito user-pool ID format is unsupported.".strip(),
            )

        region, pool_id = parsed
        domain = cls._aws_domain(region)
        pool_path = quote(pool_id, safe="_-")
        url = f"https://cognito-idp.{region}.{domain}/{pool_path}/.well-known/openid-configuration"
        try:
            with httpx.Client(timeout=8.0, follow_redirects=False) as client:
                resp = key_validation_get(client, url)
        except httpx.RequestError as exc:
            return CloudValidationResult(
                asset_type=asset_type,
                identifier=normalized,
                validation_status="DEAD",
                validation_method=method,
                evidence=f"{evidence_prefix}url={url}".strip(),
                notes=f"{notes_prefix}Cognito OIDC discovery endpoint was unreachable: {type(exc).__name__}".strip(),
            )
        except Exception as exc:  # noqa: BLE001
            return CloudValidationResult(
                asset_type=asset_type,
                identifier=normalized,
                validation_status="UNVERIFIED",
                validation_method=method,
                evidence=f"{evidence_prefix}url={url}".strip(),
                notes=f"{notes_prefix}Cognito OIDC discovery check failed: {type(exc).__name__}".strip(),
            )

        status_code = int(getattr(resp, "status_code", 0) or 0)
        body = cls._response_text(resp)
        evidence = f"{evidence_prefix}url={url} status={status_code}".strip()
        if status_code in {404, 410}:
            return CloudValidationResult(
                asset_type=asset_type,
                identifier=normalized,
                validation_status="DEAD",
                validation_method=method,
                http_status=status_code,
                evidence=evidence,
                notes=f"{notes_prefix}Cognito user-pool discovery endpoint returned not found.".strip(),
            )
        if status_code == 429:
            return CloudValidationResult(
                asset_type=asset_type,
                identifier=normalized,
                validation_status="UNVERIFIED",
                validation_method=method,
                http_status=status_code,
                evidence=evidence,
                notes=f"{notes_prefix}Cognito user-pool discovery endpoint rate limited validation.".strip(),
            )
        if status_code != 200 or cls._looks_synthetic(body):
            return CloudValidationResult(
                asset_type=asset_type,
                identifier=normalized,
                validation_status="UNVERIFIED",
                validation_method=method,
                http_status=status_code,
                evidence=evidence,
                notes=f"{notes_prefix}Cognito user-pool discovery response was inconclusive.".strip(),
            )

        payload = cls._parse_json_payload(body)
        issuer = str(payload.get("issuer") or "").rstrip("/") if isinstance(payload, dict) else ""
        jwks_uri = str(payload.get("jwks_uri") or "") if isinstance(payload, dict) else ""
        expected = {
            f"https://cognito-idp.{region}.{domain}/{pool_id}",
            f"https://issuer-cognito-idp.{region}.{domain}/{pool_id}",
        }
        if issuer not in expected or not jwks_uri:
            return CloudValidationResult(
                asset_type=asset_type,
                identifier=normalized,
                validation_status="UNVERIFIED",
                validation_method=method,
                http_status=status_code,
                evidence=f"{evidence} issuer_present={bool(issuer)} jwks_uri_present={bool(jwks_uri)}",
                notes=f"{notes_prefix}Cognito discovery metadata did not match the expected issuer.".strip(),
            )
        return CloudValidationResult(
            asset_type=asset_type,
            identifier=normalized,
            validation_status="ACCESSIBLE_BUT_NO_DATA",
            validation_method=method,
            http_status=status_code,
            evidence=f"{evidence} issuer={issuer} jwks_uri_present=true",
            notes=f"{notes_prefix}Cognito OIDC metadata is reachable; no user data was accessed.".strip(),
        )

    def validate(self, identifier: str, secret: str | None = None) -> CloudValidationResult:
        del secret
        return self._validate_pool(
            asset_type=self.asset_type,
            identifier=identifier,
            method="aws_cognito_user_pool_oidc_discovery",
        )


class AwsCognitoAppClientMetadataValidator(BaseCloudValidator):
    """Validate app-client references only through associated user-pool metadata."""

    asset_type = "aws_cognito_app_client"
    _APP_CLIENT_RE = re.compile(r"^[A-Za-z0-9_-]+$")

    def validate(self, identifier: str, secret: str | None = None) -> CloudValidationResult:
        del secret
        raw = str(identifier or "").strip()
        normalized = raw.lower()
        if "/" not in raw:
            return CloudValidationResult(
                asset_type=self.asset_type,
                identifier=normalized,
                validation_status="UNSUPPORTED",
                validation_method="aws_cognito_app_client_user_pool_discovery",
                notes="Cognito app-client ID requires an associated user-pool ID for passive validation.",
            )
        pool_id, client_id = (part.strip() for part in raw.split("/", 1))
        if not pool_id or not client_id or not self._APP_CLIENT_RE.fullmatch(client_id):
            return CloudValidationResult(
                asset_type=self.asset_type,
                identifier=normalized,
                validation_status="UNSUPPORTED",
                validation_method="aws_cognito_app_client_user_pool_discovery",
                notes="Cognito app-client reference format is unsupported.",
            )
        return AwsCognitoUserPoolMetadataValidator._validate_pool(
            asset_type=self.asset_type,
            identifier=pool_id,
            method="aws_cognito_app_client_user_pool_discovery",
            evidence_prefix="app_client_id_present=true ",
            notes_prefix="Associated user-pool check: ",
        )


class AwsAppSyncApiReachabilityValidator(BaseCloudValidator):
    """Read-only reachability proof for AppSync GraphQL endpoint references."""

    asset_type = "aws_appsync_api"
    _HOST_RE = re.compile(
        rf"^(?P<api_id>[A-Za-z0-9_-]+)\.appsync-api\.(?P<region>{_AWS_REGION_PATTERN})\.amazonaws\.com(?:\.cn)?$"
    )
    _PATH_RE = re.compile(rf"^(?P<region>{_AWS_REGION_PATTERN})/(?P<api_id>[A-Za-z0-9_-]+)$")

    @staticmethod
    def _aws_domain(region: str) -> str:
        return "amazonaws.com.cn" if region.startswith("cn-") else "amazonaws.com"

    @classmethod
    def _split_target(cls, identifier: str) -> tuple[str, str] | None:
        raw = str(identifier or "").strip().rstrip("/")
        parsed = urlparse(raw)
        if parsed.scheme in {"http", "https"} and parsed.hostname:
            match = cls._HOST_RE.fullmatch(parsed.hostname.strip().lower())
            if match and parsed.path.rstrip("/") in {"", "/graphql"}:
                return match.group("region"), match.group("api_id")
            return None
        match = cls._PATH_RE.fullmatch(raw)
        if match:
            return match.group("region"), match.group("api_id")
        return None

    def validate(self, identifier: str, secret: str | None = None) -> CloudValidationResult:
        del secret
        normalized = str(identifier or "").strip().lower()
        parsed = self._split_target(identifier)
        if parsed is None:
            return CloudValidationResult(
                asset_type=self.asset_type,
                identifier=normalized,
                validation_status="UNSUPPORTED",
                validation_method="aws_appsync_graphql_endpoint_reachability",
                notes="AppSync API identifier format is unsupported.",
            )
        region, api_id = parsed
        url = f"https://{api_id}.appsync-api.{region}.{self._aws_domain(region)}/graphql"
        try:
            with httpx.Client(timeout=8.0, follow_redirects=False) as client:
                resp = key_validation_get(client, url)
        except httpx.RequestError as exc:
            return CloudValidationResult(
                asset_type=self.asset_type,
                identifier=normalized,
                validation_status="DEAD",
                validation_method="aws_appsync_graphql_endpoint_reachability",
                evidence=f"url={url}",
                notes=f"AppSync endpoint was unreachable: {type(exc).__name__}",
            )
        except Exception as exc:  # noqa: BLE001
            return CloudValidationResult(
                asset_type=self.asset_type,
                identifier=normalized,
                validation_status="UNVERIFIED",
                validation_method="aws_appsync_graphql_endpoint_reachability",
                evidence=f"url={url}",
                notes=f"AppSync reachability check failed: {type(exc).__name__}",
            )

        status_code = int(getattr(resp, "status_code", 0) or 0)
        body = self._response_text(resp)
        evidence = f"url={url} status={status_code}"
        if status_code in {404, 410}:
            return CloudValidationResult(
                asset_type=self.asset_type,
                identifier=normalized,
                validation_status="DEAD",
                validation_method="aws_appsync_graphql_endpoint_reachability",
                http_status=status_code,
                evidence=evidence,
                notes="AppSync endpoint returned not found.",
            )
        if status_code == 429 or 500 <= status_code < 600:
            return CloudValidationResult(
                asset_type=self.asset_type,
                identifier=normalized,
                validation_status="UNVERIFIED",
                validation_method="aws_appsync_graphql_endpoint_reachability",
                http_status=status_code,
                evidence=evidence,
                notes="AppSync endpoint validation was rate limited or inconclusive.",
            )
        if self._looks_synthetic(body):
            return CloudValidationResult(
                asset_type=self.asset_type,
                identifier=normalized,
                validation_status="UNVERIFIED",
                validation_method="aws_appsync_graphql_endpoint_reachability",
                http_status=status_code,
                evidence=evidence,
                notes="AppSync endpoint returned placeholder or synthetic content.",
            )
        if 200 <= status_code < 404:
            return CloudValidationResult(
                asset_type=self.asset_type,
                identifier=normalized,
                validation_status="ACCESSIBLE_BUT_NO_DATA",
                validation_method="aws_appsync_graphql_endpoint_reachability",
                http_status=status_code,
                evidence=evidence,
                notes="AppSync endpoint is reachable; no GraphQL query or data access was attempted.",
            )
        return CloudValidationResult(
            asset_type=self.asset_type,
            identifier=normalized,
            validation_status="UNVERIFIED",
            validation_method="aws_appsync_graphql_endpoint_reachability",
            http_status=status_code,
            evidence=evidence,
            notes="AppSync endpoint returned an inconclusive response.",
        )


class FirebaseValidator(BaseCloudValidator):
    asset_type = "firebase"

    @staticmethod
    def _firebase_low_signal_root_keys() -> set[str]:
        return {
            ".settings",
            "__health__",
            "__meta__",
            "__metadata__",
            "__status__",
            "config",
            "configs",
            "configuration",
            "firebase",
            "health",
            "meta",
            "metadata",
            "ok",
            "ping",
            "project",
            "project_id",
            "projectid",
            "rule",
            "rules",
            "settings",
            "status",
        }

    @staticmethod
    def _looks_firebase_shallow_metadata_only_payload(text: str) -> bool:
        payload = BaseCloudValidator._parse_json_payload(text)
        if not isinstance(payload, dict) or not payload:
            return False
        low_signal_keys = FirebaseValidator._firebase_low_signal_root_keys()
        normalized_keys = {
            str(key or "").strip().lower()
            for key in payload.keys()
            if str(key or "").strip()
        }
        if not normalized_keys:
            return False
        if not all(
            key in low_signal_keys or key.startswith((".", "__"))
            for key in normalized_keys
        ):
            return False
        return all(
            value in (None, "", [], {}, False, True, 0, 1)
            for value in payload.values()
        )

    @staticmethod
    def _extract_firebase_shallow_candidate_keys(text: str) -> list[str]:
        payload = BaseCloudValidator._parse_json_payload(text)
        if not isinstance(payload, dict) or not payload:
            return []
        low_signal_keys = FirebaseValidator._firebase_low_signal_root_keys()
        candidates: list[str] = []
        for key in payload.keys():
            key_text = str(key or "").strip()
            normalized = key_text.lower()
            if (
                not key_text
                or normalized in low_signal_keys
                or normalized.startswith((".", "__"))
            ):
                continue
            candidates.append(key_text)
        return candidates

    @staticmethod
    def _requires_firebase_child_probe(text: str) -> bool:
        payload = BaseCloudValidator._parse_json_payload(text)
        if not isinstance(payload, dict) or not payload:
            return False
        if FirebaseValidator._looks_firebase_shallow_metadata_only_payload(text):
            return False

        for value in payload.values():
            if isinstance(value, (dict, list)) and bool(value):
                return False
            if not isinstance(value, (dict, list)) and value not in (None, "", False, True, 0, 1):
                return False
        return True

    @staticmethod
    def _firebase_payload_confirms_live_data(text: str) -> bool:
        payload = BaseCloudValidator._parse_json_payload(text)
        if payload is None:
            return False
        if isinstance(payload, list):
            return any(item not in (None, "", [], {}, False) for item in payload)
        if isinstance(payload, dict):
            if not payload:
                return False
            if FirebaseValidator._looks_firebase_shallow_metadata_only_payload(text):
                return False
            if FirebaseValidator._requires_firebase_child_probe(text):
                return False
            return any(
                (
                    isinstance(value, (dict, list)) and bool(value)
                )
                or (
                    not isinstance(value, (dict, list))
                    and str(value).strip().lower() not in {"", "false", "none", "null"}
                )
                for value in payload.values()
            )
        return str(payload).strip().lower() not in {"", "false", "none", "null"}

    def validate(self, identifier: str, secret: str | None = None) -> CloudValidationResult:
        del secret
        endpoints = [
            (
                "firebase_init_json",
                f"https://{identifier}.firebaseapp.com/__/firebase/init.json",
                {},
            ),
            (
                "firebase_web_app_init_json",
                f"https://{identifier}.web.app/__/firebase/init.json",
                {},
            ),
            (
                "firebase_database_shallow_read",
                f"https://{identifier}.firebaseio.com/.json",
                {"params": {"shallow": "true"}},
            ),
        ]
        accessible_result: CloudValidationResult | None = None
        with httpx.Client(timeout=10, follow_redirects=True) as client:
            for method, url, kwargs in endpoints:
                try:
                    resp = key_validation_get(client, url, **kwargs)
                except httpx.HTTPError as exc:
                    last_error = str(exc)
                    continue
                body = resp.text[:512]
                if resp.status_code == 200:
                    if not self._looks_like_json_payload(body):
                        return CloudValidationResult(
                            asset_type=self.asset_type,
                            identifier=identifier,
                            validation_status="UNVERIFIED",
                            validation_method=method,
                            http_status=resp.status_code,
                            evidence=body,
                            notes="Firebase endpoint returned unexpected non-JSON content.",
                        )
                    structured_error = self._classify_structured_error_payload(body, auth_status="UNVERIFIED")
                    if structured_error is not None:
                        validation_status, notes = structured_error
                        return CloudValidationResult(
                            asset_type=self.asset_type,
                            identifier=identifier,
                            validation_status=validation_status,
                            validation_method=method,
                            http_status=resp.status_code,
                            evidence=body,
                            notes=notes,
                        )
                    if (
                        method == "firebase_database_shallow_read"
                        and self._looks_firebase_shallow_metadata_only_payload(body)
                    ):
                        return CloudValidationResult(
                            asset_type=self.asset_type,
                            identifier=identifier,
                            validation_status="ACCESSIBLE_BUT_NO_DATA",
                            validation_method=method,
                            http_status=resp.status_code,
                            evidence=body,
                            notes=(
                                "Firebase database shallow probe exposed only low-signal scaffold or "
                                "metadata-style keys, but no meaningful data categories were confirmed."
                            ),
                        )
                    if not (
                        method == "firebase_database_shallow_read"
                        and self._requires_firebase_child_probe(body)
                    ) and self._looks_synthetic(body):
                        return CloudValidationResult(
                            asset_type=self.asset_type,
                            identifier=identifier,
                            validation_status="HONEYPOT_SUSPECTED",
                            validation_method=method,
                            http_status=resp.status_code,
                            evidence=body,
                            notes="Response looked synthetic or decoy-like.",
                        )
                    stripped = body.strip()
                    if stripped in {"{}", "[]", "null", ""}:
                        result = CloudValidationResult(
                            asset_type=self.asset_type,
                            identifier=identifier,
                            validation_status="ACCESSIBLE_BUT_NO_DATA",
                            validation_method=method,
                            http_status=resp.status_code,
                            evidence=body,
                            notes="Resource responded but no meaningful data was returned.",
                        )
                        if method == "firebase_database_shallow_read":
                            return result
                        accessible_result = result
                        continue
                    if method == "firebase_database_shallow_read" and self._requires_firebase_child_probe(body):
                        child_keys = self._extract_firebase_shallow_candidate_keys(body)[:3]
                        for child_key in child_keys:
                            child_url = (
                                f"https://{identifier}.firebaseio.com/"
                                f"{quote(child_key, safe='')}.json"
                            )
                            try:
                                child_resp = key_validation_get(
                                    client,
                                    child_url,
                                    params={"orderBy": '"$key"', "limitToFirst": "1"},
                                )
                            except httpx.HTTPError:
                                continue
                            child_body = child_resp.text[:768]
                            if child_resp.status_code == 200:
                                if not self._looks_like_json_payload(child_body):
                                    return CloudValidationResult(
                                        asset_type=self.asset_type,
                                        identifier=identifier,
                                        validation_status="UNVERIFIED",
                                        validation_method="firebase_database_node_read",
                                        http_status=child_resp.status_code,
                                        evidence=child_body,
                                        notes=(
                                            "Firebase child-node probe returned unexpected non-JSON content "
                                            "after the shallow key probe."
                                        ),
                                    )
                                structured_error = self._classify_structured_error_payload(
                                    child_body,
                                    auth_status="UNVERIFIED",
                                )
                                if structured_error is not None:
                                    continue
                                if self._looks_synthetic(child_body):
                                    return CloudValidationResult(
                                        asset_type=self.asset_type,
                                        identifier=identifier,
                                        validation_status="HONEYPOT_SUSPECTED",
                                        validation_method="firebase_database_node_read",
                                        http_status=child_resp.status_code,
                                        evidence=child_body,
                                        notes="Child-node response looked synthetic or decoy-like.",
                                    )
                                if child_body.strip() in {"{}", "[]", "null", ""}:
                                    continue
                                if self._firebase_payload_confirms_live_data(child_body):
                                    return CloudValidationResult(
                                        asset_type=self.asset_type,
                                        identifier=identifier,
                                        validation_status="VALIDATED",
                                        validation_method="firebase_database_node_read",
                                        http_status=child_resp.status_code,
                                        evidence=child_body,
                                        notes=(
                                            "Firebase database probe confirmed live child-node data after "
                                            "the shallow key probe."
                                        ),
                                    )
                                continue
                            if child_resp.status_code in {401, 403, 404}:
                                continue
                            return CloudValidationResult(
                                asset_type=self.asset_type,
                                identifier=identifier,
                                validation_status="UNVERIFIED",
                                validation_method="firebase_database_node_read",
                                http_status=child_resp.status_code,
                                evidence=child_body,
                                notes="Unexpected response while validating a Firebase child-node probe.",
                            )
                        return CloudValidationResult(
                            asset_type=self.asset_type,
                            identifier=identifier,
                            validation_status="ACCESSIBLE_BUT_NO_DATA",
                            validation_method=method,
                            http_status=resp.status_code,
                            evidence=body,
                            notes=(
                                "Firebase shallow probe exposed only top-level keys or sentinel values, "
                                "but no live child-node data payload was confirmed."
                            ),
                        )
                    if method in {"firebase_init_json", "firebase_web_app_init_json"}:
                        if accessible_result is None:
                            accessible_result = CloudValidationResult(
                                asset_type=self.asset_type,
                                identifier=identifier,
                                validation_status="ACCESSIBLE_BUT_NO_DATA",
                                validation_method=method,
                                http_status=resp.status_code,
                                evidence=body,
                                notes="Public Firebase bootstrap metadata responded successfully, but no database access was confirmed.",
                            )
                        continue
                    if not self._firebase_payload_confirms_live_data(body):
                        return CloudValidationResult(
                            asset_type=self.asset_type,
                            identifier=identifier,
                            validation_status="ACCESSIBLE_BUT_NO_DATA",
                            validation_method=method,
                            http_status=resp.status_code,
                            evidence=body,
                            notes=(
                                "Firebase endpoint responded successfully, but no live database payload "
                                "was confirmed."
                            ),
                        )
                    return CloudValidationResult(
                        asset_type=self.asset_type,
                        identifier=identifier,
                        validation_status="VALIDATED",
                        validation_method=method,
                        http_status=resp.status_code,
                        evidence=body,
                        notes="Firebase project reference responded with non-empty data.",
                    )
                if resp.status_code in {401, 403}:
                    result = CloudValidationResult(
                        asset_type=self.asset_type,
                        identifier=identifier,
                        validation_status="ACCESSIBLE_BUT_NO_DATA",
                        validation_method=method,
                        http_status=resp.status_code,
                        evidence=body,
                        notes="Firebase resource exists but requires authentication.",
                    )
                    if method == "firebase_database_shallow_read":
                        return result
                    if accessible_result is None:
                        accessible_result = result
                    continue
                if resp.status_code == 404:
                    last_error = body or "not found"
                    continue
                return CloudValidationResult(
                    asset_type=self.asset_type,
                    identifier=identifier,
                    validation_status="UNVERIFIED",
                    validation_method=method,
                    http_status=resp.status_code,
                    evidence=body,
                    notes="Unexpected response while validating Firebase reference.",
                )
        if accessible_result is not None:
            return accessible_result
        return CloudValidationResult(
            asset_type=self.asset_type,
            identifier=identifier,
            validation_status="DEAD",
            validation_method="firebase_http_probe",
            evidence="",
            notes=last_error if "last_error" in locals() else "No reachable Firebase endpoint.",
        )


class SupabaseValidator(BaseCloudValidator):
    asset_type = "supabase"

    @staticmethod
    def _looks_supabase_rest_schema_payload(text: str) -> bool:
        payload = BaseCloudValidator._parse_json_payload(text)
        if not isinstance(payload, dict):
            return False
        keys = {
            str(key or "").strip().lower()
            for key in payload.keys()
            if str(key or "").strip()
        }
        if not keys:
            return False
        schema_keys = {
            "basepath",
            "components",
            "consumes",
            "definitions",
            "externaldocs",
            "host",
            "info",
            "openapi",
            "paths",
            "produces",
            "schemes",
            "security",
            "securitydefinitions",
            "servers",
            "swagger",
            "tags",
        }
        if "openapi" in keys or "swagger" in keys:
            return True
        if "paths" in keys and ("info" in keys or "components" in keys or "definitions" in keys):
            return True
        return keys.issubset(schema_keys)

    @staticmethod
    def _looks_supabase_rest_metadata_only_payload(text: str) -> bool:
        payload = BaseCloudValidator._parse_json_payload(text)
        if not isinstance(payload, dict):
            return False
        keys = {
            str(key or "").strip().lower()
            for key in payload.keys()
            if str(key or "").strip()
        }
        if not keys:
            return False
        metadata_keys = {
            "anon_key",
            "db_anon_role",
            "db_schema",
            "db_schemas",
            "disable_signup",
            "external_apple_enabled",
            "external_email_enabled",
            "external_phone_enabled",
            "jwt_aud",
            "jwt_exp",
            "mailer_autoconfirm",
            "password_min_length",
            "refresh_token_reuse_interval",
            "site_url",
            "sms_autoconfirm",
            "smtp_admin_email",
            "uri_allow_list",
        }
        return keys.issubset(metadata_keys)

    @staticmethod
    def _looks_supabase_rest_catalog_payload(text: str) -> bool:
        payload = BaseCloudValidator._parse_json_payload(text)
        if not isinstance(payload, list) or not payload:
            return False

        catalog_keys = {
            "comment",
            "description",
            "href",
            "id",
            "name",
            "path",
            "rel",
            "schema",
            "table",
            "table_name",
            "title",
            "type",
        }

        saw_catalog_shape = False
        for item in payload:
            if not isinstance(item, dict) or not item:
                return False
            keys = {
                str(key or "").strip().lower()
                for key in item.keys()
                if str(key or "").strip()
            }
            if not keys or not keys.issubset(catalog_keys):
                return False
            saw_catalog_shape = True
        return saw_catalog_shape

    @staticmethod
    def _looks_supabase_rest_synthetic_row_payload(text: str) -> bool:
        payload = BaseCloudValidator._parse_json_payload(text)
        if payload is None:
            return False
        if SupabaseValidator._looks_supabase_rest_schema_payload(text):
            return False
        if SupabaseValidator._looks_supabase_rest_metadata_only_payload(text):
            return False
        if SupabaseValidator._looks_supabase_rest_catalog_payload(text):
            return False
        if not isinstance(payload, (dict, list)):
            return False

        normalized = [
            value.strip().lower()
            for value in BaseCloudValidator._json_scalar_values(payload)
            if value.strip()
        ]
        if not normalized:
            return False
        signal_values = [
            value
            for value in normalized
            if not re.fullmatch(r"(?:true|false|null|none|-?\d+(?:\.\d+)?)", value)
        ]
        if not signal_values:
            return False

        synthetic_markers = (
            "dummy",
            "sample",
            "test",
            "synthetic",
            "honeypot",
            "placeholder",
            "changeme",
            "example.com",
            "example.net",
            "example.org",
            "example.test",
            "example.invalid",
            "localhost",
            "127.0.0.1",
            "john doe",
            "jane doe",
        )
        marker_hits = sum(
            1
            for value in signal_values
            if any(marker in value for marker in synthetic_markers)
        )
        if marker_hits == len(signal_values):
            return True
        if marker_hits >= 2 and marker_hits / max(1, len(signal_values)) >= 0.5:
            return True
        return len(signal_values) <= 2 and marker_hits >= 1 and any(
            marker in value
            for value in signal_values
            for marker in (
                "example.com",
                "example.net",
                "example.org",
                "example.test",
                "example.invalid",
                "localhost",
                "127.0.0.1",
                "honeypot",
            )
        )

    @staticmethod
    def _looks_supabase_rest_low_signal_row_payload(text: str) -> bool:
        payload = BaseCloudValidator._parse_json_payload(text)
        if payload is None:
            return False
        if SupabaseValidator._looks_supabase_rest_schema_payload(text):
            return False
        if SupabaseValidator._looks_supabase_rest_metadata_only_payload(text):
            return False
        if SupabaseValidator._looks_supabase_rest_catalog_payload(text):
            return False

        if isinstance(payload, dict):
            rows = [payload]
        elif isinstance(payload, list) and payload:
            if not all(isinstance(item, dict) for item in payload):
                return False
            rows = payload
        else:
            return False

        low_signal_keys = {
            "active",
            "archived",
            "count",
            "created",
            "created_at",
            "deleted",
            "deleted_at",
            "disabled",
            "enabled",
            "guid",
            "id",
            "inactive",
            "index",
            "inserted_at",
            "is_active",
            "is_archived",
            "is_deleted",
            "is_disabled",
            "is_enabled",
            "modified_at",
            "pk",
            "position",
            "rank",
            "ref",
            "rev",
            "revision",
            "row_id",
            "rowid",
            "sort_order",
            "state",
            "status",
            "timestamp",
            "total",
            "ts",
            "uid",
            "updated",
            "updated_at",
            "uuid",
            "version",
        }
        id_like_keys = {"guid", "id", "pk", "ref", "row_id", "rowid", "uid", "uuid"}
        high_signal_key_markers = (
            "account",
            "address",
            "api",
            "auth",
            "balance",
            "city",
            "client",
            "company",
            "credential",
            "customer",
            "domain",
            "email",
            "first",
            "host",
            "invoice",
            "key",
            "last",
            "login",
            "mail",
            "mobile",
            "name",
            "order",
            "password",
            "permission",
            "phone",
            "price",
            "role",
            "secret",
            "street",
            "token",
            "uri",
            "url",
            "user",
        )
        status_values = {
            "0",
            "1",
            "active",
            "archived",
            "closed",
            "deleted",
            "disabled",
            "draft",
            "enabled",
            "false",
            "inactive",
            "new",
            "none",
            "null",
            "ok",
            "open",
            "pending",
            "ready",
            "true",
            "unknown",
        }

        def _normalize_key(key: object) -> str:
            return re.sub(r"[^a-z0-9]+", "_", str(key or "").strip().lower()).strip("_")

        def _scalar_has_direct_data_signal(value: object) -> bool:
            value_text = str(value or "").strip()
            if not value_text:
                return False
            lowered = value_text.lower()
            if re.search(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", value_text, re.IGNORECASE):
                return True
            if "://" in lowered or lowered.startswith(("www.", "mailto:")):
                return True
            if re.fullmatch(r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?:[/:?#].*)?", value_text):
                return True
            if re.search(r"\b(?:sk|pk|sb|ghp|xox[baprs]|sg|api)[_-][A-Za-z0-9_-]{12,}\b", value_text):
                return True
            return False

        def _is_low_signal_scalar(key: str, value: object) -> bool:
            if value in (None, "", False, True):
                return True
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                return True
            if _scalar_has_direct_data_signal(value):
                return False
            value_text = str(value or "").strip()
            if not value_text:
                return True
            lowered = value_text.lower()
            if re.fullmatch(r"-?\d+(?:\.\d+)?", lowered):
                return True
            if re.fullmatch(
                r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
                lowered,
            ):
                return True
            if re.fullmatch(r"\d{4}-\d{2}-\d{2}(?:[t ][0-9:.+-]+z?)?", lowered):
                return True
            if key in id_like_keys and re.fullmatch(r"[a-z0-9][a-z0-9_.:-]{0,96}", lowered):
                return True
            if key in {"active", "archived", "disabled", "enabled", "inactive", "state", "status"}:
                return lowered in status_values
            return False

        saw_low_signal_field = False
        for row in rows:
            if not row:
                return False
            for key, value in row.items():
                normalized_key = _normalize_key(key)
                if not normalized_key:
                    continue
                if any(marker in normalized_key for marker in high_signal_key_markers):
                    return False
                if normalized_key not in low_signal_keys:
                    return False
                if isinstance(value, (dict, list)):
                    if value:
                        return False
                    saw_low_signal_field = True
                    continue
                if not _is_low_signal_scalar(normalized_key, value):
                    return False
                saw_low_signal_field = True
        return saw_low_signal_field

    @staticmethod
    def _supabase_rest_payload_confirms_data_access(text: str) -> bool:
        payload = BaseCloudValidator._parse_json_payload(text)
        if payload is None:
            return False
        if isinstance(payload, list):
            if SupabaseValidator._looks_supabase_rest_catalog_payload(text):
                return False
            if SupabaseValidator._looks_supabase_rest_low_signal_row_payload(text):
                return False
            return any(item not in (None, "", [], {}, False) for item in payload)
        if not isinstance(payload, dict):
            return bool(str(payload).strip())
        if not payload:
            return False
        if SupabaseValidator._looks_supabase_rest_schema_payload(text):
            return False
        if SupabaseValidator._looks_supabase_rest_metadata_only_payload(text):
            return False
        if SupabaseValidator._looks_supabase_rest_low_signal_row_payload(text):
            return False
        return any(
            (
                isinstance(value, (dict, list)) and bool(value)
            )
            or (
                not isinstance(value, (dict, list))
                and str(value).strip().lower() not in {"", "false", "none", "null"}
            )
            for value in payload.values()
        )

    def validate(self, identifier: str, secret: str | None = None) -> CloudValidationResult:
        headers = {"Accept": "application/json"}
        if secret:
            headers["apikey"] = secret
            headers["Authorization"] = f"Bearer {secret}"
        endpoints = [
            ("supabase_settings", f"https://{identifier}.supabase.co/auth/v1/settings"),
            ("supabase_rest_root", f"https://{identifier}.supabase.co/rest/v1/"),
        ]
        accessible_result: CloudValidationResult | None = None
        with httpx.Client(timeout=10, follow_redirects=True, headers=headers) as client:
            for method, url in endpoints:
                try:
                    resp = key_validation_get(client, url)
                except httpx.HTTPError as exc:
                    last_error = str(exc)
                    continue
                body = resp.text[:512]
                if resp.status_code == 200:
                    if not self._looks_like_json_payload(body):
                        return CloudValidationResult(
                            asset_type=self.asset_type,
                            identifier=identifier,
                            validation_status="UNVERIFIED",
                            validation_method=method,
                            http_status=resp.status_code,
                            evidence=body,
                            notes="Supabase endpoint returned unexpected non-JSON content.",
                        )
                    structured_error = self._classify_structured_error_payload(body, auth_status="UNVERIFIED")
                    if structured_error is not None:
                        validation_status, notes = structured_error
                        return CloudValidationResult(
                            asset_type=self.asset_type,
                            identifier=identifier,
                            validation_status=validation_status,
                            validation_method=method,
                            http_status=resp.status_code,
                            evidence=body,
                            notes=notes,
                        )
                    if self._looks_synthetic(body):
                        return CloudValidationResult(
                            asset_type=self.asset_type,
                            identifier=identifier,
                            validation_status="HONEYPOT_SUSPECTED",
                            validation_method=method,
                            http_status=resp.status_code,
                            evidence=body,
                            notes="Response looked synthetic or decoy-like.",
                        )
                    if method == "supabase_settings":
                        settings_note = (
                            "Supabase settings endpoint responded successfully, but settings metadata alone "
                            "does not confirm table access."
                        )
                        if accessible_result is None:
                            accessible_result = CloudValidationResult(
                                asset_type=self.asset_type,
                                identifier=identifier,
                                validation_status="ACCESSIBLE_BUT_NO_DATA",
                                validation_method=method,
                                http_status=resp.status_code,
                                evidence=body,
                                notes=settings_note,
                            )
                        continue
                    if self._looks_supabase_rest_schema_payload(body):
                        return CloudValidationResult(
                            asset_type=self.asset_type,
                            identifier=identifier,
                            validation_status="ACCESSIBLE_BUT_NO_DATA",
                            validation_method=method,
                            http_status=resp.status_code,
                            evidence=body,
                            notes=(
                                "Supabase REST endpoint returned OpenAPI or PostgREST schema metadata, "
                                "but no table data was confirmed."
                            ),
                        )
                    if self._looks_supabase_rest_metadata_only_payload(body):
                        return CloudValidationResult(
                            asset_type=self.asset_type,
                            identifier=identifier,
                            validation_status="ACCESSIBLE_BUT_NO_DATA",
                            validation_method=method,
                            http_status=resp.status_code,
                            evidence=body,
                            notes=(
                                "Supabase REST endpoint returned project metadata, "
                                "but no table data was confirmed."
                            ),
                        )
                    if self._looks_supabase_rest_catalog_payload(body):
                        return CloudValidationResult(
                            asset_type=self.asset_type,
                            identifier=identifier,
                            validation_status="ACCESSIBLE_BUT_NO_DATA",
                            validation_method=method,
                            http_status=resp.status_code,
                            evidence=body,
                            notes=(
                                "Supabase REST endpoint returned table or route catalog metadata, "
                                "but no row data was confirmed."
                            ),
                        )
                    if self._looks_supabase_rest_synthetic_row_payload(body):
                        return CloudValidationResult(
                            asset_type=self.asset_type,
                            identifier=identifier,
                            validation_status="HONEYPOT_SUSPECTED",
                            validation_method=method,
                            http_status=resp.status_code,
                            evidence=body,
                            notes="Supabase REST row payload looked synthetic or demo-only.",
                        )
                    if self._looks_supabase_rest_low_signal_row_payload(body):
                        return CloudValidationResult(
                            asset_type=self.asset_type,
                            identifier=identifier,
                            validation_status="ACCESSIBLE_BUT_NO_DATA",
                            validation_method=method,
                            http_status=resp.status_code,
                            evidence=body,
                            notes=(
                                "Supabase REST endpoint returned only low-signal row metadata, "
                                "but no reportable table data was confirmed."
                            ),
                        )
                    if not self._supabase_rest_payload_confirms_data_access(body):
                        return CloudValidationResult(
                            asset_type=self.asset_type,
                            identifier=identifier,
                            validation_status="ACCESSIBLE_BUT_NO_DATA",
                            validation_method=method,
                            http_status=resp.status_code,
                            evidence=body,
                            notes="Supabase REST endpoint responded successfully, but no table data was confirmed.",
                        )
                    return CloudValidationResult(
                        asset_type=self.asset_type,
                        identifier=identifier,
                        validation_status="VALIDATED",
                        validation_method=method,
                        http_status=resp.status_code,
                        evidence=body,
                        notes="Supabase REST endpoint returned live data.",
                    )
                if resp.status_code in {401, 403}:
                    denial_result = CloudValidationResult(
                        asset_type=self.asset_type,
                        identifier=identifier,
                        validation_status="ACCESSIBLE_BUT_NO_DATA",
                        validation_method=method,
                        http_status=resp.status_code,
                        evidence=body,
                        notes="Supabase project exists but requires authentication or RLS.",
                    )
                    if method == "supabase_rest_root":
                        return denial_result
                    if accessible_result is None:
                        accessible_result = denial_result
                    continue
                if resp.status_code == 404:
                    last_error = body or "not found"
                    continue
                return CloudValidationResult(
                    asset_type=self.asset_type,
                    identifier=identifier,
                    validation_status="UNVERIFIED",
                    validation_method=method,
                    http_status=resp.status_code,
                    evidence=body,
                    notes="Unexpected response while validating Supabase reference.",
                )
        if accessible_result is not None:
            return accessible_result
        return CloudValidationResult(
            asset_type=self.asset_type,
            identifier=identifier,
            validation_status="DEAD",
            validation_method="supabase_http_probe",
            evidence="",
            notes=last_error if "last_error" in locals() else "No reachable Supabase endpoint.",
        )


class S3Validator(BaseCloudValidator):
    asset_type = "aws_s3"

    @staticmethod
    def _extract_s3_xml_keys(body: str) -> list[str]:
        return BaseCloudValidator._extract_xml_tag_values(body, "Key")

    @staticmethod
    def _looks_synthetic_listing(body: str) -> bool:
        return BaseCloudValidator._looks_synthetic_name_listing(
            S3Validator._extract_s3_xml_keys(body)
        )

    def _bucket_url(self, identifier: str) -> str:
        return f"https://{identifier}.s3.amazonaws.com"

    def _head_validation_method(self) -> str:
        return "s3_head_probe"

    def _list_validation_method(self) -> str:
        return "s3_list_bucket"

    def _provider_label(self) -> str:
        return "S3"

    def validate(self, identifier: str, secret: str | None = None) -> CloudValidationResult:
        del secret
        url = self._bucket_url(identifier)
        head_method = self._head_validation_method()
        list_method = self._list_validation_method()
        provider_label = self._provider_label()
        if not url:
            return CloudValidationResult(
                asset_type=self.asset_type,
                identifier=identifier,
                validation_status="UNVERIFIED",
                validation_method=head_method,
                notes=f"{provider_label} bucket identifier could not be parsed.",
            )
        with httpx.Client(timeout=10, follow_redirects=True) as client:
            try:
                resp = key_validation_head(client, url)
            except httpx.HTTPError as exc:
                return CloudValidationResult(
                    asset_type=self.asset_type,
                    identifier=identifier,
                    validation_status="DEAD",
                    validation_method=head_method,
                    notes=str(exc),
                )
            headers_evidence = str(dict(resp.headers))
            if resp.status_code == 200:
                try:
                    list_resp = key_validation_get(client, url, params={"max-keys": "5"})
                except httpx.HTTPError:
                    return CloudValidationResult(
                        asset_type=self.asset_type,
                        identifier=identifier,
                        validation_status="ACCESSIBLE_BUT_NO_DATA",
                        validation_method=head_method,
                        http_status=resp.status_code,
                        evidence=headers_evidence,
                        notes=(
                            "Bucket responded to HEAD request, but no follow-up listing data "
                            "could be confirmed."
                        ),
                    )
                body = list_resp.text[:1024]
                if list_resp.status_code == 200:
                    root_tag = self._xml_root_tag(body)
                    if self._looks_html_document(body) or root_tag == "html":
                        return CloudValidationResult(
                            asset_type=self.asset_type,
                            identifier=identifier,
                            validation_status="UNVERIFIED",
                            validation_method=list_method,
                            http_status=list_resp.status_code,
                            evidence=body,
                            notes="Bucket listing endpoint returned unexpected HTML content.",
                        )
                    lowered = body.lower()
                    structured_error = self._classify_structured_error_payload(
                        body,
                        auth_status="ACCESSIBLE_BUT_NO_DATA",
                    )
                    if structured_error is not None:
                        validation_status, notes = structured_error
                        return CloudValidationResult(
                            asset_type=self.asset_type,
                            identifier=identifier,
                            validation_status=validation_status,
                            validation_method=list_method,
                            http_status=list_resp.status_code,
                            evidence=body,
                            notes=notes,
                        )
                    if self._looks_synthetic(body) or self._looks_synthetic_listing(body):
                        return CloudValidationResult(
                            asset_type=self.asset_type,
                            identifier=identifier,
                            validation_status="HONEYPOT_SUSPECTED",
                            validation_method=list_method,
                            http_status=list_resp.status_code,
                            evidence=body,
                            notes="Bucket listing looked synthetic or decoy-like.",
                        )
                    keys = self._extract_s3_xml_keys(body)
                    meaningful_keys = self._meaningful_object_names(keys)
                    if "<listbucketresult" in lowered:
                        if meaningful_keys:
                            return CloudValidationResult(
                                asset_type=self.asset_type,
                                identifier=identifier,
                                validation_status="VALIDATED",
                                validation_method=list_method,
                                http_status=list_resp.status_code,
                                evidence=body,
                                notes="Bucket listing returned object metadata through a low-impact probe.",
                            )
                        if keys:
                            return CloudValidationResult(
                                asset_type=self.asset_type,
                                identifier=identifier,
                                validation_status="ACCESSIBLE_BUT_NO_DATA",
                                validation_method=list_method,
                                http_status=list_resp.status_code,
                                evidence=body,
                                notes=self._low_signal_object_listing_notes("Bucket", keys),
                            )
                        return CloudValidationResult(
                            asset_type=self.asset_type,
                            identifier=identifier,
                            validation_status="ACCESSIBLE_BUT_NO_DATA",
                            validation_method=list_method,
                            http_status=list_resp.status_code,
                            evidence=body,
                            notes="Bucket listing endpoint responded but no objects were returned.",
                        )
                    if "<error>" in lowered and "nosuchbucket" in lowered:
                        return CloudValidationResult(
                            asset_type=self.asset_type,
                            identifier=identifier,
                            validation_status="DEAD",
                            validation_method=list_method,
                            http_status=list_resp.status_code,
                            evidence=body,
                            notes="Bucket list probe reported NoSuchBucket.",
                        )
                    if "<error>" in lowered and "accessdenied" in lowered:
                        return CloudValidationResult(
                            asset_type=self.asset_type,
                            identifier=identifier,
                            validation_status="ACCESSIBLE_BUT_NO_DATA",
                            validation_method=list_method,
                            http_status=list_resp.status_code,
                            evidence=body,
                            notes="Bucket exists but object listing requires authentication.",
                        )
                    return CloudValidationResult(
                        asset_type=self.asset_type,
                        identifier=identifier,
                        validation_status="UNVERIFIED",
                        validation_method=list_method,
                        http_status=list_resp.status_code,
                        evidence=body or headers_evidence,
                        notes=(
                            "Bucket listing endpoint returned an unexpected success payload that "
                            "did not prove object metadata exposure."
                        ),
                    )
                structured_error = self._classify_structured_error_payload(
                    body,
                    auth_status="ACCESSIBLE_BUT_NO_DATA",
                )
                if structured_error is not None:
                    validation_status, notes = structured_error
                    return CloudValidationResult(
                        asset_type=self.asset_type,
                        identifier=identifier,
                        validation_status=validation_status,
                        validation_method=list_method,
                        http_status=list_resp.status_code,
                        evidence=body or headers_evidence,
                        notes=notes,
                    )
                if list_resp.status_code in {301, 302, 307, 308, 401, 403}:
                    return CloudValidationResult(
                        asset_type=self.asset_type,
                        identifier=identifier,
                        validation_status="ACCESSIBLE_BUT_NO_DATA",
                        validation_method=list_method,
                        http_status=list_resp.status_code,
                        evidence=body or headers_evidence,
                        notes="Bucket exists but listing is not publicly available.",
                    )
                if list_resp.status_code == 404:
                    return CloudValidationResult(
                        asset_type=self.asset_type,
                        identifier=identifier,
                        validation_status="UNVERIFIED",
                        validation_method=list_method,
                        http_status=list_resp.status_code,
                        evidence=body or headers_evidence,
                        notes="HEAD probe succeeded but follow-up listing probe returned 404.",
                    )
                return CloudValidationResult(
                    asset_type=self.asset_type,
                    identifier=identifier,
                    validation_status="UNVERIFIED",
                    validation_method=list_method,
                    http_status=list_resp.status_code,
                    evidence=body or headers_evidence,
                    notes=f"Unexpected response while validating {provider_label} bucket listing.",
                )
        if resp.status_code == 200:
            return CloudValidationResult(
                asset_type=self.asset_type,
                identifier=identifier,
                validation_status="VALIDATED",
                validation_method=head_method,
                http_status=resp.status_code,
                evidence=headers_evidence,
                notes="Bucket responded to HEAD request.",
            )
        if resp.status_code in {301, 302, 403}:
            return CloudValidationResult(
                asset_type=self.asset_type,
                identifier=identifier,
                validation_status="ACCESSIBLE_BUT_NO_DATA",
                validation_method=head_method,
                http_status=resp.status_code,
                evidence=headers_evidence,
                notes="Bucket exists but listing is not publicly available.",
            )
        if resp.status_code == 404:
            return CloudValidationResult(
                asset_type=self.asset_type,
                identifier=identifier,
                validation_status="DEAD",
                validation_method=head_method,
                http_status=resp.status_code,
                evidence="",
                notes="Bucket not found.",
            )
        return CloudValidationResult(
            asset_type=self.asset_type,
            identifier=identifier,
            validation_status="UNVERIFIED",
            validation_method=head_method,
            http_status=resp.status_code,
            evidence=headers_evidence,
            notes=f"Unexpected response while validating {provider_label} bucket.",
        )


class DigitalOceanSpacesValidator(S3Validator):
    asset_type = "do_spaces"

    @staticmethod
    def _parse_identifier(identifier: str) -> tuple[str, str] | None:
        text = str(identifier or "").strip().lower()
        if not re.fullmatch(r"[a-z0-9\-]+/[a-z0-9.\-]{3,63}", text):
            return None
        region, bucket = text.split("/", 1)
        if not region or not bucket:
            return None
        return region, bucket

    def _bucket_url(self, identifier: str) -> str:
        parsed = self._parse_identifier(identifier)
        if parsed is None:
            return ""
        region, bucket = parsed
        return f"https://{bucket}.{region}.digitaloceanspaces.com"

    def _head_validation_method(self) -> str:
        return "do_spaces_head_probe"

    def _list_validation_method(self) -> str:
        return "do_spaces_list_bucket"

    def _provider_label(self) -> str:
        return "DigitalOcean Spaces"


class GCSValidator(BaseCloudValidator):
    asset_type = "gcs"

    @staticmethod
    def _extract_gcs_xml_keys(body: str) -> list[str]:
        return BaseCloudValidator._extract_xml_tag_values(body, "Key")

    @staticmethod
    def _extract_gcs_json_keys(body: str) -> list[str] | None:
        payload = BaseCloudValidator._parse_json_payload(body)
        if not isinstance(payload, dict):
            return None
        root_kind = str(payload.get("kind") or "").strip().lower()
        items = payload.get("items")
        prefixes = payload.get("prefixes")
        if not isinstance(items, list):
            items = []
        if not isinstance(prefixes, list):
            prefixes = []
        looks_like_listing = root_kind == "storage#objects"
        if not looks_like_listing and items:
            for item in items:
                if not isinstance(item, dict):
                    continue
                item_kind = str(item.get("kind") or "").strip().lower()
                if item_kind == "storage#object":
                    looks_like_listing = True
                    break
                if item.get("name") and any(
                    key in item
                    for key in ("bucket", "generation", "metageneration", "contentType", "storageClass", "size")
                ):
                    looks_like_listing = True
                    break
        if not looks_like_listing:
            return None
        keys: list[str] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or "").strip()
            if name:
                keys.append(name)
        for prefix in prefixes:
            prefix_name = str(prefix or "").strip()
            if prefix_name:
                keys.append(prefix_name)
        return keys

    def validate(self, identifier: str, secret: str | None = None) -> CloudValidationResult:
        del secret
        url = f"https://storage.googleapis.com/{identifier}"
        with httpx.Client(timeout=10, follow_redirects=True) as client:
            try:
                resp = key_validation_get(client, url, params={"max-keys": "5"})
            except httpx.HTTPError as exc:
                return CloudValidationResult(
                    asset_type=self.asset_type,
                    identifier=identifier,
                    validation_status="DEAD",
                    validation_method="gcs_list_bucket",
                    notes=str(exc),
                )
        body = resp.text[:1024]
        lowered = body.lower()
        if resp.status_code == 200:
            root_tag = self._xml_root_tag(body)
            if self._looks_html_document(body) or root_tag == "html":
                return CloudValidationResult(
                    asset_type=self.asset_type,
                    identifier=identifier,
                    validation_status="UNVERIFIED",
                    validation_method="gcs_list_bucket",
                    http_status=resp.status_code,
                    evidence=body,
                    notes="Bucket listing endpoint returned unexpected HTML content.",
                )
            structured_error = self._classify_structured_error_payload(
                body,
                auth_status="ACCESSIBLE_BUT_NO_DATA",
            )
            if structured_error is not None:
                validation_status, notes = structured_error
                return CloudValidationResult(
                    asset_type=self.asset_type,
                    identifier=identifier,
                    validation_status=validation_status,
                    validation_method="gcs_list_bucket",
                    http_status=resp.status_code,
                    evidence=body,
                    notes=notes,
                )
            json_keys = self._extract_gcs_json_keys(resp.text[:65536])
            keys = self._extract_gcs_xml_keys(body)
            if json_keys is not None:
                keys = json_keys
            is_listing_payload = "<listbucketresult" in lowered or json_keys is not None
            meaningful_keys = self._meaningful_object_names(keys)
            if self._looks_synthetic(body) or self._looks_synthetic_name_listing(keys):
                return CloudValidationResult(
                    asset_type=self.asset_type,
                    identifier=identifier,
                    validation_status="HONEYPOT_SUSPECTED",
                    validation_method="gcs_list_bucket",
                    http_status=resp.status_code,
                    evidence=body,
                    notes="Bucket listing looked synthetic or decoy-like.",
                )
            if is_listing_payload:
                if meaningful_keys:
                    return CloudValidationResult(
                        asset_type=self.asset_type,
                        identifier=identifier,
                        validation_status="VALIDATED",
                        validation_method="gcs_list_bucket",
                        http_status=resp.status_code,
                        evidence=body,
                        notes="Bucket listing returned object metadata through a low-impact probe.",
                    )
                if keys:
                    return CloudValidationResult(
                        asset_type=self.asset_type,
                        identifier=identifier,
                        validation_status="ACCESSIBLE_BUT_NO_DATA",
                        validation_method="gcs_list_bucket",
                        http_status=resp.status_code,
                        evidence=body,
                        notes=self._low_signal_object_listing_notes("Bucket", keys),
                    )
                return CloudValidationResult(
                    asset_type=self.asset_type,
                    identifier=identifier,
                    validation_status="ACCESSIBLE_BUT_NO_DATA",
                    validation_method="gcs_list_bucket",
                    http_status=resp.status_code,
                    evidence=body,
                    notes="Bucket listing endpoint responded but no objects were returned.",
                )
            return CloudValidationResult(
                asset_type=self.asset_type,
                identifier=identifier,
                validation_status="UNVERIFIED",
                validation_method="gcs_list_bucket",
                http_status=resp.status_code,
                evidence=body,
                notes=(
                    "Cloud Storage endpoint returned an unexpected success payload that did not "
                    "prove bucket listing data exposure."
                ),
            )
        structured_error = self._classify_structured_error_payload(
            body,
            auth_status="ACCESSIBLE_BUT_NO_DATA",
        )
        if structured_error is not None:
            validation_status, notes = structured_error
            return CloudValidationResult(
                asset_type=self.asset_type,
                identifier=identifier,
                validation_status=validation_status,
                validation_method="gcs_list_bucket",
                http_status=resp.status_code,
                evidence=body,
                notes=notes,
            )
        if resp.status_code in {301, 302, 307, 308, 401, 403}:
            return CloudValidationResult(
                asset_type=self.asset_type,
                identifier=identifier,
                validation_status="ACCESSIBLE_BUT_NO_DATA",
                validation_method="gcs_list_bucket",
                http_status=resp.status_code,
                evidence=body,
                notes="Bucket exists but listing is not publicly available.",
            )
        if resp.status_code == 404 or "nosuchbucket" in lowered:
            return CloudValidationResult(
                asset_type=self.asset_type,
                identifier=identifier,
                validation_status="DEAD",
                validation_method="gcs_list_bucket",
                http_status=resp.status_code,
                evidence=body,
                notes="Bucket not found.",
            )
        return CloudValidationResult(
            asset_type=self.asset_type,
            identifier=identifier,
            validation_status="UNVERIFIED",
            validation_method="gcs_list_bucket",
            http_status=resp.status_code,
            evidence=body,
            notes="Unexpected response while validating Cloud Storage bucket.",
        )


class AzureBlobValidator(BaseCloudValidator):
    asset_type = "azure_blob"

    @staticmethod
    def _parse_identifier(identifier: str) -> tuple[str, str] | None:
        account, _, container = str(identifier or "").strip().lower().partition("/")
        if not account or not container:
            return None
        return account, container

    @staticmethod
    def _extract_blob_names(body: str) -> list[str]:
        return BaseCloudValidator._extract_xml_tag_values(body, "Name")

    def validate(self, identifier: str, secret: str | None = None) -> CloudValidationResult:
        del secret
        parsed = self._parse_identifier(identifier)
        if parsed is None:
            return CloudValidationResult(
                asset_type=self.asset_type,
                identifier=identifier,
                validation_status="UNSUPPORTED",
                validation_method="azure_blob_identifier_parse",
                notes="Azure Blob validation requires an account/container identifier.",
            )
        account, container = parsed
        url = f"https://{account}.blob.core.windows.net/{container}"
        with httpx.Client(timeout=10, follow_redirects=True) as client:
            try:
                resp = key_validation_get(
                    client,
                    url,
                    params={"restype": "container", "comp": "list", "maxresults": "5"},
                )
            except httpx.HTTPError as exc:
                return CloudValidationResult(
                    asset_type=self.asset_type,
                    identifier=identifier,
                    validation_status="DEAD",
                    validation_method="azure_blob_list_container",
                    notes=str(exc),
                )
        body = resp.text[:1024]
        lowered = body.lower()
        if resp.status_code == 200:
            root_tag = self._xml_root_tag(body)
            if self._looks_html_document(body) or root_tag == "html":
                return CloudValidationResult(
                    asset_type=self.asset_type,
                    identifier=identifier,
                    validation_status="UNVERIFIED",
                    validation_method="azure_blob_list_container",
                    http_status=resp.status_code,
                    evidence=body,
                    notes="Container listing endpoint returned unexpected HTML content.",
                )
            structured_error = self._classify_structured_error_payload(
                body,
                auth_status="ACCESSIBLE_BUT_NO_DATA",
            )
            if structured_error is not None:
                validation_status, notes = structured_error
                return CloudValidationResult(
                    asset_type=self.asset_type,
                    identifier=identifier,
                    validation_status=validation_status,
                    validation_method="azure_blob_list_container",
                    http_status=resp.status_code,
                    evidence=body,
                    notes=notes,
                )
            names = self._extract_blob_names(body)
            meaningful_names = self._meaningful_object_names(names)
            if self._looks_synthetic(body) or self._looks_synthetic_name_listing(names):
                return CloudValidationResult(
                    asset_type=self.asset_type,
                    identifier=identifier,
                    validation_status="HONEYPOT_SUSPECTED",
                    validation_method="azure_blob_list_container",
                    http_status=resp.status_code,
                    evidence=body,
                    notes="Container listing looked synthetic or decoy-like.",
                )
            if "<enumerationresults" in lowered or "<blobs>" in lowered:
                if meaningful_names:
                    return CloudValidationResult(
                        asset_type=self.asset_type,
                        identifier=identifier,
                        validation_status="VALIDATED",
                        validation_method="azure_blob_list_container",
                        http_status=resp.status_code,
                        evidence=body,
                        notes="Container listing returned blob metadata through a low-impact probe.",
                    )
                if names:
                    return CloudValidationResult(
                        asset_type=self.asset_type,
                        identifier=identifier,
                        validation_status="ACCESSIBLE_BUT_NO_DATA",
                        validation_method="azure_blob_list_container",
                        http_status=resp.status_code,
                        evidence=body,
                        notes=self._low_signal_object_listing_notes("Container", names),
                    )
                return CloudValidationResult(
                    asset_type=self.asset_type,
                    identifier=identifier,
                    validation_status="ACCESSIBLE_BUT_NO_DATA",
                    validation_method="azure_blob_list_container",
                    http_status=resp.status_code,
                    evidence=body,
                    notes="Container listing endpoint responded but no blobs were returned.",
                )
            return CloudValidationResult(
                asset_type=self.asset_type,
                identifier=identifier,
                validation_status="UNVERIFIED",
                validation_method="azure_blob_list_container",
                http_status=resp.status_code,
                evidence=body,
                notes=(
                    "Azure Blob endpoint returned an unexpected success payload that did not "
                    "prove container listing data exposure."
                ),
            )
        structured_error = self._classify_structured_error_payload(
            body,
            auth_status="ACCESSIBLE_BUT_NO_DATA",
        )
        if structured_error is not None:
            validation_status, notes = structured_error
            return CloudValidationResult(
                asset_type=self.asset_type,
                identifier=identifier,
                validation_status=validation_status,
                validation_method="azure_blob_list_container",
                http_status=resp.status_code,
                evidence=body,
                notes=notes,
            )
        if resp.status_code in {301, 302, 307, 308, 401, 403, 409}:
            return CloudValidationResult(
                asset_type=self.asset_type,
                identifier=identifier,
                validation_status="ACCESSIBLE_BUT_NO_DATA",
                validation_method="azure_blob_list_container",
                http_status=resp.status_code,
                evidence=body,
                notes="Container exists but listing is not publicly available.",
            )
        if resp.status_code == 404 or "containernotfound" in lowered:
            return CloudValidationResult(
                asset_type=self.asset_type,
                identifier=identifier,
                validation_status="DEAD",
                validation_method="azure_blob_list_container",
                http_status=resp.status_code,
                evidence=body,
                notes="Container not found.",
            )
        return CloudValidationResult(
            asset_type=self.asset_type,
            identifier=identifier,
            validation_status="UNVERIFIED",
            validation_method="azure_blob_list_container",
            http_status=resp.status_code,
            evidence=body,
            notes="Unexpected response while validating Azure Blob container.",
        )


class CloudValidatorRegistry:
    def __init__(self) -> None:
        self._validators: dict[str, BaseCloudValidator] = {
            "firebase": FirebaseValidator(),
            "supabase": SupabaseValidator(),
            "aws_s3": S3Validator(),
            "s3": S3Validator(),
            "do_spaces": DigitalOceanSpacesValidator(),
            "digitalocean_spaces": DigitalOceanSpacesValidator(),
            "gcs": GCSValidator(),
            "google_cloud_storage": GCSValidator(),
            "azure_blob": AzureBlobValidator(),
            "azure_blob_storage": AzureBlobValidator(),
            "aws_cognito_user_pool": AwsCognitoUserPoolMetadataValidator(),
            "aws_cognito_app_client": AwsCognitoAppClientMetadataValidator(),
            "aws_appsync_api": AwsAppSyncApiReachabilityValidator(),
            "amplify": ManagedHostingReachabilityValidator("amplify", "amplifyapp.com"),
            "gcp_appspot": ManagedHostingReachabilityValidator("gcp_appspot", "appspot.com"),
            "gcp_cloudfunctions": ManagedHostingReachabilityValidator(
                "gcp_cloudfunctions",
                "cloudfunctions.net",
                require_qualified_identifier=True,
            ),
            "github_pages": ManagedHostingReachabilityValidator("github_pages", "github.io"),
            "gitlab_pages": ManagedHostingReachabilityValidator("gitlab_pages", "gitlab.io"),
            "cloudflare_pages": ManagedHostingReachabilityValidator("cloudflare_pages", "pages.dev"),
            "cloudflare_worker": ManagedHostingReachabilityValidator(
                "cloudflare_worker",
                "workers.dev",
                require_qualified_identifier=True,
            ),
            "cloudflare_r2": CloudflareR2ReachabilityValidator(),
            "netlify": ManagedHostingReachabilityValidator("netlify", "netlify.app"),
            "vercel": ManagedHostingReachabilityValidator("vercel", "vercel.app"),
            "render": ManagedHostingReachabilityValidator("render", "onrender.com"),
            "fly": ManagedHostingReachabilityValidator("fly", "fly.dev"),
            "railway": ManagedHostingReachabilityValidator("railway", "up.railway.app"),
            "heroku": ManagedHostingReachabilityValidator("heroku", "herokuapp.com"),
            "azure_static_web_app": ManagedHostingReachabilityValidator(
                "azure_static_web_app",
                "azurestaticapps.net",
                require_qualified_identifier=True,
            ),
        }

    def get(self, service: str) -> BaseCloudValidator | None:
        return self._validators.get(service.lower().strip())


@dataclass
class CloudValidationSweepSummary:
    attempted: int = 0
    succeeded: int = 0
    failed: int = 0
    status_counts: dict[str, int] | None = None

    def __post_init__(self) -> None:
        if self.status_counts is None:
            self.status_counts = {}


def _validation_progress_snapshot(
    *,
    total: int,
    workers: int,
    completed: int,
    failed: int,
    started_at: float,
) -> dict[str, object]:
    total_items = max(0, int(total or 0))
    active_workers = max(1, int(workers or 1)) if total_items else 0
    finished = max(0, min(total_items, int(completed or 0)))
    failed_items = max(0, min(finished, int(failed or 0)))
    remaining = max(0, total_items - finished)
    running = 0 if remaining <= 0 else min(active_workers, remaining)
    pending = max(0, remaining - running)
    payload: dict[str, object] = {
        "total": total_items,
        "workers": active_workers,
        "running": running,
        "pending": pending,
        "queue_depth": pending,
        "completed": finished,
        "failed": failed_items,
        "eta_seconds": None,
    }
    if total_items and remaining <= 0:
        payload["eta_seconds"] = 0.0
    elif total_items and finished > 0:
        elapsed = max(0.0, time.perf_counter() - started_at)
        if elapsed > 0:
            payload["eta_seconds"] = round((elapsed / finished) * remaining, 1)
    return payload


def _emit_validation_progress(
    *,
    progress_label: str | None = None,
    progress_callback: Callable[[str, dict[str, object]], None] | None = None,
    total: int,
    workers: int,
    completed: int,
    failed: int,
    started_at: float,
) -> None:
    label = str(progress_label or "").strip()
    if progress_callback is None or not label:
        return
    progress_callback(
        label,
        _validation_progress_snapshot(
            total=total,
            workers=workers,
            completed=completed,
            failed=failed,
            started_at=started_at,
        ),
    )


def _run_ordered_validation_local_batch(
    items: list[Any],
    worker: Callable[[Any], Any],
    *,
    max_workers: int,
) -> list[Any]:
    """Run local validation prep concurrently while preserving input order."""
    if not items:
        return []
    bounded_workers = max(1, min(int(max_workers or 1), len(items)))
    if bounded_workers == 1:
        return [worker(item) for item in items]
    results: list[Any | None] = [None] * len(items)
    with ThreadPoolExecutor(max_workers=bounded_workers) as executor:
        future_map = {
            executor.submit(worker, item): index
            for index, item in enumerate(items)
        }
        for future in as_completed(future_map):
            results[future_map[future]] = future.result()
    return list(results)


def _decrypt_secret(key_enc: str | None) -> str | None:
    if not key_enc:
        return None
    try:
        from forge.opsec.crypto import decrypt_string

        return decrypt_string(key_enc)
    except Exception:  # noqa: BLE001
        return None


def _supabase_project_ref_from_secret(value: str | None) -> str:
    token = str(value or "").strip()
    if not token:
        return ""
    parts = token.split(".")
    if len(parts) < 2:
        return ""
    payload = parts[1].strip()
    if not payload:
        return ""
    padded = payload + ("=" * (-len(payload) % 4))
    try:
        decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
        data = json.loads(decoded.decode("utf-8", errors="ignore"))
    except Exception:  # noqa: BLE001
        return ""
    project_ref = str(data.get("ref") or "").strip().lower()
    if not re.fullmatch(r"[a-z0-9\-]{3,}", project_ref):
        return ""
    return project_ref


def _extract_identifier(service: str, row: sqlite3.Row | dict[str, Any], *, secret: str | None = None) -> str | None:
    domain_value = str(row["domain"] or "").strip().lower()
    if service == "firebase" and re.fullmatch(r"[a-z0-9\-]{4,64}", domain_value):
        return domain_value
    if service == "supabase":
        if re.fullmatch(r"[a-z0-9\-]{4,64}", domain_value):
            return domain_value
        parsed = urlparse(domain_value)
        if parsed.hostname and parsed.hostname.endswith(".supabase.co"):
            return parsed.hostname.split(".", 1)[0].lower()
    if service in {"aws_s3", "s3"}:
        if re.fullmatch(r"[a-z0-9.\-]{3,63}", domain_value):
            return domain_value
        parsed = urlparse(domain_value)
        if parsed.hostname and parsed.hostname.endswith(".s3.amazonaws.com"):
            return parsed.hostname.split(".s3.amazonaws.com", 1)[0].lower()
        if parsed.hostname and ".s3-website" in parsed.hostname and parsed.hostname.endswith(".amazonaws.com"):
            return parsed.hostname.split(".s3-website", 1)[0].lower()
        if parsed.hostname and parsed.hostname.startswith("s3-website") and parsed.hostname.endswith(".amazonaws.com"):
            parts = [part for part in parsed.path.split("/") if part]
            if parts:
                return parts[0].lower()
    if service in {"do_spaces", "digitalocean_spaces"}:
        if re.fullmatch(r"[a-z0-9\-]+/[a-z0-9.\-]{3,63}", domain_value):
            return domain_value
        parsed = urlparse(domain_value)
        if parsed.hostname and parsed.hostname.endswith(".digitaloceanspaces.com"):
            parts = parsed.hostname.split(".")
            host_parts = [part for part in parts if part]
            if len(host_parts) >= 4:
                bucket = host_parts[0].lower()
                region = host_parts[1].lower()
                return f"{region}/{bucket}"
            path_parts = [part for part in parsed.path.split("/") if part]
            if parsed.hostname and path_parts:
                region = parsed.hostname.split(".digitaloceanspaces.com", 1)[0].lower()
                return f"{region}/{path_parts[0].lower()}"
    if service in {"gcs", "google_cloud_storage"}:
        if re.fullmatch(r"[a-z0-9._\-]{3,222}", domain_value):
            return domain_value
        parsed = urlparse(domain_value)
        if parsed.hostname and parsed.hostname == "storage.googleapis.com":
            parts = [part for part in parsed.path.split("/") if part]
            if parts:
                return parts[0].lower()
        if parsed.hostname and parsed.hostname == "storage.cloud.google.com":
            parts = [part for part in parsed.path.split("/") if part]
            if parts:
                return parts[0].lower()
        if parsed.hostname and parsed.hostname == "firebasestorage.googleapis.com":
            parts = [part for part in parsed.path.split("/") if part]
            if len(parts) >= 3 and parts[0].lower() == "v0" and parts[1].lower() == "b":
                return parts[2].lower()
            if len(parts) >= 2 and parts[0].lower() == "b":
                return parts[1].lower()
        if parsed.hostname and parsed.hostname.endswith(".storage.googleapis.com"):
            return parsed.hostname.split(".storage.googleapis.com", 1)[0].lower()
    if service in {"azure_blob", "azure_blob_storage"}:
        if re.fullmatch(r"[a-z0-9\-]{3,24}/[^/?#]+", domain_value):
            return domain_value
        parsed = urlparse(domain_value)
        if parsed.hostname and parsed.hostname.endswith(".web.core.windows.net"):
            account = parsed.hostname.split(".", 1)[0].lower()
            if account:
                return f"{account}/$web"
        if parsed.hostname and parsed.hostname.endswith((".blob.core.windows.net", ".dfs.core.windows.net")):
            parts = [part for part in parsed.path.split("/") if part]
            if parts:
                account = parsed.hostname.split(".", 1)[0].lower()
                return f"{account}/{parts[0].lower()}"

    sources = [
        str(row["source_url"] or ""),
        str(row["repo_name"] or ""),
        str(row["validation_detail"] or ""),
    ]
    joined = " ".join(sources)
    if service == "firebase":
        patterns = (
            re.compile(r"https?://([a-z0-9\-]+)\.firebaseio\.com", re.IGNORECASE),
            re.compile(r"https?://([a-z0-9\-]+)\.firebaseapp\.com", re.IGNORECASE),
            re.compile(r"https?://([a-z0-9\-]+)\.web\.app", re.IGNORECASE),
        )
        for pattern in patterns:
            match = pattern.search(joined)
            if match:
                return match.group(1).lower()
    if service == "supabase":
        match = re.search(r"https://([a-z0-9\-]+)\.supabase\.co", joined, re.IGNORECASE)
        if match:
            return match.group(1).lower()
        if secret:
            project_ref = _supabase_project_ref_from_secret(secret)
            if project_ref:
                return project_ref
    if service in {"aws_s3", "s3"}:
        patterns = (
            re.compile(r"https?://([a-z0-9.\-]+)\.s3\.amazonaws\.com", re.IGNORECASE),
            re.compile(
                r"https?://([a-z0-9.\-]+)\.s3-website(?:[.-][a-z0-9-]+)?\.amazonaws\.com",
                re.IGNORECASE,
            ),
            re.compile(
                r"https?://s3-website(?:[.-][a-z0-9-]+)?\.amazonaws\.com/([a-z0-9.\-]{3,63})(?:/|$)",
                re.IGNORECASE,
            ),
        )
        for pattern in patterns:
            match = pattern.search(joined)
            if match:
                return match.group(1).lower()
    if service in {"do_spaces", "digitalocean_spaces"}:
        patterns = (
            re.compile(
                r"https?://([a-z0-9.\-]{3,63})\.([a-z0-9\-]+)\.digitaloceanspaces\.com(?:/|$)",
                re.IGNORECASE,
            ),
            re.compile(
                r"https?://([a-z0-9\-]+)\.digitaloceanspaces\.com/([a-z0-9.\-]{3,63})(?:/|$)",
                re.IGNORECASE,
            ),
        )
        for pattern in patterns:
            match = pattern.search(joined)
            if match:
                if pattern is patterns[0]:
                    bucket, region = match.group(1).lower(), match.group(2).lower()
                else:
                    region, bucket = match.group(1).lower(), match.group(2).lower()
                return f"{region}/{bucket}"
    if service in {"gcs", "google_cloud_storage"}:
        patterns = (
            re.compile(r"https?://storage\.googleapis\.com/([a-z0-9._\-]{3,222})(?:/|$)", re.IGNORECASE),
            re.compile(r"https?://([a-z0-9._\-]{3,222})\.storage\.googleapis\.com(?:/|$)", re.IGNORECASE),
            re.compile(r"https?://storage\.cloud\.google\.com/([a-z0-9._\-]{3,222})(?:/|$)", re.IGNORECASE),
            re.compile(r"https?://firebasestorage\.googleapis\.com/(?:v0/)?b/([a-z0-9._\-]{3,222})/o(?:[/?#]|$)", re.IGNORECASE),
            re.compile(r"gs://([a-z0-9._\-]{3,222})(?:/|$)", re.IGNORECASE),
        )
        for pattern in patterns:
            match = pattern.search(joined)
            if match:
                return match.group(1).lower()
    if service in {"azure_blob", "azure_blob_storage"}:
        static_match = re.search(
            r"https?://([a-z0-9\-]{3,24})(?:\.[a-z0-9\-]+)?\.web\.core\.windows\.net(?:/|$)",
            joined,
            re.IGNORECASE,
        )
        if static_match:
            return f"{static_match.group(1).lower()}/$web"
        match = re.search(
            r"https?://([a-z0-9\-]{3,24})\.(?:blob|dfs)\.core\.windows\.net/([^/?#]+)",
            joined,
            re.IGNORECASE,
        )
        if match:
            return f"{match.group(1).lower()}/{match.group(2).lower()}"
    return None


def _update_key_validation_state(
    con: sqlite3.Connection,
    key_id: int,
    result: CloudValidationResult,
) -> None:
    if result.validation_status == "VALIDATED":
        validation_state = "ACTIVE"
    elif result.validation_status == "DEAD":
        validation_state = "ERROR"
    else:
        validation_state = "UNCONFIRMED"
    con.execute(
        """
        UPDATE key_scanner_findings
        SET validation_state=?,
            validation_detail=?,
            validated_at=CURRENT_TIMESTAMP
        WHERE id=?
        """,
        (
            validation_state,
            f"{result.validation_status}:{result.validation_method}:{result.notes[:240]}",
            key_id,
        ),
    )


def _validated_identifier_from_detail(service: str, detail: str | None) -> str | None:
    provider_service = str(service or "").strip().lower()
    normalized_service = _normalize_asset_type(provider_service)
    text = str(detail or "").strip()
    if not text:
        return None
    if provider_service == "aws":
        match = re.search(r"\baccountid:\s*([0-9]{12})\b", text, re.IGNORECASE)
        if match:
            return _stable_numeric_identifier(match.group(1), min_len=12, max_len=12)
    if provider_service == "github":
        match = re.search(
            r"github user ok:\s*user_id=([0-9]{2,16})\s+login=([a-z0-9-]+)\b",
            text,
            re.IGNORECASE,
        )
        if match and re.search(r"\buser_profile_present=true\b", text, re.IGNORECASE):
            user_id = _stable_numeric_identifier(match.group(1), min_len=2, max_len=16)
            login = _stable_handle_identifier(match.group(2), allow_dot=False)
            if user_id and login:
                return login
    if provider_service == "gitlab":
        match = re.search(
            r"gitlab user ok:\s*user_id=([0-9]{2,16})\s+username=([a-z0-9_.-]+)\b",
            text,
            re.IGNORECASE,
        )
        if match and re.search(r"\buser_profile_present=true\b", text, re.IGNORECASE):
            user_id = _stable_numeric_identifier(match.group(1), min_len=2, max_len=16)
            username = _stable_handle_identifier(match.group(2))
            if user_id and username:
                return username
    if provider_service == "google":
        match = re.search(
            r"google generative language models ok:\s*models=([0-9]+)\b",
            text,
            re.IGNORECASE,
        )
        if (
            match
            and int(match.group(1)) > 0
            and _stable_model_sample_from_detail(
                text,
                require_models_prefix=True,
                provider_family="google",
            )
        ):
            return "generativelanguage/models"
    if provider_service == "openai":
        match = re.search(r"openai models ok:\s*models=([0-9]+)\b", text, re.IGNORECASE)
        if (
            match
            and int(match.group(1)) > 0
            and _stable_model_sample_from_detail(text, provider_family="openai")
        ):
            return "api.openai.com/v1/models"
    if provider_service == "anthropic":
        match = re.search(r"anthropic models ok:\s*models=([0-9]+)\b", text, re.IGNORECASE)
        if (
            match
            and int(match.group(1)) > 0
            and _stable_model_sample_from_detail(text, provider_family="anthropic")
        ):
            return "api.anthropic.com/v1/models"
    if provider_service == "huggingface":
        match = re.search(r"hugging face auth ok:\s*user=([a-z0-9_.-]+)\b", text, re.IGNORECASE)
        if match and re.search(r"\buser_profile_present=true\b", text, re.IGNORECASE):
            return _stable_handle_identifier(match.group(1))
    if provider_service == "discord":
        match = re.search(r"discord bot auth ok:\s*bot_id=([0-9]{15,22})\b", text, re.IGNORECASE)
        if match and re.search(r"\bbot_profile_present=true\b", text, re.IGNORECASE):
            return _stable_numeric_identifier(match.group(1), min_len=15, max_len=22)
    if provider_service == "telegram":
        match = re.search(r"telegram bot auth ok:\s*bot_id=([0-9]{6,20})\b", text, re.IGNORECASE)
        if match and re.search(r"\bbot_profile_present=true\b", text, re.IGNORECASE):
            return _stable_numeric_identifier(match.group(1), min_len=6, max_len=20)
    if provider_service == "notion":
        match = re.search(
            r"notion users me ok:\s*user_id=([0-9a-f-]{32,36})\b",
            text,
            re.IGNORECASE,
        )
        if match and re.search(r"\buser_profile_present=true\b", text, re.IGNORECASE):
            return _stable_uuid_or_32hex(match.group(1)) or None
    if provider_service == "datadog":
        match = re.search(
            r"datadog api key valid:\s*site=([a-z0-9.-]+)\b",
            text,
            re.IGNORECASE,
        )
        if match and re.search(r"\bproof=valid_true\b", text, re.IGNORECASE):
            site = match.group(1).lower()
            valid_sites = {
                "datadoghq.com",
                "datadoghq.eu",
                "us3.datadoghq.com",
                "us5.datadoghq.com",
                "ap1.datadoghq.com",
                "ap2.datadoghq.com",
                "ddog-gov.com",
            }
            if site in valid_sites:
                return site
    if provider_service == "cloudflare":
        match = re.search(
            r"cloudflare token valid:\s*token_id=([a-z0-9_-]{8,32})\b",
            text,
            re.IGNORECASE,
        )
        if match and re.search(r"\bstatus=active\b", text, re.IGNORECASE):
            token_id = _stable_provider_identifier(match.group(1))
            if token_id and not _looks_repeated_compact_identifier(token_id):
                return token_id
            return None
    if provider_service == "vercel":
        match = re.search(r"vercel user ok:\s*user_id=([a-z0-9_-]{3,128})\b", text, re.IGNORECASE)
        if match and re.search(r"\buser_profile_present=true\b", text, re.IGNORECASE):
            return _stable_provider_identifier(match.group(1))
    if provider_service == "netlify":
        match = re.search(r"netlify user ok:\s*user_id=([a-z0-9_-]{3,128})\b", text, re.IGNORECASE)
        if match and re.search(r"\buser_profile_present=true\b", text, re.IGNORECASE):
            return _stable_provider_identifier(match.group(1))
    if provider_service == "posthog":
        match = re.search(
            r"posthog users me ok:\s*host=([a-z0-9.-]+)\s+user_id=([a-z0-9_-]{3,128})\b",
            text,
            re.IGNORECASE,
        )
        if match:
            host = match.group(1).lower()
            user_id = _stable_provider_identifier(match.group(2))
            if (
                host not in _POSTHOG_VALIDATION_HOSTS
                or not user_id
                or not re.search(r"\buser_profile_present=true\b", text, re.IGNORECASE)
            ):
                return None
            return f"{host}/{user_id}"
    if provider_service == "sentry":
        match = re.search(r"sentry organizations ok:\s*org_id=([0-9]{3,32})\b", text, re.IGNORECASE)
        hash_match = re.search(r"\borg_slug_hash=([a-f0-9]{16,64})\b", text, re.IGNORECASE)
        if match and hash_match and _looks_repeated_compact_identifier(hash_match.group(1)):
            return None
        has_slug_flags = re.search(
            r"\borg_slug_present=true\b", text, re.IGNORECASE
        ) and re.search(r"\borg_slug_stable=true\b", text, re.IGNORECASE)
        if match and hash_match and has_slug_flags:
            return _stable_numeric_identifier(match.group(1))
    if normalized_service == "sendgrid":
        if re.search(r"sendgrid profile ok:", text, re.IGNORECASE):
            hash_match = re.search(r"\bprofile_hash=([a-f0-9]{16,64})\b", text, re.IGNORECASE)
            if (
                hash_match
                and re.search(r"\b(?:email_present|username_present)=true\b", text, re.IGNORECASE)
                and not _looks_repeated_compact_identifier(hash_match.group(1))
            ):
                return f"profile/{hash_match.group(1).lower()[:16]}"
            return None
        scopes_match = re.search(r"sendgrid scopes accessible:\s*count=([0-9]+)", text, re.IGNORECASE)
        scope_hash_match = re.search(r"\bscope_hash=([a-f0-9]{16,64})\b", text, re.IGNORECASE)
        if (
            scopes_match
            and int(scopes_match.group(1)) > 0
            and scope_hash_match
            and not _looks_repeated_compact_identifier(scope_hash_match.group(1))
        ):
            return f"scopes/{scope_hash_match.group(1).lower()[:16]}"
    if normalized_service == "stripe":
        mode_match = re.search(r"\bmode=(live|test|unknown)\b", text, re.IGNORECASE)
        currency_match = re.search(r"\bcurrencies=([a-z0-9_,.-]+)", text, re.IGNORECASE)
        balances_match = re.search(r"\bbalances=available:([0-9]+),pending:([0-9]+)\b", text, re.IGNORECASE)
        if mode_match:
            mode = mode_match.group(1).lower()
            if mode != "live" or not balances_match:
                return None
            currencies = _stable_stripe_currency_summary(
                currency_match.group(1) if currency_match else ""
            )
            if currencies:
                return f"{mode}/{currencies}"
            return None
    if normalized_service == "twilio":
        match = re.search(r"\bsid=(AC[a-z0-9]{32})\b", text, re.IGNORECASE)
        status_match = re.search(r"\bstatus=([a-z_-]+)\b", text, re.IGNORECASE)
        if match and status_match and _stable_twilio_account_status(status_match.group(1)):
            return _stable_twilio_account_sid(match.group(1))
    if normalized_service == "mailchimp":
        match = re.search(r"\bdc=([a-z]{2}[0-9]{1,2})\b", text, re.IGNORECASE)
        health_match = re.search(r"\bhealth=([^\r\n]+)", text, re.IGNORECASE)
        if match and health_match and _stable_mailchimp_health_status(health_match.group(1)):
            return _stable_mailchimp_datacenter(match.group(1))
    if normalized_service == "azure":
        match = re.search(r"\baccount=([a-z0-9]{3,24})\b", text, re.IGNORECASE)
        containers_match = re.search(r"\bcontainers=([0-9]+)\b", text, re.IGNORECASE)
        if match and containers_match and int(containers_match.group(1)) > 0:
            return _stable_azure_storage_account_name(match.group(1))
    if normalized_service == "slack":
        actor_match = re.search(r"\b(?:actor_id|user_id|bot_id)=([a-z0-9]+)\b", text, re.IGNORECASE)
        team_match = re.search(r"\bteam_id=([a-z0-9]+)\b", text, re.IGNORECASE)
        actor_id = (
            _stable_slack_identifier(actor_match.group(1), ("U", "W", "B"))
            if actor_match
            else None
        )
        team_id = _stable_slack_identifier(team_match.group(1), ("T", "E")) if team_match else None
        if team_id and actor_id:
            return f"{team_id}/{actor_id}"
    return None


def _key_validation_identifier(
    row: sqlite3.Row | dict[str, Any],
    service: str,
    *,
    secret: str | None = None,
    validation_detail: str | None = None,
) -> str:
    credential_service = str(service or "").strip().lower()
    normalized_service = _normalize_asset_type(service)
    derived_identifier = _validated_identifier_from_detail(credential_service, validation_detail)
    if derived_identifier:
        return derived_identifier
    if normalized_service == "twilio" and secret:
        twilio_sid = _stable_twilio_account_sid(secret)
        if twilio_sid:
            return twilio_sid
    if normalized_service == "azure" and secret:
        from forge.utils.intel.secret_finder import (  # noqa: PLC0415
            _parse_azure_storage_connection_string,
        )

        account_name = str(
            _parse_azure_storage_connection_string(secret).get("accountname") or ""
        ).strip()
        stable_account_name = _stable_azure_storage_account_name(account_name)
        if stable_account_name:
            return stable_account_name
    if normalized_service == "mailchimp" and secret:
        match = re.search(r"-([a-z]{2}[0-9]{1,2})$", str(secret or "").strip(), re.IGNORECASE)
        if match:
            return match.group(1).lower()
    for field_name in ("source_url", "repo_name", "domain", "pattern_name"):
        candidate = str(row[field_name] or "").strip()
        if candidate:
            return candidate
    return service or "unknown"


def _secret_bound_validation_identifier(service: str, secret: str | None) -> str | None:
    normalized_service = _normalize_asset_type(service)
    if not secret:
        return None
    secret_text = str(secret or "").strip()
    if normalized_service == "stripe":
        if secret_text.startswith(("sk_live_", "rk_live_")):
            return "live"
        if secret_text.startswith(("sk_test_", "rk_test_")):
            return "test"
    if normalized_service == "twilio":
        return _stable_twilio_account_sid(secret)
    if normalized_service == "azure":
        from forge.utils.intel.secret_finder import (  # noqa: PLC0415
            _parse_azure_storage_connection_string,
        )

        account_name = str(
            _parse_azure_storage_connection_string(secret).get("accountname") or ""
        ).strip()
        return _stable_azure_storage_account_name(account_name)
    if normalized_service == "mailchimp":
        match = re.search(r"-([a-z]{2}[0-9]{1,2})$", str(secret or "").strip(), re.IGNORECASE)
        if match:
            return match.group(1).lower()
    return None


def _proof_identifier_matches_secret_bound(
    service: str,
    proof_identifier: str,
    secret_bound_identifier: str,
) -> bool:
    normalized_service = _normalize_asset_type(service)
    proof = str(proof_identifier or "").strip().lower()
    bound = str(secret_bound_identifier or "").strip().lower()
    if not proof or not bound:
        return False
    if normalized_service == "stripe":
        return proof == bound or proof.startswith(f"{bound}/")
    return proof == bound


def _resolve_twilio_auth_token(
    db_path: Path,
    row: sqlite3.Row | dict[str, Any],
) -> str | None:
    return _resolve_related_secret(
        db_path,
        row,
        service="twilio",
        pattern_name="twilio_auth_token",
    )


def _resolve_aws_secret_key(
    db_path: Path,
    row: sqlite3.Row | dict[str, Any],
) -> str | None:
    return _resolve_related_secret(
        db_path,
        row,
        service="aws",
        pattern_name="aws_secret_access_key",
    )


def _resolve_related_secret(
    db_path: Path,
    row: sqlite3.Row | dict[str, Any],
    *,
    service: str,
    pattern_name: str,
) -> str | None:
    engagement_id = int(row["engagement_id"])
    source_url = str(row["source_url"] or "").strip()
    repo_name = str(row["repo_name"] or "").strip()
    domain = str(row["domain"] or "").strip().lower()

    clauses: list[str] = []
    clause_params: list[Any] = []
    if source_url:
        clauses.append("COALESCE(source_url, '') = ?")
        clause_params.append(source_url)
    if repo_name:
        clauses.append("COALESCE(repo_name, '') = ?")
        clause_params.append(repo_name)
    if domain:
        clauses.append("LOWER(COALESCE(domain, '')) = ?")
        clause_params.append(domain)

    if not clauses:
        return None

    query = f"""
        SELECT key_enc
        FROM key_scanner_findings
        WHERE engagement_id=?
          AND service=?
          AND pattern_name=?
          AND ({' OR '.join(clauses)})
        ORDER BY
          CASE WHEN COALESCE(source_url, '') = ? THEN 0 ELSE 1 END,
          CASE WHEN COALESCE(repo_name, '') = ? THEN 0 ELSE 1 END,
          CASE WHEN LOWER(COALESCE(domain, '')) = ? THEN 0 ELSE 1 END,
          id ASC
        LIMIT 1
    """
    params: list[Any] = [engagement_id, service, pattern_name, *clause_params, source_url, repo_name, domain]

    con = sqlite3.connect(db_path)
    try:
        match = con.execute(query, tuple(params)).fetchone()
    finally:
        con.close()
    if match is None or not match[0]:
        return None
    return _decrypt_secret(str(match[0]))


def _validate_existing_key_service(
    service: str,
    row: sqlite3.Row | dict[str, Any],
    *,
    secret: str | None,
    db_path: Path | None = None,
) -> CloudValidationResult | None:
    normalized_service = str(service or "").strip().lower()
    if not secret:
        return None

    from forge.utils.intel.secret_finder import (  # noqa: PLC0415
        ValidationState,
        load_validatable_primary_patterns,
        validator_class_by_name,
    )

    pattern_name = str(row["pattern_name"] or "").strip()
    pattern = next(
        (
            item
            for item in load_validatable_primary_patterns()
            if item.service.lower() == normalized_service and item.name == pattern_name
        ),
        None,
    )
    validator_cls = validator_class_by_name(pattern.validation_method if pattern is not None else None)
    validation_method = str(getattr(validator_cls, "result_validation_method", "") or "").strip()
    if validator_cls is None or not validation_method:
        return None
    identifier = _key_validation_identifier(row, normalized_service, secret=secret)
    if normalized_service == "aws":
        aws_secret = _resolve_aws_secret_key(db_path, row) if db_path is not None else None
        validation = validator_cls().validate(secret, secret=aws_secret)
    elif normalized_service == "twilio":
        auth_token = _resolve_twilio_auth_token(db_path, row) if db_path is not None else None
        validation = validator_cls().validate(secret, auth_token=auth_token)
    else:
        validation = validator_cls().validate(secret)
    detail = str(getattr(validation, "detail", "") or "").strip()
    state = getattr(validation, "state", None)
    proof_identifier = _validated_identifier_from_detail(normalized_service, detail)
    secret_bound_identifier = _secret_bound_validation_identifier(normalized_service, secret)
    identifier = _key_validation_identifier(
        row,
        normalized_service,
        secret=secret,
        validation_detail=detail,
    )

    if state == ValidationState.ACTIVE:
        if (
            proof_identifier
            and secret_bound_identifier
            and not _proof_identifier_matches_secret_bound(
                normalized_service,
                proof_identifier,
                secret_bound_identifier,
            )
        ):
            return CloudValidationResult(
                asset_type=normalized_service,
                identifier=secret_bound_identifier,
                validation_status="UNVERIFIED",
                validation_method=validation_method,
                evidence=detail[:512],
                notes=(
                    "Provider proof identifier did not match the identifier bound to the "
                    "discovered secret."
                ),
            )
        if not proof_identifier:
            return CloudValidationResult(
                asset_type=normalized_service,
                identifier=identifier,
                validation_status="UNVERIFIED",
                validation_method=validation_method,
                evidence=detail[:512],
                notes=(
                    detail
                    or "Existing secret validator returned ACTIVE without provider-specific proof detail."
                ),
            )
        return CloudValidationResult(
            asset_type=normalized_service,
            identifier=proof_identifier,
            validation_status="VALIDATED",
            validation_method=validation_method,
            evidence=detail[:512],
            notes=detail or "Existing secret validator confirmed live provider access.",
        )
    if state == ValidationState.REVOKED:
        return CloudValidationResult(
            asset_type=normalized_service,
            identifier=identifier,
            validation_status="DEAD",
            validation_method=validation_method,
            evidence=detail[:512],
            notes=detail or "Existing secret validator confirmed the credential was revoked or unauthorized.",
        )
    if state == ValidationState.UNCONFIRMED:
        return CloudValidationResult(
            asset_type=normalized_service,
            identifier=identifier,
            validation_status="UNVERIFIED",
            validation_method=validation_method,
            evidence=detail[:512],
            notes=detail or "Existing secret validator could not confirm live provider access.",
        )
    return CloudValidationResult(
        asset_type=normalized_service,
        identifier=identifier,
        validation_status="UNVERIFIED",
        validation_method=validation_method,
        evidence=detail[:512],
        notes=detail or "Existing secret validator returned an unexpected validation state.",
    )


def _validate_key_row_payload(
    row: Any,
    *,
    registry: CloudValidatorRegistry | None = None,
    db_path: Path | None = None,
) -> tuple[int, int, CloudValidationResult]:
    active_registry = registry or CloudValidatorRegistry()
    key_id = int(row["id"])
    engagement_id = int(row["engagement_id"])
    service = str(row["service"] or "").lower().strip()
    validator = active_registry.get(service)
    secret = _decrypt_secret(str(row["key_enc"])) if row["key_enc"] else None
    key_service_result = _validate_existing_key_service(
        service,
        row,
        secret=secret,
        db_path=db_path,
    )
    if key_service_result is not None:
        return key_id, engagement_id, key_service_result
    identifier = _extract_identifier(service, row, secret=secret)

    if validator is None or not identifier:
        result = CloudValidationResult(
            asset_type=service or "unknown",
            identifier=identifier or str(row["domain"] or ""),
            validation_status="UNSUPPORTED",
            validation_method="registry_lookup",
            notes="No deterministic validator available for this service or identifier could not be derived.",
        )
        return key_id, engagement_id, result

    result = validator.validate(identifier, secret=secret)
    return key_id, engagement_id, result


def _persist_validation_result(
    con: sqlite3.Connection,
    engagement_id: int,
    result: CloudValidationResult,
) -> None:
    if result.validation_status not in _VALID_STATUSES:
        raise ValueError(f"Unsupported validation status: {result.validation_status}")
    provider_identifier = str(result.provider_identifier or result.identifier).strip()
    con.execute(
        """
        INSERT INTO cloud_validation_results
            (engagement_id, asset_type, identifier, provider_identifier, validation_status, validation_method, http_status, evidence, notes)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(engagement_id, asset_type, identifier) DO UPDATE SET
            provider_identifier=CASE
                WHEN cloud_validation_results.provider_identifier IS NULL
                  OR TRIM(cloud_validation_results.provider_identifier) = ''
                  OR cloud_validation_results.provider_identifier = cloud_validation_results.identifier
                THEN excluded.provider_identifier
                ELSE cloud_validation_results.provider_identifier
            END,
            validation_status=excluded.validation_status,
            validation_method=excluded.validation_method,
            http_status=excluded.http_status,
            evidence=excluded.evidence,
            notes=excluded.notes,
            checked_at=CURRENT_TIMESTAMP
        """,
        (
            engagement_id,
            result.asset_type,
            result.identifier,
            provider_identifier,
            result.validation_status,
            result.validation_method,
            result.http_status,
            result.evidence[:1024],
            result.notes[:1024],
        ),
    )
    con.execute(
        """
        INSERT INTO cloud_assets
            (engagement_id, asset_type, identifier, provider_identifier, source)
        VALUES (?, ?, ?, ?, 'cloud_validate')
        ON CONFLICT(engagement_id, asset_type, identifier) DO UPDATE SET
            provider_identifier = CASE
                WHEN cloud_assets.provider_identifier IS NULL
                  OR TRIM(cloud_assets.provider_identifier) = ''
                  OR cloud_assets.provider_identifier = cloud_assets.identifier
                THEN excluded.provider_identifier
                ELSE cloud_assets.provider_identifier
            END
        """,
        (engagement_id, result.asset_type, result.identifier, provider_identifier),
    )


def _normalize_asset_type(value: str) -> str:
    normalized = str(value or "").strip().lower()
    if normalized == "s3":
        return "aws_s3"
    if normalized == "digitalocean_spaces":
        return "do_spaces"
    if normalized == "google_cloud_storage":
        return "gcs"
    if normalized == "azure_blob_storage":
        return "azure_blob"
    return normalized


def _validation_scope_values(data: dict[str, Any], *keys: str) -> list[str]:
    values: list[str] = []
    seen: set[str] = set()
    for key in keys:
        raw_value = data.get(key)
        if raw_value is None:
            continue
        raw_items = raw_value if isinstance(raw_value, list) else [raw_value]
        for item in raw_items:
            value = " ".join(str(item or "").strip().split())
            if value and value not in seen:
                seen.add(value)
                values.append(value)
    return values


def load_cloud_validation_scope_manifest(value: str | dict[str, Any]) -> dict[str, Any]:
    """Load the subset of an ROE scope manifest needed by validation gates."""
    if isinstance(value, dict):
        payload = value
        source = str(payload.get("source") or "payload_object")
    else:
        manifest_ref = str(value or "").strip()
        if not manifest_ref:
            raise ValueError("scope manifest path or JSON payload is required")
        if manifest_ref.startswith("{"):
            source = "inline_json"
            payload = json.loads(manifest_ref)
        else:
            path = Path(manifest_ref).expanduser()
            source = path.resolve().as_posix()
            payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("scope manifest must decode to a JSON object")

    exact_seeds = _validation_scope_values(
        payload,
        "exact_seeds",
        "seeds",
        "authorized_seeds",
        "allowed_seeds",
        "targets",
        "allowed_targets",
    )
    return {
        "source": source,
        "roe_id": " ".join(str(payload.get("roe_id") or payload.get("roe") or "").strip().split())[:160],
        "domains": _validation_scope_values(payload, "domains", "domain_allowlist"),
        "ip_ranges": _validation_scope_values(payload, "ip_ranges", "cidrs", "cidr_ranges"),
        "urls": _validation_scope_values(payload, "urls", "url_prefixes"),
        "exact_seeds": exact_seeds,
        "raw": payload,
    }


def _validation_scope_seed_targets(seed_value: str, seed_type: str) -> list[str]:
    value = str(seed_value or "").strip()
    kind = str(seed_type or "").strip().lower()
    targets: list[str] = []

    def _append(target: str) -> None:
        normalized = str(target or "").strip()
        if normalized and normalized not in targets:
            targets.append(normalized)

    if kind in {"url", "apk_url"}:
        _append(value)
        parsed = urlparse(value)
        _append(str(parsed.hostname or "").strip().lower().strip("."))
    elif kind == "email" and "@" in value:
        _append(value.rsplit("@", 1)[1].strip().lower().strip("."))
    elif kind in {"domain", "subdomain", "ipv4", "ipv6"}:
        _append(value.lower().strip("."))
    else:
        _append(value)
    return targets


def validate_scope_manifest_entries(
    manifest: dict[str, Any],
    seed_entries: list[dict[str, str]],
) -> dict[str, Any]:
    """Return authorized/denied seed entries using the same gate as kill-chain scope checks."""
    from forge.governance.scope_gate import EngagementScope, ScopeGate  # noqa: PLC0415

    exact_seeds = {
        str(value or "").strip().casefold()
        for value in manifest.get("exact_seeds", [])
        if str(value or "").strip()
    }
    gate = ScopeGate(
        EngagementScope(
            domains=list(manifest.get("domains") or []),
            ip_ranges=list(manifest.get("ip_ranges") or []),
            urls=list(manifest.get("urls") or []),
        )
    )
    authorized: list[dict[str, str]] = []
    denied: list[dict[str, str]] = []
    for entry in seed_entries:
        seed_value = str(entry.get("value") or "").strip()
        seed_type = str(entry.get("seed_type") or "").strip().lower()
        if not seed_value:
            continue
        if seed_value.casefold() in exact_seeds:
            authorized.append(
                {
                    "seed_value": seed_value,
                    "seed_type": seed_type,
                    "matched": seed_value,
                    "match_type": "exact_seed",
                }
            )
            continue
        candidate_targets = _validation_scope_seed_targets(seed_value, seed_type)
        if seed_type in {"url", "apk_url"} and list(manifest.get("urls") or []):
            candidate_targets = [seed_value]
        matched_target = ""
        for target in candidate_targets:
            if gate.is_in_scope(target):
                matched_target = target
                break
        if matched_target:
            authorized.append(
                {
                    "seed_value": seed_value,
                    "seed_type": seed_type,
                    "matched": matched_target,
                    "match_type": "scope_gate",
                }
            )
        else:
            denied.append({"seed_value": seed_value, "seed_type": seed_type})
    return {"authorized": authorized, "denied": denied}


def cloud_asset_scope_entries(service: str, ref: str) -> list[dict[str, str]]:
    service_name = _normalize_asset_type(service)
    raw_ref = str(ref or "").strip()
    if not raw_ref:
        return []
    entries: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def _append(value: str, seed_type: str) -> None:
        normalized_value = str(value or "").strip()
        normalized_type = str(seed_type or "").strip().lower() or "other"
        key = (normalized_type, normalized_value.casefold())
        if not normalized_value or key in seen:
            return
        seen.add(key)
        entries.append({"value": normalized_value, "seed_type": normalized_type})

    _append(raw_ref, "other")
    parsed = urlparse(raw_ref)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        _append(raw_ref, "url")
        hostname = str(parsed.hostname or "").strip().lower().strip(".")
        if hostname:
            _append(hostname, "domain")
        return entries

    ref_host = raw_ref.lower().strip(".")
    if "." in ref_host and not re.search(r"\s", ref_host):
        _append(ref_host, "domain")
        _append(f"https://{ref_host}", "url")

    compact_ref = re.sub(r"[^A-Za-z0-9_.-]+", "", raw_ref).strip(".")
    if not compact_ref:
        return entries
    if service_name == "firebase":
        for suffix in ("firebaseio.com", "firebaseapp.com", "web.app"):
            _append(f"https://{compact_ref}.{suffix}", "url")
    elif service_name == "supabase":
        _append(f"https://{compact_ref}.supabase.co", "url")
    elif service_name == "aws_s3":
        _append(f"https://{compact_ref}.s3.amazonaws.com", "url")
        _append(f"https://s3.amazonaws.com/{compact_ref}", "url")
    elif service_name == "gcs":
        _append(f"https://storage.googleapis.com/{compact_ref}", "url")
        _append(f"https://{compact_ref}.storage.googleapis.com", "url")
    elif service_name == "azure_blob":
        account = compact_ref.split(".", 1)[0]
        _append(f"https://{account}.blob.core.windows.net", "url")
    elif service_name == "do_spaces":
        _append(f"https://{compact_ref}.digitaloceanspaces.com", "url")
    return entries


def cloud_asset_scope_decision(
    manifest: dict[str, Any] | None,
    service: str,
    ref: str,
) -> dict[str, object]:
    service_name = _normalize_asset_type(service)
    raw_ref = str(ref or "").strip()
    if not raw_ref:
        return {"allowed": False, "reason": "empty", "service": service_name}
    if not (isinstance(manifest, dict) and manifest):
        return {"allowed": True, "reason": "no_scope_manifest", "service": service_name, "ref": raw_ref}
    entries = cloud_asset_scope_entries(service_name, raw_ref)
    if not entries:
        return {
            "allowed": False,
            "reason": "scope_manifest_no_candidates",
            "service": service_name,
            "ref": raw_ref,
        }
    scope_result = validate_scope_manifest_entries(manifest, entries)
    authorized = list(scope_result.get("authorized") or [])
    if authorized:
        first = authorized[0] if isinstance(authorized[0], dict) else {}
        return {
            "allowed": True,
            "reason": "allowed",
            "service": service_name,
            "ref": raw_ref,
            "matched": str(first.get("matched") or first.get("seed_value") or ""),
        }
    return {
        "allowed": False,
        "reason": "scope_manifest_denied",
        "service": service_name,
        "ref": raw_ref,
        "candidate_count": len(entries),
        "scope_manifest_source": str(manifest.get("source") or ""),
    }


def key_validation_source_entries(row_payload: dict[str, Any]) -> list[dict[str, str]]:
    entries: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def _append(value: str, seed_type: str) -> None:
        normalized_value = str(value or "").strip()
        normalized_type = str(seed_type or "").strip().lower() or "other"
        key = (normalized_type, normalized_value.casefold())
        if not normalized_value or key in seen:
            return
        seen.add(key)
        entries.append({"value": normalized_value, "seed_type": normalized_type})

    def _append_url_or_domain(value: str) -> None:
        raw_value = str(value or "").strip()
        if not raw_value:
            return
        parsed = urlparse(raw_value)
        if parsed.scheme in {"http", "https"} and parsed.netloc:
            _append(raw_value, "url")
            hostname = str(parsed.hostname or "").strip().lower().strip(".")
            if hostname:
                _append(hostname, "domain")
            return
        candidate = raw_value.lower().strip(".")
        if "." in candidate and not re.search(r"\s", candidate):
            _append(candidate, "domain")
            return
        _append(raw_value, "other")

    _append_url_or_domain(str(row_payload.get("source_url") or ""))
    _append_url_or_domain(str(row_payload.get("domain") or ""))
    repo_name = str(row_payload.get("repo_name") or "").strip()
    if repo_name:
        if repo_name.startswith(("http://", "https://")):
            _append_url_or_domain(repo_name)
        else:
            _append(repo_name, "other")
    return entries


def key_validation_scope_decision(
    manifest: dict[str, Any] | None,
    row_payload: dict[str, Any],
) -> dict[str, object]:
    if not (isinstance(manifest, dict) and manifest):
        return {"allowed": True, "reason": "no_scope_manifest"}
    source_url = str(row_payload.get("source_url") or "").strip()
    source_backend = str(row_payload.get("source_backend") or "").strip().lower()
    parsed_source = urlparse(source_url)
    local_artifact_backends = {
        "artifact",
        "artifact_text_extract",
        "mobile_config_parse",
        "local_artifact",
        "local_filesystem",
    }
    if source_backend in local_artifact_backends and parsed_source.scheme not in {"http", "https"}:
        return {
            "allowed": True,
            "reason": "operator_local_artifact",
            "source_backend": source_backend,
        }
    entries = key_validation_source_entries(row_payload)
    if not entries:
        return {
            "allowed": False,
            "reason": "scope_manifest_no_source_candidates",
            "source_backend": source_backend,
        }
    scope_result = validate_scope_manifest_entries(manifest, entries)
    authorized = list(scope_result.get("authorized") or [])
    if authorized:
        first = authorized[0] if isinstance(authorized[0], dict) else {}
        return {
            "allowed": True,
            "reason": "allowed",
            "matched": str(first.get("matched") or first.get("seed_value") or ""),
            "source_backend": source_backend,
        }
    return {
        "allowed": False,
        "reason": "scope_manifest_denied",
        "source_backend": source_backend,
        "candidate_count": len(entries),
        "scope_manifest_source": str(manifest.get("source") or ""),
    }


def _run_direct_asset_validation(
    *,
    engagement_id: int,
    asset_type: str,
    identifier: str,
    db_path: Path,
    secret: str | None = None,
    scope_checker: Callable[[str, str], bool] | None = None,
    scope_denied_callback: Callable[[str, str, str], None] | None = None,
) -> dict[str, Any]:
    registry = CloudValidatorRegistry()
    normalized_type = _normalize_asset_type(asset_type)
    provider_identifier = str(identifier or "").strip()
    normalized_identifier = provider_identifier.lower()
    if not normalized_type or not normalized_identifier:
        return {
            "status": "failed",
            "error": "asset_type and identifier are required.",
            "asset_type": normalized_type,
            "identifier": normalized_identifier,
            "provider_identifier": provider_identifier,
        }

    allowed = True
    denial_reason = "scope_manifest_denied"
    if scope_checker is not None:
        try:
            allowed = bool(scope_checker(normalized_type, normalized_identifier))
        except Exception as exc:  # noqa: BLE001
            allowed = False
            denial_reason = f"scope_checker_error:{type(exc).__name__}"
    if not allowed:
        if scope_denied_callback is not None:
            try:
                scope_denied_callback(normalized_type, normalized_identifier, denial_reason)
            except Exception:  # noqa: BLE001
                pass
        result = CloudValidationResult(
            asset_type=normalized_type,
            identifier=normalized_identifier,
            validation_status="UNVERIFIED",
            validation_method="scope_manifest",
            evidence="scope denied before cloud validation",
            notes=denial_reason,
            provider_identifier=provider_identifier,
        )
    else:
        validator = registry.get(normalized_type)
        if validator is None:
            result = CloudValidationResult(
                asset_type=normalized_type,
                identifier=normalized_identifier,
                validation_status="UNSUPPORTED",
                validation_method="registry_lookup",
                notes="No deterministic validator available for this asset type.",
                provider_identifier=provider_identifier,
            )
        else:
            result = validator.validate(provider_identifier, secret=secret)
            result.asset_type = normalized_type
            result.identifier = normalized_identifier
            result.provider_identifier = provider_identifier

    con = sqlite3.connect(db_path)
    try:
        apply_schema(con)
        run_migrations(con)
        _persist_validation_result(con, engagement_id, result)
        con.commit()
    finally:
        con.close()

    DeterministicFindingEngine(db_path, engagement_id).run()
    payload = result.to_api_dict()
    payload["engagement_id"] = engagement_id
    return payload


def _probe_cloud_asset_result(
    asset_type: str,
    identifier: str,
    *,
    secret: str | None = None,
) -> CloudValidationResult:
    registry = CloudValidatorRegistry()
    normalized_type = _normalize_asset_type(asset_type)
    provider_identifier = str(identifier or "").strip()
    normalized_identifier = provider_identifier.lower()
    if not normalized_type or not normalized_identifier:
        return CloudValidationResult(
            asset_type=normalized_type,
            identifier=normalized_identifier,
            validation_status="UNSUPPORTED",
            validation_method="input_validation",
            notes="asset_type and identifier are required.",
            provider_identifier=provider_identifier,
        )

    validator = registry.get(normalized_type)
    if validator is None:
        return CloudValidationResult(
            asset_type=normalized_type,
            identifier=normalized_identifier,
            validation_status="UNSUPPORTED",
            validation_method="registry_lookup",
            notes="No deterministic validator available for this asset type.",
            provider_identifier=provider_identifier,
        )
    result = validator.validate(provider_identifier, secret=secret)
    result.asset_type = normalized_type
    result.identifier = normalized_identifier
    result.provider_identifier = provider_identifier
    return result


def run_cloud_asset_validate(
    engagement_id: int,
    asset_type: str,
    identifier: str,
    db_path: Path,
    *,
    secret: str | None = None,
    scope_checker: Callable[[str, str], bool] | None = None,
    scope_denied_callback: Callable[[str, str, str], None] | None = None,
) -> dict[str, Any]:
    """Validate a discovered cloud asset reference without requiring a key row."""
    try:
        return _run_direct_asset_validation(
            engagement_id=engagement_id,
            asset_type=asset_type,
            identifier=identifier,
            db_path=db_path,
            secret=secret,
            scope_checker=scope_checker,
            scope_denied_callback=scope_denied_callback,
        )
    except Exception as exc:  # noqa: BLE001
        _LOG.warning(
            "cloud asset validation failed for engagement=%d asset=%s identifier=%s: %s",
            engagement_id,
            asset_type,
            identifier,
            exc,
        )
        return {
            "status": "failed",
            "error": str(exc),
            "engagement_id": engagement_id,
            "asset_type": _normalize_asset_type(asset_type),
            "identifier": str(identifier or "").strip().lower(),
        }


def run_cloud_asset_validate_batch(
    engagement_id: int,
    assets: list[tuple[str, str] | tuple[str, str, str | None]],
    db_path: Path,
    *,
    max_workers: int | None = None,
    progress_label: str | None = None,
    progress_callback: Callable[[str, dict[str, object]], None] | None = None,
    scope_checker: Callable[[str, str], bool] | None = None,
    scope_denied_callback: Callable[[str, str, str], None] | None = None,
) -> dict[str, Any]:
    """Validate multiple discovered cloud asset references with bounded concurrency."""
    worker_count = _resolve_validation_max_workers(max_workers)
    if not assets:
        return {
            "status": "success",
            "engagement_id": engagement_id,
            "attempted": 0,
            "succeeded": 0,
            "failed": 0,
            "status_counts": {},
            "results": [],
        }

    normalized_assets: list[tuple[str, str, str | None]] = []
    for asset in assets:
        if len(asset) == 2:
            asset_type, identifier = asset
            secret = None
        else:
            asset_type, identifier, secret = asset
        normalized_assets.append((str(asset_type or ""), str(identifier or ""), secret))

    result_slots: list[CloudValidationResult | None] = [None] * len(normalized_assets)
    allowed_assets: list[tuple[str, str, str | None]] = []
    allowed_indices: list[int] = []

    def _scope_gate_cloud_asset_entry(
        item: tuple[int, tuple[str, str, str | None]],
    ) -> dict[str, Any]:
        index, asset = item
        asset_type, identifier, secret = asset
        normalized_type = _normalize_asset_type(asset_type)
        normalized_identifier = str(identifier or "").strip().lower()
        allowed = True
        denial_reason = "scope_manifest_denied"
        if scope_checker is not None:
            try:
                allowed = bool(scope_checker(normalized_type, normalized_identifier))
            except Exception as exc:  # noqa: BLE001
                allowed = False
                denial_reason = f"scope_checker_error:{type(exc).__name__}"
        return {
            "index": index,
            "asset": asset,
            "normalized_type": normalized_type,
            "normalized_identifier": normalized_identifier,
            "allowed": allowed,
            "denial_reason": denial_reason,
            "secret": secret,
        }

    scoped_assets = _run_ordered_validation_local_batch(
        list(enumerate(normalized_assets)),
        _scope_gate_cloud_asset_entry,
        max_workers=worker_count,
    )

    for scoped_asset in scoped_assets:
        index = int(scoped_asset["index"])
        asset_type, identifier, secret = scoped_asset["asset"]
        normalized_type = str(scoped_asset["normalized_type"])
        normalized_identifier = str(scoped_asset["normalized_identifier"])
        allowed = bool(scoped_asset["allowed"])
        denial_reason = str(scoped_asset["denial_reason"] or "scope_manifest_denied")
        if allowed:
            allowed_indices.append(index)
            allowed_assets.append((asset_type, identifier, secret))
            continue
        if scope_denied_callback is not None:
            try:
                scope_denied_callback(normalized_type, normalized_identifier, denial_reason)
            except Exception:  # noqa: BLE001
                pass
        result_slots[index] = CloudValidationResult(
            asset_type=normalized_type,
            identifier=normalized_identifier,
            validation_status="UNVERIFIED",
            validation_method="scope_manifest",
            evidence="scope denied before cloud validation",
            notes=denial_reason,
            provider_identifier=str(identifier or "").strip(),
        )

    original_count = len(normalized_assets)
    normalized_assets = allowed_assets
    bounded_workers = max(1, min(worker_count, len(normalized_assets)))
    started_at = time.perf_counter()

    def _worker(asset: tuple[str, str, str | None]) -> CloudValidationResult:
        asset_type, identifier, secret = asset
        return _probe_cloud_asset_result(asset_type, identifier, secret=secret)

    if normalized_assets:
        _emit_validation_progress(
            progress_label=progress_label,
            progress_callback=progress_callback,
            total=len(normalized_assets),
            workers=bounded_workers,
            completed=0,
            failed=0,
            started_at=started_at,
        )
    if not normalized_assets:
        results = [
            result
            for result in result_slots
            if result is not None
        ]
    elif bounded_workers == 1:
        results: list[CloudValidationResult] = []
        for index, asset in enumerate(normalized_assets, start=1):
            try:
                results.append(_worker(asset))
            except Exception:
                _emit_validation_progress(
                    progress_label=progress_label,
                    progress_callback=progress_callback,
                    total=len(normalized_assets),
                    workers=bounded_workers,
                    completed=index,
                    failed=1,
                    started_at=started_at,
                )
                raise
            _emit_validation_progress(
                progress_label=progress_label,
                progress_callback=progress_callback,
                total=len(normalized_assets),
                workers=bounded_workers,
                completed=index,
                failed=0,
                started_at=started_at,
                )
    else:
        results: list[CloudValidationResult] = [
            CloudValidationResult(
                asset_type="unknown",
                identifier="",
                validation_status="UNSUPPORTED",
                validation_method="uninitialised",
                notes="internal placeholder",
            )
        ] * len(normalized_assets)
        completed = 0
        failed = 0
        with ThreadPoolExecutor(max_workers=bounded_workers) as executor:
            future_map = {
                executor.submit(_worker, asset): index
                for index, asset in enumerate(normalized_assets)
            }
            for future in as_completed(future_map):
                index = future_map[future]
                try:
                    results[index] = future.result()
                except Exception:
                    completed += 1
                    failed += 1
                    _emit_validation_progress(
                        progress_label=progress_label,
                        progress_callback=progress_callback,
                        total=len(normalized_assets),
                        workers=bounded_workers,
                        completed=completed,
                        failed=failed,
                        started_at=started_at,
                    )
                    raise
                completed += 1
                _emit_validation_progress(
                    progress_label=progress_label,
                    progress_callback=progress_callback,
                    total=len(normalized_assets),
                    workers=bounded_workers,
                    completed=completed,
                    failed=failed,
                    started_at=started_at,
                )

    if normalized_assets:
        for slot_index, result in zip(allowed_indices, results, strict=False):
            result_slots[slot_index] = result
        results = [
            result
            for result in result_slots
            if result is not None
        ]

    status_counts: dict[str, int] = {}
    con = sqlite3.connect(db_path)
    try:
        apply_schema(con)
        run_migrations(con)
        for result in results:
            _persist_validation_result(con, engagement_id, result)
            validation_status = str(result.validation_status or "UNKNOWN").upper()
            status_counts[validation_status] = status_counts.get(validation_status, 0) + 1
        con.commit()
    finally:
        con.close()

    DeterministicFindingEngine(db_path, engagement_id).run()
    payload_results = []
    for result in results:
        payload = result.to_api_dict()
        payload["engagement_id"] = engagement_id
        payload_results.append(payload)
    return {
        "status": "success",
        "engagement_id": engagement_id,
        "attempted": original_count,
        "succeeded": len(results),
        "failed": 0,
        "status_counts": status_counts,
        "results": payload_results,
    }


def sweep_pending_cloud_validations(
    engagement_id: int,
    db_path: Path,
    *,
    limit: int = 16,
    max_workers: int | None = None,
    only_unattempted: bool = False,
    progress_label: str | None = None,
    progress_callback: Callable[[str, dict[str, object]], None] | None = None,
    key_scope_checker: Callable[[dict[str, Any]], bool] | None = None,
    key_scope_denied_callback: Callable[[dict[str, Any], str], None] | None = None,
) -> dict[str, Any]:
    """Validate pending cloud-related key findings for an engagement."""
    from forge.utils.intel.secret_finder import load_validatable_primary_patterns  # noqa: PLC0415

    worker_count = _resolve_validation_max_workers(max_workers)
    validatable_patterns = [
        pattern
        for pattern in load_validatable_primary_patterns()
        if pattern.service.lower() not in _CLOUD_SECRET_BACKED_SERVICES
    ]
    pattern_clause = " OR ".join("(service=? AND pattern_name=?)" for _ in validatable_patterns) or "0"
    cloud_service_placeholders = ",".join("?" for _ in _CLOUD_SECRET_BACKED_SERVICES)
    rows, claim_owner, claimed_key_ids = claim_pending_cloud_key_rows(
        engagement_id,
        db_path,
        cloud_service_placeholders=cloud_service_placeholders,
        pattern_clause=pattern_clause,
        query_tail_params=(
            *_CLOUD_SECRET_BACKED_SERVICES,
            *[
                value
                for pattern in validatable_patterns
                for value in (pattern.service.lower(), pattern.name)
            ],
        ),
        only_unattempted=only_unattempted,
        limit=limit,
    )

    summary = CloudValidationSweepSummary(attempted=len(rows))
    if not rows:
        return {
            "status": "success",
            "engagement_id": engagement_id,
            "attempted": 0,
            "succeeded": 0,
            "failed": 0,
            "status_counts": {},
            "results": [],
        }

    def _scope_gate_key_row_entry(item: tuple[int, dict[str, Any]]) -> dict[str, Any]:
        index, row_payload = item
        allowed = True
        denial_reason = "scope_manifest_denied"
        if key_scope_checker is not None:
            try:
                allowed = bool(key_scope_checker(row_payload))
            except Exception as exc:  # noqa: BLE001
                allowed = False
                denial_reason = f"scope_checker_error:{type(exc).__name__}"
        return {
            "index": index,
            "row_payload": row_payload,
            "allowed": allowed,
            "denial_reason": denial_reason,
        }

    scoped_rows = _run_ordered_validation_local_batch(
        list(enumerate(rows)),
        _scope_gate_key_row_entry,
        max_workers=worker_count,
    )

    allowed_rows: list[dict[str, Any]] = []
    denied_results: list[dict[str, Any]] = []
    for scoped_row in scoped_rows:
        row_payload = scoped_row["row_payload"]
        allowed = bool(scoped_row["allowed"])
        denial_reason = str(scoped_row["denial_reason"] or "scope_manifest_denied")
        if allowed:
            allowed_rows.append(row_payload)
            continue
        if key_scope_denied_callback is not None:
            try:
                key_scope_denied_callback(row_payload, denial_reason)
            except Exception:  # noqa: BLE001
                pass
        service = str(row_payload.get("service") or "unknown").strip().lower() or "unknown"
        denied_results.append(
            {
                "key_id": int(row_payload["id"]),
                "engagement_id": int(row_payload["engagement_id"]),
                "result": CloudValidationResult(
                    asset_type=service,
                    identifier=_key_validation_identifier(row_payload, service),
                    validation_status="UNVERIFIED",
                    validation_method="scope_manifest",
                    evidence="scope denied before key validation",
                    notes=denial_reason,
                ),
            }
        )

    bounded_workers = max(1, min(worker_count, len(allowed_rows) or 1))
    registry = CloudValidatorRegistry()
    started_at = time.perf_counter()

    def _worker(row_payload: dict[str, Any]) -> dict[str, Any]:
        try:
            key_id, result_engagement_id, result = _validate_key_row_payload(
                row_payload,
                registry=registry,
                db_path=db_path,
            )
            return {
                "key_id": key_id,
                "engagement_id": result_engagement_id,
                "result": result,
            }
        except Exception as exc:  # noqa: BLE001
            return {
                "key_id": int(row_payload["id"]),
                "engagement_id": int(row_payload["engagement_id"]),
                "error": str(exc),
            }

    _emit_validation_progress(
        progress_label=progress_label,
        progress_callback=progress_callback,
        total=len(allowed_rows),
        workers=bounded_workers,
        completed=0,
        failed=0,
        started_at=started_at,
    )
    if not allowed_rows:
        processed_results = denied_results
    elif bounded_workers == 1:
        processed_results: list[dict[str, Any]] = []
        failed_items = 0
        for index, row in enumerate(allowed_rows, start=1):
            item = _worker(row)
            processed_results.append(item)
            if item.get("error"):
                failed_items += 1
            _emit_validation_progress(
                progress_label=progress_label,
                progress_callback=progress_callback,
                total=len(allowed_rows),
                workers=bounded_workers,
                completed=index,
                failed=failed_items,
                started_at=started_at,
            )
    else:
        processed_results: list[dict[str, Any] | None] = [None] * len(allowed_rows)
        completed = 0
        failed_items = 0
        with ThreadPoolExecutor(max_workers=bounded_workers) as executor:
            future_map = {
                executor.submit(_worker, row): index
                for index, row in enumerate(allowed_rows)
            }
            for future in as_completed(future_map):
                index = future_map[future]
                processed_results[index] = future.result()
                completed += 1
                item = processed_results[index]
                if isinstance(item, dict) and item.get("error"):
                    failed_items += 1
                _emit_validation_progress(
                    progress_label=progress_label,
                    progress_callback=progress_callback,
                    total=len(allowed_rows),
                    workers=bounded_workers,
                    completed=completed,
                    failed=failed_items,
                    started_at=started_at,
                )
        processed_results = [
            result
            for result in processed_results
            if result is not None
        ]
    if allowed_rows and denied_results:
        processed_results = denied_results + processed_results

    payload_results: list[dict[str, Any]] = []
    con = sqlite3.connect(db_path)
    try:
        apply_schema(con)
        run_migrations(con)
        for item in processed_results:
            key_id = int(item["key_id"])
            if item.get("error"):
                summary.failed += 1
                payload_results.append(
                    {
                        "status": "failed",
                        "key_id": key_id,
                        "error": str(item["error"]),
                    }
                )
                continue
            result_engagement_id = int(item["engagement_id"])
            result = item["result"]
            _persist_validation_result(con, result_engagement_id, result)
            _update_key_validation_state(con, key_id, result)
            summary.succeeded += 1
            validation_status = str(result.validation_status or "UNKNOWN").upper()
            summary.status_counts[validation_status] = summary.status_counts.get(validation_status, 0) + 1
            payload = result.to_api_dict()
            payload["key_id"] = key_id
            payload_results.append(payload)
        con.commit()
    finally:
        con.close()

    release_validation_key_claims(
        engagement_id,
        db_path,
        owner=claim_owner,
        key_ids=claimed_key_ids,
    )
    DeterministicFindingEngine(db_path, engagement_id).run()

    return {
        "status": "success",
        "engagement_id": engagement_id,
        "attempted": summary.attempted,
        "succeeded": summary.succeeded,
        "failed": summary.failed,
        "status_counts": summary.status_counts,
        "results": payload_results,
    }


def sweep_pending_cloud_asset_validations(
    engagement_id: int,
    db_path: Path,
    *,
    limit: int = 16,
    max_workers: int | None = None,
    progress_label: str | None = None,
    progress_callback: Callable[[str, dict[str, object]], None] | None = None,
    scope_checker: Callable[[str, str], bool] | None = None,
    scope_denied_callback: Callable[[str, str, str], None] | None = None,
) -> dict[str, Any]:
    """Validate discovered cloud_assets rows that do not yet have results."""
    worker_count = _resolve_validation_max_workers(max_workers)
    rows, claim_owner, claimed_assets = claim_pending_cloud_asset_rows(
        engagement_id,
        db_path,
        limit=limit,
    )

    assets = [
        {
            "asset_type": str(row["asset_type"] or ""),
            "identifier": str(row["identifier"] or ""),
            "provider_identifier": str(row["provider_identifier"] or row["identifier"] or ""),
        }
        for row in rows
        if str(row["asset_type"] or "").strip() and str(row["identifier"] or "").strip()
    ]
    if not assets:
        return {
            "status": "success",
            "engagement_id": engagement_id,
            "attempted": 0,
            "succeeded": 0,
            "failed": 0,
            "status_counts": {},
            "results": [],
        }

    def _scope_gate_pending_cloud_asset_entry(
        item: tuple[int, dict[str, str]],
    ) -> dict[str, Any]:
        index, asset = item
        asset_type = asset["asset_type"]
        provider_identifier = asset["provider_identifier"]
        identifier = str(provider_identifier or "").strip().lower()
        allowed = True
        denial_reason = "scope_manifest_denied"
        if scope_checker is not None:
            try:
                allowed = bool(scope_checker(asset_type, identifier))
            except Exception as exc:  # noqa: BLE001
                allowed = False
                denial_reason = f"scope_checker_error:{type(exc).__name__}"
        return {
            "index": index,
            "asset_type": asset_type,
            "identifier": identifier,
            "provider_identifier": provider_identifier,
            "allowed": allowed,
            "denial_reason": denial_reason,
        }

    scoped_assets = _run_ordered_validation_local_batch(
        list(enumerate(assets)),
        _scope_gate_pending_cloud_asset_entry,
        max_workers=worker_count,
    )

    allowed_assets: list[tuple[str, str]] = []
    denied_results: list[CloudValidationResult] = []
    for scoped_asset in scoped_assets:
        asset_type = str(scoped_asset["asset_type"])
        identifier = str(scoped_asset["identifier"])
        provider_identifier = str(scoped_asset["provider_identifier"] or identifier)
        allowed = bool(scoped_asset["allowed"])
        denial_reason = str(scoped_asset["denial_reason"] or "scope_manifest_denied")
        if allowed:
            allowed_assets.append((asset_type, provider_identifier))
            continue
        if scope_denied_callback is not None:
            try:
                scope_denied_callback(asset_type, identifier, denial_reason)
            except Exception:  # noqa: BLE001
                pass
        denied_results.append(
            CloudValidationResult(
                asset_type=asset_type,
                identifier=identifier,
                validation_status="UNVERIFIED",
                validation_method="scope_manifest",
                evidence="scope denied before cloud validation",
                notes=denial_reason,
                provider_identifier=provider_identifier,
            )
        )

    denied_status_counts: dict[str, int] = {}
    denied_payload_results: list[dict[str, Any]] = []
    if denied_results:
        con = sqlite3.connect(db_path)
        try:
            apply_schema(con)
            run_migrations(con)
            for result in denied_results:
                _persist_validation_result(con, engagement_id, result)
                validation_status = str(result.validation_status or "UNKNOWN").upper()
                denied_status_counts[validation_status] = denied_status_counts.get(validation_status, 0) + 1
                payload = result.to_api_dict()
                payload["engagement_id"] = engagement_id
                denied_payload_results.append(payload)
            con.commit()
        finally:
            con.close()

    if not allowed_assets:
        release_validation_asset_claims(
            engagement_id,
            db_path,
            owner=claim_owner,
            assets=claimed_assets,
        )
        DeterministicFindingEngine(db_path, engagement_id).run()
        return {
            "status": "success",
            "engagement_id": engagement_id,
            "attempted": len(assets),
            "succeeded": len(denied_results),
            "failed": 0,
            "status_counts": denied_status_counts,
            "results": denied_payload_results,
        }

    try:
        batch = run_cloud_asset_validate_batch(
            engagement_id,
            allowed_assets,
            db_path,
            max_workers=worker_count,
            progress_label=progress_label,
            progress_callback=progress_callback,
        )
    finally:
        release_validation_asset_claims(
            engagement_id,
            db_path,
            owner=claim_owner,
            assets=claimed_assets,
        )
    status_counts = dict(batch.get("status_counts") or {})
    for key, value in denied_status_counts.items():
        status_counts[str(key)] = int(status_counts.get(str(key), 0) or 0) + int(value or 0)
    return {
        "status": str(batch.get("status") or "success"),
        "engagement_id": engagement_id,
        "attempted": len(assets),
        "succeeded": int(batch.get("succeeded") or 0) + len(denied_results),
        "failed": int(batch.get("failed") or 0),
        "status_counts": status_counts,
        "results": denied_payload_results + list(batch.get("results") or []),
    }


def run_cloud_validate(
    key_id: int,
    rate_limit_bucket: str,
    max_requests_per_minute: int,
    db_path: Path,
    *,
    key_scope_checker: Callable[[dict[str, Any]], bool] | None = None,
    key_scope_denied_callback: Callable[[dict[str, Any], str], None] | None = None,
    rate_limiter: Any | None = None,
) -> dict[str, Any]:
    """Validate a discovered cloud reference using deterministic, low-impact probes."""
    registry = CloudValidatorRegistry()
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        apply_schema(con)
        run_migrations(con)
        row = con.execute(
            """
            SELECT id,
                   engagement_id,
                   domain,
                   service,
                   pattern_name,
                   source_backend,
                   source_url,
                   repo_name,
                   key_enc,
                   validation_detail
            FROM key_scanner_findings
            WHERE id=?
            """,
            (key_id,),
        ).fetchone()
        if row is None:
            return {
                "status": "failed",
                "error": f"key_scanner_findings row {key_id} not found.",
                "key_id": key_id,
            }

        row_payload = dict(row)
        allowed = True
        denial_reason = "scope_manifest_denied"
        if key_scope_checker is not None:
            try:
                allowed = bool(key_scope_checker(row_payload))
            except Exception as exc:  # noqa: BLE001
                allowed = False
                denial_reason = f"scope_checker_error:{type(exc).__name__}"
        if allowed:
            if max_requests_per_minute > 0:
                limiter = rate_limiter or _scheduled_validation_rate_limiter()
                if limiter is not None and not limiter.acquire(
                    rate_limit_bucket,
                    max_requests_per_minute,
                    window_seconds=60,
                ):
                    return {
                        "status": "rate_limited",
                        "error": f"rate limit bucket {rate_limit_bucket!r} exhausted.",
                        "key_id": key_id,
                        "rate_limit_bucket": rate_limit_bucket,
                    }
            _key_id, result_engagement_id, result = _validate_key_row_payload(
                row_payload,
                registry=registry,
                db_path=db_path,
            )
        else:
            if key_scope_denied_callback is not None:
                try:
                    key_scope_denied_callback(row_payload, denial_reason)
                except Exception:  # noqa: BLE001
                    pass
            service = str(row_payload.get("service") or "unknown").strip().lower() or "unknown"
            _key_id = int(row_payload["id"])
            result_engagement_id = int(row_payload["engagement_id"])
            result = CloudValidationResult(
                asset_type=service,
                identifier=_key_validation_identifier(row_payload, service),
                validation_status="UNVERIFIED",
                validation_method="scope_manifest",
                evidence="scope denied before key validation",
                notes=denial_reason,
            )
        _persist_validation_result(con, result_engagement_id, result)
        _update_key_validation_state(con, key_id, result)
        con.commit()
        DeterministicFindingEngine(db_path, result_engagement_id).run()
        payload = result.to_api_dict()
        payload["key_id"] = key_id
        return payload
    except Exception as exc:  # noqa: BLE001
        _LOG.warning("cloud validation failed for key_id=%d: %s", key_id, exc)
        return {
            "status": "failed",
            "error": str(exc),
            "key_id": key_id,
        }
    finally:
        con.close()


def _scheduled_validation_rate_limiter() -> Any | None:
    try:
        from forge.config import ForgeConfig  # noqa: PLC0415
        from forge.distributed.coordinator import RateLimiter  # noqa: PLC0415

        return RateLimiter(redis_url=ForgeConfig.load().redis_url)
    except Exception:  # noqa: BLE001
        return None
