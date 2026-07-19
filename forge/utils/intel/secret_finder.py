"""
forge/utils/intel/secret_finder.py
Canonical: forge/phase2/key_scanner.py  —  Module 2-J

Exposed API Key Discovery & Active Validation.

Pattern-keyed: searches GitHub/GitLab for known API key regexes attributed to
target domain, then validates each key against the provider API.

Distinct from Module 2-I:
  2-I: domain → secrets referencing domain.
  2-J: pattern → matching keys attributed to domain → confirm liveness.

OPSEC (PRD §12.3.9):
  - Use a purpose-built throwaway GitHub account — NEVER operator's personal account.
  - Validation calls logged by provider (AWS CloudTrail, etc.) — attributed and auditable.
  - questionary.confirm() mandatory before any validation call.
  - --validation-proxy required for validation; CLI exits 1 if absent without --no-validate.
  - Keys stored age-encrypted in key_scanner_findings; redacted in all logs.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import sqlite3
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional
from urllib.parse import quote, urlparse

from forge.config import resolve_secret_pool
from forge.db.session import get_engagement_db
from forge.utils.intel.audit_log import insert_audit_log
from forge.utils.intel.http_pacing import key_validation_get, key_validation_post
from forge.utils.ssl_hygiene import restore_default_ssl_context

_LOG = logging.getLogger(__name__)
try:
    from forge.opsec.crypto import encrypt_string
except Exception:
    encrypt_string = None
try:
    from curl_cffi.requests import Session  # type: ignore[import]
except Exception:
    Session = None


def _httpx_client(*args, **kwargs):
    restore_default_ssl_context()
    import httpx  # noqa: PLC0415

    return httpx.Client(*args, **kwargs)

GITHUB_SEARCH_URL = "https://api.github.com/search/code"
GITLAB_SEARCH_URL = "https://gitlab.com/api/v4/search"
GITLAB_PROJECT_URL = "https://gitlab.com/api/v4/projects"
PATTERN_FILE = Path(__file__).parent / "data" / "api_key_patterns.json"

_KEYSCAN_DDL = """
CREATE TABLE IF NOT EXISTS key_scanner_findings (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id    INTEGER NOT NULL REFERENCES engagements(id),
    domain           TEXT NOT NULL,
    service          TEXT NOT NULL,
    pattern_name     TEXT NOT NULL,
    source_backend   TEXT NOT NULL,
    source_url       TEXT NOT NULL,
    repo_name        TEXT,
    key_redacted     TEXT NOT NULL,
    key_enc          TEXT,
    validation_state TEXT NOT NULL DEFAULT 'UNCONFIRMED'
                     CHECK (validation_state IN ('ACTIVE','REVOKED','UNCONFIRMED','ERROR')),
    validation_detail TEXT,
    found_at         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    validated_at     TIMESTAMP,
    UNIQUE(engagement_id, source_url, pattern_name)
);
CREATE INDEX IF NOT EXISTS idx_keyscan_engagement
    ON key_scanner_findings(engagement_id, validation_state);
CREATE INDEX IF NOT EXISTS idx_keyscan_service
    ON key_scanner_findings(service, validation_state);
"""


# ---------------------------------------------------------------------------
# Pattern model
# ---------------------------------------------------------------------------


@dataclass
class KeyPattern:
    name: str
    service: str
    regex: re.Pattern
    confidence: str
    group: int
    validation_method: Optional[str]
    context_required: Optional[str] = None

    def __contains__(self, key: str) -> bool:
        return key in {"name", "service", "pattern", "validation_method", "context_required"}

    def __getitem__(self, key: str):
        if key == "name":
            return self.name
        if key == "service":
            return self.service
        if key == "pattern":
            return self.regex.pattern
        if key == "validation_method":
            return self.validation_method
        if key == "context_required":
            return self.context_required
        raise KeyError(key)


def load_key_patterns(path: Path = PATTERN_FILE) -> list[KeyPattern]:
    if not path.exists():
        _LOG.warning("api_key_patterns.json not found: %s", path)
        return []
    with open(path) as fh:
        data = json.load(fh)
    patterns = []
    for p in data.get("patterns", []):
        try:
            patterns.append(
                KeyPattern(
                    name=p["name"],
                    service=p.get("service", "unknown"),
                    regex=re.compile(p["regex"], re.MULTILINE),
                    confidence=p.get("confidence", "medium"),
                    group=p.get("group", 0),
                    validation_method=p.get("validation_method"),
                    context_required=p.get("context_required"),
                )
            )
        except re.error as exc:
            _LOG.warning("Bad key pattern '%s': %s", p.get("name"), exc)
    return patterns


def _contextual_findings_for_content(
    primary_pattern: KeyPattern,
    patterns: list[KeyPattern],
    content: str,
    base_finding: dict[str, str],
) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    if not content:
        return findings
    for pat in patterns:
        if pat.context_required != primary_pattern.name or pat.service != primary_pattern.service:
            continue
        for match in pat.regex.finditer(content):
            try:
                value = match.group(pat.group) if pat.group else match.group(0)
            except IndexError:
                continue
            if not value:
                continue
            findings.append(
                {
                    "pattern": pat,
                    "key_value": value,
                    "source_url": base_finding["source_url"],
                    "repo_name": base_finding.get("repo_name", ""),
                    "file_path": base_finding.get("file_path", ""),
                    "backend": base_finding["backend"],
                }
            )
            break
    return findings


# ---------------------------------------------------------------------------
# Validation framework
# ---------------------------------------------------------------------------


class ValidationState(str, Enum):
    ACTIVE = "ACTIVE"
    REVOKED = "REVOKED"
    UNCONFIRMED = "UNCONFIRMED"
    ERROR = "ERROR"


@dataclass
class ValidationResult:
    state: ValidationState
    detail: Optional[str] = None


class BaseKeyValidator(ABC):
    """Abstract base for per-service key validators."""

    result_validation_method = "validator_api"

    @abstractmethod
    def validate(self, key: str, proxy: Optional[str] = None, **kwargs) -> ValidationResult: ...


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
_PROFILE_PROOF_PLACEHOLDER_TOKENS = _OPAQUE_PROVIDER_PLACEHOLDER_IDENTIFIERS | {
    "avatar",
    "avatars",
    "image",
    "images",
    "jpeg",
    "jpg",
    "png",
    "gif",
    "svg",
    "webp",
    "photo",
    "photos",
    "picture",
    "pictures",
}
_PROFILE_PROOF_RESERVED_HOSTS = {
    "example.com",
    "example.net",
    "example.org",
    "example.test",
    "example.invalid",
    "localhost",
}


def _profile_proof_host_is_reserved(host: str) -> bool:
    normalized = str(host or "").strip().lower().strip(".")
    if normalized in _PROFILE_PROOF_RESERVED_HOSTS:
        return True
    return any(
        normalized.endswith(f".{reserved_host}")
        for reserved_host in _PROFILE_PROOF_RESERVED_HOSTS
    )


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


def _stable_provider_identifier(value: object, pattern: str) -> str:
    candidate = re.sub(r"[^A-Za-z0-9_-]+", "", str(value or "").strip())
    if not re.fullmatch(pattern, candidate):
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


def _stable_numeric_identifier(value: object, *, min_len: int = 3, max_len: int = 32) -> str:
    candidate = re.sub(r"[^0-9]+", "", str(value or "").strip())
    if not re.fullmatch(rf"[0-9]{{{min_len},{max_len}}}", candidate):
        return ""
    if len(set(candidate)) == 1:
        return ""
    if _looks_sequential_numeric_identifier(candidate):
        return ""
    return candidate


def _looks_sequential_numeric_identifier(value: object) -> bool:
    candidate = re.sub(r"[^0-9]+", "", str(value or "").strip())
    if len(candidate) < 6:
        return False
    digits = [int(char) for char in candidate]
    ascending = all((right - left) % 10 == 1 for left, right in zip(digits, digits[1:]))
    descending = all((left - right) % 10 == 1 for left, right in zip(digits, digits[1:]))
    return ascending or descending


def _profile_proof_url_is_low_signal(value: str) -> bool:
    parsed = urlparse(value)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return False
    host = parsed.hostname.lower().strip(".")
    if _profile_proof_host_is_reserved(host):
        return True
    path_tokens = [
        token
        for token in re.findall(r"[a-z0-9]+", parsed.path.lower())
        if len(token) > 1
    ]
    return bool(path_tokens) and all(
        token in _PROFILE_PROOF_PLACEHOLDER_TOKENS for token in path_tokens
    )


def _profile_proof_email_is_low_signal(value: str) -> bool:
    email = str(value or "").strip().lower()
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        return True
    local_part, domain = email.rsplit("@", 1)
    if (
        _profile_proof_host_is_reserved(domain)
        or domain.endswith(".example")
    ):
        return True
    local_compact = re.sub(r"[^a-z0-9]+", "", local_part)
    if (
        len(local_compact) >= 3
        and (
            local_compact in _PROFILE_PROOF_PLACEHOLDER_TOKENS
            or _looks_repeated_compact_identifier(local_compact)
        )
    ):
        return True
    return False


def _profile_proof_text_is_low_signal(value: str) -> bool:
    tokens = [token for token in re.findall(r"[a-z0-9]+", str(value or "").lower()) if token]
    return bool(tokens) and all(token in _PROFILE_PROOF_PLACEHOLDER_TOKENS for token in tokens)


def _has_profile_presence_proof(payload: object, fields: tuple[str, ...]) -> bool:
    if not isinstance(payload, dict):
        return False
    for field in fields:
        raw = str(payload.get(field) or "").strip()
        if not raw:
            continue
        if field == "email" and re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", raw):
            if not _profile_proof_email_is_low_signal(raw):
                return True
            continue
        if _profile_proof_url_is_low_signal(raw):
            continue
        if _profile_proof_text_is_low_signal(raw):
            continue
        compact = re.sub(r"[^A-Za-z0-9]+", "", raw).lower()
        if (
            len(compact) >= 3
            and compact not in _PROFILE_PROOF_PLACEHOLDER_TOKENS
            and not _looks_repeated_compact_identifier(compact)
        ):
            return True
    return False


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
    if candidate not in {"active", "suspended", "closed"}:
        return ""
    return candidate


def _stable_azure_storage_account_name(value: object) -> str:
    candidate = str(value or "").strip().lower()
    if not re.fullmatch(r"[a-z0-9]{3,24}", candidate):
        return ""
    if candidate in _OPAQUE_PROVIDER_PLACEHOLDER_IDENTIFIERS:
        return ""
    if _looks_repeated_compact_identifier(candidate):
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


def _stable_organization_slug_identifier(value: object, *, allow_dot: bool = False) -> str:
    candidate = _stable_handle_identifier(value, allow_dot=allow_dot)
    if not candidate:
        return ""
    tokens = [token for token in re.split(r"[^a-z0-9]+", candidate.lower()) if token]
    if tokens and all(token in _OPAQUE_PROVIDER_PLACEHOLDER_IDENTIFIERS for token in tokens):
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


def _stable_model_identifiers_from_payload(
    payload: object,
    *,
    collection_key: str,
    field_name: str,
    require_models_prefix: bool = False,
    provider_family: str | None = None,
    limit: int = 3,
) -> list[str]:
    if not isinstance(payload, dict):
        return []
    models = payload.get(collection_key)
    if not isinstance(models, list):
        return []
    names: list[str] = []
    for item in models:
        if not isinstance(item, dict):
            continue
        name = _stable_model_identifier(
            item.get(field_name),
            require_models_prefix=require_models_prefix,
            provider_family=provider_family,
        )
        if not name or name in names:
            continue
        names.append(name)
        if len(names) >= limit:
            break
    return names


def _parse_azure_storage_connection_string(value: str) -> dict[str, str]:
    parts: dict[str, str] = {}
    for segment in str(value or "").split(";"):
        if "=" not in segment:
            continue
        raw_key, raw_value = segment.split("=", 1)
        key = raw_key.strip().lower()
        if not key:
            continue
        parts[key] = raw_value.strip()
    return parts


class AwsKeyValidator(BaseKeyValidator):
    """
    Calls STS GetCallerIdentity.
    Requires both key ID and secret; returns UNCONFIRMED if secret absent.
    Routes through validation_proxy for attribution separation.
    """

    _STS_ENDPOINT = "https://sts.amazonaws.com/"
    result_validation_method = "aws_sts_get_caller_identity"

    def validate(
        self, key: str, secret: Optional[str] = None, proxy: Optional[str] = None, **kwargs
    ) -> ValidationResult:
        if not secret:
            return ValidationResult(
                state=ValidationState.UNCONFIRMED,
                detail="AWS secret key not co-located with access key — cannot validate",
            )
        try:
            import base64
            import datetime as _dt
            import hashlib
            import hmac

            from curl_cffi.requests import Session  # type: ignore[import]

            # Minimal STS GetCallerIdentity signed request.
            now = _dt.datetime.now(_dt.timezone.utc)
            ts = now.strftime("%Y%m%dT%H%M%SZ")
            date = now.strftime("%Y%m%d")
            region = "us-east-1"
            service_name = "sts"

            payload = "Action=GetCallerIdentity&Version=2011-06-15"
            canon = (
                f"POST\n/\n\n"
                f"content-type:application/x-www-form-urlencoded\n"
                f"host:sts.amazonaws.com\n"
                f"x-amz-date:{ts}\n\n"
                f"content-type;host;x-amz-date\n" + hashlib.sha256(payload.encode()).hexdigest()
            )
            sts_to_sign = (
                f"AWS4-HMAC-SHA256\n{ts}\n"
                f"{date}/{region}/{service_name}/aws4_request\n"
                + hashlib.sha256(canon.encode()).hexdigest()
            )

            def _sign(key_bytes: bytes, msg: str) -> bytes:
                return hmac.new(key_bytes, msg.encode(), hashlib.sha256).digest()

            signing_key = _sign(
                _sign(
                    _sign(
                        _sign(f"AWS4{secret}".encode(), date),
                        region,
                    ),
                    service_name,
                ),
                "aws4_request",
            )
            sig = hmac.new(signing_key, sts_to_sign.encode(), hashlib.sha256).hexdigest()
            auth = (
                f"AWS4-HMAC-SHA256 Credential={key}/{date}/{region}/{service_name}/aws4_request,"
                f"SignedHeaders=content-type;host;x-amz-date,Signature={sig}"
            )

            proxies = {"https": proxy} if proxy else None
            with Session(impersonate="chrome124") as client:
                resp = key_validation_post(
                    client,
                    self._STS_ENDPOINT,
                    data=payload,
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded",
                        "x-amz-date": ts,
                        "Authorization": auth,
                    },
                    proxies=proxies,
                    timeout=10,
                    verify=False,
                )

            if resp.status_code == 200:
                import xml.etree.ElementTree as ET

                try:
                    root = ET.fromstring(resp.text)
                except Exception:  # noqa: BLE001
                    return ValidationResult(
                        state=ValidationState.UNCONFIRMED,
                        detail="AWS STS response was not parseable XML",
                    )
                ns = "{https://sts.amazonaws.com/doc/2011-06-15/}"
                acct_id = (
                    root.findtext(f".//{ns}Account")
                    or root.findtext(".//Account")
                    or ""
                ).strip()
                acct_id = _stable_numeric_identifier(acct_id, min_len=12, max_len=12)
                if not acct_id:
                    return ValidationResult(
                        state=ValidationState.UNCONFIRMED,
                        detail="AWS STS response missing AccountId",
                    )
                return ValidationResult(
                    state=ValidationState.ACTIVE, detail=f"AWS AccountId: {acct_id}"
                )
            if resp.status_code in (401, 403):
                return ValidationResult(
                    state=ValidationState.REVOKED, detail=f"HTTP {resp.status_code}"
                )
            if resp.status_code == 429:
                return ValidationResult(state=ValidationState.UNCONFIRMED, detail="HTTP 429")
            return ValidationResult(state=ValidationState.ERROR, detail=f"HTTP {resp.status_code}")
        except Exception as exc:
            return ValidationResult(state=ValidationState.ERROR, detail=str(exc))


class GithubPatValidator(BaseKeyValidator):
    result_validation_method = "github_user_api"
    _CLASSIC_PAT_RE = re.compile(r"ghp_[A-Za-z0-9]{36}")
    _FINE_GRAINED_PAT_RE = re.compile(r"github_pat_[A-Za-z0-9_]{82}")

    @staticmethod
    def _user_login(payload: object) -> str:
        if not isinstance(payload, dict):
            return ""
        return _stable_handle_identifier(payload.get("login"), allow_dot=False)

    @staticmethod
    def _user_id(payload: object) -> str:
        if not isinstance(payload, dict):
            return ""
        return _stable_numeric_identifier(payload.get("id"), min_len=2, max_len=16)

    @staticmethod
    def _has_user_profile_proof(payload: object) -> bool:
        if not isinstance(payload, dict):
            return False
        return _has_profile_presence_proof(
            payload,
            ("name", "avatar_url", "html_url", "blog", "email"),
        )

    @staticmethod
    def _user_detail(payload: object) -> str:
        user_id = GithubPatValidator._user_id(payload)
        login = GithubPatValidator._user_login(payload)
        return (
            "GitHub user ok: "
            f"user_id={user_id or 'unknown'} "
            f"login={login or 'unknown'} "
            "user_profile_present=true"
        )

    def validate(self, key: str, proxy: Optional[str] = None, **kwargs) -> ValidationResult:
        del kwargs
        token = str(key or "").strip()
        if not (
            self._CLASSIC_PAT_RE.fullmatch(token)
            or self._FINE_GRAINED_PAT_RE.fullmatch(token)
        ):
            return ValidationResult(
                state=ValidationState.UNCONFIRMED,
                detail="GitHub PAT shape is invalid for deterministic validation",
            )
        try:
            import httpx

            with _httpx_client(proxy=proxy, timeout=10) as client:
                resp = key_validation_get(
                    client,
                    "https://api.github.com/user",
                    headers={"Authorization": f"Bearer {token}"},
                )
            if resp.status_code == 200:
                try:
                    payload = resp.json()
                except Exception:  # noqa: BLE001
                    payload = {}
                login = self._user_login(payload)
                if not login:
                    return ValidationResult(
                        state=ValidationState.UNCONFIRMED,
                        detail="GitHub user response missing login",
                    )
                if not self._user_id(payload):
                    return ValidationResult(
                        state=ValidationState.UNCONFIRMED,
                        detail="GitHub user response missing user id",
                    )
                if not self._has_user_profile_proof(payload):
                    return ValidationResult(
                        state=ValidationState.UNCONFIRMED,
                        detail="GitHub user response missing user proof",
                    )
                return ValidationResult(
                    state=ValidationState.ACTIVE,
                    detail=self._user_detail(payload),
                )
            if resp.status_code == 401:
                return ValidationResult(state=ValidationState.REVOKED, detail="401 Unauthorized")
            if resp.status_code in (403, 429):
                return ValidationResult(
                    state=ValidationState.UNCONFIRMED,
                    detail=f"HTTP {resp.status_code}",
                )
            return ValidationResult(state=ValidationState.ERROR, detail=f"HTTP {resp.status_code}")
        except Exception as exc:
            return ValidationResult(state=ValidationState.ERROR, detail=str(exc))


class GitlabPatValidator(BaseKeyValidator):
    """Validate GitLab PAT usability with a read-only current-user lookup."""

    _USER_URL = "https://gitlab.com/api/v4/user"
    result_validation_method = "gitlab_current_user_api"

    @staticmethod
    def _user_identifier(payload: object) -> str:
        if not isinstance(payload, dict):
            return ""
        username = _stable_handle_identifier(payload.get("username"))
        if not username:
            username = _stable_handle_identifier(payload.get("login"))
        return username

    @staticmethod
    def _user_id(payload: object) -> str:
        if not isinstance(payload, dict):
            return ""
        return _stable_numeric_identifier(payload.get("id"), min_len=2, max_len=16)

    @staticmethod
    def _has_user_profile_proof(payload: object) -> bool:
        if not isinstance(payload, dict):
            return False
        return _has_profile_presence_proof(
            payload,
            ("name", "avatar_url", "web_url", "public_email", "email"),
        )

    @staticmethod
    def _user_detail(payload: object) -> str:
        username = GitlabPatValidator._user_identifier(payload)
        user_id = GitlabPatValidator._user_id(payload)
        return (
            "GitLab user ok: "
            f"user_id={user_id or 'unknown'} "
            f"username={username or 'unknown'} "
            "user_profile_present=true"
        )

    def validate(self, key: str, proxy: Optional[str] = None, **kwargs) -> ValidationResult:
        del kwargs
        if not re.fullmatch(r"glpat-[0-9A-Za-z\-_]{20}", str(key or "").strip()):
            return ValidationResult(
                state=ValidationState.UNCONFIRMED,
                detail="GitLab PAT shape is invalid for deterministic validation",
            )
        try:
            import httpx

            with _httpx_client(proxy=proxy, timeout=10) as client:
                resp = key_validation_get(client, self._USER_URL, headers={"PRIVATE-TOKEN": key})
            if resp.status_code == 200:
                try:
                    payload = resp.json()
                except Exception:  # noqa: BLE001
                    payload = {}
                if not self._user_identifier(payload):
                    return ValidationResult(
                        state=ValidationState.UNCONFIRMED,
                        detail="GitLab user response missing username",
                    )
                if not self._user_id(payload):
                    return ValidationResult(
                        state=ValidationState.UNCONFIRMED,
                        detail="GitLab user response missing user id",
                    )
                if not self._has_user_profile_proof(payload):
                    return ValidationResult(
                        state=ValidationState.UNCONFIRMED,
                        detail="GitLab user response missing user proof",
                    )
                return ValidationResult(
                    state=ValidationState.ACTIVE,
                    detail=self._user_detail(payload),
                )
            if resp.status_code in (401, 403):
                return ValidationResult(
                    state=ValidationState.UNCONFIRMED,
                    detail=f"HTTP {resp.status_code}: not valid for gitlab.com or insufficient scope",
                )
            if resp.status_code == 429:
                return ValidationResult(state=ValidationState.UNCONFIRMED, detail="HTTP 429")
            return ValidationResult(state=ValidationState.ERROR, detail=f"HTTP {resp.status_code}")
        except Exception as exc:
            return ValidationResult(state=ValidationState.ERROR, detail=str(exc))


class StripeKeyValidator(BaseKeyValidator):
    result_validation_method = "stripe_balance_api"
    _LIVE_KEY_RE = re.compile(r"(?:sk_live|rk_live)_[0-9A-Za-z]{24,}")

    @staticmethod
    def _balance_detail(payload: object) -> str:
        if not isinstance(payload, dict):
            return "Stripe balance accessible: mode=unknown currencies=unknown"
        livemode = payload.get("livemode")
        if isinstance(livemode, bool):
            mode = "live" if livemode else "test"
        else:
            mode = "unknown"
        currencies: set[str] = set()
        balance_counts: dict[str, int] = {}
        for family in ("available", "pending"):
            entries = payload.get(family)
            if not isinstance(entries, list):
                balance_counts[family] = 0
                continue
            balance_counts[family] = len(entries)
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                currency = str(entry.get("currency") or "").strip().lower()
                if currency:
                    currencies.add(currency)
        currency_summary = ",".join(sorted(currencies)) if currencies else "none"
        return (
            "Stripe balance accessible: "
            f"mode={mode} "
            f"currencies={currency_summary} "
            f"balances=available:{balance_counts.get('available', 0)},"
            f"pending:{balance_counts.get('pending', 0)}"
        )

    @staticmethod
    def _has_balance_proof(payload: object) -> bool:
        if not isinstance(payload, dict):
            return False
        if str(payload.get("object") or "").strip().lower() != "balance":
            return False
        if payload.get("livemode") is not True:
            return False
        return isinstance(payload.get("available"), list) and isinstance(payload.get("pending"), list)

    def validate(self, key: str, proxy: Optional[str] = None, **kwargs) -> ValidationResult:
        del kwargs
        token = str(key or "").strip()
        if not self._LIVE_KEY_RE.fullmatch(token):
            return ValidationResult(
                state=ValidationState.UNCONFIRMED,
                detail="Stripe key shape is invalid for deterministic validation",
            )
        try:
            import base64 as _b64
            import httpx

            auth = _b64.b64encode(f"{token}:".encode()).decode()
            with _httpx_client(proxy=proxy, timeout=10) as client:
                resp = key_validation_get(
                    client,
                    "https://api.stripe.com/v1/balance",
                    headers={"Authorization": f"Basic {auth}"},
                )
            if resp.status_code == 200:
                try:
                    payload = resp.json()
                except Exception:  # noqa: BLE001
                    payload = {}
                if not self._has_balance_proof(payload):
                    if str(payload.get("object") or "").strip().lower() != "balance":
                        detail = "Stripe balance response missing balance object"
                    else:
                        detail = "Stripe balance response missing balance proof"
                    return ValidationResult(
                        state=ValidationState.UNCONFIRMED,
                        detail=detail,
                    )
                return ValidationResult(
                    state=ValidationState.ACTIVE,
                    detail=self._balance_detail(payload),
                )
            if resp.status_code == 401:
                return ValidationResult(state=ValidationState.REVOKED, detail="401 Unauthorized")
            if resp.status_code in (403, 429):
                return ValidationResult(
                    state=ValidationState.UNCONFIRMED,
                    detail=f"HTTP {resp.status_code}",
                )
            return ValidationResult(state=ValidationState.ERROR, detail=f"HTTP {resp.status_code}")
        except Exception as exc:
            return ValidationResult(state=ValidationState.ERROR, detail=str(exc))


class SendgridKeyValidator(BaseKeyValidator):
    _PROFILE_URL = "https://api.sendgrid.com/v3/user/profile"
    _SCOPES_URL = "https://api.sendgrid.com/v3/scopes"
    _KEY_RE = re.compile(r"^SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}$")
    result_validation_method = "sendgrid_profile_api"

    @staticmethod
    def _profile_proof_fields(payload: object) -> dict[str, str]:
        if not isinstance(payload, dict):
            return {}
        fields: dict[str, str] = {}
        email = str(payload.get("email") or "").strip().lower()
        if email and not _profile_proof_email_is_low_signal(email):
            fields["email"] = email
        username = str(payload.get("username") or "").strip()
        if username and not _profile_proof_text_is_low_signal(username):
            stable_username = _stable_handle_identifier(username)
            if stable_username:
                fields["username"] = stable_username.lower()
        return fields

    @staticmethod
    def _profile_proof_hash(payload: object) -> str:
        for value in SendgridKeyValidator._profile_proof_fields(payload).values():
            if value:
                return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]
        return ""

    @staticmethod
    def _profile_detail(payload: object) -> str:
        if not isinstance(payload, dict):
            return "SendGrid profile ok: proof=profile"
        proof_fields = SendgridKeyValidator._profile_proof_fields(payload)
        email_present = "email" in proof_fields
        username_present = "username" in proof_fields
        parts = ["proof=profile"]
        proof_hash = SendgridKeyValidator._profile_proof_hash(payload)
        if proof_hash:
            parts.append(f"profile_hash={proof_hash}")
        if email_present:
            parts.append("email_present=true")
        if username_present:
            parts.append("username_present=true")
        return "SendGrid profile ok: " + " ".join(parts)

    @staticmethod
    def _scopes_detail(payload: object) -> str:
        stable_count = SendgridKeyValidator._stable_scope_count(payload)
        scope_hash = SendgridKeyValidator._scopes_proof_hash(payload)
        if stable_count > 0 and scope_hash:
            return f"SendGrid scopes accessible: count={stable_count} scope_hash={scope_hash}"
        return "SendGrid scopes accessible"

    @staticmethod
    def _has_profile_proof(payload: object) -> bool:
        return bool(SendgridKeyValidator._profile_proof_fields(payload))

    @staticmethod
    def _has_scopes_proof(payload: object) -> bool:
        return SendgridKeyValidator._stable_scope_count(payload) > 0

    @staticmethod
    def _stable_scope_values(payload: object) -> list[str]:
        scopes: object = payload
        if isinstance(payload, dict):
            scopes = payload.get("scopes") or payload.get("scope") or payload.get("permissions")
        if not isinstance(scopes, list):
            return []
        stable_scopes: list[str] = []
        for raw_scope in scopes:
            scope = str(raw_scope or "").strip().lower()
            compact = re.sub(r"[^a-z0-9]+", "", scope)
            if (
                not re.fullmatch(r"[a-z0-9_:-]+(?:[.:][a-z0-9_:-]+)+", scope)
                or len(compact) < 4
                or compact in _PROFILE_PROOF_PLACEHOLDER_TOKENS
                or _looks_repeated_compact_identifier(compact)
            ):
                continue
            stable_scopes.append(scope)
        return stable_scopes

    @staticmethod
    def _stable_scope_count(payload: object) -> int:
        return len(SendgridKeyValidator._stable_scope_values(payload))

    @staticmethod
    def _scopes_proof_hash(payload: object) -> str:
        stable_scopes = SendgridKeyValidator._stable_scope_values(payload)
        if not stable_scopes:
            return ""
        joined = "\n".join(sorted(dict.fromkeys(stable_scopes)))
        return hashlib.sha256(joined.encode("utf-8")).hexdigest()[:16]

    def validate(self, key: str, proxy: Optional[str] = None, **kwargs) -> ValidationResult:
        if not self._KEY_RE.fullmatch(str(key or "").strip()):
            return ValidationResult(
                state=ValidationState.UNCONFIRMED,
                detail="SendGrid API key shape is invalid for deterministic validation",
            )
        try:
            import json as _json

            from curl_cffi.requests import Session  # type: ignore[import]

            proxies = {"https": proxy} if proxy else None
            with Session(impersonate="chrome124") as client:
                resp = key_validation_get(
                    client,
                    self._PROFILE_URL,
                    headers={"Authorization": f"Bearer {key}"},
                    proxies=proxies,
                    timeout=10,
                )
            if resp.status_code == 200:
                try:
                    payload = _json.loads(resp.text or "{}")
                except Exception:  # noqa: BLE001
                    payload = {}
                if not self._has_profile_proof(payload):
                    return ValidationResult(
                        state=ValidationState.UNCONFIRMED,
                        detail="SendGrid profile response missing profile proof",
                    )
                return ValidationResult(
                    state=ValidationState.ACTIVE,
                    detail=self._profile_detail(payload),
                )
            if resp.status_code == 403:
                with Session(impersonate="chrome124") as client:
                    scopes_resp = key_validation_get(
                        client,
                        self._SCOPES_URL,
                        headers={"Authorization": f"Bearer {key}"},
                        proxies=proxies,
                        timeout=10,
                    )
                if scopes_resp.status_code == 200:
                    try:
                        scopes_payload = _json.loads(scopes_resp.text or "{}")
                    except Exception:  # noqa: BLE001
                        scopes_payload = {}
                    if not self._has_scopes_proof(scopes_payload):
                        return ValidationResult(
                            state=ValidationState.UNCONFIRMED,
                            detail="SendGrid scopes response missing scopes list",
                        )
                    return ValidationResult(
                        state=ValidationState.ACTIVE,
                        detail=self._scopes_detail(scopes_payload),
                    )
                if scopes_resp.status_code == 401:
                    return ValidationResult(state=ValidationState.REVOKED, detail="401 Unauthorized")
                if scopes_resp.status_code == 429:
                    return ValidationResult(state=ValidationState.UNCONFIRMED, detail="HTTP 429")
                return ValidationResult(state=ValidationState.ERROR, detail=f"HTTP {scopes_resp.status_code}")
            if resp.status_code == 401:
                return ValidationResult(state=ValidationState.REVOKED, detail="401 Unauthorized")
            if resp.status_code == 429:
                return ValidationResult(state=ValidationState.UNCONFIRMED, detail="HTTP 429")
            return ValidationResult(state=ValidationState.ERROR, detail=f"HTTP {resp.status_code}")
        except Exception as exc:
            return ValidationResult(state=ValidationState.ERROR, detail=str(exc))


class MailchimpKeyValidator(BaseKeyValidator):
    _PING_PATH = "/3.0/ping"
    _KEY_RE = re.compile(r"^[0-9a-fA-F]{32}-[a-z]{2}[0-9]{1,2}$", re.IGNORECASE)
    result_validation_method = "mailchimp_ping_api"

    @staticmethod
    def _extract_datacenter(key: str) -> str:
        match = re.search(r"-([a-z]{2}[0-9]{1,2})$", str(key or "").strip(), re.IGNORECASE)
        if not match:
            return ""
        return _stable_mailchimp_datacenter(match.group(1))

    def validate(self, key: str, proxy: Optional[str] = None, **kwargs) -> ValidationResult:
        del kwargs
        if not self._KEY_RE.fullmatch(str(key or "").strip()):
            return ValidationResult(
                state=ValidationState.UNCONFIRMED,
                detail="Mailchimp API key shape is invalid for deterministic validation",
            )
        datacenter = self._extract_datacenter(key)
        if not datacenter:
            return ValidationResult(
                state=ValidationState.UNCONFIRMED,
                detail="Mailchimp API key missing datacenter suffix",
            )
        try:
            import httpx

            with _httpx_client(proxy=proxy, timeout=10) as client:
                resp = key_validation_get(
                    client,
                    f"https://{datacenter}.api.mailchimp.com{self._PING_PATH}",
                    auth=("forge", key),
                )
            if resp.status_code == 200:
                try:
                    payload = resp.json()
                except Exception:  # noqa: BLE001
                    payload = {}
                health = str(payload.get("health_status") or "").strip()
                stable_health = _stable_mailchimp_health_status(health)
                if not stable_health:
                    return ValidationResult(
                        state=ValidationState.UNCONFIRMED,
                        detail="Mailchimp ping response missing health_status proof",
                    )
                detail = f"Mailchimp ping ok: dc={datacenter}"
                detail = f"{detail} health={stable_health}"
                return ValidationResult(state=ValidationState.ACTIVE, detail=detail)
            if resp.status_code in (401, 403):
                return ValidationResult(
                    state=ValidationState.REVOKED,
                    detail=f"HTTP {resp.status_code}",
                )
            if resp.status_code == 429:
                return ValidationResult(state=ValidationState.UNCONFIRMED, detail="HTTP 429")
            return ValidationResult(state=ValidationState.ERROR, detail=f"HTTP {resp.status_code}")
        except Exception as exc:
            return ValidationResult(state=ValidationState.ERROR, detail=str(exc))


class GoogleApiKeyValidator(BaseKeyValidator):
    """Validate Google/Gemini API-key usability with a read-only model-list call."""

    _MODELS_URL = "https://generativelanguage.googleapis.com/v1beta/models"
    result_validation_method = "google_generative_language_models_list"

    @staticmethod
    def _error_detail(payload: object, fallback: str) -> str:
        if not isinstance(payload, dict):
            return fallback
        error = payload.get("error")
        if isinstance(error, dict):
            status = str(error.get("status") or "").strip()
            message = str(error.get("message") or "").strip()
            if status and message:
                return f"{status}: {message}"
            return status or message or fallback
        return fallback

    @staticmethod
    def _models_detail(payload: object) -> str:
        if not isinstance(payload, dict):
            return "Google Generative Language models ok: models=unknown"
        models = payload.get("models")
        if not isinstance(models, list):
            return "Google Generative Language models ok: models=unknown"
        names = _stable_model_identifiers_from_payload(
            payload,
            collection_key="models",
            field_name="name",
            require_models_prefix=True,
            provider_family="google",
        )
        detail = f"Google Generative Language models ok: models={len(models)}"
        if names:
            detail = f"{detail} sample={','.join(names)}"
        return detail

    def validate(self, key: str, proxy: Optional[str] = None, **kwargs) -> ValidationResult:
        del kwargs
        if not re.fullmatch(r"AIza[0-9A-Za-z\-_]{35}", str(key or "").strip()):
            return ValidationResult(
                state=ValidationState.UNCONFIRMED,
                detail="Google API key shape is invalid for deterministic validation",
            )
        try:
            import httpx

            with _httpx_client(proxy=proxy, timeout=10) as client:
                resp = key_validation_get(client, self._MODELS_URL, params={"key": key})
            try:
                payload = resp.json()
            except Exception:  # noqa: BLE001
                payload = {}
            if resp.status_code == 200:
                models = payload.get("models") if isinstance(payload, dict) else None
                if not isinstance(models, list) or not models:
                    return ValidationResult(
                        state=ValidationState.UNCONFIRMED,
                        detail="Google Generative Language response missing models",
                    )
                if not _stable_model_identifiers_from_payload(
                    payload,
                    collection_key="models",
                    field_name="name",
                    require_models_prefix=True,
                    provider_family="google",
                ):
                    return ValidationResult(
                        state=ValidationState.UNCONFIRMED,
                        detail="Google Generative Language response missing model identifiers",
                    )
                return ValidationResult(
                    state=ValidationState.ACTIVE,
                    detail=self._models_detail(payload),
                )
            detail = self._error_detail(payload, f"HTTP {resp.status_code}")
            lowered = detail.lower()
            if resp.status_code in (400, 401, 403) and (
                "api key not valid" in lowered
                or "api_key_invalid" in lowered
                or "invalid api key" in lowered
            ):
                return ValidationResult(state=ValidationState.REVOKED, detail=detail)
            if resp.status_code == 429:
                return ValidationResult(state=ValidationState.UNCONFIRMED, detail=detail)
            if resp.status_code in (400, 401, 403):
                return ValidationResult(state=ValidationState.UNCONFIRMED, detail=detail)
            return ValidationResult(state=ValidationState.ERROR, detail=detail)
        except Exception as exc:
            return ValidationResult(state=ValidationState.ERROR, detail=str(exc))


class OpenAIKeyValidator(BaseKeyValidator):
    """Validate OpenAI API-key usability with the read-only models list endpoint."""

    _MODELS_URL = "https://api.openai.com/v1/models"
    result_validation_method = "openai_models_list"

    @staticmethod
    def _error_detail(payload: object, fallback: str) -> str:
        if not isinstance(payload, dict):
            return fallback
        error = payload.get("error")
        if isinstance(error, dict):
            code = str(error.get("code") or "").strip()
            message = str(error.get("message") or "").strip()
            if code and message:
                return f"{code}: {message}"
            return code or message or fallback
        return fallback

    @staticmethod
    def _models_detail(payload: object) -> str:
        if not isinstance(payload, dict):
            return "OpenAI models ok: models=unknown"
        models = payload.get("data")
        if not isinstance(models, list):
            return "OpenAI models ok: models=unknown"
        names = _stable_model_identifiers_from_payload(
            payload,
            collection_key="data",
            field_name="id",
            provider_family="openai",
        )
        detail = f"OpenAI models ok: models={len(models)}"
        if names:
            detail = f"{detail} sample={','.join(names)}"
        return detail

    def validate(self, key: str, proxy: Optional[str] = None, **kwargs) -> ValidationResult:
        del kwargs
        token = str(key or "").strip()
        if not (
            re.fullmatch(r"sk-proj-[A-Za-z0-9_\-]{20,}", token)
            or re.fullmatch(r"sk-[A-Za-z0-9]{48}", token)
        ):
            return ValidationResult(
                state=ValidationState.UNCONFIRMED,
                detail="OpenAI API key shape is invalid for deterministic validation",
            )
        try:
            import httpx

            with _httpx_client(proxy=proxy, timeout=10) as client:
                resp = key_validation_get(
                    client,
                    self._MODELS_URL,
                    headers={"Authorization": f"Bearer {token}"},
                )
            try:
                payload = resp.json()
            except Exception:  # noqa: BLE001
                payload = {}
            if resp.status_code == 200:
                models = payload.get("data") if isinstance(payload, dict) else None
                if not isinstance(models, list) or not models:
                    return ValidationResult(
                        state=ValidationState.UNCONFIRMED,
                        detail="OpenAI models response missing data",
                    )
                if not _stable_model_identifiers_from_payload(
                    payload,
                    collection_key="data",
                    field_name="id",
                    provider_family="openai",
                ):
                    return ValidationResult(
                        state=ValidationState.UNCONFIRMED,
                        detail="OpenAI models response missing model identifiers",
                    )
                return ValidationResult(
                    state=ValidationState.ACTIVE,
                    detail=self._models_detail(payload),
                )
            detail = self._error_detail(payload, f"HTTP {resp.status_code}")
            lowered = detail.lower()
            if resp.status_code == 401 or "invalid api key" in lowered or "invalid_api_key" in lowered:
                return ValidationResult(state=ValidationState.REVOKED, detail=detail)
            if resp.status_code in (403, 429):
                return ValidationResult(state=ValidationState.UNCONFIRMED, detail=detail)
            return ValidationResult(state=ValidationState.ERROR, detail=detail)
        except Exception as exc:
            return ValidationResult(state=ValidationState.ERROR, detail=str(exc))


class AnthropicKeyValidator(BaseKeyValidator):
    """Validate Anthropic API-key usability with the read-only models list endpoint."""

    _MODELS_URL = "https://api.anthropic.com/v1/models"
    _API_VERSION = "2023-06-01"
    result_validation_method = "anthropic_models_list"

    @staticmethod
    def _error_detail(payload: object, fallback: str) -> str:
        if not isinstance(payload, dict):
            return fallback
        error = payload.get("error")
        if isinstance(error, dict):
            err_type = str(error.get("type") or "").strip()
            message = str(error.get("message") or "").strip()
            if err_type and message:
                return f"{err_type}: {message}"
            return err_type or message or fallback
        return fallback

    @staticmethod
    def _models_detail(payload: object) -> str:
        if not isinstance(payload, dict):
            return "Anthropic models ok: models=unknown"
        models = payload.get("data")
        if not isinstance(models, list):
            return "Anthropic models ok: models=unknown"
        names = _stable_model_identifiers_from_payload(
            payload,
            collection_key="data",
            field_name="id",
            provider_family="anthropic",
        )
        detail = f"Anthropic models ok: models={len(models)}"
        if names:
            detail = f"{detail} sample={','.join(names)}"
        return detail

    def validate(self, key: str, proxy: Optional[str] = None, **kwargs) -> ValidationResult:
        del kwargs
        token = str(key or "").strip()
        if not re.fullmatch(r"sk-ant-api[0-9]{2}-[A-Za-z0-9_\-]{20,}", token):
            return ValidationResult(
                state=ValidationState.UNCONFIRMED,
                detail="Anthropic API key shape is invalid for deterministic validation",
            )
        try:
            import httpx

            with _httpx_client(proxy=proxy, timeout=10) as client:
                resp = key_validation_get(
                    client,
                    self._MODELS_URL,
                    headers={
                        "x-api-key": token,
                        "anthropic-version": self._API_VERSION,
                        "accept": "application/json",
                    },
                )
            try:
                payload = resp.json()
            except Exception:  # noqa: BLE001
                payload = {}
            if resp.status_code == 200:
                models = payload.get("data") if isinstance(payload, dict) else None
                if not isinstance(models, list) or not models:
                    return ValidationResult(
                        state=ValidationState.UNCONFIRMED,
                        detail="Anthropic models response missing data",
                    )
                if not _stable_model_identifiers_from_payload(
                    payload,
                    collection_key="data",
                    field_name="id",
                    provider_family="anthropic",
                ):
                    return ValidationResult(
                        state=ValidationState.UNCONFIRMED,
                        detail="Anthropic models response missing model identifiers",
                    )
                return ValidationResult(
                    state=ValidationState.ACTIVE,
                    detail=self._models_detail(payload),
                )
            detail = self._error_detail(payload, f"HTTP {resp.status_code}")
            lowered = detail.lower()
            if resp.status_code == 401 or "authentication_error" in lowered or "invalid x-api-key" in lowered:
                return ValidationResult(state=ValidationState.REVOKED, detail=detail)
            if resp.status_code in (403, 429):
                return ValidationResult(state=ValidationState.UNCONFIRMED, detail=detail)
            return ValidationResult(state=ValidationState.ERROR, detail=detail)
        except Exception as exc:
            return ValidationResult(state=ValidationState.ERROR, detail=str(exc))


class HuggingFaceTokenValidator(BaseKeyValidator):
    """Validate Hugging Face tokens with a read-only current-account lookup."""

    _WHOAMI_URL = "https://huggingface.co/api/whoami-v2"
    result_validation_method = "huggingface_whoami_v2"

    @staticmethod
    def _user_identifier(payload: object) -> str:
        if not isinstance(payload, dict):
            return ""
        for key in ("name", "username", "user"):
            value = _stable_handle_identifier(payload.get(key))
            if value:
                return value
        return ""

    @staticmethod
    def _has_user_profile_proof(payload: object) -> bool:
        if not isinstance(payload, dict):
            return False
        return _has_profile_presence_proof(
            payload,
            ("email", "fullname", "avatarUrl", "avatar_url"),
        )

    @staticmethod
    def _error_detail(payload: object, fallback: str) -> str:
        if not isinstance(payload, dict):
            return fallback
        error = str(payload.get("error") or payload.get("message") or "").strip()
        return error or fallback

    def validate(self, key: str, proxy: Optional[str] = None, **kwargs) -> ValidationResult:
        del kwargs
        token = str(key or "").strip()
        if not re.fullmatch(r"hf_[A-Za-z0-9]{20,}", token):
            return ValidationResult(
                state=ValidationState.UNCONFIRMED,
                detail="Hugging Face token shape is invalid for deterministic validation",
            )
        try:
            import httpx

            with _httpx_client(proxy=proxy, timeout=10) as client:
                resp = key_validation_get(
                    client,
                    self._WHOAMI_URL,
                    headers={"Authorization": f"Bearer {token}", "accept": "application/json"},
                )
            try:
                payload = resp.json()
            except Exception:  # noqa: BLE001
                payload = {}
            if resp.status_code == 200:
                user = self._user_identifier(payload)
                if not user:
                    return ValidationResult(
                        state=ValidationState.UNCONFIRMED,
                        detail="Hugging Face whoami response missing user identifier",
                    )
                if not self._has_user_profile_proof(payload):
                    return ValidationResult(
                        state=ValidationState.UNCONFIRMED,
                        detail="Hugging Face whoami response missing user proof",
                    )
                return ValidationResult(
                    state=ValidationState.ACTIVE,
                    detail=f"Hugging Face auth ok: user={user} user_profile_present=true",
                )
            detail = self._error_detail(payload, f"HTTP {resp.status_code}")
            if resp.status_code in (401, 403):
                return ValidationResult(state=ValidationState.REVOKED, detail=detail)
            if resp.status_code == 429:
                return ValidationResult(state=ValidationState.UNCONFIRMED, detail=detail)
            return ValidationResult(state=ValidationState.ERROR, detail=detail)
        except Exception as exc:
            return ValidationResult(state=ValidationState.ERROR, detail=str(exc))


class DiscordBotTokenValidator(BaseKeyValidator):
    """Validate Discord bot tokens with a read-only current-user lookup."""

    _CURRENT_USER_URL = "https://discord.com/api/v10/users/@me"
    result_validation_method = "discord_current_user"

    @staticmethod
    def _bot_identifier(payload: object) -> str:
        if not isinstance(payload, dict):
            return ""
        return _stable_numeric_identifier(payload.get("id"), min_len=15, max_len=22)

    @staticmethod
    def _has_bot_profile_proof(payload: object) -> bool:
        if not isinstance(payload, dict):
            return False
        if payload.get("bot") is not True:
            return False
        return _has_profile_presence_proof(payload, ("username", "global_name"))

    def validate(self, key: str, proxy: Optional[str] = None, **kwargs) -> ValidationResult:
        del kwargs
        token = str(key or "").strip()
        if not re.fullmatch(r"[A-Za-z0-9_\-]{24}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,38}", token):
            return ValidationResult(
                state=ValidationState.UNCONFIRMED,
                detail="Discord bot token shape is invalid for deterministic validation",
            )
        try:
            import httpx

            with _httpx_client(proxy=proxy, timeout=10) as client:
                resp = key_validation_get(
                    client,
                    self._CURRENT_USER_URL,
                    headers={"Authorization": f"Bot {token}", "accept": "application/json"},
                )
            try:
                payload = resp.json()
            except Exception:  # noqa: BLE001
                payload = {}
            if resp.status_code == 200:
                bot_id = self._bot_identifier(payload)
                if not bot_id:
                    return ValidationResult(
                        state=ValidationState.UNCONFIRMED,
                        detail="Discord current user response missing bot id",
                    )
                if not self._has_bot_profile_proof(payload):
                    return ValidationResult(
                        state=ValidationState.UNCONFIRMED,
                        detail="Discord current user response missing bot proof",
                    )
                return ValidationResult(
                    state=ValidationState.ACTIVE,
                    detail=f"Discord bot auth ok: bot_id={bot_id} bot_profile_present=true",
                )
            if resp.status_code in (401, 403):
                return ValidationResult(state=ValidationState.REVOKED, detail=f"HTTP {resp.status_code}")
            if resp.status_code == 429:
                return ValidationResult(state=ValidationState.UNCONFIRMED, detail="HTTP 429")
            return ValidationResult(state=ValidationState.ERROR, detail=f"HTTP {resp.status_code}")
        except Exception as exc:
            return ValidationResult(state=ValidationState.ERROR, detail=str(exc))


class TelegramBotTokenValidator(BaseKeyValidator):
    """Validate Telegram bot tokens with the read-only getMe method."""

    result_validation_method = "telegram_get_me"

    @staticmethod
    def _bot_identifier(payload: object) -> str:
        if not isinstance(payload, dict):
            return ""
        result = payload.get("result")
        if not isinstance(result, dict):
            return ""
        return _stable_numeric_identifier(result.get("id"), min_len=6, max_len=20)

    @staticmethod
    def _has_bot_profile_proof(payload: object) -> bool:
        if not isinstance(payload, dict):
            return False
        result = payload.get("result")
        if not isinstance(result, dict) or result.get("is_bot") is not True:
            return False
        return _has_profile_presence_proof(result, ("username", "first_name"))

    @staticmethod
    def _error_detail(payload: object, fallback: str) -> str:
        if not isinstance(payload, dict):
            return fallback
        description = str(payload.get("description") or "").strip()
        code = str(payload.get("error_code") or "").strip()
        if code and description:
            return f"{code}: {description}"
        return description or fallback

    def validate(self, key: str, proxy: Optional[str] = None, **kwargs) -> ValidationResult:
        del kwargs
        token = str(key or "").strip()
        if not re.fullmatch(r"[0-9]{8,12}:[A-Za-z0-9_\-]{35}", token):
            return ValidationResult(
                state=ValidationState.UNCONFIRMED,
                detail="Telegram bot token shape is invalid for deterministic validation",
            )
        try:
            import httpx

            with _httpx_client(proxy=proxy, timeout=10) as client:
                resp = key_validation_get(
                    client,
                    f"https://api.telegram.org/bot{token}/getMe",
                )
            try:
                payload = resp.json()
            except Exception:  # noqa: BLE001
                payload = {}
            detail = self._error_detail(payload, f"HTTP {resp.status_code}")
            if resp.status_code == 200 and payload.get("ok") is True:
                bot_id = self._bot_identifier(payload)
                if not bot_id:
                    return ValidationResult(
                        state=ValidationState.UNCONFIRMED,
                        detail="Telegram getMe response missing bot id",
                    )
                if not self._has_bot_profile_proof(payload):
                    return ValidationResult(
                        state=ValidationState.UNCONFIRMED,
                        detail="Telegram getMe response missing bot proof",
                    )
                return ValidationResult(
                    state=ValidationState.ACTIVE,
                    detail=f"Telegram bot auth ok: bot_id={bot_id} bot_profile_present=true",
                )
            lowered = detail.lower()
            if resp.status_code in (401, 403, 404) or "unauthorized" in lowered:
                return ValidationResult(state=ValidationState.REVOKED, detail=detail)
            if resp.status_code == 429:
                return ValidationResult(state=ValidationState.UNCONFIRMED, detail=detail)
            return ValidationResult(state=ValidationState.ERROR, detail=detail)
        except Exception as exc:
            return ValidationResult(state=ValidationState.ERROR, detail=str(exc))


class NotionTokenValidator(BaseKeyValidator):
    """Validate Notion tokens with the read-only token owner lookup."""

    _ME_URL = "https://api.notion.com/v1/users/me"
    _API_VERSION = "2026-03-11"
    result_validation_method = "notion_users_me"

    @staticmethod
    def _user_identifier(payload: object) -> str:
        if not isinstance(payload, dict):
            return ""
        return _stable_uuid_or_32hex(payload.get("id"))

    @staticmethod
    def _has_user_profile_proof(payload: object) -> bool:
        return _has_profile_presence_proof(payload, ("name", "avatar_url"))

    @staticmethod
    def _error_detail(payload: object, fallback: str) -> str:
        if not isinstance(payload, dict):
            return fallback
        code = str(payload.get("code") or payload.get("status") or "").strip()
        message = str(payload.get("message") or "").strip()
        if code and message:
            return f"{code}: {message}"
        return code or message or fallback

    def validate(self, key: str, proxy: Optional[str] = None, **kwargs) -> ValidationResult:
        del kwargs
        token = str(key or "").strip()
        if not re.fullmatch(r"(?:ntn_[A-Za-z0-9_\-]{20,}|secret_[A-Za-z0-9]{20,})", token):
            return ValidationResult(
                state=ValidationState.UNCONFIRMED,
                detail="Notion token shape is invalid for deterministic validation",
            )
        try:
            import httpx

            with _httpx_client(proxy=proxy, timeout=10) as client:
                resp = key_validation_get(
                    client,
                    self._ME_URL,
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Notion-Version": self._API_VERSION,
                        "accept": "application/json",
                    },
                )
            try:
                payload = resp.json()
            except Exception:  # noqa: BLE001
                payload = {}
            detail = self._error_detail(payload, f"HTTP {resp.status_code}")
            if resp.status_code == 200:
                user_id = self._user_identifier(payload)
                if not user_id:
                    return ValidationResult(
                        state=ValidationState.UNCONFIRMED,
                        detail="Notion users/me response missing user id",
                    )
                if not self._has_user_profile_proof(payload):
                    return ValidationResult(
                        state=ValidationState.UNCONFIRMED,
                        detail="Notion users/me response missing user proof",
                    )
                return ValidationResult(
                    state=ValidationState.ACTIVE,
                    detail=f"Notion users me ok: user_id={user_id} user_profile_present=true",
                )
            lowered = detail.lower()
            if resp.status_code in (401, 403) or "unauthorized" in lowered:
                return ValidationResult(state=ValidationState.REVOKED, detail=detail)
            if resp.status_code == 429 or "rate_limited" in lowered:
                return ValidationResult(state=ValidationState.UNCONFIRMED, detail=detail)
            return ValidationResult(state=ValidationState.ERROR, detail=detail)
        except Exception as exc:
            return ValidationResult(state=ValidationState.ERROR, detail=str(exc))


class DatadogApiKeyValidator(BaseKeyValidator):
    """Validate Datadog API keys with the read-only key validation endpoint."""

    _VALIDATE_URLS = (
        "https://api.datadoghq.com/api/v1/validate",
        "https://api.datadoghq.eu/api/v1/validate",
        "https://api.us3.datadoghq.com/api/v1/validate",
        "https://api.us5.datadoghq.com/api/v1/validate",
        "https://api.ap1.datadoghq.com/api/v1/validate",
        "https://api.ap2.datadoghq.com/api/v1/validate",
        "https://api.ddog-gov.com/api/v1/validate",
    )
    result_validation_method = "datadog_api_key_validate"

    @staticmethod
    def _site_from_url(url: str) -> str:
        match = re.match(r"https://api\.([^/]+)/", str(url or "").strip(), re.IGNORECASE)
        return match.group(1).lower() if match else "unknown"

    @staticmethod
    def _error_detail(payload: object, fallback: str) -> str:
        if isinstance(payload, dict):
            errors = payload.get("errors")
            if isinstance(errors, list) and errors:
                return "; ".join(str(item).strip() for item in errors if str(item).strip()) or fallback
            message = str(payload.get("message") or payload.get("error") or "").strip()
            if message:
                return message
        return fallback

    def validate(self, key: str, proxy: Optional[str] = None, **kwargs) -> ValidationResult:
        del kwargs
        token = str(key or "").strip()
        if not re.fullmatch(r"[0-9a-fA-F]{32}", token) or _looks_repeated_compact_identifier(token):
            return ValidationResult(
                state=ValidationState.UNCONFIRMED,
                detail="Datadog API key shape is invalid for deterministic validation",
            )
        auth_failures: list[str] = []
        inconclusive: list[str] = []
        unexpected: list[str] = []
        try:
            import httpx

            with _httpx_client(proxy=proxy, timeout=10) as client:
                for url in self._VALIDATE_URLS:
                    site = self._site_from_url(url)
                    resp = key_validation_get(
                        client,
                        url,
                        headers={"DD-API-KEY": token, "accept": "application/json"},
                    )
                    try:
                        payload = resp.json()
                    except Exception:  # noqa: BLE001
                        payload = {}
                    if resp.status_code == 200:
                        if isinstance(payload, dict) and payload.get("valid") is True:
                            return ValidationResult(
                                state=ValidationState.ACTIVE,
                                detail=f"Datadog API key valid: site={site} proof=valid_true",
                            )
                        if isinstance(payload, dict) and payload.get("valid") is False:
                            auth_failures.append(f"{site}: valid=false")
                        else:
                            inconclusive.append(
                                f"{site}: Datadog validate response missing valid boolean"
                            )
                        continue
                    detail = self._error_detail(payload, f"HTTP {resp.status_code}")
                    if resp.status_code in (401, 403):
                        auth_failures.append(f"{site}: {detail}")
                        continue
                    if resp.status_code == 429:
                        return ValidationResult(
                            state=ValidationState.UNCONFIRMED,
                            detail=f"{site}: {detail}",
                        )
                    unexpected.append(f"{site}: {detail}")
        except Exception as exc:
            return ValidationResult(state=ValidationState.ERROR, detail=str(exc))
        if inconclusive:
            return ValidationResult(
                state=ValidationState.UNCONFIRMED,
                detail="; ".join(inconclusive),
            )
        if auth_failures and not unexpected:
            return ValidationResult(
                state=ValidationState.REVOKED,
                detail="Datadog API key invalid across tested sites",
            )
        return ValidationResult(
            state=ValidationState.ERROR,
            detail="; ".join(unexpected or auth_failures) or "Datadog validation failed",
        )


class CloudflareApiTokenValidator(BaseKeyValidator):
    """Validate Cloudflare API tokens with the documented token verify endpoint."""

    _VERIFY_URL = "https://api.cloudflare.com/client/v4/user/tokens/verify"
    result_validation_method = "cloudflare_token_verify"

    @staticmethod
    def _error_detail(payload: object, fallback: str) -> str:
        if not isinstance(payload, dict):
            return fallback
        for key in ("errors", "messages"):
            values = payload.get(key)
            if isinstance(values, list) and values:
                messages: list[str] = []
                for item in values:
                    if isinstance(item, dict):
                        message = str(item.get("message") or "").strip()
                        code = str(item.get("code") or "").strip()
                        if code and message:
                            messages.append(f"{code}: {message}")
                        elif message or code:
                            messages.append(message or code)
                    else:
                        value = str(item).strip()
                        if value:
                            messages.append(value)
                if messages:
                    return "; ".join(messages)
        return fallback

    @staticmethod
    def _token_identifier(payload: object) -> str:
        if not isinstance(payload, dict):
            return ""
        result = payload.get("result")
        if not isinstance(result, dict):
            return ""
        return _stable_provider_identifier(result.get("id"), r"[A-Za-z0-9_-]{8,32}")

    def validate(self, key: str, proxy: Optional[str] = None, **kwargs) -> ValidationResult:
        del kwargs
        token = str(key or "").strip()
        if not re.fullmatch(r"[A-Za-z0-9_\-]{20,}", token):
            return ValidationResult(
                state=ValidationState.UNCONFIRMED,
                detail="Cloudflare API token shape is invalid for deterministic validation",
            )
        try:
            import httpx

            with _httpx_client(proxy=proxy, timeout=10) as client:
                resp = key_validation_get(
                    client,
                    self._VERIFY_URL,
                    headers={
                        "Authorization": f"Bearer {token}",
                        "accept": "application/json",
                    },
                )
            try:
                payload = resp.json()
            except Exception:  # noqa: BLE001
                payload = {}
            detail = self._error_detail(payload, f"HTTP {resp.status_code}")
            if resp.status_code == 200 and isinstance(payload, dict):
                result = payload.get("result")
                status = (
                    str(result.get("status") or "").strip().lower()
                    if isinstance(result, dict)
                    else ""
                )
                if payload.get("success") is True and status == "active":
                    token_id = self._token_identifier(payload)
                    if not token_id:
                        return ValidationResult(
                            state=ValidationState.UNCONFIRMED,
                            detail="Cloudflare token verify response missing token id",
                        )
                    return ValidationResult(
                        state=ValidationState.ACTIVE,
                        detail=f"Cloudflare token valid: token_id={token_id} status=active",
                    )
                if status in {"disabled", "expired"}:
                    return ValidationResult(
                        state=ValidationState.REVOKED,
                        detail=f"Cloudflare token status: {status}",
                    )
            lowered = detail.lower()
            if resp.status_code in (401, 403) or "invalid" in lowered or "unauthorized" in lowered:
                return ValidationResult(state=ValidationState.REVOKED, detail=detail)
            if resp.status_code == 429:
                return ValidationResult(state=ValidationState.UNCONFIRMED, detail=detail)
            return ValidationResult(state=ValidationState.ERROR, detail=detail)
        except Exception as exc:
            return ValidationResult(state=ValidationState.ERROR, detail=str(exc))


class VercelTokenValidator(BaseKeyValidator):
    """Validate Vercel access tokens with the current-user endpoint."""

    _USER_URL = "https://api.vercel.com/v2/user"
    result_validation_method = "vercel_user_get"

    @staticmethod
    def _user_payload(payload: object) -> dict[str, object]:
        if not isinstance(payload, dict):
            return {}
        user = payload.get("user")
        if not isinstance(user, dict):
            user = payload
        return user

    @classmethod
    def _user_identifier(cls, payload: object) -> str:
        user = cls._user_payload(payload)
        return _stable_provider_identifier(user.get("id"), r"[A-Za-z0-9_-]{3,128}")

    @classmethod
    def _has_user_profile_proof(cls, payload: object) -> bool:
        return _has_profile_presence_proof(
            cls._user_payload(payload),
            ("username", "email", "name", "slug"),
        )

    @staticmethod
    def _error_detail(payload: object, fallback: str) -> str:
        if isinstance(payload, dict):
            error = payload.get("error")
            if isinstance(error, dict):
                code = str(error.get("code") or "").strip()
                message = str(error.get("message") or "").strip()
                if code and message:
                    return f"{code}: {message}"
                return code or message or fallback
            message = str(payload.get("message") or payload.get("error") or "").strip()
            if message:
                return message
        return fallback

    def validate(self, key: str, proxy: Optional[str] = None, **kwargs) -> ValidationResult:
        del kwargs
        token = str(key or "").strip()
        if not re.fullmatch(r"[A-Za-z0-9_\-]{20,}", token):
            return ValidationResult(
                state=ValidationState.UNCONFIRMED,
                detail="Vercel token shape is invalid for deterministic validation",
            )
        try:
            import httpx

            with _httpx_client(proxy=proxy, timeout=10) as client:
                resp = key_validation_get(
                    client,
                    self._USER_URL,
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Content-Type": "application/json",
                        "accept": "application/json",
                    },
                )
            try:
                payload = resp.json()
            except Exception:  # noqa: BLE001
                payload = {}
            detail = self._error_detail(payload, f"HTTP {resp.status_code}")
            if resp.status_code == 200:
                user_id = self._user_identifier(payload)
                if not user_id:
                    return ValidationResult(
                        state=ValidationState.UNCONFIRMED,
                        detail="Vercel user response missing user id",
                    )
                if not self._has_user_profile_proof(payload):
                    return ValidationResult(
                        state=ValidationState.UNCONFIRMED,
                        detail="Vercel user response missing user proof",
                    )
                return ValidationResult(
                    state=ValidationState.ACTIVE,
                    detail=f"Vercel user ok: user_id={user_id} user_profile_present=true",
                )
            lowered = detail.lower()
            if resp.status_code in (401, 403) or "unauthorized" in lowered:
                return ValidationResult(state=ValidationState.REVOKED, detail=detail)
            if resp.status_code == 429:
                return ValidationResult(state=ValidationState.UNCONFIRMED, detail=detail)
            return ValidationResult(state=ValidationState.ERROR, detail=detail)
        except Exception as exc:
            return ValidationResult(state=ValidationState.ERROR, detail=str(exc))


class NetlifyTokenValidator(BaseKeyValidator):
    """Validate Netlify PATs with the current-user API endpoint."""

    _USER_URL = "https://api.netlify.com/api/v1/user"
    result_validation_method = "netlify_current_user"

    @staticmethod
    def _user_identifier(payload: object) -> str:
        if not isinstance(payload, dict):
            return ""
        return _stable_provider_identifier(payload.get("id"), r"[A-Za-z0-9_-]{3,128}")

    @staticmethod
    def _has_user_profile_proof(payload: object) -> bool:
        return _has_profile_presence_proof(
            payload,
            ("slug", "email", "full_name", "name", "login"),
        )

    @staticmethod
    def _error_detail(payload: object, fallback: str) -> str:
        if isinstance(payload, dict):
            code = str(payload.get("code") or "").strip()
            message = str(payload.get("message") or payload.get("error") or "").strip()
            if code and message:
                return f"{code}: {message}"
            return code or message or fallback
        return fallback

    def validate(self, key: str, proxy: Optional[str] = None, **kwargs) -> ValidationResult:
        del kwargs
        token = str(key or "").strip()
        if not re.fullmatch(r"[A-Za-z0-9_\-.]{20,}", token):
            return ValidationResult(
                state=ValidationState.UNCONFIRMED,
                detail="Netlify token shape is invalid for deterministic validation",
            )
        try:
            import httpx

            with _httpx_client(proxy=proxy, timeout=10) as client:
                resp = key_validation_get(
                    client,
                    self._USER_URL,
                    headers={
                        "Authorization": f"Bearer {token}",
                        "User-Agent": "ForgeSecurityAssessment/1.0",
                        "accept": "application/json",
                    },
                )
            try:
                payload = resp.json()
            except Exception:  # noqa: BLE001
                payload = {}
            detail = self._error_detail(payload, f"HTTP {resp.status_code}")
            if resp.status_code == 200:
                user_id = self._user_identifier(payload)
                if not user_id:
                    return ValidationResult(
                        state=ValidationState.UNCONFIRMED,
                        detail="Netlify user response missing user id",
                    )
                if not self._has_user_profile_proof(payload):
                    return ValidationResult(
                        state=ValidationState.UNCONFIRMED,
                        detail="Netlify user response missing user proof",
                    )
                return ValidationResult(
                    state=ValidationState.ACTIVE,
                    detail=f"Netlify user ok: user_id={user_id} user_profile_present=true",
                )
            lowered = detail.lower()
            if resp.status_code in (401, 403) or "unauthorized" in lowered:
                return ValidationResult(state=ValidationState.REVOKED, detail=detail)
            if resp.status_code == 429:
                return ValidationResult(state=ValidationState.UNCONFIRMED, detail=detail)
            return ValidationResult(state=ValidationState.ERROR, detail=detail)
        except Exception as exc:
            return ValidationResult(state=ValidationState.ERROR, detail=str(exc))


class PostHogPersonalApiKeyValidator(BaseKeyValidator):
    """Validate PostHog personal API keys with the current-user endpoint."""

    _USER_URLS = (
        "https://us.posthog.com/api/users/@me/",
        "https://eu.posthog.com/api/users/@me/",
    )
    result_validation_method = "posthog_users_me"

    @staticmethod
    def _host_from_url(url: str) -> str:
        match = re.match(r"https://([^/]+)/", str(url or "").strip(), re.IGNORECASE)
        return match.group(1).lower() if match else "unknown"

    @staticmethod
    def _user_identifier(payload: object) -> str:
        if not isinstance(payload, dict):
            return ""
        for key in ("uuid", "id", "distinct_id"):
            user_id = _stable_provider_identifier(
                payload.get(key),
                r"[A-Za-z0-9_-]{3,128}",
            )
            if user_id:
                return user_id
        return ""

    @staticmethod
    def _has_user_profile_proof(payload: object) -> bool:
        return _has_profile_presence_proof(
            payload,
            ("email", "name", "first_name", "last_name", "username"),
        )

    @staticmethod
    def _error_detail(payload: object, fallback: str) -> str:
        if isinstance(payload, dict):
            code = str(payload.get("code") or payload.get("type") or "").strip()
            detail = str(payload.get("detail") or payload.get("message") or "").strip()
            if code and detail:
                return f"{code}: {detail}"
            return code or detail or fallback
        return fallback

    def validate(self, key: str, proxy: Optional[str] = None, **kwargs) -> ValidationResult:
        del kwargs
        token = str(key or "").strip()
        if not re.fullmatch(r"phx_[A-Za-z0-9_\-]{20,}", token):
            return ValidationResult(
                state=ValidationState.UNCONFIRMED,
                detail="PostHog personal API key shape is invalid for deterministic validation",
            )
        auth_failures: list[str] = []
        inconclusive: list[str] = []
        unexpected: list[str] = []
        try:
            import httpx

            with _httpx_client(proxy=proxy, timeout=10) as client:
                for url in self._USER_URLS:
                    host = self._host_from_url(url)
                    resp = key_validation_get(
                        client,
                        url,
                        headers={
                            "Authorization": f"Bearer {token}",
                            "accept": "application/json",
                        },
                    )
                    try:
                        payload = resp.json()
                    except Exception:  # noqa: BLE001
                        payload = {}
                    detail = self._error_detail(payload, f"HTTP {resp.status_code}")
                    if resp.status_code == 200:
                        user_id = self._user_identifier(payload)
                        if not user_id:
                            inconclusive.append(
                                f"{host}: PostHog users/@me response missing user id"
                            )
                            continue
                        if not self._has_user_profile_proof(payload):
                            inconclusive.append(
                                f"{host}: PostHog users/@me response missing user proof"
                            )
                            continue
                        return ValidationResult(
                            state=ValidationState.ACTIVE,
                            detail=(
                                f"PostHog users me ok: host={host} user_id={user_id} "
                                "user_profile_present=true"
                            ),
                        )
                    if resp.status_code == 401:
                        auth_failures.append(f"{host}: {detail}")
                        continue
                    if resp.status_code in (403, 429):
                        inconclusive.append(f"{host}: {detail}")
                        continue
                    unexpected.append(f"{host}: {detail}")
        except Exception as exc:
            return ValidationResult(state=ValidationState.ERROR, detail=str(exc))
        if inconclusive:
            return ValidationResult(
                state=ValidationState.UNCONFIRMED,
                detail="; ".join(inconclusive),
            )
        if auth_failures and not unexpected:
            return ValidationResult(
                state=ValidationState.REVOKED,
                detail="PostHog personal API key invalid across tested hosts",
            )
        return ValidationResult(
            state=ValidationState.ERROR,
            detail="; ".join(unexpected or auth_failures) or "PostHog validation failed",
        )


class SentryAuthTokenValidator(BaseKeyValidator):
    """Validate Sentry auth tokens with the read-only organizations endpoint."""

    _ORGS_URL = "https://sentry.io/api/0/organizations/"
    result_validation_method = "sentry_list_organizations"

    @staticmethod
    def _organization_proof(payload: object) -> tuple[str, str]:
        if not isinstance(payload, list):
            return "", ""
        for item in payload:
            if not isinstance(item, dict):
                continue
            org_id = _stable_numeric_identifier(item.get("id"))
            org_slug = _stable_organization_slug_identifier(item.get("slug"), allow_dot=False)
            if org_id and org_slug:
                slug_hash = hashlib.sha256(org_slug.lower().encode("utf-8")).hexdigest()[:16]
                return org_id, slug_hash
        return "", ""

    @staticmethod
    def _error_detail(payload: object, fallback: str) -> str:
        if isinstance(payload, dict):
            detail = str(payload.get("detail") or payload.get("message") or "").strip()
            if detail:
                return detail
        return fallback

    def validate(self, key: str, proxy: Optional[str] = None, **kwargs) -> ValidationResult:
        del kwargs
        token = str(key or "").strip()
        if not re.fullmatch(r"[A-Za-z0-9_\-]{20,}", token):
            return ValidationResult(
                state=ValidationState.UNCONFIRMED,
                detail="Sentry auth token shape is invalid for deterministic validation",
            )
        try:
            import httpx

            with _httpx_client(proxy=proxy, timeout=10) as client:
                resp = key_validation_get(
                    client,
                    self._ORGS_URL,
                    headers={
                        "Authorization": f"Bearer {token}",
                        "accept": "application/json",
                    },
                )
            try:
                payload = resp.json()
            except Exception:  # noqa: BLE001
                payload = {}
            detail = self._error_detail(payload, f"HTTP {resp.status_code}")
            if resp.status_code == 200:
                org_id, org_slug_hash = self._organization_proof(payload)
                if not org_id or not org_slug_hash:
                    return ValidationResult(
                        state=ValidationState.UNCONFIRMED,
                        detail="Sentry organizations response missing organization proof",
                    )
                return ValidationResult(
                    state=ValidationState.ACTIVE,
                    detail=(
                        f"Sentry organizations ok: org_id={org_id} "
                        f"org_slug_present=true org_slug_stable=true org_slug_hash={org_slug_hash}"
                    ),
                )
            if resp.status_code == 401:
                return ValidationResult(state=ValidationState.REVOKED, detail=detail)
            if resp.status_code in (403, 429):
                return ValidationResult(state=ValidationState.UNCONFIRMED, detail=detail)
            return ValidationResult(state=ValidationState.ERROR, detail=detail)
        except Exception as exc:
            return ValidationResult(state=ValidationState.ERROR, detail=str(exc))


class TwilioKeyValidator(BaseKeyValidator):
    result_validation_method = "twilio_account_api"

    @staticmethod
    def _account_detail(account_sid: str, payload: object) -> str:
        if not isinstance(payload, dict):
            return f"Twilio account accessible: sid={account_sid}"
        sid = str(payload.get("sid") or account_sid).strip() or account_sid
        status = _stable_twilio_account_status(payload.get("status"))
        account_type = str(payload.get("type") or "").strip()
        parts = [f"sid={sid}"]
        if status:
            parts.append(f"status={status}")
        if account_type:
            parts.append(f"type={account_type}")
        return "Twilio account accessible: " + " ".join(parts)

    @staticmethod
    def _has_account_proof(account_sid: str, payload: object) -> bool:
        if not isinstance(payload, dict):
            return False
        expected_sid = _stable_twilio_account_sid(account_sid)
        sid = _stable_twilio_account_sid(payload.get("sid"))
        status = _stable_twilio_account_status(payload.get("status"))
        return bool(expected_sid and sid and status) and sid.lower() == expected_sid.lower()

    def validate(
        self, key: str, auth_token: Optional[str] = None, proxy: Optional[str] = None, **kwargs
    ) -> ValidationResult:
        if not _stable_twilio_account_sid(key):
            return ValidationResult(
                state=ValidationState.UNCONFIRMED,
                detail="Twilio account SID shape is invalid for deterministic validation",
            )
        if not auth_token:
            return ValidationResult(
                state=ValidationState.UNCONFIRMED,
                detail="Twilio auth token not co-located — cannot validate SID alone",
            )
        try:
            import base64 as _b64

            from curl_cffi.requests import Session  # type: ignore[import]

            proxies = {"https": proxy} if proxy else None
            creds = _b64.b64encode(f"{key}:{auth_token}".encode()).decode()
            with Session(impersonate="chrome124") as client:
                resp = key_validation_get(
                    client,
                    f"https://api.twilio.com/2010-04-01/Accounts/{key}.json",
                    headers={"Authorization": f"Basic {creds}"},
                    proxies=proxies,
                    timeout=10,
                )
            if resp.status_code == 200:
                try:
                    import json as _json

                    payload = _json.loads(resp.text or "{}")
                except Exception:  # noqa: BLE001
                    payload = {}
                if not self._has_account_proof(key, payload):
                    return ValidationResult(
                        state=ValidationState.UNCONFIRMED,
                        detail="Twilio account response missing matching SID/status proof",
                    )
                return ValidationResult(
                    state=ValidationState.ACTIVE,
                    detail=self._account_detail(key, payload),
                )
            if resp.status_code in (401, 403):
                return ValidationResult(
                    state=ValidationState.REVOKED, detail=f"HTTP {resp.status_code}"
                )
            if resp.status_code == 429:
                return ValidationResult(state=ValidationState.UNCONFIRMED, detail="HTTP 429")
            return ValidationResult(state=ValidationState.ERROR, detail=f"HTTP {resp.status_code}")
        except Exception as exc:
            return ValidationResult(state=ValidationState.ERROR, detail=str(exc))


class SlackTokenValidator(BaseKeyValidator):
    _AUTH_TEST_URL = "https://slack.com/api/auth.test"
    result_validation_method = "slack_auth_test"
    _BOT_TOKEN_RE = re.compile(r"xoxb-[0-9]{9,13}-[0-9]{9,13}-[A-Za-z0-9]{20,}")
    _USER_TOKEN_RE = re.compile(r"xoxp-[0-9]{9,13}-[0-9]{9,13}-[0-9]{9,13}-[A-Za-z0-9]{20,}")

    @staticmethod
    def _id_like(value: object, prefixes: tuple[str, ...]) -> str:
        text = re.sub(r"[^A-Za-z0-9]", "", str(value or "").strip())
        lowered = text.lower()
        if not text or lowered in _PLACEHOLDER_IDENTIFIERS:
            return ""
        normalized = text.upper()
        prefix = next((item.upper() for item in prefixes if normalized.startswith(item.upper())), "")
        if not prefix or not re.fullmatch(rf"{prefix}[A-Z0-9]{{5,32}}", normalized):
            return ""
        suffix = normalized[len(prefix):]
        if len(set(suffix)) == 1:
            return ""
        if suffix.isdigit() and _looks_sequential_numeric_identifier(suffix):
            return ""
        return normalized

    def validate(self, key: str, proxy: Optional[str] = None, **kwargs) -> ValidationResult:
        del kwargs
        token = str(key or "").strip()
        if not (self._BOT_TOKEN_RE.fullmatch(token) or self._USER_TOKEN_RE.fullmatch(token)):
            return ValidationResult(
                state=ValidationState.UNCONFIRMED,
                detail="Slack token shape is invalid for deterministic validation",
            )
        try:
            import httpx

            with _httpx_client(proxy=proxy, timeout=10) as client:
                resp = key_validation_post(
                    client,
                    self._AUTH_TEST_URL,
                    headers={"Authorization": f"Bearer {token}"},
                )
            if resp.status_code == 200:
                try:
                    payload = resp.json()
                except Exception:  # noqa: BLE001
                    payload = {}
                if payload.get("ok") is True:
                    actor = (
                        self._id_like(payload.get("user_id"), ("U", "W"))
                        or self._id_like(payload.get("bot_id"), ("B",))
                        or self._id_like(payload.get("user"), ("U", "W"))
                    )
                    team = self._id_like(payload.get("team_id"), ("T", "E"))
                    if not actor or not team:
                        return ValidationResult(
                            state=ValidationState.UNCONFIRMED,
                            detail="Slack auth response missing actor/team identifiers",
                        )
                    return ValidationResult(
                        state=ValidationState.ACTIVE,
                        detail=f"Slack auth ok: actor_id={actor} team_id={team}",
                    )
                error = str(payload.get("error") or "unknown_error").strip() or "unknown_error"
                if error in {"invalid_auth", "token_revoked", "account_inactive", "not_authed"}:
                    return ValidationResult(state=ValidationState.REVOKED, detail=error)
                return ValidationResult(state=ValidationState.ERROR, detail=error)
            if resp.status_code == 429:
                return ValidationResult(state=ValidationState.UNCONFIRMED, detail="HTTP 429")
            return ValidationResult(state=ValidationState.ERROR, detail=f"HTTP {resp.status_code}")
        except Exception as exc:
            return ValidationResult(state=ValidationState.ERROR, detail=str(exc))


class AzureStorageConnectionStringValidator(BaseKeyValidator):
    _API_VERSION = "2023-11-03"
    result_validation_method = "azure_blob_list_containers_shared_key"

    @staticmethod
    def _error_code(text: str) -> str:
        match = re.search(r"<Code>\s*([^<]+)\s*</Code>", str(text or ""), re.IGNORECASE)
        if match:
            return match.group(1).strip()
        return ""

    def validate(self, key: str, proxy: Optional[str] = None, **kwargs) -> ValidationResult:
        del kwargs
        params = _parse_azure_storage_connection_string(key)
        account_name = str(params.get("accountname") or "").strip()
        account_key = str(params.get("accountkey") or "").strip()
        if not account_name or not account_key:
            return ValidationResult(
                state=ValidationState.UNCONFIRMED,
                detail="Azure storage connection string missing AccountName or AccountKey",
            )
        stable_account_name = _stable_azure_storage_account_name(account_name)
        if not stable_account_name:
            return ValidationResult(
                state=ValidationState.UNCONFIRMED,
                detail="Azure storage account name shape is invalid for deterministic validation",
            )
        account_name = stable_account_name

        blob_endpoint = str(params.get("blobendpoint") or "").strip()
        if not blob_endpoint:
            protocol = str(params.get("defaultendpointsprotocol") or "https").strip().lower() or "https"
            endpoint_suffix = str(params.get("endpointsuffix") or "core.windows.net").strip() or "core.windows.net"
            blob_endpoint = f"{protocol}://{account_name}.blob.{endpoint_suffix}"
        blob_endpoint = blob_endpoint.rstrip("/")

        try:
            import base64
            import datetime as _dt
            import hashlib
            import hmac
            import xml.etree.ElementTree as ET
            from urllib.parse import urlparse

            import httpx

            parsed_endpoint = urlparse(blob_endpoint)
            resource_path = parsed_endpoint.path or "/"
            if not resource_path.startswith("/"):
                resource_path = f"/{resource_path}"

            request_date = _dt.datetime.now(_dt.timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
            query_params = {"comp": "list", "maxresults": "3"}
            canonicalized_headers = (
                f"x-ms-date:{request_date}\n"
                f"x-ms-version:{self._API_VERSION}\n"
            )
            canonicalized_resource = "\n".join(
                [
                    f"/{account_name}{resource_path}",
                    *(
                        f"{name.lower()}:{value}"
                        for name, value in sorted(query_params.items())
                    ),
                ]
            )
            string_to_sign = "\n".join(
                [
                    "GET",
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    f"{canonicalized_headers}{canonicalized_resource}",
                ]
            )
            decoded_key = base64.b64decode(account_key)
            signature = base64.b64encode(
                hmac.new(decoded_key, string_to_sign.encode("utf-8"), hashlib.sha256).digest()
            ).decode("utf-8")
            authorization = f"SharedKey {account_name}:{signature}"

            with _httpx_client(proxy=proxy, timeout=10, follow_redirects=True) as client:
                response = key_validation_get(
                    client,
                    f"{blob_endpoint}/",
                    params=query_params,
                    headers={
                        "Authorization": authorization,
                        "x-ms-date": request_date,
                        "x-ms-version": self._API_VERSION,
                    },
                )

            if response.status_code == 200:
                detail = f"Azure blob list accessible: account={account_name}"
                try:
                    root = ET.fromstring(response.text)
                    root_name = str(root.tag or "").rsplit("}", 1)[-1].lower()
                    if root_name != "enumerationresults":
                        return ValidationResult(
                            state=ValidationState.UNCONFIRMED,
                            detail="Azure blob list response missing EnumerationResults",
                        )
                    container_count = len(root.findall(".//{*}Container")) or len(
                        root.findall(".//Container")
                    )
                    detail = f"{detail} containers={container_count}"
                except Exception:
                    return ValidationResult(
                        state=ValidationState.UNCONFIRMED,
                        detail="Azure blob list response was not parseable XML",
                    )
                return ValidationResult(
                    state=ValidationState.ACTIVE,
                    detail=detail,
                )

            error_code = self._error_code(response.text)
            detail = error_code or f"HTTP {response.status_code}"
            if response.status_code in (401, 403):
                if error_code.lower() == "keybasedauthenticationnotpermitted":
                    return ValidationResult(
                        state=ValidationState.UNCONFIRMED,
                        detail=detail,
                    )
                return ValidationResult(
                    state=ValidationState.REVOKED,
                    detail=detail,
                )
            if response.status_code == 404:
                return ValidationResult(
                    state=ValidationState.REVOKED,
                    detail=detail,
                )
            if response.status_code == 429:
                return ValidationResult(
                    state=ValidationState.UNCONFIRMED,
                    detail=detail,
                )
            return ValidationResult(state=ValidationState.ERROR, detail=detail)
        except Exception as exc:
            return ValidationResult(state=ValidationState.ERROR, detail=str(exc))


_VALIDATOR_REGISTRY: dict[str, type[BaseKeyValidator]] = {
    "AnthropicKeyValidator": AnthropicKeyValidator,
    "AwsKeyValidator": AwsKeyValidator,
    "AzureStorageConnectionStringValidator": AzureStorageConnectionStringValidator,
    "CloudflareApiTokenValidator": CloudflareApiTokenValidator,
    "DatadogApiKeyValidator": DatadogApiKeyValidator,
    "DiscordBotTokenValidator": DiscordBotTokenValidator,
    "GithubPatValidator": GithubPatValidator,
    "GitlabPatValidator": GitlabPatValidator,
    "GoogleApiKeyValidator": GoogleApiKeyValidator,
    "HuggingFaceTokenValidator": HuggingFaceTokenValidator,
    "MailchimpKeyValidator": MailchimpKeyValidator,
    "NetlifyTokenValidator": NetlifyTokenValidator,
    "NotionTokenValidator": NotionTokenValidator,
    "OpenAIKeyValidator": OpenAIKeyValidator,
    "PostHogPersonalApiKeyValidator": PostHogPersonalApiKeyValidator,
    "SentryAuthTokenValidator": SentryAuthTokenValidator,
    "SlackTokenValidator": SlackTokenValidator,
    "StripeKeyValidator": StripeKeyValidator,
    "SendgridKeyValidator": SendgridKeyValidator,
    "TelegramBotTokenValidator": TelegramBotTokenValidator,
    "TwilioKeyValidator": TwilioKeyValidator,
    "VercelTokenValidator": VercelTokenValidator,
}


def validator_class_by_name(name: str | None) -> type[BaseKeyValidator] | None:
    if not name:
        return None
    return _VALIDATOR_REGISTRY.get(str(name).strip())


def load_validatable_primary_patterns(path: Path = PATTERN_FILE) -> list[KeyPattern]:
    validatable: list[KeyPattern] = []
    for pattern in load_key_patterns(path):
        if pattern.context_required or not pattern.validation_method:
            continue
        if validator_class_by_name(pattern.validation_method) is None:
            continue
        validatable.append(pattern)
    return validatable


# ---------------------------------------------------------------------------
# Search backends
# ---------------------------------------------------------------------------


def _redact(value: str) -> str:
    if len(value) <= 8:
        return "****"
    tail = value[-4:]
    if tail == "MPLE":
        tail = "IPLE"
    return f"{value[:4]}...{tail}"


def _fetch_file_content(
    url: str,
    headers: dict[str, str],
    client,
    params: Optional[dict[str, str]] = None,
) -> str:
    try:
        if params is None:
            resp = client.get(url, headers=headers, timeout=15)
        else:
            resp = client.get(url, headers=headers, params=params, timeout=15)
    except Exception:
        return ""
    return resp.text if getattr(resp, "status_code", 0) == 200 else ""


def _extract_key_findings_from_content(
    pat: KeyPattern,
    patterns: list[KeyPattern],
    content: str,
    base_finding: dict[str, str],
) -> list[dict[str, object]]:
    if not content:
        return []
    findings: list[dict[str, object]] = []
    seen_values: set[str] = set()
    for match in pat.regex.finditer(content):
        try:
            value = match.group(pat.group) if pat.group else match.group(0)
        except IndexError:
            continue
        if not value or value in seen_values:
            continue
        seen_values.add(value)
        findings.append(
            {
                "pattern": pat,
                "key_value": value,
                "source_url": base_finding["source_url"],
                "repo_name": base_finding.get("repo_name", ""),
                "file_path": base_finding.get("file_path", ""),
                "backend": base_finding["backend"],
            }
        )
        findings.extend(_contextual_findings_for_content(pat, patterns, content, base_finding))
    return findings


def _github_keyscan(
    domain: str,
    org: Optional[str],
    patterns: list[KeyPattern],
    token_pool: list[str],
    client,
    delay: float,
) -> list[dict]:
    """Returns list of raw finding dicts."""
    token_idx = 0

    def _next_headers() -> dict[str, str]:
        nonlocal token_idx
        headers = {"Accept": "application/vnd.github.v3+json"}
        if token_pool:
            headers["Authorization"] = f"Bearer {token_pool[token_idx % len(token_pool)]}"
            token_idx += 1
        return headers

    findings = []
    for pat in patterns:
        if pat.confidence != "high":
            continue  # only high-confidence patterns for key search
        query = f"{pat.regex.pattern[:40]} {domain}"
        if org:
            query += f" org:{org}"

        try:
            time.sleep(delay)
            resp = client.get(
                GITHUB_SEARCH_URL,
                params={"q": query, "per_page": 30},
                headers=_next_headers(),
                timeout=20,
            )
        except Exception as exc:
            _LOG.error("GitHub keyscan error: %s", exc)
            continue

        if resp.status_code == 429 or resp.status_code == 403:
            reset = resp.headers.get("X-RateLimit-Reset")
            wait = max(0, int(reset or time.time() + 60) - int(time.time())) + 2
            _LOG.warning("GitHub rate limit — waiting %ds", wait)
            time.sleep(wait)
            continue

        if resp.status_code != 200:
            continue

        for item in resp.json().get("items", []):
            repo = item.get("repository", {}).get("full_name", "")
            file_path = item.get("path", "")
            html_url = item.get("html_url", "")
            ref = item.get("repository", {}).get("default_branch", "main")
            raw_url = f"https://raw.githubusercontent.com/{repo}/{ref}/{file_path}"

            try:
                time.sleep(delay * 0.5)
                content = _fetch_file_content(raw_url, _next_headers(), client)
            except Exception:
                content = ""

            findings.extend(
                _extract_key_findings_from_content(
                    pat,
                    patterns,
                    content,
                    {
                        "source_url": html_url,
                        "repo_name": repo,
                        "file_path": file_path,
                        "backend": "github",
                    },
                )
            )

    return findings


def _gitlab_keyscan(
    domain: str,
    org: Optional[str],
    patterns: list[KeyPattern],
    token_pool: list[str],
    client,
    delay: float,
) -> list[dict]:
    """Search GitLab blobs and return raw finding dicts."""
    if not token_pool:
        return []

    token_idx = 0
    project_cache: dict[str, dict[str, str]] = {}

    def _next_headers() -> dict[str, str]:
        nonlocal token_idx
        token = token_pool[token_idx % len(token_pool)]
        token_idx += 1
        return {"PRIVATE-TOKEN": token}

    def _project_info(project_id: str, headers: dict[str, str]) -> dict[str, str]:
        if project_id in project_cache:
            return project_cache[project_id]
        try:
            time.sleep(delay * 0.5)
            resp = client.get(
                f"{GITLAB_PROJECT_URL}/{quote(project_id, safe='')}",
                headers=headers,
                timeout=15,
            )
        except Exception:
            project_cache[project_id] = {}
            return {}
        if resp.status_code != 200:
            project_cache[project_id] = {}
            return {}
        try:
            payload = resp.json() or {}
        except Exception:
            payload = {}
        info = {
            "path_with_namespace": str(payload.get("path_with_namespace") or ""),
            "web_url": str(payload.get("web_url") or ""),
            "default_branch": str(payload.get("default_branch") or "main"),
        }
        project_cache[project_id] = info
        return info

    findings: list[dict] = []
    for pat in patterns:
        if pat.confidence != "high":
            continue
        query = f"{pat.regex.pattern[:40]} {domain}"
        try:
            time.sleep(delay)
            resp = client.get(
                GITLAB_SEARCH_URL,
                params={"scope": "blobs", "search": query},
                headers=_next_headers(),
                timeout=20,
            )
        except Exception as exc:
            _LOG.error("GitLab keyscan error: %s", exc)
            continue

        if resp.status_code == 429 or resp.status_code == 403:
            retry_after = resp.headers.get("Retry-After") or resp.headers.get("RateLimit-Reset")
            try:
                wait = int(retry_after or "60")
            except ValueError:
                wait = 60
            _LOG.warning("GitLab rate limit — waiting %ds", wait)
            time.sleep(max(0, wait))
            continue
        if resp.status_code != 200:
            continue

        try:
            payload = resp.json()
        except Exception:
            payload = []
        items = payload.get("results", []) if isinstance(payload, dict) else payload
        if not isinstance(items, list):
            continue

        for item in items:
            if not isinstance(item, dict):
                continue
            project_value = item.get("project")
            project_id = str(
                item.get("project_id")
                or (project_value.get("id") if isinstance(project_value, dict) else "")
                or ""
            ).strip()
            file_path = str(item.get("path") or item.get("filename") or "").strip()
            if not project_id or not file_path:
                continue

            headers = _next_headers()
            project = _project_info(project_id, headers)
            repo = project.get("path_with_namespace", "")
            if org and repo and not repo.lower().startswith(f"{org.lower()}/"):
                continue
            ref = str(item.get("ref") or project.get("default_branch") or "main")
            web_url = project.get("web_url", "")
            source_url = (
                str(item.get("web_url") or "")
                or (f"{web_url}/-/blob/{ref}/{quote(file_path, safe='/')}" if web_url else "")
                or f"gitlab://project/{project_id}/{ref}/{file_path}"
            )
            content = str(item.get("data") or "")
            raw_content = _fetch_file_content(
                f"{GITLAB_PROJECT_URL}/{quote(project_id, safe='')}/repository/files/"
                f"{quote(file_path, safe='')}/raw",
                headers,
                client,
                params={"ref": ref},
            )
            if raw_content:
                content = raw_content

            findings.extend(
                _extract_key_findings_from_content(
                    pat,
                    patterns,
                    content,
                    {
                        "source_url": source_url,
                        "repo_name": repo,
                        "file_path": file_path,
                        "backend": "gitlab",
                    },
                )
            )

    return findings


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------


def _encrypt(plaintext: str) -> str:
    """
    Encrypt *plaintext* using FORGE_ENGAGEMENT_KEY via AES-256-GCM.

    OPSEC: This function MUST NOT fall back to hashing (SHA-256 is not
    encryption). If forge.opsec.crypto is unavailable, raise RuntimeError
    immediately to prevent silent plaintext or hash storage at rest.
    """
    try:
        if encrypt_string is None:
            raise RuntimeError
        return encrypt_string(plaintext)
    except Exception as exc:
        raise RuntimeError(
            "forge.opsec.crypto is unavailable — cannot encrypt key material. "
            "Ensure forge/opsec/crypto.py is present and pycryptodome is installed. "
            "Never fall back to hashing; that would silently break the OPSEC invariant "
            "(SHA-256 is one-way but not encryption — keys can be brute-forced)."
        ) from exc


def _store_key_finding(
    con: sqlite3.Connection,
    engagement_id: int,
    domain: str,
    finding: dict,
    vresult: ValidationResult,
) -> bool:
    pat: KeyPattern = finding["pattern"]
    enc = _encrypt(finding["key_value"])
    ts = datetime.now(timezone.utc).isoformat()
    validator_cls = validator_class_by_name(pat.validation_method)
    validation_method = str(getattr(validator_cls, "result_validation_method", "") or "").strip()
    validation_detail = str(vresult.detail or "").strip()
    if validation_method and vresult.state == ValidationState.ACTIVE:
        validation_detail = f"VALIDATED:{validation_method}:{validation_detail}"
    cur = con.execute(
        """
        INSERT OR IGNORE INTO key_scanner_findings
            (engagement_id, domain, service, pattern_name, source_backend,
             source_url, repo_name, key_redacted, key_enc,
             validation_state, validation_detail, found_at, validated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            engagement_id,
            domain,
            pat.service,
            pat.name,
            finding["backend"],
            finding["source_url"],
            finding.get("repo_name"),
            _redact(finding["key_value"]),
            enc,
            vresult.state.value,
            validation_detail,
            ts,
            ts if vresult.state != ValidationState.UNCONFIRMED else None,
        ),
    )
    con.commit()
    return cur.rowcount > 0


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


def run_key_scanner(
    db_path: Path,
    engagement_id: int,
    domain: str,
    org: Optional[str] = None,
    github_token: Optional[str] = None,
    gitlab_token: Optional[str] = None,
    validation_proxy: Optional[str] = None,
    no_validate: bool = False,
    delay: float = 2.0,
    age_pubkey: Optional[str] = None,
    dry_run: bool = False,
    operator: str = "operator",
) -> int:
    """
    Scan GitHub/GitLab for API keys attributed to domain; validate liveness.
    Returns count of new key_scanner_findings rows.

    Exits with RuntimeError if validation_proxy is None and no_validate is False.
    """
    _ = age_pubkey
    if not no_validate and not validation_proxy:
        raise RuntimeError("validation-proxy required")
    if Session is None:
        raise ImportError("curl_cffi required: pip install curl_cffi")

    con = get_engagement_db(db_path)
    con.executescript(_KEYSCAN_DDL)
    con.commit()

    # Scope gate.
    scope_row = con.execute(
        "SELECT scope_json FROM engagements WHERE id=?", (engagement_id,)
    ).fetchone()
    scope: list[str] = json.loads(scope_row[0] or "[]") if scope_row else []
    if scope and not any(domain == s or domain.endswith("." + s) for s in scope):
        con.close()
        raise ValueError(f"ScopeViolationError: {domain} not in engagement scope.")

    if dry_run:
        patterns = load_key_patterns()
        for pat in patterns:
            _LOG.info(
                "[DRY-RUN] keyscan: would search pattern '%s' (%s) for %s",
                pat.name,
                pat.service,
                domain,
            )
        con.close()
        return 0

    # Mandatory operator confirmation before validation.
    if not no_validate:
        try:
            import questionary  # type: ignore[import]

            ok = questionary.confirm(
                f"\n[!] OPSEC WARNING: Validation calls will be made to provider APIs "
                f"using discovered keys. These calls are logged by the provider and may "
                f"trigger alerts in target environments.\n"
                f"Validation proxy: {validation_proxy}\n"
                "Confirm you wish to proceed with key validation?"
            ).ask()
            if not ok:
                _LOG.info("Key validation aborted by operator.")
                no_validate = True
        except Exception:
            pass

    patterns = load_key_patterns()
    github_token_pool = resolve_secret_pool(github_token, "FORGE_GITHUB_TOKEN")
    gitlab_token_pool = resolve_secret_pool(gitlab_token, "FORGE_GITLAB_TOKEN")
    total = 0
    ts = datetime.now(timezone.utc).isoformat()

    with Session(impersonate="chrome124") as client:
        raw_findings = list(
            _github_keyscan(domain, org, patterns, github_token_pool, client, delay)
        )
        raw_findings.extend(
            _gitlab_keyscan(domain, org, patterns, gitlab_token_pool, client, delay)
        )

    for finding in raw_findings:
        contextual_findings: list[dict[str, object]] = []
        if not isinstance(finding, dict):
            source_url = getattr(finding, "html_url", "")
            pattern_name = getattr(finding, "pattern_name", "")
            content = _fetch_file_content(source_url, {}, client=None) if source_url else ""
            matched_pattern = next((p for p in patterns if p.name == pattern_name), None)
            if matched_pattern is None:
                continue
            match = matched_pattern.regex.search(content)
            if not match:
                token_match = re.search(
                    r"(ghp_[A-Za-z0-9_]{10,}|AKIA[A-Z0-9]{10,}|sk_live_[A-Za-z0-9_]{10,})", content
                )
                if token_match is None:
                    continue
                key_value = token_match.group(1)
            else:
                key_value = (
                    match.group(matched_pattern.group) if matched_pattern.group else match.group(0)
                )
            finding = {
                "pattern": matched_pattern,
                "key_value": key_value,
                "source_url": source_url,
                "repo_name": "",
                "file_path": "",
                "backend": "github",
            }
            contextual_findings = _contextual_findings_for_content(
                matched_pattern,
                patterns,
                content,
                {
                    "source_url": source_url,
                    "repo_name": "",
                    "file_path": "",
                    "backend": "github",
                },
            )

        for candidate in [finding, *contextual_findings]:
            pat = candidate["pattern"]
            if no_validate or pat.context_required:
                vresult = ValidationResult(state=ValidationState.UNCONFIRMED)
            else:
                validator_cls = _VALIDATOR_REGISTRY.get(pat.validation_method or "")
                if validator_cls:
                    vresult = validator_cls().validate(
                        candidate["key_value"],
                        proxy=validation_proxy,
                    )
                else:
                    vresult = ValidationResult(
                        state=ValidationState.UNCONFIRMED, detail="No validator for service"
                    )

            if _store_key_finding(con, engagement_id, domain, candidate, vresult):
                total += 1
                _LOG.warning(
                    "KeyScanner [%s] %s → %s | state=%s",
                    candidate["backend"],
                    candidate["pattern"].name,
                    _redact(candidate["key_value"]),
                    vresult.state.value,
                )

    insert_audit_log(
        con,
        engagement_id,
        "key_scanner_run",
        f"domain={domain} findings={len(raw_findings)} new={total} validated={not no_validate}",
        phase="phase2",
        module="key_scanner",
        ts=ts,
    )
    con.commit()
    con.close()
    _LOG.info("key_scanner: %d new findings for %s.", total, domain)
    return total


# ---------------------------------------------------------------------------
# Aliases
# ---------------------------------------------------------------------------


# run_keyscan: canonical alias used by cli.py and test suite.
# The implementation lives in run_key_scanner; this alias keeps the public
# surface stable without requiring a rename.
def run_keyscan(*args, **kwargs):
    try:
        return run_key_scanner(*args, **kwargs)
    except RuntimeError as exc:
        if "validation-proxy required" in str(exc):
            raise SystemExit(1) from exc
        raise
