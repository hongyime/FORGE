"""Module 2-J: Exposed API Key Scanner.

Searches GitHub/GitLab for exposed API keys belonging to in-scope target orgs.
Validates active keys via per-service validators (AWS STS, Stripe, GitHub, etc.).
Age-encrypts discovered keys; redacts to first4...last4 in CLI output.

OPSEC: GitHub code search is logged and attributed to the PAT used.
Use a throwaway, non-attributable GitHub account.
Mandatory confirmation prompt before validation calls.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import sqlite3
import sys
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional
from urllib.parse import quote, urlparse

from forge.opsec.crypto import encrypt_string
from forge.opsec.rate_limiter import AdaptiveRateLimiter
from forge.opsec.resilience import (
    _SHUTDOWN,
    _interruptible_sleep,
    wait_for_internet,
    with_internet_retry,
)
from forge.opsec.scope_gate import assert_in_scope
from forge.utils.validation_identifiers import looks_compound_placeholder_identifier

_LOG = logging.getLogger(__name__)

try:
    from forge.utils.intel.secret_finder import AnthropicKeyValidator as SharedAnthropicKeyValidator
    from forge.utils.intel.secret_finder import (
        AzureStorageConnectionStringValidator as SharedAzureStorageConnectionStringValidator,
    )
    from forge.utils.intel.secret_finder import (
        CloudflareApiTokenValidator as SharedCloudflareApiTokenValidator,
    )
    from forge.utils.intel.secret_finder import (
        DatadogApiKeyValidator as SharedDatadogApiKeyValidator,
    )
    from forge.utils.intel.secret_finder import (
        DiscordBotTokenValidator as SharedDiscordBotTokenValidator,
    )
    from forge.utils.intel.secret_finder import GitlabPatValidator as SharedGitlabPatValidator
    from forge.utils.intel.secret_finder import GoogleApiKeyValidator as SharedGoogleApiKeyValidator
    from forge.utils.intel.secret_finder import (
        HuggingFaceTokenValidator as SharedHuggingFaceTokenValidator,
    )
    from forge.utils.intel.secret_finder import MailchimpKeyValidator as SharedMailchimpKeyValidator
    from forge.utils.intel.secret_finder import NetlifyTokenValidator as SharedNetlifyTokenValidator
    from forge.utils.intel.secret_finder import NotionTokenValidator as SharedNotionTokenValidator
    from forge.utils.intel.secret_finder import OpenAIKeyValidator as SharedOpenAIKeyValidator
    from forge.utils.intel.secret_finder import (
        PostHogPersonalApiKeyValidator as SharedPostHogPersonalApiKeyValidator,
    )
    from forge.utils.intel.secret_finder import (
        SentryAuthTokenValidator as SharedSentryAuthTokenValidator,
    )
    from forge.utils.intel.secret_finder import SendgridKeyValidator as SharedSendgridKeyValidator
    from forge.utils.intel.secret_finder import SlackTokenValidator as SharedSlackTokenValidator
    from forge.utils.intel.secret_finder import StripeKeyValidator as SharedStripeKeyValidator
    from forge.utils.intel.secret_finder import (
        TelegramBotTokenValidator as SharedTelegramBotTokenValidator,
    )
    from forge.utils.intel.secret_finder import VercelTokenValidator as SharedVercelTokenValidator
except Exception:  # noqa: BLE001
    SharedAnthropicKeyValidator = None  # type: ignore[assignment]
    SharedAzureStorageConnectionStringValidator = None  # type: ignore[assignment]
    SharedCloudflareApiTokenValidator = None  # type: ignore[assignment]
    SharedDatadogApiKeyValidator = None  # type: ignore[assignment]
    SharedDiscordBotTokenValidator = None  # type: ignore[assignment]
    SharedGitlabPatValidator = None  # type: ignore[assignment]
    SharedGoogleApiKeyValidator = None  # type: ignore[assignment]
    SharedHuggingFaceTokenValidator = None  # type: ignore[assignment]
    SharedMailchimpKeyValidator = None  # type: ignore[assignment]
    SharedNetlifyTokenValidator = None  # type: ignore[assignment]
    SharedNotionTokenValidator = None  # type: ignore[assignment]
    SharedOpenAIKeyValidator = None  # type: ignore[assignment]
    SharedPostHogPersonalApiKeyValidator = None  # type: ignore[assignment]
    SharedSentryAuthTokenValidator = None  # type: ignore[assignment]
    SharedSendgridKeyValidator = None  # type: ignore[assignment]
    SharedSlackTokenValidator = None  # type: ignore[assignment]
    SharedStripeKeyValidator = None  # type: ignore[assignment]
    SharedTelegramBotTokenValidator = None  # type: ignore[assignment]
    SharedVercelTokenValidator = None  # type: ignore[assignment]

_GITHUB_SEARCH_URL = "https://api.github.com/search/code"
_GITLAB_SEARCH_URL = "https://gitlab.com/api/v4/search"
_GITLAB_PROJECT_URL = "https://gitlab.com/api/v4/projects"
_GITHUB_RATE_LIMITER = AdaptiveRateLimiter(base_delay=2.0, max_delay=120.0, min_delay=2.0)

_PATTERNS_FILE = Path(__file__).parent / "data" / "api_key_patterns.json"

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS key_scanner_findings (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id    INTEGER NOT NULL,
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
)
"""


class ValidationState(str, Enum):
    ACTIVE = "ACTIVE"
    REVOKED = "REVOKED"
    UNCONFIRMED = "UNCONFIRMED"
    ERROR = "ERROR"


@dataclass
class ValidationResult:
    state: ValidationState
    detail: Optional[str] = None


def _redact(key: str) -> str:
    if len(key) > 8:
        return f"{key[:4]}...{key[-4:]}"
    return "****"


def _load_patterns() -> list[dict]:
    with open(_PATTERNS_FILE) as f:
        return json.load(f)["patterns"]


# ---------------------------------------------------------------------------
# Key Validators
# ---------------------------------------------------------------------------

_PLACEHOLDER_IDENTIFIERS = {
    "admin",
    "bot",
    "demo",
    "dummy",
    "example",
    "fake",
    "mock",
    "unknown",
    "none",
    "null",
    "placeholder",
    "sample",
    "test",
    "user",
    "undefined",
    "na",
    "n_a",
}


def _looks_sequential_numeric_identifier(value: object) -> bool:
    digits = [int(char) for char in re.sub(r"[^0-9]+", "", str(value or ""))]
    if len(digits) < 6:
        return False
    return all((right - left) % 10 == 1 for left, right in zip(digits, digits[1:])) or all(
        (left - right) % 10 == 1 for left, right in zip(digits, digits[1:])
    )


def _has_placeholder_identifier_token(value: object) -> bool:
    parts = [part for part in re.split(r"[_-]+", str(value or "").strip().lower()) if part]
    return len(parts) > 1 and any(part in _PLACEHOLDER_IDENTIFIERS for part in parts)


def _stable_github_login(value: object) -> str:
    login = re.sub(r"[^A-Za-z0-9-]+", "", str(value or "").strip())
    if not login or not re.search(r"[A-Za-z0-9]", login):
        return ""
    if login.lower() in _PLACEHOLDER_IDENTIFIERS:
        return ""
    if _has_placeholder_identifier_token(login) or looks_compound_placeholder_identifier(login):
        return ""
    compact = re.sub(r"[^A-Za-z0-9]+", "", login).lower()
    if len(compact) >= 3 and len(set(compact)) == 1:
        return ""
    return login


def _stable_github_user_id(value: object) -> str:
    user_id = re.sub(r"[^0-9]+", "", str(value or "").strip())
    if not re.fullmatch(r"[0-9]{2,16}", user_id):
        return ""
    if len(set(user_id)) == 1:
        return ""
    if _looks_sequential_numeric_identifier(user_id):
        return ""
    return user_id


def _github_profile_url_matches_login(payload: object) -> bool:
    if not isinstance(payload, dict):
        return False
    login = _stable_github_login(payload.get("login"))
    if not login:
        return False
    parsed = urlparse(str(payload.get("html_url") or "").strip())
    path_parts = [part for part in str(parsed.path or "").split("/") if part]
    return (
        str(parsed.hostname or "").lower() == "github.com"
        and bool(path_parts)
        and path_parts[0].lower() == login.lower()
    )


def _github_has_profile_proof(payload: object) -> bool:
    if not isinstance(payload, dict):
        return False
    for field in ("name", "avatar_url", "html_url", "blog", "email"):
        raw = str(payload.get(field) or "").strip()
        if not raw:
            continue
        if field == "email" and re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", raw):
            return True
        compact = re.sub(r"[^A-Za-z0-9]+", "", raw).lower()
        if len(compact) >= 3 and compact not in _PLACEHOLDER_IDENTIFIERS:
            return True
    return False


def _stripe_has_balance_proof(payload: object) -> bool:
    return (
        isinstance(payload, dict) and str(payload.get("object") or "").strip().lower() == "balance"
    )


def _stripe_balance_detail(payload: object) -> str:
    if not isinstance(payload, dict):
        return "Stripe balance accessible: mode=unknown currencies=unknown"
    livemode = payload.get("livemode")
    mode = "live" if livemode is True else "test" if livemode is False else "unknown"
    currencies: set[str] = set()
    for family in ("available", "pending"):
        entries = payload.get(family)
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            currency = str(entry.get("currency") or "").strip().lower()
            if currency:
                currencies.add(currency)
    currency_summary = ",".join(sorted(currencies)) if currencies else "none"
    return f"Stripe balance accessible: mode={mode} currencies={currency_summary}"


def _sendgrid_has_profile_proof(payload: object) -> bool:
    if not isinstance(payload, dict):
        return False
    return bool(str(payload.get("email") or "").strip()) or bool(
        str(payload.get("username") or "").strip()
    )


def _sendgrid_profile_detail(payload: object) -> str:
    if not isinstance(payload, dict):
        return "SendGrid profile ok: proof=profile"
    parts = ["proof=profile"]
    for key in ("email", "username"):
        value = str(payload.get(key) or "").strip().lower()
        if value:
            parts.append(f"profile_hash={hashlib.sha256(value.encode('utf-8')).hexdigest()[:16]}")
            break
    if str(payload.get("email") or "").strip():
        parts.append("email_present=true")
    if str(payload.get("username") or "").strip():
        parts.append("username_present=true")
    return "SendGrid profile ok: " + " ".join(parts)


class BaseKeyValidator(ABC):
    result_validation_method = "validator_api"

    @abstractmethod
    def validate(self, key: str, proxy: Optional[str] = None) -> ValidationResult: ...


class GithubPatValidator(BaseKeyValidator):
    API_URL = "https://api.github.com/user"
    result_validation_method = "github_user_api"

    def validate(self, key: str, proxy: Optional[str] = None) -> ValidationResult:
        try:
            import httpx

            transport = httpx.HTTPTransport(proxy=proxy) if proxy else None
            with httpx.Client(transport=transport, timeout=10) as client:
                resp = client.get(
                    self.API_URL,
                    headers={
                        "Authorization": f"Bearer {key}",
                        "Accept": "application/vnd.github+json",
                    },
                )
            if resp.status_code == 200:
                try:
                    payload = resp.json()
                except Exception:  # noqa: BLE001
                    payload = {}
                login = _stable_github_login(
                    payload.get("login") if isinstance(payload, dict) else ""
                )
                if not login:
                    return ValidationResult(
                        state=ValidationState.UNCONFIRMED,
                        detail="GitHub user response missing login",
                    )
                user_id = _stable_github_user_id(
                    payload.get("id") if isinstance(payload, dict) else ""
                )
                if not user_id:
                    return ValidationResult(
                        state=ValidationState.UNCONFIRMED,
                        detail="GitHub user response missing user id",
                    )
                if not _github_has_profile_proof(payload):
                    return ValidationResult(
                        state=ValidationState.UNCONFIRMED,
                        detail="GitHub user response missing user proof",
                    )
                if not _github_profile_url_matches_login(payload):
                    return ValidationResult(
                        state=ValidationState.UNCONFIRMED,
                        detail="GitHub user response missing matching profile URL",
                    )
                return ValidationResult(
                    state=ValidationState.ACTIVE,
                    detail=(
                        "GitHub user ok: "
                        f"user_id={user_id} "
                        f"login={login} "
                        "user_profile_present=true "
                        "profile_url_matches_login=true"
                    ),
                )
            if resp.status_code == 401:
                return ValidationResult(state=ValidationState.REVOKED)
            return ValidationResult(state=ValidationState.ERROR, detail=f"HTTP {resp.status_code}")
        except Exception as e:
            return ValidationResult(state=ValidationState.ERROR, detail=str(e))


class StripeKeyValidator(BaseKeyValidator):
    API_URL = "https://api.stripe.com/v1/balance"
    result_validation_method = "stripe_balance_api"

    def validate(self, key: str, proxy: Optional[str] = None) -> ValidationResult:
        try:
            import httpx

            transport = httpx.HTTPTransport(proxy=proxy) if proxy else None
            with httpx.Client(transport=transport, timeout=10) as client:
                resp = client.get(self.API_URL, headers={"Authorization": f"Bearer {key}"})
            if resp.status_code == 200:
                try:
                    payload = resp.json()
                except Exception:  # noqa: BLE001
                    payload = {}
                if not _stripe_has_balance_proof(payload):
                    return ValidationResult(
                        state=ValidationState.UNCONFIRMED,
                        detail="Stripe balance response missing balance object",
                    )
                return ValidationResult(
                    state=ValidationState.ACTIVE,
                    detail=_stripe_balance_detail(payload),
                )
            if resp.status_code == 401:
                return ValidationResult(state=ValidationState.REVOKED)
            return ValidationResult(state=ValidationState.ERROR, detail=f"HTTP {resp.status_code}")
        except Exception as e:
            return ValidationResult(state=ValidationState.ERROR, detail=str(e))


class SendgridKeyValidator(BaseKeyValidator):
    API_URL = "https://api.sendgrid.com/v3/user/profile"
    result_validation_method = "sendgrid_profile_api"

    def validate(self, key: str, proxy: Optional[str] = None) -> ValidationResult:
        try:
            import httpx

            transport = httpx.HTTPTransport(proxy=proxy) if proxy else None
            with httpx.Client(transport=transport, timeout=10) as client:
                resp = client.get(self.API_URL, headers={"Authorization": f"Bearer {key}"})
            if resp.status_code == 200:
                try:
                    payload = resp.json()
                except Exception:  # noqa: BLE001
                    payload = {}
                if not _sendgrid_has_profile_proof(payload):
                    return ValidationResult(
                        state=ValidationState.UNCONFIRMED,
                        detail="SendGrid profile response missing profile proof",
                    )
                return ValidationResult(
                    state=ValidationState.ACTIVE,
                    detail=_sendgrid_profile_detail(payload),
                )
            if resp.status_code == 401:
                return ValidationResult(state=ValidationState.REVOKED)
            return ValidationResult(state=ValidationState.ERROR, detail=f"HTTP {resp.status_code}")
        except Exception as e:
            return ValidationResult(state=ValidationState.ERROR, detail=str(e))


class TwilioKeyValidator(BaseKeyValidator):
    result_validation_method = "twilio_account_api"

    def validate(self, key: str, proxy: Optional[str] = None) -> ValidationResult:
        return ValidationResult(
            state=ValidationState.UNCONFIRMED,
            detail="Twilio requires account SID + auth token pair",
        )


class AwsKeyValidator(BaseKeyValidator):
    result_validation_method = "aws_sts_get_caller_identity"

    def validate(
        self, key: str, secret: Optional[str] = None, proxy: Optional[str] = None
    ) -> ValidationResult:
        if not secret:
            return ValidationResult(
                state=ValidationState.UNCONFIRMED,
                detail="AWS secret key not found adjacent to access key ID",
            )
        return ValidationResult(
            state=ValidationState.UNCONFIRMED,
            detail="AWS validation requires signed STS request — not yet implemented",
        )


_VALIDATOR_MAP: dict[str, BaseKeyValidator] = {
    "GithubPatValidator": GithubPatValidator(),
    "StripeKeyValidator": StripeKeyValidator(),
    "SendgridKeyValidator": SendgridKeyValidator(),
    "TwilioKeyValidator": TwilioKeyValidator(),
    "AwsKeyValidator": AwsKeyValidator(),
}
if SharedGoogleApiKeyValidator is not None:
    _VALIDATOR_MAP["GoogleApiKeyValidator"] = SharedGoogleApiKeyValidator()  # type: ignore[assignment]
if SharedOpenAIKeyValidator is not None:
    _VALIDATOR_MAP["OpenAIKeyValidator"] = SharedOpenAIKeyValidator()  # type: ignore[assignment]
if SharedAnthropicKeyValidator is not None:
    _VALIDATOR_MAP["AnthropicKeyValidator"] = SharedAnthropicKeyValidator()  # type: ignore[assignment]
if SharedHuggingFaceTokenValidator is not None:
    _VALIDATOR_MAP["HuggingFaceTokenValidator"] = SharedHuggingFaceTokenValidator()  # type: ignore[assignment]
if SharedDiscordBotTokenValidator is not None:
    _VALIDATOR_MAP["DiscordBotTokenValidator"] = SharedDiscordBotTokenValidator()  # type: ignore[assignment]
if SharedTelegramBotTokenValidator is not None:
    _VALIDATOR_MAP["TelegramBotTokenValidator"] = SharedTelegramBotTokenValidator()  # type: ignore[assignment]
if SharedNotionTokenValidator is not None:
    _VALIDATOR_MAP["NotionTokenValidator"] = SharedNotionTokenValidator()  # type: ignore[assignment]
if SharedDatadogApiKeyValidator is not None:
    _VALIDATOR_MAP["DatadogApiKeyValidator"] = SharedDatadogApiKeyValidator()  # type: ignore[assignment]
if SharedCloudflareApiTokenValidator is not None:
    _VALIDATOR_MAP["CloudflareApiTokenValidator"] = SharedCloudflareApiTokenValidator()  # type: ignore[assignment]
if SharedVercelTokenValidator is not None:
    _VALIDATOR_MAP["VercelTokenValidator"] = SharedVercelTokenValidator()  # type: ignore[assignment]
if SharedNetlifyTokenValidator is not None:
    _VALIDATOR_MAP["NetlifyTokenValidator"] = SharedNetlifyTokenValidator()  # type: ignore[assignment]
if SharedPostHogPersonalApiKeyValidator is not None:
    _VALIDATOR_MAP["PostHogPersonalApiKeyValidator"] = SharedPostHogPersonalApiKeyValidator()  # type: ignore[assignment]
if SharedSentryAuthTokenValidator is not None:
    _VALIDATOR_MAP["SentryAuthTokenValidator"] = SharedSentryAuthTokenValidator()  # type: ignore[assignment]
if SharedGitlabPatValidator is not None:
    _VALIDATOR_MAP["GitlabPatValidator"] = SharedGitlabPatValidator()  # type: ignore[assignment]
if SharedSlackTokenValidator is not None:
    _VALIDATOR_MAP["SlackTokenValidator"] = SharedSlackTokenValidator()  # type: ignore[assignment]
if SharedMailchimpKeyValidator is not None:
    _VALIDATOR_MAP["MailchimpKeyValidator"] = SharedMailchimpKeyValidator()  # type: ignore[assignment]
if SharedAzureStorageConnectionStringValidator is not None:
    _VALIDATOR_MAP["AzureStorageConnectionStringValidator"] = (
        SharedAzureStorageConnectionStringValidator()
    )  # type: ignore[assignment]
if SharedStripeKeyValidator is not None:
    _VALIDATOR_MAP["StripeKeyValidator"] = SharedStripeKeyValidator()  # type: ignore[assignment]
if SharedSendgridKeyValidator is not None:
    _VALIDATOR_MAP["SendgridKeyValidator"] = SharedSendgridKeyValidator()  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# GitHub code search
# ---------------------------------------------------------------------------


def _github_keyscan(pattern: dict, domain: str, github_token: str) -> list[dict]:
    regex = pattern["regex"]
    query = f"{regex} {domain}"
    url = f"{_GITHUB_SEARCH_URL}?q={query}&per_page=30"
    _GITHUB_RATE_LIMITER.wait(url)
    try:
        import httpx

        resp = httpx.get(
            url,
            headers={
                "Authorization": f"Bearer {github_token}",
                "Accept": "application/vnd.github+json",
            },
            timeout=15,
        )
        if resp.status_code == 429:
            _GITHUB_RATE_LIMITER.record_failure(url, 429)
            reset = int(resp.headers.get("X-RateLimit-Reset", time.time() + 60))
            wait_secs = max(0, reset - time.time()) + 1
            _LOG.warning("GitHub rate limited — waiting %ds", wait_secs)
            _interruptible_sleep(min(wait_secs, 120))
            return []
        if resp.status_code != 200:
            return []
        _GITHUB_RATE_LIMITER.record_success(url)
        items = resp.json().get("items") or []
        hits = []
        for item in items:
            repo_name = str(item.get("repository", {}).get("full_name", "") or "")
            file_path = str(item.get("path", "") or "")
            default_branch = str(item.get("repository", {}).get("default_branch", "main") or "main")
            raw_url = (
                f"https://raw.githubusercontent.com/{repo_name}/{default_branch}/{file_path}"
                if repo_name and file_path
                else ""
            )
            hits.append(
                {
                    "source_url": item.get("html_url", ""),
                    "repo_name": repo_name,
                    "file_path": file_path,
                    "raw_url": raw_url,
                    "backend": "github",
                }
            )
        return hits
    except Exception as e:
        _LOG.warning("GitHub keyscan error: %s", e)
        return []


def _gitlab_project_info(project_id: str, gitlab_token: str) -> dict[str, str]:
    try:
        import httpx

        resp = httpx.get(
            f"{_GITLAB_PROJECT_URL}/{quote(project_id, safe='')}",
            headers={"PRIVATE-TOKEN": gitlab_token},
            timeout=15,
        )
        if resp.status_code != 200:
            return {}
        payload = resp.json() or {}
    except Exception as e:
        _LOG.warning("GitLab project metadata fetch error: %s", e)
        return {}
    return {
        "path_with_namespace": str(payload.get("path_with_namespace") or ""),
        "web_url": str(payload.get("web_url") or ""),
        "default_branch": str(payload.get("default_branch") or "main"),
    }


def _gitlab_keyscan(pattern: dict, domain: str, gitlab_token: str) -> list[dict]:
    regex = pattern["regex"]
    query = f"{regex} {domain}"
    try:
        import httpx

        resp = httpx.get(
            _GITLAB_SEARCH_URL,
            params={"scope": "blobs", "search": query},
            headers={"PRIVATE-TOKEN": gitlab_token},
            timeout=20,
        )
        if resp.status_code in {403, 429}:
            retry_after = resp.headers.get("Retry-After") or resp.headers.get("RateLimit-Reset")
            try:
                wait_secs = int(retry_after or "60")
            except ValueError:
                wait_secs = 60
            _LOG.warning("GitLab rate limited — waiting %ds", wait_secs)
            _interruptible_sleep(min(max(0, wait_secs), 120))
            return []
        if resp.status_code != 200:
            return []
        payload = resp.json()
        items = payload.get("results", []) if isinstance(payload, dict) else payload
        if not isinstance(items, list):
            return []
        hits = []
        project_cache: dict[str, dict[str, str]] = {}
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
            project = project_cache.get(project_id)
            if project is None:
                project = _gitlab_project_info(project_id, gitlab_token)
                project_cache[project_id] = project
            ref = str(item.get("ref") or project.get("default_branch") or "main")
            web_url = project.get("web_url", "")
            source_url = (
                str(item.get("web_url") or "")
                or (f"{web_url}/-/blob/{ref}/{quote(file_path, safe='/')}" if web_url else "")
                or f"gitlab://project/{project_id}/{ref}/{file_path}"
            )
            raw_url = (
                f"{_GITLAB_PROJECT_URL}/{quote(project_id, safe='')}/repository/files/"
                f"{quote(file_path, safe='')}/raw"
            )
            hits.append(
                {
                    "source_url": source_url,
                    "repo_name": project.get("path_with_namespace", ""),
                    "file_path": file_path,
                    "raw_url": raw_url,
                    "ref": ref,
                    "backend": "gitlab",
                    "content": str(item.get("data") or ""),
                }
            )
        return hits
    except Exception as e:
        _LOG.warning("GitLab keyscan error: %s", e)
        return []


def _fetch_file_content(
    raw_url: str,
    token: Optional[str] = None,
    *,
    backend: str = "github",
    ref: Optional[str] = None,
) -> str:
    if not raw_url:
        return ""
    try:
        import httpx

        headers = {"Accept": "text/plain"}
        params = None
        if token and backend == "gitlab":
            headers["PRIVATE-TOKEN"] = token
            params = {"ref": ref or "main"} if ref else None
        elif token:
            headers["Authorization"] = f"Bearer {token}"
        resp = httpx.get(raw_url, headers=headers, params=params, timeout=15)
        if resp.status_code != 200:
            return ""
        return str(resp.text or "")
    except Exception as e:
        _LOG.warning("%s keyscan content fetch error: %s", backend, e)
        return ""


def _extract_keys_from_content(content: str, pattern_regex: str, group: int = 0) -> list[str]:
    keys: list[str] = []
    seen: set[str] = set()
    if not content:
        return keys
    try:
        compiled = re.compile(pattern_regex, re.MULTILINE)
    except re.error:
        return keys
    for match in compiled.finditer(content):
        try:
            value = match.group(group) if group else match.group(0)
        except IndexError:
            continue
        value = str(value or "").strip()
        if not value or value in seen:
            continue
        seen.add(value)
        keys.append(value)
    return keys


# ---------------------------------------------------------------------------
# Main scan function
# ---------------------------------------------------------------------------


def run_keyscan(
    engagement_id: int,
    engagement_scope: list[str],
    domain: str,
    eng_db_conn: sqlite3.Connection,
    github_token: Optional[str] = None,
    gitlab_token: Optional[str] = None,
    no_validate: bool = False,
    validation_proxy: Optional[str] = None,
    dry_run: bool = False,
) -> int:
    """Search GitHub/GitLab for exposed API keys and validate them.

    Returns count of findings stored.
    """
    assert_in_scope(domain, engagement_scope)
    eng_db_conn.execute(SCHEMA_SQL)
    eng_db_conn.commit()

    if not no_validate and not validation_proxy:
        _LOG.warning("[KEYSCAN] No --validation-proxy set — validation calls will be direct")

    if not no_validate:
        # FORGE_KEYSCAN_ASSUME_YES=1 bypasses the OPSEC prompt so kill-chain
        # attack-mode runs (non-TTY subprocesses) can proceed. Requires the
        # caller to have already asserted scope/ROE upstream.
        if os.environ.get("FORGE_KEYSCAN_ASSUME_YES", "0").strip() == "1":
            _LOG.info("[KEYSCAN] FORGE_KEYSCAN_ASSUME_YES=1 — skipping OPSEC prompt")
        else:
            try:
                import questionary

                if not questionary.confirm(
                    f"[KEYSCAN OPSEC] Validation calls will be made to AWS/Stripe/GitHub/etc APIs.\n"
                    f"These calls are logged by the service and may trigger alerts.\n"
                    f"Proxy: {validation_proxy or 'NONE (direct)'}\n"
                    f"Proceed?"
                ).ask():
                    print("[ABORTED] Key validation cancelled.")
                    no_validate = True
            except ImportError:
                pass

    if dry_run:
        patterns = _load_patterns()
        print(f"[DRY-RUN] Would scan for {len(patterns)} patterns on domain={domain}")
        return 0

    if not wait_for_internet():
        return 0

    patterns = _load_patterns()
    count = 0

    for pattern in patterns:
        if _SHUTDOWN.is_set():
            break
        hits: list[dict] = []
        if github_token:
            hits.extend(with_internet_retry(_github_keyscan, pattern, domain, github_token) or [])
        if gitlab_token:
            hits.extend(with_internet_retry(_gitlab_keyscan, pattern, domain, gitlab_token) or [])
        if not hits:
            continue

        for hit in hits:
            if _SHUTDOWN.is_set():
                break

            source_url = str(hit.get("source_url") or "")
            raw_url = str(hit.get("raw_url") or source_url)
            backend = str(hit.get("backend") or "github")
            fetch_token = gitlab_token if backend == "gitlab" else github_token
            content = str(hit.get("content") or "")
            fetched_content = _fetch_file_content(
                raw_url,
                fetch_token,
                backend=backend,
                ref=str(hit.get("ref") or "") or None,
            )
            if fetched_content:
                content = fetched_content
            raw_keys = _extract_keys_from_content(
                content,
                str(pattern.get("regex") or ""),
                int(pattern.get("group") or 0),
            )
            if not raw_keys:
                continue

            for raw_key in raw_keys:
                if _SHUTDOWN.is_set():
                    break

                # Dedup check
                existing = eng_db_conn.execute(
                    "SELECT id FROM key_scanner_findings WHERE engagement_id=? AND source_url=? AND pattern_name=?",
                    (engagement_id, source_url, pattern["name"]),
                ).fetchone()
                if existing:
                    continue

                key_redacted = _redact(raw_key)
                key_enc = encrypt_string(raw_key) if not no_validate else None

                validation_state = ValidationState.UNCONFIRMED
                validation_detail = None

                if not no_validate:
                    validator_name = pattern.get("validation_method")
                    validator = _VALIDATOR_MAP.get(validator_name) if validator_name else None
                    if validator:
                        result = validator.validate(raw_key, proxy=validation_proxy)
                        validation_state = result.state
                        validation_detail = result.detail
                        validation_method = str(
                            getattr(validator, "result_validation_method", "") or ""
                        ).strip()
                        if validation_method and validation_state == ValidationState.ACTIVE:
                            validation_detail = (
                                f"VALIDATED:{validation_method}:{validation_detail or ''}"
                            )

                cur = eng_db_conn.execute(
                    """INSERT OR IGNORE INTO key_scanner_findings
                       (engagement_id, domain, service, pattern_name, source_backend,
                        source_url, repo_name, key_redacted, key_enc, validation_state, validation_detail)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        engagement_id,
                        domain,
                        pattern["service"],
                        pattern["name"],
                        hit["backend"],
                        source_url,
                        hit.get("repo_name"),
                        key_redacted,
                        key_enc,
                        validation_state.value,
                        validation_detail,
                    ),
                )
                eng_db_conn.commit()
                if cur.rowcount <= 0:
                    continue
                count += 1
                print(
                    f"[KEYSCAN] Found {pattern['name']} in {source_url} — {validation_state.value}",
                    flush=True,
                )
                sys.stdout.flush()

    return count
