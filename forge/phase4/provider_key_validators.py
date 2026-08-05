"""forge/phase4/provider_key_validators.py — strict provider key validators.

Task 19. Deterministic read-only proof for 9 credential families:
Twilio, SendGrid, Slack, Stripe, Mailchimp, Discord, GitHub App,
Azure Storage shared-key connection strings, AWS access-key+secret pairs.

**Strict mode (user pick 19-2A):** a probe endpoint returning HTTP 200
is not enough — the response payload must also match the expected
shape for that provider. If payload shape is unrecognised, the result
is UNVERIFIED, not VERIFIED. This eliminates the "low-signal 200"
false-positive class.

**Scope gate:** callers MUST run the target through
:func:`forge.opsec.scope_gate.assert_in_scope` before invoking any
validator here. This module intentionally does not import scope_gate —
its job is the read-only proof, not authorisation.

**No destructive actions.** Every validator issues at most one GET / POST
against a documented read-only endpoint. No writes, no deletes, no
sends. Rate limits respected via ``FORGE_KEY_VALIDATION_*`` env
knobs — see forge/config.py.

**No plaintext persistence.** Credentials are consumed by ``probe()`` and
discarded. Any persistence is the caller's responsibility (typically
age-encrypted via forge/opsec/crypto.py).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol
from urllib.parse import quote

try:  # pragma: no cover — imported lazily elsewhere too
    import httpx
except ImportError:  # pragma: no cover
    httpx = None  # type: ignore[assignment]


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass
class ProviderCredential:
    provider: str
    identifier: str  # short display value, safe for logging (first4...last4)
    material: dict[str, str]  # actual credential parts; scope-limited to the probe


@dataclass
class ValidationResult:
    verified: bool
    provider: str
    reason: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "verified": self.verified,
            "provider": self.provider,
            "reason": self.reason,
            "metadata": dict(self.metadata),
        }


class ProviderKeyValidator(Protocol):
    provider: str

    def matches(self, raw: str) -> bool: ...
    def parse(self, raw: str) -> ProviderCredential | None: ...
    def probe(
        self,
        cred: ProviderCredential,
        *,
        client: "httpx.Client | None" = None,
        timeout: float = 10.0,
    ) -> ValidationResult: ...


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _redact(value: str) -> str:
    """first4...last4 redaction for safe display."""
    if len(value) <= 8:
        return "***"
    return f"{value[:4]}...{value[-4:]}"


def _http_client(client: "httpx.Client | None") -> "httpx.Client":
    if client is not None:
        return client
    if httpx is None:  # pragma: no cover
        raise RuntimeError("httpx not installed; provider validators require it")
    return httpx.Client(follow_redirects=False, http2=False)


def _pace_delay() -> float:
    return float(os.environ.get("FORGE_KEY_VALIDATION_REQUEST_DELAY_SECONDS") or 0.25)


def _sleep_pace() -> None:
    delay = _pace_delay()
    if delay > 0:
        time.sleep(min(delay, 5.0))


# ---------------------------------------------------------------------------
# Twilio
# ---------------------------------------------------------------------------


class TwilioValidator:
    provider = "twilio"

    _SID_RE = re.compile(r"\bAC[0-9a-fA-F]{32}\b")

    def matches(self, raw: str) -> bool:
        return bool(self._SID_RE.search(raw or ""))

    def parse(self, raw: str) -> ProviderCredential | None:
        # Expects "AC<32 hex>:<auth_token>" or a JSON blob with both parts
        text = str(raw or "").strip()
        sid_match = self._SID_RE.search(text)
        if not sid_match:
            return None
        sid = sid_match.group(0)
        # Look for a paired token in the remainder — 32-char hex commonly.
        remainder = text.replace(sid, " ").strip(" :,;\"'")
        token_match = re.search(r"\b[0-9a-fA-F]{32}\b", remainder)
        if not token_match:
            return None
        return ProviderCredential(
            provider=self.provider,
            identifier=_redact(sid),
            material={"account_sid": sid, "auth_token": token_match.group(0)},
        )

    def probe(
        self,
        cred: ProviderCredential,
        *,
        client: "httpx.Client | None" = None,
        timeout: float = 10.0,
    ) -> ValidationResult:
        _sleep_pace()
        sid = cred.material["account_sid"]
        token = cred.material["auth_token"]
        url = f"https://api.twilio.com/2010-04-01/Accounts/{sid}.json"
        c = _http_client(client)
        try:
            r = c.get(url, auth=(sid, token), timeout=timeout)
        except Exception as exc:  # noqa: BLE001
            return ValidationResult(False, self.provider, f"request failed: {exc}")
        if r.status_code != 200:
            return ValidationResult(False, self.provider, f"http {r.status_code}")
        try:
            body = r.json()
        except (ValueError, json.JSONDecodeError):
            return ValidationResult(False, self.provider, "non-JSON response")
        # Strict payload check: expect sid, friendly_name, status keys.
        required = {"sid", "friendly_name", "status"}
        if not required.issubset(set(body.keys())):
            return ValidationResult(
                False, self.provider,
                f"payload shape unexpected (keys: {sorted(body.keys())[:6]})",
            )
        return ValidationResult(
            True, self.provider,
            "twilio account probe returned canonical fields",
            metadata={
                "friendly_name": body.get("friendly_name"),
                "status": body.get("status"),
                "type": body.get("type"),
            },
        )


# ---------------------------------------------------------------------------
# SendGrid
# ---------------------------------------------------------------------------


class SendGridValidator:
    provider = "sendgrid"

    _KEY_RE = re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b")

    def matches(self, raw: str) -> bool:
        return bool(self._KEY_RE.search(raw or ""))

    def parse(self, raw: str) -> ProviderCredential | None:
        m = self._KEY_RE.search(raw or "")
        if not m:
            return None
        key = m.group(0)
        return ProviderCredential(
            provider=self.provider,
            identifier=_redact(key),
            material={"api_key": key},
        )

    def probe(
        self,
        cred: ProviderCredential,
        *,
        client: "httpx.Client | None" = None,
        timeout: float = 10.0,
    ) -> ValidationResult:
        _sleep_pace()
        c = _http_client(client)
        try:
            r = c.get(
                "https://api.sendgrid.com/v3/user/account",
                headers={"Authorization": f"Bearer {cred.material['api_key']}"},
                timeout=timeout,
            )
        except Exception as exc:  # noqa: BLE001
            return ValidationResult(False, self.provider, f"request failed: {exc}")
        if r.status_code != 200:
            return ValidationResult(False, self.provider, f"http {r.status_code}")
        try:
            body = r.json()
        except (ValueError, json.JSONDecodeError):
            return ValidationResult(False, self.provider, "non-JSON response")
        if "type" not in body or "reputation" not in body:
            return ValidationResult(
                False, self.provider,
                f"payload shape unexpected (keys: {sorted(body.keys())[:6]})",
            )
        return ValidationResult(
            True, self.provider,
            "sendgrid /user/account returned canonical fields",
            metadata={
                "account_type": body.get("type"),
                "reputation": body.get("reputation"),
            },
        )


# ---------------------------------------------------------------------------
# Slack
# ---------------------------------------------------------------------------


class SlackValidator:
    provider = "slack"

    _TOKEN_RE = re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")

    def matches(self, raw: str) -> bool:
        return bool(self._TOKEN_RE.search(raw or ""))

    def parse(self, raw: str) -> ProviderCredential | None:
        m = self._TOKEN_RE.search(raw or "")
        if not m:
            return None
        token = m.group(0)
        return ProviderCredential(
            provider=self.provider,
            identifier=_redact(token),
            material={"token": token},
        )

    def probe(
        self,
        cred: ProviderCredential,
        *,
        client: "httpx.Client | None" = None,
        timeout: float = 10.0,
    ) -> ValidationResult:
        _sleep_pace()
        c = _http_client(client)
        try:
            r = c.post(
                "https://slack.com/api/auth.test",
                headers={"Authorization": f"Bearer {cred.material['token']}"},
                timeout=timeout,
            )
        except Exception as exc:  # noqa: BLE001
            return ValidationResult(False, self.provider, f"request failed: {exc}")
        if r.status_code != 200:
            return ValidationResult(False, self.provider, f"http {r.status_code}")
        try:
            body = r.json()
        except (ValueError, json.JSONDecodeError):
            return ValidationResult(False, self.provider, "non-JSON response")
        # Slack returns { "ok": true/false, "team_id": ..., "user_id": ... }
        if not body.get("ok"):
            return ValidationResult(
                False, self.provider,
                f"slack rejected: {body.get('error', 'unknown')}",
            )
        if "team_id" not in body or "user_id" not in body:
            return ValidationResult(
                False, self.provider, "auth.test missing team_id/user_id",
            )
        return ValidationResult(
            True, self.provider,
            "slack auth.test returned ok + team_id + user_id",
            metadata={
                "team": body.get("team"),
                "team_id": body.get("team_id"),
                "user": body.get("user"),
            },
        )


# ---------------------------------------------------------------------------
# Stripe
# ---------------------------------------------------------------------------


class StripeValidator:
    provider = "stripe"

    _KEY_RE = re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{20,}\b")

    def matches(self, raw: str) -> bool:
        return bool(self._KEY_RE.search(raw or ""))

    def parse(self, raw: str) -> ProviderCredential | None:
        m = self._KEY_RE.search(raw or "")
        if not m:
            return None
        key = m.group(0)
        return ProviderCredential(
            provider=self.provider,
            identifier=_redact(key),
            material={"secret_key": key, "mode": "test" if "sk_test_" in key else "live"},
        )

    def probe(
        self,
        cred: ProviderCredential,
        *,
        client: "httpx.Client | None" = None,
        timeout: float = 10.0,
    ) -> ValidationResult:
        _sleep_pace()
        c = _http_client(client)
        try:
            r = c.get(
                "https://api.stripe.com/v1/account",
                auth=(cred.material["secret_key"], ""),
                timeout=timeout,
            )
        except Exception as exc:  # noqa: BLE001
            return ValidationResult(False, self.provider, f"request failed: {exc}")
        if r.status_code != 200:
            return ValidationResult(False, self.provider, f"http {r.status_code}")
        try:
            body = r.json()
        except (ValueError, json.JSONDecodeError):
            return ValidationResult(False, self.provider, "non-JSON response")
        if body.get("object") != "account" or "id" not in body:
            return ValidationResult(
                False, self.provider,
                "payload shape unexpected — expected object=account + id",
            )
        return ValidationResult(
            True, self.provider,
            "stripe /v1/account returned account object",
            metadata={
                "account_id": body.get("id"),
                "country": body.get("country"),
                "mode": cred.material["mode"],
            },
        )


# ---------------------------------------------------------------------------
# Mailchimp
# ---------------------------------------------------------------------------


class MailchimpValidator:
    provider = "mailchimp"

    _KEY_RE = re.compile(r"\b[a-f0-9]{32}-us[0-9]{1,3}\b")

    def matches(self, raw: str) -> bool:
        return bool(self._KEY_RE.search(raw or ""))

    def parse(self, raw: str) -> ProviderCredential | None:
        m = self._KEY_RE.search(raw or "")
        if not m:
            return None
        key = m.group(0)
        dc = key.rsplit("-", 1)[-1]
        return ProviderCredential(
            provider=self.provider,
            identifier=_redact(key),
            material={"api_key": key, "datacenter": dc},
        )

    def probe(
        self,
        cred: ProviderCredential,
        *,
        client: "httpx.Client | None" = None,
        timeout: float = 10.0,
    ) -> ValidationResult:
        _sleep_pace()
        c = _http_client(client)
        url = f"https://{cred.material['datacenter']}.api.mailchimp.com/3.0/ping"
        try:
            r = c.get(url, auth=("anystring", cred.material["api_key"]), timeout=timeout)
        except Exception as exc:  # noqa: BLE001
            return ValidationResult(False, self.provider, f"request failed: {exc}")
        if r.status_code != 200:
            return ValidationResult(False, self.provider, f"http {r.status_code}")
        try:
            body = r.json()
        except (ValueError, json.JSONDecodeError):
            return ValidationResult(False, self.provider, "non-JSON response")
        # Mailchimp /ping returns {"health_status": "Everything's Chimpy!"}
        if "health_status" not in body:
            return ValidationResult(False, self.provider, "payload shape unexpected")
        return ValidationResult(
            True, self.provider, "mailchimp /ping returned health_status",
            metadata={
                "datacenter": cred.material["datacenter"],
                "health_status": body.get("health_status"),
            },
        )


# ---------------------------------------------------------------------------
# Discord
# ---------------------------------------------------------------------------


class DiscordValidator:
    provider = "discord"

    # Discord bot tokens are three base64url segments separated by '.'
    _TOKEN_RE = re.compile(
        r"\b[MNOZ][A-Za-z0-9]{23,25}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,}\b"
    )

    def matches(self, raw: str) -> bool:
        return bool(self._TOKEN_RE.search(raw or ""))

    def parse(self, raw: str) -> ProviderCredential | None:
        m = self._TOKEN_RE.search(raw or "")
        if not m:
            return None
        token = m.group(0)
        return ProviderCredential(
            provider=self.provider,
            identifier=_redact(token),
            material={"token": token},
        )

    def probe(
        self,
        cred: ProviderCredential,
        *,
        client: "httpx.Client | None" = None,
        timeout: float = 10.0,
    ) -> ValidationResult:
        _sleep_pace()
        c = _http_client(client)
        try:
            r = c.get(
                "https://discord.com/api/v10/users/@me",
                headers={"Authorization": f"Bot {cred.material['token']}"},
                timeout=timeout,
            )
        except Exception as exc:  # noqa: BLE001
            return ValidationResult(False, self.provider, f"request failed: {exc}")
        if r.status_code == 429:
            # Rate limited — treat as UNVERIFIED and back off (don't retry
            # here; caller-level throttling handles that).
            return ValidationResult(
                False, self.provider, "rate limited (429) — retry with backoff",
            )
        if r.status_code != 200:
            return ValidationResult(False, self.provider, f"http {r.status_code}")
        try:
            body = r.json()
        except (ValueError, json.JSONDecodeError):
            return ValidationResult(False, self.provider, "non-JSON response")
        if "id" not in body or "username" not in body:
            return ValidationResult(False, self.provider, "payload shape unexpected")
        return ValidationResult(
            True, self.provider,
            "discord /users/@me returned canonical fields",
            metadata={
                "bot_id": body.get("id"),
                "username": body.get("username"),
                "discriminator": body.get("discriminator"),
            },
        )


# ---------------------------------------------------------------------------
# GitHub App
# ---------------------------------------------------------------------------


class GitHubAppValidator:
    provider = "github_app"

    _PEM_RE = re.compile(
        r"-----BEGIN RSA PRIVATE KEY-----.*?-----END RSA PRIVATE KEY-----",
        re.DOTALL,
    )

    def matches(self, raw: str) -> bool:
        return bool(self._PEM_RE.search(raw or ""))

    def parse(self, raw: str) -> ProviderCredential | None:
        m = self._PEM_RE.search(raw or "")
        if not m:
            return None
        pem = m.group(0)
        # Look for a paired GitHub App ID: numeric int somewhere in the text
        app_id_match = re.search(r"\bapp[_-]?id[:=\s]+([0-9]{4,})\b", raw or "", re.IGNORECASE)
        app_id = app_id_match.group(1) if app_id_match else ""
        return ProviderCredential(
            provider=self.provider,
            identifier=f"app:{app_id or '?'}",
            material={"private_key_pem": pem, "app_id": app_id},
        )

    def probe(
        self,
        cred: ProviderCredential,
        *,
        client: "httpx.Client | None" = None,
        timeout: float = 10.0,
    ) -> ValidationResult:
        if not cred.material.get("app_id"):
            return ValidationResult(
                False, self.provider, "no paired app_id found in source text",
            )
        try:
            import jwt  # noqa: PLC0415
        except ImportError:
            return ValidationResult(False, self.provider, "PyJWT not installed")
        now = int(time.time())
        payload = {
            "iat": now,
            "exp": now + 540,  # 9 min per GitHub docs
            "iss": cred.material["app_id"],
        }
        try:
            token = jwt.encode(payload, cred.material["private_key_pem"], algorithm="RS256")
        except Exception as exc:  # noqa: BLE001
            return ValidationResult(False, self.provider, f"jwt sign failed: {exc}")
        _sleep_pace()
        c = _http_client(client)
        try:
            r = c.get(
                "https://api.github.com/app",
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/vnd.github+json",
                },
                timeout=timeout,
            )
        except Exception as exc:  # noqa: BLE001
            return ValidationResult(False, self.provider, f"request failed: {exc}")
        if r.status_code != 200:
            return ValidationResult(False, self.provider, f"http {r.status_code}")
        try:
            body = r.json()
        except (ValueError, json.JSONDecodeError):
            return ValidationResult(False, self.provider, "non-JSON response")
        if "id" not in body or "slug" not in body:
            return ValidationResult(False, self.provider, "payload shape unexpected")
        return ValidationResult(
            True, self.provider,
            "github /app returned canonical app record",
            metadata={
                "app_slug": body.get("slug"),
                "app_id_confirmed": str(body.get("id")),
                "owner_login": (body.get("owner") or {}).get("login"),
            },
        )


# ---------------------------------------------------------------------------
# Azure Storage shared-key connection strings
# ---------------------------------------------------------------------------


class AzureStorageConnectionStringValidator:
    provider = "azure_storage_conn_str"

    _KEY_RE = re.compile(
        r"AccountName=([^;]+);AccountKey=([A-Za-z0-9+/=]+)(?:;|$)",
        re.IGNORECASE,
    )

    def matches(self, raw: str) -> bool:
        return bool(self._KEY_RE.search(raw or ""))

    def parse(self, raw: str) -> ProviderCredential | None:
        m = self._KEY_RE.search(raw or "")
        if not m:
            return None
        account = m.group(1).strip()
        key = m.group(2).strip()
        return ProviderCredential(
            provider=self.provider,
            identifier=f"acct:{account}",
            material={"account_name": account, "account_key": key},
        )

    def probe(
        self,
        cred: ProviderCredential,
        *,
        client: "httpx.Client | None" = None,
        timeout: float = 10.0,
    ) -> ValidationResult:
        _sleep_pace()
        c = _http_client(client)
        account = cred.material["account_name"]
        key = cred.material["account_key"]
        # Read-only: list-containers with x-ms-version, signed with the
        # shared key. This confirms the key without any write.
        now = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
        url_path = f"/?comp=list&restype=container"
        canonical_headers = f"x-ms-date:{now}\nx-ms-version:2020-04-08"
        canonical_resource = f"/{account}/\ncomp:list\nrestype:container"
        string_to_sign = (
            f"GET\n\n\n\n\n\n\n\n\n\n\n\n{canonical_headers}\n{canonical_resource}"
        )
        try:
            decoded_key = base64.b64decode(key)
        except (ValueError, Exception):  # noqa: BLE001
            return ValidationResult(False, self.provider, "account_key not base64")
        signature = base64.b64encode(
            hmac.new(decoded_key, string_to_sign.encode("utf-8"), hashlib.sha256).digest()
        ).decode()
        url = f"https://{account}.blob.core.windows.net{url_path}"
        headers = {
            "x-ms-date": now,
            "x-ms-version": "2020-04-08",
            "Authorization": f"SharedKey {account}:{signature}",
        }
        try:
            r = c.get(url, headers=headers, timeout=timeout)
        except Exception as exc:  # noqa: BLE001
            return ValidationResult(False, self.provider, f"request failed: {exc}")
        if r.status_code not in (200, 206):
            return ValidationResult(False, self.provider, f"http {r.status_code}")
        # Payload should be XML with <EnumerationResults ...> root.
        if "<EnumerationResults" not in r.text[:200]:
            return ValidationResult(False, self.provider, "payload shape unexpected")
        return ValidationResult(
            True, self.provider,
            "azure list-containers returned canonical XML",
            metadata={"account": account},
        )


# ---------------------------------------------------------------------------
# AWS access key + secret
# ---------------------------------------------------------------------------


class AWSAccessKeyValidator:
    provider = "aws_access_key"

    _KEY_RE = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")

    def matches(self, raw: str) -> bool:
        return bool(self._KEY_RE.search(raw or ""))

    def parse(self, raw: str) -> ProviderCredential | None:
        km = self._KEY_RE.search(raw or "")
        if not km:
            return None
        access_key = km.group(0)
        # Look for a 40-char base64ish secret nearby.
        remainder = str(raw).replace(access_key, " ")
        sm = re.search(r"\b[A-Za-z0-9+/=]{40}\b", remainder)
        if not sm:
            return None
        return ProviderCredential(
            provider=self.provider,
            identifier=_redact(access_key),
            material={"access_key_id": access_key, "secret_access_key": sm.group(0)},
        )

    def probe(
        self,
        cred: ProviderCredential,
        *,
        client: "httpx.Client | None" = None,
        timeout: float = 10.0,
    ) -> ValidationResult:
        try:
            import boto3  # noqa: PLC0415
            from botocore.exceptions import ClientError  # noqa: PLC0415
        except ImportError:
            return ValidationResult(False, self.provider, "boto3 not installed")
        _sleep_pace()
        try:
            sts = boto3.client(
                "sts",
                aws_access_key_id=cred.material["access_key_id"],
                aws_secret_access_key=cred.material["secret_access_key"],
            )
            identity = sts.get_caller_identity()
        except ClientError as exc:
            return ValidationResult(
                False, self.provider,
                f"sts get_caller_identity failed: {exc.response.get('Error', {}).get('Code', 'unknown')}",
            )
        except Exception as exc:  # noqa: BLE001
            return ValidationResult(False, self.provider, f"boto3 error: {exc}")
        # Strict: identity must have Account + Arn + UserId
        required = {"Account", "Arn", "UserId"}
        if not required.issubset(set(identity.keys())):
            return ValidationResult(False, self.provider, "identity payload malformed")
        return ValidationResult(
            True, self.provider,
            "sts get_caller_identity returned canonical fields",
            metadata={
                "account": identity["Account"],
                "arn": identity["Arn"],
                "user_id": identity["UserId"],
            },
        )


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


VALIDATORS: dict[str, ProviderKeyValidator] = {
    v.provider: v() if isinstance(v, type) else v
    for v in [
        TwilioValidator(),
        SendGridValidator(),
        SlackValidator(),
        StripeValidator(),
        MailchimpValidator(),
        DiscordValidator(),
        GitHubAppValidator(),
        AzureStorageConnectionStringValidator(),
        AWSAccessKeyValidator(),
    ]
}


def try_validate(
    raw: str,
    *,
    client: "httpx.Client | None" = None,
    timeout: float = 10.0,
) -> ValidationResult | None:
    """Try each validator in order until one matches. Returns None if
    the raw text doesn't match any known provider shape.

    IMPORTANT: caller must have already scope-gated the target. This
    function issues real HTTP calls to provider endpoints. Callers
    must not invoke this on values that fell outside engagement scope.
    """
    for validator in VALIDATORS.values():
        if not validator.matches(raw):
            continue
        cred = validator.parse(raw)
        if cred is None:
            continue
        return validator.probe(cred, client=client, timeout=timeout)
    return None


__all__ = [
    "ProviderCredential",
    "ProviderKeyValidator",
    "ValidationResult",
    "VALIDATORS",
    "try_validate",
    "TwilioValidator",
    "SendGridValidator",
    "SlackValidator",
    "StripeValidator",
    "MailchimpValidator",
    "DiscordValidator",
    "GitHubAppValidator",
    "AzureStorageConnectionStringValidator",
    "AWSAccessKeyValidator",
]
