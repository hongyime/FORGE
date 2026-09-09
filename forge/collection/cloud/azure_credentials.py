"""Azure credential collector for authorized post-exploitation evidence.

Enumerates Azure credentials from environment variables, the shared
``~/.azure/*`` state files written by ``az login`` and the Azure SDK MSAL
cache, and the Azure IMDS managed-identity token endpoint. All secret
material is SHA-256 hashed (``sha256:<hex>``) before being returned; raw
secret values never leave this module.

Sources checked:
    1. Environment variables:
       ``AZURE_CLIENT_ID`` + ``AZURE_CLIENT_SECRET`` + ``AZURE_TENANT_ID``
       (Service Principal), and ``AZURE_STORAGE_CONNECTION_STRING``
       (Shared-Key storage account).
    2. ``~/.azure/azureProfile.json`` (subscription + tenant metadata).
    3. ``~/.azure/msal_token_cache.json`` (MSAL refresh/access tokens).
    4. ``~/.azure/service_principal_entries.json`` (some tools cache SPs).
    5. Azure IMDS at
       ``http://169.254.169.254/metadata/identity/oauth2/token``.

Security invariants:
    * Raw credential values are never logged, stored, or returned.
    * Every returned secret is prefixed ``sha256:`` to distinguish from
      other hash types. Non-secret metadata (tenant ID, subscription ID,
      client ID, storage account name) is returned in cleartext because
      those identifiers are non-sensitive on their own.
    * Missing files, malformed JSON, and metadata timeouts degrade to an
      empty result for that source; the overall harvest never raises.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from urllib import error as urlerror
from urllib import request as urlrequest

__all__ = ["AzureCredential", "harvest_azure_credentials"]

_HASH_PREFIX = "sha256:"

_IMDS_TOKEN_URL = (
    "http://169.254.169.254/metadata/identity/oauth2/token"
    "?api-version=2018-02-01&resource=https%3A%2F%2Fmanagement.azure.com%2F"
)
_METADATA_TIMEOUT_SECONDS = 2.0

# Azure Storage Shared-Key connection strings look like:
#   DefaultEndpointsProtocol=https;AccountName=<name>;AccountKey=<base64>;...
_STORAGE_CS_ACCOUNT_RE = re.compile(r"AccountName=([^;]+)", re.IGNORECASE)
_STORAGE_CS_KEY_RE = re.compile(r"AccountKey=([^;]+)", re.IGNORECASE)


@dataclass(frozen=True)
class AzureCredential:
    """A single harvested Azure credential (secrets hashed).

    All hash fields use the ``sha256:<hex>`` format. Optional fields are
    ``None`` when the corresponding secret was not present (never empty
    strings).
    """

    type: str
    source: str
    tenant_id: str | None = None
    subscription_id: str | None = None
    client_id: str | None = None
    account_name: str | None = None
    secret_hash: str | None = None
    access_token_hash: str | None = None
    refresh_token_hash: str | None = None
    extra: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _sha256(value: str | bytes | None) -> str | None:
    if value is None:
        return None
    data = value.encode("utf-8") if isinstance(value, str) else value
    if not data:
        return None
    return _HASH_PREFIX + hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------------- #
# Source 1: environment variables                                             #
# --------------------------------------------------------------------------- #

def _harvest_env() -> list[AzureCredential]:
    creds: list[AzureCredential] = []
    tenant = os.environ.get("AZURE_TENANT_ID")
    client = os.environ.get("AZURE_CLIENT_ID")
    secret = os.environ.get("AZURE_CLIENT_SECRET")
    if client and secret:
        creds.append(
            AzureCredential(
                type="service_principal",
                source="env",
                tenant_id=tenant if tenant else None,
                client_id=client,
                secret_hash=_sha256(secret),
            )
        )
    storage_cs = os.environ.get("AZURE_STORAGE_CONNECTION_STRING")
    if storage_cs:
        acct = _STORAGE_CS_ACCOUNT_RE.search(storage_cs)
        key = _STORAGE_CS_KEY_RE.search(storage_cs)
        if acct and key:
            creds.append(
                AzureCredential(
                    type="storage_shared_key",
                    source="env",
                    account_name=acct.group(1).strip(),
                    secret_hash=_sha256(key.group(1).strip()),
                )
            )
    return creds


# --------------------------------------------------------------------------- #
# Source 2: ~/.azure/azureProfile.json                                        #
# --------------------------------------------------------------------------- #

def _harvest_azure_profile(profile_path: Path) -> list[AzureCredential]:
    if not profile_path.is_file():
        return []
    try:
        # azureProfile.json is sometimes written with a UTF-8 BOM.
        text = profile_path.read_text(encoding="utf-8-sig", errors="ignore")
        data = json.loads(text)
    except (OSError, json.JSONDecodeError):
        return []
    subs = data.get("subscriptions") if isinstance(data, dict) else None
    if not isinstance(subs, list):
        return []
    creds: list[AzureCredential] = []
    for entry in subs:
        if not isinstance(entry, dict):
            continue
        subscription_id = str(entry.get("id") or "").strip() or None
        tenant_id = str(entry.get("tenantId") or "").strip() or None
        if not subscription_id and not tenant_id:
            continue
        user = entry.get("user") if isinstance(entry.get("user"), dict) else {}
        creds.append(
            AzureCredential(
                type="subscription_context",
                source="azureProfile.json",
                tenant_id=tenant_id,
                subscription_id=subscription_id,
                extra={
                    key: str(entry[key])
                    for key in ("name", "state", "environmentName")
                    if key in entry and entry[key] is not None
                }
                | (
                    {"user_type": str(user.get("type") or "")}
                    if user.get("type")
                    else {}
                ),
            )
        )
    return creds


# --------------------------------------------------------------------------- #
# Source 3: ~/.azure/msal_token_cache.json                                    #
# --------------------------------------------------------------------------- #

def _harvest_msal_cache(cache_path: Path) -> list[AzureCredential]:
    if not cache_path.is_file():
        return []
    try:
        raw = cache_path.read_bytes()
    except OSError:
        return []
    if not raw:
        return []
    try:
        data = json.loads(raw.decode("utf-8", errors="ignore"))
    except json.JSONDecodeError:
        # Encrypted or DPAPI-wrapped cache: hash the whole blob so the caller
        # can still record an evidence pointer without exposing key material.
        return [
            AzureCredential(
                type="msal_encrypted_cache",
                source="msal_token_cache.json",
                access_token_hash=_sha256(raw),
                extra={"cache_size_bytes": str(len(raw))},
            )
        ]
    creds: list[AzureCredential] = []
    access_tokens = data.get("AccessToken") if isinstance(data, dict) else None
    if isinstance(access_tokens, dict):
        for entry in access_tokens.values():
            if not isinstance(entry, dict):
                continue
            secret = entry.get("secret") or entry.get("access_token")
            client_id = str(entry.get("client_id") or "").strip() or None
            tenant_id = str(entry.get("realm") or entry.get("tenant_id") or "").strip() or None
            creds.append(
                AzureCredential(
                    type="msal_access_token",
                    source="msal_token_cache.json",
                    tenant_id=tenant_id,
                    client_id=client_id,
                    access_token_hash=_sha256(secret) if secret else None,
                )
            )
    refresh_tokens = data.get("RefreshToken") if isinstance(data, dict) else None
    if isinstance(refresh_tokens, dict):
        for entry in refresh_tokens.values():
            if not isinstance(entry, dict):
                continue
            secret = entry.get("secret") or entry.get("refresh_token")
            client_id = str(entry.get("client_id") or "").strip() or None
            creds.append(
                AzureCredential(
                    type="msal_refresh_token",
                    source="msal_token_cache.json",
                    client_id=client_id,
                    refresh_token_hash=_sha256(secret) if secret else None,
                )
            )
    return creds


# --------------------------------------------------------------------------- #
# Source 4: ~/.azure/service_principal_entries.json                           #
# --------------------------------------------------------------------------- #

def _harvest_service_principals(sp_path: Path) -> list[AzureCredential]:
    if not sp_path.is_file():
        return []
    try:
        data = json.loads(sp_path.read_text(encoding="utf-8", errors="ignore"))
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(data, list):
        return []
    creds: list[AzureCredential] = []
    for entry in data:
        if not isinstance(entry, dict):
            continue
        client_id = str(entry.get("client") or entry.get("clientId") or "").strip() or None
        tenant_id = str(entry.get("tenant") or entry.get("tenantId") or "").strip() or None
        secret = entry.get("clientSecret") or entry.get("secret")
        certificate = entry.get("certificate") or entry.get("certificateThumbprint")
        if not (client_id or tenant_id):
            continue
        creds.append(
            AzureCredential(
                type="service_principal",
                source="service_principal_entries.json",
                tenant_id=tenant_id,
                client_id=client_id,
                secret_hash=_sha256(secret) if secret else None,
                extra=(
                    {"certificate_thumbprint_hash": _sha256(certificate) or ""}
                    if certificate
                    else {}
                ),
            )
        )
    return creds


# --------------------------------------------------------------------------- #
# Source 5: Azure IMDS managed identity                                       #
# --------------------------------------------------------------------------- #

def _harvest_imds(timeout: float = _METADATA_TIMEOUT_SECONDS) -> list[AzureCredential]:
    request = urlrequest.Request(
        _IMDS_TOKEN_URL,
        headers={"Metadata": "true"},
        method="GET",
    )
    try:
        with urlrequest.urlopen(request, timeout=timeout) as response:  # noqa: S310
            body = response.read()
    except (urlerror.URLError, TimeoutError, ConnectionError, OSError):
        return []
    if not body:
        return []
    try:
        data = json.loads(body.decode("utf-8", errors="ignore"))
    except json.JSONDecodeError:
        return []
    if not isinstance(data, dict):
        return []
    access_token = data.get("access_token")
    if not isinstance(access_token, str) or not access_token:
        return []
    return [
        AzureCredential(
            type="managed_identity_token",
            source="imds",
            client_id=str(data.get("client_id") or "").strip() or None,
            tenant_id=None,
            access_token_hash=_sha256(access_token),
            extra={
                key: str(data[key])
                for key in ("resource", "expires_in", "token_type")
                if key in data and data[key] is not None
            },
        )
    ]


# --------------------------------------------------------------------------- #
# Public harvest entry point                                                  #
# --------------------------------------------------------------------------- #

def harvest_azure_credentials(
    *,
    azure_dir: Path | None = None,
    include_imds: bool = True,
    imds_timeout: float = _METADATA_TIMEOUT_SECONDS,
) -> list[AzureCredential]:
    """Enumerate Azure credentials from every configured source.

    Args:
        azure_dir: Root of the ``.azure`` state directory. Defaults to
            ``~/.azure``. Callers running from an authorized evidence
            snapshot should point this at the extracted directory.
        include_imds: When ``True`` (default), attempt the Azure IMDS
            managed-identity probe. Disable for offline artifact
            processing where the loopback IMDS address is not routable
            or you do not want to touch the local network.
        imds_timeout: Seconds to wait for IMDS before giving up. Kept
            short (2 s default) so a missing IMDS never stalls the
            harvest.

    Returns:
        Deterministic, source-ordered list of ``AzureCredential`` rows.
        Missing sources contribute nothing; the harvest never raises.
    """

    if azure_dir is None:
        azure_dir = Path.home() / ".azure"
    creds: list[AzureCredential] = []
    creds.extend(_harvest_env())
    creds.extend(_harvest_azure_profile(azure_dir / "azureProfile.json"))
    creds.extend(_harvest_msal_cache(azure_dir / "msal_token_cache.json"))
    creds.extend(_harvest_service_principals(azure_dir / "service_principal_entries.json"))
    if include_imds:
        creds.extend(_harvest_imds(timeout=imds_timeout))
    return creds
