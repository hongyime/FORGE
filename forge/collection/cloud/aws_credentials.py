"""AWS credential harvesting.

Enumerates AWS credentials from environment variables, the shared
``~/.aws/credentials`` and ``~/.aws/config`` INI files, the EC2 instance
metadata service (IMDSv2/IMDSv1), and the ECS task metadata credential
endpoint. All secret material is SHA-256 hashed (``sha256:<hex>``) before
being returned; raw secret values never leave this module.

Sources checked:
    1. Environment variables: ``AWS_ACCESS_KEY_ID``, ``AWS_SECRET_ACCESS_KEY``,
       ``AWS_SESSION_TOKEN``.
    2. ``~/.aws/credentials`` (INI: per-profile access/secret/session).
    3. ``~/.aws/config`` (INI: profile role assumption metadata).
    4. EC2 IMDS at ``http://169.254.169.254/latest/meta-data/iam/security-credentials/``.
    5. ECS task metadata via ``AWS_CONTAINER_CREDENTIALS_RELATIVE_URI``
       (base ``http://169.254.170.2``) or the absolute
       ``AWS_CONTAINER_CREDENTIALS_FULL_URI``.

Security invariants:
    * Raw credential values are never logged, stored, or returned.
    * Every returned secret is prefixed ``sha256:`` to distinguish from
      other hash types.
    * Missing files, malformed INI lines, and metadata timeouts degrade
      to an empty result for that source; the overall harvest never
      raises.
    * Session token hash is omitted (``None``) when the token is empty.
"""

from __future__ import annotations

import configparser
import hashlib
import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from urllib import error as urlerror
from urllib import request as urlrequest

__all__ = ["AWSCredential", "harvest_aws_credentials"]

_HASH_PREFIX = "sha256:"

_IMDS_BASE = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
_IMDS_TOKEN_URL = "http://169.254.169.254/latest/api/token"
_IMDS_TOKEN_TTL_SECONDS = "21600"
_ECS_CREDENTIALS_BASE = "http://169.254.170.2"
_METADATA_TIMEOUT_SECONDS = 2.0


@dataclass(frozen=True)
class AWSCredential:
    """A single harvested AWS credential (secrets hashed).

    All hash fields use the ``sha256:<hex>`` format. ``session_token_hash``
    is ``None`` when no session token was present (never an empty string).
    """

    type: str
    source: str
    account_id: str | None = None
    access_key_hash: str | None = None
    secret_hash: str | None = None
    session_token_hash: str | None = None
    extra: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _sha256(value: str | bytes | None) -> str | None:
    """Return ``sha256:<hex>`` for a value, or ``None`` if empty/missing."""
    if value is None:
        return None
    data = value.encode("utf-8") if isinstance(value, str) else value
    if not data:
        return None
    return _HASH_PREFIX + hashlib.sha256(data).hexdigest()


def _account_id_from_access_key(access_key: str | None) -> str | None:
    """Recover the 12-digit AWS account ID from an access-key ID when possible.

    AWS access-key IDs (AKIA*, ASIA*, AIDA*, AROA*, ...) encode the owning
    account in a base32 payload. This offline heuristic returns the account
    ID for well-formed 20-char keys and ``None`` for anything else. It never
    makes a network call and never returns raw key material.
    """
    if not isinstance(access_key, str) or len(access_key) < 20:
        return None
    try:
        # AWS trick: base32-decode the 4-char-aligned tail of the key and
        # extract the 6-byte account payload starting at byte 1.
        import base64

        trimmed = access_key[4:]
        padding = "=" * (-len(trimmed) % 8)
        decoded = base64.b32decode(trimmed + padding, casefold=True)
    except (ValueError, TypeError):
        return None
    if len(decoded) < 7:
        return None
    # Big-endian 6-byte account payload, shifted right by 1 nibble.
    payload = int.from_bytes(decoded[0:6], "big")
    account_int = (payload & 0x7FFFFFFFFF80) >> 7
    account = str(account_int).zfill(12)
    if len(account) != 12 or not account.isdigit():
        return None
    return account


# --------------------------------------------------------------------------- #
# Source 1: environment variables                                             #
# --------------------------------------------------------------------------- #

def _harvest_env() -> list[AWSCredential]:
    access = os.environ.get("AWS_ACCESS_KEY_ID")
    secret = os.environ.get("AWS_SECRET_ACCESS_KEY")
    session = os.environ.get("AWS_SESSION_TOKEN")

    if not access and not secret and not session:
        return []

    return [
        AWSCredential(
            type="env",
            source="env:AWS_ACCESS_KEY_ID",
            account_id=_account_id_from_access_key(access),
            access_key_hash=_sha256(access),
            secret_hash=_sha256(secret),
            session_token_hash=_sha256(session),
        )
    ]


# --------------------------------------------------------------------------- #
# Sources 2 & 3: ~/.aws/credentials and ~/.aws/config                         #
# --------------------------------------------------------------------------- #

def _read_ini(path: Path) -> configparser.RawConfigParser | None:
    """Read a shared-credentials-style INI file, tolerating malformed lines.

    Returns ``None`` if the file is missing or entirely unreadable. Sections
    that contain malformed lines are best-effort: ``configparser`` in default
    mode raises on the first bad line, so on any parse error we fall back to
    a line-by-line reader that skips invalid content instead.
    """
    if not path.is_file():
        return None
    parser = configparser.RawConfigParser()
    try:
        parser.read(path, encoding="utf-8")
        return parser
    except (configparser.Error, UnicodeDecodeError, OSError):
        pass

    # Fallback: parse line-by-line, skipping malformed content.
    try:
        raw = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None
    fallback = configparser.RawConfigParser()
    current: str | None = None
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", ";")):
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped[1:-1].strip()
            if not section:
                current = None
                continue
            if not fallback.has_section(section):
                try:
                    fallback.add_section(section)
                except (ValueError, configparser.Error):
                    current = None
                    continue
            current = section
            continue
        if current is None or "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        key = key.strip()
        value = value.strip()
        if not key:
            continue
        try:
            fallback.set(current, key, value)
        except (ValueError, configparser.Error):
            continue
    return fallback


def _harvest_credentials_file(path: Path) -> list[AWSCredential]:
    parser = _read_ini(path)
    if parser is None:
        return []
    creds: list[AWSCredential] = []
    for section in parser.sections():
        access = parser.get(section, "aws_access_key_id", fallback=None)
        secret = parser.get(section, "aws_secret_access_key", fallback=None)
        session = parser.get(section, "aws_session_token", fallback=None)
        if not access and not secret and not session:
            continue
        creds.append(
            AWSCredential(
                type="shared_credentials",
                source=f"file:{path}:{section}",
                account_id=_account_id_from_access_key(access),
                access_key_hash=_sha256(access),
                secret_hash=_sha256(secret),
                session_token_hash=_sha256(session),
                extra={"profile": section},
            )
        )
    return creds


def _harvest_config_file(path: Path) -> list[AWSCredential]:
    """Enumerate assume-role profiles from ``~/.aws/config``.

    Only profiles that declare a ``role_arn`` (or ``credential_source`` /
    ``source_profile``) are surfaced; plain ``region``-only profiles are
    skipped. No secret material lives in this file, so hash fields remain
    ``None`` and the ARN plus source-profile metadata is preserved in
    ``extra``.
    """
    parser = _read_ini(path)
    if parser is None:
        return []
    creds: list[AWSCredential] = []
    for section in parser.sections():
        role_arn = parser.get(section, "role_arn", fallback=None)
        source_profile = parser.get(section, "source_profile", fallback=None)
        credential_source = parser.get(section, "credential_source", fallback=None)
        mfa_serial = parser.get(section, "mfa_serial", fallback=None)
        role_session_name = parser.get(section, "role_session_name", fallback=None)
        if not role_arn and not credential_source and not source_profile:
            continue

        # section is typically "profile <name>" in ~/.aws/config
        profile_name = section
        if section.startswith("profile "):
            profile_name = section[len("profile "):].strip() or section

        account_id: str | None = None
        if isinstance(role_arn, str) and role_arn.startswith("arn:aws:iam::"):
            parts = role_arn.split(":")
            if len(parts) >= 5 and parts[4].isdigit() and len(parts[4]) == 12:
                account_id = parts[4]

        extra: dict[str, str] = {"profile": profile_name}
        if role_arn:
            extra["role_arn"] = role_arn
        if source_profile:
            extra["source_profile"] = source_profile
        if credential_source:
            extra["credential_source"] = credential_source
        if mfa_serial:
            extra["mfa_serial"] = mfa_serial
        if role_session_name:
            extra["role_session_name"] = role_session_name

        creds.append(
            AWSCredential(
                type="assume_role_profile",
                source=f"file:{path}:{section}",
                account_id=account_id,
                extra=extra,
            )
        )
    return creds


# --------------------------------------------------------------------------- #
# Source 4: EC2 instance metadata (IMDSv2 preferred, IMDSv1 fallback)         #
# --------------------------------------------------------------------------- #

def _imds_get(
    url: str,
    *,
    timeout: float,
    token: str | None,
) -> str | None:
    headers: dict[str, str] = {}
    if token:
        headers["X-aws-ec2-metadata-token"] = token
    req = urlrequest.Request(url, headers=headers)  # noqa: S310
    try:
        with urlrequest.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            return resp.read().decode("utf-8", errors="ignore")
    except (urlerror.URLError, TimeoutError, OSError, ValueError):
        return None


def _imds_token(*, base_token_url: str, timeout: float) -> str | None:
    req = urlrequest.Request(  # noqa: S310
        base_token_url,
        method="PUT",
        headers={"X-aws-ec2-metadata-token-ttl-seconds": _IMDS_TOKEN_TTL_SECONDS},
    )
    try:
        with urlrequest.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            body = resp.read().decode("utf-8", errors="ignore").strip()
            return body or None
    except (urlerror.URLError, TimeoutError, OSError, ValueError):
        return None


def _harvest_ec2_metadata(
    *,
    base_url: str = _IMDS_BASE,
    token_url: str = _IMDS_TOKEN_URL,
    timeout: float = _METADATA_TIMEOUT_SECONDS,
) -> list[AWSCredential]:
    """Query the EC2 IMDS. Returns ``[]`` on any failure/timeout."""
    token = _imds_token(base_token_url=token_url, timeout=timeout)

    role_listing = _imds_get(base_url, timeout=timeout, token=token)
    if role_listing is None:
        return []

    roles = [line.strip() for line in role_listing.splitlines() if line.strip()]
    if not roles:
        return []

    creds: list[AWSCredential] = []
    for role in roles:
        # Guard against traversal / injection into the metadata URL.
        if "/" in role or ".." in role or not role:
            continue
        role_url = base_url.rstrip("/") + "/" + role
        body = _imds_get(role_url, timeout=timeout, token=token)
        if not body:
            continue
        try:
            payload = json.loads(body)
        except ValueError:
            continue
        if not isinstance(payload, dict):
            continue
        access = payload.get("AccessKeyId")
        secret = payload.get("SecretAccessKey")
        session = payload.get("Token")
        if not access and not secret and not session:
            continue
        extra: dict[str, str] = {"role": role}
        expiration = payload.get("Expiration")
        if isinstance(expiration, str):
            extra["expiration"] = expiration
        creds.append(
            AWSCredential(
                type="ec2_instance_metadata",
                source=f"imds:{role}",
                account_id=_account_id_from_access_key(
                    access if isinstance(access, str) else None
                ),
                access_key_hash=_sha256(access if isinstance(access, str) else None),
                secret_hash=_sha256(secret if isinstance(secret, str) else None),
                session_token_hash=_sha256(
                    session if isinstance(session, str) else None
                ),
                extra=extra,
            )
        )
    return creds


# --------------------------------------------------------------------------- #
# Source 5: ECS task metadata credential endpoint                             #
# --------------------------------------------------------------------------- #

def _harvest_ecs_metadata(
    *,
    base_url: str = _ECS_CREDENTIALS_BASE,
    timeout: float = _METADATA_TIMEOUT_SECONDS,
) -> list[AWSCredential]:
    """Query the ECS task metadata credential endpoint if configured.

    Honors ``AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`` (relative to
    ``base_url``) and ``AWS_CONTAINER_CREDENTIALS_FULL_URI`` (absolute).
    """
    relative = os.environ.get("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")
    absolute = os.environ.get("AWS_CONTAINER_CREDENTIALS_FULL_URI")
    if not relative and not absolute:
        return []

    if absolute:
        url = absolute
        source = f"ecs:{absolute}"
    else:
        # relative is guaranteed non-empty here.
        assert relative is not None
        if not relative.startswith("/"):
            relative = "/" + relative
        url = base_url.rstrip("/") + relative
        source = f"ecs:{relative}"

    headers: dict[str, str] = {}
    auth = os.environ.get("AWS_CONTAINER_AUTHORIZATION_TOKEN")
    if auth:
        headers["Authorization"] = auth

    req = urlrequest.Request(url, headers=headers)  # noqa: S310
    try:
        with urlrequest.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            body = resp.read().decode("utf-8", errors="ignore")
    except (urlerror.URLError, TimeoutError, OSError, ValueError):
        return []

    try:
        payload = json.loads(body)
    except ValueError:
        return []
    if not isinstance(payload, dict):
        return []

    access = payload.get("AccessKeyId")
    secret = payload.get("SecretAccessKey")
    session = payload.get("Token")
    if not access and not secret and not session:
        return []

    extra: dict[str, str] = {}
    role_arn = payload.get("RoleArn")
    if isinstance(role_arn, str):
        extra["role_arn"] = role_arn
    expiration = payload.get("Expiration")
    if isinstance(expiration, str):
        extra["expiration"] = expiration

    account_id = _account_id_from_access_key(
        access if isinstance(access, str) else None
    )
    if account_id is None and isinstance(role_arn, str) and role_arn.startswith(
        "arn:aws:iam::"
    ):
        parts = role_arn.split(":")
        if len(parts) >= 5 and parts[4].isdigit() and len(parts[4]) == 12:
            account_id = parts[4]

    return [
        AWSCredential(
            type="ecs_container_credentials",
            source=source,
            account_id=account_id,
            access_key_hash=_sha256(access if isinstance(access, str) else None),
            secret_hash=_sha256(secret if isinstance(secret, str) else None),
            session_token_hash=_sha256(session if isinstance(session, str) else None),
            extra=extra,
        )
    ]


# --------------------------------------------------------------------------- #
# Public entry point                                                          #
# --------------------------------------------------------------------------- #

def harvest_aws_credentials(
    *,
    home: Path | None = None,
    include_ec2_metadata: bool = False,
    include_ecs_metadata: bool = False,
    ec2_base_url: str = _IMDS_BASE,
    ec2_token_url: str = _IMDS_TOKEN_URL,
    ecs_base_url: str = _ECS_CREDENTIALS_BASE,
    metadata_timeout: float = _METADATA_TIMEOUT_SECONDS,
) -> list[AWSCredential]:
    """Harvest AWS credentials from all known local + metadata sources.

    Args:
        home: Override home directory (for testing). Defaults to
            :func:`Path.home`.
        include_ec2_metadata: Whether to query the EC2 instance metadata
            service. Disabled by default — callers must explicitly opt in
            to avoid unintended metadata service probes.
        include_ecs_metadata: Whether to consult the ECS credential
            endpoint when the ECS env vars are present.
        ec2_base_url / ec2_token_url / ecs_base_url: Override URLs used
            by tests to mock the metadata services.
        metadata_timeout: Seconds before giving up on either metadata
            service. Default 2 s per the task spec.
    """
    home_dir = home if home is not None else Path.home()
    aws_dir = home_dir / ".aws"

    creds: list[AWSCredential] = []
    # Each source is isolated: exceptions never propagate; a failing
    # source simply contributes nothing to the result.
    try:
        creds.extend(_harvest_env())
    except Exception:  # noqa: BLE001 - fail-open per spec
        pass
    try:
        creds.extend(_harvest_credentials_file(aws_dir / "credentials"))
    except Exception:  # noqa: BLE001
        pass
    try:
        creds.extend(_harvest_config_file(aws_dir / "config"))
    except Exception:  # noqa: BLE001
        pass
    if include_ec2_metadata:
        try:
            creds.extend(
                _harvest_ec2_metadata(
                    base_url=ec2_base_url,
                    token_url=ec2_token_url,
                    timeout=metadata_timeout,
                )
            )
        except Exception:  # noqa: BLE001
            pass
    if include_ecs_metadata:
        try:
            creds.extend(
                _harvest_ecs_metadata(
                    base_url=ecs_base_url,
                    timeout=metadata_timeout,
                )
            )
        except Exception:  # noqa: BLE001
            pass
    return creds
