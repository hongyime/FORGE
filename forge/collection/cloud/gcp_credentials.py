"""GCP credential harvesting.

Enumerates GCP credentials from environment variables, gcloud CLI state,
gcloud SQLite credential store, and the GCE metadata service. All secrets
are SHA-256 hashed before being returned; raw secret material never leaves
this module.

Sources checked:
    1. Environment variables: GOOGLE_APPLICATION_CREDENTIALS (path to a
       service account JSON), GCP_PROJECT, GCP_SERVICE_ACCOUNT.
    2. ~/.config/gcloud/credentials.db  (SQLite access token store).
    3. ~/.config/gcloud/configurations/  (INI-style config files).
    4. GCE metadata service (http://metadata.google.internal/...).
"""

from __future__ import annotations

import configparser
import hashlib
import json
import os
import sqlite3
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from urllib import error as urlerror
from urllib import request as urlrequest

__all__ = ["GCPCredential", "harvest_gcp_credentials"]

_METADATA_URL = (
    "http://metadata.google.internal/computeMetadata/v1/"
    "instance/service-accounts/default/token"
)
_METADATA_HEADERS = {"Metadata-Flavor": "Google"}
_METADATA_TIMEOUT_SECONDS = 2.0


@dataclass(frozen=True)
class GCPCredential:
    """A single harvested GCP credential (secrets hashed)."""

    type: str
    source: str
    project_id: str
    client_email: str | None = None
    private_key_id_hash: str | None = None
    access_token_hash: str | None = None
    extra: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _sha256(value: str | bytes | None) -> str | None:
    if value is None:
        return None
    data = value.encode("utf-8") if isinstance(value, str) else value
    if not data:
        return None
    return hashlib.sha256(data).hexdigest()


def _parse_service_account_json(
    path: Path, source: str
) -> GCPCredential | None:
    """Parse a service account JSON file into a GCPCredential.

    Returns None if the file is missing, malformed, or lacks project_id.
    Raw private_key material is discarded; only its id is hashed.
    """
    try:
        raw = path.read_text(encoding="utf-8")
        payload = json.loads(raw)
    except (OSError, ValueError, UnicodeDecodeError):
        return None
    if not isinstance(payload, dict):
        return None

    project_id = payload.get("project_id")
    if not project_id or not isinstance(project_id, str):
        return None

    cred_type = payload.get("type") or "service_account"
    client_email = payload.get("client_email")
    if client_email is not None and not isinstance(client_email, str):
        client_email = None
    private_key_id = payload.get("private_key_id")

    return GCPCredential(
        type=str(cred_type),
        source=source,
        project_id=project_id,
        client_email=client_email,
        private_key_id_hash=_sha256(
            private_key_id if isinstance(private_key_id, str) else None
        ),
        access_token_hash=None,
        extra={"path": str(path)},
    )


def _harvest_env() -> list[GCPCredential]:
    creds: list[GCPCredential] = []

    sa_path = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
    if sa_path:
        parsed = _parse_service_account_json(
            Path(sa_path), source="env:GOOGLE_APPLICATION_CREDENTIALS"
        )
        if parsed is not None:
            creds.append(parsed)

    project = os.environ.get("GCP_PROJECT")
    service_account = os.environ.get("GCP_SERVICE_ACCOUNT")
    if project:
        creds.append(
            GCPCredential(
                type="env_project",
                source="env:GCP_PROJECT",
                project_id=project,
                client_email=service_account if service_account else None,
            )
        )

    return creds


def _harvest_credentials_db(db_path: Path) -> list[GCPCredential]:
    """Parse access_token rows from gcloud's credentials.db SQLite store."""
    if not db_path.is_file():
        return []
    creds: list[GCPCredential] = []
    try:
        conn = sqlite3.connect(
            f"file:{db_path}?mode=ro", uri=True, timeout=1.0
        )
    except sqlite3.Error:
        return []
    try:
        conn.row_factory = sqlite3.Row
        try:
            cur = conn.execute("SELECT account_id, value FROM credentials")
        except sqlite3.Error:
            return []
        for row in cur:
            account_id = row["account_id"] if "account_id" in row.keys() else None
            value = row["value"] if "value" in row.keys() else None
            token_hash: str | None = None
            project_id: str | None = None
            client_email: str | None = (
                account_id if isinstance(account_id, str) else None
            )
            if isinstance(value, (str, bytes)):
                text = (
                    value.decode("utf-8", errors="ignore")
                    if isinstance(value, bytes)
                    else value
                )
                try:
                    parsed = json.loads(text)
                except ValueError:
                    parsed = None
                if isinstance(parsed, dict):
                    token = parsed.get("access_token") or parsed.get("token")
                    if isinstance(token, str):
                        token_hash = _sha256(token)
                    proj = parsed.get("project_id") or parsed.get("quota_project_id")
                    if isinstance(proj, str):
                        project_id = proj
                    email = parsed.get("client_email") or parsed.get("account")
                    if isinstance(email, str):
                        client_email = email
                else:
                    token_hash = _sha256(text)
            if not project_id:
                continue  # skip rows without a project_id (per constraints)
            creds.append(
                GCPCredential(
                    type="gcloud_access_token",
                    source=f"gcloud:{db_path}",
                    project_id=project_id,
                    client_email=client_email,
                    access_token_hash=token_hash,
                )
            )
    finally:
        conn.close()
    return creds


def _harvest_gcloud_configs(configs_dir: Path) -> list[GCPCredential]:
    """Parse gcloud config INI files under configurations/."""
    if not configs_dir.is_dir():
        return []
    creds: list[GCPCredential] = []
    for path in sorted(configs_dir.iterdir()):
        if not path.is_file():
            continue
        parser = configparser.ConfigParser()
        try:
            parser.read(path, encoding="utf-8")
        except (OSError, configparser.Error, UnicodeDecodeError):
            continue
        project = None
        account = None
        if parser.has_section("core"):
            project = parser.get("core", "project", fallback=None)
            account = parser.get("core", "account", fallback=None)
        if not project:
            continue
        creds.append(
            GCPCredential(
                type="gcloud_config",
                source=f"gcloud_config:{path.name}",
                project_id=project,
                client_email=account if account else None,
                extra={"path": str(path)},
            )
        )
    return creds


def _harvest_metadata(
    url: str = _METADATA_URL,
    timeout: float = _METADATA_TIMEOUT_SECONDS,
    project_id: str | None = None,
) -> list[GCPCredential]:
    """Query the GCE metadata service. Returns [] on any failure/timeout."""
    req = urlrequest.Request(url, headers=_METADATA_HEADERS)  # noqa: S310
    try:
        with urlrequest.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            body = resp.read().decode("utf-8", errors="ignore")
    except (urlerror.URLError, TimeoutError, OSError, ValueError):
        return []

    token: str | None = None
    parsed_project: str | None = project_id
    try:
        payload = json.loads(body)
        if isinstance(payload, dict):
            tok = payload.get("access_token")
            if isinstance(tok, str):
                token = tok
            proj = payload.get("project_id")
            if isinstance(proj, str) and not parsed_project:
                parsed_project = proj
    except ValueError:
        token = body.strip() or None

    if not parsed_project:
        # Try the project-id endpoint as a fallback.
        proj_url = (
            "http://metadata.google.internal/computeMetadata/v1/project/project-id"
        )
        proj_req = urlrequest.Request(proj_url, headers=_METADATA_HEADERS)  # noqa: S310
        try:
            with urlrequest.urlopen(proj_req, timeout=timeout) as resp:  # noqa: S310
                parsed_project = resp.read().decode("utf-8", errors="ignore").strip()
        except (urlerror.URLError, TimeoutError, OSError, ValueError):
            parsed_project = None

    if not parsed_project:
        return []

    return [
        GCPCredential(
            type="metadata_service",
            source="metadata:computeMetadata/v1",
            project_id=parsed_project,
            client_email=None,
            access_token_hash=_sha256(token),
        )
    ]


def harvest_gcp_credentials(
    *,
    home: Path | None = None,
    include_metadata: bool = False,
    metadata_url: str = _METADATA_URL,
    metadata_timeout: float = _METADATA_TIMEOUT_SECONDS,
) -> list[GCPCredential]:
    """Harvest GCP credentials from all known local + metadata sources.

    Args:
        home: Override home directory (for testing). Defaults to ``Path.home()``.
        include_metadata: Whether to query the GCE metadata service.
            Disabled by default — callers must explicitly opt in to avoid
            unintended metadata service probes.
        metadata_url: Override URL (for testing).
        metadata_timeout: Seconds before giving up on metadata service.
    """
    creds: list[GCPCredential] = []
    home_dir = home if home is not None else Path.home()
    gcloud_dir = home_dir / ".config" / "gcloud"

    creds.extend(_harvest_env())
    creds.extend(_harvest_credentials_db(gcloud_dir / "credentials.db"))
    creds.extend(_harvest_gcloud_configs(gcloud_dir / "configurations"))
    if include_metadata:
        creds.extend(
            _harvest_metadata(url=metadata_url, timeout=metadata_timeout)
        )
    return creds
