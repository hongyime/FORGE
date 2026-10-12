"""Operator-visible service connection manager.

Stores third-party service connections in a plaintext JSON file under
``<data_dir>/connections.json`` so operators can view and verify the
contents directly. The operator explicitly opted into plaintext storage;
this module intentionally does not encrypt values.

Credential values are only accepted through two patterns, never via a
positional CLI argument:

- ``--token-env ENV_VAR_NAME`` — reads the value from the referenced
  environment variable. The variable name is retained in metadata so
  the operator can rotate it later; the resolved value is stored in
  the connection file.
- ``--token-stdin`` — reads the value from stdin so copy/paste from a
  password manager never lands in shell history.

If a positional ``--token`` flag is ever added at a CLI layer, it must
raise :class:`ConnectionError` before any value is persisted — the
plaintext storage choice is independent of the "do not leak secrets
through shell history" policy.

Supported services (see :data:`SUPPORTED_SERVICES` for the authoritative
list of fields):

- ``github`` — PAT token, optional org/user list.
- ``supabase`` — project ref + anon/service key or Management API PAT.
- ``shodan`` — API key.
- ``virustotal`` — API key.
- ``replit`` — username or profile URL.
- ``urlscan`` — API key (optional free tier works without it).
- ``censys`` — API ID + secret.
- ``dehashed`` — email + API key.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping


CONNECTION_SCHEMA_VERSION = "forge.connections.v1"
CONNECTIONS_FILENAME = "connections.json"


#: Service descriptor. ``required_fields`` must be present after
#: :meth:`ServiceConnectionManager.add_connection` normalizes kwargs.
#: ``optional_fields`` are preserved when set but are not required.
#: ``credential_fields`` lists the keys that must be sourced from
#: ``--token-env`` or ``--token-stdin`` input; they are not accepted as
#: literal values at the CLI layer.
SUPPORTED_SERVICES: dict[str, dict[str, Any]] = {
    "github": {
        "description": "Scan repos for secrets, URLs, IPs, emails. Spider README/code for targets.",
        "required_fields": ("token",),
        "optional_fields": ("orgs", "users"),
        "credential_fields": ("token",),
    },
    "supabase": {
        "description": "Auto-scan Supabase tables for target-like data.",
        "required_fields": ("project_ref",),
        "optional_fields": ("key", "management_pat", "url"),
        "credential_fields": ("key", "management_pat"),
    },
    "shodan": {
        "description": "Auto-search connected domains, discover services.",
        "required_fields": ("key",),
        "optional_fields": (),
        "credential_fields": ("key",),
    },
    "virustotal": {
        "description": "Enrich domains/IPs/URLs with detection data.",
        "required_fields": ("key",),
        "optional_fields": (),
        "credential_fields": ("key",),
    },
    "replit": {
        "description": "Spider public repls for URLs, secrets, endpoints.",
        "required_fields": ("username",),
        "optional_fields": ("url",),
        "credential_fields": (),
    },
    "urlscan": {
        "description": "Deeper URLScan search with authenticated quota.",
        "required_fields": ("key",),
        "optional_fields": (),
        "credential_fields": ("key",),
    },
    "censys": {
        "description": "Search exposed services and certificates.",
        "required_fields": ("api_id", "api_secret"),
        "optional_fields": (),
        "credential_fields": ("api_id", "api_secret"),
    },
    "dehashed": {
        "description": "Breach data lookup.",
        "required_fields": ("email", "key"),
        "optional_fields": (),
        "credential_fields": ("key",),
    },
}


class ConnectionError(ValueError):
    """Raised for invalid service/field combinations or policy violations."""


@dataclass(frozen=True)
class ServiceConnection:
    """One stored service connection.

    ``config`` carries the resolved field values (including credential
    material). ``credential_sources`` records how each credential field
    was provided (``env:ENV_VAR_NAME`` or ``stdin``) so operators can
    audit provenance without re-reading the credential itself.
    """

    service: str
    added_at: str
    config: Mapping[str, Any] = field(default_factory=dict)
    credential_sources: Mapping[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "service": self.service,
            "added_at": self.added_at,
            "config": dict(self.config),
            "credential_sources": dict(self.credential_sources),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ServiceConnection":
        service = str(data.get("service") or "").strip().lower()
        if service not in SUPPORTED_SERVICES:
            raise ConnectionError(
                f"unsupported service {service!r}; "
                f"expected one of {sorted(SUPPORTED_SERVICES)}"
            )
        config = data.get("config") or {}
        if not isinstance(config, Mapping):
            raise ConnectionError("connection 'config' must be an object")
        sources = data.get("credential_sources") or {}
        if not isinstance(sources, Mapping):
            raise ConnectionError("connection 'credential_sources' must be an object")
        added_at = str(data.get("added_at") or _now_iso())
        return cls(
            service=service,
            added_at=added_at,
            config=dict(config),
            credential_sources={str(k): str(v) for k, v in sources.items()},
        )


class ServiceConnectionManager:
    """Plaintext JSON-backed service connection manager.

    The on-disk file is a schema-versioned JSON document:

    .. code-block:: json

        {
          "schema_version": "forge.connections.v1",
          "connections": [
            {
              "service": "github",
              "added_at": "2026-10-11T00:00:00+00:00",
              "config": {
                "token": "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
                "orgs": ["myorg"],
                "users": ["myuser"]
              },
              "credential_sources": {"token": "env:FORGE_GITHUB_TOKEN"}
            }
          ]
        }

    Writes are atomic: the manager writes to a temporary file in the
    same directory and renames it over the destination so a crash never
    leaves a half-written connection file.
    """

    def __init__(
        self,
        data_dir: str | os.PathLike[str],
        *,
        clock: Any = None,
    ) -> None:
        self.data_dir = Path(data_dir)
        self.config_path = self.data_dir / CONNECTIONS_FILENAME
        self._clock = clock or _now_iso

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add_connection(
        self,
        service: str,
        *,
        replace: bool = True,
        credential_sources: Mapping[str, str] | None = None,
        **fields: Any,
    ) -> ServiceConnection:
        """Store or replace a connection for ``service``.

        Args:
            service: Service id (e.g. ``github``). Must be one of
                :data:`SUPPORTED_SERVICES`.
            replace: If True (default) and a connection for the same
                service already exists, it is replaced. If False, a
                second add raises :class:`ConnectionError`.
            credential_sources: Mapping of credential field name to
                provenance label (e.g. ``{"token": "env:FORGE_GH_TOKEN"}``).
                Required for every credential field the caller passes.
            **fields: Field values. Required fields are enforced; unknown
                fields raise :class:`ConnectionError`.

        Returns:
            The stored :class:`ServiceConnection`.
        """
        canonical = self._canonicalize_fields(service, fields)
        descriptor = SUPPORTED_SERVICES[service]
        provided_sources = dict(credential_sources or {})
        for cred_field in descriptor["credential_fields"]:
            if cred_field not in canonical:
                continue
            if cred_field not in provided_sources:
                raise ConnectionError(
                    f"credential field {cred_field!r} for service "
                    f"{service!r} is missing a credential_source; "
                    "credentials must be supplied via the service's "
                    "environment or stdin credential options"
                )
        existing = self._load_connections()
        if any(c.service == service for c in existing):
            if not replace:
                raise ConnectionError(
                    f"connection for {service!r} already exists; "
                    "pass replace=True to overwrite"
                )
            existing = [c for c in existing if c.service != service]
        new_connection = ServiceConnection(
            service=service,
            added_at=self._clock(),
            config=canonical,
            credential_sources=provided_sources,
        )
        existing.append(new_connection)
        self._write_connections(existing)
        return new_connection

    def remove_connection(self, service: str) -> bool:
        """Remove the connection for ``service``.

        Returns ``True`` if a connection was removed, ``False`` if there
        was nothing to remove.
        """
        service = _normalize_service(service)
        existing = self._load_connections()
        kept = [c for c in existing if c.service != service]
        if len(kept) == len(existing):
            return False
        self._write_connections(kept)
        return True

    def get_connection(self, service: str) -> ServiceConnection | None:
        """Return the stored connection or ``None`` when absent."""
        service = _normalize_service(service, allow_unknown=True)
        for connection in self._load_connections():
            if connection.service == service:
                return connection
        return None

    def list_connections(self) -> list[ServiceConnection]:
        """Return every stored connection, sorted by service id."""
        return sorted(self._load_connections(), key=lambda c: c.service)

    def service_descriptor(self, service: str) -> dict[str, Any]:
        """Return the descriptor for ``service`` from :data:`SUPPORTED_SERVICES`."""
        service = _normalize_service(service)
        return dict(SUPPORTED_SERVICES[service])

    def available_services(self) -> list[str]:
        """Return a sorted list of supported service ids."""
        return sorted(SUPPORTED_SERVICES)

    def to_summary(self, *, redact: bool = True) -> dict[str, Any]:
        """Return a dict suitable for ``--json`` output.

        When ``redact`` is True (default) credential field values are
        replaced with ``"<redacted>"`` while names, orgs, usernames,
        emails, and credential provenance labels are retained. The
        on-disk file is **not** redacted — operators explicitly chose
        plaintext storage. Redaction only applies to the summary.
        """
        summary = {
            "schema_version": CONNECTION_SCHEMA_VERSION,
            "connections_path": str(self.config_path),
            "connections": [],
            "available_services": self.available_services(),
        }
        for connection in self.list_connections():
            payload = connection.to_dict()
            if redact:
                payload["config"] = _redact_credentials(
                    connection.service, connection.config
                )
            summary["connections"].append(payload)
        return summary

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _canonicalize_fields(
        self, service: str, fields: Mapping[str, Any]
    ) -> dict[str, Any]:
        service = _normalize_service(service)
        descriptor = SUPPORTED_SERVICES[service]
        required = set(descriptor["required_fields"])
        optional = set(descriptor["optional_fields"])
        allowed = required | optional

        canonical: dict[str, Any] = {}
        unknown: list[str] = []
        for key, value in fields.items():
            if value in (None, "", [], ()):
                continue
            if key not in allowed:
                unknown.append(key)
                continue
            canonical[key] = _normalize_field_value(key, value)
        if unknown:
            raise ConnectionError(
                f"unknown fields for service {service!r}: {sorted(unknown)}"
            )
        missing = sorted(required - canonical.keys())
        if missing:
            raise ConnectionError(
                f"service {service!r} is missing required fields {missing}"
            )
        return canonical

    def _load_connections(self) -> list[ServiceConnection]:
        if not self.config_path.exists():
            return []
        try:
            raw = self.config_path.read_text(encoding="utf-8")
        except OSError as exc:
            raise ConnectionError(
                f"cannot read connections file {self.config_path}: {exc}"
            ) from exc
        if not raw.strip():
            return []
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ConnectionError(
                f"connections file {self.config_path} is not valid JSON: {exc}"
            ) from exc
        if not isinstance(payload, Mapping):
            raise ConnectionError(
                f"connections file {self.config_path} must contain a JSON object"
            )
        items = payload.get("connections", [])
        if not isinstance(items, list):
            raise ConnectionError("'connections' must be a JSON list")
        return [ServiceConnection.from_dict(item) for item in items]

    def _write_connections(
        self, connections: Iterable[ServiceConnection]
    ) -> None:
        payload = {
            "schema_version": CONNECTION_SCHEMA_VERSION,
            "connections": [c.to_dict() for c in connections],
        }
        self.data_dir.mkdir(parents=True, exist_ok=True)
        tmp_path = self.config_path.with_suffix(
            self.config_path.suffix + ".tmp"
        )
        tmp_path.write_text(
            json.dumps(payload, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        os.replace(tmp_path, self.config_path)


# ----------------------------------------------------------------------
# Helpers used by CLI layer
# ----------------------------------------------------------------------


def read_env_credential(env_name: str) -> tuple[str, str]:
    """Read a credential from the environment.

    Returns a ``(value, source)`` tuple where ``source`` is the
    canonical provenance label ``"env:<env_name>"`` recorded in
    :attr:`ServiceConnection.credential_sources`.

    Raises :class:`ConnectionError` when the referenced variable is
    missing or empty — the CLI must then stop before persisting the
    (half-formed) connection.
    """
    env_name = str(env_name or "").strip()
    if not env_name:
        raise ConnectionError("--token-env requires an environment variable name")
    value = os.environ.get(env_name, "").strip()
    if not value:
        raise ConnectionError(
            f"environment variable {env_name!r} is empty or unset; "
            "set it before running `forge connect` or pass --token-stdin"
        )
    return value, f"env:{env_name}"


def read_stdin_credential(stream: Any = None) -> tuple[str, str]:
    """Read a credential from stdin.

    Returns ``(value, source)`` with the canonical provenance label
    ``"stdin"``. Trailing newlines are stripped so paste-friendly input
    does not inject spurious whitespace into the stored token.
    """
    stream = stream if stream is not None else sys.stdin
    data = stream.read() if stream else ""
    value = str(data).strip()
    if not value:
        raise ConnectionError(
            "--token-stdin produced no data; pipe the value or paste then press Ctrl-D"
        )
    return value, "stdin"


# ----------------------------------------------------------------------
# Internal utilities
# ----------------------------------------------------------------------


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_service(service: str, *, allow_unknown: bool = False) -> str:
    normalized = str(service or "").strip().lower()
    if not normalized:
        raise ConnectionError("service id must not be empty")
    if normalized not in SUPPORTED_SERVICES and not allow_unknown:
        raise ConnectionError(
            f"unsupported service {normalized!r}; "
            f"expected one of {sorted(SUPPORTED_SERVICES)}"
        )
    return normalized


def _normalize_field_value(key: str, value: Any) -> Any:
    """Normalize per-field values before persisting.

    List-valued fields (``orgs``, ``users``) are deduped and sorted so
    repeated adds remain idempotent. Scalar string values are stripped
    but otherwise left intact — the operator chose plaintext storage.
    """
    if key in {"orgs", "users"}:
        if isinstance(value, (list, tuple)):
            items = [str(v).strip() for v in value if str(v).strip()]
        elif isinstance(value, str):
            items = [v.strip() for v in value.split(",") if v.strip()]
        else:
            raise ConnectionError(
                f"field {key!r} must be a list of strings or comma-separated string"
            )
        return sorted(dict.fromkeys(items))
    if isinstance(value, (list, tuple)):
        raise ConnectionError(f"field {key!r} must be a scalar string, not a list")
    return str(value).strip()


def _redact_credentials(service: str, config: Mapping[str, Any]) -> dict[str, Any]:
    """Return a copy of ``config`` with credential-field values masked."""
    descriptor = SUPPORTED_SERVICES.get(service, {})
    credential_fields = set(descriptor.get("credential_fields", ()))
    masked: dict[str, Any] = {}
    for key, value in config.items():
        if key in credential_fields and value:
            masked[key] = "<redacted>"
        else:
            masked[key] = value
    return masked


__all__ = [
    "CONNECTION_SCHEMA_VERSION",
    "CONNECTIONS_FILENAME",
    "SUPPORTED_SERVICES",
    "ConnectionError",
    "ServiceConnection",
    "ServiceConnectionManager",
    "read_env_credential",
    "read_stdin_credential",
]
