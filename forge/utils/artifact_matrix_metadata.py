from __future__ import annotations

import ipaddress
import json
import re
from urllib.parse import urlparse

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$"
)


def matrix_server_delegated_hosts(text: str) -> list[str]:
    """Extract passive homeserver delegation hosts from Matrix server metadata."""

    try:
        payload = json.loads(str(text or ""))
    except Exception:  # noqa: BLE001
        return []
    if not isinstance(payload, dict):
        return []

    host = _normalize_matrix_server_host(payload.get("m.server"))
    return [host] if host else []


def _normalize_matrix_server_host(value: object) -> str:
    raw = str(value or "").strip().strip("\"'")
    if not raw or any(char.isspace() for char in raw):
        return ""
    parsed = urlparse(raw if "://" in raw else f"//{raw}")
    try:
        parsed.port
    except ValueError:
        return ""
    host = str(parsed.hostname or "").strip().lower().rstrip(".")
    if not host or host in {"localhost", "localhost.localdomain"}:
        return ""
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    if not _HOSTNAME_RE.fullmatch(host):
        return ""
    return host
