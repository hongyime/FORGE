from __future__ import annotations

import json
import re
from urllib.parse import unquote

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$"
)


def did_web_hosts(text: str) -> list[str]:
    """Extract passive host pivots from DID web identifiers."""

    try:
        payload = json.loads(str(text or ""))
    except Exception:  # noqa: BLE001
        return []

    hosts: list[str] = []
    seen: set[str] = set()
    for value in _json_string_values(payload):
        host = _did_web_host(value)
        if not host or host in seen:
            continue
        seen.add(host)
        hosts.append(host)
    return hosts


def did_web_hosts_from_lines(text: str) -> list[str]:
    """Extract DID web hosts from line-oriented DID metadata."""

    hosts: list[str] = []
    seen: set[str] = set()
    for raw_line in str(text or "").splitlines():
        host = _did_web_host(raw_line)
        if not host or host in seen:
            continue
        seen.add(host)
        hosts.append(host)
    return hosts


def _json_string_values(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        values: list[str] = []
        for item in value:
            values.extend(_json_string_values(item))
        return values
    if isinstance(value, dict):
        values = []
        for item in value.values():
            values.extend(_json_string_values(item))
        return values
    return []


def _did_web_host(value: object) -> str:
    candidate = str(value or "").strip()
    if not candidate.lower().startswith("did:web:"):
        return ""
    body = candidate[8:]
    host = unquote(body.split(":", 1)[0]).strip().lower().rstrip(".")
    if not host or host in {"localhost", "localhost.localdomain"}:
        return ""
    if not _HOSTNAME_RE.fullmatch(host):
        return ""
    return host
