from __future__ import annotations

import json
from urllib.parse import urlparse


def nostr_relay_hosts(text: str) -> list[str]:
    """Extract passive relay hosts from Nostr NIP-05 metadata."""

    try:
        payload = json.loads(str(text or ""))
    except Exception:  # noqa: BLE001
        return []

    hosts: list[str] = []
    seen: set[str] = set()
    for value in _relay_values(payload):
        host = _relay_host(value)
        if not host or host in seen:
            continue
        seen.add(host)
        hosts.append(host)
    return hosts


def _relay_values(value: object, *, under_relay_key: bool = False) -> list[str]:
    if isinstance(value, str):
        return [value] if under_relay_key else []
    if isinstance(value, list):
        values: list[str] = []
        for item in value:
            values.extend(_relay_values(item, under_relay_key=under_relay_key))
        return values
    if isinstance(value, dict):
        values = []
        for key, item in value.items():
            relay_key = under_relay_key or "relay" in str(key or "").lower()
            values.extend(_relay_values(item, under_relay_key=relay_key))
        return values
    return []


def _relay_host(value: object) -> str:
    parsed = urlparse(str(value or "").strip())
    if parsed.scheme.lower() not in {"ws", "wss"} or not parsed.hostname:
        return ""
    if parsed.username or parsed.password:
        return ""
    return parsed.hostname.lower().rstrip(".")
