"""Passive Firebase Hosting config extraction helpers."""

from __future__ import annotations

import json
import re
from typing import Any

_FIREBASE_SITE_ID_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{2,61}[a-z0-9])$")
_LOW_SIGNAL_SITE_IDS = {
    "default",
    "demo",
    "example",
    "firebase",
    "localhost",
    "placeholder",
    "project",
    "sample",
    "target",
    "test",
}


def _stable_firebase_site_id(value: object) -> str:
    site_id = str(value or "").strip()
    if site_id != site_id.lower():
        return ""
    if site_id in _LOW_SIGNAL_SITE_IDS:
        return ""
    if not _FIREBASE_SITE_ID_RE.fullmatch(site_id):
        return ""
    if "${" in site_id or "." in site_id or "--" in site_id:
        return ""
    return site_id


def _hosting_blocks(document: Any) -> list[dict[str, Any]]:
    if not isinstance(document, dict):
        return []
    hosting = document.get("hosting")
    if isinstance(hosting, dict):
        return [hosting]
    if isinstance(hosting, list):
        return [item for item in hosting if isinstance(item, dict)]
    return []


def firebase_hosting_site_urls(text: str) -> list[str]:
    """Return `.web.app` pivots from explicit `firebase.json` hosting site IDs."""
    try:
        document = json.loads(str(text or ""))
    except Exception:  # noqa: BLE001
        return []

    urls: list[str] = []
    seen: set[str] = set()
    for block in _hosting_blocks(document):
        site_id = _stable_firebase_site_id(block.get("site"))
        if not site_id or site_id in seen:
            continue
        seen.add(site_id)
        urls.append(f"https://{site_id}.web.app")
    return urls
