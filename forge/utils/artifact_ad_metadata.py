from __future__ import annotations

import json
import re
from typing import Any

_AD_SYSTEM_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$"
)
_PUBLISHER_ACCOUNT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_AUTHORIZED_RELATIONSHIPS = {"direct", "reseller"}
_SELLER_TYPES = {"publisher", "intermediary", "both"}


def ads_txt_publisher_account_assets(
    text: str,
    *,
    app_ads: bool = False,
) -> list[tuple[str, str, str]]:
    """Extract passive ad seller account inventory from ads.txt style files."""

    source = (
        "artifact_app_ads_txt_publisher_account"
        if app_ads
        else "artifact_ads_txt_publisher_account"
    )
    assets: list[tuple[str, str, str]] = []
    seen: set[str] = set()
    for line in str(text or "").splitlines():
        account = _publisher_account_from_line(line)
        if not account:
            continue
        dedupe_key = account.lower()
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        assets.append(("ad_publisher_account", account, source))
    return assets


def _publisher_account_from_line(line: str) -> str:
    body = str(line or "").split("#", 1)[0].strip()
    if not body or "=" in body:
        return ""
    parts = [part.strip() for part in body.split(",")]
    if len(parts) < 3:
        return ""
    ad_system = _normalize_ad_system_domain(parts[0])
    publisher_account_id = _normalize_publisher_account_id(parts[1])
    relationship = parts[2].lower()
    if not ad_system or not publisher_account_id or relationship not in _AUTHORIZED_RELATIONSHIPS:
        return ""
    return f"{ad_system}/{publisher_account_id}"


def _normalize_ad_system_domain(value: object) -> str:
    candidate = str(value or "").strip().lower().rstrip(".")
    if not candidate or not _AD_SYSTEM_DOMAIN_RE.fullmatch(candidate):
        return ""
    return candidate


def _normalize_publisher_account_id(value: object) -> str:
    candidate = str(value or "").strip()
    if not candidate or not _PUBLISHER_ACCOUNT_ID_RE.fullmatch(candidate):
        return ""
    return candidate


def sellers_json_seller_account_assets(text: str) -> list[tuple[str, str, str]]:
    """Extract public sellers.json seller inventory without validating accounts."""

    try:
        payload = json.loads(str(text or ""))
    except Exception:  # noqa: BLE001
        return []
    if not isinstance(payload, dict):
        return []

    assets: list[tuple[str, str, str]] = []
    seen: set[str] = set()
    for entry in payload.get("sellers") or []:
        account = _seller_account_from_entry(entry)
        if not account:
            continue
        dedupe_key = account.lower()
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        assets.append(("ad_seller_account", account, "artifact_sellers_json_seller_account"))
    return assets


def _seller_account_from_entry(entry: Any) -> str:
    if not isinstance(entry, dict) or _is_truthy(entry.get("is_confidential")):
        return ""
    seller_id = _normalize_publisher_account_id(entry.get("seller_id"))
    domain = _normalize_ad_system_domain(entry.get("domain"))
    seller_type = str(entry.get("seller_type") or "").strip().lower()
    if seller_type and seller_type not in _SELLER_TYPES:
        return ""
    if not seller_id or not domain:
        return ""
    return f"{domain}/{seller_id}"


def _is_truthy(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    return str(value or "").strip().lower() in {"1", "true", "yes", "y"}
