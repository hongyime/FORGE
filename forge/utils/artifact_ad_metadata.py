from __future__ import annotations

import re

_AD_SYSTEM_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$"
)
_PUBLISHER_ACCOUNT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_AUTHORIZED_RELATIONSHIPS = {"direct", "reseller"}


def ads_txt_publisher_account_assets(
    text: str,
    *,
    app_ads: bool = False,
) -> list[tuple[str, str, str]]:
    """Extract passive ad seller account inventory from ads.txt style files."""

    source = "artifact_app_ads_txt_publisher_account" if app_ads else "artifact_ads_txt_publisher_account"
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
    if (
        not ad_system
        or not publisher_account_id
        or relationship not in _AUTHORIZED_RELATIONSHIPS
    ):
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
