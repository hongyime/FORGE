from __future__ import annotations

from datetime import datetime, timezone


def generate_dynamic_passwords(domain: str, limit: int = 200) -> list[str]:
    normalized = domain.strip().lower()
    if "." in normalized:
        org = normalized.split(".")[0]
    else:
        org = normalized
    org_clean = "".join(ch for ch in org if ch.isalnum())
    current_year = datetime.now(timezone.utc).year
    base_tokens = {
        org_clean,
        org_clean.capitalize(),
        f"{org_clean}123",
        f"{org_clean}@123",
        f"{org_clean}2024",
        f"{org_clean}2025",
        f"{org_clean}{current_year}",
        f"{org_clean}!",
        f"{org_clean}#",
        "Password123!",
        "Welcome123!",
        "Spring2026!",
        "Summer2026!",
        "Autumn2026!",
        "Winter2026!",
    }
    variants: set[str] = set()
    for token in base_tokens:
        if not token:
            continue
        variants.add(token)
        variants.add(token.lower())
        variants.add(token.upper())
        variants.add(token.capitalize())
    ranked = sorted(variants, key=lambda item: (len(item), item))
    return ranked[:limit]
