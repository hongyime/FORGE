from __future__ import annotations

from collections.abc import Iterable

CANONICAL_CLOUD_ASSET_TYPES = frozenset(
    {
        "aws_s3",
        "azure_blob",
        "do_spaces",
        "firebase",
        "gcs",
        "supabase",
    }
)

_ASSET_TYPE_ALIASES = {
    "azure_blob_storage": "azure_blob",
    "digitalocean_spaces": "do_spaces",
    "google_cloud_storage": "gcs",
    "s3": "aws_s3",
}
_TITLE_PREFIXES = (
    "validated firebase data exposure",
    "validated supabase data exposure",
    "validated public ",
    "externally reachable ",
    "public ",
)
_TITLE_SUFFIXES = (
    " listing exposure",
    " metadata observed",
    " detected",
)


def normalize_cloud_exposure_asset_type(value: str) -> str:
    normalized = str(value or "").strip().lower()
    return _ASSET_TYPE_ALIASES.get(normalized, normalized)


def is_deterministic_cloud_exposure(
    vuln_type: str,
    title: str,
    asset_hints: Iterable[str] = (),
) -> bool:
    """Identify cloud exposure rows whose reportability depends on validation."""
    if str(vuln_type or "").strip().upper() == "DETERMINISTIC_CLOUD_EXPOSURE":
        return True
    if not any(
        normalize_cloud_exposure_asset_type(hint) in CANONICAL_CLOUD_ASSET_TYPES
        for hint in asset_hints
    ):
        return False

    normalized_title = str(title or "").strip().lower()
    return normalized_title.startswith(_TITLE_PREFIXES) and (
        normalized_title.endswith(_TITLE_SUFFIXES)
        or " data exposure" in normalized_title
    )
