"""Passive OCI image-layout helpers.

These helpers inspect local OCI/Docker-style JSON metadata only. They never
pull images, contact registries, or execute container tooling.
"""

from __future__ import annotations

import re
from typing import Any

_SHA256_RE = re.compile(r"(?:sha256:)?([a-f0-9]{64})\Z", re.IGNORECASE)


def oci_digest(value: Any) -> str:
    match = _SHA256_RE.fullmatch(str(value or "").strip())
    return str(match.group(1)).lower() if match else ""


def oci_blob_member_name(digest: Any) -> str:
    value = oci_digest(digest)
    return f"blobs/sha256/{value}" if value else ""


def oci_index_manifest_digests(payload: Any) -> list[str]:
    if not isinstance(payload, dict):
        return []
    digests: list[str] = []
    seen: set[str] = set()
    for item in payload.get("manifests") or []:
        if not isinstance(item, dict):
            continue
        digest = oci_digest(item.get("digest"))
        media_type = str(item.get("mediaType") or item.get("media_type") or "").lower()
        if not digest or digest in seen:
            continue
        if media_type and "manifest" not in media_type:
            continue
        seen.add(digest)
        digests.append(digest)
    return digests[:8]


def oci_manifest_config_digest(payload: Any) -> str:
    if not isinstance(payload, dict) or not isinstance(payload.get("config"), dict):
        return ""
    return oci_digest(payload["config"].get("digest"))


def oci_manifest_layer_digests(payload: Any) -> list[str]:
    if not isinstance(payload, dict):
        return []
    digests: list[str] = []
    seen: set[str] = set()
    for item in payload.get("layers") or []:
        if not isinstance(item, dict):
            continue
        digest = oci_digest(item.get("digest"))
        media_type = str(item.get("mediaType") or item.get("media_type") or "").lower()
        if not digest or digest in seen:
            continue
        if media_type and "layer" not in media_type:
            continue
        seen.add(digest)
        digests.append(digest)
    return digests[:16]
