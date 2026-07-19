from __future__ import annotations

import base64
import json
import re
from collections.abc import Callable, Collection
from typing import Any


def har_scalar_text(value: Any, *, limit: int = 512) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        try:
            text = json.dumps(value, ensure_ascii=False, sort_keys=True)
        except Exception:  # noqa: BLE001
            text = str(value)
    else:
        text = str(value)
    cleaned = text.replace("\x00", "").strip()
    if len(cleaned) <= limit:
        return cleaned
    return f"{cleaned[: limit - 3]}..."


def har_content_text(
    content: dict[str, Any],
    *,
    scalar_text: Callable[[Any, int], str],
    text_from_bytes: Callable[[bytes, int], str],
) -> str:
    raw_text = content.get("text")
    if raw_text is None:
        return ""
    text_value = str(raw_text)
    encoding = str(content.get("encoding") or "").strip().lower()
    if encoding != "base64":
        return scalar_text(text_value, 4096)
    decoded = _har_base64_bytes(text_value, limit=0)
    if not decoded:
        return ""
    return text_from_bytes(decoded, 4096)


def har_content_image_payload_lines(
    content: dict[str, Any],
    *,
    mime_type: str,
    suffix: str,
    image_suffixes: Collection[str],
    max_image_bytes: int,
    ocr_text_limit: int,
    ocr_image_bytes: Callable[[bytes, str], str],
    image_metadata_payload: Callable[[bytes], str],
) -> list[str]:
    normalized_mime = str(mime_type or "").split(";", 1)[0].strip().lower()
    if not normalized_mime.startswith("image/") or suffix not in image_suffixes:
        return []
    if str(content.get("encoding") or "").strip().lower() != "base64":
        return []
    decoded = _har_base64_bytes(str(content.get("text") or ""), limit=max_image_bytes)
    if not decoded:
        return []
    lines: list[str] = []
    ocr_text = ocr_image_bytes(decoded, suffix).strip()
    if ocr_text:
        lines.append(f"response.content.ocr={ocr_text[:ocr_text_limit]}")
    metadata_payload = image_metadata_payload(decoded).strip()
    if metadata_payload:
        lines.append(f"response.content.imageMetadata={metadata_payload}")
    return lines


def _har_base64_bytes(value: str, *, limit: int) -> bytes:
    raw_text = str(value or "").strip()
    if not raw_text:
        return b""
    try:
        decoded = base64.b64decode(
            re.sub(r"\s+", "", raw_text).encode("ascii", errors="ignore"),
            validate=False,
        )
    except Exception:  # noqa: BLE001
        return b""
    if limit > 0:
        return decoded[:limit]
    return decoded
