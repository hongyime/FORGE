from __future__ import annotations

from io import BytesIO
from pathlib import Path
from typing import Any

_SUPPRESSED_PREFIXES = ("otpauth://", "wifi:")
_MAX_PAYLOAD_CHARS = 2048


def barcode_payloads_from_path(path: Path, *, max_bytes: int) -> list[str]:
    try:
        return barcode_payloads_from_bytes(path.read_bytes()[:max_bytes])
    except Exception:  # noqa: BLE001
        return []


def barcode_payloads_from_bytes(data: bytes) -> list[str]:
    if not data:
        return []
    payloads: list[str] = []
    payloads.extend(_decode_with_pyzbar(data))
    payloads.extend(_decode_with_opencv(data))
    return _dedupe_safe_payloads(payloads)


def _dedupe_safe_payloads(payloads: list[str]) -> list[str]:
    deduped: list[str] = []
    seen: set[str] = set()
    for raw_payload in payloads:
        payload = _safe_barcode_payload(raw_payload)
        lowered = payload.lower()
        if not payload or lowered in seen:
            continue
        seen.add(lowered)
        deduped.append(payload)
    return deduped[:16]


def _safe_barcode_payload(value: str) -> str:
    payload = " ".join(str(value or "").replace("\x00", " ").split()).strip()
    if not payload:
        return ""
    if payload.lower().startswith(_SUPPRESSED_PREFIXES):
        return ""
    return payload[:_MAX_PAYLOAD_CHARS]


def _decode_with_pyzbar(data: bytes) -> list[str]:
    try:
        from PIL import Image
        from pyzbar.pyzbar import decode as pyzbar_decode

        with Image.open(BytesIO(data)) as image:
            return [_decoded_object_text(obj) for obj in pyzbar_decode(image)]
    except Exception:  # noqa: BLE001
        return []


def _decoded_object_text(obj: Any) -> str:
    raw_data = getattr(obj, "data", b"")
    if isinstance(raw_data, bytes):
        return raw_data.decode("utf-8", errors="replace")
    return str(raw_data or "")


def _decode_with_opencv(data: bytes) -> list[str]:
    try:
        import cv2
        import numpy as np

        image = cv2.imdecode(np.frombuffer(data, dtype=np.uint8), cv2.IMREAD_COLOR)
        if image is None:
            return []
        detector = cv2.QRCodeDetector()
        ok, decoded_info, _points, _straight = detector.detectAndDecodeMulti(image)
        if ok:
            return [str(item or "") for item in decoded_info]
        single, _points, _straight = detector.detectAndDecode(image)
        return [str(single or "")]
    except Exception:  # noqa: BLE001
        return []
