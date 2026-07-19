from __future__ import annotations

from functools import lru_cache
from io import BytesIO
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse

_SUPPRESSED_PREFIXES = (
    "begin:vcard",
    "bitcoin:",
    "ethereum:",
    "litecoin:",
    "mecard:",
    "monero:",
    "otpauth://",
    "solana:",
    "vcard:",
    "wifi:",
)
_MAX_PAYLOAD_CHARS = 2048


def barcode_decoder_backend_names() -> tuple[str, ...]:
    return _available_backend_names()


def barcode_payloads_from_path(path: Path, *, max_bytes: int) -> list[str]:
    try:
        return barcode_payloads_from_bytes(path.read_bytes()[:max_bytes])
    except Exception:  # noqa: BLE001
        return []


def barcode_payloads_from_bytes(data: bytes) -> list[str]:
    if not data:
        return []
    payloads: list[str] = []
    if "pyzbar" in _available_backend_names():
        payloads.extend(_decode_with_pyzbar(data))
    if "opencv" in _available_backend_names():
        payloads.extend(_decode_with_opencv(data))
    return _dedupe_safe_payloads(payloads)


@lru_cache(maxsize=1)
def _available_backend_names() -> tuple[str, ...]:
    names: list[str] = []
    if _pyzbar_available():
        names.append("pyzbar")
    if _opencv_available():
        names.append("opencv")
    return tuple(names)


def _pyzbar_available() -> bool:
    try:
        from PIL import Image  # noqa: F401
        from pyzbar.pyzbar import decode as _decode  # noqa: F401

        return True
    except Exception:  # noqa: BLE001
        return False


def _opencv_available() -> bool:
    try:
        import cv2  # noqa: F401
        import numpy as np  # noqa: F401

        return True
    except Exception:  # noqa: BLE001
        return False


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
    payload = _sanitize_barcode_url_payload(payload)
    return payload[:_MAX_PAYLOAD_CHARS]


def _sanitize_barcode_url_payload(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return value
    hostname = parsed.hostname.lower()
    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"
    try:
        port = parsed.port
    except ValueError:
        port = None
    netloc = f"{hostname}:{port}" if port else hostname
    safe_query = urlencode(
        [
            (key, item_value)
            for key, item_value in parse_qsl(parsed.query, keep_blank_values=True)
            if not _query_key_is_sensitive(key)
        ],
        doseq=True,
    )
    return parsed._replace(netloc=netloc, query=safe_query).geturl()


def _query_key_is_sensitive(value: str) -> bool:
    compact = "".join(ch for ch in str(value or "").lower() if ch.isalnum() or ch == "_")
    return compact in {
        "access_token",
        "api_key",
        "auth_token",
        "client_secret",
        "id_token",
        "password",
        "refresh_token",
        "secret",
        "security_token",
        "session_token",
        "signature",
        "token",
        "x_amz_signature",
        "x_amz_security_token",
    } or compact.endswith(("_token", "_secret"))


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
