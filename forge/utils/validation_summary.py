from __future__ import annotations

import re
from typing import Any

MAX_VALIDATION_SUMMARY_LENGTH = 280

_ASSIGNMENT_SECRET_RE = re.compile(
    r"(?i)\b("
    r"password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|"
    r"session[_-]?token|security[_-]?token|client[_-]?secret|token|"
    r"x-amz-credential|x-amz-signature|x-amz-security-token|"
    r"x-goog-credential|x-goog-signature|awsaccesskeyid|signature|sig"
    r")\s*[:=]\s*[^\s,;&]+"
)
_QUERY_SECRET_RE = re.compile(
    r"(?i)([?&]"
    r"(?:X-Amz-Credential|X-Amz-Signature|X-Amz-Security-Token|"
    r"X-Goog-Credential|X-Goog-Signature|X-Goog-Algorithm|"
    r"X-Goog-SignedHeaders|AWSAccessKeyId|Signature|sig|token|"
    r"access_token|api_key|key|client_secret|se|sp|sv|sr|spr|"
    r"skoid|sktid|skt|ske|sks|skv)"
    r"=)[^&#\s]+"
)
_HEADER_STOP_RE = (
    r"(?=(?:\s+(?:Authorization|Set-Cookie|Cookie|HTTP\s+\d{3}|"
    r"[A-Za-z0-9-]{2,40}\s*:|"
    r"(?:password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|"
    r"session[_-]?token|security[_-]?token|client[_-]?secret|token)\s*[=:]))"
    r"|[\r\n]|$)"
)
_AUTH_SIMPLE_HEADER_RE = re.compile(
    r"(?i)\b(Authorization)\s*:\s*"
    r"(?:Bearer|Basic|Digest)\s+[^\s,;]+"
)
_AUTH_AWS_HEADER_RE = re.compile(
    r"(?is)\b(Authorization)\s*:\s*AWS4-HMAC-SHA256\s+.*?"
    + _HEADER_STOP_RE
)
_COOKIE_HEADER_RE = re.compile(
    r"(?is)\b(Set-Cookie|Cookie)\s*:\s*.*?"
    + _HEADER_STOP_RE
)
_BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+\-/]+=*")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_AWS_ACCESS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
_LONG_SECRETISH_RE = re.compile(r"\b[A-Za-z0-9+/=_-]{48,}\b")


def safe_validation_summary(value: Any, *, max_length: int = MAX_VALIDATION_SUMMARY_LENGTH) -> str:
    text = str(value or "")
    if not text:
        return ""

    text = _QUERY_SECRET_RE.sub(lambda match: f"{match.group(1)}[REDACTED]", text)
    text = _AUTH_SIMPLE_HEADER_RE.sub(lambda match: f"{match.group(1)}: [REDACTED]", text)
    text = _AUTH_AWS_HEADER_RE.sub(lambda match: f"{match.group(1)}: [REDACTED]", text)
    text = _COOKIE_HEADER_RE.sub(lambda match: f"{match.group(1)}: [REDACTED]", text)
    text = _ASSIGNMENT_SECRET_RE.sub(
        lambda match: f"{match.group(1)}=[REDACTED]",
        text,
    )
    text = _BEARER_RE.sub("Bearer [REDACTED]", text)
    text = _JWT_RE.sub("[REDACTED_JWT]", text)
    text = _AWS_ACCESS_KEY_RE.sub("[REDACTED_AWS_KEY]", text)
    text = _LONG_SECRETISH_RE.sub("[REDACTED]", text)
    text = " ".join(text.split())

    if len(text) <= max_length:
        return text
    return text[: max_length - 3] + "..."
