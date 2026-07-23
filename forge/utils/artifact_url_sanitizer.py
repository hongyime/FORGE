from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlparse


def strip_sensitive_url_query(value: str) -> str:
    """Remove credential-like query parameters from a normalized HTTP(S) URL."""

    parsed = urlparse(str(value or "").strip())
    if parsed.scheme not in {"http", "https"} or not parsed.query:
        return str(value or "")
    safe_pairs = [
        (key, item)
        for key, item in parse_qsl(parsed.query, keep_blank_values=True)
        if not _query_key_is_sensitive(key)
    ]
    return parsed._replace(query=urlencode(safe_pairs, doseq=True)).geturl()


def _query_key_is_sensitive(value: str) -> bool:
    key = str(value or "").strip().lower()
    if not key:
        return False
    compact = key.replace("-", "_").replace(".", "_")
    if compact in {
        "access_key",
        "access_key_id",
        "access_token",
        "api_key",
        "apikey",
        "auth",
        "auth_token",
        "authorization",
        "client_secret",
        "code",
        "credential",
        "id_token",
        "key",
        "password",
        "refresh_token",
        "relaystate",
        "samlrequest",
        "samlresponse",
        "secret",
        "security_token",
        "session",
        "session_id",
        "sessionid",
        "session_token",
        "shared_access_signature",
        "sig",
        "sigalg",
        "signature",
        "sid",
        "jsessionid",
        "phpsessid",
        "token",
        "x_amz_credential",
        "x_amz_security_token",
        "x_amz_signature",
    }:
        return True
    return (
        compact.endswith("_token")
        or compact.endswith("_secret")
        or compact.endswith("_session")
        or "signature" in compact
        or "credential" in compact
    )
