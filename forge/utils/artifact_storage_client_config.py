from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from urllib.parse import urlparse, urlunparse


_DIRECT_LABELS = {
    ".s3cfg": "s3cmd-config",
    ".boto": "boto-config",
    "boto.cfg": "boto-config",
}
_CACHE_LABEL_SUFFIXES = {
    ".s3cmd-config": "s3cmd-config",
    ".boto-config": "boto-config",
}
_ENDPOINT_KEYS = {
    "cloudfronthost",
    "gshost",
    "hostbase",
    "hostbucket",
    "s3host",
    "websiteendpoint",
}
_SECRET_KEY_MARKERS = ("access", "auth", "credential", "key", "pass", "secret", "token")
_PAIR_RE = re.compile(
    r"""(?im)^\s*["']?(?P<key>[A-Za-z_][A-Za-z0-9_.-]*)["']?\s*
    (?:=|:)\s*(?P<value>[^\r\n#;]{1,1024})""",
    re.VERBOSE,
)
_HOSTISH_RE = re.compile(
    r"""(?ix)^
    (?:
        (?:[a-z0-9][a-z0-9_-]*\.)+[a-z0-9][a-z0-9_-]*
        |
        \d{1,3}(?:\.\d{1,3}){3}
        |
        (?=[0-9a-f:.]{3,64}$)(?=[0-9a-f:.]*:)[0-9a-f:.]+
    )
    $"""
)


def storage_client_config_artifact_label(value: str) -> str:
    parts = _artifact_parts(value)
    if not parts:
        return ""
    name = parts[-1]
    for suffix, label in _CACHE_LABEL_SUFFIXES.items():
        if name.endswith(suffix):
            return label
    return _DIRECT_LABELS.get(name, "")


def storage_client_config_candidates(text: str) -> list[str]:
    values: list[str] = []
    seen: set[str] = set()
    for match in _PAIR_RE.finditer(str(text or "")):
        key = _fingerprint(match.group("key"))
        if key not in _ENDPOINT_KEYS or _secret_key(key):
            continue
        _append(values, seen, match.group("value"))
    return values


def storage_client_config_public_payload_text(text: str) -> str:
    lines: list[str] = []
    for line in str(text or "").splitlines():
        match = _PAIR_RE.match(line)
        if not match:
            lines.append(line)
            continue
        key = _fingerprint(match.group("key"))
        if _secret_key(key):
            continue
        if key not in _ENDPOINT_KEYS:
            lines.append(line)
            continue
        lines.extend(storage_client_config_candidates(line))
    return "\n".join(lines)


def _artifact_parts(value: str) -> list[str]:
    text = str(value or "").strip().replace("\\", "/").strip("/")
    if not text:
        return []
    return [Path(part).name.lower() for part in text.split("/") if part]


def _append(values: list[str], seen: set[str], value: str) -> None:
    candidate = _endpoint_url(value)
    lowered = candidate.lower()
    if not candidate or lowered in seen:
        return
    seen.add(lowered)
    values.append(candidate)


def _endpoint_url(value: str) -> str:
    raw = _strip_storage_template(str(value or "").strip().strip("\"'"))
    if not raw or any(marker in raw for marker in ("${", "%(", "{{", "}}", "<", ">")):
        return ""
    if raw.startswith("//"):
        raw = f"https:{raw}"
    if "://" not in raw and "." in raw:
        raw = f"https://{raw}"
    parsed = urlparse(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return ""
    host = parsed.hostname.lower().strip(".")
    if not _usable_host(host):
        return ""
    try:
        netloc = f"{host}:{parsed.port}" if parsed.port else host
    except ValueError:
        return ""
    return urlunparse((parsed.scheme.lower(), netloc, "", "", "", ""))


def _strip_storage_template(value: str) -> str:
    text = value.strip().strip("\"'").strip()
    text = re.sub(r"^(?:%\([^)]+\)s|\{[^}]+\}|\$\{[^}]+\})\.", "", text)
    return text.strip().strip("/")


def _usable_host(host: str) -> bool:
    if not host or host in {"localhost", "localhost.localdomain"}:
        return False
    try:
        parsed_ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return bool(_HOSTISH_RE.fullmatch(host))
    return not (parsed_ip.is_loopback or parsed_ip.is_multicast or parsed_ip.is_unspecified)


def _secret_key(key: str) -> bool:
    return any(marker in key for marker in _SECRET_KEY_MARKERS)


def _fingerprint(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value or "").strip().lower())
