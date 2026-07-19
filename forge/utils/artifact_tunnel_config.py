from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from urllib.parse import urlparse


_CACHE_LABEL_SUFFIXES = {
    ".ngrok-config": "ngrok-config",
    ".cloudflared-config": "cloudflared-config",
    ".tailscale-serve-config": "tailscale-serve-config",
    ".localtunnel-config": "localtunnel-config",
}
_NGROK_NAMES = {"ngrok.yml", "ngrok.yaml", "ngrok.json", "ngrok.conf", ".ngrok.yml", ".ngrok.yaml"}
_CLOUDFLARED_NAMES = {
    "config.yml",
    "config.yaml",
    "config.json",
    "tunnel.yml",
    "tunnel.yaml",
    "cloudflared.yml",
    "cloudflared.yaml",
    "cloudflared.json",
    "ingress.yml",
    "ingress.yaml",
}
_TAILSCALE_NAMES = {
    "serve.json",
    "serve.yaml",
    "serve.yml",
    "funnel.json",
    "funnel.yaml",
    "funnel.yml",
    "tailscale-serve.json",
    "tailscale-serve.yaml",
    "tailscale-funnel.json",
    "tailscale-funnel.yaml",
}
_LOCALTUNNEL_DIRECT_NAMES = {".localtunnelrc", "localtunnel.json", "localtunnel.yaml", "localtunnel.yml"}
_LOCALTUNNEL_SEGMENT_NAMES = {"lt.json", "lt.yaml", "lt.yml", *_LOCALTUNNEL_DIRECT_NAMES}
_ENDPOINT_KEYS = (
    r"host|hostname|domain|domains|fqdn|endpoint|endpoints|url|urls|"
    r"public[_-]?url|publicurl|public[_-]?hostname|service"
)
_VALUE = r"(?P<value>[^\"'\s,\]}#<>]{3,512})"
_FIELD_RE = re.compile(
    rf"""(?im)^\s*(?:-\s*)?["']?(?:{_ENDPOINT_KEYS})["']?\s*(?::|=)\s*["']?{_VALUE}""",
    re.VERBOSE,
)
_JSON_FIELD_RE = re.compile(
    rf"""(?i)["'](?:{_ENDPOINT_KEYS})["']\s*:\s*["']{_VALUE}["']""",
    re.VERBOSE,
)
_XML_ELEMENT_RE = re.compile(
    rf"""(?is)<(?:{_ENDPOINT_KEYS})>\s*{_VALUE}\s*</(?:{_ENDPOINT_KEYS})>""",
    re.VERBOSE,
)
_PLIST_RE = re.compile(
    rf"""(?is)<key>\s*(?:{_ENDPOINT_KEYS})\s*</key>\s*<string>\s*{_VALUE}\s*</string>""",
    re.VERBOSE,
)
_HOSTISH_RE = re.compile(
    r"""(?ix)^
    (?:
        (?:[A-Za-z0-9][A-Za-z0-9-]*\.)+[A-Za-z0-9][A-Za-z0-9-]*
        |
        \d{1,3}(?:\.\d{1,3}){3}
        |
        (?=[0-9A-Fa-f:.]{3,64}$)(?=[0-9A-Fa-f:.]*:)[0-9A-Fa-f:.]+
    )
    $"""
)


def tunnel_config_artifact_label(value: str) -> str:
    parts = _artifact_parts(value)
    if not parts:
        return ""
    name = parts[-1]
    for suffix, label in _CACHE_LABEL_SUFFIXES.items():
        if name.endswith(suffix):
            return label
    segments = set(parts[:-1])
    if name in _NGROK_NAMES:
        return "ngrok-config"
    if name.startswith("ngrok.") and Path(name).suffix.lower() in {".yml", ".yaml", ".json", ".conf"}:
        return "ngrok-config"
    if name.startswith("cloudflared.") and Path(name).suffix.lower() in {".yml", ".yaml", ".json"}:
        return "cloudflared-config"
    if _has_segment(parts, ".cloudflared", "cloudflared") and name in _CLOUDFLARED_NAMES:
        return "cloudflared-config"
    if ("cloudflare" in segments or "tunnels" in segments) and name in {"tunnel.yml", "tunnel.yaml"}:
        return "cloudflared-config"
    if name.startswith(("tailscale-serve.", "tailscale-funnel.")):
        return "tailscale-serve-config"
    if _has_segment(parts, "tailscale") and name in _TAILSCALE_NAMES:
        return "tailscale-serve-config"
    if name in _LOCALTUNNEL_DIRECT_NAMES or _has_segment(parts, "localtunnel") and name in _LOCALTUNNEL_SEGMENT_NAMES:
        return "localtunnel-config"
    return ""


def tunnel_config_endpoint_candidates(text: str) -> list[str]:
    values: list[str] = []
    seen: set[str] = set()
    matches: list[tuple[int, str]] = []
    for pattern in (_JSON_FIELD_RE, _FIELD_RE, _XML_ELEMENT_RE, _PLIST_RE):
        matches.extend((match.start(), match.group("value")) for match in pattern.finditer(str(text or "")))
    for _, value in sorted(matches, key=lambda item: item[0]):
        _append(values, seen, value)
    return values


def tunnel_config_public_payload_text(text: str) -> str:
    raw = str(text or "")
    if not raw:
        return ""
    dropped_ranges: list[tuple[int, int]] = []
    for pattern in (_JSON_FIELD_RE, _FIELD_RE, _XML_ELEMENT_RE, _PLIST_RE):
        for match in pattern.finditer(raw):
            host = _candidate_host(match.group("value"))
            if host and not _public_endpoint_host(host):
                start = raw.rfind("\n", 0, match.start()) + 1
                next_line = raw.find("\n", match.end())
                end = len(raw) if next_line < 0 else next_line + 1
                dropped_ranges.append((start, end))
    lines: list[str] = []
    offset = 0
    for line in raw.splitlines(keepends=True):
        line_end = offset + len(line)
        if not any(offset < end and line_end > start for start, end in dropped_ranges):
            lines.append(line)
        offset = line_end
    return "".join(lines)


def _artifact_parts(value: str) -> list[str]:
    text = str(value or "").strip().replace("\\", "/").strip("/")
    if not text:
        return []
    return [Path(part).name.lower() for part in text.split("/") if part]


def _has_segment(parts: list[str], *values: str) -> bool:
    wanted = set(values)
    return bool(wanted & set(parts[:-1]))


def _append(values: list[str], seen: set[str], value: str) -> None:
    candidate = str(value or "").strip().strip("\"'`[]{}(),;").strip(".")
    if not candidate or any(marker in candidate for marker in ("${", "$(", "{{", "}}", "<", ">", "*")):
        return
    host = _candidate_host(candidate)
    if not host or not _public_endpoint_host(host):
        return
    key = candidate.lower()
    if key in seen:
        return
    seen.add(key)
    values.append(candidate)


def _candidate_host(value: str) -> str:
    candidate = str(value or "").strip()
    if candidate.startswith("//"):
        candidate = f"https:{candidate}"
    if "://" in candidate:
        hostname = urlparse(candidate).hostname or ""
        return hostname.strip().lower().strip(".")
    host = candidate.split("/", 1)[0].strip().strip("[]").lower().strip(".")
    if host.count(":") == 1:
        left, right = host.rsplit(":", 1)
        if right.isdigit() and 0 < int(right) <= 65535:
            host = left
    return host


def _public_endpoint_host(host: str) -> bool:
    candidate = str(host or "").strip().lower().strip("[]").strip(".")
    if not candidate or candidate in {"localhost", "localhost.localdomain"}:
        return False
    if candidate.endswith((".localhost", ".local")):
        return False
    parsed_ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None
    try:
        parsed_ip = ipaddress.ip_address(candidate)
    except ValueError:
        parsed_ip = None
    if parsed_ip and (
        parsed_ip.is_loopback
        or parsed_ip.is_unspecified
        or parsed_ip.is_multicast
        or parsed_ip.is_private
        or parsed_ip.is_link_local
    ):
        return False
    return bool(_HOSTISH_RE.fullmatch(candidate))
