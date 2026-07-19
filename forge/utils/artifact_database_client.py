from __future__ import annotations

import ipaddress
import re
from pathlib import Path


_DBeaver_NAMES = {"data-sources.json", "data-sources.xml"}
_JETBRAINS_NAMES = {"datasources.xml", "datasources.local.xml"}
_TABLEPLUS_NAMES = {"connections.json", "connections.xml", "connections.plist", "favorites.plist"}
_SQL_DEVELOPER_NAMES = {"connections.xml"}
_PGADMIN_NAMES = {"servers.json"}
_HEIDISQL_NAMES = {"heidisql.ini", "portable_settings.txt"}
_DBVIS_NAMES = {"dbvis.xml", "connections.xml"}
_CACHE_LABEL_SUFFIXES = {
    ".dbeaver-datasources": "dbeaver-datasources",
    ".jetbrains-datasources": "jetbrains-datasources",
    ".tableplus-connections": "tableplus-connections",
    ".sqldeveloper-connections": "sqldeveloper-connections",
    ".pgadmin-servers": "pgadmin-servers",
    ".heidisql-config": "heidisql-config",
    ".dbvis-connections": "dbvis-connections",
}
_HOST_KEYS = r"host|hostname|server|serverhost|remotehost|address|dbhost|databasehost"
_FIELD_RE = re.compile(
    rf"""(?im)^\s*["']?(?:{_HOST_KEYS})["']?\s*(?::|=)\s*["']?
    (?P<value>[A-Za-z0-9_.:\[\]-]{{2,255}})""",
    re.VERBOSE,
)
_JSON_FIELD_RE = re.compile(
    rf"""(?i)["'](?:{_HOST_KEYS})["']\s*:\s*["']
    (?P<value>[A-Za-z0-9_.:\[\]-]{{2,255}})["']""",
    re.VERBOSE,
)
_XML_ATTR_RE = re.compile(
    rf"""(?is)<[^>]*(?:name|key)=["'](?:{_HOST_KEYS})["'][^>]*
    \bvalue=["'](?P<value>[A-Za-z0-9_.:\[\]-]{{2,255}})["'][^>]*>""",
    re.VERBOSE,
)
_XML_ATTR_REVERSED = re.compile(
    rf"""(?is)<[^>]*\bvalue=["'](?P<value>[A-Za-z0-9_.:\[\]-]{{2,255}})["'][^>]*
    (?:name|key)=["'](?:{_HOST_KEYS})["'][^>]*>""",
    re.VERBOSE,
)
_XML_ELEMENT_RE = re.compile(
    rf"""(?is)<(?:{_HOST_KEYS})>\s*(?P<value>[A-Za-z0-9_.:\[\]-]{{2,255}})\s*</(?:{_HOST_KEYS})>""",
    re.VERBOSE,
)
_PLIST_RE = re.compile(
    rf"""(?is)<key>\s*(?:{_HOST_KEYS})\s*</key>\s*
    <string>\s*(?P<value>[A-Za-z0-9_.:\[\]-]{{2,255}})\s*</string>""",
    re.VERBOSE,
)
_PORT_SUFFIX_RE = re.compile(r"^(?P<host>\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9_.-]+):(?P<port>\d{1,5})$")
_HOSTISH_RE = re.compile(
    r"""(?ix)^
    (?:
        (?:[A-Za-z0-9_][A-Za-z0-9_\-]*\.)+[A-Za-z0-9_][A-Za-z0-9_\-]*
        |
        [A-Za-z_](?:[A-Za-z0-9_\-]{0,61}[A-Za-z0-9_])?
        |
        \d{1,3}(?:\.\d{1,3}){3}
        |
        (?=[0-9A-Fa-f:.]{3,64}$)(?=[0-9A-Fa-f:.]*:)[0-9A-Fa-f:.]+
        |
        \[(?=[0-9A-Fa-f:.]{3,64}\])(?=[0-9A-Fa-f:.]*:)[0-9A-Fa-f:.]+\]
    )
    $"""
)


def database_client_config_artifact_label(value: str) -> str:
    parts = _artifact_parts(value)
    if not parts:
        return ""
    name = parts[-1]
    for suffix, label in _CACHE_LABEL_SUFFIXES.items():
        if name.endswith(suffix):
            return label
    segments = set(parts[:-1])
    if ({"dbeaver", ".dbeaver"} & segments or _has_segment_containing(parts, "dbeaver")) and name in _DBeaver_NAMES:
        return "dbeaver-datasources"
    if ({".idea", "datagrip", "jetbrains"} & segments) and name in _JETBRAINS_NAMES:
        return "jetbrains-datasources"
    if "tableplus" in segments and name in _TABLEPLUS_NAMES:
        return "tableplus-connections"
    if {"sqldeveloper", "sql developer"} & segments and name in _SQL_DEVELOPER_NAMES:
        return "sqldeveloper-connections"
    if {"pgadmin", "pgadmin4"} & segments and name in _PGADMIN_NAMES:
        return "pgadmin-servers"
    if "heidisql" in segments and name in _HEIDISQL_NAMES:
        return "heidisql-config"
    if {"dbvisualizer", "dbvis", ".dbvis"} & segments and name in _DBVIS_NAMES:
        return "dbvis-connections"
    return ""


def database_client_host_candidates(text: str) -> list[str]:
    values: list[str] = []
    seen: set[str] = set()
    matches: list[tuple[int, str]] = []
    for pattern in (
        _JSON_FIELD_RE,
        _FIELD_RE,
        _XML_ATTR_RE,
        _XML_ATTR_REVERSED,
        _XML_ELEMENT_RE,
        _PLIST_RE,
    ):
        matches.extend((match.start(), match.group("value")) for match in pattern.finditer(str(text or "")))
    for _, value in sorted(matches, key=lambda item: item[0]):
        _append(values, seen, value)
    return values


def _artifact_parts(value: str) -> list[str]:
    text = str(value or "").strip().replace("\\", "/").strip("/")
    if not text:
        return []
    return [Path(part).name.lower() for part in text.split("/") if part]


def _has_segment_containing(parts: list[str], value: str) -> bool:
    return any(value in part for part in parts)


def _append(values: list[str], seen: set[str], value: str) -> None:
    candidate = str(value or "").strip().strip("\"'(){}.,;").lower().strip(".")
    candidate = _without_port(candidate)
    if not candidate or candidate in seen:
        return
    if candidate in {"localhost", "localhost.localdomain", "[::1]"}:
        return
    parsed_ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None
    bracketed = candidate.startswith("[") and candidate.endswith("]")
    if bracketed:
        inner = candidate[1:-1]
        try:
            parsed_ip = ipaddress.ip_address(inner)
        except ValueError:
            return
        if parsed_ip.version != 6:
            return
    elif re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", candidate):
        try:
            parsed_ip = ipaddress.ip_address(candidate)
        except ValueError:
            return
        if parsed_ip.version != 4:
            return
    elif ":" in candidate:
        try:
            parsed_ip = ipaddress.ip_address(candidate)
        except ValueError:
            return
        if parsed_ip.version != 6:
            return
    if parsed_ip and (parsed_ip.is_loopback or parsed_ip.is_unspecified or parsed_ip.is_multicast):
        return
    if not _HOSTISH_RE.fullmatch(candidate):
        return
    candidate = candidate.strip("[]")
    if candidate in seen:
        return
    seen.add(candidate)
    values.append(candidate)


def _without_port(candidate: str) -> str:
    match = _PORT_SUFFIX_RE.fullmatch(candidate)
    if not match:
        return candidate
    port = int(match.group("port"))
    return match.group("host") if 0 < port <= 65535 else candidate
