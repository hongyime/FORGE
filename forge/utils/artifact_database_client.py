from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from urllib.parse import urlparse, urlunparse


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
_KEY_VALUE_RE = re.compile(
    r"""(?im)^\s*["']?(?P<key>[A-Za-z_][A-Za-z0-9_. -]*)["']?\s*
    (?:=|:)\s*["']?(?P<value>[^"',}\r\n]{1,512})""",
    re.VERBOSE,
)
_JSON_PAIR_RE = re.compile(
    r"""(?i)["'](?P<key>[A-Za-z_][A-Za-z0-9_. -]*)["']\s*:\s*["']
    (?P<value>[^"']{1,512})["']""",
    re.VERBOSE,
)
_XML_PROPERTY_RE = re.compile(
    r"""(?is)<[^>]*(?:name|key)=["'](?P<key>[A-Za-z_][A-Za-z0-9_. -]*)["'][^>]*
    \bvalue=["'](?P<value>[^"']{1,512})["'][^>]*>""",
    re.VERBOSE,
)
_XML_PROPERTY_REVERSED = re.compile(
    r"""(?is)<[^>]*\bvalue=["'](?P<value>[^"']{1,512})["'][^>]*
    (?:name|key)=["'](?P<key>[A-Za-z_][A-Za-z0-9_. -]*)["'][^>]*>""",
    re.VERBOSE,
)
_XML_ELEMENT_PAIR_RE = re.compile(
    r"""(?is)<(?P<key>host|hostname|server|driver|type|adapter|engine|port|database|dbname|schema)>
    \s*(?P<value>[^<]{1,512})\s*</(?P=key)>""",
    re.VERBOSE,
)
_PLIST_PAIR_RE = re.compile(
    r"""(?is)<key>\s*(?P<key>[A-Za-z_][A-Za-z0-9_. -]*)\s*</key>\s*
    <(?:string|integer)>\s*(?P<value>[^<]{1,512})\s*</(?:string|integer)>""",
    re.VERBOSE,
)
_DSN_RE = re.compile(
    r"""(?ix)\b(?:jdbc:)?(?:
    postgres|postgresql|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|mssql|
    sqlserver|clickhouse|oracle
    )://[^\s"'<>`]+"""
)
_SCHEME_VALUES = {
    "clickhouse": "clickhouse",
    "mariadb": "mariadb",
    "mongodb": "mongodb",
    "mongodb+srv": "mongodb+srv",
    "mssql": "mssql",
    "mysql": "mysql",
    "oracle": "oracle",
    "postgres": "postgres",
    "postgresql": "postgresql",
    "redis": "redis",
    "rediss": "rediss",
    "sqlserver": "sqlserver",
}
_SCHEME_KEYS = {"adapter", "dbtype", "driver", "engine", "provider", "protocol", "type", "vendor"}
_PORT_KEYS = {"port", "dbport", "databaseport", "serverport"}
_DATABASE_KEYS = {"database", "databasename", "dbname", "schema", "sid", "servicename"}
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
    if (
        {"dbeaver", ".dbeaver"} & segments or _has_segment_containing(parts, "dbeaver")
    ) and name in _DBeaver_NAMES:
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
        matches.extend(
            (match.start(), match.group("value")) for match in pattern.finditer(str(text or ""))
        )
    for _, value in sorted(matches, key=lambda item: item[0]):
        _append(values, seen, value)
    return values


def database_client_endpoint_candidates(text: str) -> list[str]:
    values: list[str] = []
    seen: set[str] = set()
    for match in _DSN_RE.finditer(str(text or "")):
        _append_endpoint(values, seen, _sanitize_dsn(match.group(0)))
    pairs = _field_pairs(text)
    scheme = _first_scheme(pairs)
    if not scheme:
        # Legacy fallback: drives host recursion when a DB-client config omits its engine.
        for host in database_client_host_candidates(text):
            _append_endpoint(values, seen, _split_endpoint("postgres", host))
        return values
    port = _first_port(pairs)
    database = _first_database(pairs)
    for host in database_client_host_candidates(text):
        endpoint = _split_endpoint(scheme, host, port=port, database=database)
        _append_endpoint(values, seen, endpoint)
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


def _field_pairs(text: str) -> list[tuple[int, str, str]]:
    pairs: list[tuple[int, str, str]] = []
    for pattern in (
        _JSON_PAIR_RE,
        _KEY_VALUE_RE,
        _XML_PROPERTY_RE,
        _XML_PROPERTY_REVERSED,
        _XML_ELEMENT_PAIR_RE,
        _PLIST_PAIR_RE,
    ):
        pairs.extend(
            (
                match.start(),
                _fingerprint(match.group("key")),
                str(match.group("value") or "").strip(),
            )
            for match in pattern.finditer(str(text or ""))
        )
    return sorted(pairs, key=lambda item: item[0])


def _first_scheme(pairs: list[tuple[int, str, str]]) -> str:
    for _index, key, value in pairs:
        if key in _SCHEME_KEYS:
            scheme = _scheme_from_value(value)
            if scheme:
                return scheme
    return ""


def _first_port(pairs: list[tuple[int, str, str]]) -> str:
    for _index, key, value in pairs:
        if key not in _PORT_KEYS:
            continue
        candidate = str(value or "").strip().strip("\"'")
        if candidate.isdigit() and 0 < int(candidate) <= 65535:
            return candidate
    return ""


def _first_database(pairs: list[tuple[int, str, str]]) -> str:
    for _index, key, value in pairs:
        if key in _DATABASE_KEYS:
            candidate = str(value or "").strip().strip("\"'/")
            if candidate and re.fullmatch(r"[A-Za-z0-9_.~+\-]{1,128}", candidate):
                return candidate
    return ""


def _scheme_from_value(value: str) -> str:
    normalized = str(value or "").strip().lower()
    normalized = normalized.replace("jdbc:", "")
    compact = _fingerprint(normalized)
    for marker, scheme in (
        ("postgresql", "postgresql"),
        ("postgres", "postgres"),
        ("mariadb", "mariadb"),
        ("mongodb+srv", "mongodb+srv"),
        ("mongodb", "mongodb"),
        ("sqlserver", "sqlserver"),
        ("mssql", "mssql"),
        ("clickhouse", "clickhouse"),
        ("oracle", "oracle"),
        ("redis", "redis"),
        ("mysql", "mysql"),
    ):
        if marker in normalized or _fingerprint(marker) in compact:
            return scheme
    return _SCHEME_VALUES.get(normalized, "")


def _sanitize_dsn(value: str) -> str:
    raw = str(value or "").strip().strip("\"'").rstrip(")]}.,;")
    if raw.lower().startswith("jdbc:"):
        raw = raw[5:]
    parsed = urlparse(raw)
    scheme = parsed.scheme.lower()
    if scheme not in _SCHEME_VALUES or not parsed.hostname:
        return ""
    host = parsed.hostname.lower().strip(".")
    if not _host_allowed_for_endpoint(host):
        return ""
    try:
        port = parsed.port
    except ValueError:
        return ""
    netloc = _netloc(host, str(port) if port else "")
    path = parsed.path if _safe_path(parsed.path) else ""
    return urlunparse((scheme, netloc, path, "", "", ""))


def _split_endpoint(
    scheme: str,
    host: str,
    *,
    port: str = "",
    database: str = "",
) -> str:
    clean_host = str(host or "").strip().strip("[]").lower().strip(".")
    if scheme not in _SCHEME_VALUES or not _host_allowed_for_endpoint(clean_host):
        return ""
    path = f"/{database}" if database else ""
    return urlunparse((scheme, _netloc(clean_host, port), path, "", "", ""))


def _host_allowed_for_endpoint(host: str) -> bool:
    if not host or host in {"localhost", "localhost.localdomain"}:
        return False
    try:
        parsed_ip = ipaddress.ip_address(host)
    except ValueError:
        return bool(_HOSTISH_RE.fullmatch(host))
    return not (parsed_ip.is_loopback or parsed_ip.is_unspecified or parsed_ip.is_multicast)


def _netloc(host: str, port: str) -> str:
    wrapped_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
    return f"{wrapped_host}:{port}" if port else wrapped_host


def _safe_path(path: str) -> bool:
    return bool(path == "" or re.fullmatch(r"/[A-Za-z0-9_./~+\-]{1,256}", path))


def _append_endpoint(values: list[str], seen: set[str], value: str) -> None:
    candidate = str(value or "").strip()
    lowered = candidate.lower()
    if not candidate or lowered in seen:
        return
    seen.add(lowered)
    values.append(candidate)


def _fingerprint(value: str) -> str:
    return re.sub(r"[^a-z0-9+]+", "", str(value or "").strip().lower())
