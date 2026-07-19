from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from urllib.parse import urlparse


_SPRING_NAMES = {
    "application.properties",
    "application.yml",
    "application.yaml",
    "bootstrap.properties",
    "bootstrap.yml",
    "bootstrap.yaml",
}
_SPRING_PROFILE_NAME_RE = re.compile(
    r"^(?:application|bootstrap)-[a-z0-9_.-]+\.(?:properties|ya?ml)$"
)
_CACHE_LABEL_SUFFIXES = {
    ".rails-database-config": "rails-database-config",
    ".spring-config": "spring-config",
    ".dotnet-appsettings": "dotnet-appsettings",
    ".dotnet-web-config": "dotnet-web-config",
    ".alembic-config": "alembic-config",
    ".laravel-database-config": "laravel-database-config",
    ".django-settings": "django-settings",
}
_DB_KEY_RE = (
    r"host|hostname|server|address|db[_\-.]?host|database[_\-.]?host|"
    r"database[_\-.]?url|db[_\-.]?url|datasource[_\-.]?(?:url|host)|"
    r"spring\.datasource\.(?:url|jdbc-url|host)|spring\.r2dbc\.url|"
    r"sqlalchemy\.url|connection(?:strings?|[_\-.]?string)?|jdbc[_\-.]?url"
)
_VALUE = r"(?P<value>[^\"'\s,#<>]{3,2048})"
_FIELD_RE = re.compile(
    rf"""(?im)^\s*["']?(?:[-\w.]+\.)?(?:{_DB_KEY_RE})["']?\s*(?:=>|:|=)\s*["']?{_VALUE}""",
    re.VERBOSE,
)
_QUOTED_FIELD_RE = re.compile(
    rf"""(?i)["'](?:[-\w.]+\.)?(?:{_DB_KEY_RE})["']\s*(?:=>|:|=)\s*["']
    (?P<value>[^"'\r\n]{{3,2048}})["']""",
    re.VERBOSE,
)
_DOTNET_CONNECTION_RE = re.compile(
    r"""(?i)["'][^"']*(?:connection|string)[^"']*["']\s*:\s*["'](?P<value>[^"'\r\n]{3,2048})["']"""
)
_XML_CONNECTION_RE = re.compile(r"""(?i)\bconnectionString=["'](?P<value>[^"']{3,2048})["']""")
_ENV_FALLBACK_RE = re.compile(
    r"""(?i)["'](?:DB_HOST|DATABASE_HOST|DB_URL|DATABASE_URL)["']\s*,\s*["'](?P<value>[^"']{3,1024})["']"""
)
_CONNECTION_STRING_HOST_RE = re.compile(
    r"""(?ix)(?:server|host|data\s+source|address|network\s+address)\s*=\s*(?P<host>[^;,\s]+)"""
)
_ORACLE_JDBC_RE = re.compile(
    r"""(?ix)jdbc:oracle:thin:(?:(?:[^@\s"'<>`;()]+)@|@)?(?://)?(?P<host>[^:/\s"'<>`;()]+)"""
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
    )
    $"""
)


def framework_config_artifact_label(value: str) -> str:
    parts = _artifact_parts(value)
    if not parts:
        return ""
    name = parts[-1]
    for suffix, label in _CACHE_LABEL_SUFFIXES.items():
        if name.endswith(suffix):
            return label
    segments = set(parts[:-1])
    if name in {"database.yml", "database.yaml"} and "config" in segments:
        return "rails-database-config"
    if name == "alembic.ini":
        return "alembic-config"
    if name == "database.php" and "config" in segments:
        return "laravel-database-config"
    if _is_spring_config_name(name) and (
        _has_sequence(parts, ("src", "main", "resources")) or _has_segment(parts, "spring")
    ):
        return "spring-config"
    if name == "web.config":
        return "dotnet-web-config"
    if name.startswith("appsettings") and name.endswith(".json"):
        return "dotnet-appsettings"
    if name == "settings.py" and _has_segment(parts, "django"):
        return "django-settings"
    return ""


def framework_config_host_candidates(text: str) -> list[str]:
    matches: list[tuple[int, str]] = []
    for pattern in (_QUOTED_FIELD_RE, _FIELD_RE, _DOTNET_CONNECTION_RE, _XML_CONNECTION_RE, _ENV_FALLBACK_RE):
        matches.extend((match.start(), match.group("value")) for match in pattern.finditer(str(text or "")))
    values: list[str] = []
    seen: set[str] = set()
    for _, value in sorted(matches, key=lambda item: item[0]):
        _append(values, seen, value)
    return values


def _artifact_parts(value: str) -> list[str]:
    text = str(value or "").strip().replace("\\", "/").replace("#", "/").strip("/")
    if not text:
        return []
    return [Path(part).name.lower() for part in text.split("/") if part]


def _has_segment(parts: list[str], value: str) -> bool:
    return value in parts[:-1]


def _has_sequence(parts: list[str], sequence: tuple[str, ...]) -> bool:
    size = len(sequence)
    return any(tuple(parts[index : index + size]) == sequence for index in range(max(0, len(parts) - size + 1)))


def _is_spring_config_name(name: str) -> bool:
    return name in _SPRING_NAMES or bool(_SPRING_PROFILE_NAME_RE.fullmatch(name))


def _append(values: list[str], seen: set[str], value: str) -> None:
    raw = str(value or "").strip().strip("\"'`[]{}(),;").strip(".")
    lowered = raw.lower()
    if not raw or lowered in {"config", "env", "getenv", "process"}:
        return
    if any(marker in lowered for marker in ("${", "$(", "{{", "}}", "env(", "getenv(", "process.env", "os.getenv")):
        return
    host = _candidate_host(raw).strip("[]").lower().strip(".")
    if not host or host in seen or not _usable_host(host):
        return
    seen.add(host)
    values.append(host)


def _candidate_host(value: str) -> str:
    connection_match = _CONNECTION_STRING_HOST_RE.search(value)
    if connection_match:
        return _normalize_connection_host(connection_match.group("host"))
    oracle_match = _ORACLE_JDBC_RE.search(value)
    if oracle_match:
        return oracle_match.group("host")
    candidate = value[5:] if value.lower().startswith("jdbc:") else value
    if "://" in candidate:
        parsed = urlparse(candidate)
        return parsed.hostname or ""
    return candidate.split("/", 1)[0].split(";", 1)[0]


def _normalize_connection_host(value: str) -> str:
    candidate = str(value or "").strip().strip("\"'[]")
    for prefix in ("tcp:", "np:", "lpc:"):
        if candidate.lower().startswith(prefix):
            candidate = candidate[len(prefix) :]
    return candidate.split(",", 1)[0].split(":", 1)[0]


def _usable_host(host: str) -> bool:
    candidate = str(host or "").strip().lower().strip("[]").strip(".")
    if not candidate or candidate in {"localhost", "localhost.localdomain"}:
        return False
    try:
        parsed_ip = ipaddress.ip_address(candidate)
    except ValueError:
        parsed_ip = None
    if parsed_ip and (parsed_ip.is_loopback or parsed_ip.is_unspecified or parsed_ip.is_multicast):
        return False
    return bool(_HOSTISH_RE.fullmatch(candidate))
