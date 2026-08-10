from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from urllib.parse import urlparse


_SCRIPT_EXTENSIONS = {".cjs", ".js", ".json", ".jsonc", ".mjs", ".ts", ".yaml", ".yml"}
_CACHE_LABEL_SUFFIXES = {
    ".prisma-schema": "prisma-schema",
    ".prisma-config": "prisma-config",
    ".drizzle-config": "drizzle-config",
    ".typeorm-config": "typeorm-config",
    ".sequelize-config": "sequelize-config",
    ".knexfile": "knexfile",
    ".mikro-orm-config": "mikro-orm-config",
    ".liquibase-config": "liquibase-config",
    ".flyway-config": "flyway-config",
}
_DB_KEY_RE = (
    r"host|hostname|server|address|db[_-]?host|database[_-]?host|"
    r"url|uri|database[_-]?url|direct[_-]?url|shadow[_-]?database[_-]?url|"
    r"connection|string|connection[_-]?string|connectionstring|jdbc[_-]?url"
)
_VALUE = r"(?P<value>[^\"'\s,\]}#<>]{3,1024})"
_FIELD_RE = re.compile(
    rf"""(?im)^\s*(?:[-\w.]+\.)?["']?(?:{_DB_KEY_RE})["']?\s*(?::|=)\s*["']?{_VALUE}""",
    re.VERBOSE,
)
_JSON_FIELD_RE = re.compile(
    rf"""(?i)["'](?:{_DB_KEY_RE})["']\s*:\s*["']{_VALUE}["']""",
    re.VERBOSE,
)
_PRISMA_FIELD_RE = re.compile(
    rf"""(?im)^\s*(?:url|directUrl|shadowDatabaseUrl)\s*=\s*["']{_VALUE}["']""",
    re.VERBOSE,
)
_PLIST_RE = re.compile(
    rf"""(?is)<key>\s*(?:{_DB_KEY_RE})\s*</key>\s*<string>\s*{_VALUE}\s*</string>""",
    re.VERBOSE,
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


def orm_config_artifact_label(value: str) -> str:
    parts = _artifact_parts(value)
    if not parts:
        return ""
    name = parts[-1]
    for suffix, label in _CACHE_LABEL_SUFFIXES.items():
        if name.endswith(suffix):
            return label
    segments = set(parts[:-1])
    suffix = Path(name).suffix.lower()
    if name == "schema.prisma" or suffix == ".prisma":
        return "prisma-schema"
    if name.startswith("prisma.config.") and suffix in _SCRIPT_EXTENSIONS:
        return "prisma-config"
    if name.startswith("drizzle.config.") and suffix in _SCRIPT_EXTENSIONS:
        return "drizzle-config"
    if name.startswith("ormconfig.") and suffix in _SCRIPT_EXTENSIONS | {".env"}:
        return "typeorm-config"
    if name.startswith("typeorm.config.") and suffix in _SCRIPT_EXTENSIONS:
        return "typeorm-config"
    if name in {"data-source.ts", "data-source.js", "data-source.mjs", "data-source.cjs"} and (
        segments & {"db", "database", "typeorm"}
    ):
        return "typeorm-config"
    if name == ".sequelizerc" or name.startswith("sequelize.config."):
        return "sequelize-config"
    if name.startswith("knexfile.") and suffix in {".cjs", ".js", ".mjs", ".ts"}:
        return "knexfile"
    if name.startswith("mikro-orm.config.") and suffix in _SCRIPT_EXTENSIONS:
        return "mikro-orm-config"
    if name in {"liquibase.properties", "liquibase.yaml", "liquibase.yml", "liquibase.json"}:
        return "liquibase-config"
    if "liquibase" in segments and name in {"changelog.xml", "db.changelog-master.xml"}:
        return "liquibase-config"
    if (
        name in {"flyway.conf", "flyway.toml"}
        or name.startswith("flyway.")
        and suffix in _SCRIPT_EXTENSIONS
    ):
        return "flyway-config"
    return ""


def orm_config_host_candidates(text: str) -> list[str]:
    matches: list[tuple[int, str]] = []
    for pattern in (_JSON_FIELD_RE, _FIELD_RE, _PRISMA_FIELD_RE, _PLIST_RE):
        matches.extend(
            (match.start(), match.group("value")) for match in pattern.finditer(str(text or ""))
        )
    values: list[str] = []
    seen: set[str] = set()
    for _, value in sorted(matches, key=lambda item: item[0]):
        _append(values, seen, value)
    return values


def _artifact_parts(value: str) -> list[str]:
    text = str(value or "").strip().replace("\\", "/").strip("/")
    if not text:
        return []
    return [Path(part).name.lower() for part in text.split("/") if part]


def _append(values: list[str], seen: set[str], value: str) -> None:
    raw = str(value or "").strip().strip("\"'`[]{}(),;").strip(".")
    lowered = raw.lower()
    if (
        not raw
        or lowered in _template_tokens()
        or any(marker in lowered for marker in _template_markers())
    ):
        return
    host = _candidate_host(raw)
    if not host:
        return
    host = _without_port(host).strip("[]").lower().strip(".")
    if not host or host in seen or not _usable_host(host):
        return
    seen.add(host)
    values.append(host)


def _template_markers() -> tuple[str, ...]:
    return (
        "${",
        "$(",
        "{{",
        "}}",
        "env(",
        "getenv(",
        "import.meta.env",
        "os.getenv",
        "process.env",
    )


def _template_tokens() -> set[str]:
    return {"config", "env", "getenv", "process"}


def _candidate_host(value: str) -> str:
    oracle_match = _ORACLE_JDBC_RE.search(value)
    if oracle_match:
        return oracle_match.group("host")
    candidate = value[5:] if value.lower().startswith("jdbc:") else value
    if "://" in candidate:
        parsed = urlparse(candidate)
        return parsed.hostname or ""
    return candidate.split("/", 1)[0].split(";", 1)[0]


def _usable_host(host: str) -> bool:
    candidate = str(host or "").strip().lower().strip("[]").strip(".")
    if not candidate or candidate in {"localhost", "localhost.localdomain"}:
        return False
    parsed_ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None
    try:
        parsed_ip = ipaddress.ip_address(candidate)
    except ValueError:
        parsed_ip = None
    if parsed_ip and (parsed_ip.is_loopback or parsed_ip.is_unspecified or parsed_ip.is_multicast):
        return False
    return bool(_HOSTISH_RE.fullmatch(candidate))


def _without_port(candidate: str) -> str:
    match = _PORT_SUFFIX_RE.fullmatch(candidate)
    if not match:
        return candidate
    port = int(match.group("port"))
    return match.group("host") if 0 < port <= 65535 else candidate
