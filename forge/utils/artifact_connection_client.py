from __future__ import annotations

import re
import shlex
from pathlib import Path
from urllib.parse import urlsplit


_DIRECT_LABELS = {
    "winscp.ini": "winscp-config",
    "mobaxterm.ini": "mobaxterm-config",
    "sessions.mxtsessions": "mobaxterm-sessions",
    "putty.reg": "putty-config",
    "kitty.ini": "kitty-config",
    "superputty.settings": "superputty-config",
    "filezilla.xml": "filezilla-config",
}
_FILEZILLA_NAMES = {"sitemanager.xml", "recentservers.xml", "filezilla.xml"}
_TRANSMIT_NAMES = {"favorites.xml", "favorites.plist"}
_LFTP_NAMES = {"bookmarks", "rc", "lftp.conf"}
_NCFTP_NAMES = {"bookmarks", "firewall", "prefs"}
_CACHE_LABEL_SUFFIXES = {
    ".mobaxterm-sessions": "mobaxterm-sessions",
    ".securecrt-session": "securecrt-session",
    ".superputty-config": "superputty-config",
    ".filezilla-config": "filezilla-config",
    ".cyberduck-bookmark": "cyberduck-bookmark",
    ".transmit-favorites": "transmit-favorites",
    ".lftp-config": "lftp-config",
    ".ncftp-config": "ncftp-config",
    ".remmina-config": "remmina-config",
}
_HOST_FIELD_RE = re.compile(
    r"""(?im)^\s*(?:[A-Za-z]:)?\s*["']?
    (?:
        host\s*name|hostname|host|remotehost|remote_host|server|serverhost|
        ssh[_-]?tunnel[_-]?server|sshhost|sftphost|ftphost
    )
    ["']?\s*(?::|=)\s*["']?(?P<value>[A-Za-z0-9_.:\[\]-]{3,255})
    """,
    re.VERBOSE,
)
_XML_HOST_RE = re.compile(
    r"""(?is)<(?:host|hostname|server|serverhost|remotehost)>\s*
    (?P<value>[A-Za-z0-9_.:\[\]-]{3,255})\s*
    </(?:host|hostname|server|serverhost|remotehost)>""",
    re.VERBOSE,
)
_PLIST_HOST_RE = re.compile(
    r"""(?is)<key>\s*
    (?:host|hostname|server|serverhost|remotehost)\s*
    </key>\s*<string>\s*(?P<value>[A-Za-z0-9_.:\[\]-]{3,255})\s*</string>""",
    re.VERBOSE,
)
_CLIENT_COMMAND_RE = re.compile(
    r"(?i)\b(?:ssh|sftp|scp|telnet|rlogin|ftp|lftp|ncftp)(?=\s|$)[^\r\n]*"
)
_COMMAND_VALUE_FLAGS = {
    "ssh": {
        "-B",
        "-b",
        "-c",
        "-D",
        "-E",
        "-e",
        "-F",
        "-I",
        "-i",
        "-J",
        "-L",
        "-l",
        "-m",
        "-O",
        "-o",
        "-p",
        "-Q",
        "-R",
        "-S",
        "-W",
        "-w",
    },
    "sftp": {"-B", "-b", "-c", "-D", "-F", "-i", "-J", "-l", "-o", "-P", "-R", "-S"},
    "scp": {"-c", "-F", "-i", "-J", "-l", "-o", "-P", "-S"},
}
_HOSTISH_RE = re.compile(
    r"""(?ix)^
    (?:
        (?:[A-Za-z0-9][A-Za-z0-9_\-]*\.)+[A-Za-z0-9][A-Za-z0-9_\-]*
        |
        \d{1,3}(?:\.\d{1,3}){3}
        |
        \[[0-9A-Fa-f:.]{3,64}\]
    )
    $"""
)


def connection_client_config_artifact_label(value: str) -> str:
    parts = _artifact_parts(value)
    if not parts:
        return ""
    name = parts[-1]
    for suffix, label in _CACHE_LABEL_SUFFIXES.items():
        if name.endswith(suffix):
            return label
    if name in _DIRECT_LABELS:
        return _DIRECT_LABELS[name]
    if name.endswith(".remmina"):
        return "remmina-config"
    if name.endswith((".mxtsessions", ".mxtsessions.backup")):
        return "mobaxterm-sessions"
    segments = set(parts[:-1])
    if "securecrt" in segments and "sessions" in segments and name.endswith((".ini", ".xml")):
        return "securecrt-session"
    if "superputty" in segments and (
        name == "sessions.xml" or ("sessions" in segments and name.endswith((".xml", ".settings")))
    ):
        return "superputty-config"
    if "filezilla" in segments and name in _FILEZILLA_NAMES:
        return "filezilla-config"
    if "cyberduck" in segments and (
        name.endswith(".duck") or name in {"bookmarks.xml", "bookmarks.plist"}
    ):
        return "cyberduck-bookmark"
    if "transmit" in segments and name in _TRANSMIT_NAMES:
        return "transmit-favorites"
    if {".lftp", "lftp"} & segments and name in _LFTP_NAMES:
        return "lftp-config"
    if {".ncftp", "ncftp"} & segments and name in _NCFTP_NAMES:
        return "ncftp-config"
    return ""


def connection_client_host_candidates(text: str) -> list[str]:
    values: list[str] = []
    seen: set[str] = set()
    for match in _HOST_FIELD_RE.finditer(str(text or "")):
        _append(values, seen, match.group("value"))
    for match in _XML_HOST_RE.finditer(str(text or "")):
        _append(values, seen, match.group("value"))
    for match in _PLIST_HOST_RE.finditer(str(text or "")):
        _append(values, seen, match.group("value"))
    for match in _CLIENT_COMMAND_RE.finditer(str(text or "")):
        for host in _client_command_host_values(match.group(0)):
            _append(values, seen, host)
    return values


def _artifact_parts(value: str) -> list[str]:
    text = str(value or "").strip().replace("\\", "/").strip("/")
    if not text:
        return []
    return [Path(part).name.lower() for part in text.split("/") if part]


def _append(values: list[str], seen: set[str], value: str) -> None:
    candidate = _normalize_host_value(value)
    if not candidate or candidate in seen:
        return
    if candidate in {"localhost", "localhost.localdomain"}:
        return
    seen.add(candidate)
    values.append(candidate)


def _normalize_host_value(value: str) -> str:
    candidate = str(value or "").strip().strip("\"'(){}.,;").lower().strip(".")
    if candidate.startswith("[") and "]" in candidate:
        host = candidate.split("]", 1)[0].strip("[]")
        return host.strip(".")
    if candidate.count(":") == 1:
        host, port = candidate.rsplit(":", 1)
        if port.isdigit():
            candidate = host
    return candidate.strip("[]").strip(".")


def _client_command_host_values(command_text: str) -> list[str]:
    values: list[str] = []
    try:
        raw_tokens = shlex.split(str(command_text or ""), posix=True)
    except ValueError:
        raw_tokens = str(command_text or "").split()
    tokens = [token.strip().strip("\"'(){};,") for token in raw_tokens if token.strip()]
    if not tokens:
        return values
    command = tokens[0].lower()
    skip_next = False
    for token in tokens[1:]:
        if skip_next:
            skip_next = False
            continue
        option_mode = _option_value_mode(command, token)
        if option_mode == "next":
            skip_next = True
            continue
        if option_mode == "attached":
            continue
        lowered = token.lower()
        if lowered.startswith("-"):
            continue
        if command == "scp" and not any(marker in token for marker in (":", "@", "://")):
            continue
        if "://" in token:
            parsed = urlsplit(token)
            candidate = parsed.hostname or ""
        else:
            candidate = token.rsplit("@", 1)[-1].split("/", 1)[0].strip()
        if candidate.startswith("["):
            candidate = candidate.split("]", 1)[0] + "]" if "]" in candidate else candidate
        elif candidate.count(":") == 1:
            host_part, port_part = candidate.rsplit(":", 1)
            if port_part.isdigit() or command == "scp":
                candidate = host_part
        if _HOSTISH_RE.fullmatch(candidate):
            values.append(candidate)
            break
    return values


def _option_value_mode(command: str, token: str) -> str:
    flags = _COMMAND_VALUE_FLAGS.get(command, set())
    if token in flags:
        return "next"
    if len(token) > 2 and token[:2] in flags:
        return "attached"
    return ""
