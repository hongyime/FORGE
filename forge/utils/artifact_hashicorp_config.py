from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from urllib.parse import urlparse, urlunparse


_VAULT_CONFIG_DIRECT_NAMES = {
    "vault-agent.hcl",
    "vault-agent.json",
    "vault-client.hcl",
    "vault-client.json",
    "vault-server.hcl",
    "vault-server.json",
    "vault.hcl",
    "vault.json",
}
_VAULT_CONFIG_SEGMENTS = {"vault", ".vault.d", "vault.d", "hashicorp-vault"}
_VAULT_CONFIG_NAMES = {
    "agent.hcl",
    "client.hcl",
    "config.hcl",
    "server.hcl",
    "vault-agent.hcl",
    "vault-client.hcl",
    "vault-server.hcl",
}
_VAULT_ENDPOINT_KEYS = {
    "apiaddr",
    "clusteraddr",
    "redirectaddr",
    "vaultaddr",
    "vaultaddress",
    "vaultaddressurl",
    "vaulturl",
}
_ASSIGNMENT_RE = re.compile(
    r"""(?im)^\s*(?P<key>["']?[A-Za-z_][A-Za-z0-9_.-]*["']?)\s*
    (?:=|:)\s*(?P<value>[^\r\n#]{1,2048})""",
    re.VERBOSE,
)
_QUOTED_VALUE_RE = re.compile(r"""["'](?P<value>[^"'\r\n]{3,2048})["']""")
_HOSTISH_RE = re.compile(
    r"""(?ix)^
    (?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+
    [a-z](?:[a-z0-9-]{0,61}[a-z0-9])?
    $"""
)


def hashicorp_config_artifact_label(value: str) -> str:
    parts = _artifact_parts(value)
    if not parts:
        return ""
    name = parts[-1]
    if name in _VAULT_CONFIG_DIRECT_NAMES:
        return "hashicorp-vault-config"
    if name in _VAULT_CONFIG_NAMES and bool(set(parts[:-1]) & _VAULT_CONFIG_SEGMENTS):
        return "hashicorp-vault-config"
    return ""


def hashicorp_config_candidates(text: str, *, source_hint: str = "") -> list[str]:
    if hashicorp_config_artifact_label(source_hint) != "hashicorp-vault-config":
        return []
    candidates: list[str] = []
    seen: set[str] = set()
    for match in list(_ASSIGNMENT_RE.finditer(str(text or "")))[:4096]:
        key = _fingerprint(match.group("key"))
        if key not in _VAULT_ENDPOINT_KEYS:
            continue
        for value in _candidate_values(match.group("value")):
            _append(candidates, seen, value)
            if len(candidates) >= 256:
                return candidates
    return candidates


def _artifact_parts(value: str) -> list[str]:
    text = str(value or "").strip().replace("\\", "/").replace("#", "/").strip("/")
    if not text:
        return []
    return [Path(part).name.lower() for part in text.split("/") if part]


def _candidate_values(value: str) -> list[str]:
    raw = str(value or "").strip()
    quoted = [match.group("value") for match in _QUOTED_VALUE_RE.finditer(raw)]
    if quoted:
        return quoted
    return [raw.strip().strip("\"'[]{}(),;")]


def _append(values: list[str], seen: set[str], value: str) -> None:
    normalized = _normalize_vault_endpoint(value)
    key = normalized.lower()
    if normalized and key not in seen:
        seen.add(key)
        values.append(normalized)


def _normalize_vault_endpoint(value: str) -> str:
    raw = str(value or "").strip().strip("\"'`[]{}(),;").strip()
    if not raw or any(marker in raw for marker in ("${", "$(", "{{", "}}", "%{", "<", ">", "*")):
        return ""
    if "@" in raw.split("/", 1)[0]:
        return ""
    candidate = f"https:{raw}" if raw.startswith("//") else raw
    if "://" not in candidate:
        candidate = f"https://{candidate}"
    parsed = urlparse(candidate)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return ""
    if parsed.username or parsed.password or not _public_dns_host(parsed.hostname):
        return ""
    try:
        port = parsed.port
    except ValueError:
        return ""
    netloc = parsed.hostname.lower().strip(".")
    if port:
        netloc = f"{netloc}:{port}"
    path = parsed.path if _safe_path(parsed.path) else ""
    return urlunparse((parsed.scheme.lower(), netloc, path.rstrip("/"), "", "", ""))


def _public_dns_host(host: str) -> bool:
    candidate = str(host or "").strip().lower().strip(".")
    if not candidate or candidate in {"localhost", "localhost.localdomain"}:
        return False
    if candidate.endswith((".local", ".localhost", ".internal", ".lan")):
        return False
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return bool(_HOSTISH_RE.fullmatch(candidate))
    return False


def _safe_path(path: str) -> bool:
    return bool(path == "" or re.fullmatch(r"/[A-Za-z0-9_./~+\-]{1,256}", path))


def _fingerprint(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value or "").strip().lower().strip("\"'"))
