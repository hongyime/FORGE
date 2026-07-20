from __future__ import annotations

import re

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$"
)
_MTA_STS_MX_RE = re.compile(r"^\s*mx\s*:\s*(?P<host>\S+)", re.IGNORECASE)


def mta_sts_mx_hosts(text: str) -> list[str]:
    """Extract passive MX host patterns from an MTA-STS policy file."""

    hosts: list[str] = []
    seen: set[str] = set()
    for line in str(text or "").splitlines():
        match = _MTA_STS_MX_RE.match(line.split("#", 1)[0])
        if not match:
            continue
        host = _normalize_mta_sts_mx_host(match.group("host"))
        if not host or host in seen:
            continue
        seen.add(host)
        hosts.append(host)
    return hosts


def _normalize_mta_sts_mx_host(value: object) -> str:
    candidate = str(value or "").strip().lower().rstrip(".")
    if candidate.startswith("*."):
        candidate = candidate[2:]
    if not candidate or candidate in {"localhost", "localhost.localdomain"}:
        return ""
    if not _HOSTNAME_RE.fullmatch(candidate):
        return ""
    return candidate
