from __future__ import annotations

import ipaddress
import re


_DNS_RESOURCE_TYPES = {
    "aws_route53_record",
    "azurerm_dns_a_record",
    "azurerm_dns_aaaa_record",
    "azurerm_dns_caa_record",
    "azurerm_dns_cname_record",
    "azurerm_dns_mx_record",
    "azurerm_dns_ns_record",
    "azurerm_dns_ptr_record",
    "azurerm_dns_srv_record",
    "azurerm_dns_txt_record",
    "cloudflare_dns_record",
    "cloudflare_record",
    "digitalocean_record",
    "dnsimple_record",
    "google_dns_record_set",
}
_BLOCK_START_RE = re.compile(r'^\s*resource\s+"(?P<type>[A-Za-z0-9_]+)"\s+"[^"\r\n]+"\s*\{')
_ASSIGNMENT_RE = re.compile(
    r"^\s*(?P<key>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<value>[^\r\n#]{1,2048})"
)
_QUOTED_VALUE_RE = re.compile(r"""["'](?P<value>[^"'\r\n]{1,1024})["']""")
_HOST_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$")
_NAME_KEYS = {"fqdn", "hostname", "name"}
_TARGET_KEYS = {
    "alias_name",
    "cname",
    "content",
    "record",
    "records",
    "rrdata",
    "rrdatas",
    "target",
    "target_dns_name",
    "value",
}
_ZONE_KEYS = {"domain", "dns_zone_name", "managed_zone_name", "zone", "zone_name"}
_PRIVATE_SUFFIXES = (
    ".corp",
    ".home",
    ".internal",
    ".lan",
    ".local",
    ".localhost",
    ".test",
)


def terraform_dns_record_hosts(text: str) -> list[str]:
    candidates: list[str] = []
    seen: set[str] = set()
    for resource_type, block_text in _iter_resource_blocks(text):
        if resource_type not in _DNS_RESOURCE_TYPES:
            continue
        assignments = _block_assignments(block_text)
        zone_names = _hosts_from_assignments(assignments, _ZONE_KEYS, zone_name="")
        zone_name = zone_names[0] if zone_names else ""
        for key_set in (_NAME_KEYS, _TARGET_KEYS):
            for host in _hosts_from_assignments(assignments, key_set, zone_name=zone_name):
                if host not in seen:
                    seen.add(host)
                    candidates.append(host)
    return candidates


def _iter_resource_blocks(text: str) -> list[tuple[str, str]]:
    lines = str(text or "").splitlines()
    blocks: list[tuple[str, str]] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        match = _BLOCK_START_RE.match(line)
        if not match:
            index += 1
            continue
        resource_type = str(match.group("type") or "").strip().lower()
        brace_depth = line.count("{") - line.count("}")
        block_lines = [line]
        index += 1
        while index < len(lines):
            current = lines[index]
            block_lines.append(current)
            brace_depth += current.count("{") - current.count("}")
            index += 1
            if brace_depth <= 0:
                break
        blocks.append((resource_type, "\n".join(block_lines)))
    return blocks


def _block_assignments(block_text: str) -> dict[str, list[str]]:
    assignments: dict[str, list[str]] = {}
    for raw_line in str(block_text or "").splitlines()[:4096]:
        match = _ASSIGNMENT_RE.match(raw_line)
        if not match:
            continue
        key = str(match.group("key") or "").strip().lower()
        values = _assignment_values(match.group("value"))
        if key and values:
            assignments.setdefault(key, []).extend(values)
    return assignments


def _assignment_values(value: str) -> list[str]:
    raw = str(value or "").strip()
    quoted = [match.group("value") for match in _QUOTED_VALUE_RE.finditer(raw)]
    if quoted:
        return quoted[:64]
    return [raw.strip().strip("\"'[]{}(),;")]


def _hosts_from_assignments(
    assignments: dict[str, list[str]],
    keys: set[str],
    *,
    zone_name: str,
) -> list[str]:
    hosts: list[str] = []
    for key, values in assignments.items():
        if key not in keys:
            continue
        for value in values:
            host = _normalize_dns_host(value, zone_name=zone_name)
            if host:
                hosts.append(host)
    return _dedupe(hosts)


def _normalize_dns_host(value: str, *, zone_name: str) -> str:
    raw = str(value or "").strip().strip("\"'`[]{}(),;").strip().lower().strip(".")
    if not raw or any(marker in raw for marker in ("${", "$(", "{{", "}}", "%{", "<", ">", "*")):
        return ""
    if "/" in raw or ":" in raw:
        return ""
    zone = str(zone_name or "").strip().lower().strip(".")
    if raw == "@":
        raw = zone
    elif "." not in raw and zone:
        raw = f"{raw}.{zone}"
    if not raw or raw.endswith(_PRIVATE_SUFFIXES):
        return ""
    try:
        ipaddress.ip_address(raw)
    except ValueError:
        return raw if _HOST_RE.fullmatch(raw) else ""
    return ""


def _dedupe(values: list[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        lowered = str(value or "").strip().lower()
        if lowered and lowered not in seen:
            seen.add(lowered)
            result.append(lowered)
    return result
