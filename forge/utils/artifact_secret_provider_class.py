from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any
from urllib.parse import quote, urlparse

try:
    import yaml
except Exception:  # noqa: BLE001
    yaml = None  # type: ignore[assignment]


_FIELD_RE = re.compile(
    r"""(?im)^\s*-?\s*(?P<key>objectName|objectType|resourceName|secretPath|path)\s*:\s*
    ["']?(?P<value>[^"'\r\n#]+)["']?\s*$""",
    re.VERBOSE,
)
_GCP_SECRET_RE = re.compile(
    r"^projects/(?P<project>[a-z0-9][a-z0-9-]{3,63})/secrets/(?P<secret>[^/\s]+)"
)
_AWS_SECRETS_ARN_RE = re.compile(r"^(arn:aws[a-z-]*:secretsmanager:[^:\s]+:\d{12}:secret:[^:\s]+)")
_AZURE_VAULT_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,22}[a-z0-9]$")


def secret_provider_class_candidates(mapping: Mapping[str, Any]) -> list[str]:
    normalized = _normalized(mapping)
    if _fingerprint(_ref(normalized, "kind")) != "secretproviderclass":
        return []
    spec = _child(mapping, "spec")
    if not spec:
        return []

    candidates: list[str] = []
    seen: set[str] = set()

    def append(value: str) -> None:
        candidate = str(value or "").strip().strip("\"'")
        lowered = candidate.lower()
        if not candidate or lowered in seen:
            return
        seen.add(lowered)
        candidates.append(candidate)

    identifier = _object_identifier(mapping)
    if identifier:
        append(f"secret-provider-class://{identifier}")

    spec_norm = _normalized(spec)
    params = _child(spec, "parameters")
    params_norm = _normalized(params)
    provider = _fingerprint(_ref(spec_norm, "provider") or _ref(params_norm, "provider"))
    records = _object_records(params.get("objects") or params.get("secrets") or params)

    if provider == "azure":
        _azure_candidates(params_norm, records, append)
    elif provider == "aws":
        _aws_candidates(params_norm, records, append)
    elif provider in {"gcp", "google"}:
        _gcp_candidates(params_norm, records, append)
    elif provider in {"vault", "hashicorpvault"}:
        _vault_candidates(params_norm, records, append)

    return candidates


def _azure_candidates(
    params: Mapping[str, Any], records: Sequence[Mapping[str, str]], append: Any
) -> None:
    vault = str(_ref(params, "keyvaultName", "keyVaultName", "vaultName") or "").strip().lower()
    if not _AZURE_VAULT_RE.fullmatch(vault):
        return
    append(f"https://{vault}.vault.azure.net")
    for record in records:
        name = _segment(record.get("objectname"))
        if not name:
            continue
        family = {
            "key": "keys",
            "secret": "secrets",
            "certificate": "certificates",
            "cert": "certificates",
        }.get(_fingerprint(record.get("objecttype")), "secrets")
        append(f"https://{vault}.vault.azure.net/{family}/{name}")


def _aws_candidates(
    params: Mapping[str, Any], records: Sequence[Mapping[str, str]], append: Any
) -> None:
    region = _segment(_ref(params, "region"))
    for record in records:
        name = str(record.get("objectname") or record.get("secretpath") or "").strip()
        if not name:
            continue
        arn = _AWS_SECRETS_ARN_RE.match(name)
        if arn:
            append(f"aws-secretsmanager://{arn.group(1)}")
            continue
        encoded = _segment(name)
        if not encoded:
            continue
        family = (
            "aws-parameterstore"
            if "parameter" in _fingerprint(record.get("objecttype"))
            else "aws-secretsmanager"
        )
        append(f"{family}://{region}/{encoded}" if region else f"{family}://{encoded}")


def _gcp_candidates(
    params: Mapping[str, Any], records: Sequence[Mapping[str, str]], append: Any
) -> None:
    project = _segment(_ref(params, "projectID", "projectId", "project", "project_id"))
    if project:
        append(f"gcp-secretmanager://{project}")
    for record in records:
        resource = str(record.get("resourcename") or record.get("objectname") or "").strip()
        match = _GCP_SECRET_RE.match(resource)
        if match:
            append(f"gcp-secretmanager://{match.group('project')}")
            append(
                f"gcp-secretmanager://{match.group('project')}/{_segment(match.group('secret'))}"
            )
        elif project:
            secret = _segment(resource)
            if secret:
                append(f"gcp-secretmanager://{project}/{secret}")


def _vault_candidates(
    params: Mapping[str, Any], records: Sequence[Mapping[str, str]], append: Any
) -> None:
    address = _url(_ref(params, "vaultAddress", "vault_addr", "server", "url", "address"))
    if not address:
        return
    append(address)
    parsed = urlparse(address)
    if not parsed.hostname:
        return
    append(f"hashicorp-vault://{parsed.hostname.lower()}")
    for record in records:
        path = _segment(record.get("secretpath") or record.get("path") or record.get("objectname"))
        if path:
            append(f"hashicorp-vault://{parsed.hostname.lower()}/{path}")


def _object_records(value: Any) -> list[dict[str, str]]:
    if isinstance(value, Mapping):
        record = {
            _fingerprint(key): str(item).strip().strip("\"'")
            for key, item in value.items()
            if _fingerprint(key)
            in {"objectname", "objecttype", "resourcename", "secretpath", "path"}
            and isinstance(item, (str, int, float))
        }
        records = [record] if record else []
        for child in value.values():
            records.extend(_object_records(child))
        return records
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        records: list[dict[str, str]] = []
        for child in value:
            records.extend(_object_records(child))
        return records
    if isinstance(value, str):
        return _object_records_from_text(value)
    return []


def _object_records_from_text(text: str) -> list[dict[str, str]]:
    parsed = _parse_embedded_yaml(text)
    if parsed is not None and parsed is not text:
        parsed_records = _object_records(parsed)
        if parsed_records:
            return parsed_records
    records: list[dict[str, str]] = []
    current: dict[str, str] = {}
    for match in _FIELD_RE.finditer(str(text or "")):
        key = _fingerprint(match.group("key"))
        if key in {"objectname", "resourcename", "secretpath"} and current:
            records.append(current)
            current = {}
        current[key] = match.group("value").strip().strip("\"'")
    if current:
        records.append(current)
    return records


def _parse_embedded_yaml(text: str) -> Any:
    if yaml is None:
        return None
    try:
        return yaml.safe_load(text)
    except Exception:  # noqa: BLE001
        return None


def _object_identifier(mapping: Mapping[str, Any]) -> str:
    metadata = _child(mapping, "metadata")
    normalized = _normalized(metadata)
    name = _segment(_ref(normalized, "name"))
    namespace = _segment(_ref(normalized, "namespace"))
    return f"{namespace}/{name}" if name and namespace else name


def _child(mapping: Mapping[str, Any], *keys: str) -> Mapping[str, Any]:
    wanted = {_fingerprint(key) for key in keys}
    for key, value in mapping.items():
        if _fingerprint(key) in wanted and isinstance(value, Mapping):
            return value
    return {}


def _normalized(mapping: Mapping[str, Any]) -> dict[str, Any]:
    return {_fingerprint(key): value for key, value in mapping.items() if str(key or "").strip()}


def _ref(mapping: Mapping[str, Any], *keys: str) -> str:
    for key in keys:
        value = mapping.get(_fingerprint(key))
        if isinstance(value, (str, int, float)):
            text = str(value).strip()
            if text:
                return text
    return ""


def _fingerprint(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value or "").strip().lower())


def _segment(value: Any) -> str:
    text = str(value or "").strip().strip("\"'").strip("/")
    if not text or len(text) > 512 or re.search(r"\s|{{|}}", text):
        return ""
    return quote(text, safe="/._:@+=-")


def _url(value: Any) -> str:
    text = str(value or "").strip().strip("\"'")
    if not text or "{{" in text or "}}" in text:
        return ""
    if "://" not in text:
        text = f"https://{text}"
    parsed = urlparse(text)
    return text if parsed.scheme in {"http", "https"} and parsed.hostname else ""
