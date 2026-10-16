"""Parsing and scope helpers for provider-native cloud references."""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit


@dataclass(frozen=True)
class CloudReference:
    provider: str
    resource_type: str
    resource_id: str
    canonical_value: str


_ARN = re.compile(r"^arn:(aws(?:-[a-z0-9-]+)?):([a-z0-9-]+):([^:]*):([^:]*):(.+)$", re.I)
_AZURE_ID = re.compile(r"^/(?:subscriptions/[^/]+/)?(?:resourcegroups/[^/]+/)?providers/([^/]+)/(.+)$", re.I)
_GCP_FULL = re.compile(r"^//([a-z0-9.-]+\.googleapis\.com)/(.+)$", re.I)
_GCP_PATH = re.compile(r"^(projects|organizations|folders)/([^/]+)(?:/(.+))?$", re.I)


def parse_cloud_ref(value: str) -> CloudReference | None:
    """Parse an ARN, Azure resource ID, GCP resource name, cloud URL, or legacy ref."""
    text = str(value or "").strip()
    if not text or any(ch.isspace() for ch in text):
        return None
    arn = _ARN.fullmatch(text)
    if arn:
        partition, service, _region, _account, resource = arn.groups()
        resource_type, sep, resource_id = resource.partition("/")
        if not sep:
            resource_type, sep, resource_id = resource.partition(":")
        if not sep:
            resource_type, resource_id = service, resource
        if not resource_type or not resource_id or "*" in text:
            return None
        return CloudReference("aws", resource_type.lower(), resource_id, text.lower())
    azure = _AZURE_ID.fullmatch(text)
    if azure:
        provider, rest = azure.groups()
        pieces = [part for part in rest.split("/") if part]
        if len(pieces) < 2:
            return None
        return CloudReference("azure", pieces[-2].lower(), pieces[-1], text.rstrip("/"))
    gcp = _GCP_FULL.fullmatch(text)
    if gcp:
        service, resource = gcp.groups()
        parts = resource.strip("/").split("/")
        if len(parts) < 2:
            return None
        return CloudReference("gcp", parts[-2].lower(), parts[-1], text.rstrip("/"))
    gcp_path = _GCP_PATH.fullmatch(text.strip("/"))
    if gcp_path:
        root, identifier, tail = gcp_path.groups()
        return CloudReference("gcp", root.lower().rstrip("s"), identifier, text.strip("/"))
    parsed = urlsplit(text)
    if parsed.scheme.lower() in {"http", "https"} and parsed.hostname:
        host = parsed.hostname.lower()
        provider = next((p for suffix, p in ((".amazonaws.com", "aws"), (".googleapis.com", "gcp"), (".blob.core.windows.net", "azure"), (".supabase.co", "supabase"), (".supabase.in", "supabase")) if host.endswith(suffix)), None)
        if provider:
            kind = "bucket" if provider in {"aws", "gcp"} else "endpoint"
            identifier = "/".join(part for part in (host, parsed.path.strip("/")) if part)
            return CloudReference(provider, kind, identifier, text)
    return None


def validate_cloud_ref(value: str) -> bool:
    """Return whether value is a supported, structurally valid cloud reference."""
    return parse_cloud_ref(value) is not None


def engagement_scope(reference: CloudReference) -> dict[str, list[str]]:
    """Return least-broad host/seed scope data suitable for a cloud target."""
    scope = {"domains": [], "urls": [], "authorized_seeds": [reference.canonical_value]}
    parsed = urlsplit(reference.canonical_value)
    if parsed.scheme in {"http", "https"} and parsed.hostname:
        scope["domains"] = [parsed.hostname.lower()]
        scope["urls"] = [reference.canonical_value]
    return scope
