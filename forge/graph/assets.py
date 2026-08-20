from __future__ import annotations

import ipaddress
import json
import re
import sqlite3
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit, urlunsplit

from forge.secrets.lifecycle import secret_lifecycle_for_finding, sync_secret_lifecycle
from forge.standards.vulnerabilities import vulnerability_standards_metadata
from forge.utils.artifact_url_sanitizer import strip_sensitive_url_query

_FORBIDDEN_METADATA_KEYS = {
    "api_key",
    "apikey",
    "authorization",
    "credential",
    "hash_plaintext",
    "key_enc",
    "key_raw",
    "password",
    "password_enc",
    "password_hash",
    "password_plaintext_enc",
    "refresh_token",
    "secret",
    "token",
}
_FORBIDDEN_KEY_FRAGMENTS = ("authorization", "password", "secret", "token")
_SAFE_ENTITY_TYPES = {
    "asset",
    "seed",
    "host",
    "service",
    "identity",
    "cloud",
    "evidence",
    "secret",
    "finding",
    "validation",
    "remediation",
    "ticket",
    "owner",
    "organization",
    "other",
}
_SAFE_RELATIONSHIP_TYPES = {
    "derived_from",
    "corroborates",
    "conflicts_with",
    "same_entity",
    "related_asset",
    "runs_service",
    "has_identity",
    "references_cloud",
    "supported_by",
    "validated_by",
    "has_finding",
    "remediates",
    "tracked_by",
    "owned_by",
    "routed_to",
    "observed_in",
    "other",
}
_SAFE_OWNER_KINDS = {
    "team",
    "person",
    "email",
    "workspace",
    "organization",
    "third_party",
    "cloud_account",
    "service",
    "unknown",
}
_SAFE_CLAIM_TYPES = {"explicit", "inferred", "route", "scope", "cloud_account", "manual"}
_SAFE_CLAIM_STATUSES = {"active", "needs_review", "rejected", "superseded"}
_CLOUD_PROVIDER_ALIASES = {
    "aws": "aws",
    "aws_s3": "aws",
    "s3": "aws",
    "azure": "azure",
    "azure_blob": "azure",
    "azure_blob_storage": "azure",
    "firebase": "gcp",
    "gcs": "gcp",
    "google_cloud_storage": "gcp",
    "supabase": "supabase",
    "cloudflare_r2": "cloudflare",
    "r2": "cloudflare",
}
_CLOUD_ACCOUNT_KEYS = (
    "account_id",
    "account",
    "aws_account_id",
    "owner_account",
    "cloud_account_id",
    "subscription_id",
    "subscription",
    "project_id",
    "project",
)
_CLOUD_ORG_KEYS = (
    "organization_id",
    "organization",
    "org_id",
    "tenant_id",
    "tenant",
    "folder_id",
    "management_group_id",
)
_CLOUD_REGION_KEYS = ("region", "location", "zone")
_SENSITIVE_CLASSIFICATIONS = {
    "confidential",
    "critical",
    "high",
    "internal",
    "pii",
    "phi",
    "restricted",
    "sensitive",
}
_VALIDATED_SECRET_STATES = {"ACTIVE", "VALID", "VALIDATED", "LIVE"}
_PUBLIC_INTERNET_ENTITY_KEY = "asset:internet:public"
_PUBLIC_OBSERVATION_SOURCES = {
    "censys",
    "crtsh",
    "dnsdumpster",
    "httpx",
    "projectdiscovery",
    "shodan",
    "urlscan",
}
_WORKLOAD_CONTEXT_KEYS = {
    "app",
    "application",
    "compute",
    "container",
    "k8s",
    "kubernetes",
    "runtime",
    "runtime_context",
    "service_context",
    "workload",
    "workload_context",
}
_CLOUD_IDENTITY_CONTEXT_KEYS = {
    "identity",
    "identity_context",
    "iam",
    "iam_context",
    "principal",
    "principal_context",
    "service_account",
    "service_account_context",
    "managed_identity",
    "managed_identity_context",
}
_CLOUD_IDENTITY_LIST_KEYS = {
    "identities",
    "iam_principals",
    "principals",
    "service_accounts",
    "managed_identities",
    "role_assignments",
    "iam_bindings",
    "bindings",
    "policy_bindings",
}
_CLOUD_IDENTITY_BINDING_LIST_KEYS = {
    "iam_bindings",
    "bindings",
    "policy_bindings",
}
_CLOUD_IDENTITY_REF_KEYS = (
    "principal_arn",
    "principal_id",
    "principal",
    "identity_arn",
    "identity_id",
    "iam_role_arn",
    "role_arn",
    "role_id",
    "role_name",
    "assumed_role_arn",
    "service_account",
    "service_account_email",
    "managed_identity",
    "managed_identity_client_id",
    "client_id",
)
_CLOUD_IDENTITY_KIND_KEYS = ("identity_kind", "principal_type", "identity_type", "type", "kind")
_CLOUD_IDENTITY_NAME_KEYS = (
    "name",
    "principal_name",
    "role_name",
    "user_name",
    "service_account",
    "service_account_email",
    "display_name",
    "client_id",
)
_CLOUD_IDENTITY_PRIVILEGE_KEYS = (
    "privilege",
    "access_level",
    "permission_level",
    "effective_permission",
    "policy_effect",
    "risk",
)
_CLOUD_IDENTITY_ACTION_KEYS = {
    "action",
    "actions",
    "allowed_action",
    "allowed_actions",
    "permission",
    "permissions",
    "policy_action",
    "policy_actions",
    "iam_action",
    "iam_actions",
}
_CLOUD_IDENTITY_RESOURCE_KEYS = {
    "resource",
    "resources",
    "resource_arn",
    "resource_arns",
    "not_resource",
    "not_resources",
    "target_resource",
    "target_resources",
}
_CLOUD_IDENTITY_POLICY_REF_KEYS = {
    "policy",
    "policies",
    "policy_arn",
    "policy_arns",
    "policy_name",
    "policy_names",
    "managed_policy",
    "managed_policies",
    "managed_policy_arn",
    "managed_policy_arns",
    "role",
    "roles",
    "role_definition_name",
    "role_definition_names",
    "inline_policy",
    "inline_policies",
}
_CLOUD_IDENTITY_EFFECT_KEYS = {"effect", "effects"}
_CLOUD_IDENTITY_WRITE_ACTION_MARKERS = (
    ":add",
    ":attach",
    ":assume",
    ":create",
    ":delete",
    ":detach",
    ":modify",
    ":passrole",
    ":put",
    ":set",
    ":update",
    ":write",
    "admin",
    "editor",
    "owner",
    "roles/editor",
    "roles/owner",
)
_CLOUD_IDENTITY_DATA_ACTION_MARKERS = (
    ":decrypt",
    ":getobject",
    ":getsecretvalue",
    ":listbucket",
    ":read",
    "kms.decrypt",
    "secretsmanager",
    "storage.objects.get",
)
_WORKLOAD_NAME_KEYS = (
    "workload_name",
    "workload_id",
    "application_name",
    "app_name",
    "service_name",
    "function_name",
    "lambda_function_name",
    "container_name",
    "pod_name",
    "deployment_name",
    "name",
)
_WORKLOAD_RUNTIME_KEYS = (
    "runtime_kind",
    "runtime_type",
    "compute_platform",
    "orchestrator",
    "platform",
    "kind",
    "type",
)
_WORKLOAD_CLUSTER_KEYS = ("cluster", "cluster_name", "kubernetes_cluster", "eks_cluster", "aks_cluster")
_WORKLOAD_NAMESPACE_KEYS = ("namespace", "kubernetes_namespace", "k8s_namespace")
_WORKLOAD_ENVIRONMENT_KEYS = ("environment", "env", "stage")
_WORKLOAD_RESOURCE_GROUP_KEYS = ("resource_group", "resourcegroup", "resource_group_name")
_WORKLOAD_SERVICE_RUNTIME = {
    "app": "azure_app_service",
    "appservice": "azure_app_service",
    "cloudfunctions": "gcp_cloud_functions",
    "cloudrun": "gcp_cloud_run",
    "ecs": "aws_ecs",
    "eks": "kubernetes",
    "function": "serverless_function",
    "functions": "serverless_function",
    "lambda": "aws_lambda",
    "microsoft.web": "azure_app_service",
    "run": "gcp_cloud_run",
}
_SECRET_CLOUD_PROVIDER_MARKERS = (
    ("aws", ("aws", "amazon", "s3", "iam access key")),
    ("azure", ("azure", "microsoft.storage", "storage connection string")),
    ("gcp", ("gcp", "google", "firebase", "gcs", "google_cloud")),
    ("cloudflare", ("cloudflare", "r2")),
    ("supabase", ("supabase",)),
)
_AWS_ACCOUNT_ASSET_TYPES = {"aws", "aws_account", "aws_sts", "sts"}
_AWS_STS_VALIDATION_METHODS = {"aws_sts_get_caller_identity"}
_AWS_ACCOUNT_ID_RE = re.compile(r"(?<!\d)(\d{12})(?!\d)")


def _ensure_rows(con: sqlite3.Connection) -> None:
    if con.row_factory is None:
        con.row_factory = sqlite3.Row


def _table_exists(con: sqlite3.Connection, table_name: str) -> bool:
    row = con.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (table_name,),
    ).fetchone()
    return row is not None


def _json_loads(value: object) -> Any:
    if isinstance(value, (dict, list)):
        return value
    text = str(value or "").strip()
    if not text:
        return {}
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {}


def _scrub_metadata(value: Any) -> Any:
    if isinstance(value, Mapping):
        scrubbed: dict[str, Any] = {}
        for raw_key, raw_value in value.items():
            key = str(raw_key)
            lowered = key.lower()
            if lowered in _FORBIDDEN_METADATA_KEYS:
                continue
            if any(fragment in lowered for fragment in _FORBIDDEN_KEY_FRAGMENTS):
                if lowered != "key_redacted":
                    continue
            scrubbed[key] = _scrub_metadata(raw_value)
        return scrubbed
    if isinstance(value, list):
        return [_scrub_metadata(item) for item in value]
    if isinstance(value, tuple):
        return [_scrub_metadata(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _metadata_json(metadata: Mapping[str, Any] | None) -> str:
    return json.dumps(_scrub_metadata(dict(metadata or {})), sort_keys=True)


def _safe_url_reference(value: object, *, limit: int = 240) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    sanitized = strip_sensitive_url_query(text)
    parsed = urlsplit(sanitized)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        host = parsed.hostname or parsed.netloc.rsplit("@", 1)[-1]
        netloc = host
        try:
            port = parsed.port
        except ValueError:
            port = None
        if port:
            netloc = f"{netloc}:{port}"
        sanitized = urlunsplit((parsed.scheme, netloc, parsed.path or "", parsed.query, ""))
    return sanitized[:limit]


def _confidence(value: object, default: float = 0.5) -> float:
    try:
        score = float(value)
    except (TypeError, ValueError):
        score = default
    return max(0.0, min(1.0, score))


def _evidence_preview(value: object, *, limit: int = 500) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list, tuple)):
        text = json.dumps(_scrub_metadata(value), sort_keys=True)
    else:
        text = str(value)
    text = text.strip()
    if not text:
        return ""
    replacements = (
        (
            re.compile(
                r"(?is)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----"
            ),
            "[REDACTED_PRIVATE_KEY]",
        ),
        (
            re.compile(
                r"(?i)\b(authorization|bearer|api[_-]?key|access[_-]?key|secret|token|password)"
                r"\b\s*[:=]?\s*['\"]?[^'\"\s&,;]+"
            ),
            r"\1=[REDACTED]",
        ),
        (re.compile(r"\bA[SK]IA[0-9A-Z]{12,20}\b"), "[REDACTED_AWS_KEY]"),
        (re.compile(r"(?i)\bgh[pousr]_[A-Za-z0-9_]{20,}\b"), "[REDACTED_GITHUB_TOKEN]"),
    )
    for pattern, replacement in replacements:
        text = pattern.sub(replacement, text)
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) <= limit:
        return text
    return f"{text[: max(0, limit - 3)]}..."


def _safe_slug(value: object) -> str:
    text = str(value or "").strip().lower()
    text = re.sub(r"\s+", " ", text)
    return text[:240]


def _row_value(row: sqlite3.Row | Mapping[str, Any], key: str, default: Any = None) -> Any:
    if isinstance(row, sqlite3.Row):
        return row[key] if key in row.keys() else default
    return row.get(key, default)


def _first_present_text(mapping: Mapping[str, Any], keys: Iterable[str]) -> str:
    lowered = {str(key).lower(): value for key, value in mapping.items()}
    for key in keys:
        value = lowered.get(key.lower())
        text = str(value or "").strip()
        if text:
            return text
    return ""


def _first_scalar_text(mapping: Mapping[str, Any], keys: Iterable[str]) -> str:
    lowered = {str(key).lower(): value for key, value in mapping.items()}
    for key in keys:
        value = lowered.get(key.lower())
        if isinstance(value, (Mapping, list, tuple, set)):
            continue
        text = str(value or "").strip()
        if text:
            return text
    return ""


def _cloud_provider(asset_type: object, provider_identifier: object = "") -> str:
    normalized = _safe_slug(asset_type).replace("-", "_")
    if normalized in _CLOUD_PROVIDER_ALIASES:
        return _CLOUD_PROVIDER_ALIASES[normalized]
    provider_text = str(provider_identifier or "").strip().lower()
    if provider_text.startswith("arn:aws:"):
        return "aws"
    if provider_text.startswith("/subscriptions/") or "/providers/microsoft." in provider_text:
        return "azure"
    if "googleapis.com" in provider_text:
        return "gcp"
    return normalized.split("_", 1)[0] or "cloud"


def _cloud_resource_kind(asset_type: object, provider_identifier: object = "") -> str:
    text = f"{asset_type or ''} {provider_identifier or ''}".lower()
    normalized_asset_type = _safe_slug(asset_type).replace("-", "_")
    if normalized_asset_type in _AWS_ACCOUNT_ASSET_TYPES:
        return "account"
    if any(marker in text for marker in ("bucket", "storage", "s3", "blob", "gcs")):
        return "storage"
    if any(marker in text for marker in ("identity", "iam", "principal", "role", "user")):
        return "identity"
    if any(marker in text for marker in ("function", "lambda", "appservice", "workload", "compute")):
        return "workload"
    return "resource"


def _stable_aws_account_ref(value: object) -> str:
    for candidate in _AWS_ACCOUNT_ID_RE.findall(str(value or "")):
        if candidate == "000000000000":
            continue
        return candidate
    return ""


def _aws_account_ref_from_validation(
    *,
    asset_type: object,
    identifier: object,
    provider_identifier: object,
    validation_method: object = "",
    evidence: object = "",
) -> str:
    normalized_asset_type = _safe_slug(asset_type).replace("-", "_")
    method = str(validation_method or "").strip().lower()
    if (
        normalized_asset_type not in _AWS_ACCOUNT_ASSET_TYPES
        and method not in _AWS_STS_VALIDATION_METHODS
    ):
        return ""
    if _cloud_provider(asset_type, provider_identifier) != "aws":
        return ""
    for value in (identifier, provider_identifier, evidence):
        account_ref = _stable_aws_account_ref(value)
        if account_ref:
            return account_ref
    return ""


def _arn_context(provider_identifier: object) -> dict[str, str]:
    text = str(provider_identifier or "").strip()
    if not text.lower().startswith("arn:aws:"):
        return {}
    parts = text.split(":", 5)
    if len(parts) < 6:
        return {}
    context = {"provider": "aws", "service": parts[2], "resource": parts[5]}
    if parts[3]:
        context["region"] = parts[3]
    if parts[4]:
        context["account_ref"] = parts[4]
    return context


def _azure_resource_context(provider_identifier: object) -> dict[str, str]:
    text = str(provider_identifier or "").strip()
    if not text.startswith("/"):
        return {}
    parts = [part for part in text.split("/") if part]
    lowered = [part.lower() for part in parts]
    context: dict[str, str] = {"provider": "azure"}
    for marker, field in (("subscriptions", "account_ref"), ("resourcegroups", "resource_group")):
        if marker in lowered:
            index = lowered.index(marker)
            if index + 1 < len(parts):
                context[field] = parts[index + 1]
    if "providers" in lowered:
        index = lowered.index("providers")
        if index + 1 < len(parts):
            context["service"] = parts[index + 1]
    return context


def _boolish(value: object) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "y", "public", "enabled"}


def _global_ip(value: object) -> bool:
    text = str(value or "").strip()
    if not text:
        return False
    try:
        return ipaddress.ip_address(text).is_global
    except ValueError:
        return False


def _public_observation_sources(metadata: Mapping[str, Any]) -> list[str]:
    raw_sources = metadata.get("provider_sources") or metadata.get("sources") or metadata.get("source")
    if isinstance(raw_sources, str):
        values: Iterable[object] = re.split(r"[,;\s]+", raw_sources)
    elif isinstance(raw_sources, Iterable):
        values = raw_sources
    else:
        values = ()
    sources = sorted(
        {
            str(source or "").strip().lower()
            for source in values
            if str(source or "").strip()
        }
    )
    return [source for source in sources if source in _PUBLIC_OBSERVATION_SOURCES]


def _internet_entrypoint_entity(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    source_table: str,
    source_id: int,
) -> int:
    return upsert_asset_entity(
        con,
        engagement_id=engagement_id,
        entity_key=_PUBLIC_INTERNET_ENTITY_KEY,
        entity_type="asset",
        label="Public Internet",
        source_table=source_table,
        source_id=source_id,
        confidence=0.95,
        metadata={
            "asset_role": "internet_entrypoint",
            "entrypoint_type": "public_internet",
            "source": "passive_graph_projection",
        },
    )


def _link_internet_entrypoint(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    target_entity_id: int,
    source_table: str,
    source_id: int,
    confidence: float,
    evidence: Mapping[str, Any],
) -> int:
    internet_entity = _internet_entrypoint_entity(
        con,
        engagement_id=engagement_id,
        source_table=source_table,
        source_id=source_id,
    )
    return upsert_asset_relationship(
        con,
        engagement_id=engagement_id,
        source_entity_id=internet_entity,
        target_entity_id=target_entity_id,
        relationship_type="related_asset",
        confidence=confidence,
        source_table=source_table,
        source_id=source_id,
        evidence={"entrypoint": "public_internet", **dict(evidence)},
    )


def _host_internet_exposure(row: sqlite3.Row, metadata: Mapping[str, Any]) -> dict[str, Any]:
    sources = _public_observation_sources(metadata)
    public_ip = _global_ip(row["ip"])
    explicit = any(
        _boolish(metadata.get(key))
        for key in ("internet_exposed", "public", "public_ip", "exposed")
    )
    if not (sources or public_ip or explicit):
        return {}
    return {
        "source": "hosts",
        "ip": row["ip"],
        "hostname": row["hostname"],
        "public_ip": public_ip,
        "public_observation_sources": sources,
        "explicit_public_signal": explicit,
    }


def _workload_source_metadata(metadata: Mapping[str, Any]) -> dict[str, Any]:
    combined: dict[str, Any] = {}
    for raw_key, raw_value in metadata.items():
        key = str(raw_key)
        if isinstance(raw_value, Mapping):
            if key.lower() in _WORKLOAD_CONTEXT_KEYS:
                combined.update(raw_value)
            continue
        combined[key] = raw_value
    return combined


def _runtime_from_cloud_service(service: object) -> str:
    normalized = str(service or "").strip().lower()
    if not normalized:
        return ""
    for marker, runtime in _WORKLOAD_SERVICE_RUNTIME.items():
        if marker in normalized:
            return runtime
    return ""


def _workload_context(
    *,
    metadata: Mapping[str, Any],
    cloud_context: Mapping[str, Any] | None = None,
    default_name: object = "",
) -> dict[str, Any]:
    source_metadata = metadata or {}
    cloud = cloud_context or {}
    combined = _workload_source_metadata(source_metadata)
    explicit_context = any(
        isinstance(source_metadata.get(key), Mapping)
        for key in _WORKLOAD_CONTEXT_KEYS
    )
    name = _first_scalar_text(combined, _WORKLOAD_NAME_KEYS)
    if not name and cloud.get("resource_kind") == "workload":
        name = str(default_name or cloud.get("identifier") or "").strip()
    if not name:
        return {}

    provider = (
        _first_scalar_text(combined, ("provider", "cloud_provider"))
        or str(cloud.get("provider") or "").strip()
    )
    account_ref = (
        _first_scalar_text(combined, _CLOUD_ACCOUNT_KEYS)
        or str(cloud.get("account_ref") or "").strip()
    )
    org_ref = (
        _first_scalar_text(combined, _CLOUD_ORG_KEYS)
        or str(cloud.get("org_ref") or "").strip()
    )
    region = (
        _first_scalar_text(combined, _CLOUD_REGION_KEYS)
        or str(cloud.get("region") or "").strip()
    )
    runtime_kind = (
        _first_scalar_text(combined, _WORKLOAD_RUNTIME_KEYS)
        or _runtime_from_cloud_service(cloud.get("service"))
    )
    cluster = _first_scalar_text(combined, _WORKLOAD_CLUSTER_KEYS)
    namespace = _first_scalar_text(combined, _WORKLOAD_NAMESPACE_KEYS)
    environment = _first_scalar_text(combined, _WORKLOAD_ENVIRONMENT_KEYS)
    resource_group = (
        _first_scalar_text(combined, _WORKLOAD_RESOURCE_GROUP_KEYS)
        or str(cloud.get("resource_group") or "").strip()
    )
    if not runtime_kind and (cluster or namespace):
        runtime_kind = "kubernetes"
    if not runtime_kind and _first_scalar_text(combined, ("container_name",)):
        runtime_kind = "container"

    has_workload_signal = bool(
        explicit_context
        or runtime_kind
        or cluster
        or namespace
        or cloud.get("resource_kind") == "workload"
    )
    if not has_workload_signal:
        return {}

    context: dict[str, Any] = {
        "name": name,
        "source": "passive_graph_projection",
    }
    if provider:
        context["provider"] = provider
    if account_ref:
        context["account_ref"] = account_ref
        context["account_key"] = f"{provider or 'cloud'}:{account_ref}"
    if org_ref:
        context["org_ref"] = org_ref
    if region:
        context["region"] = region
    if runtime_kind:
        context["runtime_kind"] = runtime_kind
    if cluster:
        context["cluster"] = cluster
    if namespace:
        context["namespace"] = namespace
    if environment:
        context["environment"] = environment
    if resource_group:
        context["resource_group"] = resource_group
    if cloud.get("internet_exposed") is True:
        context["internet_exposed"] = True
    for key in ("container_name", "pod_name", "deployment_name", "task_definition"):
        value = _first_scalar_text(combined, (key,))
        if value:
            context[key] = value
    return context


def _workload_entity_key(context: Mapping[str, Any]) -> str:
    provider = _safe_slug(context.get("provider") or context.get("runtime_kind") or "local")
    scope = _safe_slug(
        context.get("account_ref")
        or context.get("cluster")
        or context.get("environment")
        or "local"
    )
    namespace = _safe_slug(context.get("namespace"))
    name = _safe_slug(context.get("name"))
    parts = ["workload", provider, scope]
    if namespace:
        parts.append(namespace)
    parts.append(name)
    return ":".join(parts)


def _cloud_identity_source_contexts(metadata: Mapping[str, Any]) -> list[dict[str, Any]]:
    contexts: list[dict[str, Any]] = []
    top_level: dict[str, Any] = {}
    identity_keys = (
        set(_CLOUD_IDENTITY_REF_KEYS)
        | set(_CLOUD_IDENTITY_KIND_KEYS)
        | set(_CLOUD_IDENTITY_NAME_KEYS)
        | set(_CLOUD_IDENTITY_PRIVILEGE_KEYS)
        | _CLOUD_IDENTITY_ACTION_KEYS
        | _CLOUD_IDENTITY_RESOURCE_KEYS
        | _CLOUD_IDENTITY_POLICY_REF_KEYS
        | _CLOUD_IDENTITY_EFFECT_KEYS
    )
    for raw_key, raw_value in metadata.items():
        key = str(raw_key).strip().lower()
        if isinstance(raw_value, Mapping):
            if key in _CLOUD_IDENTITY_CONTEXT_KEYS:
                contexts.append(dict(raw_value))
            continue
        if isinstance(raw_value, list):
            if key in _CLOUD_IDENTITY_LIST_KEYS:
                for item in raw_value[:20]:
                    if isinstance(item, Mapping):
                        if key in _CLOUD_IDENTITY_BINDING_LIST_KEYS:
                            contexts.extend(_identity_contexts_from_binding(item))
                        else:
                            contexts.append(dict(item))
                    elif str(item or "").strip():
                        contexts.append({"principal": str(item).strip()})
            continue
        if key in identity_keys:
            top_level[str(raw_key)] = raw_value
    if top_level:
        contexts.insert(0, top_level)
    return contexts


def _identity_kind_from_ref(ref: str, explicit: str = "") -> str:
    normalized = str(explicit or "").strip().lower()
    if normalized:
        compact = normalized.replace("_", "").replace("-", "").replace(" ", "")
        if compact in {"managedidentity", "userassignedmanagedidentity", "systemassignedmanagedidentity"}:
            return "managed_identity"
        if compact in {"serviceaccount", "gcpserviceaccount"}:
            return "service_account"
        return normalized
    text = str(ref or "").strip().lower()
    if not text:
        return "cloud_principal"
    if text.endswith(".iam.gserviceaccount.com"):
        return "service_account"
    if ":role/" in text or text.startswith("role/") or text.startswith("awsreserved/sso"):
        return "iam_role"
    if ":user/" in text or text.startswith("user/"):
        return "iam_user"
    if "managedidentity" in text or "managedidentity" in text.replace("-", ""):
        return "managed_identity"
    if "serviceaccount" in text.replace("_", "").replace("-", ""):
        return "service_account"
    return "cloud_principal"


def _gcp_service_account_project(ref: str) -> str:
    match = re.search(r"@([a-z0-9][a-z0-9-]{2,})\.iam\.gserviceaccount\.com$", ref.strip().lower())
    return match.group(1) if match else ""


def _normalize_identity_member_ref(value: object) -> tuple[str, str]:
    text = str(value or "").strip()
    if not text:
        return "", ""
    lowered = text.lower()
    for prefix, kind in (
        ("serviceaccount:", "service_account"),
        ("user:", "user"),
        ("group:", "group"),
        ("domain:", "domain"),
        ("principal://", "workload_identity"),
        ("principalset://", "workload_identity"),
    ):
        if lowered.startswith(prefix):
            if prefix.endswith("://"):
                return text, kind
            return text.split(":", 1)[1].strip(), kind
    return text, ""


def _privilege_from_role_text(*values: object) -> str:
    text = " ".join(str(value or "").strip().lower() for value in values if str(value or "").strip())
    if not text:
        return ""
    if any(marker in text for marker in ("administrator", "admin", "owner", "contributor", "roles/editor", "roles/owner")):
        return "admin"
    if any(marker in text for marker in ("write", "writer", "storage.objectadmin", "storage.admin", "secretmanager.secretaccessor")):
        return "read_write"
    if any(marker in text for marker in ("reader", "read", "viewer", "storage.objectviewer")):
        return "read"
    return ""


def _identity_contexts_from_binding(binding: Mapping[str, Any]) -> list[dict[str, Any]]:
    role = _first_scalar_text(binding, ("role", "roles", "role_definition_name", "roleDefinitionName"))
    members = _collect_permission_values(
        binding,
        {"member", "members", "principal", "principals", "principal_id", "principalid"},
    )
    if not members:
        members = _collect_permission_values(binding, set(_CLOUD_IDENTITY_REF_KEYS))
    contexts: list[dict[str, Any]] = []
    for member in members[:20]:
        principal_ref, member_kind = _normalize_identity_member_ref(member)
        if not principal_ref:
            continue
        context = dict(binding)
        context["principal"] = principal_ref
        if member_kind:
            context["principal_type"] = member_kind
        if role:
            context["policy"] = role
            context.setdefault("privilege", _privilege_from_role_text(role))
        contexts.append(context)
    return contexts


def _cloud_identity_permission_summary(raw_context: Mapping[str, Any]) -> dict[str, Any]:
    actions = _collect_permission_values(raw_context, _CLOUD_IDENTITY_ACTION_KEYS)
    resources = _collect_permission_values(raw_context, _CLOUD_IDENTITY_RESOURCE_KEYS)
    policy_refs = _collect_permission_values(raw_context, _CLOUD_IDENTITY_POLICY_REF_KEYS)
    effects = sorted(
        {
            str(item).strip().lower()
            for item in _collect_permission_values(raw_context, _CLOUD_IDENTITY_EFFECT_KEYS)
            if str(item).strip()
        }
    )
    wildcard_actions = [
        action
        for action in actions
        if action == "*" or action.endswith(":*") or action.startswith("*:")
    ]
    wildcard_resources = [
        resource
        for resource in resources
        if resource == "*" or "*" in resource
    ]
    write_actions = [
        action
        for action in actions
        if action in wildcard_actions
        or any(marker in action.lower() for marker in _CLOUD_IDENTITY_WRITE_ACTION_MARKERS)
    ]
    data_actions = [
        action
        for action in actions
        if action in wildcard_actions
        or any(marker in action.lower() for marker in _CLOUD_IDENTITY_DATA_ACTION_MARKERS)
    ]
    if not any((actions, resources, policy_refs, effects)):
        return {}
    return {
        "action_count": len(actions),
        "resource_count": len(resources),
        "policy_count": len(policy_refs),
        "actions": actions[:20],
        "resources": resources[:20],
        "policies": policy_refs[:20],
        "effects": effects[:10],
        "wildcard_action": bool(wildcard_actions),
        "wildcard_resource": bool(wildcard_resources),
        "write_action_count": len(write_actions),
        "sensitive_data_action_count": len(data_actions),
    }


def _collect_permission_values(value: Any, key_names: set[str], *, limit: int = 80) -> list[str]:
    values: list[str] = []
    seen: set[str] = set()

    def collect_scalar(raw: Any) -> None:
        if len(values) >= limit:
            return
        if isinstance(raw, Mapping):
            for child in raw.values():
                collect_scalar(child)
            return
        if isinstance(raw, (list, tuple, set)):
            for child in raw:
                collect_scalar(child)
            return
        text = str(raw or "").strip()
        if not text:
            return
        text = re.sub(r"\s+", " ", text)[:240]
        if text not in seen:
            seen.add(text)
            values.append(text)

    def walk(raw: Any) -> None:
        if len(values) >= limit:
            return
        if isinstance(raw, Mapping):
            for key, child in raw.items():
                lowered = str(key).strip().lower().replace("-", "_")
                if lowered in key_names:
                    collect_scalar(child)
                else:
                    walk(child)
            return
        if isinstance(raw, (list, tuple, set)):
            for child in raw:
                walk(child)

    walk(value)
    return values


def _cloud_identity_contexts(
    *,
    metadata: Mapping[str, Any],
    cloud_context: Mapping[str, Any],
) -> list[dict[str, Any]]:
    identities: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for raw_context in _cloud_identity_source_contexts(metadata):
        provider = (
            _first_scalar_text(raw_context, ("provider", "cloud_provider"))
            or str(cloud_context.get("provider") or "").strip()
        )
        principal_ref = _first_scalar_text(raw_context, _CLOUD_IDENTITY_REF_KEYS)
        principal_name = _first_scalar_text(raw_context, _CLOUD_IDENTITY_NAME_KEYS)
        if not principal_ref and principal_name:
            principal_ref = principal_name
        if not principal_ref:
            continue
        arn = _arn_context(principal_ref)
        azure = _azure_resource_context(principal_ref)
        if arn.get("provider"):
            provider = arn["provider"]
        elif azure.get("provider"):
            provider = azure["provider"]
        elif principal_ref.lower().endswith(".iam.gserviceaccount.com"):
            provider = "gcp"

        account_ref = (
            _first_scalar_text(raw_context, _CLOUD_ACCOUNT_KEYS)
            or arn.get("account_ref", "")
            or azure.get("account_ref", "")
            or _gcp_service_account_project(principal_ref)
            or str(cloud_context.get("account_ref") or "").strip()
        )
        org_ref = _first_scalar_text(raw_context, _CLOUD_ORG_KEYS) or str(
            cloud_context.get("org_ref") or ""
        ).strip()
        region = _first_scalar_text(raw_context, _CLOUD_REGION_KEYS) or str(
            cloud_context.get("region") or ""
        ).strip()
        identity_kind = _identity_kind_from_ref(
            principal_ref,
            _first_scalar_text(raw_context, _CLOUD_IDENTITY_KIND_KEYS),
        )
        privilege = _first_scalar_text(raw_context, _CLOUD_IDENTITY_PRIVILEGE_KEYS)
        permission_summary = _cloud_identity_permission_summary(raw_context)
        if not privilege and permission_summary:
            privilege = _privilege_from_role_text(
                permission_summary.get("policies", []),
                permission_summary.get("actions", []),
            )
        key = (
            str(provider or "cloud").strip().lower(),
            identity_kind,
            str(principal_ref).strip().lower(),
        )
        if key in seen:
            continue
        seen.add(key)
        context: dict[str, Any] = {
            "provider": provider or "cloud",
            "identity_kind": identity_kind,
            "principal_ref": str(principal_ref).strip(),
            "source": "passive_graph_projection",
        }
        if principal_name and principal_name != principal_ref:
            context["principal_name"] = principal_name
        if account_ref:
            context["account_ref"] = account_ref
            context["account_key"] = f"{context['provider']}:{account_ref}"
        if org_ref:
            context["org_ref"] = org_ref
        if region:
            context["region"] = region
        if privilege:
            context["privilege"] = privilege
        if permission_summary:
            context["permission_summary"] = permission_summary
        identities.append(context)
    return identities


def _cloud_identity_entity_key(context: Mapping[str, Any]) -> str:
    provider = _safe_slug(context.get("provider") or "cloud")
    identity_kind = _safe_slug(context.get("identity_kind") or "cloud_principal")
    principal_ref = _safe_slug(context.get("principal_ref") or context.get("principal_name"))
    return f"identity:cloud_principal:{provider}:{identity_kind}:{principal_ref}"


def _upsert_cloud_identities(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    cloud_entity_id: int,
    cloud_context: Mapping[str, Any],
    metadata: Mapping[str, Any],
    source_table: str,
    source_id: int,
) -> int:
    count = 0
    provider = str(cloud_context.get("provider") or "cloud").strip().lower()
    account_ref = str(cloud_context.get("account_ref") or "").strip()
    account_entity_id = (
        _fetch_entity_id_by_key(
            con,
            engagement_id,
            f"organization:cloud_account:{provider}:{_safe_slug(account_ref)}",
        )
        if account_ref
        else None
    )
    for identity_context in _cloud_identity_contexts(
        metadata=metadata,
        cloud_context=cloud_context,
    ):
        principal_ref = str(identity_context.get("principal_ref") or "").strip()
        if not principal_ref:
            continue
        identity_kind = str(identity_context.get("identity_kind") or "cloud_principal").strip()
        label = str(identity_context.get("principal_name") or principal_ref).strip()
        identity_entity = upsert_asset_entity(
            con,
            engagement_id=engagement_id,
            entity_key=_cloud_identity_entity_key(identity_context),
            entity_type="identity",
            label=label,
            source_table=source_table,
            source_id=source_id,
            confidence=0.76,
            metadata={
                "identity_context": identity_context,
                "cloud_context": {
                    key: cloud_context.get(key)
                    for key in ("provider", "account_ref", "org_ref", "region", "resource_kind")
                    if cloud_context.get(key)
                },
            },
        )
        upsert_asset_relationship(
            con,
            engagement_id=engagement_id,
            source_entity_id=cloud_entity_id,
            target_entity_id=identity_entity,
            relationship_type="has_identity",
            confidence=0.72,
            source_table=source_table,
            source_id=source_id,
            evidence={
                "match": "cloud_resource_identity_context",
                "provider": identity_context.get("provider"),
                "identity_kind": identity_kind,
                "principal_ref": principal_ref,
            },
        )
        upsert_asset_relationship(
            con,
            engagement_id=engagement_id,
            source_entity_id=identity_entity,
            target_entity_id=cloud_entity_id,
            relationship_type="references_cloud",
            confidence=0.74,
            source_table=source_table,
            source_id=source_id,
            evidence={
                "match": "cloud_identity_to_cloud_resource",
                "provider": identity_context.get("provider"),
                "identity_kind": identity_kind,
                "principal_ref": principal_ref,
            },
        )
        identity_account_ref = str(identity_context.get("account_ref") or account_ref).strip()
        identity_provider = str(identity_context.get("provider") or provider or "cloud").strip().lower()
        target_account_entity_id = account_entity_id
        if identity_account_ref and (
            target_account_entity_id is None or identity_provider != provider
        ):
            target_account_entity_id = _fetch_entity_id_by_key(
                con,
                engagement_id,
                f"organization:cloud_account:{identity_provider}:{_safe_slug(identity_account_ref)}",
            )
        if target_account_entity_id is not None:
            upsert_asset_relationship(
                con,
                engagement_id=engagement_id,
                source_entity_id=identity_entity,
                target_entity_id=target_account_entity_id,
                relationship_type="references_cloud",
                confidence=0.7,
                source_table=source_table,
                source_id=source_id,
                evidence={
                    "match": "cloud_identity_to_cloud_account",
                    "provider": identity_provider,
                    "account_ref": identity_account_ref,
                    "identity_kind": identity_kind,
                },
            )
        count += 1
    return count


def _upsert_workload_context(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    source_entity_id: int,
    context: Mapping[str, Any],
    source_table: str,
    source_id: int,
    relationship_type: str,
    match: str,
    confidence: float = 0.72,
) -> int:
    name = str(context.get("name") or "").strip()
    if not name:
        return 0
    runtime_kind = str(context.get("runtime_kind") or "").strip()
    label = f"{runtime_kind}:{name}" if runtime_kind else name
    workload_entity = upsert_asset_entity(
        con,
        engagement_id=engagement_id,
        entity_key=_workload_entity_key(context),
        entity_type="asset",
        label=label,
        source_table=source_table,
        source_id=source_id,
        confidence=confidence,
        metadata={
            "asset_role": "workload",
            "source": "passive_graph_projection",
            "workload_context": context,
        },
    )
    upsert_asset_relationship(
        con,
        engagement_id=engagement_id,
        source_entity_id=source_entity_id,
        target_entity_id=workload_entity,
        relationship_type=relationship_type,
        confidence=confidence,
        source_table=source_table,
        source_id=source_id,
        evidence={
            "match": match,
            "workload_name": name,
            "runtime_kind": runtime_kind,
            "provider": context.get("provider"),
            "account_ref": context.get("account_ref"),
            "cluster": context.get("cluster"),
            "namespace": context.get("namespace"),
        },
    )
    count = 1
    if context.get("account_ref"):
        count += _upsert_cloud_context(
            con,
            engagement_id=engagement_id,
            cloud_entity_id=workload_entity,
            context=context,
            source_table=source_table,
            source_id=source_id,
        )
    return count


def _cloud_data_sensitivity(
    *,
    asset_type: object,
    metadata: Mapping[str, Any],
    validation_status: object = "",
    validation_method: object = "",
    evidence: object = "",
) -> dict[str, Any]:
    signals: list[str] = []
    tier = ""
    classification = _first_present_text(
        metadata,
        ("data_classification", "classification", "sensitivity", "data_sensitivity"),
    ).lower()
    if classification:
        signals.append(f"classification={classification}")
        tier = "high" if classification in _SENSITIVE_CLASSIFICATIONS else "medium"
    if _boolish(metadata.get("contains_pii")) or _boolish(metadata.get("pii")):
        signals.append("contains_pii=true")
        tier = "high"
    if _cloud_resource_kind(asset_type) == "storage":
        signals.append("resource_kind=storage")
        tier = tier or "medium"
    exposure_text = " ".join(
        str(value or "").lower()
        for value in (validation_status, validation_method, evidence, metadata.get("public_access"))
    )
    if "validated" in exposure_text and any(
        marker in exposure_text for marker in ("public", "listing", "read", "accessible", "200")
    ):
        signals.append("validated_public_access=true")
        tier = "high"
    if _boolish(metadata.get("public_access")):
        signals.append("public_access=true")
        tier = "high"
    if not signals:
        return {}
    return {"tier": tier or "low", "signals": sorted(set(signals))}


def _cloud_context(
    *,
    asset_type: object,
    identifier: object,
    provider_identifier: object = "",
    metadata: Mapping[str, Any] | None = None,
    validation_status: object = "",
    validation_method: object = "",
    evidence: object = "",
) -> dict[str, Any]:
    source_metadata = metadata or {}
    provider = _cloud_provider(asset_type, provider_identifier)
    provider_context = {
        **_arn_context(provider_identifier),
        **_azure_resource_context(provider_identifier),
    }
    account_ref = (
        _first_present_text(source_metadata, _CLOUD_ACCOUNT_KEYS)
        or provider_context.get("account_ref", "")
        or _aws_account_ref_from_validation(
            asset_type=asset_type,
            identifier=identifier,
            provider_identifier=provider_identifier,
            validation_method=validation_method,
            evidence=evidence,
        )
    )
    org_ref = _first_present_text(source_metadata, _CLOUD_ORG_KEYS)
    region = _first_present_text(source_metadata, _CLOUD_REGION_KEYS) or provider_context.get("region", "")
    resource_kind = _cloud_resource_kind(asset_type, provider_identifier)
    context: dict[str, Any] = {
        "provider": provider_context.get("provider", provider),
        "resource_kind": resource_kind,
    }
    if account_ref:
        context["account_ref"] = account_ref
        context["account_key"] = f"{context['provider']}:{account_ref}"
    if org_ref:
        context["org_ref"] = org_ref
        context["org_key"] = f"{context['provider']}:{org_ref}"
    if region:
        context["region"] = region
    if provider_context.get("service"):
        context["service"] = provider_context["service"]
    sensitivity = _cloud_data_sensitivity(
        asset_type=asset_type,
        metadata=source_metadata,
        validation_status=validation_status,
        validation_method=validation_method,
        evidence=evidence,
    )
    if sensitivity:
        context["data_sensitivity"] = sensitivity
    exposure_text = " ".join(
        str(value or "").lower()
        for value in (validation_status, validation_method, evidence, source_metadata.get("public_access"))
    )
    if "validated" in exposure_text and any(
        marker in exposure_text for marker in ("public", "listing", "accessible", "200")
    ):
        context["internet_exposed"] = True
    if _boolish(source_metadata.get("public_access")):
        context["internet_exposed"] = True
    if str(identifier or "").strip():
        context["identifier"] = str(identifier).strip()
    return context


def asset_entity_key(source_table: str, row: sqlite3.Row | Mapping[str, Any]) -> str:
    table = str(source_table or "").strip()
    if table == "engagement_seeds":
        return f"seed:{_safe_slug(_row_value(row, 'seed_type'))}:{_safe_slug(_row_value(row, 'seed_value'))}"
    if table == "hosts":
        hostname = _safe_slug(_row_value(row, "hostname"))
        ip = _safe_slug(_row_value(row, "ip"))
        return f"host:{hostname or ip}"
    if table == "services":
        return (
            f"service:{_safe_slug(_row_value(row, 'host_id'))}:"
            f"{_safe_slug(_row_value(row, 'protocol', 'tcp'))}:"
            f"{_safe_slug(_row_value(row, 'port'))}"
        )
    if table in {"emails", "credentials"}:
        return f"identity:email:{_safe_slug(_row_value(row, 'email'))}"
    if table == "cloud_assets":
        return f"cloud:{_safe_slug(_row_value(row, 'asset_type'))}:{_safe_slug(_row_value(row, 'identifier'))}"
    if table == "cloud_validation_results":
        return (
            f"validation:cloud:{_safe_slug(_row_value(row, 'asset_type'))}:"
            f"{_safe_slug(_row_value(row, 'identifier'))}"
        )
    if table == "active_validation_runs":
        return f"validation:active_validation:{_row_value(row, 'id')}"
    if table == "key_scanner_findings":
        return f"secret:{_safe_slug(_row_value(row, 'service'))}:{_safe_slug(_row_value(row, 'pattern_name'))}:{_row_value(row, 'id')}"
    if table == "vulnerability_findings":
        return f"finding:vulnerability:{_row_value(row, 'id')}"
    if table == "remediation_items":
        return f"remediation:{_row_value(row, 'id')}"
    if table == "remediation_ticket":
        return f"ticket:{_safe_slug(_row_value(row, 'ticket_system'))}:{_safe_slug(_row_value(row, 'ticket_ref') or _row_value(row, 'ticket_url'))}"
    return f"{_safe_slug(table) or 'other'}:{_safe_slug(_row_value(row, 'id'))}"


def _source_table_id(row: sqlite3.Row | Mapping[str, Any]) -> int | None:
    value = _row_value(row, "id")
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def upsert_asset_entity(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    entity_key: str,
    entity_type: str,
    label: str,
    source_table: str | None = None,
    source_id: int | None = None,
    confidence: float = 0.5,
    metadata: Mapping[str, Any] | None = None,
) -> int:
    _ensure_rows(con)
    safe_type = entity_type if entity_type in _SAFE_ENTITY_TYPES else "other"
    key = str(entity_key or "").strip()
    if not key:
        raise ValueError("entity_key is required")
    display = str(label or key).strip()[:240]
    score = _confidence(confidence)
    con.execute(
        """
        INSERT INTO asset_entities
            (engagement_id, entity_key, entity_type, label, source_table, source_id,
             confidence, metadata_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(engagement_id, entity_key) DO UPDATE SET
            entity_type=excluded.entity_type,
            label=excluded.label,
            source_table=COALESCE(excluded.source_table, asset_entities.source_table),
            source_id=COALESCE(excluded.source_id, asset_entities.source_id),
            confidence=CASE
                WHEN excluded.confidence > asset_entities.confidence THEN excluded.confidence
                ELSE asset_entities.confidence
            END,
            metadata_json=excluded.metadata_json,
            last_seen_at=CURRENT_TIMESTAMP,
            updated_at=CURRENT_TIMESTAMP
        """,
        (
            int(engagement_id),
            key,
            safe_type,
            display,
            source_table,
            source_id,
            score,
            _metadata_json(metadata),
        ),
    )
    row = con.execute(
        "SELECT id FROM asset_entities WHERE engagement_id=? AND entity_key=?",
        (int(engagement_id), key),
    ).fetchone()
    if row is None:
        raise RuntimeError(f"asset entity upsert failed for {key}")
    return int(row["id"])


def upsert_asset_relationship(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    source_entity_id: int,
    target_entity_id: int,
    relationship_type: str,
    confidence: float = 0.5,
    source_table: str = "system",
    source_id: int | None = 0,
    evidence: Mapping[str, Any] | None = None,
) -> int:
    _ensure_rows(con)
    relation = relationship_type if relationship_type in _SAFE_RELATIONSHIP_TYPES else "other"
    con.execute(
        """
        INSERT INTO asset_relationships
            (engagement_id, source_entity_id, target_entity_id, relationship_type,
             confidence, source_table, source_id, evidence_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(
            engagement_id,
            source_entity_id,
            target_entity_id,
            relationship_type,
            source_table,
            source_id
        ) DO UPDATE SET
            confidence=CASE
                WHEN excluded.confidence > asset_relationships.confidence THEN excluded.confidence
                ELSE asset_relationships.confidence
            END,
            evidence_json=excluded.evidence_json,
            updated_at=CURRENT_TIMESTAMP
        """,
        (
            int(engagement_id),
            int(source_entity_id),
            int(target_entity_id),
            relation,
            _confidence(confidence),
            str(source_table or "system"),
            int(source_id or 0),
            _metadata_json(evidence),
        ),
    )
    row = con.execute(
        """
        SELECT id
        FROM asset_relationships
        WHERE engagement_id=?
          AND source_entity_id=?
          AND target_entity_id=?
          AND relationship_type=?
          AND source_table=?
          AND source_id=?
        """,
        (
            int(engagement_id),
            int(source_entity_id),
            int(target_entity_id),
            relation,
            str(source_table or "system"),
            int(source_id or 0),
        ),
    ).fetchone()
    if row is None:
        raise RuntimeError("asset relationship upsert failed")
    return int(row["id"])


def _upsert_evidence_entity(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    source_table: str,
    source_id: int,
    evidence_kind: str,
    label: str,
    preview: object | None = None,
    observed_at: object | None = None,
    confidence: float = 0.7,
    metadata: Mapping[str, Any] | None = None,
) -> int:
    preview_text = _evidence_preview(preview)
    payload: dict[str, Any] = {
        "source_table": source_table,
        "source_id": int(source_id),
        "evidence_kind": evidence_kind,
    }
    if observed_at:
        payload["observed_at"] = str(observed_at)
    if preview_text:
        payload["evidence_preview"] = preview_text
    payload.update(dict(metadata or {}))
    return upsert_asset_entity(
        con,
        engagement_id=engagement_id,
        entity_key=(
            f"evidence:{_safe_slug(source_table)}:{_safe_slug(source_id)}:"
            f"{_safe_slug(evidence_kind)}"
        ),
        entity_type="evidence",
        label=str(label or evidence_kind).strip()[:240],
        source_table=source_table,
        source_id=int(source_id),
        confidence=confidence,
        metadata=payload,
    )


def _link_supported_by(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    entity_id: int,
    evidence_entity_id: int,
    source_table: str,
    source_id: int,
    confidence: float = 0.7,
    evidence: Mapping[str, Any] | None = None,
) -> int:
    return upsert_asset_relationship(
        con,
        engagement_id=engagement_id,
        source_entity_id=entity_id,
        target_entity_id=evidence_entity_id,
        relationship_type="supported_by",
        confidence=confidence,
        source_table=source_table,
        source_id=int(source_id),
        evidence=evidence,
    )


def upsert_ownership_claim(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    entity_id: int,
    owner_ref: str,
    owner_kind: str = "team",
    owner_display: str | None = None,
    claim_type: str = "inferred",
    confidence: float = 0.5,
    source: str = "system",
    status: str = "active",
    evidence: Mapping[str, Any] | None = None,
    created_by: str = "",
) -> int:
    _ensure_rows(con)
    ref = str(owner_ref or "").strip()
    if not ref:
        raise ValueError("owner_ref is required")
    kind = owner_kind if owner_kind in _SAFE_OWNER_KINDS else "unknown"
    claim = claim_type if claim_type in _SAFE_CLAIM_TYPES else "inferred"
    claim_status = status if status in _SAFE_CLAIM_STATUSES else "active"
    display = str(owner_display or ref).strip()[:240]
    con.execute(
        """
        INSERT INTO asset_ownership_claims
            (engagement_id, entity_id, owner_kind, owner_ref, owner_display,
             claim_type, confidence, source, status, evidence_json, created_by)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(engagement_id, entity_id, owner_kind, owner_ref, claim_type, source)
        DO UPDATE SET
            owner_display=excluded.owner_display,
            confidence=CASE
                WHEN excluded.confidence > asset_ownership_claims.confidence THEN excluded.confidence
                ELSE asset_ownership_claims.confidence
            END,
            status=excluded.status,
            evidence_json=excluded.evidence_json,
            created_by=excluded.created_by,
            updated_at=CURRENT_TIMESTAMP
        """,
        (
            int(engagement_id),
            int(entity_id),
            kind,
            ref,
            display,
            claim,
            _confidence(confidence),
            str(source or "system"),
            claim_status,
            _metadata_json(evidence),
            str(created_by or ""),
        ),
    )
    row = con.execute(
        """
        SELECT id
        FROM asset_ownership_claims
        WHERE engagement_id=?
          AND entity_id=?
          AND owner_kind=?
          AND owner_ref=?
          AND claim_type=?
          AND source=?
        """,
        (int(engagement_id), int(entity_id), kind, ref, claim, str(source or "system")),
    ).fetchone()
    if row is None:
        raise RuntimeError("asset ownership claim upsert failed")
    claim_id = int(row["id"])
    owner_entity_id = upsert_asset_entity(
        con,
        engagement_id=engagement_id,
        entity_key=f"owner:{kind}:{_safe_slug(ref)}",
        entity_type="owner",
        label=display,
        source_table="asset_ownership_claims",
        source_id=claim_id,
        confidence=_confidence(confidence),
        metadata={"owner_kind": kind, "owner_ref": ref, "source": source},
    )
    upsert_asset_relationship(
        con,
        engagement_id=engagement_id,
        source_entity_id=entity_id,
        target_entity_id=owner_entity_id,
        relationship_type="owned_by",
        confidence=_confidence(confidence),
        source_table="asset_ownership_claims",
        source_id=claim_id,
        evidence=evidence,
    )
    return claim_id


def _fetch_entity_id_by_key(con: sqlite3.Connection, engagement_id: int, entity_key: str) -> int | None:
    row = con.execute(
        "SELECT id FROM asset_entities WHERE engagement_id=? AND entity_key=?",
        (int(engagement_id), entity_key),
    ).fetchone()
    return int(row["id"]) if row else None


def _upsert_seed_entities(con: sqlite3.Connection, engagement_id: int) -> tuple[int, dict[int, int]]:
    if not _table_exists(con, "engagement_seeds"):
        return 0, {}
    seed_to_entity: dict[int, int] = {}
    rows = con.execute(
        """
        SELECT id, seed_value, seed_type, source, status, depth, confidence,
               parent_seed_id, metadata_json
        FROM engagement_seeds
        WHERE engagement_id=?
        """,
        (int(engagement_id),),
    ).fetchall()
    for row in rows:
        entity_id = upsert_asset_entity(
            con,
            engagement_id=engagement_id,
            entity_key=asset_entity_key("engagement_seeds", row),
            entity_type="seed",
            label=str(row["seed_value"] or ""),
            source_table="engagement_seeds",
            source_id=int(row["id"]),
            confidence=_confidence(row["confidence"], 1.0),
            metadata={
                "seed_type": row["seed_type"],
                "source": row["source"],
                "status": row["status"],
                "depth": row["depth"],
                **(_json_loads(row["metadata_json"]) if isinstance(_json_loads(row["metadata_json"]), dict) else {}),
            },
        )
        seed_to_entity[int(row["id"])] = entity_id
    for row in rows:
        parent_id = row["parent_seed_id"]
        if parent_id is None:
            continue
        source_entity = seed_to_entity.get(int(parent_id))
        target_entity = seed_to_entity.get(int(row["id"]))
        if source_entity and target_entity:
            upsert_asset_relationship(
                con,
                engagement_id=engagement_id,
                source_entity_id=source_entity,
                target_entity_id=target_entity,
                relationship_type="derived_from",
                confidence=_confidence(row["confidence"], 0.5),
                source_table="engagement_seeds",
                source_id=int(row["id"]),
                evidence={"parent_seed_id": int(parent_id), "seed_id": int(row["id"])},
            )
    if _table_exists(con, "seed_relations"):
        relation_rows = con.execute(
            """
            SELECT id, source_seed_id, target_seed_id, relation_type, confidence, evidence_json
            FROM seed_relations
            WHERE engagement_id=?
            """,
            (int(engagement_id),),
        ).fetchall()
        for row in relation_rows:
            source_entity = seed_to_entity.get(int(row["source_seed_id"]))
            target_entity = seed_to_entity.get(int(row["target_seed_id"]))
            if source_entity and target_entity:
                upsert_asset_relationship(
                    con,
                    engagement_id=engagement_id,
                    source_entity_id=source_entity,
                    target_entity_id=target_entity,
                    relationship_type=str(row["relation_type"] or "related_asset"),
                    confidence=_confidence(row["confidence"], 0.5),
                    source_table="seed_relations",
                    source_id=int(row["id"]),
                    evidence=_json_loads(row["evidence_json"]),
                )
    return len(rows), seed_to_entity


def _upsert_hosts_and_services(con: sqlite3.Connection, engagement_id: int) -> int:
    if not _table_exists(con, "hosts"):
        return 0
    count = 0
    host_rows = con.execute(
        """
        SELECT id, ip, hostname, os_family, host_context, in_scope, discovered_at
        FROM hosts
        WHERE engagement_id=?
        """,
        (int(engagement_id),),
    ).fetchall()
    host_to_entity: dict[int, int] = {}
    for row in host_rows:
        label = str(row["hostname"] or row["ip"] or "")
        context_value = _json_loads(row["host_context"])
        host_context = context_value if isinstance(context_value, dict) else {}
        internet_exposure = _host_internet_exposure(row, host_context)
        entity_id = upsert_asset_entity(
            con,
            engagement_id=engagement_id,
            entity_key=asset_entity_key("hosts", row),
            entity_type="host",
            label=label,
            source_table="hosts",
            source_id=int(row["id"]),
            confidence=1.0 if int(row["in_scope"] or 0) else 0.4,
            metadata={
                "ip": row["ip"],
                "hostname": row["hostname"],
                "os_family": row["os_family"],
                "in_scope": int(row["in_scope"] or 0),
                "internet_exposure": internet_exposure,
                **host_context,
            },
        )
        if internet_exposure:
            _link_internet_entrypoint(
                con,
                engagement_id=engagement_id,
                target_entity_id=entity_id,
                source_table="hosts",
                source_id=int(row["id"]),
                confidence=0.82 if internet_exposure["public_observation_sources"] else 0.7,
                evidence=internet_exposure,
            )
        workload_context = _workload_context(metadata=host_context, default_name=label)
        if workload_context:
            if internet_exposure:
                workload_context["internet_exposed"] = True
            count += _upsert_workload_context(
                con,
                engagement_id=engagement_id,
                source_entity_id=entity_id,
                context=workload_context,
                source_table="hosts",
                source_id=int(row["id"]),
                relationship_type="runs_service",
                match="host_to_runtime_workload",
                confidence=0.74,
            )
        host_to_entity[int(row["id"])] = entity_id
        count += 1
    if not _table_exists(con, "services"):
        return count
    service_rows = con.execute(
        """
        SELECT id, host_id, port, protocol, service_name, banner, version, discovered_at
        FROM services
        WHERE host_id IN (SELECT id FROM hosts WHERE engagement_id=?)
        """,
        (int(engagement_id),),
    ).fetchall()
    for row in service_rows:
        host_entity = host_to_entity.get(int(row["host_id"]))
        label = f"{row['service_name'] or row['protocol']}/{row['port']}"
        service_entity = upsert_asset_entity(
            con,
            engagement_id=engagement_id,
            entity_key=asset_entity_key("services", row),
            entity_type="service",
            label=label,
            source_table="services",
            source_id=int(row["id"]),
            confidence=0.8,
            metadata={
                "host_id": row["host_id"],
                "port": row["port"],
                "protocol": row["protocol"],
                "service_name": row["service_name"],
                "version": row["version"],
            },
        )
        if host_entity:
            upsert_asset_relationship(
                con,
                engagement_id=engagement_id,
                source_entity_id=host_entity,
                target_entity_id=service_entity,
                relationship_type="runs_service",
                confidence=0.8,
                source_table="services",
                source_id=int(row["id"]),
                evidence={"port": row["port"], "protocol": row["protocol"]},
            )
        count += 1
    return count


def _upsert_email_identity(con: sqlite3.Connection, engagement_id: int, row: sqlite3.Row, table: str) -> int:
    return upsert_asset_entity(
        con,
        engagement_id=engagement_id,
        entity_key=asset_entity_key(table, row),
        entity_type="identity",
        label=str(row["email"] or ""),
        source_table=table,
        source_id=int(row["id"]),
        confidence=0.75,
        metadata={
            "email": row["email"],
            "domain": _row_value(row, "domain"),
            "source": _row_value(row, "source"),
            "validated": _row_value(row, "validated"),
            "validated_service": _row_value(row, "validated_service"),
        },
    )


def _upsert_identities(con: sqlite3.Connection, engagement_id: int) -> int:
    count = 0
    if _table_exists(con, "emails"):
        for row in con.execute(
            "SELECT id, email, domain, source FROM emails WHERE engagement_id=?",
            (int(engagement_id),),
        ).fetchall():
            _upsert_email_identity(con, engagement_id, row, "emails")
            count += 1
    if _table_exists(con, "credentials"):
        for row in con.execute(
            """
            SELECT id, email, source, validated, validated_service, validated_host
            FROM credentials
            WHERE engagement_id=?
            """,
            (int(engagement_id),),
        ).fetchall():
            _upsert_email_identity(con, engagement_id, row, "credentials")
            count += 1
    return count


def _upsert_cloud_context(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    cloud_entity_id: int,
    context: Mapping[str, Any],
    source_table: str,
    source_id: int,
) -> int:
    provider = str(context.get("provider") or "cloud").strip().lower()
    count = 0
    org_entity_id: int | None = None
    org_ref = str(context.get("org_ref") or "").strip()
    if org_ref:
        org_entity_id = upsert_asset_entity(
            con,
            engagement_id=engagement_id,
            entity_key=f"organization:cloud_org:{provider}:{_safe_slug(org_ref)}",
            entity_type="organization",
            label=f"{provider.upper()} org {org_ref}",
            source_table=source_table,
            source_id=source_id,
            confidence=0.72,
            metadata={
                "cloud_context_kind": "cloud_org",
                "provider": provider,
                "org_ref": org_ref,
                "source_table": source_table,
            },
        )
        upsert_asset_relationship(
            con,
            engagement_id=engagement_id,
            source_entity_id=org_entity_id,
            target_entity_id=cloud_entity_id,
            relationship_type="references_cloud",
            confidence=0.68,
            source_table=source_table,
            source_id=source_id,
            evidence={"provider": provider, "org_ref": org_ref},
        )
        count += 1

    account_ref = str(context.get("account_ref") or "").strip()
    if account_ref:
        account_entity_id = upsert_asset_entity(
            con,
            engagement_id=engagement_id,
            entity_key=f"organization:cloud_account:{provider}:{_safe_slug(account_ref)}",
            entity_type="organization",
            label=f"{provider.upper()} account {account_ref}",
            source_table=source_table,
            source_id=source_id,
            confidence=0.78,
            metadata={
                "cloud_context_kind": "cloud_account",
                "provider": provider,
                "account_ref": account_ref,
                "org_ref": org_ref,
                "region": context.get("region") or "",
                "source_table": source_table,
            },
        )
        upsert_asset_relationship(
            con,
            engagement_id=engagement_id,
            source_entity_id=account_entity_id,
            target_entity_id=cloud_entity_id,
            relationship_type="references_cloud",
            confidence=0.75,
            source_table=source_table,
            source_id=source_id,
            evidence={"provider": provider, "account_ref": account_ref},
        )
        if org_entity_id is not None:
            upsert_asset_relationship(
                con,
                engagement_id=engagement_id,
                source_entity_id=org_entity_id,
                target_entity_id=account_entity_id,
                relationship_type="related_asset",
                confidence=0.65,
                source_table=source_table,
                source_id=source_id,
                evidence={"provider": provider, "org_ref": org_ref, "account_ref": account_ref},
            )
        upsert_ownership_claim(
            con,
            engagement_id=engagement_id,
            entity_id=cloud_entity_id,
            owner_kind="cloud_account",
            owner_ref=f"{provider}:{account_ref}",
            owner_display=f"{provider.upper()} account {account_ref}",
            claim_type="cloud_account",
            confidence=0.74,
            source="cloud_context",
            evidence={
                "provider": provider,
                "account_ref": account_ref,
                "org_ref": org_ref,
                "source_table": source_table,
            },
        )
        count += 1
    return count


def _upsert_cloud(con: sqlite3.Connection, engagement_id: int) -> int:
    count = 0
    if _table_exists(con, "cloud_assets"):
        rows = con.execute(
            """
            SELECT id, asset_type, identifier, provider_identifier, source,
                   metadata_json, discovered_at
            FROM cloud_assets
            WHERE engagement_id=?
            """,
            (int(engagement_id),),
        ).fetchall()
        for row in rows:
            metadata_value = _json_loads(row["metadata_json"])
            stored_metadata = metadata_value if isinstance(metadata_value, dict) else {}
            context = _cloud_context(
                asset_type=row["asset_type"],
                identifier=row["identifier"],
                provider_identifier=row["provider_identifier"],
                metadata=stored_metadata,
            )
            cloud_entity = upsert_asset_entity(
                con,
                engagement_id=engagement_id,
                entity_key=asset_entity_key("cloud_assets", row),
                entity_type="cloud",
                label=f"{row['asset_type']}:{row['identifier']}",
                source_table="cloud_assets",
                source_id=int(row["id"]),
                confidence=0.8,
                metadata={
                    "asset_type": row["asset_type"],
                    "identifier": row["identifier"],
                    "provider_identifier": row["provider_identifier"],
                    "source": row["source"],
                    "cloud_context": context,
                    **stored_metadata,
                },
            )
            count += _upsert_cloud_context(
                con,
                engagement_id=engagement_id,
                cloud_entity_id=cloud_entity,
                context=context,
                source_table="cloud_assets",
                source_id=int(row["id"]),
            )
            count += _upsert_cloud_identities(
                con,
                engagement_id=engagement_id,
                cloud_entity_id=cloud_entity,
                cloud_context=context,
                metadata=stored_metadata,
                source_table="cloud_assets",
                source_id=int(row["id"]),
            )
            if context.get("internet_exposed") is True:
                _link_internet_entrypoint(
                    con,
                    engagement_id=engagement_id,
                    target_entity_id=cloud_entity,
                    source_table="cloud_assets",
                    source_id=int(row["id"]),
                    confidence=0.82,
                    evidence={
                        "provider": context.get("provider"),
                        "account_ref": context.get("account_ref"),
                        "resource_kind": context.get("resource_kind"),
                        "exposure_source": "cloud_asset_metadata",
                    },
                )
            workload_context = _workload_context(
                metadata=stored_metadata,
                cloud_context=context,
                default_name=row["identifier"],
            )
            if workload_context:
                count += _upsert_workload_context(
                    con,
                    engagement_id=engagement_id,
                    source_entity_id=cloud_entity,
                    context=workload_context,
                    source_table="cloud_assets",
                    source_id=int(row["id"]),
                    relationship_type="related_asset",
                    match="cloud_asset_to_runtime_workload",
                    confidence=0.76,
                )
            count += 1
    if _table_exists(con, "cloud_validation_results"):
        rows = con.execute(
            """
            SELECT id, asset_type, identifier, provider_identifier, validation_status,
                   validation_method, http_status, evidence, notes, checked_at
            FROM cloud_validation_results
            WHERE engagement_id=?
            """,
            (int(engagement_id),),
        ).fetchall()
        for row in rows:
            cloud_key = f"cloud:{_safe_slug(row['asset_type'])}:{_safe_slug(row['identifier'])}"
            context = _cloud_context(
                asset_type=row["asset_type"],
                identifier=row["identifier"],
                provider_identifier=row["provider_identifier"],
                metadata={},
                validation_status=row["validation_status"],
                validation_method=row["validation_method"],
                evidence=row["evidence"],
            )
            cloud_entity = _fetch_entity_id_by_key(con, engagement_id, cloud_key)
            if cloud_entity is None:
                cloud_entity = upsert_asset_entity(
                    con,
                    engagement_id=engagement_id,
                    entity_key=cloud_key,
                    entity_type="cloud",
                    label=f"{row['asset_type']}:{row['identifier']}",
                    source_table="cloud_validation_results",
                    source_id=int(row["id"]),
                    confidence=0.7,
                    metadata={
                        "asset_type": row["asset_type"],
                        "identifier": row["identifier"],
                        "provider_identifier": row["provider_identifier"],
                        "cloud_context": context,
                    },
                )
            count += _upsert_cloud_context(
                con,
                engagement_id=engagement_id,
                cloud_entity_id=cloud_entity,
                context=context,
                source_table="cloud_validation_results",
                source_id=int(row["id"]),
            )
            if context.get("internet_exposed") is True:
                _link_internet_entrypoint(
                    con,
                    engagement_id=engagement_id,
                    target_entity_id=cloud_entity,
                    source_table="cloud_validation_results",
                    source_id=int(row["id"]),
                    confidence=0.88 if row["validation_status"] == "VALIDATED" else 0.62,
                    evidence={
                        "provider": context.get("provider"),
                        "account_ref": context.get("account_ref"),
                        "resource_kind": context.get("resource_kind"),
                        "validation_status": row["validation_status"],
                        "validation_method": row["validation_method"],
                        "exposure_source": "cloud_validation",
                    },
                )
            workload_context = _workload_context(
                metadata={},
                cloud_context=context,
                default_name=row["identifier"],
            )
            if workload_context:
                count += _upsert_workload_context(
                    con,
                    engagement_id=engagement_id,
                    source_entity_id=cloud_entity,
                    context=workload_context,
                    source_table="cloud_validation_results",
                    source_id=int(row["id"]),
                    relationship_type="related_asset",
                    match="cloud_validation_to_runtime_workload",
                    confidence=0.7,
                )
            validation_entity = upsert_asset_entity(
                con,
                engagement_id=engagement_id,
                entity_key=asset_entity_key("cloud_validation_results", row),
                entity_type="validation",
                label=f"{row['validation_status']} {row['asset_type']}:{row['identifier']}",
                source_table="cloud_validation_results",
                source_id=int(row["id"]),
                confidence=0.9 if row["validation_status"] == "VALIDATED" else 0.5,
                metadata={
                    "validation_status": row["validation_status"],
                    "validation_method": row["validation_method"],
                    "http_status": row["http_status"],
                    "checked_at": row["checked_at"],
                    "cloud_context": context,
                },
            )
            upsert_asset_relationship(
                con,
                engagement_id=engagement_id,
                source_entity_id=cloud_entity,
                target_entity_id=validation_entity,
                relationship_type="validated_by",
                confidence=0.8,
                source_table="cloud_validation_results",
                source_id=int(row["id"]),
                evidence={"validation_status": row["validation_status"], "checked_at": row["checked_at"]},
            )
            evidence_entity = _upsert_evidence_entity(
                con,
                engagement_id=engagement_id,
                source_table="cloud_validation_results",
                source_id=int(row["id"]),
                evidence_kind="validation",
                label=f"Validation evidence for {row['asset_type']}:{row['identifier']}",
                preview=row["evidence"],
                observed_at=row["checked_at"],
                confidence=0.85 if row["validation_status"] == "VALIDATED" else 0.55,
                metadata={
                    "validation_status": row["validation_status"],
                    "validation_method": row["validation_method"],
                    "http_status": row["http_status"],
                    "notes_preview": _evidence_preview(row["notes"], limit=300),
                },
            )
            _link_supported_by(
                con,
                engagement_id=engagement_id,
                entity_id=validation_entity,
                evidence_entity_id=evidence_entity,
                source_table="cloud_validation_results",
                source_id=int(row["id"]),
                confidence=0.85 if row["validation_status"] == "VALIDATED" else 0.55,
                evidence={"validation_method": row["validation_method"], "checked_at": row["checked_at"]},
            )
            count += 1
    return count


def _secret_cloud_provider(row: sqlite3.Row | Mapping[str, Any]) -> str:
    text = " ".join(
        str(_row_value(row, key) or "").lower()
        for key in ("service", "pattern_name", "validation_detail")
    )
    for provider, markers in _SECRET_CLOUD_PROVIDER_MARKERS:
        if any(marker in text for marker in markers):
            return provider
    return ""


def _cloud_context_for_node(row: sqlite3.Row) -> dict[str, Any]:
    metadata = _json_loads(row["metadata_json"])
    if not isinstance(metadata, dict):
        return {}
    context = metadata.get("cloud_context")
    return context if isinstance(context, dict) else {}


def _link_secret_to_cloud_context(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    secret_entity_id: int,
    row: sqlite3.Row,
) -> int:
    if str(row["validation_state"] or "").strip().upper() not in _VALIDATED_SECRET_STATES:
        return 0
    provider = _secret_cloud_provider(row)
    if not provider:
        return 0

    linked = 0
    account_rows = con.execute(
        """
        SELECT id, entity_key, label, metadata_json
        FROM asset_entities
        WHERE engagement_id=?
          AND entity_type='organization'
          AND entity_key LIKE ?
        """,
        (int(engagement_id), f"organization:cloud_account:{provider}:%"),
    ).fetchall()
    account_refs: set[str] = set()
    for account in account_rows:
        metadata = _json_loads(account["metadata_json"])
        account_ref = str(
            metadata.get("account_ref") if isinstance(metadata, dict) else ""
        ).strip()
        if account_ref:
            account_refs.add(account_ref)
        upsert_asset_relationship(
            con,
            engagement_id=engagement_id,
            source_entity_id=secret_entity_id,
            target_entity_id=int(account["id"]),
            relationship_type="references_cloud",
            confidence=0.68,
            source_table="key_scanner_findings",
            source_id=int(row["id"]),
            evidence={
                "provider": provider,
                "secret_finding_id": int(row["id"]),
                "match": "validated_secret_provider_to_cloud_account",
            },
        )
        linked += 1

    cloud_rows = con.execute(
        """
        SELECT id, entity_key, label, metadata_json
        FROM asset_entities
        WHERE engagement_id=?
          AND entity_type='cloud'
        """,
        (int(engagement_id),),
    ).fetchall()
    for cloud in cloud_rows:
        context = _cloud_context_for_node(cloud)
        if str(context.get("provider") or "").strip().lower() != provider:
            continue
        account_ref = str(context.get("account_ref") or "").strip()
        account_match = bool(account_ref and account_ref in account_refs)
        upsert_asset_relationship(
            con,
            engagement_id=engagement_id,
            source_entity_id=secret_entity_id,
            target_entity_id=int(cloud["id"]),
            relationship_type="references_cloud",
            confidence=0.66 if account_match else 0.55,
            source_table="key_scanner_findings",
            source_id=int(row["id"]),
            evidence={
                "provider": provider,
                "secret_finding_id": int(row["id"]),
                "account_ref": account_ref,
                "match": "validated_secret_to_cloud_resource"
                if account_match
                else "validated_secret_provider_to_cloud_resource",
            },
        )
        linked += 1
    return linked


def _upsert_secret_findings(con: sqlite3.Connection, engagement_id: int) -> int:
    if not _table_exists(con, "key_scanner_findings"):
        return 0
    sync_secret_lifecycle(con, int(engagement_id))
    count = 0
    rows = con.execute(
        """
        SELECT id, domain, service, pattern_name, source_backend, source_url,
               repo_name, key_redacted, validation_state, validation_detail,
               found_at, validated_at
        FROM key_scanner_findings
        WHERE engagement_id=?
        """,
        (int(engagement_id),),
    ).fetchall()
    for row in rows:
        lifecycle = secret_lifecycle_for_finding(con, int(engagement_id), int(row["id"]))
        secret_entity = upsert_asset_entity(
            con,
            engagement_id=engagement_id,
            entity_key=asset_entity_key("key_scanner_findings", row),
            entity_type="secret",
            label=f"{row['service']} {row['pattern_name']}",
            source_table="key_scanner_findings",
            source_id=int(row["id"]),
            confidence=0.9 if row["validation_state"] == "ACTIVE" else 0.5,
            metadata={
                "domain": row["domain"],
                "service": row["service"],
                "pattern_name": row["pattern_name"],
                "source_backend": row["source_backend"],
                "source_url": row["source_url"],
                "repo_name": row["repo_name"],
                "key_redacted": row["key_redacted"],
                "validation_state": row["validation_state"],
                "validated_at": row["validated_at"],
                "lifecycle": lifecycle,
            },
        )
        owner = str(lifecycle.get("owner") or "").strip()
        if owner:
            upsert_ownership_claim(
                con,
                engagement_id=engagement_id,
                entity_id=secret_entity,
                owner_ref=owner,
                owner_kind="email" if "@" in owner else "team",
                owner_display=owner,
                claim_type="route",
                confidence=0.85,
                source=str(lifecycle.get("owner_source") or "secret_lifecycle"),
                evidence={"key_finding_id": int(row["id"]), "lifecycle_status": lifecycle.get("lifecycle_status")},
            )
        domain = _safe_slug(row["domain"])
        if domain:
            domain_entity = upsert_asset_entity(
                con,
                engagement_id=engagement_id,
                entity_key=f"asset:domain:{domain}",
                entity_type="asset",
                label=domain,
                source_table="key_scanner_findings",
                source_id=int(row["id"]),
                confidence=0.5,
                metadata={"source": "key_scanner_findings", "domain": domain},
            )
            upsert_asset_relationship(
                con,
                engagement_id=engagement_id,
                source_entity_id=domain_entity,
                target_entity_id=secret_entity,
                relationship_type="has_finding",
                confidence=0.7,
                source_table="key_scanner_findings",
                source_id=int(row["id"]),
                evidence={"validation_state": row["validation_state"]},
            )
        evidence_entity = _upsert_evidence_entity(
            con,
            engagement_id=engagement_id,
            source_table="key_scanner_findings",
            source_id=int(row["id"]),
            evidence_kind="secret_observation",
            label=f"Secret evidence for {row['service']} {row['pattern_name']}",
            observed_at=row["validated_at"] or row["found_at"],
            confidence=0.85 if row["validation_state"] == "ACTIVE" else 0.55,
            metadata={
                "source_backend": row["source_backend"],
                "source_url": row["source_url"],
                "repo_name": row["repo_name"],
                "key_redacted": row["key_redacted"],
                "validation_state": row["validation_state"],
            },
        )
        _link_supported_by(
            con,
            engagement_id=engagement_id,
            entity_id=secret_entity,
            evidence_entity_id=evidence_entity,
            source_table="key_scanner_findings",
            source_id=int(row["id"]),
            confidence=0.85 if row["validation_state"] == "ACTIVE" else 0.55,
            evidence={"source_backend": row["source_backend"], "validation_state": row["validation_state"]},
        )
        _link_secret_to_cloud_context(
            con,
            engagement_id=engagement_id,
            secret_entity_id=secret_entity,
            row=row,
        )
        count += 1
    return count


def _upsert_vulnerability_findings(con: sqlite3.Connection, engagement_id: int) -> int:
    if not _table_exists(con, "vulnerability_findings"):
        return 0
    count = 0
    rows = con.execute(
        """
        SELECT id, vuln_type, target_url, parameter, severity, title, description,
               evidence, cve_id, cvss_score, cvss_version, cvss_vector,
               cwe_ids, cpe_matches, epss_score, epss_percentile, cisa_kev,
               cisa_kev_due_date, attack_techniques, stix_external_refs_json,
               standards_json, found_at
        FROM vulnerability_findings
        WHERE engagement_id=?
        """,
        (int(engagement_id),),
    ).fetchall()
    for row in rows:
        standards = vulnerability_standards_metadata(row)
        finding_entity = upsert_asset_entity(
            con,
            engagement_id=engagement_id,
            entity_key=asset_entity_key("vulnerability_findings", row),
            entity_type="finding",
            label=str(row["title"] or row["vuln_type"] or f"Finding {row['id']}"),
            source_table="vulnerability_findings",
            source_id=int(row["id"]),
            confidence=0.8,
            metadata={
                "vuln_type": row["vuln_type"],
                "target_url": row["target_url"],
                "parameter": row["parameter"],
                "severity": row["severity"],
                "cvss_score": row["cvss_score"],
                "standards": standards,
                "found_at": row["found_at"],
            },
        )
        target = str(row["target_url"] or "").strip()
        if target:
            asset_entity = upsert_asset_entity(
                con,
                engagement_id=engagement_id,
                entity_key=f"asset:url:{_safe_slug(target)}",
                entity_type="asset",
                label=target,
                source_table="vulnerability_findings",
                source_id=int(row["id"]),
                confidence=0.7,
                metadata={"target_url": target},
            )
            upsert_asset_relationship(
                con,
                engagement_id=engagement_id,
                source_entity_id=asset_entity,
                target_entity_id=finding_entity,
                relationship_type="has_finding",
                confidence=0.8,
                source_table="vulnerability_findings",
                source_id=int(row["id"]),
                evidence={"severity": row["severity"], "vuln_type": row["vuln_type"]},
            )
        evidence_entity = _upsert_evidence_entity(
            con,
            engagement_id=engagement_id,
            source_table="vulnerability_findings",
            source_id=int(row["id"]),
            evidence_kind="finding_evidence",
            label=f"Finding evidence for {row['title'] or row['vuln_type'] or row['id']}",
            preview=row["evidence"],
            observed_at=row["found_at"],
            confidence=0.8,
            metadata={
                "severity": row["severity"],
                "vuln_type": row["vuln_type"],
                "cvss_score": row["cvss_score"],
                "standards": standards,
            },
        )
        _link_supported_by(
            con,
            engagement_id=engagement_id,
            entity_id=finding_entity,
            evidence_entity_id=evidence_entity,
            source_table="vulnerability_findings",
            source_id=int(row["id"]),
            confidence=0.8,
            evidence={"severity": row["severity"], "vuln_type": row["vuln_type"]},
        )
        count += 1
    return count


def _finding_entity_for_remediation(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    row: sqlite3.Row,
) -> int | None:
    table = str(row["finding_table"] or "").strip()
    finding_id = row["finding_id"]
    finding_ref = str(row["finding_ref"] or "").strip()
    if table == "asset_graph" and finding_ref:
        existing = _fetch_entity_id_by_key(con, engagement_id, finding_ref)
        if existing is not None:
            return existing
        key = f"finding:asset_graph:{_safe_slug(finding_ref)}"
    elif table == "vulnerability_findings" and finding_id is not None:
        key = f"finding:vulnerability:{int(finding_id)}"
    elif table:
        key = f"finding:{_safe_slug(table)}:{_safe_slug(finding_ref or finding_id or row['id'])}"
    else:
        return None
    existing = _fetch_entity_id_by_key(con, engagement_id, key)
    if existing is not None:
        return existing
    return upsert_asset_entity(
        con,
        engagement_id=engagement_id,
        entity_key=key,
        entity_type="finding",
        label=str(row["title"] or finding_ref or table),
        source_table=table or "remediation_items",
        source_id=int(finding_id or row["id"]),
        confidence=0.5,
        metadata={"finding_table": table, "finding_ref": finding_ref},
    )


def _upsert_remediation(con: sqlite3.Connection, engagement_id: int) -> int:
    if not _table_exists(con, "remediation_items"):
        return 0
    count = 0
    rows = con.execute(
        """
        SELECT id, finding_table, finding_id, finding_ref, title, severity, owner,
               sla_due_at, status, retest_status, ticket_system, ticket_ref,
               ticket_url, risk_acceptance_expires_at, metadata_json, created_at, updated_at
        FROM remediation_items
        WHERE engagement_id=?
        """,
        (int(engagement_id),),
    ).fetchall()
    for row in rows:
        row_metadata = _json_loads(row["metadata_json"])
        if not isinstance(row_metadata, dict):
            row_metadata = {}
        safe_ticket_url = _safe_url_reference(row["ticket_url"])
        remediation_entity = upsert_asset_entity(
            con,
            engagement_id=engagement_id,
            entity_key=asset_entity_key("remediation_items", row),
            entity_type="remediation",
            label=str(row["title"] or f"Remediation {row['id']}"),
            source_table="remediation_items",
            source_id=int(row["id"]),
            confidence=0.8,
            metadata={
                **row_metadata,
                "finding_table": row["finding_table"],
                "finding_ref": row["finding_ref"],
                "severity": row["severity"],
                "status": row["status"],
                "sla_due_at": row["sla_due_at"],
                "risk_acceptance_expires_at": row["risk_acceptance_expires_at"],
                "retest_status": row["retest_status"],
                "ticket_system": row["ticket_system"],
                "ticket_ref": row["ticket_ref"],
                "ticket_url": safe_ticket_url,
            },
        )
        finding_entity = _finding_entity_for_remediation(con, engagement_id=engagement_id, row=row)
        if finding_entity is not None:
            upsert_asset_relationship(
                con,
                engagement_id=engagement_id,
                source_entity_id=remediation_entity,
                target_entity_id=finding_entity,
                relationship_type="remediates",
                confidence=0.8,
                source_table="remediation_items",
                source_id=int(row["id"]),
                evidence={"status": row["status"], "retest_status": row["retest_status"]},
            )
        evidence_entity = _upsert_evidence_entity(
            con,
            engagement_id=engagement_id,
            source_table="remediation_items",
            source_id=int(row["id"]),
            evidence_kind="workflow_state",
            label=f"Remediation evidence for {row['title'] or row['id']}",
            observed_at=row["updated_at"] or row["created_at"],
            confidence=0.75,
            metadata={
                "status": row["status"],
                "retest_status": row["retest_status"],
                "sla_due_at": row["sla_due_at"],
                "risk_acceptance_expires_at": row["risk_acceptance_expires_at"],
                "ticket_system": row["ticket_system"],
                "ticket_ref": row["ticket_ref"],
            },
        )
        _link_supported_by(
            con,
            engagement_id=engagement_id,
            entity_id=remediation_entity,
            evidence_entity_id=evidence_entity,
            source_table="remediation_items",
            source_id=int(row["id"]),
            confidence=0.75,
            evidence={"status": row["status"], "retest_status": row["retest_status"]},
        )
        owner = str(row["owner"] or "").strip()
        if owner:
            upsert_ownership_claim(
                con,
                engagement_id=engagement_id,
                entity_id=remediation_entity,
                owner_ref=owner,
                owner_kind="email" if "@" in owner else "team",
                owner_display=owner,
                claim_type="inferred",
                confidence=0.75,
                source="remediation_items",
                evidence={"remediation_item_id": int(row["id"]), "field": "owner"},
            )
            if finding_entity is not None:
                upsert_ownership_claim(
                    con,
                    engagement_id=engagement_id,
                    entity_id=finding_entity,
                    owner_ref=owner,
                    owner_kind="email" if "@" in owner else "team",
                    owner_display=owner,
                    claim_type="inferred",
                    confidence=0.65,
                    source="remediation_items",
                    evidence={"remediation_item_id": int(row["id"]), "field": "owner"},
                )
        ticket_ref = str(row["ticket_ref"] or "").strip()
        ticket_url = str(row["ticket_url"] or "").strip()
        ticket_system = str(row["ticket_system"] or "").strip()
        if ticket_system and (ticket_ref or ticket_url):
            ticket_entity = upsert_asset_entity(
                con,
                engagement_id=engagement_id,
                entity_key=asset_entity_key("remediation_ticket", row),
                entity_type="ticket",
                label=ticket_ref or safe_ticket_url,
                source_table="remediation_items",
                source_id=int(row["id"]),
                confidence=0.9,
                metadata={
                    "ticket_system": ticket_system,
                    "ticket_ref": ticket_ref,
                    "ticket_url": safe_ticket_url,
                },
            )
            upsert_asset_relationship(
                con,
                engagement_id=engagement_id,
                source_entity_id=remediation_entity,
                target_entity_id=ticket_entity,
                relationship_type="tracked_by",
                confidence=0.9,
                source_table="remediation_items",
                source_id=int(row["id"]),
                evidence={"ticket_system": ticket_system},
            )
        count += 1
    return count


def _active_validation_confidence(status: object, result: object) -> float:
    normalized_status = str(status or "").strip().lower()
    normalized_result = str(result or "").strip().lower()
    if normalized_status == "completed" and normalized_result in {
        "control_passed",
        "headers_strong",
        "not_reachable",
        "reachable",
        "simulated_pass",
    }:
        return 0.82
    if normalized_status == "completed":
        return 0.68
    if normalized_status == "blocked":
        return 0.45
    if normalized_status == "failed":
        return 0.5
    return 0.55


def _active_validation_target_entity_keys(
    row: sqlite3.Row,
    job_metadata: Mapping[str, Any],
) -> list[str]:
    keys: list[str] = []

    def append(value: str) -> None:
        if value and value not in keys:
            keys.append(value)

    remediation_item_id = job_metadata.get("remediation_item_id")
    try:
        if remediation_item_id not in (None, ""):
            append(f"remediation:{int(remediation_item_id)}")
    except (TypeError, ValueError):
        pass

    finding_table = str(job_metadata.get("remediation_finding_table") or "").strip()
    finding_ref = str(job_metadata.get("remediation_finding_ref") or "").strip()
    if finding_table == "vulnerability_findings" and finding_ref:
        append(f"finding:vulnerability:{finding_ref}")

    target_ref = str(row["target_ref"] or "").strip()
    target_kind = str(row["target_kind"] or "").strip().lower()
    if not target_ref:
        return keys
    if target_ref.startswith(
        (
            "asset:",
            "cloud:",
            "finding:",
            "host:",
            "identity:",
            "remediation:",
            "secret:",
            "seed:",
            "service:",
            "validation:",
        )
    ):
        append(target_ref)
    if target_kind == "host":
        host_ref = target_ref.removeprefix("host:").strip()
        if host_ref:
            append(f"host:{_safe_slug(host_ref)}")
    if target_kind == "service" and target_ref.startswith("service:"):
        append(target_ref)
    parsed = urlsplit(target_ref)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        safe_url = _safe_url_reference(target_ref)
        append(f"asset:url:{_safe_slug(safe_url)}")
        append(f"seed:url:{_safe_slug(safe_url)}")
        host = str(parsed.hostname or "").strip().lower().rstrip(".")
        if host:
            append(f"host:{_safe_slug(host)}")
    return keys


def _upsert_active_validation_runs(con: sqlite3.Connection, engagement_id: int) -> int:
    if not (
        _table_exists(con, "active_validation_jobs")
        and _table_exists(con, "active_validation_runs")
    ):
        return 0
    rows = con.execute(
        """
        SELECT r.id, r.engagement_id, r.job_id, r.status, r.result,
               r.operator, r.evidence_json, r.error, r.started_at,
               r.completed_at, r.created_at,
               j.target_ref, j.target_kind, j.method, j.mode, j.safe_profile,
               j.metadata_json
        FROM active_validation_runs r
        JOIN active_validation_jobs j
          ON j.engagement_id=r.engagement_id AND j.id=r.job_id
        WHERE r.engagement_id=?
        ORDER BY r.id ASC
        """,
        (int(engagement_id),),
    ).fetchall()
    count = 0
    for row in rows:
        evidence_payload = _json_loads(row["evidence_json"])
        evidence = evidence_payload if isinstance(evidence_payload, dict) else {}
        job_metadata_payload = _json_loads(row["metadata_json"])
        job_metadata = job_metadata_payload if isinstance(job_metadata_payload, dict) else {}
        proof_summary = evidence.get("proof_summary")
        if not isinstance(proof_summary, dict):
            proof_summary = {}
        confidence = _active_validation_confidence(row["status"], row["result"])
        safe_target = _safe_url_reference(row["target_ref"])
        metadata = {
            "validation_status": row["status"],
            "validation_method": row["method"],
            "validation_result": row["result"],
            "mode": row["mode"],
            "target_kind": row["target_kind"],
            "target_ref": safe_target,
            "job_id": int(row["job_id"]),
            "proof_kind": (
                evidence.get("method", {}).get("proof_kind")
                if isinstance(evidence.get("method"), dict)
                else ""
            ),
            "proof_summary": proof_summary,
            "network_execution": bool(evidence.get("network_execution")),
            "destructive_actions": bool(evidence.get("destructive_actions")),
            "lateral_movement": bool(evidence.get("lateral_movement")),
            "post_exploitation": bool(evidence.get("post_exploitation")),
            "completed_at": row["completed_at"],
        }
        validation_entity = upsert_asset_entity(
            con,
            engagement_id=engagement_id,
            entity_key=asset_entity_key("active_validation_runs", row),
            entity_type="validation",
            label=f"Active validation {row['method']} {row['result'] or row['status']}",
            source_table="active_validation_runs",
            source_id=int(row["id"]),
            confidence=confidence,
            metadata=metadata,
        )
        target_entity_ids: list[int] = []
        for key in _active_validation_target_entity_keys(row, job_metadata):
            entity_id = _fetch_entity_id_by_key(con, engagement_id, key)
            if entity_id is not None and entity_id not in target_entity_ids:
                target_entity_ids.append(entity_id)
        for target_entity_id in target_entity_ids:
            upsert_asset_relationship(
                con,
                engagement_id=engagement_id,
                source_entity_id=target_entity_id,
                target_entity_id=validation_entity,
                relationship_type="validated_by",
                confidence=confidence,
                source_table="active_validation_runs",
                source_id=int(row["id"]),
                evidence={
                    "validation_method": row["method"],
                    "validation_result": row["result"],
                    "mode": row["mode"],
                },
            )
        evidence_preview = (
            proof_summary.get("evidence")
            or proof_summary.get("live_proof")
            or proof_summary.get("fix_match")
            or evidence
        )
        evidence_entity = _upsert_evidence_entity(
            con,
            engagement_id=engagement_id,
            source_table="active_validation_runs",
            source_id=int(row["id"]),
            evidence_kind="active_validation",
            label=f"Active validation evidence for {row['method']} run {row['id']}",
            preview=evidence_preview,
            observed_at=row["completed_at"] or row["created_at"],
            confidence=confidence,
            metadata={
                "validation_status": row["status"],
                "validation_method": row["method"],
                "validation_result": row["result"],
                "mode": row["mode"],
                "proof_summary": proof_summary,
            },
        )
        _link_supported_by(
            con,
            engagement_id=engagement_id,
            entity_id=validation_entity,
            evidence_entity_id=evidence_entity,
            source_table="active_validation_runs",
            source_id=int(row["id"]),
            confidence=confidence,
            evidence={"validation_method": row["method"], "result": row["result"]},
        )
        count += 1
    return count


def _upsert_validation_claim_owners(con: sqlite3.Connection, engagement_id: int) -> int:
    if not _table_exists(con, "validation_claims"):
        return 0
    count = 0
    rows = con.execute(
        """
        SELECT id, claim_type, key_id, asset_type, identifier, owner,
               claimed_at, expires_at, updated_at
        FROM validation_claims
        WHERE engagement_id=?
        """,
        (int(engagement_id),),
    ).fetchall()
    for row in rows:
        entity_id: int | None = None
        if row["claim_type"] == "asset":
            key = f"cloud:{_safe_slug(row['asset_type'])}:{_safe_slug(row['identifier'])}"
            entity_id = _fetch_entity_id_by_key(con, engagement_id, key)
            if entity_id is None:
                entity_id = upsert_asset_entity(
                    con,
                    engagement_id=engagement_id,
                    entity_key=key,
                    entity_type="cloud",
                    label=f"{row['asset_type']}:{row['identifier']}",
                    source_table="validation_claims",
                    source_id=int(row["id"]),
                    confidence=0.6,
                    metadata={"asset_type": row["asset_type"], "identifier": row["identifier"]},
                )
        elif row["claim_type"] == "key" and row["key_id"] is not None:
            key_row = con.execute(
                """
                SELECT id, domain, service, pattern_name, source_backend, source_url,
                       repo_name, key_redacted, validation_state, validation_detail,
                       found_at, validated_at
                FROM key_scanner_findings
                WHERE engagement_id=? AND id=?
                """,
                (int(engagement_id), int(row["key_id"])),
            ).fetchone()
            if key_row is not None:
                lifecycle = secret_lifecycle_for_finding(con, int(engagement_id), int(key_row["id"]))
                entity_id = upsert_asset_entity(
                    con,
                    engagement_id=engagement_id,
                    entity_key=asset_entity_key("key_scanner_findings", key_row),
                    entity_type="secret",
                    label=f"{key_row['service']} {key_row['pattern_name']}",
                    source_table="key_scanner_findings",
                    source_id=int(key_row["id"]),
                    confidence=0.8,
                    metadata={
                        "key_redacted": key_row["key_redacted"],
                        "validation_state": key_row["validation_state"],
                        "lifecycle": lifecycle,
                    },
                )
        if entity_id is not None and str(row["owner"] or "").strip():
            upsert_ownership_claim(
                con,
                engagement_id=engagement_id,
                entity_id=entity_id,
                owner_ref=str(row["owner"]),
                owner_kind="email" if "@" in str(row["owner"]) else "team",
                owner_display=str(row["owner"]),
                claim_type="explicit",
                confidence=0.9,
                source="validation_claims",
                evidence={"validation_claim_id": int(row["id"]), "expires_at": row["expires_at"]},
            )
            count += 1
    return count


def sync_engagement_asset_graph(
    con: sqlite3.Connection,
    engagement_id: int,
) -> dict[str, Any]:
    _ensure_rows(con)
    source_counts: dict[str, int] = {}
    seed_count, _seed_map = _upsert_seed_entities(con, int(engagement_id))
    source_counts["engagement_seeds"] = seed_count
    source_counts["hosts_services"] = _upsert_hosts_and_services(con, int(engagement_id))
    source_counts["identities"] = _upsert_identities(con, int(engagement_id))
    source_counts["cloud"] = _upsert_cloud(con, int(engagement_id))
    source_counts["secrets"] = _upsert_secret_findings(con, int(engagement_id))
    source_counts["vulnerabilities"] = _upsert_vulnerability_findings(con, int(engagement_id))
    source_counts["remediation"] = _upsert_remediation(con, int(engagement_id))
    source_counts["active_validation"] = _upsert_active_validation_runs(con, int(engagement_id))
    source_counts["validation_claims"] = _upsert_validation_claim_owners(con, int(engagement_id))
    con.commit()
    totals = con.execute(
        """
        SELECT
            (SELECT COUNT(*) FROM asset_entities WHERE engagement_id=?) AS nodes,
            (SELECT COUNT(*) FROM asset_relationships WHERE engagement_id=?) AS edges,
            (SELECT COUNT(*) FROM asset_ownership_claims WHERE engagement_id=?) AS ownership_claims
        """,
        (int(engagement_id), int(engagement_id), int(engagement_id)),
    ).fetchone()
    node_count = int(totals["nodes"] or 0)
    return {
        "schema_version": "forge.asset_graph.sync.v1",
        "execution_policy": "writes_canonical_asset_graph_tables",
        "total_count": node_count,
        "selected_count": node_count,
        "omitted_count": 0,
        "engagement_id": int(engagement_id),
        "node_count": node_count,
        "edge_count": int(totals["edges"] or 0),
        "ownership_claim_count": int(totals["ownership_claims"] or 0),
        "source_counts": source_counts,
    }


def _ownership_claim_payload(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": int(row["id"]),
        "entity_id": int(row["entity_id"]),
        "entity_key": row["entity_key"],
        "entity_label": row["entity_label"],
        "entity_type": row["entity_type"],
        "owner_kind": row["owner_kind"],
        "owner_ref": row["owner_ref"],
        "owner_display": row["owner_display"],
        "claim_type": row["claim_type"],
        "confidence": float(row["confidence"]),
        "source": row["source"],
        "status": row["status"],
        "evidence": _json_loads(row["evidence_json"]),
    }


def _entity_reference_rows(
    con: sqlite3.Connection,
    engagement_id: int,
    *,
    entity_key: str | None = None,
    source_table: str | None = None,
    source_id: int | None = None,
) -> list[sqlite3.Row]:
    _ensure_rows(con)
    if not _table_exists(con, "asset_entities"):
        return []
    rows: list[sqlite3.Row] = []
    seen: set[int] = set()
    key = str(entity_key or "").strip()
    if key:
        row = con.execute(
            """
            SELECT id, entity_key, entity_type, label
            FROM asset_entities
            WHERE engagement_id=? AND entity_key=?
            """,
            (int(engagement_id), key),
        ).fetchone()
        if row is not None:
            rows.append(row)
            seen.add(int(row["id"]))
    table = str(source_table or "").strip()
    if table and source_id is not None:
        for row in con.execute(
            """
            SELECT id, entity_key, entity_type, label
            FROM asset_entities
            WHERE engagement_id=? AND source_table=? AND source_id=?
            ORDER BY confidence DESC, updated_at DESC, id DESC
            """,
            (int(engagement_id), table, int(source_id)),
        ).fetchall():
            row_id = int(row["id"])
            if row_id in seen:
                continue
            rows.append(row)
            seen.add(row_id)
    return rows


def ownership_claims_for_entity(
    con: sqlite3.Connection,
    engagement_id: int,
    *,
    entity_key: str | None = None,
    source_table: str | None = None,
    source_id: int | None = None,
    include_inactive: bool = False,
    limit: int = 25,
) -> list[dict[str, Any]]:
    entity_rows = _entity_reference_rows(
        con,
        int(engagement_id),
        entity_key=entity_key,
        source_table=source_table,
        source_id=source_id,
    )
    if not entity_rows or not _table_exists(con, "asset_ownership_claims"):
        return []
    entity_ids = [int(row["id"]) for row in entity_rows]
    placeholders = ",".join("?" for _ in entity_ids)
    status_clause = "" if include_inactive else "AND c.status='active'"
    rows = con.execute(
        f"""
        SELECT c.id,
               c.entity_id,
               e.entity_key,
               e.label AS entity_label,
               e.entity_type,
               c.owner_kind,
               c.owner_ref,
               c.owner_display,
               c.claim_type,
               c.confidence,
               c.source,
               c.status,
               c.evidence_json
        FROM asset_ownership_claims c
        JOIN asset_entities e ON e.id=c.entity_id
        WHERE c.engagement_id=?
          AND c.entity_id IN ({placeholders})
          {status_clause}
        ORDER BY c.confidence DESC, c.updated_at DESC, c.id DESC
        LIMIT ?
        """,
        (int(engagement_id), *entity_ids, max(1, int(limit))),
    ).fetchall()
    return [_ownership_claim_payload(row) for row in rows]


def ownership_conflicts_for_engagement(
    con: sqlite3.Connection,
    engagement_id: int,
    *,
    entity_key: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    _ensure_rows(con)
    if not (_table_exists(con, "asset_entities") and _table_exists(con, "asset_ownership_claims")):
        return []
    key_filter = str(entity_key or "").strip()
    params: list[Any] = [int(engagement_id)]
    where = "WHERE c.engagement_id=? AND c.status='active'"
    if key_filter:
        where += " AND e.entity_key=?"
        params.append(key_filter)
    params.append(max(1, int(limit) * 10))
    rows = con.execute(
        f"""
        SELECT c.id,
               c.entity_id,
               e.entity_key,
               e.label AS entity_label,
               e.entity_type,
               c.owner_kind,
               c.owner_ref,
               c.owner_display,
               c.claim_type,
               c.confidence,
               c.source,
               c.status,
               c.evidence_json
        FROM asset_ownership_claims c
        JOIN asset_entities e ON e.id=c.entity_id
        {where}
        ORDER BY e.entity_key ASC, c.confidence DESC, c.updated_at DESC, c.id DESC
        LIMIT ?
        """,
        tuple(params),
    ).fetchall()
    grouped: dict[int, list[dict[str, Any]]] = {}
    for row in rows:
        claim = _ownership_claim_payload(row)
        grouped.setdefault(int(claim["entity_id"]), []).append(claim)

    conflicts: list[dict[str, Any]] = []
    for claims in grouped.values():
        owners: list[dict[str, Any]] = []
        seen: set[str] = set()
        for claim in claims:
            owner_key = f"{claim['owner_kind']}:{claim['owner_ref']}"
            if owner_key in seen:
                continue
            seen.add(owner_key)
            owners.append(
                {
                    "owner_kind": claim["owner_kind"],
                    "owner_ref": claim["owner_ref"],
                    "owner_display": claim["owner_display"],
                    "confidence": claim["confidence"],
                    "claim_type": claim["claim_type"],
                    "source": claim["source"],
                }
            )
        if len(owners) <= 1:
            continue
        first = claims[0]
        conflicts.append(
            {
                "entity_id": first["entity_id"],
                "entity_key": first["entity_key"],
                "entity_label": first["entity_label"],
                "entity_type": first["entity_type"],
                "owner_count": len(owners),
                "claim_count": len(claims),
                "owners": owners,
                "highest_confidence": max(float(owner["confidence"]) for owner in owners),
            }
        )
    conflicts.sort(key=lambda item: (-float(item["highest_confidence"]), str(item["entity_key"])))
    return conflicts[: max(1, int(limit))]


def resolve_ownership_conflict(
    con: sqlite3.Connection,
    engagement_id: int,
    *,
    entity_key: str | None = None,
    claim_id: int | None = None,
    owner_ref: str = "",
    owner_kind: str = "",
    superseded_status: str = "superseded",
    reason: str = "",
    resolved_by: str = "",
) -> dict[str, Any]:
    _ensure_rows(con)
    if not (_table_exists(con, "asset_entities") and _table_exists(con, "asset_ownership_claims")):
        raise LookupError("asset graph ownership tables are not available")
    if superseded_status not in {"superseded", "rejected"}:
        raise ValueError("superseded_status must be superseded or rejected")

    params: list[Any] = [int(engagement_id)]
    where = "WHERE c.engagement_id=?"
    key = str(entity_key or "").strip()
    if key:
        where += " AND e.entity_key=?"
        params.append(key)
    selected_claim_id = int(claim_id) if claim_id not in (None, 0) else None
    if selected_claim_id is not None:
        where += " AND c.id=?"
        params.append(selected_claim_id)
    elif str(owner_ref or "").strip():
        where += " AND c.owner_ref=?"
        params.append(str(owner_ref or "").strip())
        if str(owner_kind or "").strip():
            where += " AND c.owner_kind=?"
            params.append(str(owner_kind or "").strip())
    else:
        raise ValueError("claim_id or owner_ref is required")

    selected_rows = con.execute(
        f"""
        SELECT c.id,
               c.entity_id,
               e.entity_key,
               e.label AS entity_label,
               e.entity_type,
               c.owner_kind,
               c.owner_ref,
               c.owner_display,
               c.claim_type,
               c.confidence,
               c.source,
               c.status,
               c.evidence_json
        FROM asset_ownership_claims c
        JOIN asset_entities e ON e.id=c.entity_id
        {where}
        ORDER BY c.confidence DESC, c.updated_at DESC, c.id DESC
        """,
        tuple(params),
    ).fetchall()
    if not selected_rows:
        raise LookupError("ownership claim not found")
    selected = _ownership_claim_payload(selected_rows[0])
    entity_id = int(selected["entity_id"])
    selected_owner_key = f"{selected['owner_kind']}:{selected['owner_ref']}"

    all_rows = con.execute(
        """
        SELECT c.id,
               c.entity_id,
               e.entity_key,
               e.label AS entity_label,
               e.entity_type,
               c.owner_kind,
               c.owner_ref,
               c.owner_display,
               c.claim_type,
               c.confidence,
               c.source,
               c.status,
               c.evidence_json
        FROM asset_ownership_claims c
        JOIN asset_entities e ON e.id=c.entity_id
        WHERE c.engagement_id=? AND c.entity_id=?
        ORDER BY c.confidence DESC, c.updated_at DESC, c.id DESC
        """,
        (int(engagement_id), entity_id),
    ).fetchall()
    selected_ids: list[int] = []
    superseded_ids: list[int] = []
    resolved_at_evidence = {
        "resolution": "selected_owner",
        "resolution_reason": str(reason or "").strip(),
        "resolved_by": str(resolved_by or "").strip(),
    }
    for row in all_rows:
        claim = _ownership_claim_payload(row)
        claim_owner_key = f"{claim['owner_kind']}:{claim['owner_ref']}"
        prior_evidence = claim.get("evidence") if isinstance(claim.get("evidence"), dict) else {}
        next_evidence = {**prior_evidence, **resolved_at_evidence}
        if claim_owner_key == selected_owner_key:
            selected_ids.append(int(claim["id"]))
            next_evidence["resolution_status"] = "selected"
            con.execute(
                """
                UPDATE asset_ownership_claims
                SET status='active',
                    evidence_json=?,
                    updated_at=CURRENT_TIMESTAMP
                WHERE engagement_id=? AND id=?
                """,
                (_metadata_json(next_evidence), int(engagement_id), int(claim["id"])),
            )
        elif claim["status"] == "active":
            superseded_ids.append(int(claim["id"]))
            next_evidence["resolution_status"] = superseded_status
            con.execute(
                """
                UPDATE asset_ownership_claims
                SET status=?,
                    evidence_json=?,
                    updated_at=CURRENT_TIMESTAMP
                WHERE engagement_id=? AND id=?
                """,
                (
                    superseded_status,
                    _metadata_json(next_evidence),
                    int(engagement_id),
                    int(claim["id"]),
                ),
            )
    if superseded_ids:
        placeholders = ",".join("?" for _ in superseded_ids)
        con.execute(
            f"""
            DELETE FROM asset_relationships
            WHERE engagement_id=?
              AND relationship_type='owned_by'
              AND source_table='asset_ownership_claims'
              AND source_id IN ({placeholders})
            """,
            (int(engagement_id), *superseded_ids),
        )
    return {
        "engagement_id": int(engagement_id),
        "entity_id": entity_id,
        "entity_key": selected["entity_key"],
        "selected_owner": selected["owner_ref"],
        "selected_owner_kind": selected["owner_kind"],
        "selected_claim_ids": selected_ids,
        "superseded_claim_ids": superseded_ids,
        "superseded_status": superseded_status,
        "owner": resolve_asset_owner(con, int(engagement_id), entity_key=str(selected["entity_key"])),
        "claims": ownership_claims_for_entity(
            con,
            int(engagement_id),
            entity_key=str(selected["entity_key"]),
            include_inactive=True,
            limit=100,
        ),
        "conflicts": ownership_conflicts_for_engagement(
            con,
            int(engagement_id),
            entity_key=str(selected["entity_key"]),
            limit=25,
        ),
    }


def resolve_asset_owner(
    con: sqlite3.Connection,
    engagement_id: int,
    *,
    entity_key: str | None = None,
    source_table: str | None = None,
    source_id: int | None = None,
) -> dict[str, Any]:
    claims = ownership_claims_for_entity(
        con,
        int(engagement_id),
        entity_key=entity_key,
        source_table=source_table,
        source_id=source_id,
        include_inactive=False,
        limit=25,
    )
    owners: list[dict[str, Any]] = []
    seen: set[str] = set()
    for claim in claims:
        owner_key = f"{claim['owner_kind']}:{claim['owner_ref']}"
        if owner_key in seen:
            continue
        seen.add(owner_key)
        owners.append(
            {
                "owner_kind": claim["owner_kind"],
                "owner_ref": claim["owner_ref"],
                "owner_display": claim["owner_display"],
                "confidence": claim["confidence"],
                "claim_type": claim["claim_type"],
                "source": claim["source"],
            }
        )
    if not claims:
        return {
            "owner_ref": "",
            "owner_display": "",
            "owner_kind": "",
            "confidence": 0.0,
            "claim_type": "",
            "source": "",
            "status": "",
            "entity_key": str(entity_key or ""),
            "entity_label": "",
            "conflict": False,
            "claim_count": 0,
            "owners": [],
        }
    selected = claims[0]
    return {
        "owner_ref": selected["owner_ref"],
        "owner_display": selected["owner_display"],
        "owner_kind": selected["owner_kind"],
        "confidence": selected["confidence"],
        "claim_type": selected["claim_type"],
        "source": selected["source"],
        "status": selected["status"],
        "entity_key": selected["entity_key"],
        "entity_label": selected["entity_label"],
        "conflict": len(owners) > 1,
        "claim_count": len(claims),
        "owners": owners,
    }


_SEVERITY_SCORE = {
    "CRITICAL": 90.0,
    "HIGH": 72.0,
    "MEDIUM": 45.0,
    "LOW": 20.0,
    "INFO": 8.0,
    "INFORMATIONAL": 8.0,
}
_ENTRY_ENTITY_TYPES = {"seed", "host", "service", "asset", "cloud", "identity"}
_CRITICAL_ENTITY_TYPES = {"asset", "host", "service", "cloud", "identity", "secret", "finding", "validation"}


def _node_metadata(node: Mapping[str, Any]) -> dict[str, Any]:
    metadata = node.get("metadata")
    return metadata if isinstance(metadata, dict) else {}


def _node_risk_profile(node: Mapping[str, Any]) -> dict[str, Any]:
    entity_type = str(node.get("entity_type") or "").strip().lower()
    metadata = _node_metadata(node)
    tags: list[str] = []
    factors: list[str] = []
    score = _confidence(node.get("confidence"), 0.5) * 10.0

    severity = str(metadata.get("severity") or metadata.get("cvss_severity") or "").strip().upper()
    if severity in _SEVERITY_SCORE:
        score += _SEVERITY_SCORE[severity]
        tags.append(f"{severity.lower()}_severity")
        factors.append(f"severity={severity}")
    standards = metadata.get("standards") if isinstance(metadata.get("standards"), dict) else {}
    cvss = standards.get("cvss") if isinstance(standards.get("cvss"), dict) else {}
    try:
        cvss_score = float(cvss.get("score") or metadata.get("cvss_score") or 0.0)
    except (TypeError, ValueError):
        cvss_score = 0.0
    if cvss_score >= 9.0:
        score += 18.0
        tags.append("cvss_critical")
        factors.append(f"cvss={cvss_score:.1f}")
    elif cvss_score >= 7.0:
        score += 12.0
        tags.append("cvss_high")
        factors.append(f"cvss={cvss_score:.1f}")
    if standards.get("cisa_kev") is True:
        score += 18.0
        tags.append("cisa_kev")
        factors.append("cisa_kev=true")
    epss = standards.get("epss") if isinstance(standards.get("epss"), dict) else {}
    try:
        epss_score = float(epss.get("score") or metadata.get("epss_score") or 0.0)
    except (TypeError, ValueError):
        epss_score = 0.0
    if epss_score >= 0.7:
        score += 10.0
        tags.append("epss_likely")
        factors.append(f"epss={epss_score:.2f}")

    if entity_type == "secret":
        score += 45.0
        tags.append("secret")
        factors.append("entity_type=secret")
        state = str(metadata.get("validation_state") or "").strip().upper()
        if state in {"ACTIVE", "VALID", "VALIDATED", "LIVE"}:
            score += 25.0
            tags.append("validated_secret")
            factors.append(f"validation_state={state}")
        lifecycle = metadata.get("lifecycle") if isinstance(metadata.get("lifecycle"), dict) else {}
        if lifecycle.get("lifecycle_status") in {"owner_routed", "revocation_ready"}:
            score += 8.0
            tags.append("routable_secret")
    elif entity_type == "finding":
        score += 30.0
        tags.append("finding")
        factors.append("entity_type=finding")
    elif entity_type == "cloud":
        score += 20.0
        tags.append("cloud_asset")
        factors.append("entity_type=cloud")
        asset_type = str(metadata.get("asset_type") or "").strip().lower()
        cloud_context = metadata.get("cloud_context") if isinstance(metadata.get("cloud_context"), dict) else {}
        if any(marker in asset_type for marker in ("bucket", "storage", "s3", "blob")):
            score += 10.0
            tags.append("data_asset")
        if cloud_context.get("account_ref"):
            score += 5.0
            tags.append("cloud_account_mapped")
            factors.append("cloud_account_ref=present")
        sensitivity = (
            cloud_context.get("data_sensitivity")
            if isinstance(cloud_context.get("data_sensitivity"), dict)
            else {}
        )
        if sensitivity.get("tier") in {"high", "critical"}:
            score += 15.0
            tags.append("sensitive_data")
            factors.append(f"data_sensitivity={sensitivity.get('tier')}")
        if cloud_context.get("internet_exposed") is True:
            score += 12.0
            tags.append("internet_exposed")
            factors.append("internet_exposed=true")
    elif entity_type == "identity":
        score += 22.0
        tags.append("identity")
        factors.append("entity_type=identity")
        identity_context = (
            metadata.get("identity_context")
            if isinstance(metadata.get("identity_context"), dict)
            else {}
        )
        if identity_context:
            score += 12.0
            tags.append("cloud_identity")
            tags.append("cloud_principal")
            factors.append(
                f"cloud_identity_kind={identity_context.get('identity_kind') or 'cloud_principal'}"
            )
            if identity_context.get("account_ref"):
                score += 8.0
                tags.append("cloud_account_mapped")
                factors.append("identity_cloud_account_ref=present")
            privilege = str(identity_context.get("privilege") or "").strip().lower()
            if any(
                marker in privilege
                for marker in (
                    "admin",
                    "administrator",
                    "owner",
                    "write",
                    "full",
                    "privileged",
                    "high",
                    "wildcard",
                    "*",
                )
            ):
                score += 22.0
                tags.append("privileged_identity")
                factors.append(f"identity_privilege={privilege}")
            permission_summary = (
                identity_context.get("permission_summary")
                if isinstance(identity_context.get("permission_summary"), dict)
                else {}
            )
            if permission_summary:
                score += 8.0
                tags.append("cloud_permission_context")
                factors.append(
                    f"permission_actions={int(permission_summary.get('action_count') or 0)}"
                )
                if permission_summary.get("wildcard_action"):
                    score += 18.0
                    tags.append("wildcard_action")
                    factors.append("wildcard_action=true")
                if permission_summary.get("wildcard_resource"):
                    score += 14.0
                    tags.append("wildcard_resource")
                    factors.append("wildcard_resource=true")
                write_action_count = int(permission_summary.get("write_action_count") or 0)
                if write_action_count:
                    score += 12.0
                    tags.append("write_capable_identity")
                    factors.append(f"write_actions={write_action_count}")
                data_action_count = int(
                    permission_summary.get("sensitive_data_action_count") or 0
                )
                if data_action_count:
                    score += 10.0
                    tags.append("data_access_identity")
                    factors.append(f"sensitive_data_actions={data_action_count}")
    elif entity_type == "validation":
        status_text = str(metadata.get("validation_status") or "").strip().upper()
        if status_text in {"VALIDATED", "EXPOSED", "PUBLIC", "CONFIRMED"}:
            score += 25.0
            tags.append("validated_exposure")
            factors.append(f"validation_status={status_text}")
    elif entity_type == "remediation":
        status_text = str(metadata.get("status") or "").strip().lower()
        if status_text and status_text not in {"done", "closed", "resolved", "accepted"}:
            score += 15.0
            tags.append("open_remediation")
            factors.append(f"remediation_status={status_text}")
    elif entity_type == "asset":
        asset_role = str(metadata.get("asset_role") or "").strip().lower()
        if asset_role == "internet_entrypoint":
            score += 12.0
            tags.append("internet_entrypoint")
            factors.append("asset_role=internet_entrypoint")
        elif asset_role == "workload":
            score += 20.0
            tags.append("workload")
            factors.append("asset_role=workload")
            workload_context = (
                metadata.get("workload_context")
                if isinstance(metadata.get("workload_context"), dict)
                else {}
            )
            if workload_context.get("internet_exposed") is True:
                score += 16.0
                tags.append("internet_exposed")
                factors.append("workload_internet_exposed=true")
            if workload_context.get("account_ref"):
                score += 5.0
                tags.append("cloud_account_mapped")
                factors.append("workload_cloud_account_ref=present")

    explicit_critical = bool(metadata.get("critical_asset") or metadata.get("crown_jewel"))
    if explicit_critical:
        score += 25.0
        tags.append("critical_asset")
        factors.append("critical_asset=true")

    final_score = round(min(100.0, score), 1)
    if final_score >= 80.0:
        tier = "critical"
    elif final_score >= 60.0:
        tier = "high"
    elif final_score >= 35.0:
        tier = "medium"
    else:
        tier = "low"
    critical_asset = entity_type in _CRITICAL_ENTITY_TYPES and (
        explicit_critical or final_score >= 70.0 or entity_type == "secret"
    )
    return {
        "score": final_score,
        "tier": tier,
        "critical_asset": critical_asset,
        "tags": sorted(set(tags)),
        "factors": factors,
    }


def _owner_by_entity_id(ownership_claims: list[dict[str, Any]]) -> dict[int, dict[str, Any]]:
    owners: dict[int, dict[str, Any]] = {}
    for claim in ownership_claims:
        if str(claim.get("status") or "").strip().lower() != "active":
            continue
        entity_id = int(claim.get("entity_id") or 0)
        current = owners.get(entity_id)
        if current is None or float(claim.get("confidence") or 0.0) > float(
            current.get("confidence") or 0.0
        ):
            owners[entity_id] = claim
    return owners


def _path_score(
    path_nodes: list[dict[str, Any]],
    path_edges: list[dict[str, Any]],
) -> float:
    node_score = sum(float(node.get("risk", {}).get("score") or 0.0) for node in path_nodes)
    edge_score = sum(float(edge.get("confidence") or 0.0) * 8.0 for edge in path_edges)
    return round(min(100.0, node_score / max(1, len(path_nodes)) + edge_score), 1)


def _path_tier(score: float) -> str:
    if score >= 80.0:
        return "critical"
    if score >= 60.0:
        return "high"
    if score >= 35.0:
        return "medium"
    return "low"


def _derive_asset_graph_paths(
    nodes: list[dict[str, Any]],
    edges: list[dict[str, Any]],
    ownership_claims: list[dict[str, Any]],
    *,
    limit: int,
) -> dict[str, Any]:
    node_by_id = {int(node["id"]): node for node in nodes}
    owner_by_entity_id = _owner_by_entity_id(ownership_claims)
    remediation_actions_by_target = _remediation_actions_by_target(
        edges,
        node_by_id,
        owner_by_entity_id,
    )
    adjacency: dict[int, list[dict[str, Any]]] = {}
    undirected_degree: dict[int, int] = {}
    for edge in edges:
        source_id = int(edge["source_entity_id"])
        target_id = int(edge["target_entity_id"])
        if source_id not in node_by_id or target_id not in node_by_id:
            continue
        adjacency.setdefault(source_id, []).append(edge)
        undirected_degree[source_id] = undirected_degree.get(source_id, 0) + 1
        undirected_degree[target_id] = undirected_degree.get(target_id, 0) + 1

    critical_assets: list[dict[str, Any]] = []
    for node in nodes:
        risk = node.get("risk") if isinstance(node.get("risk"), dict) else {}
        if not risk.get("critical_asset"):
            continue
        owner = owner_by_entity_id.get(int(node["id"]), {})
        critical_assets.append(
            {
                "node_id": int(node["id"]),
                "entity_key": node["entity_key"],
                "label": node["label"],
                "entity_type": node["entity_type"],
                "risk_score": risk.get("score", 0.0),
                "risk_tier": risk.get("tier", "low"),
                "tags": risk.get("tags", []),
                "risk_factors": risk.get("factors", []),
                "owner_ref": owner.get("owner_ref", ""),
                "owner_display": owner.get("owner_display", ""),
            }
        )
    critical_ids = {int(item["node_id"]) for item in critical_assets}
    entry_ids = [
        int(node["id"])
        for node in nodes
        if str(node.get("entity_type") or "").strip().lower() in _ENTRY_ENTITY_TYPES
    ]

    paths: list[dict[str, Any]] = []
    seen_paths: set[tuple[int, ...]] = set()
    max_depth = 4
    for start_id in entry_ids:
        queue: list[tuple[int, list[int], list[dict[str, Any]]]] = [(start_id, [start_id], [])]
        while queue and len(paths) < max(10, int(limit)):
            current_id, path_node_ids, path_edges = queue.pop(0)
            if len(path_node_ids) > max_depth:
                continue
            if current_id in critical_ids and current_id != start_id:
                path_key = tuple(path_node_ids)
                if path_key in seen_paths:
                    continue
                seen_paths.add(path_key)
                path_nodes = [node_by_id[node_id] for node_id in path_node_ids]
                score = _path_score(path_nodes, path_edges)
                terminal = node_by_id[current_id]
                exposure_summary = _attack_path_exposure_summary(
                    path_nodes,
                    path_edges,
                    owner_by_entity_id,
                    remediation_actions_by_target,
                )
                paths.append(
                    {
                        "path_id": f"path:{len(paths) + 1}",
                        "score": score,
                        "risk_tier": _path_tier(score),
                        "terminal_node_id": current_id,
                        "terminal_entity_key": terminal["entity_key"],
                        "exposure_summary": exposure_summary,
                        "recommended_actions": exposure_summary["recommended_actions"],
                        "nodes": [
                            _attack_path_node_payload(
                                node,
                                owner_by_entity_id,
                                remediation_actions_by_target,
                            )
                            for node in path_nodes
                        ],
                        "edges": [
                            {
                                "source_entity_id": int(edge["source_entity_id"]),
                                "target_entity_id": int(edge["target_entity_id"]),
                                "relationship_type": edge["relationship_type"],
                                "confidence": edge["confidence"],
                            }
                            for edge in path_edges
                        ],
                    }
                )
                continue
            for edge in adjacency.get(current_id, []):
                target_id = int(edge["target_entity_id"])
                if target_id in path_node_ids:
                    continue
                queue.append((target_id, [*path_node_ids, target_id], [*path_edges, edge]))

    paths.sort(key=lambda item: (-float(item["score"]), str(item["path_id"])))
    paths = paths[: max(1, min(int(limit), 25))]
    path_membership: dict[int, int] = {}
    for path in paths:
        for node in path["nodes"]:
            node_id = int(node["node_id"])
            path_membership[node_id] = path_membership.get(node_id, 0) + 1

    choke_points: list[dict[str, Any]] = []
    for node_id, node in node_by_id.items():
        path_count = path_membership.get(node_id, 0)
        degree = undirected_degree.get(node_id, 0)
        if path_count < 2 and degree < 3:
            continue
        reachable = _reachable_nodes(node_id, adjacency, max_depth=3)
        reachable_types = sorted(
            {
                str(node_by_id[target_id].get("entity_type") or "")
                for target_id in reachable
                if target_id in node_by_id
            }
        )
        risk = node.get("risk", {}) if isinstance(node.get("risk"), dict) else {}
        choke_point = {
            "node_id": node_id,
            "entity_key": node["entity_key"],
            "label": node["label"],
            "entity_type": node["entity_type"],
            "path_count": path_count,
            "degree": degree,
            "blast_radius_count": len(reachable),
            "blast_radius_types": reachable_types,
            "blast_radius_summary": _blast_radius_summary(
                node_id,
                reachable,
                node_by_id,
                critical_ids,
            ),
            "score": round(
                path_count * 20.0 + degree * 4.0 + float(risk.get("score") or 0.0) / 4.0,
                1,
            ),
        }
        remediation = _remediation_summary_for_candidate(
            node,
            owner_by_entity_id,
            remediation_actions_by_target,
        )
        if remediation["item_count"]:
            choke_point["remediation"] = remediation
        choke_points.append(choke_point)
    choke_points.sort(key=lambda item: (-float(item["score"]), str(item["entity_key"])))

    fix_candidates = _derive_minimal_fix_candidates(
        paths,
        node_by_id,
        owner_by_entity_id,
        remediation_actions_by_target,
    )
    return {
        "critical_assets": critical_assets[: max(1, min(int(limit), 25))],
        "attack_paths": paths,
        "choke_points": choke_points[: max(1, min(int(limit), 25))],
        "minimal_fix_set_candidates": fix_candidates[: max(1, min(int(limit), 10))],
        "attack_path_summary": {
            "critical_asset_count": len(critical_assets),
            "path_count": len(paths),
            "choke_point_count": len(choke_points),
            "top_path_score": float(paths[0]["score"]) if paths else 0.0,
            "top_path_tier": str(paths[0]["risk_tier"]) if paths else "none",
            "scoring_model": "forge.asset_graph.v1",
        },
    }


def _reachable_nodes(
    start_id: int,
    adjacency: Mapping[int, list[dict[str, Any]]],
    *,
    max_depth: int,
) -> set[int]:
    seen: set[int] = set()
    queue: list[tuple[int, int]] = [(int(start_id), 0)]
    while queue:
        node_id, depth = queue.pop(0)
        if depth >= max_depth:
            continue
        for edge in adjacency.get(node_id, []):
            target_id = int(edge["target_entity_id"])
            if target_id == start_id or target_id in seen:
                continue
            seen.add(target_id)
            queue.append((target_id, depth + 1))
    return seen


def _blast_radius_summary(
    node_id: int,
    reachable: set[int],
    node_by_id: Mapping[int, dict[str, Any]],
    critical_ids: set[int],
) -> dict[str, Any]:
    entity_type_counts: dict[str, int] = {}
    risk_tier_counts: dict[str, int] = {}
    risk_tags: list[str] = []
    risk_factors: list[str] = []
    account_refs: list[str] = []
    regions: list[str] = []
    data_sensitivity_tiers: list[str] = []
    workloads: list[str] = []
    identity_refs: list[str] = []
    critical_asset_refs: list[str] = []
    for target_id in sorted(reachable):
        node = node_by_id.get(target_id)
        if not node:
            continue
        entity_type = str(node.get("entity_type") or "unknown").strip().lower() or "unknown"
        entity_type_counts[entity_type] = entity_type_counts.get(entity_type, 0) + 1
        risk = node.get("risk") if isinstance(node.get("risk"), dict) else {}
        risk_tier = str(risk.get("tier") or "unknown").strip().lower() or "unknown"
        risk_tier_counts[risk_tier] = risk_tier_counts.get(risk_tier, 0) + 1
        for tag in risk.get("tags", []) if isinstance(risk.get("tags"), list) else []:
            _append_unique_text(risk_tags, tag)
        for factor in risk.get("factors", []) if isinstance(risk.get("factors"), list) else []:
            _append_unique_text(risk_factors, factor)
        if target_id in critical_ids:
            _append_unique_text(critical_asset_refs, node.get("entity_key"))
        metadata = _node_metadata(node)
        cloud_context = (
            metadata.get("cloud_context")
            if isinstance(metadata.get("cloud_context"), dict)
            else {}
        )
        if cloud_context:
            _append_unique_text(account_refs, cloud_context.get("account_ref"))
            _append_unique_text(regions, cloud_context.get("region"))
            sensitivity = (
                cloud_context.get("data_sensitivity")
                if isinstance(cloud_context.get("data_sensitivity"), dict)
                else {}
            )
            _append_unique_text(data_sensitivity_tiers, sensitivity.get("tier"))
        workload_context = (
            metadata.get("workload_context")
            if isinstance(metadata.get("workload_context"), dict)
            else {}
        )
        if workload_context:
            _append_unique_text(account_refs, workload_context.get("account_ref"))
            _append_unique_text(workloads, workload_context.get("name"))
        identity_context = (
            metadata.get("identity_context")
            if isinstance(metadata.get("identity_context"), dict)
            else {}
        )
        if identity_context:
            _append_unique_text(account_refs, identity_context.get("account_ref"))
            _append_unique_text(identity_refs, identity_context.get("principal_ref"))

    toxic_combinations = _attack_path_toxic_combinations(risk_tags, risk_factors)
    return {
        "source_node_id": int(node_id),
        "reachable_count": len(reachable),
        "critical_asset_count": len(critical_asset_refs),
        "critical_asset_refs": critical_asset_refs[:12],
        "entity_type_counts": dict(sorted(entity_type_counts.items())),
        "risk_tier_counts": dict(sorted(risk_tier_counts.items())),
        "risk_tags": sorted(risk_tags)[:12],
        "risk_factors": sorted(risk_factors)[:12],
        "toxic_combinations": toxic_combinations,
        "cloud_context": {
            "account_refs": account_refs[:8],
            "regions": regions[:8],
            "data_sensitivity_tiers": data_sensitivity_tiers[:8],
            "workloads": workloads[:8],
            "identity_refs": identity_refs[:8],
        },
    }


def _derive_minimal_fix_candidates(
    paths: list[dict[str, Any]],
    node_by_id: Mapping[int, dict[str, Any]],
    owner_by_entity_id: Mapping[int, dict[str, Any]],
    remediation_actions_by_target: Mapping[int, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    candidates: dict[int, dict[str, Any]] = {}
    for path in paths:
        terminal_id = int(path["terminal_node_id"])
        path_score = float(path["score"])
        for node_ref in reversed(path["nodes"]):
            node_id = int(node_ref["node_id"])
            node = node_by_id[node_id]
            entity_type = str(node.get("entity_type") or "").strip().lower()
            if entity_type not in {
                "finding",
                "secret",
                "validation",
                "cloud",
                "identity",
                "remediation",
            }:
                continue
            owner = owner_by_entity_id.get(node_id, {})
            current = candidates.get(node_id)
            if current is None:
                remediation = _remediation_summary_for_candidate(
                    node,
                    owner_by_entity_id,
                    remediation_actions_by_target,
                )
                candidates[node_id] = {
                    "node_id": node_id,
                    "entity_key": node["entity_key"],
                    "label": node["label"],
                    "entity_type": node["entity_type"],
                    "owner_ref": owner.get("owner_ref", ""),
                    "owner_display": owner.get("owner_display", ""),
                    "reason": _fix_candidate_reason(node),
                    "recommended_actions": _fix_candidate_recommendations(node),
                    "risk_tier": node.get("risk", {}).get("tier", "low"),
                    "risk_tags": node.get("risk", {}).get("tags", []),
                    "risk_factors": node.get("risk", {}).get("factors", []),
                    "supporting_path_count": 1,
                    "expected_risk_reduction": path_score,
                    "terminal_node_id": terminal_id,
                    "remediation": remediation,
                    "remediation_action_count": remediation["item_count"],
                    "remediation_actions": remediation["items"][:3],
                }
            else:
                current["supporting_path_count"] = int(current["supporting_path_count"]) + 1
                current["expected_risk_reduction"] = round(
                    max(float(current["expected_risk_reduction"]), path_score),
                    1,
                )
            break
    result = list(candidates.values())
    result.sort(
        key=lambda item: (
            -int(item["supporting_path_count"]),
            -float(item["expected_risk_reduction"]),
            str(item["entity_key"]),
        )
    )
    return result


def _attack_path_node_payload(
    node: Mapping[str, Any],
    owner_by_entity_id: Mapping[int, dict[str, Any]],
    remediation_actions_by_target: Mapping[int, list[dict[str, Any]]],
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "node_id": int(node["id"]),
        "entity_key": node["entity_key"],
        "label": node["label"],
        "entity_type": node["entity_type"],
        "risk_score": node.get("risk", {}).get("score", 0.0),
    }
    remediation = _remediation_summary_for_candidate(
        node,
        owner_by_entity_id,
        remediation_actions_by_target,
    )
    if remediation["item_count"]:
        payload["remediation"] = remediation
    return payload


def _attack_path_exposure_summary(
    path_nodes: list[dict[str, Any]],
    path_edges: list[dict[str, Any]],
    owner_by_entity_id: Mapping[int, dict[str, Any]],
    remediation_actions_by_target: Mapping[int, list[dict[str, Any]]],
) -> dict[str, Any]:
    if not path_nodes:
        return {
            "entry_entity_key": "",
            "terminal_entity_key": "",
            "summary": "",
            "relationship_chain": [],
            "risk_tags": [],
            "risk_factors": [],
            "owner_refs": [],
            "toxic_combinations": [],
            "cloud_context": {
                "account_refs": [],
                "regions": [],
                "data_sensitivity_tiers": [],
                "workloads": [],
                "identity_refs": [],
            },
            "remediation_action_count": 0,
            "recommended_actions": [],
        }
    entry = path_nodes[0]
    terminal = path_nodes[-1]
    risk_tags: list[str] = []
    risk_factors: list[str] = []
    owner_refs: list[str] = []
    remediation_count = 0
    recommended_actions: list[str] = []
    account_refs: list[str] = []
    regions: list[str] = []
    data_sensitivity_tiers: list[str] = []
    workloads: list[str] = []
    identity_refs: list[str] = []
    for node in path_nodes:
        risk = node.get("risk") if isinstance(node.get("risk"), dict) else {}
        for tag in risk.get("tags", []) if isinstance(risk.get("tags"), list) else []:
            text = str(tag or "").strip()
            if text and text not in risk_tags:
                risk_tags.append(text)
        for factor in risk.get("factors", []) if isinstance(risk.get("factors"), list) else []:
            text = str(factor or "").strip()
            if text and text not in risk_factors:
                risk_factors.append(text)
        owner = owner_by_entity_id.get(int(node.get("id") or 0), {})
        owner_ref = str(owner.get("owner_ref") or "").strip()
        if owner_ref and owner_ref not in owner_refs:
            owner_refs.append(owner_ref)
        remediation = _remediation_summary_for_candidate(
            node,
            owner_by_entity_id,
            remediation_actions_by_target,
        )
        remediation_count += int(remediation.get("item_count") or 0)
        metadata = _node_metadata(node)
        cloud_context = (
            metadata.get("cloud_context")
            if isinstance(metadata.get("cloud_context"), dict)
            else {}
        )
        if cloud_context:
            _append_unique_text(account_refs, cloud_context.get("account_ref"))
            _append_unique_text(regions, cloud_context.get("region"))
            sensitivity = (
                cloud_context.get("data_sensitivity")
                if isinstance(cloud_context.get("data_sensitivity"), dict)
                else {}
            )
            _append_unique_text(data_sensitivity_tiers, sensitivity.get("tier"))
        workload_context = (
            metadata.get("workload_context")
            if isinstance(metadata.get("workload_context"), dict)
            else {}
        )
        if workload_context:
            _append_unique_text(account_refs, workload_context.get("account_ref"))
            _append_unique_text(workloads, workload_context.get("name"))
        identity_context = (
            metadata.get("identity_context")
            if isinstance(metadata.get("identity_context"), dict)
            else {}
        )
        if identity_context:
            _append_unique_text(account_refs, identity_context.get("account_ref"))
            _append_unique_text(identity_refs, identity_context.get("principal_ref"))

    for node in reversed(path_nodes):
        recommended_actions = _fix_candidate_recommendations(node)
        if recommended_actions:
            break

    relationship_chain = [
        str(edge.get("relationship_type") or "").strip()
        for edge in path_edges
        if str(edge.get("relationship_type") or "").strip()
    ]
    summary = (
        f"{entry.get('label') or entry.get('entity_key')} reaches "
        f"{terminal.get('label') or terminal.get('entity_key')} through "
        f"{len(path_edges)} graph hop{'s' if len(path_edges) != 1 else ''}."
    )
    toxic_combinations = _attack_path_toxic_combinations(risk_tags, risk_factors)
    return {
        "entry_entity_key": str(entry.get("entity_key") or ""),
        "terminal_entity_key": str(terminal.get("entity_key") or ""),
        "summary": summary,
        "relationship_chain": relationship_chain,
        "risk_tags": sorted(risk_tags)[:12],
        "risk_factors": sorted(risk_factors)[:12],
        "owner_refs": owner_refs[:8],
        "toxic_combinations": toxic_combinations,
        "cloud_context": {
            "account_refs": account_refs[:8],
            "regions": regions[:8],
            "data_sensitivity_tiers": data_sensitivity_tiers[:8],
            "workloads": workloads[:8],
            "identity_refs": identity_refs[:8],
        },
        "remediation_action_count": remediation_count,
        "recommended_actions": recommended_actions,
    }


def _append_unique_text(items: list[str], value: object) -> None:
    text = str(value or "").strip()
    if text and text not in items:
        items.append(text)


def _attack_path_toxic_combinations(
    risk_tags: Iterable[str],
    risk_factors: Iterable[str],
) -> list[str]:
    tags = {str(tag or "").strip().lower() for tag in risk_tags if str(tag or "").strip()}
    factors = {
        str(factor or "").strip().lower()
        for factor in risk_factors
        if str(factor or "").strip()
    }
    public_exposure = bool(
        tags
        & {
            "internet_entrypoint",
            "internet_exposed",
            "validated_exposure",
        }
    ) or any("public" in factor or "internet_exposed=true" in factor for factor in factors)
    sensitive_data = bool(tags & {"data_asset", "sensitive_data", "data_access_identity"}) or any(
        factor.startswith("data_sensitivity=")
        or factor.startswith("sensitive_data_actions=")
        for factor in factors
    )
    privileged_identity = bool(
        tags
        & {
            "privileged_identity",
            "wildcard_action",
            "wildcard_resource",
            "write_capable_identity",
        }
    ) or any(
        factor.startswith("identity_privilege=")
        or factor.startswith("wildcard_action=")
        or factor.startswith("wildcard_resource=")
        or factor.startswith("write_actions=")
        for factor in factors
    )
    validated_exposure = "validated_exposure" in tags or any(
        factor.startswith("validation_status=") for factor in factors
    )
    open_remediation = "open_remediation" in tags or any(
        factor.startswith("remediation_status=") for factor in factors
    )
    combinations: list[str] = []
    if public_exposure and sensitive_data:
        combinations.append("public_sensitive_data_exposure")
    if sensitive_data and privileged_identity:
        combinations.append("privileged_identity_to_sensitive_data")
    if public_exposure and privileged_identity:
        combinations.append("public_entry_to_privileged_identity")
    if public_exposure and sensitive_data and privileged_identity:
        combinations.append("public_to_privileged_sensitive_data_path")
    if validated_exposure and open_remediation:
        combinations.append("validated_exposure_with_open_remediation")
    return combinations


def _remediation_actions_by_target(
    edges: list[dict[str, Any]],
    node_by_id: Mapping[int, dict[str, Any]],
    owner_by_entity_id: Mapping[int, dict[str, Any]],
) -> dict[int, list[dict[str, Any]]]:
    actions: dict[int, list[dict[str, Any]]] = {}
    for edge in edges:
        if str(edge.get("relationship_type") or "") != "remediates":
            continue
        source_id = int(edge.get("source_entity_id") or 0)
        target_id = int(edge.get("target_entity_id") or 0)
        remediation_node = node_by_id.get(source_id)
        if not remediation_node or str(remediation_node.get("entity_type") or "") != "remediation":
            continue
        owner = owner_by_entity_id.get(source_id, {})
        actions.setdefault(target_id, []).append(_remediation_action_payload(remediation_node, owner))
    for target_actions in actions.values():
        target_actions.sort(key=_remediation_action_sort_key)
    return actions


def _remediation_actions_for_candidate(
    node: Mapping[str, Any],
    owner_by_entity_id: Mapping[int, dict[str, Any]],
    remediation_actions_by_target: Mapping[int, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    node_id = int(node.get("id") or 0)
    if str(node.get("entity_type") or "") == "remediation":
        return [
            _remediation_action_payload(
                node,
                owner_by_entity_id.get(node_id, {}),
            )
        ]
    return list(remediation_actions_by_target.get(node_id, []))


def _remediation_summary_for_candidate(
    node: Mapping[str, Any],
    owner_by_entity_id: Mapping[int, dict[str, Any]],
    remediation_actions_by_target: Mapping[int, list[dict[str, Any]]],
) -> dict[str, Any]:
    actions = _remediation_actions_for_candidate(
        node,
        owner_by_entity_id,
        remediation_actions_by_target,
    )
    open_statuses = {
        "assigned",
        "in_progress",
        "open",
        "retest_pending",
        "risk_accepted",
        "triage",
    }
    return {
        "item_count": len(actions),
        "open_count": sum(
            1 for item in actions if str(item.get("status") or "").strip().lower() in open_statuses
        ),
        "ticketed_count": sum(
            1
            for item in actions
            if str(item.get("ticket_ref") or "").strip() or str(item.get("ticket_url") or "").strip()
        ),
        "retest_pending_count": sum(
            1
            for item in actions
            if str(item.get("retest_status") or "").strip().lower() == "pending"
            or str(item.get("status") or "").strip().lower() == "retest_pending"
        ),
        "risk_acceptance_state": _risk_acceptance_state(actions),
        "items": actions[:5],
    }


def _remediation_action_payload(
    node: Mapping[str, Any],
    owner: Mapping[str, Any],
) -> dict[str, Any]:
    metadata = node.get("metadata") if isinstance(node.get("metadata"), dict) else {}
    item_id = node.get("source_id")
    try:
        normalized_item_id = int(item_id) if item_id is not None else 0
    except (TypeError, ValueError):
        normalized_item_id = 0
    return {
        "id": normalized_item_id,
        "node_id": int(node.get("id") or 0),
        "entity_key": str(node.get("entity_key") or ""),
        "label": str(node.get("label") or ""),
        "status": str(metadata.get("status") or ""),
        "sla_due_at": str(metadata.get("sla_due_at") or ""),
        "retest_status": str(metadata.get("retest_status") or ""),
        "risk_acceptance_expires_at": str(metadata.get("risk_acceptance_expires_at") or ""),
        "ticket_system": str(metadata.get("ticket_system") or ""),
        "ticket_ref": str(metadata.get("ticket_ref") or ""),
        "ticket_url": _safe_url_reference(metadata.get("ticket_url")),
        "owner_ref": str(owner.get("owner_ref") or ""),
        "owner_display": str(owner.get("owner_display") or ""),
    }


def _risk_acceptance_state(actions: list[dict[str, Any]]) -> str:
    accepted = [
        item
        for item in actions
        if str(item.get("status") or "").strip().lower() == "risk_accepted"
    ]
    if not accepted:
        return "none"
    expiries = [str(item.get("risk_acceptance_expires_at") or "").strip() for item in accepted]
    if any(not expiry for expiry in expiries):
        return "missing_expiry"
    return "expiry_recorded"


def _remediation_action_sort_key(item: Mapping[str, Any]) -> tuple[int, str, str]:
    status = str(item.get("status") or "").strip().lower()
    terminal = 1 if status in {"closed", "done", "false_positive", "resolved"} else 0
    due = str(item.get("sla_due_at") or "")
    return (terminal, due, str(item.get("entity_key") or ""))


def _fix_candidate_reason(node: Mapping[str, Any]) -> str:
    entity_type = str(node.get("entity_type") or "").strip().lower()
    risk = node.get("risk") if isinstance(node.get("risk"), dict) else {}
    tags = {
        str(tag or "").strip().lower()
        for tag in risk.get("tags", [])
        if str(tag or "").strip()
    } if isinstance(risk.get("tags"), list) else set()
    if entity_type == "finding":
        return "remediate_highest_risk_finding"
    if entity_type == "secret":
        return "revoke_or_rotate_secret"
    if entity_type == "validation":
        return "resolve_validated_exposure"
    if entity_type == "cloud":
        if {"internet_exposed", "sensitive_data"} <= tags:
            return "restrict_public_sensitive_data_asset"
        if "sensitive_data" in tags:
            return "protect_sensitive_cloud_data_asset"
        if "internet_exposed" in tags:
            return "reduce_public_cloud_exposure"
        return "reduce_cloud_asset_exposure"
    if entity_type == "identity":
        return "reduce_cloud_identity_privilege"
    if entity_type == "remediation":
        return "complete_existing_remediation_item"
    return "reduce_path_risk"


def _fix_candidate_recommendations(node: Mapping[str, Any]) -> list[str]:
    entity_type = str(node.get("entity_type") or "").strip().lower()
    risk = node.get("risk") if isinstance(node.get("risk"), dict) else {}
    tags = {
        str(tag or "").strip().lower()
        for tag in risk.get("tags", [])
        if str(tag or "").strip()
    } if isinstance(risk.get("tags"), list) else set()
    if entity_type == "cloud":
        actions: list[str] = []
        if "internet_exposed" in tags:
            actions.extend(
                [
                    "disable_public_access",
                    "restrict_public_policy_or_acl",
                ]
            )
        if "sensitive_data" in tags:
            actions.extend(
                [
                    "confirm_data_classification",
                    "add_data_loss_guardrails",
                ]
            )
        if "cloud_account_mapped" in tags:
            actions.append("route_to_cloud_account_owner")
        if not actions:
            actions.append("review_cloud_resource_exposure")
        return list(dict.fromkeys(actions))[:6]
    if entity_type == "identity":
        if {"wildcard_action", "wildcard_resource"} & tags:
            return [
                "remove_wildcard_permissions",
                "scope_identity_to_required_resources",
                "retest_cloud_access_path",
            ]
        return ["review_identity_permissions", "apply_least_privilege"]
    if entity_type == "secret":
        return ["revoke_or_rotate_secret", "route_owner", "verify_revocation"]
    if entity_type == "finding":
        return ["assign_remediation_owner", "open_or_update_ticket", "request_retest"]
    if entity_type == "validation":
        return ["review_validation_proof", "apply_fix", "rerun_validation"]
    if entity_type == "remediation":
        return ["complete_remediation_item", "sync_ticket", "rerun_retest"]
    return []


def list_asset_graph(
    con: sqlite3.Connection,
    engagement_id: int,
    *,
    entity_key: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    _ensure_rows(con)
    where = "WHERE engagement_id=?"
    params: list[Any] = [int(engagement_id)]
    if entity_key:
        where += " AND entity_key=?"
        params.append(entity_key)
    total_node_count = int(
        con.execute(
            f"""
            SELECT COUNT(*) AS count
            FROM asset_entities
            {where}
            """,
            tuple(params),
        ).fetchone()["count"]
    )
    params.append(max(1, int(limit)))
    nodes = [
        {
            "id": int(row["id"]),
            "entity_key": row["entity_key"],
            "entity_type": row["entity_type"],
            "label": row["label"],
            "source_table": row["source_table"],
            "source_id": int(row["source_id"]) if row["source_id"] is not None else None,
            "confidence": float(row["confidence"]),
            "metadata": _json_loads(row["metadata_json"]),
        }
        for row in con.execute(
            f"""
            SELECT id, entity_key, entity_type, label, source_table, source_id,
                   confidence, metadata_json
            FROM asset_entities
            {where}
            ORDER BY updated_at DESC, id DESC
            LIMIT ?
            """,
            tuple(params),
        ).fetchall()
    ]
    for node in nodes:
        node["risk"] = _node_risk_profile(node)
    node_ids = [int(node["id"]) for node in nodes]
    if node_ids:
        placeholders = ",".join("?" for _ in node_ids)
        edge_rows = con.execute(
            f"""
            SELECT source_entity_id, target_entity_id, relationship_type, confidence, evidence_json
            FROM asset_relationships
            WHERE engagement_id=?
              AND (source_entity_id IN ({placeholders}) OR target_entity_id IN ({placeholders}))
            ORDER BY updated_at DESC
            LIMIT ?
            """,
            (int(engagement_id), *node_ids, *node_ids, max(1, int(limit))),
        ).fetchall()
    else:
        edge_rows = []
    edges = [
        {
            "source_entity_id": int(row["source_entity_id"]),
            "target_entity_id": int(row["target_entity_id"]),
            "relationship_type": row["relationship_type"],
            "confidence": float(row["confidence"]),
            "evidence": _json_loads(row["evidence_json"]),
        }
        for row in edge_rows
    ]
    ownership_rows = con.execute(
        """
        SELECT c.entity_id, c.owner_kind, c.owner_ref, c.owner_display,
               c.claim_type, c.confidence, c.source, c.status, c.evidence_json
        FROM asset_ownership_claims c
        JOIN asset_entities e ON e.id=c.entity_id
        WHERE c.engagement_id=?
          AND (?='' OR e.entity_key=?)
        ORDER BY c.confidence DESC, c.updated_at DESC
        LIMIT ?
        """,
        (int(engagement_id), entity_key or "", entity_key or "", max(1, int(limit))),
    ).fetchall()
    ownership_claims = [
        {
            "entity_id": int(row["entity_id"]),
            "owner_kind": row["owner_kind"],
            "owner_ref": row["owner_ref"],
            "owner_display": row["owner_display"],
            "claim_type": row["claim_type"],
            "confidence": float(row["confidence"]),
            "source": row["source"],
            "status": row["status"],
            "evidence": _json_loads(row["evidence_json"]),
        }
        for row in ownership_rows
    ]
    derived_paths = _derive_asset_graph_paths(
        nodes,
        edges,
        ownership_claims,
        limit=max(1, int(limit)),
    )
    return {
        "schema_version": "forge.asset_graph.list.v1",
        "execution_policy": "read_only_asset_graph_inventory_no_commands_executed",
        "total_count": total_node_count,
        "selected_count": len(nodes),
        "omitted_count": max(0, total_node_count - len(nodes)),
        "engagement_id": int(engagement_id),
        "nodes": nodes,
        "edges": edges,
        "ownership_claims": ownership_claims,
        "ownership_conflicts": ownership_conflicts_for_engagement(
            con,
            int(engagement_id),
            entity_key=entity_key,
            limit=max(1, int(limit)),
        ),
        **derived_paths,
    }


def entity_id_for_key(con: sqlite3.Connection, engagement_id: int, entity_key: str) -> int | None:
    _ensure_rows(con)
    return _fetch_entity_id_by_key(con, int(engagement_id), entity_key)
