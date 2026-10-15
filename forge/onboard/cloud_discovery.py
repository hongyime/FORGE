"""Cloud-account discovery data model; discovery functions land in later goals."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


CLOUD_SEED_DROP_FILENAME = "connected-services-cloud-seeds.local.json"


@dataclass(frozen=True)
class CloudAccount:
    provider: str
    account_id: str
    account_name: str | None = None
    regions: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    discovery_source: str = ""
    first_seen_at: str = ""
    engagement_points: list[str] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)
    quarantined: bool = False


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def discover_aws_accounts(
    *,
    session: Any | None = None,
    credentials: list[Any] | None = None,
    profile: str | None = None,
    regions: list[str] | None = None,
    services: list[str] | None = None,
    timeout: float = 5.0,
) -> list[CloudAccount]:
    """Discover the current AWS account, then fall back to harvested credentials."""
    del timeout  # Accepted for API compatibility; boto3 clients remain unmodified.
    default_services = ["iam", "s3", "rds", "ec2", "lambda", "cloudtrail"]
    try:
        active_session = session
        if active_session is None:
            try:
                import boto3

                active_session = boto3.Session(profile_name=profile)
            except Exception:
                active_session = None

        if active_session is not None:
            try:
                identity = active_session.client("sts").get_caller_identity()
                account_id = identity.get("Account") if isinstance(identity, dict) else None
                if isinstance(account_id, str) and re.fullmatch(r"\d{12}", account_id):
                    account_name = None
                    try:
                        aliases = active_session.client("iam").list_account_aliases()
                        values = aliases.get("AccountAliases", []) if isinstance(aliases, dict) else []
                        if values:
                            account_name = values[0]
                    except Exception:
                        pass
                    engagement_points: list[str] = []
                    try:
                        buckets = active_session.client("s3").list_buckets()
                        values = buckets.get("Buckets", []) if isinstance(buckets, dict) else []
                        engagement_points = [
                            f"https://{bucket['Name']}.s3.amazonaws.com"
                            for bucket in values
                            if isinstance(bucket, dict) and isinstance(bucket.get("Name"), str)
                        ][:50]
                    except Exception:
                        pass
                    arn = identity.get("Arn")
                    return [
                        CloudAccount(
                            provider="aws",
                            account_id=account_id,
                            account_name=account_name,
                            regions=list(regions) if regions is not None else [],
                            services=list(services) if services is not None else default_services,
                            discovery_source="sts:get_caller_identity",
                            first_seen_at=_now_iso(),
                            engagement_points=engagement_points,
                            extra={"arn": arn} if arn else {},
                        )
                    ]
            except Exception:
                pass

        if credentials is not None and not credentials:
            return []
        if credentials is None:
            try:
                from forge.collection.cloud.aws_credentials import harvest_aws_credentials

                harvested = harvest_aws_credentials()
            except Exception:
                return []
        else:
            harvested = credentials

        accounts: list[CloudAccount] = []
        seen: set[str] = set()
        for cred in harvested:
            try:
                account_id = getattr(cred, "account_id", None)
                if not isinstance(account_id, str) or not re.fullmatch(r"\d{12}", account_id) or account_id in seen:
                    continue
                source = getattr(cred, "source", None)
                accounts.append(
                    CloudAccount(
                        provider="aws",
                        account_id=account_id,
                        account_name=None,
                        regions=list(regions) if regions is not None else [],
                        services=list(services) if services is not None else default_services.copy(),
                        discovery_source=f"offline:{source}" if source else "offline:harvest",
                        first_seen_at=_now_iso(),
                        engagement_points=[],
                        extra={},
                        quarantined=True,
                    )
                )
                seen.add(account_id)
            except Exception:
                continue
        return accounts
    except Exception:
        return []


def _verify_gcp_project(project_id: str) -> bool:
    """Verify project visibility with the authenticated Cloud Resource Manager API."""
    try:
        import google.auth
        from google.auth.transport.requests import AuthorizedSession

        credential, _ = google.auth.default(
            scopes=["https://www.googleapis.com/auth/cloud-platform"]
        )
        response = AuthorizedSession(credential).get(
            f"https://cloudresourcemanager.googleapis.com/v1/projects/{project_id}",
            timeout=5,
        )
        return response.status_code == 200
    except Exception:
        return False


def discover_gcp_projects(
    *, credentials: list[Any] | None = None, include_metadata: bool = False,
    verifier: Any | None = None,
) -> list[CloudAccount]:
    """Discover projects and verify visibility when usable Google credentials exist."""
    accounts: list[CloudAccount] = []
    try:
        if credentials is not None:
            if not credentials:
                return []
            harvested = credentials
        else:
            from forge.collection.cloud.gcp_credentials import harvest_gcp_credentials

            harvested = harvest_gcp_credentials(include_metadata=include_metadata)

        seen: set[str] = set()
        verify = verifier or _verify_gcp_project
        for cred in harvested:
            try:
                project_id = getattr(cred, "project_id", None)
                if (
                    not isinstance(project_id, str)
                    or not re.fullmatch(r"[a-z][a-z0-9-]{4,28}[a-z0-9]", project_id)
                    or project_id in seen
                ):
                    continue

                source = getattr(cred, "source", None)
                client_email = getattr(cred, "client_email", None)
                verified = bool(verify(project_id))
                accounts.append(
                    CloudAccount(
                        provider="gcp",
                        account_id=project_id,
                        account_name=None,
                        regions=[],
                        services=[],
                        discovery_source="cloudresourcemanager:projects.get" if verified else (f"offline:{source}" if source else "offline:harvest"),
                        first_seen_at=_now_iso(),
                        engagement_points=[],
                        extra={"client_email": client_email}
                        if isinstance(client_email, str) and client_email
                        else {},
                        quarantined=not verified,
                    )
                )
                seen.add(project_id)
            except Exception:
                continue
        return accounts
    except Exception:
        return accounts


def discover_azure_subscriptions(
    *,
    client: Any | None = None,
    credentials: list[Any] | None = None,
    subscription_id: str | None = None,
    tenant_id: str | None = None,
    client_id: str | None = None,
    client_secret: str | None = None,
) -> list[CloudAccount]:
    """Discover Azure subscriptions from an explicit client or harvested credentials."""
    accounts: list[CloudAccount] = []
    guid_pattern = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    subscription_filter = (
        subscription_id.lower()
        if isinstance(subscription_id, str) and subscription_id
        else None
    )
    try:
        if client is None and client_id and client_secret and tenant_id:
            from azure.identity import ClientSecretCredential
            from azure.mgmt.resource import ResourceManagementClient

            credential = ClientSecretCredential(
                tenant_id=tenant_id, client_id=client_id, client_secret=client_secret
            )
            client = ResourceManagementClient(credential, "")

        if client is not None:
            try:
                seen: set[str] = set()
                for item in client.subscriptions.list():
                    item_id = getattr(item, "subscription_id", None)
                    if not isinstance(item_id, str) or not re.fullmatch(guid_pattern, item_id):
                        continue
                    normalized_id = item_id.lower()
                    if subscription_filter and normalized_id != subscription_filter:
                        continue
                    if normalized_id in seen:
                        continue
                    display_name = getattr(item, "display_name", None)
                    item_tenant = getattr(item, "tenant_id", None)
                    accounts.append(
                        CloudAccount(
                            provider="azure",
                            account_id=normalized_id,
                            account_name=display_name if display_name else None,
                            regions=[],
                            services=[],
                            discovery_source="azure_mgmt:subscriptions.list",
                            first_seen_at=_now_iso(),
                            engagement_points=[],
                            extra={"tenant_id": item_tenant}
                            if isinstance(item_tenant, str) and item_tenant
                            else {},
                        )
                    )
                    seen.add(normalized_id)
                if accounts:
                    return accounts
            except Exception:
                accounts = []

        if credentials is not None:
            if not credentials:
                return []
            harvested = credentials
        else:
            from forge.collection.cloud.azure_credentials import harvest_azure_credentials

            harvested = harvest_azure_credentials()

        seen = set()
        for cred in harvested:
            try:
                item_id = getattr(cred, "subscription_id", None)
                if not isinstance(item_id, str) or not re.fullmatch(guid_pattern, item_id):
                    continue
                normalized_id = item_id.lower()
                if subscription_filter and normalized_id != subscription_filter:
                    continue
                if normalized_id in seen:
                    continue
                source = getattr(cred, "source", None)
                account_name = getattr(cred, "account_name", None)
                cred_tenant = getattr(cred, "tenant_id", None)
                accounts.append(
                    CloudAccount(
                        provider="azure",
                        account_id=normalized_id,
                        account_name=account_name
                        if isinstance(account_name, str) and account_name
                        else None,
                        regions=[],
                        services=[],
                        discovery_source=f"offline:{source}"
                        if isinstance(source, str) and source
                        else "offline:harvest",
                        first_seen_at=_now_iso(),
                        engagement_points=[],
                        extra={"tenant_id": cred_tenant}
                        if isinstance(cred_tenant, str) and cred_tenant
                        else {},
                        quarantined=True,
                    )
                )
                seen.add(normalized_id)
            except Exception:
                continue
        return accounts
    except Exception:
        return accounts


def discover_all_cloud_accounts(
    *,
    cfg: Any | None = None,
    enable_aws: bool = True,
    enable_gcp: bool = True,
    enable_azure: bool = True,
    aws_session: Any | None = None,
    azure_client: Any | None = None,
    gcp_verifier: Any | None = None,
    gcp_credentials: list[Any] | None = None,
) -> tuple[list[CloudAccount], dict[str, str]]:
    """Run enabled cloud providers independently and combine their accounts."""
    providers = ("aws", "gcp", "azure")
    try:
        if cfg is not None and not getattr(cfg, "cloud_discovery_enabled", True):
            return [], {provider: "disabled" for provider in providers}

        enabled = {
            "aws": enable_aws and (cfg is None or getattr(cfg, "cloud_discovery_aws", True)),
            "gcp": enable_gcp and (cfg is None or getattr(cfg, "cloud_discovery_gcp", True)),
            "azure": enable_azure and (cfg is None or getattr(cfg, "cloud_discovery_azure", True)),
        }
        timeout_value = (
            getattr(cfg, "cloud_discovery_timeout_seconds", 5.0) if cfg is not None else 5.0
        )
        timeout = timeout_value if isinstance(timeout_value, (int, float)) else 5.0
        functions = {
            "aws": lambda: discover_aws_accounts(session=aws_session, timeout=timeout),
            "gcp": lambda: discover_gcp_projects(credentials=gcp_credentials, verifier=gcp_verifier),
            "azure": lambda: (
                discover_azure_subscriptions()
                if azure_client is None
                else discover_azure_subscriptions(client=azure_client)
            ),
        }
        accounts: list[CloudAccount] = []
        skip_reasons: dict[str, str] = {}
        seen: set[tuple[str, str]] = set()
        for provider in providers:
            if not enabled[provider]:
                skip_reasons[provider] = "disabled"
                continue
            try:
                found = functions[provider]()
                skip_reasons[provider] = "ok" if found else "no_accounts_found"
                for account in found:
                    key = (account.provider, account.account_id)
                    if key not in seen:
                        accounts.append(account)
                        seen.add(key)
            except Exception:
                skip_reasons[provider] = "error"
        return accounts, skip_reasons
    except Exception:
        return [], {provider: "error" for provider in providers}


def cloud_account_to_feed_candidate(
    account: CloudAccount,
    *,
    confidence: float | None = None,
    first_seen_at: str | None = None,
) -> Any:
    """Convert a cloud account into its primary feed candidate."""
    from forge.automation_target_feed import FeedCandidate

    canonical_val = f"{account.provider}:{account.account_id}"
    effective_confidence = confidence if confidence is not None else (0.4 if account.quarantined else 0.95)
    return FeedCandidate(
        target_type="cloud_ref",
        target_value=canonical_val,
        canonical_value=canonical_val,
        source_kind="cloud_discovery",
        source_group=f"cloud_discovery:{account.provider}",
        confidence=effective_confidence,
        first_seen_at=first_seen_at or account.first_seen_at or _now_iso(),
        provenance=f"cloud_discovery:{account.provider}:{account.discovery_source}",
    )


def cloud_account_to_all_candidates(
    account: CloudAccount, *, confidence: float | None = None
) -> list[Any]:
    """Convert a cloud account and its engagement points into feed candidates."""
    from forge.automation_target_feed import _candidate

    candidates = [cloud_account_to_feed_candidate(account, confidence=confidence)]
    for engagement_point in account.engagement_points:
        candidate = _candidate(
            engagement_point,
            source_kind="cloud_discovery",
            source_group=f"cloud_discovery:{account.provider}",
            provenance=(
                f"cloud_discovery:{account.provider}:{account.account_id}:engagement_point"
            ),
            confidence=0.90,
            first_seen_at=account.first_seen_at or _now_iso(),
            target_type_hint="auto",
        )
        if candidate is not None:
            candidates.append(candidate)
    return candidates


def cloud_accounts_to_seed_drop_payload(
    accounts: list[CloudAccount], *, generated_at: str | None = None
) -> dict[str, Any]:
    """Serialize cloud discovery results using the connected-services seed format."""
    seeds = [
        {
            "target_value": candidate.target_value,
            "target_type": candidate.target_type,
            "source_kind": candidate.source_kind,
            "source_group": candidate.source_group,
            "provenance": candidate.provenance,
            "confidence": candidate.confidence,
            "first_seen_at": candidate.first_seen_at,
        }
        for account in accounts
        for candidate in cloud_account_to_all_candidates(account)
    ]
    return {
        "schema_version": "forge.connected_services_scan.v1",
        "connector_id": "cloud_discovery",
        "input_kind": "connected_services",
        "generated_at": generated_at or _now_iso(),
        "seeds": seeds,
        "secret_hits": [],
    }
