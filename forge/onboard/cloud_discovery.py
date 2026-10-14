"""Cloud-account discovery data model; discovery functions land in later goals."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


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
                    )
                )
                seen.add(account_id)
            except Exception:
                continue
        return accounts
    except Exception:
        return []


def discover_gcp_projects(
    *, credentials: list[Any] | None = None, include_metadata: bool = False
) -> list[CloudAccount]:
    """Discover GCP projects from locally harvested credentials."""
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
                accounts.append(
                    CloudAccount(
                        provider="gcp",
                        account_id=project_id,
                        account_name=None,
                        regions=[],
                        services=[],
                        discovery_source=f"offline:{source}" if source else "offline:harvest",
                        first_seen_at=_now_iso(),
                        engagement_points=[
                            f"https://{project_id}.appspot.com",
                            f"https://{project_id}.firebaseio.com",
                            f"https://{project_id}.web.app",
                        ],
                        extra={"client_email": client_email}
                        if isinstance(client_email, str) and client_email
                        else {},
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
                    )
                )
                seen.add(normalized_id)
            except Exception:
                continue
        return accounts
    except Exception:
        return accounts
