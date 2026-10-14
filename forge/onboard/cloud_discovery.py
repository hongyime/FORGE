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
