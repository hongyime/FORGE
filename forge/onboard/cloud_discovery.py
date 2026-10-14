"""Cloud-account discovery data model; discovery functions land in later goals."""

from __future__ import annotations

from dataclasses import dataclass, field
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
