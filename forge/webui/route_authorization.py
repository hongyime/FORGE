"""FastAPI route authorization helpers for engagement-scoped Web UI routes."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fastapi import HTTPException

from forge.webui.engagement_discovery import (
    EngagementDiscoveryContext,
    authorized_engagement_db_path as resolve_authorized_engagement_db_path,
)


EngagementDiscoveryContextFactory = Callable[[], EngagementDiscoveryContext]


@dataclass(frozen=True)
class AuthorizedEngagementResolver:
    context_factory: EngagementDiscoveryContextFactory

    def db_path(self, engagement_id: int, principal: Any) -> Path:
        try:
            return resolve_authorized_engagement_db_path(
                self.context_factory(),
                engagement_id,
                principal,
            )
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc


__all__ = ["AuthorizedEngagementResolver"]
