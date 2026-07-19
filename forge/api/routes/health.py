"""
forge/api/routes/health.py - Health-check endpoints.

``/health`` returns 200 only when the message bus is connected and the
platform is operational; ``/ready`` is a lightweight liveness probe used by
container orchestrators to detect process startup.

Requirements: 12.1, 12.2
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, status

from forge.api.deps import get_bus
from forge.bus.base import MessageBus

__all__ = ["router"]

_LOG = logging.getLogger(__name__)

router = APIRouter(tags=["health"])


@router.get("/health", summary="Platform health probe (Req 12.2)")
async def health(bus: MessageBus = Depends(get_bus)) -> dict[str, object]:
    """Return 200 when the message bus is operational.

    The probe deliberately exercises the bus's :meth:`health_check` so a
    silent disconnect surfaces as a 503 rather than a misleading 200.
    """
    try:
        bus_ok = await bus.health_check()
    except Exception as exc:
        _LOG.warning("health: bus health_check raised %s", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"message_bus_error:{exc.__class__.__name__}",
        ) from exc

    if not bus_ok:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="message_bus_unavailable",
        )

    return {
        "status": "ok",
        "bus_connected": True,
        "version": "7.2.0-platform",
    }


@router.get("/ready", summary="Liveness probe")
async def ready() -> dict[str, str]:
    """Return 200 once the process has booted.

    Container orchestrators typically poll this endpoint to determine when
    the container has finished starting. Unlike ``/health`` it does NOT
    exercise downstream dependencies.
    """
    return {"status": "ready"}
