"""
forge/api/app.py - FastAPI application factory.

The factory pattern keeps the construction of the app explicit so test
clients and production servers share the same wiring. The ``lifespan``
context manager wires up startup (state-store schema bootstrap) and
shutdown (bus + state store cleanup).

Run in development with::

    uvicorn forge.api.app:app --host 0.0.0.0 --port 8000

Requirements: 12.1, 12.2
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from forge.api.deps import get_bus, get_state_store
from forge.api.routes import health, quality, reports, workflows
from forge.security_headers import install_security_headers

__all__ = ["app", "create_app"]

_LOG = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    """Initialise persistent dependencies, then tear down cleanly on exit."""
    state_store = get_state_store()
    try:
        await state_store.init_schema()
        _LOG.info("FORGE API: state store schema ready")
    except Exception:  # noqa: BLE001 - surface error but allow startup
        _LOG.exception("FORGE API: state store schema init failed")

    yield

    # Graceful shutdown
    bus = get_bus()
    if hasattr(bus, "close"):
        try:
            await bus.close()
        except Exception:  # noqa: BLE001 - best-effort cleanup
            _LOG.debug("FORGE API: bus close raised", exc_info=True)
    try:
        await state_store.close()
    except Exception:  # noqa: BLE001 - best-effort cleanup
        _LOG.debug("FORGE API: state store close raised", exc_info=True)


def create_app() -> FastAPI:
    """Return a fully wired :class:`FastAPI` application."""
    fastapi_app = FastAPI(
        title="FORGE Autonomous Security Platform",
        version="7.2.0",
        description=(
            "Multi-agent security orchestration platform with workflow "
            "engine, plugin architecture, and provider abstraction."
        ),
        lifespan=lifespan,
    )
    install_security_headers(fastapi_app, surface="api")
    fastapi_app.include_router(health.router)
    fastapi_app.include_router(workflows.router)
    fastapi_app.include_router(reports.router)
    fastapi_app.include_router(quality.router)
    return fastapi_app


app: FastAPI = create_app()
