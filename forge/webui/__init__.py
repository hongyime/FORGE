from __future__ import annotations

__all__ = ["create_app", "create_server"]


def __getattr__(name: str):  # noqa: ANN201
    """Lazy-load forge.webui.app only when create_app / create_server are
    actually accessed.  Importing ``forge.webui`` (e.g. ``from forge.webui
    import auth``) must NOT trigger the full 2600-line app.py import chain
    -- that chain imports llama_cpp, SQLAlchemy, asyncpg, Redis clients, etc.
    and causes 30-60 s hangs during pytest collection on Windows.
    """
    if name in ("create_app", "create_server"):
        from forge.webui.app import create_app, create_server  # noqa: PLC0415
        globals()["create_app"] = create_app
        globals()["create_server"] = create_server
        return globals()[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
