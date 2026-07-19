"""Guard project-wide TLS defaults from third-party global monkeypatches."""

from __future__ import annotations

import ssl
from typing import Any

_ORIGINAL_CREATE_DEFAULT_CONTEXT = ssl.create_default_context
_ORIGINAL_PRIVATE_CREATE_DEFAULT_CONTEXT = getattr(
    ssl,
    "_create_default_context",
    ssl.create_default_context,
)
_ORIGINAL_CREATE_DEFAULT_HTTPS_CONTEXT = getattr(
    ssl,
    "_create_default_https_context",
    ssl.create_default_context,
)


def _is_impacket_context_factory(value: Any) -> bool:
    return str(getattr(value, "__module__", "") or "").startswith("impacket.examples")


def restore_default_ssl_context() -> None:
    """Restore stdlib SSL context factories after impacket examples imports.

    Some impacket example modules globally replace ``ssl.create_default_context``
    to allow legacy TLS. That is unacceptable for provider validation and REST
    plugin clients, and can recurse if imported repeatedly in one process.
    """
    if _is_impacket_context_factory(getattr(ssl, "create_default_context", None)):
        ssl.create_default_context = _ORIGINAL_CREATE_DEFAULT_CONTEXT
    if _is_impacket_context_factory(getattr(ssl, "_create_default_context", None)):
        ssl._create_default_context = _ORIGINAL_PRIVATE_CREATE_DEFAULT_CONTEXT  # type: ignore[attr-defined]
    if _is_impacket_context_factory(getattr(ssl, "_create_default_https_context", None)):
        ssl._create_default_https_context = _ORIGINAL_CREATE_DEFAULT_HTTPS_CONTEXT  # type: ignore[attr-defined]
