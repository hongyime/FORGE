VERSION = "7.2.0"

# Capture stdlib TLS defaults before optional third-party integrations import.
from forge.utils import ssl_hygiene as _ssl_hygiene  # noqa: F401,E402

# Install the httpx / httpcore / urllib3 / requests query-string secret
# redaction filter at package import so every entry point (CLI, webui,
# api, distributed worker, TUI, migration scripts, provider subprocesses)
# inherits it. Previously the filter installed only when forge.cli was
# imported, so any non-CLI entry emitted secret query params unredacted.
# See forge/utils/log_redaction.py for the filter definition.
import logging as _logging  # noqa: E402

_logging.getLogger("httpx").setLevel(_logging.WARNING)
_logging.getLogger("httpcore").setLevel(_logging.WARNING)

from forge.utils.log_redaction import (  # noqa: E402
    install_query_redaction_filter as _install_query_redaction_filter,
)

_install_query_redaction_filter()

# Extend the filter to cover urllib.request / aiohttp / curl_cffi loggers too —
# these emit URLs from Phase 0 KB fetchers and subdomain enumeration paths.
_install_query_redaction_filter(
    (
        "urllib.request",
        "urllib3.connectionpool",
        "aiohttp.client",
        "curl_cffi",
        "curl_cffi.requests",
    )
)
