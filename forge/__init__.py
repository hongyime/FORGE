VERSION = "7.2.0"

# Capture stdlib TLS defaults before optional third-party integrations import.
from forge.utils import ssl_hygiene as _ssl_hygiene  # noqa: F401,E402
