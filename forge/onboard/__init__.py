"""FORGE interactive onboarding — operators never edit JSON manually.

This package wires three operator-facing surfaces so first-run and
daily-use workflows do not require hand-editing ``manifests/*.json``,
``imports/*.local.json``, or ``connections.json``:

- :mod:`forge.onboard.service_connections` — a plaintext connection
  manager under ``<data_dir>/connections.json`` for third-party
  services (GitHub, Supabase, Shodan, VirusTotal, Replit, URLScan,
  Censys, DeHashed). The operator can view the file directly and
  values are stored unencrypted per the explicit operator request.
  Credentials are only accepted through ``--token-env`` / ``--token-stdin``
  patterns, never positional ``--token VALUE`` arguments that would
  leak into shell history.
- :mod:`forge.onboard.target_wizard` — auto-detects seed type for a
  single string, allocates (or reuses) an engagement, and auto-updates
  the scope manifest so ``forge targets add example.com`` is a complete
  flow with no manual JSON edits.
- :mod:`forge.onboard.auto_scope` — scope expansion rules that promote
  feed-discovered subdomains, URLs, and reverse-DNS IPs into the
  manifest when they are related to already-scoped targets. Unrelated
  discoveries are returned as review-required candidates instead of
  silently expanding scope.
- :mod:`forge.onboard.github_spider` — GitHub repo spider that uses
  the GitHub REST API (via a stored PAT) to extract URLs, IPs,
  domains, and email addresses from repository metadata, README files,
  and GitHub Actions workflows. The parser is deliberately offline-safe
  for tests (mock HTTP) and returns ``target-feed.v1`` compatible items.

Every public operation remains ROE/scope aware. The onboarding layer
does not grant any live-execution capability by itself — it only
makes the "normalize scope + plumb credentials" paperwork less painful.
"""

from forge.onboard.service_connections import (
    CONNECTION_SCHEMA_VERSION,
    CONNECTIONS_FILENAME,
    SUPPORTED_SERVICES,
    ConnectionError,
    ServiceConnection,
    ServiceConnectionManager,
    read_env_credential,
    read_stdin_credential,
)
from forge.onboard.target_wizard import (
    TARGET_WIZARD_SCHEMA_VERSION,
    AddTargetResult,
    add_target,
    detect_seed_type,
)
from forge.onboard.auto_scope import (
    AUTO_SCOPE_SCHEMA_VERSION,
    ScopeExpansion,
    ScopeExpansionCandidate,
    expand_scope_from_feeds,
    load_scope_manifest,
    normalize_candidate,
    write_scope_manifest,
)
from forge.onboard.github_spider import (
    GITHUB_SPIDER_SCHEMA_VERSION,
    GitHubSpiderError,
    GitHubSpiderResult,
    extract_seeds_from_text,
    parse_github_repo_payload,
    spider_github,
)


__all__ = [
    "AUTO_SCOPE_SCHEMA_VERSION",
    "AddTargetResult",
    "CONNECTIONS_FILENAME",
    "CONNECTION_SCHEMA_VERSION",
    "ConnectionError",
    "GITHUB_SPIDER_SCHEMA_VERSION",
    "GitHubSpiderError",
    "GitHubSpiderResult",
    "SUPPORTED_SERVICES",
    "ScopeExpansion",
    "ScopeExpansionCandidate",
    "ServiceConnection",
    "ServiceConnectionManager",
    "TARGET_WIZARD_SCHEMA_VERSION",
    "add_target",
    "detect_seed_type",
    "expand_scope_from_feeds",
    "extract_seeds_from_text",
    "load_scope_manifest",
    "normalize_candidate",
    "parse_github_repo_payload",
    "read_env_credential",
    "read_stdin_credential",
    "spider_github",
    "write_scope_manifest",
]
