"""FORGE free/no-key threat-intel feed fetchers.

Every fetcher in this package is:

- Free. No API key required to use the public endpoint.
- Passive. One-shot HTTP GET (or shallow git pull for nuclei-templates).
- Bounded. Hard timeouts, rate-limited, size-capped parsing.
- Local-only writes. Output lands in ``imports/<name>.local.json``,
  which is gitignored, so operators can rerun safely without
  accidentally committing feed data.

Each fetcher writes a ``_meta`` block (schema version, source url,
fetched_at timestamp, item count) alongside parsed items. Extracted
references and observations remain source-classified enrichment; they
must not become live targets without a separate asset-linkage check.

Top-level entry points:

- :class:`forge.feeds.fetcher.FeedFetcher` — orchestrator used by the
  CLI and the autopilot loop.
- :func:`fetch_all_free_feeds` — convenience wrapper for one-off calls.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from forge.feeds.cisa_kev import CisaKevFetcher
from forge.feeds.epss import EpssFetcher
from forge.feeds.fetcher import FeedFetcher
from forge.feeds.nuclei_templates import NucleiTemplateFetcher
from forge.feeds.nvd_cve import NvdCveFetcher
from forge.feeds.security_rss import SecurityRssFetcher
from forge.feeds.urlscan_public import UrlscanPublicFetcher


def fetch_all_free_feeds(
    imports_dir: Path | str,
    *,
    data_dir: Path | str | None = None,
    max_age_days: int = 7,
    timeout_per_source: int = 60,
) -> dict[str, Any]:
    """Run every free-feed fetcher once.

    ``imports_dir`` is where the ``*.local.json`` files land. ``data_dir``
    is only used by the nuclei-templates fetcher for the local clone; it
    defaults to a sibling ``.forge_data`` directory beside imports when
    not supplied.
    """
    imports_path = Path(imports_dir)
    data_path = Path(data_dir) if data_dir is not None else imports_path.parent / ".forge_data"
    fetcher = FeedFetcher(
        imports_dir=imports_path,
        data_dir=data_path,
        max_age_days=max_age_days,
    )
    return fetcher.fetch_all(timeout_per_source=timeout_per_source)


__all__ = [
    "CisaKevFetcher",
    "EpssFetcher",
    "FeedFetcher",
    "NucleiTemplateFetcher",
    "NvdCveFetcher",
    "SecurityRssFetcher",
    "UrlscanPublicFetcher",
    "fetch_all_free_feeds",
]
