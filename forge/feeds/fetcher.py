"""Orchestrator for :mod:`forge.feeds` fetchers.

:class:`FeedFetcher` composes every registered free-feed fetcher and
runs them in sequence. One fetcher's failure never aborts the loop —
each result is captured as ``{"status": "error", "error": "..."}`` so
the autopilot can continue through the remaining phases.
"""

from __future__ import annotations

import time
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from forge.feeds.base import BaseFeedFetcher
from forge.feeds.cisa_kev import CisaKevFetcher
from forge.feeds.epss import EpssFetcher
from forge.feeds.nuclei_templates import NucleiTemplateFetcher
from forge.feeds.nvd_cve import NvdCveFetcher
from forge.feeds.security_rss import SecurityRssFetcher
from forge.feeds.urlscan_public import UrlscanPublicFetcher


FEED_FETCHER_SCHEMA_VERSION = "forge.feeds.orchestrator.v1"

DEFAULT_TIMEOUT_PER_SOURCE = 60


class FeedFetcher:
    """Run all registered free-feed fetchers.

    Each fetcher runs independently; failures are captured as
    structured results. The orchestrator returns a schema-versioned
    summary dict with per-source entries and aggregate counts.
    """

    def __init__(
        self,
        imports_dir: Path | str,
        data_dir: Path | str,
        *,
        max_age_days: int = 7,
        fetchers: Iterable[BaseFeedFetcher] | None = None,
    ) -> None:
        self.imports_dir = Path(imports_dir)
        self.data_dir = Path(data_dir)
        self.max_age_days = max(1, int(max_age_days))
        if fetchers is not None:
            self.fetchers: list[BaseFeedFetcher] = list(fetchers)
        else:
            self.fetchers = [
                NvdCveFetcher(self.imports_dir, max_age_days=self.max_age_days),
                CisaKevFetcher(self.imports_dir),
                EpssFetcher(self.imports_dir),
                SecurityRssFetcher(self.imports_dir),
                NucleiTemplateFetcher(self.data_dir, imports_dir=self.imports_dir, max_age_days=self.max_age_days),
                UrlscanPublicFetcher(self.imports_dir),
            ]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def list_sources(self) -> list[dict[str, str]]:
        """Static catalog view: source ids, URLs, and output filenames."""
        rows: list[dict[str, str]] = []
        for fetcher in self.fetchers:
            rows.append(
                {
                    "source_id": fetcher.source_id,
                    "source_url": fetcher.source_url,
                    "output_filename": fetcher.output_filename,
                    "schema_version": (
                        fetcher.schema_version
                        or f"forge.feeds.{fetcher.source_id}.v1"
                    ),
                }
            )
        return rows

    def fetch_all(
        self,
        *,
        timeout_per_source: int = DEFAULT_TIMEOUT_PER_SOURCE,
    ) -> dict[str, Any]:
        """Run every registered fetcher and tally results."""
        timeout = max(5, int(timeout_per_source))
        started_at = _iso_now()
        results: dict[str, Any] = {}
        for fetcher in self.fetchers:
            source_id = fetcher.source_id
            try:
                result = fetcher.fetch(timeout=timeout)
            except Exception as exc:  # noqa: BLE001 — defense-in-depth
                result = {
                    "source_id": source_id,
                    "source_url": fetcher.source_url,
                    "status": "error",
                    "fetched_at": _iso_now(),
                    "count": 0,
                    "error": _bounded_error(exc),
                }
            results[source_id] = result
        finished_at = _iso_now()
        return self._summarize(results, started_at=started_at, finished_at=finished_at)

    def fetch_one(
        self,
        source_id: str,
        *,
        timeout_per_source: int = DEFAULT_TIMEOUT_PER_SOURCE,
    ) -> dict[str, Any]:
        """Run exactly one registered fetcher by id."""
        for fetcher in self.fetchers:
            if fetcher.source_id == source_id:
                timeout = max(5, int(timeout_per_source))
                try:
                    result = fetcher.fetch(timeout=timeout)
                except Exception as exc:  # noqa: BLE001
                    result = {
                        "source_id": source_id,
                        "source_url": fetcher.source_url,
                        "status": "error",
                        "fetched_at": _iso_now(),
                        "count": 0,
                        "error": _bounded_error(exc),
                    }
                started_at = result.get("fetched_at") or _iso_now()
                return self._summarize(
                    {source_id: result},
                    started_at=started_at,
                    finished_at=_iso_now(),
                )
        raise LookupError(f"unknown feed source: {source_id!r}")

    def status(self) -> dict[str, Any]:
        """Read-only snapshot of the most recent run per source.

        Reads only the ``_meta`` block from each on-disk output file so
        this is safe to call without triggering any network IO.
        """
        rows: list[dict[str, Any]] = []
        for fetcher in self.fetchers:
            out_path = self.imports_dir / fetcher.output_filename
            row: dict[str, Any] = {
                "source_id": fetcher.source_id,
                "source_url": fetcher.source_url,
                "output_filename": fetcher.output_filename,
                "exists": out_path.is_file(),
                "fetched_at": None,
                "item_count": 0,
                "schema_version": fetcher.schema_version or "",
            }
            if out_path.is_file():
                meta = _read_meta_only(out_path)
                row["fetched_at"] = meta.get("fetched_at")
                row["item_count"] = int(meta.get("item_count") or 0)
                row["schema_version"] = str(
                    meta.get("schema_version") or row["schema_version"]
                )
            rows.append(row)
        return {
            "schema_version": FEED_FETCHER_SCHEMA_VERSION,
            "imports_dir": str(self.imports_dir),
            "data_dir": str(self.data_dir),
            "sources": rows,
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _summarize(
        self,
        results: dict[str, Any],
        *,
        started_at: str,
        finished_at: str,
    ) -> dict[str, Any]:
        status_counts: dict[str, int] = {}
        total_items = 0
        for row in results.values():
            status = str(row.get("status") or "unknown")
            status_counts[status] = status_counts.get(status, 0) + 1
            total_items += int(row.get("count") or 0)
        overall = "ok"
        if status_counts.get("error") and not status_counts.get("ok"):
            overall = "error"
        elif status_counts.get("error"):
            overall = "partial"
        elif status_counts.get("skipped") and not status_counts.get("ok"):
            overall = "skipped"
        return {
            "schema_version": FEED_FETCHER_SCHEMA_VERSION,
            "started_at": started_at,
            "finished_at": finished_at,
            "overall_status": overall,
            "status_counts": status_counts,
            "total_item_count": total_items,
            "results": results,
        }


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _bounded_error(exc: BaseException, limit: int = 240) -> str:
    text = (str(exc).strip() or exc.__class__.__name__)[:limit]
    return text


def _read_meta_only(path: Path) -> dict[str, Any]:
    """Return the ``_meta`` block of a feed JSON file (never the items)."""
    import json  # noqa: PLC0415 — only needed in this helper

    try:
        with path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, ValueError):
        return {}
    if not isinstance(payload, dict):
        return {}
    meta = payload.get("_meta")
    if isinstance(meta, dict):
        return meta
    return {}


__all__ = ["FEED_FETCHER_SCHEMA_VERSION", "FeedFetcher"]
