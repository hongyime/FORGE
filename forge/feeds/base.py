"""Shared base class for :mod:`forge.feeds` fetchers.

Each fetcher subclass sets ``source_id``, ``source_url``, and
``output_filename`` class attributes and implements ``_fetch``. The base
class owns the common contract: hard HTTP timeout, structured error
return, ``_meta`` block emission, and bounded JSON output.

Design notes:

- HTTP calls happen inside ``_http_get`` / ``_http_get_bytes`` so tests
  can monkeypatch either the module-level helpers or the method.
- No fetcher raises on network/parse failure. Every error is caught and
  returned as ``{"status": "error", "error": "..."}``. The orchestrator
  depends on this contract so one broken feed never aborts the loop.
- ``_write_json`` is atomic (write to ``.tmp`` sibling then rename) and
  truncates on each run. Feed data is a snapshot, not an append log.
"""

from __future__ import annotations

import json
import os
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx


# Hard cap on parsed JSON payloads so a surprise 1 GB response from an
# upstream mirror does not blow out memory. 100 MB matches the cap used
# by ``forge connectors import-cti`` for the same reason.
_MAX_RESPONSE_BYTES = 100 * 1024 * 1024


def _iso_now() -> str:
    """Return a timezone-aware UTC timestamp usable in JSON output."""
    return datetime.now(timezone.utc).isoformat()


@dataclass
class FeedFetchResult:
    """Normalized return shape from :meth:`BaseFeedFetcher.fetch`.

    Encoded as a plain dict by :meth:`to_dict` so the orchestrator and
    CLI can emit stable JSON without pulling in the dataclass.
    """

    source_id: str
    source_url: str
    status: str
    fetched_at: str
    count: int = 0
    path: str | None = None
    error: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "source_id": self.source_id,
            "source_url": self.source_url,
            "status": self.status,
            "fetched_at": self.fetched_at,
            "count": self.count,
        }
        if self.path is not None:
            payload["path"] = self.path
        if self.error:
            payload["error"] = self.error
        if self.details:
            payload["details"] = self.details
        return payload


class BaseFeedFetcher:
    """Base class for every free-feed fetcher.

    Subclasses must set:

    - ``source_id`` — short machine identifier used in CLI/JSON output.
    - ``source_url`` — canonical upstream URL for the ``_meta`` block.
    - ``output_filename`` — ``imports/<filename>`` destination.
    - ``schema_version`` — the ``_meta.schema_version`` written to disk.

    Subclasses implement ``_fetch(timeout)`` which returns a dict with
    ``items`` plus any extra top-level keys (e.g. ``urls``). The base
    class wraps that in ``_meta`` and writes it atomically.
    """

    source_id: str = ""
    source_url: str = ""
    output_filename: str = ""
    schema_version: str = ""
    feed_class: str = ""

    #: Minimum seconds to wait before the first HTTP request. Overridden
    #: per source so NVD stays below 5 reqs/30 sec and urlscan stays
    #: below 1 req/2 sec.
    rate_limit_seconds: float = 0.0

    def __init__(
        self,
        imports_dir: Path | str,
        *,
        sleep_fn: Callable[[float], None] | None = None,
        http_client_factory: Callable[..., httpx.Client] | None = None,
    ) -> None:
        self.imports_dir = Path(imports_dir)
        self._sleep_fn = sleep_fn or time.sleep
        self._http_client_factory = http_client_factory or httpx.Client

    # ------------------------------------------------------------------
    # Public contract
    # ------------------------------------------------------------------

    def fetch(self, *, timeout: int = 60) -> dict[str, Any]:
        """Fetch, parse, and persist. Returns a result dict.

        This method never raises. Network, parse, or write failures are
        caught and surfaced through the returned ``status``/``error``
        fields so the orchestrator can tally per-source outcomes.
        """
        if not self.source_id or not self.output_filename:
            raise RuntimeError(
                "Subclass must set source_id and output_filename"
            )

        self.imports_dir.mkdir(parents=True, exist_ok=True)
        self._pre_fetch_sleep()
        try:
            payload = self._fetch(timeout=timeout)
        except Exception as exc:  # noqa: BLE001 — fetchers must never raise
            return FeedFetchResult(
                source_id=self.source_id,
                source_url=self.source_url,
                status="error",
                fetched_at=_iso_now(),
                error=_bounded_error(exc),
            ).to_dict()

        if not isinstance(payload, Mapping):
            return FeedFetchResult(
                source_id=self.source_id,
                source_url=self.source_url,
                status="error",
                fetched_at=_iso_now(),
                error=f"invalid_payload_type:{type(payload).__name__}",
            ).to_dict()

        items = payload.get("items")
        if not isinstance(items, list):
            items = []
        count = len(items)
        extra: dict[str, Any] = {
            key: value for key, value in payload.items() if key != "items"
        }

        meta = {
            "schema_version": self.schema_version or self._default_schema(),
            "source_id": self.source_id,
            "source_url": self.source_url,
            "fetched_at": _iso_now(),
            "item_count": count,
        }
        if self.feed_class:
            meta["feed_class"] = self.feed_class
        extra_meta = payload.get("_meta_extra")
        if isinstance(extra_meta, Mapping):
            meta.update(extra_meta)
            extra.pop("_meta_extra", None)

        out_path = self.imports_dir / self.output_filename
        try:
            self._write_json(out_path, {"_meta": meta, **extra, "items": items})
        except Exception as exc:  # noqa: BLE001 — fetchers must never raise
            return FeedFetchResult(
                source_id=self.source_id,
                source_url=self.source_url,
                status="error",
                fetched_at=meta["fetched_at"],
                count=count,
                error=f"write_error:{_bounded_error(exc)}",
            ).to_dict()

        return FeedFetchResult(
            source_id=self.source_id,
            source_url=self.source_url,
            status="ok",
            fetched_at=meta["fetched_at"],
            count=count,
            path=str(out_path),
            details={
                k: v
                for k, v in extra.items()
                if isinstance(v, (int, float, str, bool))
            },
        ).to_dict()

    # ------------------------------------------------------------------
    # Subclass hooks
    # ------------------------------------------------------------------

    def _fetch(self, *, timeout: int) -> dict[str, Any]:
        """Subclass hook. Return a dict with at least an ``items`` list."""
        raise NotImplementedError

    def _default_schema(self) -> str:
        return f"forge.feeds.{self.source_id}.v1"

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _pre_fetch_sleep(self) -> None:
        """Enforce the fetcher's pre-request rate-limit floor."""
        if self.rate_limit_seconds > 0:
            self._sleep_fn(self.rate_limit_seconds)

    def _http_get_json(
        self,
        url: str,
        *,
        timeout: int,
        headers: Mapping[str, str] | None = None,
        params: Mapping[str, Any] | None = None,
    ) -> Any:
        """GET ``url`` and parse the response as JSON.

        Raises :class:`httpx.HTTPError` on transport failure and
        :class:`ValueError` on HTTP >= 400 or invalid JSON.
        """
        raw = self._http_get_bytes(
            url, timeout=timeout, headers=headers, params=params
        )
        try:
            return json.loads(raw.decode("utf-8", errors="replace"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid_json:{exc}") from exc

    def _http_get_bytes(
        self,
        url: str,
        *,
        timeout: int,
        headers: Mapping[str, str] | None = None,
        params: Mapping[str, Any] | None = None,
    ) -> bytes:
        """GET ``url`` and return the raw body. Enforces size cap."""
        request_headers = {"User-Agent": _user_agent()}
        if headers:
            request_headers.update(headers)
        with self._http_client_factory(
            timeout=timeout,
            follow_redirects=True,
            headers=request_headers,
        ) as client:
            response = client.get(url, params=dict(params or {}))
            status = getattr(response, "status_code", 0)
            if status >= 400:
                raise ValueError(f"http_{status}")
            content = response.content
            if content is None:
                return b""
            if len(content) > _MAX_RESPONSE_BYTES:
                raise ValueError(
                    f"response_too_large:{len(content)}>_{_MAX_RESPONSE_BYTES}"
                )
            return bytes(content)

    def _write_json(self, path: Path, payload: Mapping[str, Any]) -> None:
        """Atomically write ``payload`` as pretty JSON to ``path``."""
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = path.with_suffix(path.suffix + ".tmp")
        with tmp_path.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True, default=str)
            handle.flush()
            try:
                os.fsync(handle.fileno())
            except (AttributeError, OSError):
                # Not all tempfiles support fsync (StringIO wrappers in
                # tests); best-effort flush is enough.
                pass
        os.replace(tmp_path, path)


def _user_agent() -> str:
    """Honest-but-generic UA so free providers can rate-limit us fairly."""
    return os.environ.get(
        "FORGE_FEEDS_USER_AGENT",
        "forge-toolkit-feeds/1.0 (+https://github.com/forge-toolkit)",
    )


def _bounded_error(exc: BaseException, limit: int = 240) -> str:
    text = (str(exc).strip() or exc.__class__.__name__)[:limit]
    return text


__all__ = ["BaseFeedFetcher", "FeedFetchResult"]
