"""EPSS exploit-prediction score fetcher.

Cyentia publishes the daily EPSS score drop as a gzipped CSV. We fetch
it directly, decompress, parse the three-column CSV (``cve``, ``epss``,
``percentile``), and persist a compact JSON index. The payload powers
CVE prioritization downstream and never includes raw CSV bytes.

Output: ``imports/epss-scores.local.json`` with ``_meta`` plus parsed
items; also a ``high_risk`` list of CVE ids above an EPSS threshold.
"""

from __future__ import annotations

import csv
import gzip
import io
from pathlib import Path
from typing import Any

from forge.feeds.base import BaseFeedFetcher


_EPSS_ENDPOINT = "https://epss.cyentia.com/epss_scores-current.csv.gz"

# Cyentia publishes daily; EPSS scores change slowly. A tiny delay keeps
# the autopilot polite without hurting fetch latency.
_EPSS_RATE_LIMIT_SECONDS = 0.5

# Full EPSS corpus is ~250k rows today. 500k is a safe forward-looking
# cap that still fits in a few tens of MB of memory.
_MAX_EPSS_ROWS = 500_000

# EPSS score cutoff for the ``high_risk`` list. 0.5 keeps the list in
# the thousands range rather than tens of thousands; operators can
# cross-reference against findings in-process.
_HIGH_RISK_THRESHOLD = 0.5

# Guardrails on the extracted high-risk list so it stays bounded.
_MAX_HIGH_RISK = 20_000


class EpssFetcher(BaseFeedFetcher):
    """Fetch and parse the daily EPSS score drop (gzipped CSV)."""

    source_id = "epss"
    source_url = _EPSS_ENDPOINT
    output_filename = "epss-scores.local.json"
    schema_version = "forge.feeds.epss.v1"
    rate_limit_seconds = _EPSS_RATE_LIMIT_SECONDS

    def __init__(
        self,
        imports_dir: Path | str,
        *,
        high_risk_threshold: float = _HIGH_RISK_THRESHOLD,
        **kwargs: Any,
    ) -> None:
        super().__init__(imports_dir, **kwargs)
        self.high_risk_threshold = max(0.0, min(float(high_risk_threshold), 1.0))

    def _fetch(self, *, timeout: int) -> dict[str, Any]:
        raw = self._http_get_bytes(
            self.source_url,
            timeout=timeout,
            headers={"Accept": "application/gzip,text/csv"},
        )
        try:
            decompressed = gzip.decompress(raw)
        except OSError as exc:
            raise ValueError(f"gzip_decompress_failed:{exc}") from exc

        text = decompressed.decode("utf-8", errors="replace")
        items, high_risk, header_date = _parse_epss_csv(
            text, high_risk_threshold=self.high_risk_threshold
        )

        return {
            "items": items,
            "high_risk": high_risk,
            "_meta_extra": {
                "high_risk_threshold": self.high_risk_threshold,
                "high_risk_count": len(high_risk),
                "model_date": header_date,
            },
        }


def _parse_epss_csv(
    text: str, *, high_risk_threshold: float
) -> tuple[list[dict[str, Any]], list[str], str]:
    """Parse the EPSS CSV body.

    EPSS files start with a comment line like
    ``#model_version:v2024.03.01,score_date:2026-10-11T00:00:00+0000``
    followed by a header row ``cve,epss,percentile`` and the data. We
    tolerate missing fields by skipping the row.
    """
    model_date = ""
    buffer = io.StringIO(text)
    first_line = buffer.readline().strip()
    if first_line.startswith("#"):
        model_date = _extract_score_date(first_line)
    else:
        # No preamble; rewind so the DictReader sees the header.
        buffer.seek(0)

    reader = csv.DictReader(buffer)
    items: list[dict[str, Any]] = []
    high_risk: list[str] = []
    rows_seen = 0
    for row in reader:
        rows_seen += 1
        if rows_seen > _MAX_EPSS_ROWS:
            break
        cve_id = (row.get("cve") or "").strip().upper()
        if not cve_id.startswith("CVE-"):
            continue
        epss_value = _safe_float(row.get("epss"))
        percentile = _safe_float(row.get("percentile"))
        if epss_value is None or percentile is None:
            continue
        items.append(
            {
                "cve_id": cve_id,
                "epss": round(epss_value, 6),
                "percentile": round(percentile, 6),
            }
        )
        if (
            epss_value >= high_risk_threshold
            and len(high_risk) < _MAX_HIGH_RISK
        ):
            high_risk.append(cve_id)
    return items, high_risk, model_date


def _extract_score_date(preamble: str) -> str:
    """Parse ``#model_version:...,score_date:...`` into just the date."""
    for part in preamble.lstrip("#").split(","):
        key, _, value = part.partition(":")
        if key.strip() == "score_date":
            return value.strip()
    return ""


def _safe_float(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


__all__ = ["EpssFetcher"]
