"""Supabase deep scanner.

Reads every table exposed by a Supabase project's PostgREST Data API
through an owned read-only API key and pulls seed-like strings out of
every column of every row. All extraction is delegated to
:mod:`forge.onboard.patterns` so URLs, bare domains, IPs, emails,
cloud references, phone numbers, and secret hits are all surfaced
through the same deduped shape as :class:`GitHubDeepScanner`.

Design constraints:

- The HTTP layer is injectable so tests run offline with mock payloads.
- The scanner is bounded. ``max_tables`` and ``max_rows_per_table``
  cap the walk. A single column body larger than ``max_text_bytes`` is
  truncated before extraction so the scanner cannot blow up memory
  because a Supabase cell happens to hold a dump.
- No row data is persisted. Only extracted seeds + redacted secret hits
  are returned. Column names are kept in the per-table summary so
  operators can tell *which* table a secret landed in without the
  scanner handing back the raw row.
- Supabase REST responses use ``Content-Range`` to indicate pagination.
  The scanner honours it and iterates in bounded page sizes.
- Keys passed in via :class:`SupabaseDeepScanner`'s constructor are
  **never** echoed in error messages, logs, or audit fields.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Mapping, Sequence
from urllib.parse import urlsplit

from forge.onboard.patterns import (
    classify_cloud_reference,
    extract_seeds_from_text,
    scan_secrets,
)


SUPABASE_DEEP_SCANNER_SCHEMA_VERSION = "forge.supabase_deep_scanner.v1"


#: Maximum per-cell text size handed to :mod:`forge.onboard.patterns`.
#: Larger cells are truncated to avoid catastrophic regex blow-up on
#: megabyte-sized JSON blobs that occasionally land in Supabase.
_DEFAULT_MAX_TEXT_BYTES = 262_144

#: Max rows retained in memory for a single table before yielding.
_DEFAULT_PAGE_SIZE = 1000

#: Column names that frequently carry target-like identifiers; the
#: scanner reports these in the per-table summary so operators can
#: notice when a seed came from a notably-named field.
_SIGNIFICANT_COLUMN_HINTS: frozenset[str] = frozenset(
    {
        "email",
        "emails",
        "username",
        "handle",
        "name",
        "full_name",
        "phone",
        "mobile",
        "domain",
        "host",
        "url",
        "endpoint",
        "ip",
        "ip_address",
        "address",
        "owner",
        "contact",
        "profile_url",
    }
)


class SupabaseScannerError(RuntimeError):
    """Raised for configuration errors inside the scanner (not HTTP errors)."""


@dataclass
class SupabaseTableSummary:
    """Per-table statistics."""

    name: str
    rows_scanned: int = 0
    seeds_added: int = 0
    secret_hits: int = 0
    columns_sampled: list[str] = field(default_factory=list)
    significant_columns: list[str] = field(default_factory=list)
    truncated: bool = False
    status: str = "ok"
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SupabaseScanResult:
    """Aggregate output of :meth:`SupabaseDeepScanner.scan_all`."""

    schema_version: str = SUPABASE_DEEP_SCANNER_SCHEMA_VERSION
    project_ref: str = ""
    base_url: str = ""
    tables_total: int = 0
    tables_scanned: int = 0
    rows_scanned: int = 0
    seeds: list[dict[str, Any]] = field(default_factory=list)
    secret_hits: list[dict[str, Any]] = field(default_factory=list)
    tables: list[SupabaseTableSummary] = field(default_factory=list)
    source_errors: list[dict[str, Any]] = field(default_factory=list)
    endpoints_called: list[str] = field(default_factory=list)
    started_at: str = ""
    finished_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["tables"] = [t.to_dict() for t in self.tables]
        return payload


class SupabaseDeepScanner:
    """Scan every table exposed by a Supabase project.

    Supabase's Data API is served at ``https://<project_ref>.supabase.co``.
    The scanner:

    1. ``GET /rest/v1/`` — the PostgREST root responds with an
       OpenAPI document whose ``paths`` keys enumerate every exposed
       table.
    2. For each table: ``GET /rest/v1/<table>?select=*`` with
       pagination via ``Range: 0-<page>`` / ``Content-Range``.
    3. Every string cell is handed to
       :func:`forge.onboard.patterns.extract_seeds_from_text`.
       Significant column names are recorded for operator triage.
    4. Secret-looking values are reported via
       :func:`forge.onboard.patterns.scan_secrets` — never the raw
       cell body.

    The scanner never writes any data back to Supabase. All methods
    are read-only PostgREST GETs.
    """

    def __init__(
        self,
        project_ref: str,
        api_key: str,
        *,
        http_get: Callable[..., Any] | None = None,
        base_url: str | None = None,
        max_tables: int = 1000,
        max_rows_per_table: int = 100_000,
        page_size: int = _DEFAULT_PAGE_SIZE,
        max_text_bytes: int = _DEFAULT_MAX_TEXT_BYTES,
        extra_schemas: Sequence[str] = (),
    ) -> None:
        project = str(project_ref or "").strip().lower()
        if not project:
            raise SupabaseScannerError(
                "Supabase deep scanner requires a non-empty project_ref"
            )
        if not re.match(r"^[a-z0-9][a-z0-9\-]*$", project):
            raise SupabaseScannerError(
                f"invalid Supabase project_ref {project!r}"
            )
        key_value = str(api_key or "").strip()
        if not key_value:
            raise SupabaseScannerError(
                "Supabase deep scanner requires a non-empty API key"
            )
        self.project_ref = project
        self._api_key = key_value
        self.base_url = (base_url or f"https://{project}.supabase.co").rstrip("/")
        self._http = http_get or _default_http_get
        self.max_tables = max(1, int(max_tables))
        self.max_rows_per_table = max(1, int(max_rows_per_table))
        self.page_size = max(1, min(int(page_size), 10_000))
        self.max_text_bytes = max(4096, int(max_text_bytes))
        self.extra_schemas = tuple(
            s.strip() for s in extra_schemas if s and s.strip()
        )
        self.headers = {
            "apikey": self._api_key,
            "Authorization": f"Bearer {self._api_key}",
            "Accept": "application/json",
        }

    # ------------------------------------------------------------------
    # Public entry points
    # ------------------------------------------------------------------

    def scan_all(self) -> SupabaseScanResult:
        """Discover tables and scan each one."""
        result = SupabaseScanResult(
            project_ref=self.project_ref,
            base_url=self.base_url,
            started_at=_now_iso(),
        )
        tables = self._discover_tables(result=result)
        result.tables_total = len(tables)
        if not tables:
            result.finished_at = _now_iso()
            return result
        seen_seed_keys: set[tuple[str, str]] = set()
        for table in tables:
            if result.tables_scanned >= self.max_tables:
                break
            table_summary = self._scan_table(
                table,
                result=result,
                seen_seed_keys=seen_seed_keys,
            )
            result.tables.append(table_summary)
            result.tables_scanned += 1
        self._dedupe_and_classify(result)
        result.finished_at = _now_iso()
        return result

    def _scan_tables(
        self,
        result: SupabaseScanResult,
        seen_seed_keys: set[tuple[str, str]],
    ) -> list[SupabaseTableSummary]:
        """Discover and scan every table. Used in isolation by tests."""
        summaries: list[SupabaseTableSummary] = []
        for table in self._discover_tables(result=result):
            if result.tables_scanned >= self.max_tables:
                break
            summary = self._scan_table(
                table,
                result=result,
                seen_seed_keys=seen_seed_keys,
            )
            summaries.append(summary)
            result.tables_scanned += 1
        return summaries

    def _scan_all_rows(
        self,
        table: str,
        *,
        result: SupabaseScanResult,
        seen_seed_keys: set[tuple[str, str]],
    ) -> SupabaseTableSummary:
        """Paginate through every row in ``table`` and extract seeds."""
        return self._scan_table(
            table, result=result, seen_seed_keys=seen_seed_keys
        )

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------

    def _discover_tables(self, *, result: SupabaseScanResult) -> list[str]:
        """GET the PostgREST OpenAPI root and extract table paths."""
        url = f"{self.base_url}/rest/v1/"
        response = self._call(url, result=result, context="discover_tables")
        if response is None:
            return []
        body = response.get("json")
        if not isinstance(body, Mapping):
            return []
        paths = body.get("paths")
        tables: list[str] = []
        if isinstance(paths, Mapping):
            for raw_path in paths.keys():
                name = _table_name_from_path(str(raw_path))
                if name:
                    tables.append(name)
        definitions = body.get("definitions")
        if isinstance(definitions, Mapping):
            for name in definitions.keys():
                normalized = _normalize_table_name(str(name))
                if normalized and normalized not in tables:
                    tables.append(normalized)
        # Preserve stable ordering so repeated scans produce stable output.
        unique: list[str] = []
        seen: set[str] = set()
        for name in tables:
            if name in seen:
                continue
            seen.add(name)
            unique.append(name)
        return unique

    # ------------------------------------------------------------------
    # Per-table scan
    # ------------------------------------------------------------------

    def _scan_table(
        self,
        table: str,
        *,
        result: SupabaseScanResult,
        seen_seed_keys: set[tuple[str, str]],
    ) -> SupabaseTableSummary:
        """Paginate through ``table`` using Range/Content-Range."""
        summary = SupabaseTableSummary(name=table)
        if not table:
            summary.status = "skipped"
            summary.detail = "empty_table_name"
            return summary
        row_offset = 0
        columns_seen: list[str] = []
        columns_set: set[str] = set()
        significant_columns: set[str] = set()
        rows_added = 0
        new_seeds_added = 0
        new_secret_hits = 0

        while row_offset < self.max_rows_per_table:
            page_cap = min(
                self.page_size,
                self.max_rows_per_table - row_offset,
            )
            if page_cap <= 0:
                break
            response = self._fetch_rows(
                table,
                offset=row_offset,
                limit=page_cap,
                result=result,
            )
            if response is None:
                summary.status = "error"
                summary.detail = f"page_offset={row_offset}"
                return summary
            body = response.get("json")
            if not isinstance(body, list):
                summary.status = "error"
                summary.detail = "non_array_body"
                return summary
            if not body:
                break
            for row in body:
                if not isinstance(row, Mapping):
                    continue
                rows_added += 1
                row_label = (
                    f"supabase:{self.project_ref}:{table}:row_{row_offset + rows_added}"
                )
                for column, value in row.items():
                    col = str(column)
                    if col not in columns_set:
                        columns_set.add(col)
                        columns_seen.append(col)
                    if col.lower() in _SIGNIFICANT_COLUMN_HINTS:
                        significant_columns.add(col.lower())
                    for text_fragment in _coerce_text_fragments(
                        value, max_bytes=self.max_text_bytes
                    ):
                        source_label = f"{row_label}:{col}"
                        new_seeds_added += self._extract_from_fragment(
                            text_fragment,
                            source_label=source_label,
                            result=result,
                            seen_seed_keys=seen_seed_keys,
                        )
                        secrets = scan_secrets(
                            text_fragment,
                            source_label=source_label,
                        )
                        for hit in secrets:
                            hit_payload = dict(hit)
                            hit_payload["table"] = table
                            hit_payload["column"] = col
                            hit_payload["project_ref"] = self.project_ref
                            result.secret_hits.append(hit_payload)
                            new_secret_hits += 1
                    # Also classify bare values that look like cloud refs
                    # but didn't match in-text regex (e.g. a dedicated
                    # `aws_account_id` column that contains just the id).
                    if isinstance(value, str) and value and len(value) <= 80:
                        classification = classify_cloud_reference(value.strip())
                        if classification is not None:
                            payload = {
                                "target_type": "cloud_ref",
                                "target_value": classification["canonical_value"],
                                "type": "cloud_ref",
                                "value": classification["canonical_value"],
                                "confidence": "medium",
                                "source_kind": "supabase_scanner",
                                "source_group": "supabase_scanner",
                                "provenance": f"{row_label}:{col}",
                                "first_seen_at": _now_iso(),
                                "source_detail": classification["provider"],
                            }
                            key = (
                                payload["target_type"],
                                payload["target_value"],
                            )
                            if key not in seen_seed_keys:
                                seen_seed_keys.add(key)
                                result.seeds.append(payload)
                                new_seeds_added += 1

            row_offset += len(body)
            result.rows_scanned += len(body)
            if len(body) < page_cap:
                # Short page => no more rows.
                break

        summary.rows_scanned = row_offset
        summary.seeds_added = new_seeds_added
        summary.secret_hits = new_secret_hits
        summary.columns_sampled = columns_seen[:64]
        summary.significant_columns = sorted(significant_columns)
        if row_offset >= self.max_rows_per_table:
            summary.truncated = True
            summary.detail = "max_rows_per_table_cap_reached"
        return summary

    def _extract_from_fragment(
        self,
        text: str,
        *,
        source_label: str,
        result: SupabaseScanResult,
        seen_seed_keys: set[tuple[str, str]],
    ) -> int:
        """Run pattern extraction and append non-duplicate seeds."""
        if not text:
            return 0
        candidates = extract_seeds_from_text(
            text, source_label=source_label
        )
        appended = 0
        for seed in candidates:
            key = (
                str(seed.get("target_type") or ""),
                str(seed.get("target_value") or ""),
            )
            if key in seen_seed_keys:
                continue
            seen_seed_keys.add(key)
            payload = dict(seed)
            payload["source_kind"] = "supabase_scanner"
            payload["source_group"] = "supabase_scanner"
            result.seeds.append(payload)
            appended += 1
        return appended

    # ------------------------------------------------------------------
    # HTTP
    # ------------------------------------------------------------------

    def _fetch_rows(
        self,
        table: str,
        *,
        offset: int,
        limit: int,
        result: SupabaseScanResult,
    ) -> dict[str, Any] | None:
        """Fetch one page of rows using Range/Content-Range pagination."""
        url = f"{self.base_url}/rest/v1/{table}?select=*"
        headers = dict(self.headers)
        headers["Range-Unit"] = "items"
        headers["Range"] = f"{offset}-{offset + limit - 1}"
        try:
            response = self._http(url, headers=headers)
        except Exception as exc:  # noqa: BLE001
            result.source_errors.append(
                {
                    "context": f"supabase:{self.project_ref}:{table}:fetch",
                    "detail": f"{exc.__class__.__name__}: {str(exc)[:200]}",
                }
            )
            return None
        if not isinstance(response, Mapping):
            result.source_errors.append(
                {
                    "context": f"supabase:{self.project_ref}:{table}:fetch",
                    "detail": "http_get did not return a mapping",
                }
            )
            return None
        status = int(response.get("status", 0))
        if status >= 400:
            result.source_errors.append(
                {
                    "context": f"supabase:{self.project_ref}:{table}:fetch",
                    "detail": f"HTTP {status}",
                }
            )
            return None
        return dict(response)

    def _call(
        self,
        url: str,
        *,
        result: SupabaseScanResult,
        context: str,
    ) -> dict[str, Any] | None:
        if len(result.endpoints_called) < 2000:
            result.endpoints_called.append(url)
        try:
            response = self._http(url, headers=dict(self.headers))
        except Exception as exc:  # noqa: BLE001
            result.source_errors.append(
                {
                    "context": context,
                    "detail": f"{exc.__class__.__name__}: {str(exc)[:200]}",
                }
            )
            return None
        if not isinstance(response, Mapping):
            result.source_errors.append(
                {"context": context, "detail": "http_get did not return a mapping"}
            )
            return None
        status = int(response.get("status", 0))
        if status >= 400:
            result.source_errors.append(
                {"context": context, "detail": f"HTTP {status}"}
            )
            return None
        return dict(response)

    # ------------------------------------------------------------------
    # Final cleanup
    # ------------------------------------------------------------------

    def _dedupe_and_classify(self, result: SupabaseScanResult) -> None:
        """Collapse duplicate seeds across tables."""
        unique: dict[tuple[str, str], dict[str, Any]] = {}
        for seed in result.seeds:
            key = (
                str(seed.get("target_type") or ""),
                str(seed.get("target_value") or ""),
            )
            if not key[0] or not key[1]:
                continue
            unique.setdefault(key, seed)
        result.seeds = list(unique.values())

        unique_secrets: list[dict[str, Any]] = []
        secret_keys: set[tuple[str, str, str, str]] = set()
        for secret in result.secret_hits:
            label = str(secret.get("label") or "")
            table = str(secret.get("table") or "")
            column = str(secret.get("column") or "")
            sample = str(secret.get("redacted_sample") or "")
            key = (label, table, column, sample)
            if key in secret_keys:
                continue
            secret_keys.add(key)
            unique_secrets.append(secret)
        result.secret_hits = unique_secrets


# ----------------------------------------------------------------------
# Module-level helpers
# ----------------------------------------------------------------------


def _table_name_from_path(path: str) -> str:
    """Extract the table name from a PostgREST OpenAPI path.

    ``/orders`` -> ``orders``. ``/orders/{id}`` -> ``orders``.
    ``/rpc/foo`` is skipped (RPC endpoints are not tables).
    """
    text = str(path or "").strip()
    if not text or not text.startswith("/"):
        return ""
    stripped = text.lstrip("/")
    if stripped.startswith("rpc/"):
        return ""
    first = stripped.split("/", 1)[0]
    return _normalize_table_name(first)


def _normalize_table_name(value: str) -> str:
    text = str(value or "").strip()
    if not text or text.startswith("{"):
        return ""
    # Supabase sometimes includes schema qualifiers like ``public.orders``;
    # the Data API only accepts the schemaless name for the ``public``
    # schema, so strip the ``public.`` prefix.
    if text.lower().startswith("public."):
        text = text.split(".", 1)[1]
    return text


def _coerce_text_fragments(value: Any, *, max_bytes: int) -> Iterable[str]:
    """Yield text fragments from a Supabase cell value.

    - Strings are yielded as-is (truncated to ``max_bytes``).
    - Lists/tuples are walked recursively.
    - Dicts are flattened: both keys and values become fragments.
    - Numbers, bools, None are converted to str() when non-empty.
    """
    stack: list[Any] = [value]
    while stack:
        current = stack.pop()
        if current is None:
            continue
        if isinstance(current, str):
            text = current if len(current) <= max_bytes else current[:max_bytes]
            if text.strip():
                yield text
            continue
        if isinstance(current, bool):
            continue
        if isinstance(current, (int, float)):
            text = str(current)
            if text.strip():
                yield text
            continue
        if isinstance(current, (list, tuple, set)):
            # Keep bounded. A million-element array is pathological; we
            # look at the first 1000 to catch realistic cases.
            for item in list(current)[:1000]:
                stack.append(item)
            continue
        if isinstance(current, Mapping):
            # Serialize once so URL/IP patterns in nested JSON still
            # match. Also walk values individually to catch embedded
            # cloud references.
            try:
                serialized = json.dumps(current, default=str)
            except (TypeError, ValueError):
                serialized = ""
            if serialized:
                text = (
                    serialized
                    if len(serialized) <= max_bytes
                    else serialized[:max_bytes]
                )
                yield text
            for sub in list(current.values())[:1000]:
                stack.append(sub)
            continue
        text = str(current)
        if text.strip():
            yield text[:max_bytes]


def _default_http_get(url: str, *, headers: Mapping[str, str]) -> dict[str, Any]:
    """Default HTTP getter — thin wrapper around :mod:`httpx`."""
    import httpx  # noqa: PLC0415

    with httpx.Client(timeout=30.0) as client:
        resp = client.get(url, headers=dict(headers))
    headers_dict = dict(resp.headers)
    body: Any = None
    text: str = ""
    try:
        body = resp.json()
    except (ValueError, json.JSONDecodeError):
        text = resp.text
    return {
        "status": resp.status_code,
        "headers": headers_dict,
        "json": body,
        "text": text,
    }


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


__all__ = [
    "SUPABASE_DEEP_SCANNER_SCHEMA_VERSION",
    "SupabaseDeepScanner",
    "SupabaseScanResult",
    "SupabaseScannerError",
    "SupabaseTableSummary",
]
