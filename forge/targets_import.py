from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx

from forge.config import ForgeConfig
from forge.db.session import get_engagement_db
from forge.engagement_ids import allocate_engagement_id, numeric_engagement_db_files

TARGET_FEED_SCHEMA_VERSION = "target-feed.v1"
SUPPORTED_TARGET_TYPES = {"domain", "url"}


@dataclass(frozen=True)
class TargetFeedItem:
    target_type: str
    target_value: str
    canonical_value: str
    target_key: str
    source_kind: str
    confidence: float
    first_seen_at: str
    provenance: str


@dataclass(frozen=True)
class TargetImportResult:
    engagement_id: int | None
    target_type: str
    target_value: str
    target_key: str
    scope_manifest: Path | None
    created: bool
    started: bool
    dry_run: bool


def load_target_feed(
    *,
    feed_url: str | None,
    feed_file: Path | None,
    auth_header_env: str | None,
    limit: int | None,
) -> list[TargetFeedItem]:
    if bool(feed_url) == bool(feed_file):
        raise ValueError("specify exactly one of --feed-url or --feed-file")
    payload = _fetch_feed(feed_url, auth_header_env) if feed_url else _read_feed_file(feed_file)
    if not isinstance(payload, dict):
        raise ValueError("target feed must decode to a JSON object")
    schema_version = str(payload.get("schema_version") or "").strip()
    if schema_version != TARGET_FEED_SCHEMA_VERSION:
        raise ValueError(
            f"unsupported target feed schema_version={schema_version!r}; "
            f"expected {TARGET_FEED_SCHEMA_VERSION!r}"
        )
    raw_items = payload.get("items")
    if not isinstance(raw_items, list):
        raise ValueError("target feed items must be a list")

    max_items = _normalize_limit(limit)
    items: list[TargetFeedItem] = []
    seen: set[str] = set()
    for raw_item in raw_items:
        if len(items) >= max_items:
            break
        item = _coerce_feed_item(raw_item)
        if item is None or item.target_key in seen:
            continue
        seen.add(item.target_key)
        items.append(item)
    return items


def import_targets(
    *,
    feed_url: str | None,
    feed_file: Path | None,
    auth_header_env: str | None,
    roe_id: str | None,
    start: bool,
    dry_run: bool,
    limit: int | None,
    max_iter: int,
    start_limit: int | None = None,
    config: ForgeConfig | None = None,
) -> list[TargetImportResult]:
    if start and not str(roe_id or "").strip():
        raise ValueError("--start requires --roe-id so live execution is authorized")
    cfg = config or ForgeConfig.load()
    items = load_target_feed(
        feed_url=feed_url,
        feed_file=feed_file,
        auth_header_env=auth_header_env,
        limit=limit,
    )
    results: list[TargetImportResult] = []
    starts_remaining = _normalize_start_limit(start_limit)
    for item in items:
        if dry_run:
            results.append(
                TargetImportResult(
                    engagement_id=None,
                    target_type=item.target_type,
                    target_value=item.canonical_value,
                    target_key=item.target_key,
                    scope_manifest=None,
                    created=False,
                    started=False,
                    dry_run=True,
                )
            )
            continue

        engagement_id, created = _create_or_reuse_engagement(cfg, item)
        manifest_path = _write_scope_manifest(cfg, engagement_id, item, roe_id)
        started = False
        if (
            start
            and starts_remaining != 0
            and not _has_passive_kill_chain_run(cfg, engagement_id, item.canonical_value)
        ):
            _start_passive_kill_chain(
                engagement_id=engagement_id,
                seed=item.canonical_value,
                roe_id=str(roe_id or "").strip(),
                scope_manifest=manifest_path,
                max_iter=max_iter,
            )
            started = True
            if starts_remaining is not None:
                starts_remaining -= 1
        results.append(
            TargetImportResult(
                engagement_id=engagement_id,
                target_type=item.target_type,
                target_value=item.canonical_value,
                target_key=item.target_key,
                scope_manifest=manifest_path,
                created=created,
                started=started,
                dry_run=False,
            )
        )
    return results


def _fetch_feed(feed_url: str | None, auth_header_env: str | None) -> Any:
    assert feed_url is not None
    headers: dict[str, str] = {}
    if auth_header_env:
        env_name = str(auth_header_env).strip()
        if not env_name:
            raise ValueError("--auth-header-env cannot be blank")
        header_value = os.environ.get(env_name)
        if not header_value:
            raise ValueError(f"auth header environment variable is not set: {env_name}")
        if ":" in header_value:
            name, value = header_value.split(":", 1)
            if name.strip() and value.strip():
                headers[name.strip()] = value.strip()
            else:
                raise ValueError(f"invalid auth header value in environment variable: {env_name}")
        else:
            headers["X-Monitor-Key"] = header_value
    response = httpx.get(feed_url, headers=headers, timeout=15.0)
    response.raise_for_status()
    return response.json()


def _read_feed_file(feed_file: Path | None) -> Any:
    assert feed_file is not None
    path = Path(feed_file).expanduser()
    if path.stat().st_size > 2_097_152:
        raise ValueError("target feed file is too large: exceeds 2 MiB cap")
    return json.loads(path.read_text(encoding="utf-8"))


def _normalize_limit(limit: int | None) -> int:
    if limit is None:
        return 100
    value = int(limit)
    if value <= 0:
        raise ValueError("--limit must be greater than zero")
    return min(value, 1_000)


def _normalize_start_limit(start_limit: int | None) -> int | None:
    if start_limit is None:
        return None
    value = int(start_limit)
    if value <= 0:
        raise ValueError("--start-limit must be greater than zero")
    return value


def _coerce_feed_item(raw_item: object) -> TargetFeedItem | None:
    if not isinstance(raw_item, dict):
        return None
    target_type = str(raw_item.get("target_type") or "").strip().lower()
    if target_type not in SUPPORTED_TARGET_TYPES:
        return None
    target_value = str(raw_item.get("target_value") or "").strip()
    canonical_value = _canonical_target_value(target_type, target_value)
    if not canonical_value:
        return None
    target_key = external_target_key(target_type, canonical_value)
    return TargetFeedItem(
        target_type=target_type,
        target_value=target_value,
        canonical_value=canonical_value,
        target_key=target_key,
        source_kind=_bounded_text(raw_item.get("source_kind"), 80),
        confidence=_coerce_confidence(raw_item.get("confidence")),
        first_seen_at=_bounded_text(raw_item.get("first_seen_at"), 80),
        provenance=_bounded_text(raw_item.get("provenance"), 240),
    )


def _canonical_target_value(target_type: str, value: str) -> str:
    text = " ".join(str(value or "").strip().split())
    if not text:
        return ""
    if target_type == "domain":
        if "://" in text or "/" in text or "@" in text:
            return ""
        return text.lower().strip(".")
    parsed = urlsplit(text)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        return ""
    host = (parsed.hostname or "").lower().strip(".")
    if not host:
        return ""
    netloc = host
    if parsed.port:
        netloc = f"{host}:{parsed.port}"
    path = parsed.path or "/"
    return urlunsplit((parsed.scheme.lower(), netloc, path, "", ""))


def external_target_key(target_type: str, canonical_target_value: str) -> str:
    raw = f"{target_type}:{canonical_target_value}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _coerce_confidence(value: object) -> float:
    try:
        confidence = float(value)
    except (TypeError, ValueError):
        return 0.5
    return min(max(confidence, 0.0), 1.0)


def _bounded_text(value: object, max_len: int) -> str:
    return " ".join(str(value or "").strip().split())[:max_len]


def _create_or_reuse_engagement(
    cfg: ForgeConfig,
    item: TargetFeedItem,
) -> tuple[int, bool]:
    existing_id = _find_existing_engagement_id(cfg, item.target_key)
    if existing_id is not None:
        return existing_id, False

    engagement_id = allocate_engagement_id(cfg.data_dir)
    db_path = cfg.engagement_db_path(str(engagement_id))
    conn = get_engagement_db(db_path)
    try:
        now = datetime.now(timezone.utc).isoformat()
        metadata = {
            "external_feed": TARGET_FEED_SCHEMA_VERSION,
            "external_target_key": item.target_key,
            "source_kind": item.source_kind,
            "provenance_summary": item.provenance,
            "target_type": item.target_type,
            "target_value": item.canonical_value,
            "first_seen_at": item.first_seen_at,
            "confidence": item.confidence,
            "imported_at": now,
        }
        conn.execute(
            """
            INSERT INTO engagements (id, name, scope_json, status, operator, metadata_json)
            VALUES (?, ?, ?, 'ACTIVE', ?, ?)
            """,
            (
                engagement_id,
                f"external-target-{item.target_key[:12]}",
                json.dumps(_scope_json_for_item(item), sort_keys=True),
                cfg.operator,
                json.dumps(metadata, sort_keys=True),
            ),
        )
        conn.execute(
            """
            INSERT OR IGNORE INTO engagement_seeds
                (engagement_id, seed_value, seed_type, source, confidence, metadata_json)
            VALUES (?, ?, ?, 'scope', ?, ?)
            """,
            (
                engagement_id,
                item.canonical_value,
                item.target_type,
                item.confidence,
                json.dumps(
                    {
                        "external_feed": TARGET_FEED_SCHEMA_VERSION,
                        "external_target_key": item.target_key,
                    },
                    sort_keys=True,
                ),
            ),
        )
        conn.commit()
    finally:
        conn.close()
    return engagement_id, True


def _find_existing_engagement_id(cfg: ForgeConfig, target_key: str) -> int | None:
    for db_path in numeric_engagement_db_files(cfg.data_dir):
        conn = sqlite3.connect(db_path)
        try:
            row = conn.execute(
                "SELECT id, metadata_json FROM engagements ORDER BY id LIMIT 1"
            ).fetchone()
        except sqlite3.Error:
            continue
        finally:
            conn.close()
        if not row:
            continue
        try:
            metadata = json.loads(str(row[1] or "{}"))
        except json.JSONDecodeError:
            metadata = {}
        if isinstance(metadata, dict) and metadata.get("external_target_key") == target_key:
            return int(row[0])
    return None


def _scope_json_for_item(item: TargetFeedItem) -> dict[str, list[str]]:
    if item.target_type == "domain":
        return {"domains": [item.canonical_value], "urls": []}
    host = str(urlsplit(item.canonical_value).hostname or "").lower().strip(".")
    return {"domains": [host] if host else [], "urls": [item.canonical_value]}


def _write_scope_manifest(
    cfg: ForgeConfig,
    engagement_id: int,
    item: TargetFeedItem,
    roe_id: str | None,
) -> Path:
    manifest_dir = cfg.data_dir / "target_imports"
    manifest_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = manifest_dir / f"scope_{engagement_id}_{item.target_key[:12]}.json"
    scope = _scope_json_for_item(item)
    payload = {
        "roe_id": str(roe_id or "").strip(),
        "domains": scope["domains"],
        "urls": scope["urls"],
        "authorized_seeds": [item.canonical_value],
        "metadata": {
            "external_feed": TARGET_FEED_SCHEMA_VERSION,
            "external_target_key": item.target_key,
            "target_type": item.target_type,
        },
    }
    manifest_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return manifest_path


def _has_passive_kill_chain_run(cfg: ForgeConfig, engagement_id: int, seed: str) -> bool:
    db_path = cfg.engagement_db_path(str(engagement_id))
    if not db_path.exists():
        return False
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute(
            """
            SELECT 1
            FROM engagement_runs
            WHERE engagement_id=?
              AND run_kind='kill_chain'
              AND seed_value=?
              AND status IN ('running', 'completed')
            LIMIT 1
            """,
            (engagement_id, seed),
        ).fetchone()
    except sqlite3.Error:
        return False
    finally:
        conn.close()
    return row is not None


def _start_passive_kill_chain(
    *,
    engagement_id: int,
    seed: str,
    roe_id: str,
    scope_manifest: Path,
    max_iter: int,
) -> None:
    command = [
        sys.executable,
        "-m",
        "forge.cli",
        "kill-chain",
        seed,
        "--engagement",
        str(engagement_id),
        "--roe-id",
        roe_id,
        "--scope-manifest",
        str(scope_manifest),
        "--max-iter",
        str(max(1, int(max_iter))),
        "--no-attack-mode",
        "--no-auto-run-detected",
    ]
    subprocess.run(command, check=True)
