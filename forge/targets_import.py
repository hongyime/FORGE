from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
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
from forge.db.control import index_engagement_db_file
from forge.db.session import get_engagement_db
from forge.engagement_ids import allocate_engagement_id, numeric_engagement_db_files

TARGET_FEED_SCHEMA_VERSION = "target-feed.v1"
TARGET_IMPORT_MONITORING_POLICY_NAME = "Target import seed exposure"
TARGET_IMPORT_MONITORING_INTERVAL_MINUTES = 60
SUPPORTED_TARGET_TYPES = {
    "apk_url",
    "artifact_url",
    "auto",
    "cloud_ref",
    "company",
    "domain",
    "email",
    "email_address",
    "fqdn",
    "handle",
    "host",
    "hostname",
    "ip",
    "ip_address",
    "ipv4",
    "ipv6",
    "name",
    "organization",
    "person",
    "phone",
    "subdomain",
    "tel",
    "telephone",
    "url",
    "username",
    "web_url",
    "website",
}
CANONICAL_TARGET_TYPES = {
    "apk_url",
    "cloud_ref",
    "company",
    "domain",
    "email",
    "ipv4",
    "ipv6",
    "name",
    "phone",
    "subdomain",
    "url",
    "username",
}
TARGET_TYPE_ALIASES = {
    "artifact_url": "artifact_url",
    "email_address": "email",
    "fqdn": "auto",
    "handle": "username",
    "host": "auto",
    "hostname": "auto",
    "ip": "auto",
    "ip_address": "auto",
    "organization": "company",
    "person": "name",
    "tel": "phone",
    "telephone": "phone",
    "web_url": "url",
    "website": "url",
}


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
    existing_targets = _external_target_engagement_index(cfg)
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

        engagement_id, created = _create_or_reuse_engagement(cfg, item, existing_targets)
        _ensure_target_import_monitoring(cfg, engagement_id=engagement_id, item=item)
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
                engagement_db_path=cfg.engagement_db_path(str(engagement_id)),
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
    raw_target_type = str(raw_item.get("target_type") or "").strip().lower()
    if raw_target_type not in SUPPORTED_TARGET_TYPES:
        return None
    target_value = str(raw_item.get("target_value") or "").strip()
    try:
        normalized = _normalize_target_value(raw_target_type, target_value)
    except ValueError:
        return None
    if normalized is None:
        return None
    target_type, canonical_value = normalized
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


def _normalize_target_value(raw_target_type: str, value: str) -> tuple[str, str] | None:
    target_type = TARGET_TYPE_ALIASES.get(raw_target_type, raw_target_type)
    if target_type == "auto":
        target_type = _classify_target_value(value)
    if target_type == "artifact_url":
        canonical_url = _canonical_http_url_value(value)
        if not canonical_url:
            return None
        target_type = "apk_url" if _is_mobile_bundle_target_url(canonical_url) else "url"
        if target_type == "url" and _url_is_cloud_target(canonical_url):
            target_type = "cloud_ref"
        return target_type, canonical_url
    if target_type not in CANONICAL_TARGET_TYPES:
        return None
    canonical_value = _canonical_target_value(target_type, value)
    if not canonical_value:
        return None
    if target_type in {"domain", "subdomain"} and _hostname_is_cloud_target(canonical_value):
        return "cloud_ref", canonical_value
    if target_type == "url" and _url_is_cloud_target(canonical_value):
        return "cloud_ref", canonical_value
    return target_type, canonical_value


def _canonical_target_value(target_type: str, value: str) -> str:
    text = " ".join(str(value or "").strip().split())
    if not text:
        return ""
    if target_type in {"domain", "subdomain"}:
        if "://" in text or "/" in text or "@" in text:
            return ""
        return text.lower().strip(".")
    if target_type in {"url", "apk_url"}:
        return _canonical_http_url_value(text)
    if target_type == "cloud_ref":
        return _canonical_cloud_target_value(text)
    if target_type == "email":
        candidate = text.lower()
        return candidate if re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", candidate) else ""
    if target_type == "phone":
        return _normalize_phone_target_value(text)
    if target_type == "username":
        username = text[1:] if text.startswith("@") else text
        if re.match(r"^[A-Za-z0-9_.\-]{2,32}$", username):
            return f"@{username.lower()}"
        return ""
    if target_type in {"ipv4", "ipv6"}:
        return _canonical_ip_target_value(text, target_type)
    if target_type in {"name", "company"}:
        return text[:160]
    return ""


def _canonical_http_url_value(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        return ""
    host = (parsed.hostname or "").lower().strip(".")
    if not host:
        return ""
    netloc = f"[{host}]" if ":" in host and not host.startswith("[") else host
    try:
        port = parsed.port
    except ValueError:
        return ""
    if port:
        netloc = f"{netloc}:{port}"
    path = parsed.path or "/"
    return urlunsplit((parsed.scheme.lower(), netloc, path, "", ""))


def _canonical_cloud_target_value(value: str) -> str:
    try:
        from forge.engagement_orchestrator import _canonical_cloud_ref_value  # noqa: PLC0415
    except Exception:  # noqa: BLE001
        _canonical_cloud_ref_value = None

    if _canonical_cloud_ref_value is not None:
        canonical_ref = _canonical_cloud_ref_value(value)
        if canonical_ref:
            return canonical_ref

    canonical_url = _canonical_http_url_value(value)
    if canonical_url and _url_is_cloud_target(canonical_url):
        return canonical_url

    host = " ".join(str(value or "").strip().split()).lower().strip(".")
    if host and "://" not in host and "/" not in host and "@" not in host and _hostname_is_cloud_target(host):
        return host
    return ""


def _canonical_ip_target_value(value: str, target_type: str) -> str:
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError:
        return ""
    if target_type == "ipv4" and parsed.version != 4:
        return ""
    if target_type == "ipv6" and parsed.version != 6:
        return ""
    return str(parsed)


def _classify_target_value(value: str) -> str:
    try:
        from forge.engagement_orchestrator import _classify_seed_value  # noqa: PLC0415
    except Exception:  # noqa: BLE001
        return _fallback_classify_target_value(value)
    target_type = str(_classify_seed_value(str(value or "")) or "").strip().lower()
    return target_type if target_type in CANONICAL_TARGET_TYPES else ""


def _fallback_classify_target_value(value: str) -> str:
    text = " ".join(str(value or "").strip().split())
    if not text:
        return ""
    lowered = text.lower()
    if re.match(r"^\+\d{6,15}$", text):
        return "phone"
    if re.match(r"^@[a-z0-9_.\-]{2,32}$", lowered):
        return "username"
    try:
        parsed_ip = ipaddress.ip_address(text)
        return "ipv6" if parsed_ip.version == 6 else "ipv4"
    except ValueError:
        pass
    if _canonical_cloud_target_value(text):
        return "cloud_ref"
    parsed = urlsplit(text)
    if parsed.scheme.lower() in {"http", "https"} and parsed.netloc:
        return "apk_url" if _is_mobile_bundle_target_url(text) else "url"
    if re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", text):
        return "email"
    if _hostname_is_cloud_target(lowered):
        return "cloud_ref"
    if re.match(
        r"^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(?:\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)+$",
        lowered.lstrip("*."),
    ):
        return "domain"
    return ""


def _is_mobile_bundle_target_url(value: str) -> bool:
    try:
        from forge.engagement_orchestrator import _is_mobile_bundle_url  # noqa: PLC0415
    except Exception:  # noqa: BLE001
        parsed = urlsplit(value)
        return parsed.scheme.lower() in {"http", "https"} and parsed.path.lower().endswith(
            (".apk", ".ipa", ".aab", ".apkm", ".apks", ".xapk")
        )
    return bool(_is_mobile_bundle_url(str(value or "")))


def _hostname_is_cloud_target(hostname: str) -> bool:
    try:
        from forge.engagement_orchestrator import _hostname_is_cloud_ref  # noqa: PLC0415
    except Exception:  # noqa: BLE001
        return False
    return bool(_hostname_is_cloud_ref(str(hostname or "")))


def _url_is_cloud_target(value: str) -> bool:
    parsed = urlsplit(str(value or ""))
    return bool(parsed.netloc and _hostname_is_cloud_target(parsed.netloc))


def _normalize_phone_target_value(value: str) -> str:
    try:
        from forge.engagement_orchestrator import _normalize_phone_seed_value  # noqa: PLC0415
    except Exception:  # noqa: BLE001
        candidate = re.sub(r"[^\d+]", "", str(value or "").strip())
        if candidate.startswith("00") and len(candidate) > 3:
            candidate = f"+{candidate[2:]}"
        return candidate if re.match(r"^\+\d{6,15}$", candidate) else ""
    return str(_normalize_phone_seed_value(value) or "")


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
    existing_targets: dict[str, int],
) -> tuple[int, bool]:
    existing_id = existing_targets.get(item.target_key)
    if existing_id is not None:
        return existing_id, False

    engagement_id, db_path = _allocate_empty_target_import_engagement(cfg)
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
    index_engagement_db_file(cfg.data_dir, db_path, engagement_id=engagement_id)
    existing_targets[item.target_key] = engagement_id
    return engagement_id, True


def _allocate_empty_target_import_engagement(cfg: ForgeConfig) -> tuple[int, Path]:
    for _attempt in range(100):
        engagement_id = allocate_engagement_id(cfg.data_dir)
        db_path = cfg.engagement_db_path(str(engagement_id))
        if not _engagement_db_has_existing_engagement(db_path):
            return engagement_id, db_path
    raise RuntimeError("could not allocate an empty engagement database for target import")


def _engagement_db_has_existing_engagement(db_path: Path) -> bool:
    if not db_path.exists():
        return False
    conn = sqlite3.connect(db_path)
    try:
        tables = {
            str(row[0])
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        if "engagements" not in tables:
            return False
        row = conn.execute("SELECT 1 FROM engagements LIMIT 1").fetchone()
        return row is not None
    except sqlite3.Error:
        return True
    finally:
        conn.close()


def _ensure_target_import_monitoring(
    cfg: ForgeConfig,
    *,
    engagement_id: int,
    item: TargetFeedItem,
) -> None:
    from forge.monitoring.continuous import (  # noqa: PLC0415
        create_monitoring_snapshot,
        upsert_monitoring_policy,
    )

    db_path = cfg.engagement_db_path(str(engagement_id))
    con = get_engagement_db(db_path)
    try:
        policy_row = con.execute(
            """
            SELECT id, last_snapshot_id
            FROM monitoring_policies
            WHERE engagement_id=? AND name=?
            LIMIT 1
            """,
            (engagement_id, TARGET_IMPORT_MONITORING_POLICY_NAME),
        ).fetchone()
        if policy_row is None:
            policy = upsert_monitoring_policy(
                con,
                engagement_id=engagement_id,
                name=TARGET_IMPORT_MONITORING_POLICY_NAME,
                enabled=True,
                schedule_interval_minutes=TARGET_IMPORT_MONITORING_INTERVAL_MINUTES,
                mode="passive",
                metadata={
                    "external_feed": TARGET_FEED_SCHEMA_VERSION,
                    "external_target_key": item.target_key,
                    "refresh": {"type": "seed_exposure"},
                    "source": "target_import",
                    "target_type": item.target_type,
                },
            )
        else:
            policy = {
                "id": int(policy_row["id"]),
                "last_snapshot_id": (
                    int(policy_row["last_snapshot_id"])
                    if policy_row["last_snapshot_id"] is not None
                    else None
                ),
            }

        if policy.get("last_snapshot_id"):
            return
        snapshot = create_monitoring_snapshot(
            con,
            engagement_id=engagement_id,
            policy_id=int(policy["id"]),
            snapshot_kind="manual",
            refresh={
                "status": "completed",
                "source": "target_import",
                "target_type": item.target_type,
            },
        )
        con.execute(
            """
            INSERT INTO audit_log (engagement_id, phase, module, action, target, result, operator)
            VALUES (?, 'monitoring', 'target_import', 'monitoring_policy_seeded', ?, ?, ?)
            """,
            (
                engagement_id,
                TARGET_IMPORT_MONITORING_POLICY_NAME,
                f"snapshot={snapshot['snapshot']['id']} target={item.target_type}",
                cfg.operator,
            ),
        )
        con.commit()
    finally:
        con.close()


def _external_target_engagement_index(cfg: ForgeConfig) -> dict[str, int]:
    targets: dict[str, int] = {}
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
        target_key = metadata.get("external_target_key") if isinstance(metadata, dict) else None
        if isinstance(target_key, str) and target_key:
            targets[target_key] = int(row[0])
    return targets


def _scope_json_for_item(item: TargetFeedItem) -> dict[str, list[str]]:
    scope: dict[str, list[str]] = {"domains": [], "urls": []}
    if item.target_type in {"domain", "subdomain"}:
        scope["domains"] = [item.canonical_value]
    elif item.target_type in {"url", "apk_url"}:
        host = str(urlsplit(item.canonical_value).hostname or "").lower().strip(".")
        scope["domains"] = [host] if host else []
        scope["urls"] = [item.canonical_value]
    elif item.target_type == "cloud_ref":
        parsed = urlsplit(item.canonical_value)
        if parsed.scheme in {"http", "https"} and parsed.netloc:
            host = str(parsed.hostname or "").lower().strip(".")
            scope["domains"] = [host] if host else []
            scope["urls"] = [item.canonical_value]
        elif _hostname_is_cloud_target(item.canonical_value):
            scope["domains"] = [item.canonical_value]
        scope["authorized_seeds"] = [item.canonical_value]
    elif item.target_type in {"ipv4", "ipv6"}:
        parsed_ip = ipaddress.ip_address(item.canonical_value)
        prefix = 32 if parsed_ip.version == 4 else 128
        scope["ip_ranges"] = [f"{parsed_ip}/{prefix}"]
        scope["authorized_seeds"] = [item.canonical_value]
    else:
        scope["authorized_seeds"] = [item.canonical_value]
    return scope


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
        "domains": scope.get("domains", []),
        "ip_ranges": scope.get("ip_ranges", []),
        "urls": scope.get("urls", []),
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
    engagement_db_path: Path,
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
    proc = subprocess.run(command, check=False, capture_output=True, text=True)
    if proc.stdout:
        sys.stdout.write(proc.stdout)
        sys.stdout.flush()
    if proc.stderr:
        sys.stderr.write(proc.stderr)
        sys.stderr.flush()
    if proc.returncode == 0:
        return
    combined_output = f"{proc.stdout or ''}\n{proc.stderr or ''}"
    if proc.returncode == 2 and "Kill-chain complete" in combined_output and "Report:" in combined_output:
        return
    if proc.returncode == 2 and _completed_passive_kill_chain_run(
        engagement_db_path,
        engagement_id=engagement_id,
        seed=seed,
    ):
        return
    raise subprocess.CalledProcessError(
        proc.returncode,
        command,
        output=proc.stdout,
        stderr=proc.stderr,
    )


def _completed_passive_kill_chain_run(
    db_path: Path,
    *,
    engagement_id: int,
    seed: str,
) -> bool:
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
              AND status='completed'
            LIMIT 1
            """,
            (engagement_id, seed),
        ).fetchone()
    except sqlite3.Error:
        return False
    finally:
        conn.close()
    return row is not None
