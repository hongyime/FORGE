from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Callable, Iterable

from forge.config import ForgeConfig
from forge.db.session import get_engagement_db
from forge.phase1.state_store import LongRunningTask
from forge.utils.intel.http_pacing import record_rate_limit_cooldown, sleep_rate_limit_cooldown

_DEFAULT_LABELS: tuple[str, ...] = (
    # Web front-doors
    "www",
    "www2",
    "www3",
    "web",
    "web1",
    "web2",
    # Common apps / product surfaces
    "api",
    "api-v1",
    "api-v2",
    "app",
    "apps",
    "mobile",
    "portal",
    "dashboard",
    "console",
    "manage",
    "admin",
    "administrator",
    "moderator",
    "auth",
    "sso",
    "login",
    "signin",
    "id",
    "identity",
    "oauth",
    "shop",
    "store",
    "checkout",
    "billing",
    "pay",
    "payments",
    # Internal / dev / staging
    "dev",
    "development",
    "test",
    "testing",
    "qa",
    "uat",
    "staging",
    "stg",
    "beta",
    "alpha",
    "sandbox",
    "demo",
    "preview",
    "canary",
    "prod",
    "internal",
    "intranet",
    "corp",
    "office",
    # Mail / infra
    "mail",
    "smtp",
    "imap",
    "pop",
    "pop3",
    "webmail",
    "email",
    "mx",
    "mx1",
    "mx2",
    "mailgate",
    "relay",
    "autodiscover",
    "autoconfig",
    "vpn",
    "ssl",
    "remote",
    "rdp",
    "rdweb",
    "ras",
    "ipsec",
    "wireguard",
    "ns",
    "ns1",
    "ns2",
    "dns",
    "dns1",
    "dns2",
    # Files / assets / CDN
    "cdn",
    "cdn1",
    "cdn2",
    "static",
    "assets",
    "media",
    "img",
    "images",
    "files",
    "downloads",
    "docs",
    "documentation",
    "help",
    "support",
    "kb",
    "wiki",
    "learn",
    "training",
    # Monitoring / ops
    "status",
    "health",
    "metrics",
    "grafana",
    "kibana",
    "prometheus",
    "monitor",
    "monitoring",
    "logs",
    "logging",
    "logstash",
    # Dev-ops / source / CI
    "git",
    "gitlab",
    "gitea",
    "svn",
    "code",
    "source",
    "ci",
    "cd",
    "jenkins",
    "build",
    "artifact",
    "artifactory",
    "nexus",
    "harbor",
    "docker",
    "registry",
    "hub",
    # Databases / caches / queues
    "db",
    "database",
    "sql",
    "mysql",
    "postgres",
    "redis",
    "mongo",
    "elasticsearch",
    "queue",
    "rabbit",
    "kafka",
    # Communication / collab
    "chat",
    "im",
    "meet",
    "video",
    "conf",
    "conference",
    "jira",
    "confluence",
    "phab",
    "phabricator",
    "gerrit",
    # SaaS integrations
    "sso-int",
    "okta",
    "auth0",
    "keycloak",
    "stripe",
    "shopify",
    "salesforce",
    "hubspot",
    "zoom",
    "slack",
    "teams",
    # Marketing / public content
    "blog",
    "news",
    "press",
    "careers",
    "jobs",
    "hire",
    "events",
    "community",
    "forum",
    "forums",
    "landing",
    "campaign",
    "promo",
    # Ops / legacy hints
    "legacy",
    "old",
    "archive",
    "backup",
    "backups",
    "prod-old",
    "www-old",
    "beta2",
    "beta3",
)
_DOMAIN_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_CRTSH_DEFAULT_REQUEST_DELAY_SECONDS = 1.0
_CRTSH_DEFAULT_RATE_LIMIT_BACKOFF_SECONDS = 60.0
_CRTSH_DEFAULT_MAX_RETRY_AFTER_SECONDS = 300.0


def _stable_ip(hostname: str) -> str:
    digest = hashlib.sha256(hostname.encode("utf-8")).digest()
    return f"198.18.{digest[0]}.{max(1, digest[1])}"


def _resolve_ip(hostname: str) -> str:
    try:
        return socket.gethostbyname(hostname)
    except OSError:
        return _stable_ip(hostname)


def _normalise_domain(domain: str) -> str:
    value = domain.strip().lower().rstrip(".")
    if not _DOMAIN_RE.fullmatch(value):
        raise ValueError(f"Invalid domain for subdomain enumeration: {domain!r}")
    return value


def _float_env(name: str, default: float, *, minimum: float, maximum: float) -> float:
    raw_value = os.environ.get(name, "").strip()
    if not raw_value:
        return default
    try:
        parsed = float(raw_value)
    except ValueError:
        return default
    return max(minimum, min(maximum, parsed))


def _crtsh_request_delay_seconds() -> float:
    return _float_env(
        "FORGE_CRTSH_REQUEST_DELAY_SECONDS",
        _CRTSH_DEFAULT_REQUEST_DELAY_SECONDS,
        minimum=0.0,
        maximum=60.0,
    )


def _crtsh_rate_limit_backoff_seconds() -> float:
    return _float_env(
        "FORGE_CRTSH_RATE_LIMIT_BACKOFF_SECONDS",
        _CRTSH_DEFAULT_RATE_LIMIT_BACKOFF_SECONDS,
        minimum=1.0,
        maximum=300.0,
    )


def _crtsh_max_retry_after_seconds() -> float:
    return _float_env(
        "FORGE_CRTSH_MAX_RETRY_AFTER_SECONDS",
        _CRTSH_DEFAULT_MAX_RETRY_AFTER_SECONDS,
        minimum=1.0,
        maximum=600.0,
    )


def _crtsh_rate_limit_retries() -> int:
    return int(
        _float_env(
            "FORGE_CRTSH_RATE_LIMIT_RETRIES",
            1.0,
            minimum=0.0,
            maximum=3.0,
        )
    )


def _crtsh_retry_after_seconds(response: object) -> float:
    headers = getattr(response, "headers", {}) or {}
    raw_value = ""
    try:
        raw_value = str(headers.get("Retry-After") or headers.get("retry-after") or "").strip()
    except Exception:  # noqa: BLE001
        raw_value = ""
    if not raw_value:
        return _crtsh_rate_limit_backoff_seconds()
    try:
        seconds = float(raw_value)
    except ValueError:
        try:
            retry_at = parsedate_to_datetime(raw_value)
            seconds = max(0.0, retry_at.timestamp() - time.time())
        except Exception:  # noqa: BLE001
            seconds = _crtsh_rate_limit_backoff_seconds()
    return min(max(1.0, seconds), _crtsh_max_retry_after_seconds())


def _read_crtsh_payload(req: urllib.request.Request, timeout: float) -> str:
    attempts = _crtsh_rate_limit_retries() + 1
    url = getattr(req, "full_url", "") or getattr(req, "selector", "") or "https://crt.sh/"
    sleep_rate_limit_cooldown("crtsh", str(url))
    for attempt in range(attempts):
        request_delay = _crtsh_request_delay_seconds()
        if request_delay > 0:
            time.sleep(request_delay)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                return response.read().decode("utf-8", errors="ignore")
        except urllib.error.HTTPError as exc:
            if exc.code != 429 or attempt >= attempts - 1:
                return ""
            wait_seconds = _crtsh_retry_after_seconds(exc)
            record_rate_limit_cooldown("crtsh", str(url), wait_seconds)
            if wait_seconds > 0:
                time.sleep(wait_seconds)
        except (TimeoutError, urllib.error.URLError):
            return ""
    return ""


def _collect_passive_subdomains(
    conn: sqlite3.Connection,
    engagement_id: int,
    domain: str,
) -> list[str]:
    found: set[str] = set()
    rows = conn.execute(
        "SELECT hostname FROM hosts WHERE engagement_id=? AND hostname IS NOT NULL",
        (engagement_id,),
    ).fetchall()
    for row in rows:
        hostname = str(row["hostname"]).strip().lower()
        if hostname.endswith(f".{domain}") or hostname == domain:
            found.add(hostname)
    email_rows = conn.execute(
        "SELECT email FROM emails WHERE engagement_id=?",
        (engagement_id,),
    ).fetchall()
    for row in email_rows:
        value = str(row["email"]).strip().lower()
        if "@" not in value:
            continue
        email_domain = value.split("@", maxsplit=1)[1]
        if email_domain.endswith(f".{domain}") or email_domain == domain:
            found.add(email_domain)
    for host in _collect_crtsh_subdomains(domain):
        if host.endswith(f".{domain}") or host == domain:
            found.add(host)
    return sorted(found)


def _collect_crtsh_subdomains(domain: str, timeout: float = 3.0) -> list[str]:
    query = urllib.parse.urlencode({"q": f"%.{domain}", "output": "json"})
    url = f"https://crt.sh/?{query}"
    req = urllib.request.Request(url, headers={"User-Agent": "FORGE-Recon/1.0"})
    names: set[str] = set()
    payload = _read_crtsh_payload(req, timeout)
    if not payload:
        return []
    try:
        rows = json.loads(payload)
    except json.JSONDecodeError:
        return []
    if not isinstance(rows, list):
        return []
    for row in rows:
        if not isinstance(row, dict):
            continue
        value = str(row.get("name_value", "")).strip().lower()
        if not value:
            continue
        for entry in value.splitlines():
            host = entry.strip().lstrip("*.").rstrip(".")
            if host and _DOMAIN_RE.fullmatch(host):
                names.add(host)
    return sorted(names)


def _ensure_engagement_row(
    conn: sqlite3.Connection, engagement_id: int, domain: str, operator: str
) -> None:
    scope_json = json.dumps([domain])
    now = datetime.now(tz=timezone.utc).isoformat()
    conn.execute(
        """
        INSERT INTO engagements (id, name, scope_json, status, operator, created_at, updated_at)
        VALUES (?, ?, ?, 'ACTIVE', ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            scope_json=excluded.scope_json,
            updated_at=excluded.updated_at
        """,
        (engagement_id, f"engagement-{engagement_id}", scope_json, operator, now, now),
    )


def enumerate_subdomains(
    engagement_id: str | int,
    domain: str,
    resume: bool = True,
    db_path: Path | None = None,
    operator: str | None = None,
    extra_labels: Iterable[str] | None = None,
    passive: bool = True,
    progress_callback: Callable[[int, int, str, bool], None] | None = None,
) -> list[str]:
    cfg = ForgeConfig.load()
    eng_id = int(engagement_id)
    target_db = db_path or cfg.engagement_db_path(str(engagement_id))
    op = operator or cfg.operator

    norm_domain = _normalise_domain(domain)
    labels = list(_DEFAULT_LABELS)
    if extra_labels:
        labels.extend([x.strip().lower() for x in extra_labels if x.strip()])
    candidates = [norm_domain] + [f"{label}.{norm_domain}" for label in labels]
    seen: set[str] = set()
    unique_candidates = [x for x in candidates if not (x in seen or seen.add(x))]

    conn = get_engagement_db(target_db)
    try:
        _ensure_engagement_row(conn, eng_id, norm_domain, op)
        conn.commit()
    finally:
        conn.close()

    task = LongRunningTask(target_db, eng_id, f"subdomain_enum:{norm_domain}")
    state = task.start()
    start_index = 0
    if resume and state.checkpoint and "index" in state.checkpoint:
        start_index = int(state.checkpoint["index"])

    conn = get_engagement_db(target_db)
    inserted: list[str] = []
    last_index = start_index
    failure: Exception | None = None
    try:
        passive_candidates = (
            _collect_passive_subdomains(conn, eng_id, norm_domain) if passive else []
        )
        all_candidates = unique_candidates + [
            x for x in passive_candidates if x not in set(unique_candidates)
        ]
        bounded_start = min(max(0, start_index), len(all_candidates))
        total = len(all_candidates)
        for idx, hostname in enumerate(all_candidates[bounded_start:], start=bounded_start):
            ip = _resolve_ip(hostname)
            row = conn.execute(
                "SELECT id FROM hosts WHERE engagement_id=? AND ip=?",
                (eng_id, ip),
            ).fetchone()
            inserted_host = False
            if row is None:
                synthetic_ip = ip == _stable_ip(hostname)
                conn.execute(
                    """
                    INSERT INTO hosts (engagement_id, ip, hostname, os_family, host_context, in_scope)
                    VALUES (?, ?, ?, 'unknown', ?, 1)
                    """,
                    (
                        eng_id,
                        ip,
                        hostname,
                        json.dumps(
                            {
                                "discovery": (
                                    "passive" if hostname in passive_candidates else "wordlist"
                                ),
                                "synthetic_ip": synthetic_ip,
                            }
                        ),
                    ),
                )
                inserted.append(hostname)
                inserted_host = True
            conn.execute(
                """
                INSERT INTO audit_log (engagement_id, phase, module, action, target, result, operator)
                VALUES (?, 'phase1', 'subdomain_enum', 'enumerate', ?, 'ok', ?)
                """,
                (eng_id, hostname, op),
            )
            if progress_callback is not None:
                progress_callback(idx + 1, total, hostname, inserted_host)
            last_index = idx + 1
        conn.commit()
    except Exception as exc:
        conn.rollback()
        failure = exc
    finally:
        conn.close()

    if failure is not None:
        task.fail(str(failure))
        raise failure

    task.save_checkpoint({"index": last_index})
    task.complete()
    return inserted
