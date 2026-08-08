"""Shared CLI helper functions extracted from forge/cli.py for modularity.

This module contains pure-function utilities, dataclasses, batch runners,
scope-manifest loaders, and HTML mining helpers used throughout the CLI.
No Typer app or command registration lives here.
"""

from __future__ import annotations

import csv
import html as html_lib
import ipaddress
import json
import logging
import os
import re
import sqlite3
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Optional, Sequence
from urllib.parse import urljoin, urlparse, urlsplit, urlunsplit

import typer

from forge.db.direct_connect import direct_connect

__all__ = [
    "_append_cli_flag_once",
    "_append_cli_option_once",
    "_append_scope_manifest_arg",
    "_ARTIFACT_PROCESSOR_DEFAULT_MAX_WORKERS",
    "_artifact_processor_max_workers",
    "_batch_progress_snapshot",
    "_canonical_http_url_value",
    "_cli_audit",
    "_cli_float_env",
    "_cli_int_env",
    "_detected_prereq_child_argv",
    "_direct_cli_load_scope_lists",
    "_direct_cli_require_roe",
    "_direct_cli_require_scope_manifest",
    "_direct_cli_scope_manifest_value",
    "_direct_cli_split_scope_entries",
    "_DNS_DEFAULT_MAX_WORKERS",
    "_empty_html_mined_result",
    "_extract_html_surface_urls",
    "_extract_passive_text_urls",
    "_HTML_ATTRIBUTE_URL_RE",
    "_HTML_CSS_IMPORT_RE",
    "_HTML_CSS_URL_RE",
    "_HTML_IGNORED_URL_PREFIXES",
    "_HTML_JS_CALL_URL_RE",
    "_HTML_JS_CONSTRUCTOR_URL_RE",
    "_HTML_JS_METHOD_CALL_URL_RE",
    "_HTML_META_REFRESH_URL_RE",
    "_HTML_META_TAG_RE",
    "_HTML_MINED_KEYS",
    "_HTML_PHONE_RE",
    "_HTML_SRCSET_ATTRIBUTE_RE",
    "_HTML_TAG_ATTRIBUTE_RE",
    "_IDENTITY_LOOKUP_DEFAULT_MAX_WORKERS",
    "_identity_lookup_max_workers",
    "_is_mobile_bundle_url",
    "_load_scope_manifest",
    "_merge_html_mined_result",
    "_MOBILE_BUNDLE_SEED_SUFFIXES",
    "_module_provider_key",
    "_MODULE_SUBPROCESS_DEFAULT_TIMEOUT_SECONDS",
    "_MODULE_SUBPROCESS_TIMEOUT_EXIT_CODE",
    "_module_subprocess_timeout_seconds",
    "_normalise_output_format",
    "_normalize_discovered_url",
    "_normalized_provider_env_key",
    "_passive_archive_lookup_max_workers",
    "_PASSIVE_TEXT_URL_RE",
    "_PASSIVE_WEB_DIRECTIVES",
    "_path_under",
    "_PROVIDER_BATCH_STAGGER_DEFAULT_SECONDS",
    "_provider_batch_stagger_seconds",
    "_PROVIDER_DEFAULT_MAX_WORKERS",
    "_provider_launch_delays",
    "_provider_limited_worker_count",
    "_provider_max_workers",
    "_render_sarif",
    "_run_callable_batch",
    "_run_forge_module_subprocess",
    "_run_html_fetch_batch",
    "_run_inprocess_batch",
    "_run_module_batch",
    "_run_ptr_lookup_batch",
    "_reject_broad_scope_manifest_for_live",
    "_scope_manifest_broad_reasons",
    "_scope_manifest_seed_targets",
    "_scope_manifest_values",
    "_sleep_provider_launch_delay",
    "_timeout_stream_text",
    "_validate_scope_manifest_seed_values",
    "_VALIDATION_DEFAULT_MAX_WORKERS",
    "_validation_max_workers",
    "_WEB_FETCH_DEFAULT_REQUEST_DELAY_SECONDS",
    "_web_fetch_request_delay_seconds",
    "_write_cloud_output",
    "HtmlFetchSpec",
    "ModuleDispatchSpec",
]

_MOBILE_BUNDLE_SEED_SUFFIXES = (".apk", ".ipa", ".aab", ".apkm", ".apks", ".xapk")
_WEB_FETCH_DEFAULT_REQUEST_DELAY_SECONDS = 0.0
_IDENTITY_LOOKUP_DEFAULT_MAX_WORKERS = 2
_VALIDATION_DEFAULT_MAX_WORKERS = 1
_ARTIFACT_PROCESSOR_DEFAULT_MAX_WORKERS = 4
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


def _artifact_processor_max_workers() -> int:
    return _cli_int_env(
        "FORGE_ARTIFACT_PROCESSOR_MAX_WORKERS",
        _ARTIFACT_PROCESSOR_DEFAULT_MAX_WORKERS,
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


def _append_scope_manifest_arg(argv: list[str], scope_manifest: str) -> list[str]:
    return _append_cli_option_once(argv, "--scope-manifest", str(scope_manifest or "").strip())


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


def _canonical_http_url_value(value: str) -> str | None:
    try:
        parsed = urlsplit(str(value or "").strip())
    except ValueError:
        return None
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        return None
    host = (parsed.hostname or "").strip().lower()
    if not host:
        return None
    try:
        port = parsed.port
    except ValueError:
        return None
    host_part = f"[{host}]" if ":" in host and not host.startswith("[") else host
    default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    netloc = f"{host_part}:{port}" if port is not None and not default_port else host_part
    return urlunsplit((scheme, netloc, parsed.path or "/", parsed.query, ""))


def _is_mobile_bundle_url(value: str) -> bool:
    text = _canonical_http_url_value(value) or ""
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


def _path_under(candidate: Path, root: Path) -> bool:
    """True if *candidate* is *root* or a descendant of *root*.

    Uses :meth:`Path.relative_to` (available since 3.9). Returns False on
    OSError / ValueError instead of raising, so a symlink hop that fails
    to resolve doesn't crash the manifest loader.
    """
    try:
        candidate.relative_to(root)
        return True
    except ValueError:
        return False


def _load_scope_manifest(value: str) -> dict[str, Any]:
    manifest_ref = str(value or "").strip()
    if not manifest_ref:
        raise ValueError("scope manifest path or JSON payload is required")
    if manifest_ref.startswith("{"):
        # P2-B10: cap inline JSON at 1 MiB to prevent OOM from a
        # pathological caller.
        if len(manifest_ref) > 1_048_576:
            raise ValueError(
                f"scope manifest inline JSON is too large: "
                f"{len(manifest_ref)} bytes exceeds 1 MiB cap"
            )
        source = "inline_json"
        payload = json.loads(manifest_ref)
    else:
        path = Path(manifest_ref).expanduser()
        # P2-B10: size cap + safe read.
        # - Reject files >1 MiB (scope manifest should never be that big;
        #   larger typically indicates a wrong path like /dev/urandom).
        # - Refuse to follow the file if resolving it would traverse outside
        #   the current working directory tree AND outside the caller's
        #   home. This blocks casual `--scope-manifest /etc/shadow` reads.
        # - Wrap OSError so upstream `raise typer.BadParameter(...invalid --scope-manifest: {exc}...)`
        #   picks it up as a clean CLI error rather than a raw traceback.
        try:
            stat = path.stat()
        except OSError as exc:
            raise ValueError(f"cannot stat scope manifest: {exc}") from exc
        if stat.st_size > 1_048_576:
            raise ValueError(
                f"scope manifest file too large: {stat.st_size} bytes exceeds 1 MiB cap"
            )
        try:
            resolved = path.resolve(strict=False)
        except OSError as exc:
            raise ValueError(f"cannot resolve scope manifest path: {exc}") from exc
        cwd = Path.cwd().resolve()
        home = Path.home().resolve()
        if not (
            _path_under(resolved, cwd)
            or _path_under(resolved, home)
        ):
            raise ValueError(
                f"scope manifest path {resolved.as_posix()!r} is outside "
                f"the current working directory and the operator home; "
                f"refusing to read for OPSEC (drop the manifest under the "
                f"engagement workspace and re-run)."
            )
        source = resolved.as_posix()
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except OSError as exc:
            raise ValueError(f"cannot read scope manifest: {exc}") from exc
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


def _scope_manifest_broad_reasons(manifest: dict[str, Any]) -> list[str]:
    """Return reasons a manifest authorizes an unbounded live surface."""
    reasons: list[str] = []
    wildcard_fields = {
        "domains": list(manifest.get("domains") or []),
        "urls": list(manifest.get("urls") or []),
        "authorized_seeds": list(manifest.get("exact_seeds") or []),
    }
    for field_name, values in wildcard_fields.items():
        for value in values:
            normalized = " ".join(str(value or "").strip().split()).casefold()
            if normalized in {"*", "*.*"}:
                reasons.append(f"{field_name} contains wildcard {str(value)!r}")
                break

    for value in list(manifest.get("ip_ranges") or []):
        text = " ".join(str(value or "").strip().split())
        if not text:
            continue
        try:
            network = ipaddress.ip_network(text, strict=False)
        except ValueError:
            continue
        if network.prefixlen == 0:
            reasons.append(f"ip_ranges contains unbounded CIDR {text!r}")

    return reasons


def _reject_broad_scope_manifest_for_live(manifest: dict[str, Any]) -> None:
    reasons = _scope_manifest_broad_reasons(manifest)
    if not reasons:
        return
    source = str(manifest.get("source") or "").strip() or "scope manifest"
    preview = "; ".join(reasons[:4])
    raise ValueError(
        "scope manifest is too broad for live execution: "
        f"{preview}. Create a target-specific manifest instead of using {source!r}."
    )


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
    elif kind == "cloud_ref":
        # cloud_ref may be a URL ("https://xyz.supabase.co/") or a bare
        # hostname ("xyz.supabase.co"). Emit both the URL form (if any) and
        # the hostname so the scope gate can match by URL prefix OR domain.
        parsed = urlparse(value)
        if parsed.scheme and parsed.netloc:
            _append(value)
            _append(str(parsed.hostname or "").strip().lower().strip("."))
        else:
            _append(value.lower().strip("."))
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

    # Wildcard support: if exact_seeds contains "*", authorize ALL seeds
    # unconditionally. This is the "I'm authorized for everything I target"
    # manifest pattern (manifests/default.json).
    _wildcard_authorize_all = "*" in exact_seeds

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
        if _wildcard_authorize_all:
            authorized.append(
                {
                    "seed_value": seed_value,
                    "seed_type": seed_type,
                    "matched": "*",
                    "match_type": "wildcard_all",
                }
            )
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
        if seed_type in {"url", "apk_url", "cloud_ref"} and list(manifest.get("urls") or []):
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
        try:
            _reject_broad_scope_manifest_for_live(manifest)
        except ValueError as exc:
            raise typer.BadParameter(str(exc)) from exc
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


def _extract_html_surface_urls(
    html: str,
    *,
    base_url: str = "",
    max_workers: int = 1,
) -> list[str]:
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

    def _resolve_surface_candidate(raw_value: str) -> str:
        value = html_lib.unescape(str(raw_value or "").strip())
        if not value or value.lower().startswith(_HTML_IGNORED_URL_PREFIXES):
            return ""
        return urljoin(base_url, value)

    parsed_base = urlparse(str(base_url or "").strip())
    has_base = parsed_base.scheme in {"http", "https"} and bool(parsed_base.netloc)
    families = ["literal"]
    if has_base:
        families.extend(
            [
                "attribute",
                "meta_refresh",
                "srcset",
                "css_url",
                "css_import",
                "js",
            ]
        )

    def _family_candidates(family: str) -> list[str]:
        candidates: list[str] = []
        if family == "literal":
            return [match.group(0) for match in _PASSIVE_TEXT_URL_RE.finditer(raw_html)]
        if family == "attribute":
            for match in _HTML_ATTRIBUTE_URL_RE.finditer(raw_html):
                resolved = _resolve_surface_candidate(str(match.group(1) or ""))
                if resolved:
                    candidates.append(resolved)
            return candidates
        if family == "meta_refresh":
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
                if resolved:
                    candidates.append(resolved)
            return candidates
        if family == "srcset":
            for match in _HTML_SRCSET_ATTRIBUTE_RE.finditer(raw_html):
                srcset_value = html_lib.unescape(str(match.group(1) or ""))
                skip_data_payload = False
                for candidate in srcset_value.split(","):
                    raw_value = (
                        candidate.strip().split(maxsplit=1)[0]
                        if candidate.strip()
                        else ""
                    )
                    if skip_data_payload:
                        skip_data_payload = False
                        continue
                    if not raw_value or raw_value.lower().startswith(_HTML_IGNORED_URL_PREFIXES):
                        if raw_value.lower().startswith("data:"):
                            skip_data_payload = True
                        continue
                    candidates.append(urljoin(base_url, raw_value))
            return candidates
        if family == "css_url":
            for match in _HTML_CSS_URL_RE.finditer(raw_html):
                resolved = _resolve_surface_candidate(str(match.group(1) or ""))
                if resolved:
                    candidates.append(resolved)
            return candidates
        if family == "css_import":
            for match in _HTML_CSS_IMPORT_RE.finditer(raw_html):
                resolved = _resolve_surface_candidate(str(match.group(1) or ""))
                if resolved:
                    candidates.append(resolved)
            return candidates
        if family == "js":
            for pattern in (
                _HTML_JS_CALL_URL_RE,
                _HTML_JS_CONSTRUCTOR_URL_RE,
                _HTML_JS_METHOD_CALL_URL_RE,
            ):
                for match in pattern.finditer(raw_html):
                    resolved = _resolve_surface_candidate(str(match.group(1) or ""))
                    if resolved:
                        candidates.append(resolved)
            return candidates
        return candidates

    if len(families) > 1 and int(max_workers or 1) > 1:
        family_batches = _run_inprocess_batch(
            families,
            _family_candidates,
            max_workers=max_workers,
        )
    else:
        family_batches = [_family_candidates(family) for family in families]
    for family_batch in family_batches:
        for candidate in family_batch:
            _append(candidate)

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
        with direct_connect(db_path) as con:
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
