from __future__ import annotations

import os
from collections.abc import Callable, MutableMapping
from dataclasses import dataclass
from typing import Any

from typer.models import ArgumentInfo, OptionInfo

from forge.utils.kill_chain_options import (
    normalize_kill_chain_max_iter,
    normalize_kill_chain_max_runtime_minutes,
    normalize_kill_chain_synthesis_depth,
    normalize_kill_chain_validation_batch_limit,
)


@dataclass(frozen=True)
class KillChainRuntimeOptions:
    related_seed: object | None
    engagement: object | None
    resume: bool
    max_iter: int
    tor: bool
    dry_run: bool
    attack_mode: bool
    roe_id: str
    scope_manifest: str
    skip_cloud: bool
    skip_keyscan: bool
    parallel_fanout: int
    report_provider: str | None
    report_max_loops: object | None
    auto_run_detected: bool
    go_hard: bool
    include_offensive_prereqs: bool
    use_tor: bool
    max_iterations: int
    dry_run_all: bool
    dry_run_keyscan: bool
    active_recon: bool
    credential_validate: bool
    resume_enabled: bool
    no_playwright: bool
    wayback_full: bool
    live_launch: bool
    require_scope_manifest: bool
    parallel_workers: int
    synthesis_depth_limit: int
    pending_validation_batch_limit: int
    max_runtime_minutes: int


ScopeManifestLoader = Callable[[str], dict[str, Any]]
BroadScopeManifestRejector = Callable[[dict[str, Any]], None]


def is_typer_default(value: object) -> bool:
    return isinstance(value, (OptionInfo, ArgumentInfo))


def normalize_roe_id(value: object) -> str:
    return " ".join(str(value or "").strip().split())[:160]


def normalize_kill_chain_runtime_options(
    *,
    related_seed: object,
    engagement: object,
    resume: object,
    max_iter: object,
    tor: object,
    dry_run: object,
    attack_mode: object,
    roe_id: object,
    scope_manifest: object,
    skip_cloud: object,
    skip_keyscan: object,
    parallel_fanout: object,
    report_provider: object,
    report_max_loops: object,
    auto_run_detected: object,
    go_hard: object,
    include_offensive_prereqs: object,
    max_runtime_minutes: object = None,
    env: MutableMapping[str, str] | None = None,
) -> KillChainRuntimeOptions:
    env_map = os.environ if env is None else env

    normalized_related_seed = None if is_typer_default(related_seed) else related_seed
    normalized_engagement = None if is_typer_default(engagement) else engagement
    normalized_resume = True if is_typer_default(resume) else bool(resume)
    normalized_max_iter = normalize_kill_chain_max_iter(
        None if is_typer_default(max_iter) else max_iter,
        default=7,
    )
    normalized_tor = False if is_typer_default(tor) else bool(tor)
    normalized_dry_run = False if is_typer_default(dry_run) else bool(dry_run)
    normalized_attack_mode = bool(attack_mode)
    normalized_roe_id = (
        env_map.get("FORGE_ROE_ID", "")
        if is_typer_default(roe_id) or roe_id is None
        else str(roe_id)
    )
    normalized_roe_id = normalize_roe_id(normalized_roe_id)
    normalized_scope_manifest = (
        env_map.get("FORGE_SCOPE_MANIFEST", "")
        if is_typer_default(scope_manifest) or scope_manifest is None
        else str(scope_manifest)
    )
    normalized_scope_manifest = str(normalized_scope_manifest or "").strip()
    normalized_skip_cloud = False if is_typer_default(skip_cloud) else bool(skip_cloud)
    normalized_skip_keyscan = False if is_typer_default(skip_keyscan) else bool(skip_keyscan)
    normalized_parallel_fanout = (
        4 if is_typer_default(parallel_fanout) else int(parallel_fanout)
    )
    normalized_report_provider = (
        None if is_typer_default(report_provider) else report_provider
    )
    normalized_report_provider = str(normalized_report_provider or "").strip() or None
    normalized_report_max_loops = (
        None if is_typer_default(report_max_loops) else report_max_loops
    )
    normalized_auto_run_detected = (
        True if is_typer_default(auto_run_detected) else bool(auto_run_detected)
    )
    normalized_include_offensive_prereqs = (
        bool(normalized_attack_mode)
        if is_typer_default(include_offensive_prereqs)
        else bool(include_offensive_prereqs)
    )
    normalized_go_hard = False if is_typer_default(go_hard) else bool(go_hard)

    if normalized_go_hard:
        normalized_max_iter = 20
        normalized_parallel_fanout = 8
        normalized_auto_run_detected = True
        env_map.setdefault("FORGE_COMMONCRAWL_INDEX_LIMIT", "5")
        env_map.setdefault("FORGE_COMMONCRAWL_RESULTS_PER_INDEX", "5000")
        env_map.setdefault("FORGE_IDENTITY_LOOKUP_MAX_WORKERS", "3")

    if (
        normalized_report_max_loops is not None
        and int(normalized_report_max_loops) < 0
    ):
        raise ValueError("--report-max-loops must be zero or greater.")

    live_launch = not normalized_dry_run
    try:
        parallel_workers = max(1, min(8, int(normalized_parallel_fanout or 4)))
    except (TypeError, ValueError):
        parallel_workers = 2
    synthesis_depth_limit = normalize_kill_chain_synthesis_depth(
        env_map.get("FORGE_KILL_CHAIN_SYNTHESIS_DEPTH"),
        default=3,
    )
    pending_validation_batch_limit = normalize_kill_chain_validation_batch_limit(
        env_map.get("FORGE_KILL_CHAIN_VALIDATION_BATCH_LIMIT"),
        default=16,
    )
    normalized_max_runtime_minutes = normalize_kill_chain_max_runtime_minutes(
        env_map.get("FORGE_KILL_CHAIN_MAX_RUNTIME_MINUTES")
        if is_typer_default(max_runtime_minutes) or max_runtime_minutes is None
        else max_runtime_minutes,
        default=25,
    )

    return KillChainRuntimeOptions(
        related_seed=normalized_related_seed,
        engagement=normalized_engagement,
        resume=normalized_resume,
        max_iter=normalized_max_iter,
        tor=normalized_tor,
        dry_run=normalized_dry_run,
        attack_mode=normalized_attack_mode,
        roe_id=normalized_roe_id,
        scope_manifest=normalized_scope_manifest,
        skip_cloud=normalized_skip_cloud,
        skip_keyscan=normalized_skip_keyscan,
        parallel_fanout=normalized_parallel_fanout,
        report_provider=normalized_report_provider,
        report_max_loops=normalized_report_max_loops,
        auto_run_detected=normalized_auto_run_detected,
        go_hard=normalized_go_hard,
        include_offensive_prereqs=normalized_include_offensive_prereqs,
        use_tor=normalized_tor,
        max_iterations=normalized_max_iter,
        dry_run_all=normalized_dry_run,
        dry_run_keyscan=normalized_dry_run,
        active_recon=normalized_attack_mode,
        credential_validate=normalized_attack_mode,
        resume_enabled=normalized_resume,
        no_playwright=False,
        wayback_full=True,
        live_launch=live_launch,
        require_scope_manifest=live_launch,
        parallel_workers=parallel_workers,
        synthesis_depth_limit=synthesis_depth_limit,
        pending_validation_batch_limit=pending_validation_batch_limit,
        max_runtime_minutes=normalized_max_runtime_minutes,
    )


def prime_kill_chain_attack_mode_env(
    options: KillChainRuntimeOptions,
    *,
    env: MutableMapping[str, str] | None = None,
) -> None:
    if not (
        options.attack_mode
        and options.live_launch
        and options.roe_id
        and options.scope_manifest
    ):
        return
    env_map = os.environ if env is None else env
    env_map.setdefault("FORGE_ATTACK_MODE_AUTO", "1")
    env_map.setdefault("FORGE_KEYSCAN_ASSUME_YES", "1")
    env_map.setdefault("FORGE_POST_LATERAL_ASSUME_YES", "1")


def load_kill_chain_scope_manifest_metadata(
    options: KillChainRuntimeOptions,
    *,
    load_scope_manifest: ScopeManifestLoader,
    reject_broad_scope_manifest_for_live: BroadScopeManifestRejector,
) -> dict[str, Any] | None:
    if options.live_launch and not options.roe_id:
        raise ValueError(
            "live kill-chain execution requires --roe-id or FORGE_ROE_ID. "
            "Use --dry-run to preview without live execution."
        )
    if options.require_scope_manifest and not options.scope_manifest:
        raise ValueError(
            "live kill-chain execution requires --scope-manifest or "
            "FORGE_SCOPE_MANIFEST so live execution is bounded to explicit authorization. "
            "Use --dry-run to preview without live execution."
        )
    if not options.scope_manifest:
        return None
    try:
        metadata = load_scope_manifest(options.scope_manifest)
        if options.live_launch:
            reject_broad_scope_manifest_for_live(metadata)
        manifest_roe_id = str(metadata.get("roe_id") or "").strip()
        if manifest_roe_id and options.roe_id and manifest_roe_id != options.roe_id:
            raise ValueError(
                f"scope manifest roe_id {manifest_roe_id!r} "
                f"does not match --roe-id {options.roe_id!r}"
            )
    except Exception as exc:  # noqa: BLE001
        raise ValueError(f"invalid --scope-manifest: {exc}") from exc
    return metadata


__all__ = [
    "BroadScopeManifestRejector",
    "KillChainRuntimeOptions",
    "ScopeManifestLoader",
    "is_typer_default",
    "load_kill_chain_scope_manifest_metadata",
    "normalize_kill_chain_runtime_options",
    "normalize_roe_id",
    "prime_kill_chain_attack_mode_env",
]
