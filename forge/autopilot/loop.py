"""Main autopilot loop — composes existing automation primitives.

``ForgeAutopilot`` is a single orchestrator that runs the full
auto-seed → auto-engage → auto-resume → auto-monitor → auto-dashboard
pipeline. Live execution (``apply=True``) requires an ROE; without one,
every phase runs in dry-run mode and no files are mutated.

Design constraints:

- No config file is required. Everything is auto-detected from
  :class:`forge.config.ForgeConfig` (environment variables) plus
  :class:`AutopilotDefaults`.
- Safety gates on the components still apply. ``FORGE_SAFE_MODE=1``
  overrides live mode back to dry-run. Scope manifest / ROE presence
  is enforced inside :func:`forge.targets_import.import_targets`.
- Phase failures do not abort the loop. Each phase returns a
  :class:`AutopilotPhaseResult`; the loop records them and continues.
- The loop is designed to be idempotent and cheap when re-run — feed
  dedupe, resume state, monitoring due-time, and dashboard timestamping
  all handle re-entry.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from forge.autopilot.defaults import AutopilotDefaults
from forge.config import ForgeConfig


AUTOPILOT_SCHEMA_VERSION = "forge.autopilot.v1"
_DEFAULT_SCOPE_MANIFEST_CANDIDATES = (
    Path("manifests") / "default.json",
    Path("imports") / "scope-manifest.local.json",
)


@dataclass
class AutopilotPhaseResult:
    """Outcome of a single autopilot phase.

    ``status`` is one of ``ok`` (completed), ``skipped`` (intentionally
    not run), ``blocked`` (gate failed), ``error`` (exception caught).
    """

    name: str
    status: str
    detail: str = ""
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "detail": self.detail,
            "data": self.data,
        }


class ForgeAutopilot:
    """Self-running loop over the FORGE automation pipeline.

    The autopilot binds together the already-existing building blocks
    (:func:`forge.automation_target_feed.build_target_feed`,
    :func:`forge.targets_import.import_targets`,
    :func:`forge.targets_resume_candidates.execute_target_resume_plan`,
    :func:`forge.monitoring.runner.run_due_monitoring_for_data_dir`,
    :func:`forge.reporting.dashboard.generate_dashboard`). Each phase
    runs independently; one failure never prevents the next phase.

    Public API:

    - :meth:`run_once` — a single pass through all phases.
    - :meth:`run` — ``run_once`` on a loop, sleeping ``cooldown_minutes``
      between iterations.
    - :meth:`describe` — read-only snapshot of resolved configuration
      without executing anything.
    """

    def __init__(
        self,
        *,
        data_dir: Path | None = None,
        imports_dir: Path | None = None,
        reports_dir: Path | None = None,
        feed_file: Path | None = None,
        roe_id: str | None = None,
        scope_manifest: Path | None = None,
        safe_mode: bool | None = None,
        defaults: AutopilotDefaults | None = None,
        config: ForgeConfig | None = None,
        skip_phases: set[str] | None = None,
    ) -> None:
        self._cfg = config or ForgeConfig.load()
        self.data_dir = Path(data_dir or self._cfg.data_dir)
        self.imports_dir = Path(imports_dir or "imports")
        self.reports_dir = Path(reports_dir or "reports")
        self.feed_file = Path(feed_file or self.imports_dir / "target-feed.json")

        self.defaults = defaults or AutopilotDefaults()

        env_roe = os.environ.get("FORGE_ROE_ID", "").strip()
        resolved_roe = (roe_id or env_roe).strip()
        if not resolved_roe:
            # Fall back to the baked-in default so autopilot always has
            # a non-empty ROE handle. Scope manifest enforcement is the
            # real gate for live kill-chain execution.
            resolved_roe = (self.defaults.default_roe_id or "").strip()
        self.roe_id = resolved_roe or None

        if scope_manifest is not None:
            self.scope_manifest: Path | None = Path(scope_manifest)
        else:
            env_manifest = os.environ.get("FORGE_SCOPE_MANIFEST", "").strip()
            if env_manifest:
                self.scope_manifest = Path(env_manifest)
            else:
                self.scope_manifest = self._auto_scope_manifest()

        if safe_mode is None:
            safe_mode = bool(self._cfg.safe_mode)
        self.safe_mode = bool(safe_mode)
        self.skip_phases: set[str] = {
            p.lower().strip() for p in (skip_phases or set())
        }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def has_roe(self) -> bool:
        """True when a non-empty ROE id is available."""
        return bool(self.roe_id)

    def resolve_execution_mode(self, *, dry_run: bool | None) -> str:
        """Return the effective mode: ``dry_run`` or ``apply``.

        Default behavior is **apply** — the autopilot runs live by
        default so operators who ``git clone && setup && autopilot``
        get working automation out of the box. Dry-run only kicks in
        when it is explicitly requested or when ``FORGE_SAFE_MODE=1``
        is set.

        Precedence:

        1. Explicit ``dry_run=True`` wins and forces dry-run.
        2. ``FORGE_SAFE_MODE=1`` forces dry-run (operator safety override).
        3. Explicit ``dry_run=False`` forces apply.
        4. Otherwise apply — the autopilot's default, since
           :class:`AutopilotDefaults` provides a default ROE handle.
        """
        if dry_run is True:
            return "dry_run"
        if self.safe_mode:
            return "dry_run"
        if dry_run is False:
            return "apply"
        return "apply"

    def describe(self) -> dict[str, Any]:
        """Return a read-only snapshot of resolved autopilot state."""
        return {
            "schema_version": AUTOPILOT_SCHEMA_VERSION,
            "data_dir": str(self.data_dir),
            "imports_dir": str(self.imports_dir),
            "reports_dir": str(self.reports_dir),
            "feed_file": str(self.feed_file),
            "roe_id_present": self.has_roe,
            "scope_manifest": (
                str(self.scope_manifest) if self.scope_manifest else None
            ),
            "safe_mode": self.safe_mode,
            "default_execution_mode": self.resolve_execution_mode(dry_run=None),
            "defaults": asdict(self.defaults),
        }

    def run_once(self, *, dry_run: bool | None = None) -> dict[str, Any]:
        """Single pass over every autopilot phase.

        Phases:

        1. Feed-fetch — refresh free/no-key threat-intel sources.
        2. Connected-services scan — spider GitHub + Supabase using
           stored connections so results flow into the target feed on
           the next ``feed_build`` pass.
        3. Auto-seed — build/refresh ``imports/target-feed.json``.
        4. Auto-engage — import feed, create engagements, start
           kill-chain for new targets.
        5. Auto-resume — resume ready paused/failed engagement runs.
        6. Auto-monitor — run due monitoring policies.
        7. Auto-dashboard — refresh the static operator dashboard.

        Returns a schema-versioned summary payload.
        """
        mode = self.resolve_execution_mode(dry_run=dry_run)
        is_dry_run = mode == "dry_run"
        started_at = _now_iso()
        phases: list[AutopilotPhaseResult] = []
        phases.append(self._maybe_phase("feed_fetch", is_dry_run))
        phases.append(self._maybe_phase("connected_services_scan", is_dry_run))
        phases.append(self._maybe_phase("feed_build", is_dry_run))
        phases.append(self._maybe_phase("auto_scope", is_dry_run))
        phases.append(self._maybe_phase("import_targets", is_dry_run))
        phases.append(self._maybe_phase("resume_candidates", is_dry_run))
        phases.append(self._maybe_phase("monitoring", is_dry_run))
        phases.append(self._maybe_phase("dashboard", is_dry_run))
        finished_at = _now_iso()
        return self._summarize(
            phases,
            mode=mode,
            dry_run=is_dry_run,
            started_at=started_at,
            finished_at=finished_at,
        )

    def run(
        self,
        *,
        dry_run: bool | None = None,
        iterations: int | None = None,
        sleep_fn: Any = None,
    ) -> dict[str, Any]:
        """Run the loop ``iterations`` times (default 1).

        When ``iterations`` > 1, the loop sleeps
        ``defaults.cooldown_minutes * 60`` seconds between passes.
        Pass a custom ``sleep_fn`` (e.g. ``time.sleep``) for test
        injection; defaults to :func:`time.sleep`.
        """
        if iterations is None or iterations <= 0:
            iterations = 1
        sleep = sleep_fn or time.sleep
        cooldown = max(0, int(self.defaults.cooldown_minutes)) * 60
        results: list[dict[str, Any]] = []
        for idx in range(iterations):
            payload = self.run_once(dry_run=dry_run)
            payload["iteration"] = idx + 1
            payload["total_iterations"] = iterations
            results.append(payload)
            if idx + 1 < iterations and cooldown:
                sleep(cooldown)
        last = results[-1] if results else {}
        last["iterations_run"] = len(results)
        return last

    # ------------------------------------------------------------------
    # Phase implementations
    # ------------------------------------------------------------------

    _PHASE_DISPATCH = {
        "feed_fetch": "_phase_feed_fetch",
        "connected_services_scan": "_phase_connected_services_scan",
        "feed_build": "_phase_feed_build",
        "auto_scope": "_phase_auto_scope",
        "import_targets": "_phase_import_targets",
        "resume_candidates": "_phase_resume_candidates",
        "monitoring": "_phase_monitoring",
        "dashboard": "_phase_dashboard",
    }

    def _maybe_phase(self, name: str, dry_run: bool) -> AutopilotPhaseResult:
        """Dispatch a phase or short-circuit when the operator skipped it."""
        if name in self.skip_phases:
            return AutopilotPhaseResult(
                name=name,
                status="skipped",
                detail="operator_skip_requested",
            )
        method = getattr(self, self._PHASE_DISPATCH[name])
        return method(dry_run=dry_run)

    def _phase_feed_fetch(self, *, dry_run: bool) -> AutopilotPhaseResult:
        """Refresh free/no-key threat-intel feeds before feed-build.

        Dry-run skips the network calls entirely — the autopilot
        rehearsal must stay offline-friendly. Apply runs every
        registered fetcher in :class:`forge.feeds.FeedFetcher`, which
        catches individual-source failures and never aborts the loop.
        """
        if dry_run:
            return AutopilotPhaseResult(
                name="feed_fetch",
                status="skipped",
                detail="dry_run_skips_network_fetch",
            )

        try:
            from forge.feeds import FeedFetcher  # noqa: PLC0415
        except Exception as exc:  # noqa: BLE001
            return AutopilotPhaseResult(
                name="feed_fetch",
                status="error",
                detail=f"import_error:{_bounded_text(exc)}",
            )

        try:
            fetcher = FeedFetcher(
                imports_dir=self.imports_dir,
                data_dir=self.data_dir,
            )
            payload = fetcher.fetch_all(timeout_per_source=60)
        except Exception as exc:  # noqa: BLE001
            return AutopilotPhaseResult(
                name="feed_fetch",
                status="error",
                detail=_bounded_text(exc),
            )

        status_counts = payload.get("status_counts", {}) or {}
        overall = payload.get("overall_status", "ok")
        return AutopilotPhaseResult(
            name="feed_fetch",
            status="ok" if overall in {"ok", "partial"} else "error",
            detail=(
                f"total_items={payload.get('total_item_count', 0)} "
                f"overall={overall} ok={status_counts.get('ok', 0)} "
                f"error={status_counts.get('error', 0)}"
            ),
            data={
                "overall_status": overall,
                "status_counts": dict(status_counts),
                "total_item_count": int(payload.get("total_item_count") or 0),
            },
        )

    def _phase_connected_services_scan(
        self, *, dry_run: bool
    ) -> AutopilotPhaseResult:
        """Spider every stored service connection into local seeds.

        Reads ``<data_dir>/connections.json`` and runs the deep scanner
        for each connection:

        - ``github`` → :class:`forge.onboard.github_spider.GitHubDeepScanner`
          over every stored org/user. Writes a sanitized seed drop to
          ``imports/connected-services-github-seeds.local.json`` so the
          next ``feed_build`` pass picks it up without a second network
          call.
        - ``supabase`` → :class:`forge.onboard.supabase_scanner.SupabaseDeepScanner`
          against the stored project ref using the stored anon/service
          key. Output goes to
          ``imports/connected-services-supabase-seeds.local.json``.

        Dry-run never hits the network and never writes files; it only
        reports what *would* run. Apply fails per-service rather than
        aborting the loop — one bad token should not disable the other
        services.
        """
        try:
            from forge.onboard.service_connections import (  # noqa: PLC0415
                ServiceConnectionManager,
            )
        except Exception as exc:  # noqa: BLE001
            return AutopilotPhaseResult(
                name="connected_services_scan",
                status="error",
                detail=f"import_error:{_bounded_text(exc)}",
            )

        try:
            manager = ServiceConnectionManager(self.data_dir)
            connections = manager.list_connections()
        except Exception as exc:  # noqa: BLE001
            return AutopilotPhaseResult(
                name="connected_services_scan",
                status="error",
                detail=_bounded_text(exc),
            )

        if not connections:
            return AutopilotPhaseResult(
                name="connected_services_scan",
                status="skipped",
                detail="no_service_connections_stored",
            )

        services_summary: list[dict[str, Any]] = []
        total_seeds = 0
        total_secret_hits = 0
        errors = 0
        for connection in connections:
            service = connection.service
            if service == "github":
                outcome = self._scan_github_connection(connection, dry_run=dry_run)
            elif service == "supabase":
                outcome = self._scan_supabase_connection(connection, dry_run=dry_run)
            else:
                outcome = {
                    "service": service,
                    "status": "skipped",
                    "detail": "no_deep_scanner_for_service",
                    "seeds": 0,
                    "secret_hits": 0,
                }
            services_summary.append(outcome)
            total_seeds += int(outcome.get("seeds") or 0)
            total_secret_hits += int(outcome.get("secret_hits") or 0)
            if outcome.get("status") == "error":
                errors += 1

        status = "ok" if errors == 0 else "error"
        return AutopilotPhaseResult(
            name="connected_services_scan",
            status=status,
            detail=(
                f"services={len(connections)} "
                f"seeds={total_seeds} "
                f"secrets={total_secret_hits} "
                f"errors={errors}"
            ),
            data={
                "dry_run": dry_run,
                "service_count": len(connections),
                "seeds_total": total_seeds,
                "secret_hits_total": total_secret_hits,
                "errors": errors,
                "services": services_summary,
            },
        )

    def _scan_github_connection(
        self, connection: Any, *, dry_run: bool
    ) -> dict[str, Any]:
        """Deep-scan a single GitHub connection."""
        config = connection.config or {}
        token = str(config.get("token") or "").strip()
        orgs = [str(o) for o in (config.get("orgs") or []) if o]
        users = [str(u) for u in (config.get("users") or []) if u]
        if not token:
            return {
                "service": "github",
                "status": "skipped",
                "detail": "no_token_in_connection",
                "seeds": 0,
                "secret_hits": 0,
            }
        if dry_run:
            return {
                "service": "github",
                "status": "skipped",
                "detail": "dry_run_skips_network_scan",
                "owners_planned": sorted(set(orgs + users)),
                "seeds": 0,
                "secret_hits": 0,
            }
        try:
            from forge.onboard.github_spider import (  # noqa: PLC0415
                GitHubDeepScanner,
                GitHubSpiderError,
            )
        except Exception as exc:  # noqa: BLE001
            return {
                "service": "github",
                "status": "error",
                "detail": f"import_error:{_bounded_text(exc)}",
                "seeds": 0,
                "secret_hits": 0,
            }
        try:
            scanner = GitHubDeepScanner(token=token, max_repos=100)
            result = scanner.scan_all(orgs=orgs or None, users=users or None)
        except GitHubSpiderError as exc:
            return {
                "service": "github",
                "status": "error",
                "detail": _bounded_text(exc),
                "seeds": 0,
                "secret_hits": 0,
            }
        except Exception as exc:  # noqa: BLE001
            return {
                "service": "github",
                "status": "error",
                "detail": _bounded_text(exc),
                "seeds": 0,
                "secret_hits": 0,
            }
        output_path = self.imports_dir / "connected-services-github-seeds.local.json"
        try:
            self._write_seed_drop(
                output_path,
                connector_id="github_deep_spider",
                input_kind="connected_services",
                seeds=result.seeds,
                secret_hits=result.secret_hits,
                extra={
                    "repos_scanned": result.repos_scanned,
                    "repos_total": result.repos_total,
                    "orgs_scanned": result.orgs_scanned,
                    "users_scanned": result.users_scanned,
                    "source_errors": result.source_errors[-20:],
                    "rate_limit": result.rate_limit,
                },
            )
        except OSError as exc:
            return {
                "service": "github",
                "status": "error",
                "detail": f"write_error:{_bounded_text(exc)}",
                "seeds": len(result.seeds),
                "secret_hits": len(result.secret_hits),
            }
        return {
            "service": "github",
            "status": "ok",
            "repos_scanned": result.repos_scanned,
            "seeds": len(result.seeds),
            "secret_hits": len(result.secret_hits),
            "output_path": str(output_path),
        }

    def _scan_supabase_connection(
        self, connection: Any, *, dry_run: bool
    ) -> dict[str, Any]:
        """Deep-scan a single Supabase connection."""
        config = connection.config or {}
        project_ref = str(config.get("project_ref") or "").strip()
        key = str(config.get("key") or "").strip()
        management_pat = str(
            config.get("management_pat") or os.environ.get("FORGE_SUPABASE_PAT") or ""
        ).strip()
        if not project_ref or (not key and not management_pat):
            return {
                "service": "supabase",
                "status": "skipped",
                "detail": "incomplete_connection_fields",
                "seeds": 0,
                "secret_hits": 0,
            }
        if dry_run:
            return {
                "service": "supabase",
                "status": "skipped",
                "detail": "dry_run_skips_network_scan",
                "project_ref": project_ref,
                "seeds": 0,
                "secret_hits": 0,
            }
        try:
            from forge.onboard.supabase_scanner import (  # noqa: PLC0415
                SupabaseDeepScanner,
                SupabaseScannerError,
            )
        except Exception as exc:  # noqa: BLE001
            return {
                "service": "supabase",
                "status": "error",
                "detail": f"import_error:{_bounded_text(exc)}",
                "seeds": 0,
                "secret_hits": 0,
            }
        try:
            scanner = SupabaseDeepScanner(
                project_ref=project_ref,
                api_key=key or None,
                management_pat=management_pat or None,
                max_tables=200,
                max_rows_per_table=10_000,
            )
            result = scanner.scan_all()
        except SupabaseScannerError as exc:
            return {
                "service": "supabase",
                "status": "error",
                "detail": _bounded_text(exc),
                "seeds": 0,
                "secret_hits": 0,
            }
        except Exception as exc:  # noqa: BLE001
            return {
                "service": "supabase",
                "status": "error",
                "detail": _bounded_text(exc),
                "seeds": 0,
                "secret_hits": 0,
            }
        output_path = (
            self.imports_dir / "connected-services-supabase-seeds.local.json"
        )
        try:
            self._write_seed_drop(
                output_path,
                connector_id="supabase_deep_scanner",
                input_kind="connected_services",
                seeds=result.seeds,
                secret_hits=result.secret_hits,
                extra={
                    "project_ref": result.project_ref,
                    "tables_total": result.tables_total,
                    "tables_scanned": result.tables_scanned,
                    "rows_scanned": result.rows_scanned,
                    "transport": (
                        "management_api" if management_pat else "postgrest"
                    ),
                    "source_errors": result.source_errors[-20:],
                },
            )
        except OSError as exc:
            return {
                "service": "supabase",
                "status": "error",
                "detail": f"write_error:{_bounded_text(exc)}",
                "seeds": len(result.seeds),
                "secret_hits": len(result.secret_hits),
            }
        return {
            "service": "supabase",
            "status": "ok",
            "tables_scanned": result.tables_scanned,
            "rows_scanned": result.rows_scanned,
            "seeds": len(result.seeds),
            "secret_hits": len(result.secret_hits),
            "output_path": str(output_path),
        }

    def _write_seed_drop(
        self,
        path: Path,
        *,
        connector_id: str,
        input_kind: str,
        seeds: list[dict[str, Any]],
        secret_hits: list[dict[str, Any]],
        extra: dict[str, Any],
    ) -> None:
        """Write a scanner seed drop to disk atomically.

        The output shape matches the other ``imports/*.local.json`` feed
        drop files so ``automation_target_feed.build_target_feed`` picks
        them up on the next cycle.
        """
        self.imports_dir.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema_version": "forge.connected_services_scan.v1",
            "connector_id": connector_id,
            "input_kind": input_kind,
            "generated_at": _now_iso(),
            "seeds": list(seeds),
            "secret_hits": list(secret_hits),
            **extra,
        }
        tmp_path = path.with_suffix(path.suffix + ".tmp")
        tmp_path.write_text(
            json.dumps(payload, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        os.replace(tmp_path, path)

    def _phase_feed_build(self, *, dry_run: bool) -> AutopilotPhaseResult:
        """Build and (when applying) write the local target feed."""
        try:
            from forge.automation_target_feed import (  # noqa: PLC0415
                build_target_feed,
                write_target_feed,
            )
        except Exception as exc:  # noqa: BLE001
            return AutopilotPhaseResult(
                name="feed_build",
                status="error",
                detail=f"import_error:{_bounded_text(exc)}",
            )

        try:
            payload = build_target_feed(
                sources=list(self.defaults.feed_sources),
                data_dir=self.data_dir,
                reports_dir=self.reports_dir,
                imports_dir=self.imports_dir,
                limit=self.defaults.import_limit,
                existing_feed_path=self.feed_file,
                apply=not dry_run,
                supabase_config_path=(
                    self.imports_dir / "supabase-projects.local.json"
                ),
            )
        except Exception as exc:  # noqa: BLE001
            return AutopilotPhaseResult(
                name="feed_build",
                status="error",
                detail=_bounded_text(exc),
            )

        written = False
        if not dry_run:
            try:
                write_target_feed(payload, self.feed_file)
                written = True
            except Exception as exc:  # noqa: BLE001
                return AutopilotPhaseResult(
                    name="feed_build",
                    status="error",
                    detail=f"write_error:{_bounded_text(exc)}",
                    data={"counts": payload.get("counts", {})},
                )

        counts = payload.get("counts", {})
        return AutopilotPhaseResult(
            name="feed_build",
            status="ok",
            detail=(
                f"total={counts.get('total', 0)} "
                f"new={counts.get('new_vs_existing', 0)} "
                f"written={written}"
            ),
            data={
                "written": written,
                "feed_file": str(self.feed_file),
                "counts": counts,
                "source_errors": payload.get("source_errors", []),
            },
        )

    def _phase_auto_scope(self, *, dry_run: bool) -> AutopilotPhaseResult:
        """Auto-expand the scope manifest from recently discovered seeds.

        Rules (see :mod:`forge.onboard.auto_scope`):

        - Subdomains of already-scoped domains are auto-added.
        - URLs whose hostname is already scoped are auto-added.
        - IPs are only added when the candidate's ``related_domains``
          list points at an already-scoped domain.
        - New unrelated domains stay in ``review_required`` instead of
          silently widening the operator's authorized boundary.

        Dry-run returns the expansion preview without writing. Apply
        writes the merged manifest when at least one new entry is
        accepted.
        """
        if self.scope_manifest is None or not Path(self.scope_manifest).is_file():
            return AutopilotPhaseResult(
                name="auto_scope",
                status="skipped",
                detail="no_scope_manifest_configured",
            )
        if not self.feed_file.is_file():
            return AutopilotPhaseResult(
                name="auto_scope",
                status="skipped",
                detail="no_feed_file_present",
            )

        try:
            from forge.onboard.auto_scope import (  # noqa: PLC0415
                expand_scope_from_feeds,
                normalize_candidate,
            )
        except Exception as exc:  # noqa: BLE001
            return AutopilotPhaseResult(
                name="auto_scope",
                status="error",
                detail=f"import_error:{_bounded_text(exc)}",
            )

        candidates: list[dict[str, Any]] = []
        try:
            feed_text = Path(self.feed_file).read_text(encoding="utf-8")
            feed_payload = json.loads(feed_text) if feed_text.strip() else {}
        except (OSError, json.JSONDecodeError) as exc:
            return AutopilotPhaseResult(
                name="auto_scope",
                status="error",
                detail=f"feed_parse_error:{_bounded_text(exc)}",
            )
        for item in (feed_payload.get("items") or []):
            if not isinstance(item, dict):
                continue
            try:
                candidates.append(
                    normalize_candidate(
                        str(item.get("target_value") or item.get("value") or ""),
                        seed_type=item.get("target_type") or item.get("seed_type"),
                        related_domains=item.get("related_domains") or [],
                    )
                )
            except ValueError:
                continue

        try:
            result = expand_scope_from_feeds(
                self.scope_manifest,
                candidates,
                apply=not dry_run,
            )
        except Exception as exc:  # noqa: BLE001
            return AutopilotPhaseResult(
                name="auto_scope",
                status="error",
                detail=_bounded_text(exc),
            )

        return AutopilotPhaseResult(
            name="auto_scope",
            status="ok",
            detail=(
                f"accepted={len(result.accepted)} "
                f"review={len(result.review_required)} "
                f"unchanged={result.unchanged}"
            ),
            data={
                "manifest_path": result.manifest_path,
                "accepted_count": len(result.accepted),
                "review_required_count": len(result.review_required),
                "added_domains": result.added_domains,
                "added_urls": result.added_urls,
                "added_ip_ranges": result.added_ip_ranges,
                "unchanged": result.unchanged,
                "dry_run": dry_run,
            },
        )

    def _phase_import_targets(self, *, dry_run: bool) -> AutopilotPhaseResult:
        """Import the local target feed, auto-starting kill-chain runs.

        Blocked (not an error) when live mode is requested but no ROE
        is present — the operator can't start kill-chain runs without
        authorization. In that case the autopilot drops to dry-run for
        this phase alone and keeps going.
        """
        if not self.feed_file.is_file():
            return AutopilotPhaseResult(
                name="import_targets",
                status="skipped",
                detail=f"feed_missing:{self.feed_file}",
            )

        try:
            from forge.targets_import import import_targets  # noqa: PLC0415
        except Exception as exc:  # noqa: BLE001
            return AutopilotPhaseResult(
                name="import_targets",
                status="error",
                detail=f"import_error:{_bounded_text(exc)}",
            )

        start = not dry_run and self.has_roe
        effective_dry_run = dry_run or not self.has_roe
        try:
            results = import_targets(
                feed_url=None,
                feed_file=self.feed_file,
                auth_header_env=None,
                roe_id=self.roe_id,
                start=start,
                dry_run=effective_dry_run,
                limit=self.defaults.import_limit,
                max_iter=self.defaults.max_iter,
                max_runtime_minutes=self.defaults.max_runtime_minutes,
                start_limit=self.defaults.start_limit,
                min_start_source_count=self.defaults.min_start_source_count,
                config=self._cfg,
            )
        except Exception as exc:  # noqa: BLE001
            return AutopilotPhaseResult(
                name="import_targets",
                status="error",
                detail=_bounded_text(exc),
            )

        created = sum(1 for r in results if r.created)
        started = sum(1 for r in results if r.started)
        status_label = "ok"
        if effective_dry_run and not dry_run:
            status_label = "blocked"
        return AutopilotPhaseResult(
            name="import_targets",
            status=status_label,
            detail=(
                f"total={len(results)} created={created} "
                f"started={started} start_requested={start}"
            ),
            data={
                "dry_run": effective_dry_run,
                "start_requested": start,
                "total": len(results),
                "created": created,
                "started": started,
            },
        )

    def _phase_resume_candidates(self, *, dry_run: bool) -> AutopilotPhaseResult:
        """Resume ready paused/failed kill-chain runs."""
        try:
            from forge.targets_resume_candidates import (  # noqa: PLC0415
                execute_target_resume_plan,
            )
        except Exception as exc:  # noqa: BLE001
            return AutopilotPhaseResult(
                name="resume_candidates",
                status="error",
                detail=f"import_error:{_bounded_text(exc)}",
            )

        try:
            payload = execute_target_resume_plan(
                data_dir=self.data_dir,
                limit=self.defaults.resume_limit,
                max_runtime_minutes=self.defaults.max_runtime_minutes,
                max_parallel=self.defaults.max_parallel,
                dry_run=dry_run,
                stop_on_failure=False,
                break_stale_lock=True,
            )
        except Exception as exc:  # noqa: BLE001
            return AutopilotPhaseResult(
                name="resume_candidates",
                status="error",
                detail=_bounded_text(exc),
            )

        counts = payload.get("result_counts", {})
        return AutopilotPhaseResult(
            name="resume_candidates",
            status="ok",
            detail=(
                f"status={payload.get('status', '?')} "
                f"planned={payload.get('planned_count', 0)} "
                f"skipped={payload.get('skipped_count', 0)}"
            ),
            data={
                "dry_run": dry_run,
                "status": payload.get("status"),
                "planned_count": payload.get("planned_count", 0),
                "result_counts": dict(counts),
            },
        )

    def _phase_monitoring(self, *, dry_run: bool) -> AutopilotPhaseResult:
        """Run due monitoring policies in a bounded batch."""
        try:
            from forge.monitoring.runner import (  # noqa: PLC0415
                run_due_monitoring_for_data_dir,
            )
        except Exception as exc:  # noqa: BLE001
            return AutopilotPhaseResult(
                name="monitoring",
                status="error",
                detail=f"import_error:{_bounded_text(exc)}",
            )

        try:
            payload = run_due_monitoring_for_data_dir(
                self.data_dir,
                limit=self.defaults.monitor_limit,
                dry_run=dry_run,
            )
        except Exception as exc:  # noqa: BLE001
            return AutopilotPhaseResult(
                name="monitoring",
                status="error",
                detail=_bounded_text(exc),
            )

        return AutopilotPhaseResult(
            name="monitoring",
            status="ok",
            detail=(
                f"due={payload.get('due_count', 0)} "
                f"run={payload.get('run_count', 0)} "
                f"alerts={payload.get('alert_count', 0)}"
            ),
            data={
                "dry_run": dry_run,
                "due_count": payload.get("due_count", 0),
                "run_count": payload.get("run_count", 0),
                "alert_count": payload.get("alert_count", 0),
                "change_count": payload.get("change_count", 0),
            },
        )

    def _phase_dashboard(self, *, dry_run: bool) -> AutopilotPhaseResult:
        """Rebuild the static engagement dashboard."""
        if dry_run:
            return AutopilotPhaseResult(
                name="dashboard",
                status="skipped",
                detail="dry_run_skips_local_writes",
            )

        try:
            from forge.reporting.dashboard import generate_dashboard  # noqa: PLC0415
        except Exception as exc:  # noqa: BLE001
            return AutopilotPhaseResult(
                name="dashboard",
                status="error",
                detail=f"import_error:{_bounded_text(exc)}",
            )

        output_path = self.reports_dir / "dashboard.html"
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            result = generate_dashboard(
                data_dir=self.data_dir,
                reports_dir=self.reports_dir,
                output_path=output_path,
                include_legacy=True,
            )
        except Exception as exc:  # noqa: BLE001
            return AutopilotPhaseResult(
                name="dashboard",
                status="error",
                detail=_bounded_text(exc),
            )

        size = 0
        try:
            size = result.stat().st_size
        except OSError:
            pass
        return AutopilotPhaseResult(
            name="dashboard",
            status="ok",
            detail=f"path={result} bytes={size}",
            data={"path": str(result), "bytes": size},
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _auto_scope_manifest(self) -> Path | None:
        """Locate a scope manifest without demanding one.

        Returns the first existing candidate; otherwise ``None``.
        The autopilot never fabricates a manifest.
        """
        for candidate in _DEFAULT_SCOPE_MANIFEST_CANDIDATES:
            if candidate.is_file():
                return candidate
        return None

    def _summarize(
        self,
        phases: list[AutopilotPhaseResult],
        *,
        mode: str,
        dry_run: bool,
        started_at: str,
        finished_at: str,
    ) -> dict[str, Any]:
        """Fold phase results into a schema-versioned summary payload."""
        status_counts: dict[str, int] = {}
        for phase in phases:
            status_counts[phase.status] = status_counts.get(phase.status, 0) + 1
        overall_status = "ok"
        if status_counts.get("error"):
            overall_status = "error"
        elif status_counts.get("blocked"):
            overall_status = "blocked"
        elif status_counts.get("skipped") and not status_counts.get("ok"):
            overall_status = "skipped"
        return {
            "schema_version": AUTOPILOT_SCHEMA_VERSION,
            "execution_policy": (
                "dry_run_no_writes_or_live_commands_executed"
                if dry_run
                else "apply_full_automation_pipeline"
            ),
            "mode": mode,
            "dry_run": dry_run,
            "status": overall_status,
            "started_at": started_at,
            "finished_at": finished_at,
            "config": self.describe(),
            "status_counts": status_counts,
            "phases": [phase.to_dict() for phase in phases],
        }


# ----------------------------------------------------------------------
# Module-level helpers
# ----------------------------------------------------------------------


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _bounded_text(exc: BaseException, limit: int = 240) -> str:
    text = str(exc).strip() or exc.__class__.__name__
    if len(text) > limit:
        return text[: limit - 1] + "\u2026"
    return text


__all__ = [
    "AUTOPILOT_SCHEMA_VERSION",
    "AutopilotPhaseResult",
    "ForgeAutopilot",
]
