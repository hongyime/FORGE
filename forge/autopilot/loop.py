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

        env_roe = os.environ.get("FORGE_ROE_ID", "").strip()
        self.roe_id = (roe_id or env_roe).strip() or None

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
        self.defaults = defaults or AutopilotDefaults()
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

        Precedence:

        1. Explicit ``dry_run`` argument wins when passed.
        2. ``FORGE_SAFE_MODE=1`` always forces ``dry_run``.
        3. ``FORGE_ROE_ID`` presence promotes to ``apply``.
        4. Otherwise ``dry_run``.
        """
        if dry_run is True:
            return "dry_run"
        if dry_run is False:
            # explicit apply still blocks under SAFE_MODE
            return "dry_run" if self.safe_mode else "apply"
        if self.safe_mode:
            return "dry_run"
        return "apply" if self.has_roe else "dry_run"

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

        1. Auto-seed — build/refresh ``imports/target-feed.json``.
        2. Auto-engage — import feed, create engagements, start
           kill-chain for new targets.
        3. Auto-resume — resume ready paused/failed engagement runs.
        4. Auto-monitor — run due monitoring policies.
        5. Auto-dashboard — refresh the static operator dashboard.

        Returns a schema-versioned summary payload.
        """
        mode = self.resolve_execution_mode(dry_run=dry_run)
        is_dry_run = mode == "dry_run"
        started_at = _now_iso()
        phases: list[AutopilotPhaseResult] = []
        phases.append(self._maybe_phase("feed_build", is_dry_run))
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
        "feed_build": "_phase_feed_build",
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
