"""forge.dashboard.goal_progress — Cairn-style goal progress visualization.

Task 11 (Explore #16). Combines two deterministic data sources:

- The ``recursion_intents`` SQLite table (Wave 2 #20) for Fact/Intent board
  counts.
- The ``forge.exploitation.goal_engine`` on-disk goal_state.json for goal
  type / phase history / current intent.
- The ``forge.exploitation.credential_store`` on-disk index.json for
  captured credential, session, and MFA counts.
- The sibling ``exploitation/{module}/{engagement_id}/`` result trees for
  per-module activity counts.

Rendering is deterministic — same inputs produce the same JSON and HTML.
No LLM narrative is involved.
"""

from __future__ import annotations

import html
import json
import os
import sqlite3
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from forge.exploitation.goal_engine import (
    FORGE_GOAL_CATALOG_VERSION,
    FORGE_GOALS,
)

__all__ = [
    "get_goal_progress",
    "get_exploitation_summary",
    "generate_goal_dashboard_json",
    "generate_goal_dashboard_html",
    "GOAL_DASHBOARD_SCHEMA_VERSION",
]

GOAL_DASHBOARD_SCHEMA_VERSION = "forge.dashboard.goal_progress.v1"

_PHASES: tuple[str, ...] = (
    "unset",
    "bootstrap",
    "reasoning",
    "exploring",
    "achieved",
    "failed",
)
_INTENT_STATUSES: tuple[str, ...] = ("open", "claimed", "completed", "abandoned")
_EXPLOITATION_MODULES: tuple[str, ...] = (
    "credential_store",
    "muraena",
    "necrobrowser",
    "strix",
    "goal_engine",
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def get_goal_progress(
    db_path: str | os.PathLike[str] | None,
    engagement_id: str | int,
    *,
    data_dir: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """Return goal progress snapshot for a single engagement.

    See the module docstring for the data shape. Fields:

    - ``goal_type`` / ``goal_status`` / ``catalog_version``
    - ``facts_count`` (completed intents observed as Facts)
    - ``intents_open`` / ``intents_claimed`` / ``intents_completed`` / ``intents_abandoned``
    - ``progress_percentage`` (0-100)
    - ``phase_history`` (list of {phase, timestamp, result})
    - ``current_intent`` (target seed being explored, or None)
    """
    engagement_id_text = str(engagement_id).strip()
    counts = _intent_counts(db_path, engagement_id_text)
    completed = counts["completed"]
    total = counts["total"]
    percentage = (
        int(round((completed / total) * 100)) if total else 0
    )

    state = _load_goal_state(data_dir, engagement_id_text)
    current_intent = None
    current_intent_id = state.get("current_intent_id")
    if current_intent_id and db_path and Path(db_path).exists():
        current_intent = _lookup_intent(db_path, current_intent_id)

    return {
        "schema_version": GOAL_DASHBOARD_SCHEMA_VERSION,
        "engagement_id": engagement_id_text,
        "goal_type": state.get("goal_type"),
        "goal_status": state.get("goal_status") or "unset",
        "catalog_version": state.get("catalog_version") or FORGE_GOAL_CATALOG_VERSION,
        "known_goals": list(FORGE_GOALS),
        "facts_count": completed,
        "intents_open": counts["open"],
        "intents_claimed": counts["claimed"],
        "intents_completed": counts["completed"],
        "intents_abandoned": counts["abandoned"],
        "intents_total": total,
        "progress_percentage": percentage,
        "phase_history": list(state.get("phase_history") or []),
        "current_intent": current_intent,
        "current_intent_id": current_intent_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def get_exploitation_summary(
    data_dir: str | os.PathLike[str],
    engagement_id: str | int,
) -> dict[str, Any]:
    """Return a summary of exploitation module activity for an engagement."""
    engagement_id_text = str(engagement_id).strip()
    root = Path(data_dir).expanduser() / "exploitation"

    cred_counts = _credential_counts(root, engagement_id_text)
    strix_counts = _strix_counts(root, engagement_id_text)
    necro_counts = _necrobrowser_counts(root, engagement_id_text)
    goal_counts = _goal_engine_counts(root, engagement_id_text)
    goals_achieved = 1 if goal_counts["achieved"] else 0

    modules_active: list[str] = []
    if cred_counts["total"]:
        modules_active.append("credential_store")
    if necro_counts["results"]:
        modules_active.append("necrobrowser")
    if strix_counts["results"]:
        modules_active.append("strix")
    if goal_counts["goal_type"]:
        modules_active.append("goal_engine")
    # ``muraena`` is only observable through credential store writes;
    # if any credential has source matching "muraena" treat the lane as active.
    if cred_counts["sources"].get("muraena") or any(
        "muraena" in str(src).lower() for src in cred_counts["sources"]
    ):
        modules_active.append("muraena")

    return {
        "schema_version": GOAL_DASHBOARD_SCHEMA_VERSION,
        "engagement_id": engagement_id_text,
        "modules_active": modules_active,
        "credentials_captured": cred_counts["passwords"],
        "sessions_captured": cred_counts["sessions"],
        "mfa_tokens_captured": cred_counts["mfa_tokens"],
        "credentials_total": cred_counts["total"],
        "strix_findings_count": strix_counts["findings"],
        "strix_scans_count": strix_counts["scans"],
        "necrobrowser_tasks_count": necro_counts["results"],
        "goals_achieved": goals_achieved,
        "goal_type": goal_counts["goal_type"],
        "goal_status": goal_counts["goal_status"],
        "credential_sources": cred_counts["sources"],
        "root": str(root),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def generate_goal_dashboard_json(
    db_path: str | os.PathLike[str] | None,
    data_dir: str | os.PathLike[str],
    engagement_id: str | int,
) -> dict[str, Any]:
    """Return the combined JSON payload rendered by :func:`generate_goal_dashboard_html`."""
    engagement_id_text = str(engagement_id).strip()
    progress = get_goal_progress(db_path, engagement_id_text, data_dir=data_dir)
    exploitation = get_exploitation_summary(data_dir, engagement_id_text)
    return {
        "schema_version": GOAL_DASHBOARD_SCHEMA_VERSION,
        "engagement_id": engagement_id_text,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "goal_progress": progress,
        "exploitation_summary": exploitation,
    }


def generate_goal_dashboard_html(
    db_path: str | os.PathLike[str] | None,
    data_dir: str | os.PathLike[str],
    engagement_id: str | int,
    output_path: str | os.PathLike[str],
) -> Path:
    """Render the goal progress dashboard as a self-contained HTML page."""
    payload = generate_goal_dashboard_json(db_path, data_dir, engagement_id)
    out = Path(output_path).expanduser()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(_render_html(payload), encoding="utf-8")
    return out


# ---------------------------------------------------------------------------
# Data loaders
# ---------------------------------------------------------------------------


def _intent_counts(
    db_path: str | os.PathLike[str] | None,
    engagement_id: str,
) -> dict[str, int]:
    counts = {status: 0 for status in _INTENT_STATUSES}
    counts["total"] = 0
    if not db_path:
        return counts
    db_path = Path(db_path)
    if not db_path.exists():
        return counts
    try:
        with sqlite3.connect(str(db_path), timeout=5.0) as conn:
            conn.row_factory = sqlite3.Row
            # Check the table exists before querying.
            exists = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='recursion_intents'"
            ).fetchone()
            if not exists:
                return counts
            rows = conn.execute(
                """
                SELECT status, COUNT(*) AS c FROM recursion_intents
                WHERE engagement_id = ?
                GROUP BY status
                """,
                (engagement_id,),
            ).fetchall()
            for row in rows:
                status = str(row["status"] or "").lower()
                if status in counts:
                    counts[status] = int(row["c"])
                counts["total"] += int(row["c"])
    except sqlite3.DatabaseError:
        pass
    return counts


def _lookup_intent(
    db_path: str | os.PathLike[str],
    intent_id: str,
) -> dict[str, Any] | None:
    try:
        with sqlite3.connect(str(db_path), timeout=5.0) as conn:
            conn.row_factory = sqlite3.Row
            exists = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='recursion_intents'"
            ).fetchone()
            if not exists:
                return None
            row = conn.execute(
                """
                SELECT intent_id, target_seed, seed_type, rationale, status,
                       created_at, claimed_by, claimed_at
                FROM recursion_intents
                WHERE intent_id = ?
                """,
                (intent_id,),
            ).fetchone()
            if row is None:
                return None
            return {
                "intent_id": row["intent_id"],
                "target_seed": row["target_seed"],
                "seed_type": row["seed_type"],
                "rationale": row["rationale"],
                "status": row["status"],
                "created_at": row["created_at"],
                "claimed_by": row["claimed_by"],
                "claimed_at": row["claimed_at"],
            }
    except sqlite3.DatabaseError:
        return None


def _load_goal_state(
    data_dir: str | os.PathLike[str] | None,
    engagement_id: str,
) -> dict[str, Any]:
    """Load the goal engine state file.

    Two formats are supported, in priority order:

    1. Subprocess-driver layout at
       ``exploitation/goals/engagement_<id>/goal_state.json`` with the
       fields ``goal``/``status``/``bootstrap_done``/``iterations``.
    2. Scaffold layout at
       ``exploitation/goal_engine/<id>/goal_state.json`` with
       ``goal_type``/``goal_status``/``phase_history``/``current_intent_id``.

    The return dict always uses the scaffold field names so the dashboard
    renderer and ``get_goal_progress`` output stay stable across backends.
    """
    if not data_dir:
        return {}
    base = Path(data_dir).expanduser() / "exploitation"
    candidates = (
        base / "goals" / f"engagement_{engagement_id}" / "goal_state.json",
        base / "goal_engine" / engagement_id / "goal_state.json",
    )
    for candidate in candidates:
        if not candidate.exists():
            continue
        try:
            data = json.loads(candidate.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(data, Mapping):
            continue
        return _normalize_goal_state(dict(data))
    return {}


def _normalize_goal_state(state: dict[str, Any]) -> dict[str, Any]:
    """Normalize goal state dicts into the shared dashboard shape."""
    goal_type = state.get("goal_type") or state.get("goal")
    goal_status = state.get("goal_status") or state.get("status") or "unset"
    # Subprocess-driver status values map to the scaffold's phase labels.
    status_map = {
        "idle": "unset",
        "goal_pending": "bootstrap" if not state.get("bootstrap_done") else "reasoning",
        "new_intents": "exploring",
        "no_op": "exploring",
        "goal_met": "achieved",
    }
    goal_status = status_map.get(str(goal_status), goal_status)
    phase_history = list(state.get("phase_history") or [])
    if not phase_history:
        # Derive a 1-2 entry history from subprocess-driver fields so the
        # dashboard timeline is never empty when a goal has been set.
        if goal_type:
            created_ts = state.get("created_at")
            if isinstance(created_ts, (int, float)):
                created_iso = datetime.fromtimestamp(
                    float(created_ts), tz=timezone.utc
                ).isoformat()
            else:
                created_iso = str(created_ts) if created_ts else ""
            updated_ts = state.get("updated_at")
            if isinstance(updated_ts, (int, float)):
                updated_iso = datetime.fromtimestamp(
                    float(updated_ts), tz=timezone.utc
                ).isoformat()
            else:
                updated_iso = str(updated_ts) if updated_ts else created_iso
            phase_history.append(
                {
                    "phase": "bootstrap",
                    "timestamp": created_iso,
                    "result": f"goal={goal_type}",
                }
            )
            if state.get("bootstrap_done"):
                phase_history.append(
                    {
                        "phase": goal_status or "reasoning",
                        "timestamp": updated_iso,
                        "result": f"iterations={state.get('iterations', 0)}",
                    }
                )
    return {
        "goal_type": goal_type,
        "goal_status": goal_status,
        "catalog_version": state.get("catalog_version") or FORGE_GOAL_CATALOG_VERSION,
        "phase_history": phase_history,
        "current_intent_id": state.get("current_intent_id"),
        "bootstrap_done": state.get("bootstrap_done"),
        "iterations": int(state.get("iterations") or 0),
        "created_at": state.get("created_at"),
        "updated_at": state.get("updated_at"),
    }


def _credential_counts(root: Path, engagement_id: str) -> dict[str, Any]:
    engagement_dir = root / "credentials" / engagement_id
    counts: dict[str, Any] = {
        "passwords": 0,
        "sessions": 0,
        "mfa_tokens": 0,
        "total": 0,
        "sources": {},
    }
    index_path = engagement_dir / "index.json"
    if index_path.exists():
        try:
            data = json.loads(index_path.read_text(encoding="utf-8"))
            if isinstance(data, Mapping):
                index_counts = data.get("counts") or {}
                for key in ("passwords", "sessions", "mfa_tokens"):
                    counts[key] = int(index_counts.get(key) or 0)
                counts["total"] = sum(counts[key] for key in ("passwords", "sessions", "mfa_tokens"))
                for cred in data.get("credentials") or []:
                    source = str((cred or {}).get("source") or "").strip() or "unknown"
                    counts["sources"][source] = counts["sources"].get(source, 0) + 1
                return counts
        except (OSError, json.JSONDecodeError):
            pass
    # Fallback: count files directly.
    for bucket in ("passwords", "sessions", "mfa_tokens"):
        bucket_dir = engagement_dir / bucket
        if bucket_dir.exists():
            counts[bucket] = sum(1 for _ in bucket_dir.glob("*.json"))
    counts["total"] = sum(counts[k] for k in ("passwords", "sessions", "mfa_tokens"))
    return counts


def _strix_counts(root: Path, engagement_id: str) -> dict[str, int]:
    engagement_dir = root / "strix" / engagement_id
    findings = 0
    scans = 0
    if engagement_dir.exists():
        for path in engagement_dir.glob("*.json"):
            name = path.name
            if name.startswith("finding."):
                findings += 1
            else:
                scans += 1
    return {"findings": findings, "scans": scans, "results": findings + scans}


def _necrobrowser_counts(root: Path, engagement_id: str) -> dict[str, int]:
    engagement_dir = root / "necrobrowser" / engagement_id
    results = sum(1 for _ in engagement_dir.glob("*.json")) if engagement_dir.exists() else 0
    return {"results": results}


def _goal_engine_counts(root: Path, engagement_id: str) -> dict[str, Any]:
    """Return goal engine summary from either state-file layout."""
    candidates = (
        root / "goals" / f"engagement_{engagement_id}" / "goal_state.json",
        root / "goal_engine" / engagement_id / "goal_state.json",
    )
    for state_path in candidates:
        if not state_path.exists():
            continue
        try:
            state = json.loads(state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(state, Mapping):
            continue
        goal_type = state.get("goal_type") or state.get("goal")
        raw_status = str(state.get("goal_status") or state.get("status") or "").lower() or None
        achieved = raw_status in ("achieved", "goal_met")
        return {
            "goal_type": goal_type,
            "goal_status": raw_status,
            "achieved": achieved,
        }
    return {"goal_type": None, "goal_status": None, "achieved": False}


# ---------------------------------------------------------------------------
# HTML rendering
# ---------------------------------------------------------------------------


_HTML_HEAD = """<!DOCTYPE html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <title>FORGE Goal Progress — Engagement {engagement_id}</title>
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <style>
    :root{{
      --bg:#0b1020; --panel:#11172a; --panel-alt:#16203a; --border:#26324f;
      --text:#e8edf7; --muted:#91a0bc; --accent:#66d9c2; --accent-strong:#97f6d2;
      --warn:#f7c95f; --danger:#ff7a7a; --good:#77d68a; --link:#8ec5ff;
      --shadow:0 18px 46px rgba(0,0,0,.30);
    }}
    *{{box-sizing:border-box}}
    body{{
      margin:0;
      background:
        radial-gradient(circle at top right, rgba(102,217,194,.12), transparent 28%),
        radial-gradient(circle at top left, rgba(142,197,255,.10), transparent 24%),
        linear-gradient(180deg, #0a0f1d 0%, #0b1020 56%, #090d18 100%);
      color:var(--text);
      font:14px/1.5 \"Segoe UI\", Inter, system-ui, sans-serif;
    }}
    .shell{{max-width:1200px;margin:0 auto;padding:28px 22px 40px}}
    .hero{{
      display:flex;justify-content:space-between;gap:18px;align-items:flex-end;
      margin-bottom:24px;padding:24px;border:1px solid var(--border);
      border-radius:20px;background:linear-gradient(160deg, rgba(17,23,42,.98), rgba(12,17,31,.88));
      box-shadow:var(--shadow);
    }}
    .hero h1{{margin:0 0 6px;font-size:30px;line-height:1.05;letter-spacing:-.03em}}
    .muted{{color:var(--muted)}}
    .stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:18px 0 24px}}
    .stat{{
      padding:14px 16px;border-radius:16px;border:1px solid var(--border);
      background:linear-gradient(180deg, rgba(17,23,42,.92), rgba(11,16,32,.92));
      box-shadow:var(--shadow);
    }}
    .stat .label{{font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:var(--muted)}}
    .stat .value{{margin-top:6px;font-size:28px;font-weight:700;letter-spacing:-.03em}}
    .panel{{border:1px solid var(--border);border-radius:18px;background:rgba(17,23,42,.92);
            box-shadow:var(--shadow);margin-bottom:16px}}
    .panel-head{{padding:14px 18px;border-bottom:1px solid var(--border);background:rgba(255,255,255,.02);
                 display:flex;justify-content:space-between;align-items:center}}
    .panel-head h2{{margin:0;font-size:15px;letter-spacing:.02em}}
    .panel-body{{padding:16px 18px}}
    table{{width:100%;border-collapse:collapse}}
    th,td{{text-align:left;padding:8px 10px;border-bottom:1px solid rgba(255,255,255,.05)}}
    th{{color:var(--muted);font-size:11px;letter-spacing:.08em;text-transform:uppercase}}
    .pill{{display:inline-block;padding:3px 8px;border-radius:999px;border:1px solid var(--border);
           background:rgba(255,255,255,.04);font-size:11px;color:var(--text)}}
    .pill.ok{{color:var(--good);border-color:rgba(119,214,138,.35)}}
    .pill.warn{{color:var(--warn);border-color:rgba(247,201,95,.35)}}
    .pill.danger{{color:var(--danger);border-color:rgba(255,122,122,.35)}}
    .pill.accent{{color:var(--accent-strong);border-color:rgba(102,217,194,.35)}}
    .progress{{
      position:relative;height:28px;border-radius:999px;overflow:hidden;
      border:1px solid var(--border);background:rgba(255,255,255,.04);margin:14px 0 10px
    }}
    .progress-bar{{
      position:absolute;inset:0 auto 0 0;background:linear-gradient(90deg, var(--accent), var(--accent-strong));
      transition:width .5s ease
    }}
    .progress-label{{
      position:absolute;inset:0;display:flex;align-items:center;justify-content:center;
      font-weight:700;font-size:13px;color:#06111e;mix-blend-mode:screen
    }}
    .phases{{display:flex;gap:8px;margin-top:12px;flex-wrap:wrap}}
    .phase-chip{{padding:6px 10px;border-radius:999px;border:1px solid var(--border);background:rgba(255,255,255,.03);font-size:12px;color:var(--muted)}}
    .phase-chip.active{{color:#06111e;background:var(--accent-strong);border-color:transparent;font-weight:700}}
    .phase-chip.done{{color:var(--good);border-color:rgba(119,214,138,.35)}}
    .mod-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px}}
    .mod-card{{padding:14px;border-radius:14px;border:1px solid var(--border);background:rgba(255,255,255,.03)}}
    .mod-card h3{{margin:0 0 6px;font-size:14px}}
    .mono{{font-family:\"Cascadia Code\",\"JetBrains Mono\",Consolas,monospace;font-size:12px}}
  </style>
</head>
<body>
  <div class=\"shell\">
"""

_HTML_FOOT = """
  </div>
</body>
</html>
"""


def _render_html(payload: Mapping[str, Any]) -> str:
    engagement_id = str(payload.get("engagement_id") or "")
    progress = payload.get("goal_progress") or {}
    exploitation = payload.get("exploitation_summary") or {}

    goal_type = progress.get("goal_type") or "(no goal set)"
    goal_status = progress.get("goal_status") or "unset"
    percentage = int(progress.get("progress_percentage") or 0)

    stats_html = _render_stats(progress, exploitation)
    phases_html = _render_phases(goal_status)
    phase_history_html = _render_phase_history(progress)
    intent_board_html = _render_intent_board(progress)
    modules_html = _render_modules(exploitation)
    cred_summary_html = _render_credential_summary(exploitation)

    body = (
        _HTML_HEAD.format(engagement_id=html.escape(engagement_id))
        + f"""
    <div class=\"hero\">
      <div>
        <h1>FORGE Goal Progress</h1>
        <div class=\"muted\">Engagement <span class=\"mono\">{html.escape(engagement_id)}</span>
          · Goal <span class=\"pill accent\">{html.escape(str(goal_type))}</span>
          · Phase <span class=\"pill\">{html.escape(str(goal_status))}</span>
        </div>
      </div>
      <div class=\"muted\" style=\"text-align:right\">
        <div>Catalog <span class=\"mono\">{html.escape(str(progress.get('catalog_version') or ''))}</span></div>
        <div>Generated <span class=\"mono\">{html.escape(str(payload.get('generated_at') or ''))}</span></div>
      </div>
    </div>

    <div class=\"panel\">
      <div class=\"panel-head\"><h2>Overall progress</h2><span class=\"muted mono\">{percentage}%</span></div>
      <div class=\"panel-body\">
        <div class=\"progress\">
          <div class=\"progress-bar\" style=\"width:{percentage}%\"></div>
          <div class=\"progress-label\">{percentage}% complete</div>
        </div>
        {phases_html}
      </div>
    </div>

    {stats_html}

    <div class=\"panel\">
      <div class=\"panel-head\"><h2>Intent board</h2>
        <span class=\"muted\">Open / Claimed / Completed / Abandoned</span></div>
      <div class=\"panel-body\">{intent_board_html}</div>
    </div>

    <div class=\"panel\">
      <div class=\"panel-head\"><h2>Exploitation module status</h2>
        <span class=\"muted\">{len(exploitation.get('modules_active') or [])} active</span></div>
      <div class=\"panel-body\">{modules_html}</div>
    </div>

    <div class=\"panel\">
      <div class=\"panel-head\"><h2>Credential capture summary</h2>
        <span class=\"muted\">{exploitation.get('credentials_total') or 0} records</span></div>
      <div class=\"panel-body\">{cred_summary_html}</div>
    </div>

    <div class=\"panel\">
      <div class=\"panel-head\"><h2>Phase history</h2>
        <span class=\"muted\">{len(progress.get('phase_history') or [])} entries</span></div>
      <div class=\"panel-body\">{phase_history_html}</div>
    </div>
"""
        + _HTML_FOOT
    )
    return body


def _render_stats(progress: Mapping[str, Any], exploitation: Mapping[str, Any]) -> str:
    entries = [
        ("Facts", progress.get("facts_count") or 0),
        ("Intents open", progress.get("intents_open") or 0),
        ("Intents claimed", progress.get("intents_claimed") or 0),
        ("Intents completed", progress.get("intents_completed") or 0),
        ("Intents abandoned", progress.get("intents_abandoned") or 0),
        ("Credentials", exploitation.get("credentials_captured") or 0),
        ("Sessions", exploitation.get("sessions_captured") or 0),
        ("MFA tokens", exploitation.get("mfa_tokens_captured") or 0),
        ("Strix findings", exploitation.get("strix_findings_count") or 0),
        ("Necrobrowser tasks", exploitation.get("necrobrowser_tasks_count") or 0),
    ]
    cards = "".join(
        f"<div class='stat'><div class='label'>{html.escape(label)}</div>"
        f"<div class='value'>{int(value)}</div></div>"
        for label, value in entries
    )
    return f"<div class='stats'>{cards}</div>"


def _render_phases(active_status: str) -> str:
    order = ("bootstrap", "reasoning", "exploring", "achieved")
    try:
        active_index = order.index(active_status)
    except ValueError:
        active_index = -1
    chips = []
    for idx, phase in enumerate(order):
        label = phase.capitalize()
        if idx < active_index:
            cls = "phase-chip done"
        elif idx == active_index:
            cls = "phase-chip active"
        else:
            cls = "phase-chip"
        chips.append(f"<span class='{cls}'>{html.escape(label)}</span>")
    if active_status == "failed":
        chips.append("<span class='phase-chip' style='color:var(--danger);border-color:rgba(255,122,122,.35)'>Failed</span>")
    return f"<div class='phases'>{''.join(chips)}</div>"


def _render_phase_history(progress: Mapping[str, Any]) -> str:
    history = list(progress.get("phase_history") or [])
    if not history:
        return "<div class='muted'>No phase history yet.</div>"
    rows = []
    for entry in history:
        rows.append(
            "<tr>"
            f"<td class='mono'>{html.escape(str(entry.get('timestamp') or ''))}</td>"
            f"<td><span class='pill'>{html.escape(str(entry.get('phase') or ''))}</span></td>"
            f"<td>{html.escape(str(entry.get('result') or ''))}</td>"
            "</tr>"
        )
    return (
        "<table><thead><tr><th>Timestamp</th><th>Phase</th><th>Result</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>"
    )


def _render_intent_board(progress: Mapping[str, Any]) -> str:
    cards = []
    columns = [
        ("Open", progress.get("intents_open") or 0, "accent"),
        ("Claimed", progress.get("intents_claimed") or 0, "warn"),
        ("Completed", progress.get("intents_completed") or 0, "ok"),
        ("Abandoned", progress.get("intents_abandoned") or 0, "danger"),
    ]
    for label, value, pill in columns:
        cards.append(
            f"<div class='mod-card'>"
            f"<span class='pill {pill}'>{html.escape(label)}</span>"
            f"<div class='value' style='font-size:24px;font-weight:700;margin-top:8px'>{int(value)}</div>"
            "</div>"
        )
    current = progress.get("current_intent") or None
    current_block = ""
    if current:
        current_block = (
            "<div class='mod-card' style='margin-top:12px'>"
            "<h3>Currently exploring</h3>"
            f"<div class='mono'>{html.escape(str(current.get('target_seed') or ''))}</div>"
            f"<div class='muted'>intent_id={html.escape(str(current.get('intent_id') or ''))} status={html.escape(str(current.get('status') or ''))}</div>"
            f"<div class='muted'>rationale: {html.escape(str(current.get('rationale') or '-'))}</div>"
            "</div>"
        )
    return f"<div class='mod-grid'>{''.join(cards)}</div>{current_block}"


def _render_modules(exploitation: Mapping[str, Any]) -> str:
    active = set(exploitation.get("modules_active") or [])
    cards = []
    status_values = {
        "credential_store": exploitation.get("credentials_total") or 0,
        "muraena": 1 if "muraena" in active else 0,
        "necrobrowser": exploitation.get("necrobrowser_tasks_count") or 0,
        "strix": exploitation.get("strix_findings_count") or 0,
        "goal_engine": exploitation.get("goals_achieved") or 0,
    }
    module_labels = {
        "credential_store": "Credential vault",
        "muraena": "Reverse-proxy capture",
        "necrobrowser": "Post-login automation",
        "strix": "Autonomous exploit",
        "goal_engine": "Goal tracker",
    }
    descriptions = {
        "credential_store": "Plaintext credential inventory (captures + exports).",
        "muraena": "Reverse-proxy credential capture.",
        "necrobrowser": "Post-login browser automation.",
        "strix": "Autonomous exploit runner.",
        "goal_engine": "Bootstrap / Reason / Explore goal tracker.",
    }
    for module in _EXPLOITATION_MODULES:
        pill_cls = "pill ok" if module in active else "pill"
        label = "active" if module in active else "idle"
        value = status_values.get(module, 0)
        display_name = module_labels.get(module, module)
        cards.append(
            "<div class='mod-card'>"
            f"<h3>{html.escape(display_name)}</h3>"
            f"<span class='{pill_cls}'>{html.escape(label)}</span>"
            f"<div class='value' style='font-size:22px;font-weight:700;margin-top:8px'>{int(value)}</div>"
            f"<div class='muted'>{html.escape(descriptions.get(module, ''))}</div>"
            "</div>"
        )
    return f"<div class='mod-grid'>{''.join(cards)}</div>"


def _render_credential_summary(exploitation: Mapping[str, Any]) -> str:
    sources = exploitation.get("credential_sources") or {}
    if not sources:
        return "<div class='muted'>No captured credentials yet.</div>"
    rows = []
    for source in sorted(sources):
        count = int(sources.get(source) or 0)
        rows.append(
            "<tr>"
            f"<td class='mono'>{html.escape(str(source))}</td>"
            f"<td>{count}</td>"
            "</tr>"
        )
    return (
        "<table><thead><tr><th>Source</th><th>Count</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>"
    )
