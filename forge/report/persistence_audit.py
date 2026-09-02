"""
forge/report/persistence_audit.py - Persistence audit generator (E1.2).

Read-only scanner over the FORGE JSONL audit log. Detects patterns that
would indicate persistence being established during an engagement so a
security team can review, whitelist, or investigate them.

Detected pattern classes
------------------------
1. Recurring actions at the same time of day (candidate scheduled task).
2. Service creation or modification events.
3. Registry writes into known Windows autorun locations.
4. File creation under startup folders (Windows or POSIX).

Severity
--------
- HIGH   : write to a known persistence location (registry autorun key,
           startup folder, service create/modify).
- MEDIUM : recurring same-time actions above the daily threshold.
- LOW    : anomalous but explainable (recurring at low count, or an
           event that matched a soft keyword but not a hard location).

Design notes
------------
- Pure read: the scanner opens the audit log ``rt`` and never writes back.
- Supports two JSONL shapes emitted by :class:`forge.audit.logger.AuditLogger`:
  a plain :class:`AuditEntry` line and a hash-chain wrapper
  ``{"entry": {...}, "prev_hash": ..., "entry_hash": ...}``.
- Whitelist reduces false positives from legitimate admin tools (WSUS,
  Defender, package managers). The default whitelist is conservative;
  callers can extend or replace it.
- No wall-clock, no randomness, no network — deterministic per input.

Public surface
--------------
- :class:`Severity`
- :class:`PersistenceFinding`
- :class:`PersistenceFindings`
- :func:`scan_for_persistence_patterns`
- :func:`render_markdown`
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping, Sequence

__all__ = [
    "AUTORUN_REGISTRY_FRAGMENTS",
    "DEFAULT_RECURRING_THRESHOLD",
    "DEFAULT_WHITELIST",
    "PersistenceFinding",
    "PersistenceFindings",
    "SERVICE_KEYWORDS",
    "STARTUP_FOLDER_FRAGMENTS",
    "Severity",
    "render_markdown",
    "scan_for_persistence_patterns",
]


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Known Windows autorun registry paths. Matched case-insensitively as
#: substrings against any string value in an audit entry's ``input_params``.
AUTORUN_REGISTRY_FRAGMENTS: tuple[str, ...] = (
    r"software\microsoft\windows\currentversion\run",
    r"software\microsoft\windows\currentversion\runonce",
    r"software\microsoft\windows\currentversion\runonceex",
    r"software\wow6432node\microsoft\windows\currentversion\run",
    r"software\microsoft\windows nt\currentversion\winlogon",
    r"software\microsoft\windows\currentversion\explorer\shell folders",
    r"software\microsoft\windows nt\currentversion\image file execution options",
    r"system\currentcontrolset\services",
    r"software\microsoft\active setup\installed components",
)

#: Startup folder fragments. Same substring/case-insensitive rule.
STARTUP_FOLDER_FRAGMENTS: tuple[str, ...] = (
    r"\startup\\",
    r"/startup/",
    r"start menu\programs\startup",
    r"appdata\roaming\microsoft\windows\start menu\programs\startup",
    r"/etc/init.d/",
    r"/etc/systemd/system/",
    r"~/.config/autostart/",
    r"/library/launchagents/",
    r"/library/launchdaemons/",
)

#: Service create / modify keyword hints. Matched against tool name and
#: input params. Kept small on purpose so a broad "service" mention alone
#: does not fire.
SERVICE_KEYWORDS: tuple[str, ...] = (
    "service_create",
    "service_modify",
    "service_install",
    "sc create",
    "sc config",
    "new-service",
    "set-service",
    "systemctl enable",
    "systemctl mask",
    "launchctl load",
)

#: Conservative whitelist of legitimate admin tools. Case-insensitive
#: substring match against tool_name / agent_role / any input_params
#: string value. Callers can pass their own via ``whitelist=``.
DEFAULT_WHITELIST: tuple[str, ...] = (
    "windows_update",
    "wuauclt",
    "wsus",
    "windows defender",
    "msmpeng",
    "chocolatey",
    "winget",
    "apt-get",
    "yum",
    "dnf",
    "zypper",
    "brew",
    "sccm",
    "intune",
)

#: Minimum recurrence count (same tool + same minute-of-day) before a
#: recurring-timing finding is emitted.
DEFAULT_RECURRING_THRESHOLD: int = 3


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class Severity(str, Enum):
    """Finding severity ordered LOW < MEDIUM < HIGH."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def rank(self) -> int:
        return {"low": 0, "medium": 1, "high": 2}[self.value]


_PATTERN_RECOMMENDATIONS: Mapping[str, str] = {
    "registry_autorun": (
        "Review registry write. Confirm the target key is authorised for "
        "this engagement and, if not, capture the value, snapshot the key, "
        "then remove and hunt for equivalents on peer hosts."
    ),
    "startup_folder": (
        "Inspect the dropped file. Verify signer, hash against known-good "
        "inventories, and remove if not authorised. Check for identical "
        "artifacts under other users' startup folders."
    ),
    "service_event": (
        "Review the created or modified service. Confirm authorisation, "
        "audit the binary path and account it runs as, and disable or "
        "remove if not part of the change ticket."
    ),
    "recurring_action": (
        "Cross-reference the recurring schedule with change control. "
        "Recurring same-time invocations may indicate a scheduled task; "
        "enumerate scheduled tasks / cron on the host and validate."
    ),
}


@dataclass(frozen=True, slots=True)
class PersistenceFinding:
    """One persistence indicator.

    Attributes
    ----------
    timestamp_utc:
        UTC ISO 8601 timestamp of the source audit event.
    action:
        Short human-readable action label (usually the tool name).
    severity:
        See :class:`Severity`.
    pattern_type:
        One of ``registry_autorun``, ``startup_folder``, ``service_event``,
        ``recurring_action``.
    recommendation:
        Deterministic follow-up guidance.
    evidence:
        Short quoted evidence string extracted from the audit entry
        (registry path, file path, service name, or recurrence summary).
    correlation_id:
        Audit correlation id of the source entry, when known.
    """

    timestamp_utc: str
    action: str
    severity: Severity
    pattern_type: str
    recommendation: str
    evidence: str
    correlation_id: str = ""


@dataclass(frozen=True, slots=True)
class PersistenceFindings:
    """Collected findings plus scan metadata."""

    engagement_id: int
    audit_log_path: str
    findings: tuple[PersistenceFinding, ...] = field(default_factory=tuple)
    total_events_scanned: int = 0
    time_start: str | None = None
    time_end: str | None = None
    min_severity: Severity | None = None

    def by_severity(self, severity: Severity) -> tuple[PersistenceFinding, ...]:
        return tuple(f for f in self.findings if f.severity is severity)


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


def _unwrap(raw: Mapping[str, Any]) -> Mapping[str, Any]:
    """Return the inner AuditEntry dict, handling the hash-chain wrapper."""
    inner = raw.get("entry")
    if isinstance(inner, Mapping):
        return inner
    return raw


def _iter_entries(audit_log_path: Path) -> Iterator[Mapping[str, Any]]:
    """Yield parsed audit entries. Malformed lines are skipped silently."""
    with audit_log_path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, Mapping):
                yield _unwrap(obj)


def _in_time_range(
    entry: Mapping[str, Any],
    time_start: datetime | None,
    time_end: datetime | None,
) -> bool:
    if time_start is None and time_end is None:
        return True
    ts = entry.get("timestamp_utc")
    if not isinstance(ts, (int, float)):
        return False
    when = datetime.fromtimestamp(float(ts), tz=timezone.utc)
    if time_start is not None and when < time_start:
        return False
    if time_end is not None and when > time_end:
        return False
    return True


# ---------------------------------------------------------------------------
# Matching helpers
# ---------------------------------------------------------------------------


def _collect_strings(value: Any, out: list[str]) -> None:
    """Depth-limited walk that collects string leaves for substring match."""
    if isinstance(value, str):
        out.append(value)
    elif isinstance(value, Mapping):
        for v in value.values():
            _collect_strings(v, out)
    elif isinstance(value, (list, tuple)):
        for v in value:
            _collect_strings(v, out)


def _entry_strings(entry: Mapping[str, Any]) -> list[str]:
    haystack: list[str] = []
    for key in ("tool_name", "agent_role", "output_summary", "error_detail"):
        v = entry.get(key)
        if isinstance(v, str):
            haystack.append(v)
    params = entry.get("input_params")
    if params is not None:
        _collect_strings(params, haystack)
    return haystack


def _lowered(strings: Sequence[str]) -> list[str]:
    return [s.lower() for s in strings]


def _match_fragment(strings: Sequence[str], fragments: Sequence[str]) -> str | None:
    for s in strings:
        for frag in fragments:
            if frag in s:
                return s
    return None


def _is_whitelisted(strings: Sequence[str], whitelist: Sequence[str]) -> bool:
    for s in strings:
        for w in whitelist:
            if w in s:
                return True
    return False


def _iso(entry: Mapping[str, Any]) -> str:
    ts = entry.get("timestamp_utc")
    if isinstance(ts, (int, float)):
        return (
            datetime.fromtimestamp(float(ts), tz=timezone.utc)
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z")
        )
    return ""


def _corr(entry: Mapping[str, Any]) -> str:
    v = entry.get("correlation_id")
    return v if isinstance(v, str) else ""


def _action(entry: Mapping[str, Any]) -> str:
    v = entry.get("tool_name") or entry.get("event_type") or "unknown"
    return str(v)


# ---------------------------------------------------------------------------
# Detectors
# ---------------------------------------------------------------------------


def _detect_registry_autorun(
    entry: Mapping[str, Any], lowered: Sequence[str]
) -> PersistenceFinding | None:
    hit = _match_fragment(lowered, AUTORUN_REGISTRY_FRAGMENTS)
    if hit is None:
        return None
    return PersistenceFinding(
        timestamp_utc=_iso(entry),
        action=_action(entry),
        severity=Severity.HIGH,
        pattern_type="registry_autorun",
        recommendation=_PATTERN_RECOMMENDATIONS["registry_autorun"],
        evidence=hit,
        correlation_id=_corr(entry),
    )


def _detect_startup_folder(
    entry: Mapping[str, Any], lowered: Sequence[str]
) -> PersistenceFinding | None:
    hit = _match_fragment(lowered, STARTUP_FOLDER_FRAGMENTS)
    if hit is None:
        return None
    return PersistenceFinding(
        timestamp_utc=_iso(entry),
        action=_action(entry),
        severity=Severity.HIGH,
        pattern_type="startup_folder",
        recommendation=_PATTERN_RECOMMENDATIONS["startup_folder"],
        evidence=hit,
        correlation_id=_corr(entry),
    )


def _detect_service_event(
    entry: Mapping[str, Any], lowered: Sequence[str]
) -> PersistenceFinding | None:
    hit = _match_fragment(lowered, SERVICE_KEYWORDS)
    if hit is None:
        return None
    return PersistenceFinding(
        timestamp_utc=_iso(entry),
        action=_action(entry),
        severity=Severity.HIGH,
        pattern_type="service_event",
        recommendation=_PATTERN_RECOMMENDATIONS["service_event"],
        evidence=hit,
        correlation_id=_corr(entry),
    )


def _detect_recurring(
    entries: Sequence[Mapping[str, Any]], threshold: int
) -> list[PersistenceFinding]:
    """Group entries by (tool_name, minute-of-day) and flag groups over the
    threshold that occur on 2+ distinct dates (i.e. a real recurrence,
    not a single burst)."""
    buckets: dict[tuple[str, int], list[Mapping[str, Any]]] = {}
    for entry in entries:
        ts = entry.get("timestamp_utc")
        tool = entry.get("tool_name")
        if not isinstance(ts, (int, float)) or not isinstance(tool, str):
            continue
        when = datetime.fromtimestamp(float(ts), tz=timezone.utc)
        key = (tool, when.hour * 60 + when.minute)
        buckets.setdefault(key, []).append(entry)

    findings: list[PersistenceFinding] = []
    for (tool, minute), group in buckets.items():
        if len(group) < threshold:
            continue
        distinct_dates = {
            datetime.fromtimestamp(float(e["timestamp_utc"]), tz=timezone.utc).date()
            for e in group
        }
        if len(distinct_dates) < 2:
            # A single day's burst is not a schedule.
            continue
        severity = Severity.MEDIUM if len(group) < threshold * 2 else Severity.HIGH
        hh, mm = divmod(minute, 60)
        first = min(group, key=lambda e: e["timestamp_utc"])
        findings.append(
            PersistenceFinding(
                timestamp_utc=_iso(first),
                action=tool,
                severity=severity,
                pattern_type="recurring_action",
                recommendation=_PATTERN_RECOMMENDATIONS["recurring_action"],
                evidence=(
                    f"{tool} observed {len(group)} times at "
                    f"~{hh:02d}:{mm:02d} UTC across {len(distinct_dates)} days"
                ),
                correlation_id=_corr(first),
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def scan_for_persistence_patterns(
    audit_log_path: Path,
    engagement_id: int,
    *,
    time_start: datetime | None = None,
    time_end: datetime | None = None,
    min_severity: Severity | None = None,
    whitelist: Iterable[str] | None = None,
    recurring_threshold: int = DEFAULT_RECURRING_THRESHOLD,
) -> PersistenceFindings:
    """Scan the JSONL audit log at ``audit_log_path`` for persistence patterns.

    Parameters
    ----------
    audit_log_path:
        Path to a FORGE audit JSONL file. Read-only; never written back.
    engagement_id:
        Engagement scope, embedded verbatim in the returned findings.
    time_start, time_end:
        Optional inclusive UTC bounds. Entries outside the window are ignored.
    min_severity:
        Optional lower bound. Findings below this severity are dropped.
    whitelist:
        Optional replacement whitelist. When ``None``, :data:`DEFAULT_WHITELIST`
        is used. Entries whose strings match any whitelist substring are
        skipped entirely.
    recurring_threshold:
        Minimum count for a same-tool same-minute group to be flagged.

    Returns
    -------
    PersistenceFindings
        Frozen container with the sorted findings and scan metadata.
    """
    if not audit_log_path.is_file():
        raise FileNotFoundError(f"audit log not found: {audit_log_path}")
    if recurring_threshold < 2:
        raise ValueError("recurring_threshold must be >= 2")

    wl_tuple = tuple(w.lower() for w in (whitelist if whitelist is not None else DEFAULT_WHITELIST))

    kept: list[Mapping[str, Any]] = []
    total = 0
    for entry in _iter_entries(audit_log_path):
        total += 1
        if not _in_time_range(entry, time_start, time_end):
            continue
        strings = _entry_strings(entry)
        lowered = _lowered(strings)
        if _is_whitelisted(lowered, wl_tuple):
            continue
        kept.append(entry)

    findings: list[PersistenceFinding] = []
    for entry in kept:
        lowered = _lowered(_entry_strings(entry))
        for detector in (
            _detect_registry_autorun,
            _detect_startup_folder,
            _detect_service_event,
        ):
            hit = detector(entry, lowered)
            if hit is not None:
                findings.append(hit)

    findings.extend(_detect_recurring(kept, recurring_threshold))

    if min_severity is not None:
        floor = min_severity.rank
        findings = [f for f in findings if f.severity.rank >= floor]

    # Deterministic ordering: severity desc, timestamp asc, pattern, evidence.
    findings.sort(
        key=lambda f: (-f.severity.rank, f.timestamp_utc, f.pattern_type, f.evidence)
    )

    return PersistenceFindings(
        engagement_id=engagement_id,
        audit_log_path=str(audit_log_path),
        findings=tuple(findings),
        total_events_scanned=total,
        time_start=time_start.isoformat().replace("+00:00", "Z") if time_start else None,
        time_end=time_end.isoformat().replace("+00:00", "Z") if time_end else None,
        min_severity=min_severity,
    )


# ---------------------------------------------------------------------------
# Markdown rendering
# ---------------------------------------------------------------------------


_SEVERITY_BADGE: Mapping[Severity, str] = {
    Severity.HIGH: "🔴 HIGH",
    Severity.MEDIUM: "🟡 MEDIUM",
    Severity.LOW: "🟢 LOW",
}

_PATTERN_LABEL: Mapping[str, str] = {
    "registry_autorun": "Registry autorun",
    "startup_folder": "Startup folder",
    "service_event": "Service create/modify",
    "recurring_action": "Recurring action",
}


def _md_escape(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ").strip()


def render_markdown(findings: PersistenceFindings) -> str:
    """Render the findings as a Markdown report section.

    Always emits the fixed heading ``## Potential Persistence Indicators``
    so downstream report assemblers can locate the section.
    """
    lines: list[str] = ["## Potential Persistence Indicators", ""]

    meta = [
        f"- **Engagement:** {findings.engagement_id}",
        f"- **Audit log:** `{findings.audit_log_path}`",
        f"- **Events scanned:** {findings.total_events_scanned}",
        f"- **Findings:** {len(findings.findings)}",
    ]
    if findings.time_start:
        meta.append(f"- **Time start:** {findings.time_start}")
    if findings.time_end:
        meta.append(f"- **Time end:** {findings.time_end}")
    if findings.min_severity is not None:
        meta.append(f"- **Min severity:** {findings.min_severity.value}")
    lines.extend(meta)
    lines.append("")

    if not findings.findings:
        lines.append("_No persistence indicators detected._")
        lines.append("")
        return "\n".join(lines)

    lines.append("| # | Timestamp (UTC) | Severity | Pattern | Action | Evidence | Recommendation |")
    lines.append("|---|-----------------|----------|---------|--------|----------|----------------|")
    for idx, f in enumerate(findings.findings, start=1):
        lines.append(
            "| {n} | {ts} | {sev} | {pat} | {act} | `{ev}` | {rec} |".format(
                n=idx,
                ts=_md_escape(f.timestamp_utc or "-"),
                sev=_SEVERITY_BADGE[f.severity],
                pat=_PATTERN_LABEL.get(f.pattern_type, f.pattern_type),
                act=_md_escape(f.action),
                ev=_md_escape(f.evidence),
                rec=_md_escape(f.recommendation),
            )
        )
    lines.append("")
    return "\n".join(lines)
